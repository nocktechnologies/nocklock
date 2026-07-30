package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
	"github.com/nocktechnologies/nocklock/internal/fence/fs/landlock"
	"github.com/nocktechnologies/nocklock/internal/fence/syscallfence"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/spf13/cobra"
)

type doctorSeverity string

const (
	doctorOK       doctorSeverity = "ok"
	doctorWarning  doctorSeverity = "warning"
	doctorCritical doctorSeverity = "critical"
	doctorInfo     doctorSeverity = "info"
)

type doctorVerdict string

const (
	doctorVerdictProtected doctorVerdict = "PROTECTED"
	doctorVerdictGapsFound doctorVerdict = "GAPS FOUND"
)

type doctorCheck struct {
	Group    string         `json:"group"`
	Name     string         `json:"name"`
	Severity doctorSeverity `json:"severity"`
	Status   string         `json:"status"`
	Message  string         `json:"message"`
	Fix      string         `json:"fix,omitempty"`
}

type doctorActivity struct {
	Last24hBlocked int `json:"last24h_blocked"`
	AllTimeBlocked int `json:"all_time_blocked"`
}

type doctorReport struct {
	Verdict  doctorVerdict  `json:"verdict"`
	Checks   []doctorCheck  `json:"checks"`
	Gaps     []doctorCheck  `json:"gaps,omitempty"`
	Activity doctorActivity `json:"activity"`
}

type doctorCapabilities struct {
	goos           string
	fsBackend      func() error
	landlockABI    func() (int, error)
	syscallBackend func() bool
	networkBackend func() error
	sandboxExec    func() error
	now            func() time.Time
}

var currentDoctorCapabilities = doctorCapabilities{
	goos:           runtime.GOOS,
	fsBackend:      func() error { return nil },
	landlockABI:    landlock.DetectABI,
	syscallBackend: syscallfence.Supported,
	networkBackend: localProxyBackendAvailable,
	sandboxExec:    fsfence.EnsureSandboxExecAvailable,
	now:            time.Now,
}

var doctorCmd = &cobra.Command{
	Use:   "doctor",
	Short: "Check whether NockLock fences are enforceable",
	RunE: func(cmd *cobra.Command, args []string) error {
		asJSON, _ := cmd.Flags().GetBool("json")
		report := runDoctor(currentDoctorCapabilities)
		if asJSON {
			if err := renderDoctorJSON(cmd.OutOrStdout(), report); err != nil {
				return err
			}
		} else {
			renderDoctorHuman(cmd.OutOrStdout(), report)
		}
		if report.Verdict == doctorVerdictGapsFound {
			cmd.SilenceUsage = true
			cmd.SilenceErrors = true
			return &exitCodeError{code: 1}
		}
		return nil
	},
}

func init() {
	doctorCmd.Flags().Bool("json", false, "emit structured JSON output")
	rootCmd.AddCommand(doctorCmd)
}

func runDoctor(caps doctorCapabilities) doctorReport {
	var checks []doctorCheck
	configPath, err := config.FindConfig()
	if err != nil {
		msg := "Config missing. Run 'nocklock init' first."
		if !errors.Is(err, os.ErrNotExist) {
			msg = fmt.Sprintf("Config lookup failed: %v", err)
		}
		checks = append(checks, doctorCheck{
			Group:    "Config",
			Name:     "config",
			Severity: doctorCritical,
			Status:   "missing",
			Message:  msg,
			Fix:      "run nocklock init",
		})
		return finishDoctorReport(checks, doctorActivity{})
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		checks = append(checks, doctorCheck{
			Group:    "Config",
			Name:     "config",
			Severity: doctorCritical,
			Status:   "parse-error",
			Message:  fmt.Sprintf("Config failed to load: %v", err),
			Fix:      "fix .nock/config.toml and rerun nocklock doctor",
		})
		return finishDoctorReport(checks, doctorActivity{})
	}

	checks = append(checks, doctorCheck{
		Group:    "Config",
		Name:     "config",
		Severity: doctorOK,
		Status:   "loaded",
		Message:  fmt.Sprintf("Config loaded from %s", configPath),
	})

	checks = append(checks, filesystemDoctorCheck(cfg, caps))
	checks = append(checks, syscallDoctorCheck(cfg, caps))
	checks = append(checks, networkDoctorCheck(cfg, caps))
	checks = append(checks, secretDoctorCheck(cfg))
	checks = append(checks, sanityDoctorChecks(cfg, caps)...)

	activity := doctorActivityCheck(cfg, configPath, caps.now())
	checks = append(checks, doctorCheck{
		Group:    "Activity",
		Name:     "recent-enforcement",
		Severity: doctorInfo,
		Status:   "observed",
		Message:  activityMessage(activity),
	})

	return finishDoctorReport(checks, activity)
}

func filesystemDoctorCheck(cfg *config.Config, caps doctorCapabilities) doctorCheck {
	if cfg.Filesystem.Root == "" {
		return doctorCheck{
			Group:    "Fences",
			Name:     "filesystem",
			Severity: doctorInfo,
			Status:   "not-configured",
			Message:  "Filesystem fence is not configured.",
		}
	}

	switch caps.goos {
	case "darwin":
		if err := caps.sandboxExec(); err != nil {
			return doctorCriticalCheck("Fences", "filesystem", "configured-but-backend-missing",
				fmt.Sprintf("Filesystem fence configured, but macOS Seatbelt backend is unavailable: %v", err),
				"install or restore sandbox-exec support before wrapping agents")
		}
		return doctorOKCheck("Fences", "filesystem", "enforceable", "Filesystem fence enforceable with macOS Seatbelt.")
	case "linux":
		if err := caps.fsBackend(); err != nil {
			return doctorCriticalCheck("Fences", "filesystem", "configured-but-backend-missing",
				fmt.Sprintf("Filesystem fence configured, but userspace backend is unavailable: %v", err),
				"build/install the filesystem fence backend")
		}
		if linuxEnforcementMode(cfg.Filesystem.LinuxEnforcement) != linuxEnforcementOff {
			abi, err := caps.landlockABI()
			if err != nil {
				return doctorCriticalCheck("Fences", "filesystem", "configured-but-backend-missing",
					fmt.Sprintf("Filesystem fence configured, but Landlock detection failed: %v", err),
					"run on a Landlock-capable Linux kernel or set filesystem.linux_enforcement only if intentionally accepted")
			}
			if abi == 0 {
				return doctorCriticalCheck("Fences", "filesystem", "configured-but-backend-missing",
					"Filesystem fence configured, but Linux Landlock is unavailable on this kernel.",
					"run on a Landlock-capable Linux kernel or set filesystem.linux_enforcement only if intentionally accepted")
			}
			return doctorOKCheck("Fences", "filesystem", "enforceable", fmt.Sprintf("Filesystem fence enforceable with Linux Landlock ABI v%d.", abi))
		}
		return doctorOKCheck("Fences", "filesystem", "enforceable", "Filesystem fence userspace backend is available; Landlock enforcement is off by config.")
	default:
		return doctorCriticalCheck("Fences", "filesystem", "backend-unavailable-on-this-platform",
			fmt.Sprintf("Filesystem fence configured, but %s has no supported backend.", caps.goos),
			"run NockLock on macOS or Linux for filesystem enforcement")
	}
}

func syscallDoctorCheck(cfg *config.Config, caps doctorCapabilities) doctorCheck {
	if syscallEnforcementMode(cfg.Syscall.Enforcement) == syscallfence.ModeOff {
		return doctorCheck{
			Group:    "Fences",
			Name:     "syscall",
			Severity: doctorInfo,
			Status:   "not-configured",
			Message:  "Syscall fence is off by config.",
		}
	}

	switch caps.goos {
	case "linux":
		if !caps.syscallBackend() {
			return doctorCriticalCheck("Fences", "syscall", "configured-but-backend-missing",
				"Syscall fence configured, but seccomp-BPF is unavailable on this kernel.",
				"run on a seccomp-capable Linux kernel or set syscall.enforcement = \"off\" if intentionally disabled")
		}
		return doctorOKCheck("Fences", "syscall", "enforceable", "Syscall fence enforceable with Linux seccomp-BPF.")
	case "darwin":
		if !cfg.Filesystem.Hardened {
			return doctorCriticalCheck("Fences", "syscall", "configured-but-backend-missing",
				"Syscall fence configured, but macOS hardened SBPL is not enabled.",
				"set filesystem.hardened = true or set syscall.enforcement = \"off\" if intentionally disabled")
		}
		if err := caps.sandboxExec(); err != nil {
			return doctorCriticalCheck("Fences", "syscall", "configured-but-backend-missing",
				fmt.Sprintf("Syscall fence configured, but macOS Seatbelt backend is unavailable: %v", err),
				"install or restore sandbox-exec support before wrapping agents")
		}
		return doctorOKCheck("Fences", "syscall", "enforceable", "Syscall hardening enforceable with hardened macOS SBPL.")
	default:
		return doctorCriticalCheck("Fences", "syscall", "backend-unavailable-on-this-platform",
			fmt.Sprintf("Syscall fence configured, but %s has no supported backend.", caps.goos),
			"run NockLock on Linux for seccomp or macOS with hardened SBPL")
	}
}

func networkDoctorCheck(cfg *config.Config, caps doctorCapabilities) doctorCheck {
	if cfg.Network.AllowAll {
		return doctorCheck{
			Group:    "Fences",
			Name:     "network",
			Severity: doctorInfo,
			Status:   "disabled",
			Message:  "Network fence is disabled by allow_all = true.",
		}
	}
	if err := caps.networkBackend(); err != nil {
		return doctorCriticalCheck("Fences", "network", "configured-but-backend-missing",
			fmt.Sprintf("Network fence configured, but proxy backend is unavailable: %v", err),
			"fix local proxy startup before wrapping agents")
	}
	return doctorOKCheck("Fences", "network", "enforceable", "Network fence proxy backend is available.")
}

func secretDoctorCheck(cfg *config.Config) doctorCheck {
	if len(cfg.Secrets.Block) == 0 {
		return doctorCheck{
			Group:    "Fences",
			Name:     "secrets",
			Severity: doctorWarning,
			Status:   "permissive",
			Message:  "Secret fence is enforceable, but no secret patterns are blocked.",
			Fix:      "add patterns under secrets.block",
		}
	}
	return doctorOKCheck("Fences", "secrets", "enforceable", fmt.Sprintf("Secret fence enforceable with %d blocked pattern(s).", len(cfg.Secrets.Block)))
}

func sanityDoctorChecks(cfg *config.Config, caps doctorCapabilities) []doctorCheck {
	var checks []doctorCheck
	if cfg.Network.AllowAll {
		checks = append(checks, doctorCheck{
			Group:    "Sanity",
			Name:     "network-allow-all",
			Severity: doctorWarning,
			Status:   "warning",
			Message:  "Network fence is OFF — the agent can reach any host. Set network.allow and drop allow_all to fence it.",
			Fix:      "set network.allow and allow_all = false",
		})
	}

	// Inert-allowlist footgun: on Linux, when the network fence is active
	// (allow_all = false) AND the syscall fence is on, buildSyscallPolicy forces
	// the socket-family allowlist to unix-only (syscall_wire.go). The proxy that
	// enforces network.allow listens on TCP 127.0.0.1, which the child can no
	// longer reach — so the posture collapses to no-IP-network and the curated
	// domain allowlist is inert (the agent reaches NONE of the allowed domains,
	// not a selective subset). This is the intended hardened no-network posture,
	// but a user who spent effort curating network.allow will not expect it, so
	// surface it rather than let the allowlist silently do nothing.
	if caps.goos == "linux" &&
		!cfg.Network.AllowAll &&
		len(cfg.Network.Allow) > 0 &&
		syscallEnforcementMode(cfg.Syscall.Enforcement) != syscallfence.ModeOff {
		checks = append(checks, doctorCheck{
			Group:    "Sanity",
			Name:     "network-allowlist-inert-under-syscall-fence",
			Severity: doctorWarning,
			Status:   "warning",
			Message: fmt.Sprintf(
				"Network allowlist is inert on Linux: the syscall fence restricts the child to unix-domain sockets while the network fence is active, so the agent gets no IP network at all — your %d allowed domain(s) are not selectively reachable. This is the hardened no-network posture.",
				len(cfg.Network.Allow)),
			Fix: "for a working (but userspace-bypassable) domain allowlist set [syscall] enforcement = \"off\"; otherwise the posture is no-network by design and network.allow is documentation-only",
		})
	}
	if len(cfg.Secrets.Block) == 0 {
		checks = append(checks, doctorCheck{
			Group:    "Sanity",
			Name:     "secret-patterns",
			Severity: doctorWarning,
			Status:   "warning",
			Message:  "No secret patterns blocked.",
			Fix:      "add patterns under secrets.block",
		})
	}
	if cfg.Filesystem.Root != "" && len(cfg.Filesystem.Deny) == 0 && hasBroadFilesystemAllow(cfg) {
		checks = append(checks, doctorCheck{
			Group:    "Sanity",
			Name:     "filesystem-permissive",
			Severity: doctorInfo,
			Status:   "permissive",
			Message:  "Filesystem fence has a root but no deny paths and a broad allow rule; this is permissive.",
		})
	}
	if len(checks) == 0 {
		checks = append(checks, doctorOKCheck("Sanity", "config-sanity", "ok", "No obvious permissive config issues found."))
	}
	return checks
}

func doctorActivityCheck(cfg *config.Config, configPath string, now time.Time) doctorActivity {
	dbPath, projectRoot := config.ResolveDBPath(cfg, configPath)
	if _, err := os.Stat(dbPath); err != nil {
		return doctorActivity{}
	}
	logger, err := logging.NewLogger(dbPath, projectRoot)
	if err != nil {
		return doctorActivity{}
	}
	defer logger.Close()

	blocked := true
	since := now.Add(-24 * time.Hour)
	recent, err := logger.Query(logging.QueryOptions{Blocked: &blocked, Since: &since, Limit: 10000})
	if err != nil {
		recent = nil
	}
	stats, err := logger.Stats("")
	allTime := 0
	if err == nil {
		allTime = stats.BlockedCount
	}
	return doctorActivity{Last24hBlocked: len(recent), AllTimeBlocked: allTime}
}

func finishDoctorReport(checks []doctorCheck, activity doctorActivity) doctorReport {
	gaps := make([]doctorCheck, 0)
	for _, check := range checks {
		if check.Severity == doctorCritical {
			gaps = append(gaps, check)
		}
	}
	verdict := doctorVerdictProtected
	if len(gaps) > 0 {
		verdict = doctorVerdictGapsFound
	}
	return doctorReport{
		Verdict:  verdict,
		Checks:   checks,
		Gaps:     gaps,
		Activity: activity,
	}
}

func renderDoctorJSON(w io.Writer, report doctorReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func renderDoctorHuman(w io.Writer, report doctorReport) {
	currentGroup := ""
	for _, check := range report.Checks {
		if check.Group != currentGroup {
			if currentGroup != "" {
				fmt.Fprintln(w)
			}
			currentGroup = check.Group
			fmt.Fprintf(w, "%s\n", check.Group)
		}
		fmt.Fprintf(w, "%s %s [%s]: %s\n", doctorSymbol(check.Severity), check.Name, check.Status, check.Message)
	}
	fmt.Fprintf(w, "\nVERDICT: %s\n", report.Verdict)
	if len(report.Gaps) > 0 {
		fmt.Fprintln(w, "Gaps:")
		for _, gap := range report.Gaps {
			fix := gap.Fix
			if fix == "" {
				fix = "fix the reported backend/configuration issue"
			}
			fmt.Fprintf(w, "- %s: %s Fix: %s.\n", gap.Name, gap.Message, strings.TrimSuffix(fix, "."))
		}
	}
}

func doctorSymbol(severity doctorSeverity) string {
	switch severity {
	case doctorOK:
		return "✓"
	case doctorWarning:
		return "⚠"
	case doctorCritical:
		return "✗"
	default:
		return "ℹ"
	}
}

func doctorOKCheck(group, name, status, message string) doctorCheck {
	return doctorCheck{Group: group, Name: name, Severity: doctorOK, Status: status, Message: message}
}

func doctorCriticalCheck(group, name, status, message, fix string) doctorCheck {
	return doctorCheck{Group: group, Name: name, Severity: doctorCritical, Status: status, Message: message, Fix: fix}
}

func hasBroadFilesystemAllow(cfg *config.Config) bool {
	for _, allow := range cfg.Filesystem.Allow {
		switch strings.TrimSpace(allow) {
		case ".", "./", "/", "*":
			return true
		}
	}
	return false
}

func activityMessage(activity doctorActivity) string {
	if activity.Last24hBlocked > 0 || activity.AllTimeBlocked > 0 {
		return fmt.Sprintf("Fence blocked %d action(s) in the last 24h (%d all-time).", activity.Last24hBlocked, activity.AllTimeBlocked)
	}
	return "No denials logged yet (either nothing tried, or fences not exercised)."
}

func localProxyBackendAvailable() error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	return ln.Close()
}
