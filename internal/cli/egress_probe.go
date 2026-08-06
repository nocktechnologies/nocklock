package cli

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

// egress_probe.go implements `nocklock egress-probe`: a repeatable, structured
// feasibility probe for the Linux network-egress-enforcement track (see
// docs/superpowers/specs/2026-07-30-linux-network-egress-enforcement.md). It
// codifies the Phase 0 VPS probe runs so that every fleet kernel — CI runners
// included — is measured the same way before Phase 1 locks the privileged-helper
// design.
//
// Fidelity to the receipt is the point. The spec's Phase 0 table rows are literal
// `unshare` invocations; "probed the same way" means the same command, not a
// Go-native reimplementation that could answer differently (an equivalent-looking
// clone with a parent-written uid_map takes a different privilege path and can
// report a more-permissive false green). So the namespace attempts here shell out
// to `unshare` with the receipted flags verbatim.
//
// Scope of THIS tool (Phase 0, deliverable 1): the non-mutating feasibility
// checks only —
//   - unprivileged userns / userns+netns creation via `unshare` (subprocess, so
//     a successful clone never alters the probe's own credentials);
//   - the two sysctls that decide the classic-vs-AppArmor cause
//     (unprivileged_userns_clone, apparmor_restrict_unprivileged_userns);
//   - nftables binary + nft_tproxy module presence;
//   - passwordless-sudo reachability for the privileged-helper track.
//
// It deliberately does NOT create a real, persistent network namespace, load
// modules, or run the acceptance tests. The Q6 post-drop mutation test, the
// protocol-matrix egress test, and the AppArmor toggle test all require root and
// live namespace setup; they are enumerated as integration-tagged follow-ups and
// would turn a bare CI `go test ./...` red, so they are intentionally out of this
// increment.
//
// Naming note: the hidden `__probe` command (probe.go) is the in-child fence
// self-test used by `verify`. It is a different concept, so everything here is
// prefixed `egressProbe*` to avoid colliding with that command's symbols.

// egressProbeSchema versions the machine-readable output so results collected
// from different fleet kernels over time remain comparable and parseable.
const egressProbeSchema = "nocklock.egress-probe/v1"

// Evidence qualifiers. The spec is deliberate that AppArmor is the *indicated*
// (documented-signature) cause rather than a toggle-proven one, and that the
// privileged-helper setup path is only "confirmed" once a live namespace is
// actually created — which this non-mutating probe does not do. The schema
// carries that distinction explicitly instead of overclaiming.
const (
	evidenceObserved  = "observed"   // directly measured on this host
	evidenceIndicated = "indicated"  // documented signature, not isolated/proven here
	evidenceNotProbed = "not-probed" // requires a mutating/root/tool step not exercised here
)

// Namespace-attempt outcomes. "unavailable" (the `unshare` tool is missing) is
// deliberately distinct from "blocked" (the kernel denied the capability): a
// missing tool is not a denied capability and must not read as a hard block.
const (
	nsPermitted   = "permitted"
	nsBlocked     = "blocked"
	nsToolMissing = "unavailable"
)

// Sysctl read states. A missing knob (the file does not exist on this kernel)
// must be distinguishable from a knob that exists but could not be read (e.g.
// a restricted /proc) — the latter is a probe failure, not evidence the knob
// is absent, and must be reported not-probed rather than as false "observed"
// absence.
const (
	sysctlFound      = "found"
	sysctlAbsent     = "absent"
	sysctlUnreadable = "unreadable"
)

// nft_tproxy detection states. /proc/modules and modinfo only see loaded or
// loadable (out-of-tree/module-form) support; a kernel with CONFIG_NFT_TPROXY=y
// has the feature compiled in with neither source showing it. "unproven" keeps
// that gap honest instead of reporting a false "unavailable" for a capability
// that may in fact be present.
const (
	tproxyAvailable   = "available"
	tproxyUnavailable = "unavailable"
	tproxyUnproven    = "unproven"
)

// Track verdicts — which Candidate B path this host supports.
const (
	trackUnprivilegedClean = "unprivileged-clean" // unprivileged userns+netns works; no helper needed
	trackPrivilegedHelper  = "privileged-helper"  // unprivileged blocked, but a privileged helper is reachable
	trackBlocked           = "blocked"            // unprivileged blocked and no privileged path detected
	trackUndetermined      = "undetermined"       // unprivileged path could not be probed (tool missing) and no privileged path
	trackUnsupported       = "unsupported"        // not a Linux host
)

// nsAttemptResult is the outcome of a single `unshare` feasibility attempt.
type nsAttemptResult struct {
	Status string // nsPermitted | nsBlocked | nsToolMissing
	Detail string
}

type egressProbeCheck struct {
	ID       string `json:"id"`
	Category string `json:"category"`
	Status   string `json:"status"`
	Evidence string `json:"evidence"`
	Detail   string `json:"detail"`
}

type egressProbeHost struct {
	OS            string `json:"os"`
	Arch          string `json:"arch"`
	KernelRelease string `json:"kernel_release,omitempty"`
	Distro        string `json:"distro,omitempty"`
}

type egressProbeReport struct {
	Schema string             `json:"schema"`
	Track  string             `json:"track"`
	Host   egressProbeHost    `json:"host"`
	Checks []egressProbeCheck `json:"checks"`
}

// egressProbeCapabilities holds the host-touching operations behind injectable
// function fields so runEgressProbe stays pure and unit-testable without root,
// exec, or /proc access — the same pattern doctor uses for its backend probes.
// The real implementations live in egress_probe_linux.go; egress_probe_other.go
// supplies no-op stubs for non-Linux builds.
type egressProbeCapabilities struct {
	goos string
	arch string

	kernelRelease func() string
	distro        func() string

	// Sysctls. Each returns the trimmed value and a sysctlFound/sysctlAbsent/
	// sysctlUnreadable status — an unreadable knob must not be reported as
	// observed-absent.
	unprivUsernsClone func() (value string, status string)
	apparmorRestrict  func() (value string, status string)

	// Unprivileged namespace creation, attempted via `unshare` subprocesses with
	// the receipted flags.
	tryUsernsMapped      func() nsAttemptResult // unshare --user --map-root-user
	tryUserNetnsMapped   func() nsAttemptResult // unshare --user --net --map-root-user
	tryUserNetnsUnmapped func() nsAttemptResult // unshare --user --net (no uid_map write)

	// Mechanism + privileged-path detection (non-mutating).
	nftVersion         func() (version string, ok bool)
	nftTproxyModule    func() (status string) // tproxyAvailable | tproxyUnavailable | tproxyUnproven
	sudoNonInteractive func() (ok bool)
}

var currentEgressProbeCapabilities = defaultEgressProbeCapabilities()

var egressProbeCmd = &cobra.Command{
	Use:   "egress-probe",
	Short: "Probe Linux network-egress enforcement feasibility on this host",
	Long: "egress-probe measures whether this kernel can host NockLock's network-egress\n" +
		"fence (Candidate B: netns + transparent redirect) and, if not unprivileged-clean,\n" +
		"whether the privileged-helper track is reachable. It emits a structured, versioned\n" +
		"result so CI-runner kernels are probed identically to the dev VPS before Phase 1.\n\n" +
		"It is non-mutating: it attempts unprivileged namespace creation via throwaway\n" +
		"`unshare` subprocesses and detects tool/module presence, but never creates a\n" +
		"persistent namespace, loads modules, or runs the root-only acceptance tests\n" +
		"(those are integration follow-ups).",
	RunE: func(cmd *cobra.Command, args []string) error {
		asJSON, _ := cmd.Flags().GetBool("json")
		report := runEgressProbe(currentEgressProbeCapabilities)
		if asJSON {
			if err := renderEgressProbeJSON(cmd.OutOrStdout(), report); err != nil {
				return err
			}
		} else {
			renderEgressProbeHuman(cmd.OutOrStdout(), report)
		}
		// A probe that runs to completion always exits 0, whatever the verdict:
		// "unprivileged netns blocked" is the *expected, correct* finding on a
		// hardened host, and a CI wrapper must read a completed probe as success.
		return nil
	},
}

func init() {
	egressProbeCmd.Flags().Bool("json", false, "emit structured JSON output")
	rootCmd.AddCommand(egressProbeCmd)
}

func runEgressProbe(caps egressProbeCapabilities) egressProbeReport {
	report := egressProbeReport{
		Schema: egressProbeSchema,
		Host:   egressProbeHost{OS: caps.goos, Arch: caps.arch},
	}
	if caps.kernelRelease != nil {
		report.Host.KernelRelease = caps.kernelRelease()
	}
	if caps.distro != nil {
		report.Host.Distro = caps.distro()
	}

	if caps.goos != "linux" {
		report.Track = trackUnsupported
		report.Checks = append(report.Checks, egressProbeCheck{
			ID:       "platform",
			Category: "platform",
			Status:   "unsupported",
			Evidence: evidenceObserved,
			Detail: fmt.Sprintf(
				"Linux network-egress enforcement is only meaningful on Linux; host is %s. No probe performed.",
				caps.goos),
		})
		return report
	}

	var checks []egressProbeCheck

	// --- Sysctls that decide the classic-vs-AppArmor cause ------------------
	usernsClone, usernsCloneStatus := caps.unprivUsernsClone()
	checks = append(checks, sysctlCheck(
		"unprivileged-userns-clone", "userns",
		"kernel.unprivileged_userns_clone", usernsClone, usernsCloneStatus,
		"classic unprivileged-userns sysctl"))
	classicSysctlPermissive := usernsCloneStatus == sysctlFound && usernsClone == "1"

	apparmorRestrict, apparmorStatus := caps.apparmorRestrict()
	checks = append(checks, sysctlCheck(
		"apparmor-restrict-unprivileged-userns", "apparmor",
		"kernel.apparmor_restrict_unprivileged_userns", apparmorRestrict, apparmorStatus,
		"Ubuntu 24.04+ AppArmor unprivileged-userns gate"))
	apparmorRestrictOn := apparmorStatus == sysctlFound && apparmorRestrict == "1"

	// --- Unprivileged namespace creation via `unshare` ---------------------
	usernsMapped := caps.tryUsernsMapped()
	checks = append(checks, attemptCheck(
		"unprivileged-userns", "userns", "unshare --user --map-root-user", usernsMapped))

	netnsMapped := caps.tryUserNetnsMapped()
	checks = append(checks, attemptCheck(
		"unprivileged-userns-netns", "netns", "unshare --user --net --map-root-user", netnsMapped))

	// The discriminator the one-off 2026-08-03 probe did not run: bare userns+netns
	// creation WITHOUT the root-mapping uid_map write. If this succeeds while the
	// mapped attempt is denied, the blocker is specifically the uid_map write, not
	// namespace creation — a materially narrower finding.
	netnsUnmapped := caps.tryUserNetnsUnmapped()
	checks = append(checks, attemptCheck(
		"unprivileged-userns-netns-unmapped", "netns", "unshare --user --net", netnsUnmapped))

	// --- Cause attribution --------------------------------------------------
	if cause, ok := attributeUsernsCause(usernsMapped, netnsUnmapped, classicSysctlPermissive, apparmorRestrictOn); ok {
		checks = append(checks, cause)
	}

	// --- Mechanism + privileged-path detection -----------------------------
	nftVer, nftOK := caps.nftVersion()
	checks = append(checks, presenceCheck(
		"nftables-binary", "nftables", nftOK,
		fmt.Sprintf("nft present (%s) — tproxy mechanism candidate", nftVer),
		"nft binary not found — tproxy redirect mechanism unavailable"))

	tproxyStatus := caps.nftTproxyModule()
	checks = append(checks, tproxyCheck(tproxyStatus))

	sudoOK := caps.sudoNonInteractive()
	checks = append(checks, presenceCheck(
		"sudo-nopasswd", "privileged-helper", sudoOK,
		"passwordless sudo available — a privileged helper is reachable on this host",
		"passwordless sudo unavailable — the sudo-based privileged-helper path is not reachable non-interactively here"))

	// --- Track verdict ------------------------------------------------------
	track, trackCheck := deriveEgressTrack(netnsMapped, sudoOK, nftOK, tproxyStatus)
	checks = append(checks, trackCheck)

	report.Track = track
	report.Checks = checks
	return report
}

// attributeUsernsCause reproduces the spec's careful reasoning about WHY an
// unprivileged userns is denied, and returns false when no attribution applies
// (mapped userns not blocked, or the classic sysctl not permissive).
// apparmorRestrictOn must only be true when the sysctl was actually read as
// =1 — AppArmor must never be named as a cause on a host where that isn't
// observed.
func attributeUsernsCause(usernsMapped, netnsUnmapped nsAttemptResult, classicSysctlPermissive, apparmorRestrictOn bool) (egressProbeCheck, bool) {
	if usernsMapped.Status != nsBlocked || !classicSysctlPermissive {
		return egressProbeCheck{}, false
	}
	switch {
	case netnsUnmapped.Status == nsPermitted:
		detail := "Bare unprivileged userns+netns creation succeeds, but the root-mapping uid_map write is denied — a NARROWER blocker than a full userns denial. " +
			"(The 2026-08-03 manual probe recorded the mapped failure but did not test the unmapped path.) " +
			"The classic sysctl is permissive (=1), so it is ruled out; "
		if apparmorRestrictOn {
			detail += "apparmor_restrict_unprivileged_userns=1 is the indicated cause of the map-write restriction — documented signature, not toggle-proven here."
		} else {
			detail += "apparmor_restrict_unprivileged_userns is not =1/present here, so the cause of the map-write restriction is unattributed on this host — needs a targeted follow-up."
		}
		return egressProbeCheck{
			ID:       "unprivileged-userns-cause",
			Category: "userns",
			Status:   "uid-map-write-gate",
			Evidence: evidenceIndicated,
			Detail:   detail,
		}, true
	case apparmorRestrictOn:
		return egressProbeCheck{
			ID:       "unprivileged-userns-cause",
			Category: "userns",
			Status:   "apparmor-gate",
			Evidence: evidenceIndicated,
			Detail: "Unprivileged userns denied despite unprivileged_userns_clone=1, so the classic sysctl is ruled out. " +
				"apparmor_restrict_unprivileged_userns=1 (standard on Ubuntu 24.04+) is the indicated cause of this signature — " +
				"documented, not isolated here (toggling a live security control is out of scope; see the AppArmor-toggle follow-up).",
		}, true
	default:
		return egressProbeCheck{
			ID:       "unprivileged-userns-cause",
			Category: "userns",
			Status:   "unattributed",
			Evidence: evidenceIndicated,
			Detail: "Unprivileged userns denied despite unprivileged_userns_clone=1 (classic sysctl ruled out), " +
				"but apparmor_restrict_unprivileged_userns is not =1/present here — cause unattributed on this host; needs a targeted follow-up.",
		}, true
	}
}

// trackVerdict builds the single "track" summary check, factored out because
// deriveEgressTrack's arms otherwise repeat the same four struct fields.
func trackVerdict(track, evidence, detail string) (string, egressProbeCheck) {
	return track, egressProbeCheck{
		ID:       "track",
		Category: "verdict",
		Status:   track,
		Evidence: evidence,
		Detail:   detail,
	}
}

// deriveEgressTrack decides which Candidate B path this host supports and
// returns a summary check. The privileged-helper verdict is marked "reachable,
// not confirmed": this probe never creates a live namespace, so it records
// reachability (sudo + nft observed) while leaving actual setup viability
// not-probed — that proof is the integration-tagged follow-up.
//
// nft_tproxy is required for BOTH deployable tracks: without it, Candidate
// B's chosen transparent-redirect mechanism isn't available, regardless of
// the namespace/privilege path. tproxyStatus is threaded through (not
// collapsed to a bool) so a merely tproxyUnproven host — no evidence either
// way, possibly built in — downgrades to trackUndetermined rather than the
// confirmed-observed trackBlocked a tproxyUnavailable host gets; collapsing
// the two would assert "observed unavailable" from evidence that only says
// "not probed".
func deriveEgressTrack(netnsMapped nsAttemptResult, sudoOK, nftOK bool, tproxyStatus string) (string, egressProbeCheck) {
	tproxyOK := tproxyStatus == tproxyAvailable
	tproxyUnknown := tproxyStatus == tproxyUnproven

	switch {
	case netnsMapped.Status == nsPermitted && tproxyOK:
		return trackVerdict(trackUnprivilegedClean, evidenceObserved,
			"Unprivileged userns+netns creation with root-mapping succeeded here and nft_tproxy is available: Candidate B can run unprivileged-clean, no privileged helper required on this host.")
	case sudoOK && nftOK && tproxyOK:
		return trackVerdict(trackPrivilegedHelper, evidenceNotProbed,
			"Unprivileged root-mapped netns is not available, but passwordless sudo, nft, and nft_tproxy are present, so the privileged-helper track is REACHABLE. "+
				"Setup viability is NOT confirmed by this probe — it does not create a live namespace or nftables policy; "+
				"that proof (plus the Q6 post-drop mutation acceptance test) is the integration follow-up.")
	case netnsMapped.Status == nsPermitted && tproxyUnknown:
		return trackVerdict(trackUndetermined, evidenceNotProbed,
			"Unprivileged root-mapped netns creation succeeded, but nft_tproxy presence could not be determined on this kernel (see the nftables-tproxy-module check) — Candidate B's deployability is unproven, not confirmed blocked.")
	case sudoOK && nftOK && tproxyUnknown:
		return trackVerdict(trackUndetermined, evidenceNotProbed,
			"Passwordless sudo and nft are present, but nft_tproxy presence could not be determined on this kernel (see the nftables-tproxy-module check) — the privileged-helper track's deployability is unproven, not confirmed blocked.")
	case netnsMapped.Status == nsPermitted:
		return trackVerdict(trackBlocked, evidenceObserved,
			"Unprivileged root-mapped netns creation succeeded, but nft_tproxy (the transparent-redirect mechanism Candidate B depends on) is confirmed unavailable on this kernel. "+
				"Candidate B is not deployable without enabling nft_tproxy, even though the namespace path itself works.")
	case sudoOK && nftOK:
		return trackVerdict(trackBlocked, evidenceObserved,
			"Passwordless sudo and nft are present, but nft_tproxy (the transparent-redirect mechanism Candidate B depends on) is confirmed unavailable on this kernel. "+
				"The privileged-helper track is not deployable without enabling nft_tproxy.")
	case !tproxyOK && !tproxyUnknown:
		// Neither namespace path nor privileged-helper path is reachable
		// (both prior tproxy-gated arms already claimed every case where one
		// was), and nft_tproxy is confirmed unavailable here — a universal
		// blocker regardless of which path is or isn't reachable, so it must
		// be checked before falling through to the path-specific arms below
		// (which would otherwise report an unshare-tooling remediation that
		// cannot actually fix a missing nft_tproxy).
		return trackVerdict(trackBlocked, evidenceObserved,
			"nft_tproxy (the transparent-redirect mechanism Candidate B depends on) is confirmed unavailable on this kernel, so Candidate B is not deployable on this host regardless of the namespace/privileged-helper path status.")
	case netnsMapped.Status == nsBlocked:
		return trackVerdict(trackBlocked, evidenceObserved,
			"Unprivileged root-mapped netns is denied and no privileged-helper path was detected (missing passwordless sudo and/or nft). "+
				"Candidate B is not deployable on this host without further provisioning.")
	default:
		return trackVerdict(trackUndetermined, evidenceNotProbed,
			"The unprivileged path could not be probed (the unshare tool is unavailable) and no privileged-helper path was detected. "+
				"Install util-linux (unshare) to determine the unprivileged-clean track on this host.")
	}
}

func sysctlCheck(id, category, knob, value, status, desc string) egressProbeCheck {
	switch status {
	case sysctlUnreadable:
		return egressProbeCheck{
			ID:       id,
			Category: category,
			Status:   "not-probed",
			Evidence: evidenceNotProbed,
			Detail:   fmt.Sprintf("%s (%s) could not be read (permission denied or I/O error) — not probed, not confirmed absent.", desc, knob),
		}
	case sysctlAbsent:
		return egressProbeCheck{
			ID:       id,
			Category: category,
			Status:   "absent",
			Evidence: evidenceObserved,
			Detail:   fmt.Sprintf("%s (%s) not present on this kernel.", desc, knob),
		}
	default:
		return egressProbeCheck{
			ID:       id,
			Category: category,
			Status:   "value=" + value,
			Evidence: evidenceObserved,
			Detail:   fmt.Sprintf("%s (%s) = %s.", desc, knob, value),
		}
	}
}

// tproxyCheck reports the nft_tproxy detection result. tproxyAvailable and
// tproxyUnavailable are both observed evidence, so they reuse presenceCheck;
// tproxyUnproven (no evidence either way — a possible built-in) gets its own
// not-probed shape rather than being folded into the observed "unavailable"
// presenceCheck would otherwise assign it.
func tproxyCheck(status string) egressProbeCheck {
	switch status {
	case tproxyAvailable, tproxyUnavailable:
		return presenceCheck(
			"nftables-tproxy-module", "nftables", status == tproxyAvailable,
			"nft_tproxy module available (loaded or loadable) — Q2 tproxy is on this kernel.",
			"nft_tproxy is not loaded, not loadable, and not compiled into the running kernel — transparent redirect (Q2) is not available on this kernel.")
	default: // tproxyUnproven, and any unrecognized status
		return egressProbeCheck{
			ID:       "nftables-tproxy-module",
			Category: "nftables",
			Status:   "unproven",
			Evidence: evidenceNotProbed,
			Detail:   "nft_tproxy is not currently loaded, and neither modinfo nor the running kernel's own config source could confirm or rule out a loadable or compiled-in (CONFIG_NFT_TPROXY=y) build — presence is unproven, not confirmed absent.",
		}
	}
}

func attemptCheck(id, category, method string, r nsAttemptResult) egressProbeCheck {
	evidence := evidenceObserved
	if r.Status == nsToolMissing {
		evidence = evidenceNotProbed
	}
	return egressProbeCheck{
		ID:       id,
		Category: category,
		Status:   r.Status,
		Evidence: evidence,
		Detail:   r.Detail,
	}
}

func presenceCheck(id, category string, ok bool, presentDetail, absentDetail string) egressProbeCheck {
	if ok {
		return egressProbeCheck{
			ID:       id,
			Category: category,
			Status:   "available",
			Evidence: evidenceObserved,
			Detail:   presentDetail,
		}
	}
	return egressProbeCheck{
		ID:       id,
		Category: category,
		Status:   "unavailable",
		Evidence: evidenceObserved,
		Detail:   absentDetail,
	}
}

func renderEgressProbeJSON(w io.Writer, report egressProbeReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func renderEgressProbeHuman(w io.Writer, report egressProbeReport) {
	fmt.Fprintf(w, "NockLock egress-probe (%s)\n", report.Schema)
	host := report.Host
	fmt.Fprintf(w, "Host: %s/%s", host.OS, host.Arch)
	if host.KernelRelease != "" {
		fmt.Fprintf(w, " kernel %s", host.KernelRelease)
	}
	if host.Distro != "" {
		fmt.Fprintf(w, " (%s)", host.Distro)
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w)

	currentCategory := ""
	for _, check := range report.Checks {
		if check.Category != currentCategory {
			if currentCategory != "" {
				fmt.Fprintln(w)
			}
			currentCategory = check.Category
			fmt.Fprintf(w, "%s\n", check.Category)
		}
		fmt.Fprintf(w, "  %s [%s] (%s): %s\n", check.ID, check.Status, check.Evidence, check.Detail)
	}
	fmt.Fprintf(w, "\nTRACK: %s\n", report.Track)
}

// goarch is a tiny indirection so the platform default-caps builders share one
// arch source.
func goarch() string { return runtime.GOARCH }

// scanKernelConfigForSymbol scans a kernel .config-format stream (plain text,
// e.g. /proc/config.gz already gunzipped, or /boot/config-<release>) for a
// CONFIG_* symbol and reports whether it is enabled (=y or =m) and whether the
// symbol was addressed at all (either "SYMBOL=value" or the kconfig
// "# SYMBOL is not set" convention). found=false means the config source did
// not mention the symbol either way — the caller must not treat that as a
// confirmed absence.
func scanKernelConfigForSymbol(r io.Reader, symbol string) (enabled, found bool) {
	scanner := bufio.NewScanner(r)
	prefix := symbol + "="
	notSet := "# " + symbol + " is not set"
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if v, ok := strings.CutPrefix(line, prefix); ok {
			v = strings.TrimSpace(v)
			return v == "y" || v == "m", true
		}
		if line == notSet {
			return false, true
		}
	}
	return false, false
}

// looksLikeUnshareUsageError reports whether unshare's failure output looks
// like a tool/flag incompatibility (e.g. util-linux too old to know
// --map-root-user) rather than a kernel capability denial. Denials look like
// "unshare: unshare failed: Operation not permitted" or "uid_map: ...";
// usage errors print an "unrecognized/invalid/unknown option" diagnostic and a
// usage synopsis. Misclassifying the former as a denial would report a hard
// kernel block where the real cause is a missing flag on this host's unshare
// build.
// unshareUsageMarkers are substrings that mark unshare's failure output as a
// tool/flag incompatibility rather than a kernel capability denial.
var unshareUsageMarkers = []string{
	"unrecognized option",
	"invalid option",
	"unknown option",
	"option requires an argument",
	"try 'unshare --help'",
	"try 'unshare -h'",
}

func looksLikeUnshareUsageError(output string) bool {
	lower := strings.ToLower(output)
	for _, marker := range unshareUsageMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
