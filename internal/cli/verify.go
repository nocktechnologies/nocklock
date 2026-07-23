package cli

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/fence/syscallfence"
	"github.com/spf13/cobra"
)

type verifyResult string

const (
	verifyPass verifyResult = "PASS"
	verifyFail verifyResult = "FAIL"
	verifySkip verifyResult = "SKIP"
)

type verifyCheck struct {
	Fence  string       `json:"fence"`
	Result verifyResult `json:"result"`
	Detail string       `json:"detail"`
}

type verifySummary struct {
	Passed  int `json:"passed"`
	Failed  int `json:"failed"`
	Skipped int `json:"skipped"`
}

type verifyReport struct {
	Checks  []verifyCheck `json:"checks"`
	Summary verifySummary `json:"summary"`
}

type probeRunner func(context.Context, *config.Config, string, string, map[string]string) (probeResult, error)

var currentProbeRunner probeRunner = runProbeUnderWrap
var verifyFilesystemBackend = findLibFenceFS

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Run adversarial self-tests against configured fences",
	Long: "Run benign proof-of-block probes under the same fenced child path used by wrap.\n\n" +
		"Probes never exfiltrate, never write outside a temp dir, and never touch real secrets: " +
		"they read a self-created non-secret canary, dial invalid/example hosts, check a canary " +
		"environment variable is absent, and attempt one side-effect-free denied syscall.",
	RunE: func(cmd *cobra.Command, args []string) error {
		asJSON, _ := cmd.Flags().GetBool("json")
		report, err := runVerify(cmd.Context(), currentDoctorCapabilities, currentProbeRunner)
		if err != nil {
			cmd.SilenceUsage = true
			return err
		}
		if asJSON {
			if err := renderVerifyJSON(cmd.OutOrStdout(), report); err != nil {
				return err
			}
		} else {
			renderVerifyHuman(cmd.OutOrStdout(), report)
		}
		if report.Summary.Failed > 0 {
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			return &exitCodeError{code: 1}
		}
		return nil
	},
}

func init() {
	verifyCmd.Flags().Bool("json", false, "emit structured JSON output")
	rootCmd.AddCommand(verifyCmd)
}

func runVerify(ctx context.Context, caps doctorCapabilities, runner probeRunner) (verifyReport, error) {
	configPath, err := config.FindConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return verifyReport{}, fmt.Errorf("no NockLock config found. Run 'nocklock init' first")
		}
		return verifyReport{}, fmt.Errorf("config lookup failed: %w", err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return verifyReport{}, err
	}
	projectRoot := filepath.Dir(filepath.Dir(configPath))
	checks := make([]verifyCheck, 0, 4)
	skipped := map[string]string{}
	for _, fence := range []string{"filesystem", "network", "secret", "syscall"} {
		if skip, detail := verifySkipReason(fence, cfg, caps); skip {
			skipped[fence] = detail
			checks = append(checks, verifyCheck{Fence: fence, Result: verifySkip, Detail: detail})
			continue
		}
		probeCfg := cloneVerifyConfig(cfg)
		disableSkippedFences(&probeCfg, skipped)
		env, cleanup, prepErr := prepareProbeEnv(fence, &probeCfg, projectRoot)
		if prepErr != nil {
			checks = append(checks, verifyCheck{Fence: fence, Result: verifyFail, Detail: prepErr.Error()})
			continue
		}
		if cleanup != nil {
			defer cleanup()
		}
		result, runErr := runner(ctx, &probeCfg, configPath, fence, env)
		checks = append(checks, verifyCheckFromProbe(fence, result, runErr))
	}
	return finishVerifyReport(checks), nil
}

func verifySkipReason(fence string, cfg *config.Config, caps doctorCapabilities) (bool, string) {
	switch fence {
	case "filesystem":
		check := filesystemDoctorCheck(cfg, caps)
		if cfg.Filesystem.Root == "" {
			return true, check.Message
		}
		if check.Severity == doctorCritical {
			return true, check.Message
		}
		if runtime.GOOS == "linux" && linuxEnforcementMode(cfg.Filesystem.LinuxEnforcement) == linuxEnforcementOff {
			return true, "Filesystem kernel enforcement is off by config."
		}
		if runtime.GOOS == "linux" {
			if _, err := verifyFilesystemBackend(); err != nil {
				return true, fmt.Sprintf("Filesystem userspace backend is unavailable: %v", err)
			}
		}
	case "network":
		check := networkDoctorCheck(cfg, caps)
		if cfg.Network.AllowAll {
			return true, check.Message
		}
		if check.Severity == doctorCritical {
			return true, check.Message
		}
	case "secret":
		return false, ""
	case "syscall":
		check := syscallDoctorCheck(cfg, caps)
		if syscallEnforcementMode(cfg.Syscall.Enforcement) == syscallfence.ModeOff {
			return true, check.Message
		}
		if check.Severity == doctorCritical {
			return true, check.Message
		}
	}
	return false, ""
}

func cloneVerifyConfig(cfg *config.Config) config.Config {
	out := *cfg
	out.Filesystem.Allow = append([]string(nil), cfg.Filesystem.Allow...)
	out.Filesystem.Deny = append([]string(nil), cfg.Filesystem.Deny...)
	out.Network.Allow = append([]string(nil), cfg.Network.Allow...)
	out.Secrets.Pass = append([]string(nil), cfg.Secrets.Pass...)
	out.Secrets.Block = append([]string(nil), cfg.Secrets.Block...)
	out.Syscall.SocketFamilies = append([]string(nil), cfg.Syscall.SocketFamilies...)
	out.Syscall.ExtraDeny = append([]string(nil), cfg.Syscall.ExtraDeny...)
	return out
}

func disableSkippedFences(cfg *config.Config, skipped map[string]string) {
	if _, ok := skipped["filesystem"]; ok {
		cfg.Filesystem.Root = ""
	}
	if _, ok := skipped["network"]; ok {
		cfg.Network.AllowAll = true
	}
	if _, ok := skipped["syscall"]; ok {
		cfg.Syscall.Enforcement = "off"
	}
}

func prepareProbeEnv(fence string, cfg *config.Config, projectRoot string) (map[string]string, func(), error) {
	env := map[string]string{}
	switch fence {
	case "filesystem":
		path, cleanup, err := createFilesystemCanary(cfg, projectRoot)
		if err != nil {
			return nil, nil, err
		}
		env[verifyCanaryPathEnv] = path
		return env, cleanup, nil
	case "secret":
		env[verifySecretName] = randomHex(16)
		cfg.Secrets.Block = appendUnique(cfg.Secrets.Block, verifySecretName)
		return env, nil, nil
	default:
		return env, nil, nil
	}
}

func verifyCheckFromProbe(fence string, result probeResult, err error) verifyCheck {
	if result.Detail == "" && err != nil {
		result.Detail = err.Error()
	}
	if err != nil && !result.Attempted {
		return verifyCheck{Fence: fence, Result: verifyFail, Detail: firstNonEmpty(result.Detail, "probe failed before attempting escape")}
	}
	if !result.Attempted {
		return verifyCheck{Fence: fence, Result: verifySkip, Detail: firstNonEmpty(result.Detail, "probe was not attempted")}
	}
	if result.Blocked && err == nil {
		return verifyCheck{Fence: fence, Result: verifyPass, Detail: result.Detail}
	}
	return verifyCheck{Fence: fence, Result: verifyFail, Detail: firstNonEmpty(result.Detail, "probe escaped")}
}

func runProbeUnderWrap(ctx context.Context, cfg *config.Config, configPath, fence string, extraEnv map[string]string) (probeResult, error) {
	tmp, err := os.MkdirTemp("", "nocklock-verify-config-*")
	if err != nil {
		return probeResult{Fence: fence}, err
	}
	defer os.RemoveAll(tmp)
	tmpNock := filepath.Join(tmp, config.Dir)
	if err := os.MkdirAll(tmpNock, 0o755); err != nil {
		return probeResult{Fence: fence}, err
	}
	cfgCopy := *cfg
	absolutizeConfigPaths(&cfgCopy, filepath.Dir(filepath.Dir(configPath)))
	cfgCopy.Logging.DB = filepath.Join(tmp, config.Dir, "events.db")
	cfgCopy.Cloud.APIKey = ""
	tmpConfig := filepath.Join(tmpNock, config.File)
	if err := writeConfigTOML(tmpConfig, &cfgCopy); err != nil {
		return probeResult{Fence: fence}, err
	}
	exe, err := os.Executable()
	if err != nil {
		return probeResult{Fence: fence}, err
	}
	childCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(childCtx, exe, "wrap", "--", exe, "__probe", fence)
	cmd.Dir = tmp
	cmd.Env = os.Environ()
	for key, value := range extraEnv {
		cmd.Env = append(removeEnvVars(cmd.Env, key), key+"="+value)
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	result := probeResult{Fence: fence}
	if decodeErr := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &result); decodeErr != nil {
		if err != nil {
			return result, fmt.Errorf("%v: %s", err, strings.TrimSpace(stderr.String()))
		}
		return result, fmt.Errorf("invalid probe output: %w", decodeErr)
	}
	if err != nil && result.Blocked {
		return result, nil
	}
	return result, err
}

func absolutizeConfigPaths(cfg *config.Config, projectRoot string) {
	cfg.Project.Root = absConfigPath(projectRoot, cfg.Project.Root)
	cfg.Filesystem.Root = absConfigPath(projectRoot, cfg.Filesystem.Root)
	cfg.Filesystem.Allow = absConfigPathList(projectRoot, cfg.Filesystem.Allow)
	cfg.Filesystem.Deny = absConfigPathList(projectRoot, cfg.Filesystem.Deny)
	cfg.Logging.DB = absConfigPath(projectRoot, cfg.Logging.DB)
}

func absConfigPathList(base string, paths []string) []string {
	out := make([]string, len(paths))
	for i, p := range paths {
		out[i] = absConfigPath(base, p)
	}
	return out
}

func absConfigPath(base, p string) string {
	if p == "" || strings.HasPrefix(p, "~") || filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(base, p)
}

func writeConfigTOML(path string, cfg *config.Config) error {
	var buf bytes.Buffer
	if err := toml.NewEncoder(&buf).Encode(cfg); err != nil {
		return err
	}
	return os.WriteFile(path, buf.Bytes(), 0o644)
}

func createFilesystemCanary(cfg *config.Config, projectRoot string) (string, func(), error) {
	allowed := filesystemAllowedRoots(cfg, projectRoot)
	if path, cleanup, ok := createCanaryOutside(allowed); ok {
		return path, cleanup, nil
	}
	rootOnly := filesystemRootOnly(cfg, projectRoot)
	if path, cleanup, ok := createCanaryOutside(rootOnly); ok {
		return path, cleanup, nil
	}
	return "", nil, fmt.Errorf("could not create filesystem canary outside configured root")
}

func createCanaryOutside(roots []string) (string, func(), bool) {
	for _, base := range []string{"/var/tmp", "/dev/shm", os.TempDir()} {
		if base == "" || pathWithinAny(base, roots) {
			continue
		}
		dir, err := os.MkdirTemp(base, "nocklock-verify-*")
		if err != nil {
			continue
		}
		path := filepath.Join(dir, "canary.txt")
		if err := os.WriteFile(path, []byte("nocklock verify canary\n"), 0o600); err != nil {
			os.RemoveAll(dir)
			continue
		}
		return path, func() { os.RemoveAll(dir) }, true
	}
	return "", nil, false
}

func filesystemAllowedRoots(cfg *config.Config, projectRoot string) []string {
	paths := append([]string{cfg.Filesystem.Root}, cfg.Filesystem.Allow...)
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		p = absConfigPath(projectRoot, p)
		if resolved, err := filepath.EvalSymlinks(p); err == nil {
			p = resolved
		}
		out = append(out, filepath.Clean(p))
	}
	return out
}

func filesystemRootOnly(cfg *config.Config, projectRoot string) []string {
	root := absConfigPath(projectRoot, cfg.Filesystem.Root)
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	return []string{filepath.Clean(root)}
}

func pathWithinAny(path string, roots []string) bool {
	clean := filepath.Clean(path)
	if resolved, err := filepath.EvalSymlinks(clean); err == nil {
		clean = resolved
	}
	for _, root := range roots {
		if root == "" {
			continue
		}
		if clean == root {
			return true
		}
		rel, err := filepath.Rel(root, clean)
		if err == nil && rel != ".." && !strings.HasPrefix(rel, "../") {
			return true
		}
	}
	return false
}

func finishVerifyReport(checks []verifyCheck) verifyReport {
	var summary verifySummary
	for _, check := range checks {
		switch check.Result {
		case verifyPass:
			summary.Passed++
		case verifyFail:
			summary.Failed++
		case verifySkip:
			summary.Skipped++
		}
	}
	return verifyReport{Checks: checks, Summary: summary}
}

func renderVerifyJSON(w io.Writer, report verifyReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}

func renderVerifyHuman(w io.Writer, report verifyReport) {
	for _, check := range report.Checks {
		fmt.Fprintf(w, "[%s] %s: %s\n", check.Result, check.Fence, check.Detail)
	}
	fmt.Fprintf(w, "\nSummary: %d passed, %d failed, %d skipped\n", report.Summary.Passed, report.Summary.Failed, report.Summary.Skipped)
}

func randomHex(n int) string {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func appendUnique(values []string, value string) []string {
	for _, existing := range values {
		if existing == value {
			return values
		}
	}
	return append(values, value)
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
