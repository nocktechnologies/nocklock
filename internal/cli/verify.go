package cli

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/fence/syscallfence"
	"github.com/nocktechnologies/nocklock/internal/logging"
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
var verifyPositiveControlRunner = runProbePositiveControl

var verifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Run adversarial self-tests against configured fences",
	Long: "Run benign proof-of-block probes under the same fenced child path used by wrap.\n\n" +
		"Probes never exfiltrate, never write outside a temp dir, and never touch real secrets: " +
		"they read a self-created non-secret canary, dial invalid/example hosts, check a canary " +
		"environment variable is absent, and attempt one side-effect-free denied syscall.",
	RunE: func(cmd *cobra.Command, args []string) error {
		asJSON, _ := cmd.Flags().GetBool("json")
		asAudit, _ := cmd.Flags().GetBool("audit")
		exportPub, _ := cmd.Flags().GetBool("export-pubkey")
		pubFlag, _ := cmd.Flags().GetString("ed25519-pub")
		if exportPub {
			return runExportPubkey(cmd.OutOrStdout())
		}
		if asAudit {
			return runAuditVerify(cmd.Context(), cmd.OutOrStdout(), pubFlag)
		}
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
		if !verifyReportSucceeded(report) {
			cmd.SilenceErrors = true
			cmd.SilenceUsage = true
			return &exitCodeError{code: 1}
		}
		return nil
	},
}

func init() {
	verifyCmd.Flags().Bool("json", false, "emit structured JSON output")
	verifyCmd.Flags().Bool("audit", false, "verify the audit chain instead of running fence probes")
	verifyCmd.Flags().Bool("export-pubkey", false, "print the Ed25519 audit-log public key (base64) for out-of-band verification")
	verifyCmd.Flags().String("ed25519-pub", "", "Ed25519 public key (base64 or hex) to verify signatures against; overrides the local key file")
	rootCmd.AddCommand(verifyCmd)
}

func runAuditVerify(ctx context.Context, w io.Writer, pubFlag string) error {
	configPath, err := config.FindConfig()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("no NockLock config found. Run 'nocklock init' first")
		}
		return fmt.Errorf("config lookup failed: %w", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		return err
	}

	// Get the logging DB path from config
	if cfg.Logging.DB == "" {
		return fmt.Errorf("no logging DB configured")
	}

	dbPath := cfg.Logging.DB
	projectRoot := filepath.Dir(filepath.Dir(configPath))

	// Make path absolute if relative
	if !filepath.IsAbs(dbPath) {
		dbPath = filepath.Join(projectRoot, dbPath)
	}

	// Open the logger (will error if DB doesn't exist)
	if _, err := os.Stat(dbPath); err != nil {
		return fmt.Errorf("event log not found at %s: %w", dbPath, err)
	}

	// Resolve a public key for authenticity checking. An explicit --ed25519-pub
	// wins; otherwise derive it from the local signing key file if one exists.
	// No key at all means a hash-only (CONSISTENCY) verification.
	pub, err := resolveVerifyPublicKey(pubFlag)
	if err != nil {
		return err
	}

	logger, err := logging.NewLogger(dbPath, projectRoot)
	if err != nil {
		return fmt.Errorf("failed to open event log: %w", err)
	}
	defer logger.Close()

	// Verify the chain (signature-aware when a key is available).
	result, err := logger.VerifyChainSigned(pub)
	if err != nil {
		return fmt.Errorf("verification failed: %w", err)
	}

	// Format and print output
	return writeAuditVerifyResult(w, result)
}

// resolveVerifyPublicKey returns the Ed25519 public key to verify against, or
// nil for a hash-only check. A supplied key (base64 or hex) overrides the local
// key file; a missing key file is not an error (falls back to nil).
func resolveVerifyPublicKey(pubFlag string) (ed25519.PublicKey, error) {
	if pubFlag != "" {
		pub, err := logging.ParsePublicKey(pubFlag)
		if err != nil {
			return nil, fmt.Errorf("invalid --ed25519-pub: %w", err)
		}
		return pub, nil
	}
	keyPath, err := logging.DefaultSigningKeyPath()
	if err != nil {
		return nil, nil
	}
	pub, err := logging.LoadPublicKeyFile(keyPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to load signing public key from %s: %w", keyPath, err)
	}
	return pub, nil
}

// signingLoggerOpts returns the Logger options that enable Ed25519 signing with
// the NockLock-managed key. If the key path cannot be resolved it returns no
// options, degrading to an unsigned (hash-only) open rather than failing.
func signingLoggerOpts() []logging.Option {
	keyPath, err := logging.DefaultSigningKeyPath()
	if err != nil {
		return nil
	}
	return []logging.Option{logging.WithSigning(keyPath)}
}

// runExportPubkey prints the base64 Ed25519 audit-log public key. The key is
// generated on first use if absent; the private key is never printed.
func runExportPubkey(w io.Writer) error {
	keyPath, err := logging.DefaultSigningKeyPath()
	if err != nil {
		return fmt.Errorf("cannot resolve signing key path: %w", err)
	}
	pub, err := logging.EnsurePublicKeyFile(keyPath)
	if err != nil {
		return fmt.Errorf("failed to load signing public key: %w", err)
	}
	fmt.Fprintf(w, "ed25519 %s\n", logging.EncodePublicKey(pub))
	return nil
}

// writeAuditVerifyResult renders a chain verification result. An intact chain
// prints the CONSISTENT verdict, followed by a NOTE for any migration boundary
// and any prune boundary — so a compaction of the log can never read back as
// untouched history. A broken chain prints the TAMPERED verdict and returns a
// non-zero exit.
func writeAuditVerifyResult(w io.Writer, result *logging.ChainVerifyResult) error {
	// A broken hash chain is TAMPERED regardless of signatures.
	if !result.Intact {
		fmt.Fprintf(w, "AUDIT: TAMPERED — chain breaks at entry %d (%s)\n", result.FirstBrokenID, result.BrokenReason)
		return &exitCodeError{code: 1}
	}

	// A signature that does not verify is FORGED. Never conflated with a clean
	// unsigned pass: the hash chain here is intact, but authenticity failed.
	if result.SigState == "forged" {
		where := "chain_head"
		if result.SigBrokenID != 0 {
			where = fmt.Sprintf("entry %d", result.SigBrokenID)
		}
		fmt.Fprintf(w, "AUDIT: FORGED — hash chain intact but signature check failed at %s (%s)\n", where, result.SigBrokenReason)
		return &exitCodeError{code: 1}
	}

	if result.SigState == "authentic" {
		fmt.Fprintf(w, "AUDIT: AUTHENTIC — %d entries verified, %d Ed25519-signed and valid, chain_head signature valid\n", result.EntriesVerified, result.SigVerified)
		if result.SignedGenesisAt != nil && result.UnsignedEntries > 0 {
			fmt.Fprintf(w, "NOTE: entries 1..%d predate signing adoption (%s); consistent but unsigned, not authenticated.\n", result.UnsignedThroughID, result.SignedGenesisAt.Format(time.RFC3339))
		}
		writeAuditBoundaryNotes(w, result)
		fmt.Fprintf(w, "Head hash: %s\n", result.HeadHash)
		return nil
	}

	// SigState is "" (hash-only requested), "unsigned", or "unverified": the
	// hash chain is internally consistent but authenticity is NOT established.
	fmt.Fprintf(w, "AUDIT: CONSISTENT — %d entries verified, hash chain intact (not externally anchored)\n", result.EntriesVerified)
	if result.SigState == "unverified" {
		fmt.Fprintf(w, "NOTE: %d entries carry Ed25519 signatures but no public key was supplied; authenticity NOT checked (pass --ed25519-pub or run on the signing host).\n", result.SignedEntries)
	} else if result.PubKeyProvided && result.SignedEntries == 0 {
		fmt.Fprintln(w, "NOTE: no entries are signed; this proves internal consistency only, not that NockLock recorded them.")
	}
	writeAuditBoundaryNotes(w, result)
	fmt.Fprintf(w, "Head hash: %s\n", result.HeadHash)
	return nil
}

// writeAuditBoundaryNotes prints the migration and prune boundary notes shared
// by every non-tampered verdict.
func writeAuditBoundaryNotes(w io.Writer, result *logging.ChainVerifyResult) {
	if result.MigratedAt != nil {
		fmt.Fprintf(w, "NOTE: entries 1..%d predate the chain (migrated %s); structurally chained, not authenticated.\n", result.LegacyThroughID, result.MigratedAt.Format(time.RFC3339))
	}
	if result.PrunedAt != nil {
		fmt.Fprintf(w, "NOTE: chain was re-anchored by a prune at %s; %d event(s) were removed in that prune and history before it is not retained.\n", result.PrunedAt.Format(time.RFC3339), result.PrunedCount)
	}
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
		isolateProbeFence(fence, &probeCfg)
		env, cleanup, prepErr := prepareProbeEnv(fence, &probeCfg, projectRoot)
		if prepErr != nil {
			checks = append(checks, verifyCheck{Fence: fence, Result: verifyFail, Detail: prepErr.Error()})
			continue
		}
		if cleanup != nil {
			defer cleanup()
		}
		if requiresPositiveControl(fence) {
			if err := verifyPositiveControlRunner(ctx, fence, env); err != nil {
				checks = append(checks, verifyCheck{Fence: fence, Result: verifyFail, Detail: err.Error()})
				continue
			}
		}
		if fence == "filesystem" {
			env[verifyCanaryKnownEnv] = "1"
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

func requiresPositiveControl(fence string) bool {
	switch fence {
	case "filesystem", "secret", "syscall":
		return true
	default:
		return false
	}
}

func isolateProbeFence(fence string, cfg *config.Config) {
	if fence == "network" {
		cfg.Syscall.Enforcement = "off"
	}
}

func prepareProbeEnv(fence string, cfg *config.Config, projectRoot string) (map[string]string, func(), error) {
	env := map[string]string{}
	switch fence {
	case "filesystem":
		path, token, cleanup, err := createFilesystemCanary(cfg, projectRoot)
		if err != nil {
			return nil, nil, err
		}
		env[verifyCanaryPathEnv] = path
		env[verifyCanaryTokenEnv] = token
		return env, cleanup, nil
	case "network":
		target, err := selectOffAllowlistNetworkTarget(cfg)
		if err != nil {
			return nil, nil, err
		}
		env[verifyNetworkURLEnv] = target
		return env, nil, nil
	case "secret":
		env[verifySecretName] = randomHex(16)
		env[verifySecretControlName] = randomHex(16)
		cfg.Secrets.Block = appendUnique(cfg.Secrets.Block, verifySecretName)
		return env, nil, nil
	default:
		return env, nil, nil
	}
}

func runProbePositiveControl(ctx context.Context, fence string, extraEnv map[string]string) error {
	exe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("%s positive control setup failed: %w", fence, err)
	}
	childCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(childCtx, exe, "__probe", fence)
	cmd.Env = envWithOverrides(os.Environ(), extraEnv)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	var result probeResult
	if decodeErr := json.Unmarshal(bytes.TrimSpace(stdout.Bytes()), &result); decodeErr != nil {
		if runErr != nil {
			return fmt.Errorf("%s positive control failed: %v: %s", fence, runErr, strings.TrimSpace(stderr.String()))
		}
		return fmt.Errorf("%s positive control produced invalid output: %w", fence, decodeErr)
	}
	if !result.Attempted {
		return fmt.Errorf("%s positive control was inconclusive: %s", fence, result.Detail)
	}
	if result.Blocked {
		return fmt.Errorf("%s positive control was blocked before the fence: %s", fence, result.Detail)
	}
	return nil
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
	cmd.Env = envWithOverrides(os.Environ(), extraEnv)
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

func envWithOverrides(base []string, overrides map[string]string) []string {
	out := append([]string(nil), base...)
	for key, value := range overrides {
		out = append(removeEnvVars(out, key), key+"="+value)
	}
	return out
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

func createFilesystemCanary(cfg *config.Config, projectRoot string) (string, string, func(), error) {
	allowed := filesystemAllowedRoots(cfg, projectRoot)
	if path, token, cleanup, ok := createCanaryOutside(allowed); ok {
		return path, token, cleanup, nil
	}
	rootOnly := filesystemRootOnly(cfg, projectRoot)
	if path, token, cleanup, ok := createCanaryOutside(rootOnly); ok {
		return path, token, cleanup, nil
	}
	return "", "", nil, fmt.Errorf("could not create filesystem canary outside configured root")
}

func createCanaryOutside(roots []string) (string, string, func(), bool) {
	for _, base := range []string{"/var/tmp", "/dev/shm", os.TempDir()} {
		if base == "" || pathWithinAny(base, roots) {
			continue
		}
		dir, err := os.MkdirTemp(base, "nocklock-verify-*")
		if err != nil {
			continue
		}
		path := filepath.Join(dir, "canary.txt")
		token := randomHex(16)
		if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
			os.RemoveAll(dir)
			continue
		}
		if data, err := os.ReadFile(path); err != nil || strings.TrimSpace(string(data)) != token {
			os.RemoveAll(dir)
			continue
		}
		return path, token, func() { os.RemoveAll(dir) }, true
	}
	return "", "", nil, false
}

func selectOffAllowlistNetworkTarget(cfg *config.Config) (string, error) {
	for _, target := range []string{
		"http://verify.nocklock.invalid",
		"http://nocklock-verify.invalid",
		"http://nocklock-verify-canary.test",
	} {
		u, err := url.Parse(target)
		if err != nil {
			continue
		}
		if !networkHostAllowed(u.Host, cfg.Network.Allow) {
			return target, nil
		}
	}
	return "", fmt.Errorf("could not select an off-allowlist network canary target")
}

func networkHostAllowed(hostname string, allowlist []string) bool {
	host := hostname
	if h, _, err := net.SplitHostPort(hostname); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	if net.ParseIP(host) != nil {
		return false
	}
	for _, entry := range allowlist {
		entry = strings.ToLower(entry)
		if strings.HasPrefix(entry, "*.") {
			if strings.HasSuffix(host, entry[1:]) {
				return true
			}
			continue
		}
		if host == entry || strings.HasSuffix(host, "."+entry) {
			return true
		}
	}
	return false
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

func verifyReportSucceeded(report verifyReport) bool {
	return report.Summary.Failed == 0 && report.Summary.Passed > 0
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
