package cli

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
	"github.com/spf13/cobra"
)

// TestRemoveEnvVars covers the removeEnvVars helper used to clear NO_PROXY.
func TestRemoveEnvVarsRemovesMatchingKeys(t *testing.T) {
	env := []string{
		"HOME=/home/user",
		"NO_PROXY=localhost",
		"no_proxy=127.0.0.1",
		"PATH=/usr/bin",
	}
	result := removeEnvVars(env, "NO_PROXY", "no_proxy")

	for _, entry := range result {
		if strings.HasPrefix(entry, "NO_PROXY=") || strings.HasPrefix(entry, "no_proxy=") {
			t.Errorf("removeEnvVars left %q in result", entry)
		}
	}
	if len(result) != 2 {
		t.Errorf("expected 2 remaining entries, got %d: %v", len(result), result)
	}
}

func TestRemoveEnvVarsPreservesOtherVars(t *testing.T) {
	env := []string{"HOME=/home/user", "PATH=/usr/bin", "TERM=xterm"}
	result := removeEnvVars(env, "NO_PROXY")
	if len(result) != len(env) {
		t.Errorf("expected %d entries unchanged, got %d", len(env), len(result))
	}
}

func TestRemoveEnvVarsEmptyInput(t *testing.T) {
	result := removeEnvVars(nil, "NO_PROXY")
	if len(result) != 0 {
		t.Errorf("expected empty result, got %v", result)
	}
}

func TestRemoveEnvVarsNoKeysSpecified(t *testing.T) {
	env := []string{"A=1", "B=2"}
	result := removeEnvVars(env)
	if len(result) != 2 {
		t.Errorf("expected 2 entries with no keys to remove, got %d", len(result))
	}
}

func TestRemoveEnvVarsExactKeyWithoutEquals(t *testing.T) {
	// An env entry without "=" is unusual but should match on bare key.
	env := []string{"WEIRD_ENTRY", "NORMAL=value"}
	result := removeEnvVars(env, "WEIRD_ENTRY")
	if len(result) != 1 || result[0] != "NORMAL=value" {
		t.Errorf("expected only NORMAL=value, got %v", result)
	}
}

// fsAllowedEntries returns every NOCKLOCK_FS_ALLOWED=... entry in env, in order.
func fsAllowedEntries(env []string) []string {
	var out []string
	for _, e := range env {
		if strings.HasPrefix(e, fsfence.EnvFSAllowed+"=") {
			out = append(out, e)
		}
	}
	return out
}

// TestMergeFSFenceEnvStripsInheritedFSAllowed is the N8185 regression test.
//
// The userspace filesystem fence reads its policy from a SINGLE env var,
// NOCKLOCK_FS_ALLOWED, via glibc getenv() in the LD_PRELOAD interposer. glibc
// getenv() returns the FIRST matching entry in the child environment block.
// childEnv is built from secrets.Filter(os.Environ()), so an attacker who sets
// NOCKLOCK_FS_ALLOWED in the parent environment lands an entry that sits EARLIER
// in childEnv than the fence's own value — and therefore wins, forging an
// allow-all (root=/ rw) policy and silently neutering the fence.
//
// mergeFSFenceEnv must strip any inherited NOCKLOCK_FS_ALLOWED before appending
// the fence's own, so exactly ONE entry remains and it is the fence's.
func TestMergeFSFenceEnvStripsInheritedFSAllowed(t *testing.T) {
	const attacker = "/=rw" // forged allow-all the attacker tries to inject
	const fenceVal = "/srv/project=ro;sock=/tmp/fence.sock"

	childEnv := []string{
		"HOME=/home/agent",
		fsfence.EnvFSAllowed + "=" + attacker, // inherited / attacker-controlled
		"PATH=/usr/bin",
	}
	fenceEnv := []string{
		fsfence.EnvLDPreload + "=/usr/local/lib/nocklock/libfence_fs.so",
		fsfence.EnvFSAllowed + "=" + fenceVal,
	}

	merged := mergeFSFenceEnv(childEnv, fenceEnv)

	got := fsAllowedEntries(merged)
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 %s entry after merge, got %d: %v",
			fsfence.EnvFSAllowed, len(got), got)
	}
	want := fsfence.EnvFSAllowed + "=" + fenceVal
	if got[0] != want {
		t.Fatalf("effective %s = %q, want the fence's value %q (inherited attacker value not stripped)",
			fsfence.EnvFSAllowed, got[0], want)
	}
	for _, e := range merged {
		if e == fsfence.EnvFSAllowed+"="+attacker {
			t.Fatalf("inherited attacker %s=%s survived the merge: %v",
				fsfence.EnvFSAllowed, attacker, merged)
		}
	}
}

// TestMergeFSFenceEnvMergesInheritedLDPreload guards the LD_PRELOAD merge
// behavior the fix must preserve: a legitimately inherited LD_PRELOAD is kept
// but the fence library is loaded FIRST (prepended), and there is still exactly
// one LD_PRELOAD entry.
func TestMergeFSFenceEnvMergesInheritedLDPreload(t *testing.T) {
	const fenceLib = "/usr/local/lib/nocklock/libfence_fs.so"
	const inherited = "/opt/other/libthing.so"

	childEnv := []string{
		"HOME=/home/agent",
		fsfence.EnvLDPreload + "=" + inherited,
	}
	fenceEnv := []string{
		fsfence.EnvLDPreload + "=" + fenceLib,
		fsfence.EnvFSAllowed + "=/srv=ro",
	}

	merged := mergeFSFenceEnv(childEnv, fenceEnv)

	var ld []string
	for _, e := range merged {
		if strings.HasPrefix(e, fsfence.EnvLDPreload+"=") {
			ld = append(ld, e)
		}
	}
	if len(ld) != 1 {
		t.Fatalf("expected exactly 1 %s entry, got %d: %v", fsfence.EnvLDPreload, len(ld), ld)
	}
	want := fsfence.EnvLDPreload + "=" + fenceLib + ":" + inherited
	if ld[0] != want {
		t.Fatalf("merged %s = %q, want %q (fence lib must load first, inherited preserved)",
			fsfence.EnvLDPreload, ld[0], want)
	}
}

// TestMergeFSFenceEnvNoInheritedValues confirms the common, clean case: with no
// inherited fence vars the fence's LD_PRELOAD and FS_ALLOWED are simply added.
func TestMergeFSFenceEnvNoInheritedValues(t *testing.T) {
	childEnv := []string{"HOME=/home/agent", "PATH=/usr/bin"}
	fenceEnv := []string{
		fsfence.EnvLDPreload + "=/usr/local/lib/nocklock/libfence_fs.so",
		fsfence.EnvFSAllowed + "=/srv=ro",
	}

	merged := mergeFSFenceEnv(childEnv, fenceEnv)

	if entries := fsAllowedEntries(merged); len(entries) != 1 {
		t.Fatalf("expected 1 %s entry, got %v", fsfence.EnvFSAllowed, entries)
	}
	var ldCount int
	for _, e := range merged {
		if strings.HasPrefix(e, fsfence.EnvLDPreload+"=") {
			ldCount++
		}
	}
	if ldCount != 1 {
		t.Fatalf("expected 1 %s entry, got %d", fsfence.EnvLDPreload, ldCount)
	}
}

func TestWrapDryRunValidatesConfigWithoutCommand(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, dryRunTestTOML())
	withWorkingDir(t, dir)

	cmd := &cobra.Command{}
	err := wrapCmd.RunE(cmd, []string{"--dry-run"})
	if err != nil {
		t.Fatalf("dry run should validate config without a child command: %v", err)
	}
}

// The audit trail is the product's core promise ("every fence decision is
// recorded"), so a logger that cannot open must FAIL CLOSED — the agent does not
// start — rather than silently continue unrecorded. Same posture as the network
// fence (the removed --allow-unfenced).
func TestWrapFailsClosedWhenEventLogCannotOpen(t *testing.T) {
	dir := t.TempDir()
	// Put a regular FILE where the log directory needs to be, so the logger's
	// MkdirAll fails and NewLogger returns an error — a portable way to force an
	// unopenable event log without relying on permission bits.
	if err := os.WriteFile(filepath.Join(dir, "blocker"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	toml := strings.Replace(dryRunTestTOML(), `db = ".nock/events.db"`, `db = "blocker/events.db"`, 1)
	if !strings.Contains(toml, "blocker/events.db") {
		t.Fatal("test setup: failed to redirect the log db path")
	}
	writeTestConfig(t, dir, toml)
	withWorkingDir(t, dir)

	cmd := &cobra.Command{}
	err := wrapCmd.RunE(cmd, []string{"--", "true"})
	if err == nil {
		t.Fatal("wrap should fail closed when the event log cannot open, but returned nil")
	}
	if !strings.Contains(err.Error(), "event log") || !strings.Contains(err.Error(), "audit trail is required") {
		t.Fatalf("expected a fail-closed audit-log error, got: %v", err)
	}
}

func TestAuditDenyPath(t *testing.T) {
	root := t.TempDir()
	nock := filepath.Join(root, ".nock")
	if err := os.MkdirAll(nock, 0o755); err != nil {
		t.Fatal(err)
	}

	// Common case: db in a .nock subdir -> deny the whole audit dir (covers the
	// db and blocks rename/delete of the log).
	db := filepath.Join(nock, "events.db")
	if got := auditDenyPath(db, root); got != nock {
		t.Errorf("subdir case: auditDenyPath = %q, want %q", got, nock)
	}

	// Pathological: db directly in the project root -> deny only the file, never
	// the root itself.
	dbInRoot := filepath.Join(root, "events.db")
	if got := auditDenyPath(dbInRoot, root); got != dbInRoot {
		t.Errorf("root case: auditDenyPath = %q, want the file %q", got, dbInRoot)
	}
}

// TestLinuxEnforcementModePreferredFailsClosed verifies empty/preferred/required
// all resolve to required, while off remains off.
func TestLinuxEnforcementModePreferredFailsClosed(t *testing.T) {
	for _, raw := range []string{"", "preferred", "required"} {
		if got := linuxEnforcementMode(raw); got != linuxEnforcementRequired {
			t.Fatalf("linuxEnforcementMode(%q) = %q, want required", raw, got)
		}
	}
	if got := linuxEnforcementMode("off"); got != linuxEnforcementOff {
		t.Fatalf("linuxEnforcementMode(off) = %q, want off", got)
	}
}

// A symlinked project root must be recognized as the root via symlink resolution
// (macOS /tmp -> /private/tmp). Without it, a string compare would see the audit
// dir and the symlinked root as different and DENY THE WHOLE ROOT, breaking the
// agent. db sits directly in the real root; root is given as a symlink to it.
func TestAuditDenyPathSymlinkedRoot(t *testing.T) {
	realRoot := t.TempDir()
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(realRoot, link); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	db := filepath.Join(realRoot, "events.db")
	if got := auditDenyPath(db, link); got != db {
		t.Errorf("symlinked root not recognized: got %q, want the file %q (denying the root would break the agent)", got, db)
	}
}

func TestLandlockAuditAllowPaths(t *testing.T) {
	db := filepath.Join(t.TempDir(), ".nock", "events.db")
	paths := landlockAuditAllowPaths(db)
	want := []string{db, db + "-wal", db + "-shm", db + "-journal"}
	if len(paths) != len(want) {
		t.Fatalf("got %d paths, want %d: %+v", len(paths), len(want), paths)
	}
	for i := range want {
		if paths[i].Path != want[i] {
			t.Fatalf("path %d = %q, want %q", i, paths[i].Path, want[i])
		}
		if paths[i].Access != "read-write" {
			t.Fatalf("path %d access = %q, want read-write", i, paths[i].Access)
		}
	}
}

func TestFindTrustedLibFenceFSRejectsProjectRelativeLibrary(t *testing.T) {
	projectRoot := t.TempDir()
	projectLib := filepath.Join(projectRoot, "internal", "fence", "fs", "interposer", "libfence_fs.so")
	if err := os.MkdirAll(filepath.Dir(projectLib), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(projectLib, []byte("not a trusted shared library"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := findTrustedLibFenceFS(
		filepath.Join(t.TempDir(), "nocklock"),
		projectRoot,
		[]string{projectLib},
		func(path string) (bool, error) { return path == projectLib, nil },
	)
	if err == nil {
		t.Fatalf("expected project-relative libfence_fs.so to be rejected, got %q", got)
	}
	if got != "" {
		t.Fatalf("project-relative libfence_fs.so must never be selected for LD_PRELOAD, got %q", got)
	}
}

func TestFindTrustedLibFenceFSFailsClosedWhenNoTrustedLibraryExists(t *testing.T) {
	got, err := findTrustedLibFenceFS(
		filepath.Join(t.TempDir(), "nocklock"),
		t.TempDir(),
		nil,
		func(string) (bool, error) { return false, nil },
	)
	if err == nil {
		t.Fatalf("expected fail-closed error when no trusted libfence_fs.so exists, got %q", got)
	}
	if got != "" {
		t.Fatalf("expected no path when resolver fails closed, got %q", got)
	}
	if !strings.Contains(err.Error(), "trusted filesystem fence library not found") {
		t.Fatalf("expected actionable trusted-library error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "/usr/local/lib/nocklock/libfence_fs.so") ||
		!strings.Contains(err.Error(), "/usr/lib/nocklock/libfence_fs.so") ||
		!strings.Contains(err.Error(), "next to the nocklock binary") {
		t.Fatalf("expected error to list accepted install locations, got: %v", err)
	}
}

func TestFindTrustedLibFenceFSSelectsInstalledPath(t *testing.T) {
	installed := filepath.Join(t.TempDir(), "libfence_fs.so")
	got, err := findTrustedLibFenceFS(
		filepath.Join(t.TempDir(), "nocklock"),
		t.TempDir(),
		[]string{installed},
		func(path string) (bool, error) { return path == installed, nil },
	)
	if err != nil {
		t.Fatalf("expected installed trusted path to be selected: %v", err)
	}
	if got != installed {
		t.Fatalf("got %q, want %q", got, installed)
	}
}

func TestFindTrustedLibFenceFSAcceptsSystemPathFromRootWorkingDir(t *testing.T) {
	systemLib := filepath.Join(string(os.PathSeparator), "usr", "lib", "nocklock", "libfence_fs.so")
	got, err := findTrustedLibFenceFS(
		filepath.Join(t.TempDir(), "nocklock"),
		string(os.PathSeparator),
		nil,
		func(path string) (bool, error) { return path == systemLib, nil },
	)
	if err != nil {
		t.Fatalf("expected system libfence_fs.so to be accepted when cwd is filesystem root: %v", err)
	}
	if got != systemLib {
		t.Fatalf("got %q, want %q", got, systemLib)
	}
}

func TestFindTrustedLibFenceFSSurfacesStatErrors(t *testing.T) {
	statErr := os.ErrPermission
	got, err := findTrustedLibFenceFS(
		"",
		t.TempDir(),
		[]string{filepath.Join(t.TempDir(), "libfence_fs.so")},
		func(string) (bool, error) { return false, statErr },
	)
	if err == nil {
		t.Fatalf("expected stat error to fail closed, got %q", got)
	}
	if got != "" {
		t.Fatalf("expected no path when stat fails, got %q", got)
	}
	if !strings.Contains(err.Error(), "cannot inspect trusted filesystem fence library candidate") ||
		!strings.Contains(err.Error(), statErr.Error()) {
		t.Fatalf("expected actionable stat error, got: %v", err)
	}
}

func TestWrapDryRunRejectsMalformedConfig(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, "[network]\nallow_all = \"sometimes\"\n")
	withWorkingDir(t, dir)

	cmd := &cobra.Command{}
	err := wrapCmd.RunE(cmd, []string{"--dry-run"})
	if err == nil {
		t.Fatal("expected dry run to reject malformed config")
	}
	if !strings.Contains(err.Error(), "failed to load config") {
		t.Fatalf("expected config load error, got: %v", err)
	}
}

func TestWrapDryRunPrintsAllowPrivateRangesFlag(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, dryRunTestTOML())
	withWorkingDir(t, dir)

	cmd := &cobra.Command{}
	var runErr error
	stdout := captureStdout(t, func() {
		runErr = wrapCmd.RunE(cmd, []string{"--dry-run", "--allow-private-ranges"})
	})
	if runErr != nil {
		t.Fatalf("dry run should accept allow-private-ranges flag: %v", runErr)
	}
	if !strings.Contains(stdout, "private_ranges=allowed") {
		t.Fatalf("dry run policy should show private ranges allowed, got:\n%s", stdout)
	}
}

func TestWrapProfileListPrintsEmbeddedProfiles(t *testing.T) {
	cmd := &cobra.Command{}
	var runErr error
	stdout := captureStdout(t, func() {
		runErr = wrapCmd.RunE(cmd, []string{"--profile", "list"})
	})
	if runErr != nil {
		t.Fatalf("profile list should not require config or command: %v", runErr)
	}
	for _, want := range []string{"NockLock profiles:", "claude-code", "codex"} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("profile list missing %q:\n%s", want, stdout)
		}
	}
}

func TestWrapDryRunProfileUsesEmbeddedBaseWithoutConfig(t *testing.T) {
	dir := t.TempDir()
	withWorkingDir(t, dir)

	cmd := &cobra.Command{}
	var runErr error
	stdout := captureStdout(t, func() {
		runErr = wrapCmd.RunE(cmd, []string{"--profile", "codex", "--dry-run"})
	})
	if runErr != nil {
		t.Fatalf("dry run profile should not require project config: %v", runErr)
	}
	if !strings.Contains(stdout, "Profile: codex") || !strings.Contains(stdout, "api.openai.com") {
		t.Fatalf("dry run did not show codex profile policy:\n%s", stdout)
	}
}

func TestWrapProfileUnknownFailsClosed(t *testing.T) {
	cmd := &cobra.Command{}
	err := wrapCmd.RunE(cmd, []string{"--profile", "missing", "--dry-run"})
	if err == nil {
		t.Fatal("expected unknown profile to fail")
	}
	if !strings.Contains(err.Error(), `unknown profile "missing"`) {
		t.Fatalf("expected clear unknown profile error, got: %v", err)
	}
	if !strings.Contains(err.Error(), "valid profiles: [aider claude-code codex gemini-cli goose opencode]") {
		t.Fatalf("expected valid profile names in error, got: %v", err)
	}
}

func TestEffectiveWrapConfigPreservesAllowPrivateRanges(t *testing.T) {
	cfg := config.DefaultConfig()

	effective := effectiveWrapConfig(&cfg, WrapFlags{AllowPrivateRanges: true})
	if !effective.Network.AllowPrivateRanges {
		t.Fatal("expected allow-private-ranges CLI flag to be reflected in effective config")
	}

	cfg.Network.AllowPrivateRanges = true
	effective = effectiveWrapConfig(&cfg, WrapFlags{})
	if !effective.Network.AllowPrivateRanges {
		t.Fatal("expected config allow_private_ranges to be preserved in effective config")
	}
}

func TestComposeChildArgvAddsPrefixesWithoutDroppingPriorShim(t *testing.T) {
	got := composeChildArgv(
		[]string{"agent", "--task"},
		[]string{"nocklock", "__landlock-exec"},
		[]string{"sandbox-exec", "-f", "profile.sb"},
	)
	want := []string{"sandbox-exec", "-f", "profile.sb", "nocklock", "__landlock-exec", "agent", "--task"}
	if strings.Join(got, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("composeChildArgv = %q, want %q", got, want)
	}
}

func TestValidateWrapRuntimeConfigRejectsUnsupportedFilesystemFence(t *testing.T) {
	if fsfence.IsSupported() {
		t.Skip("filesystem fence is supported on this platform")
	}

	cfg := config.DefaultConfig()
	err := validateWrapRuntimeConfig(&cfg)
	if err == nil {
		t.Fatal("expected configured filesystem fence to fail closed on unsupported platform")
	}
	if !strings.Contains(err.Error(), "filesystem fence configured but not supported on "+runtime.GOOS) {
		t.Fatalf("expected unsupported filesystem fence error, got: %v", err)
	}
}

// TestWrapDryRunFailsClosedForMacOSFilesystemRoot verifies dry-run rejects the
// macOS Seatbelt path when filesystem.root asks for Linux-style root isolation.
func TestWrapDryRunFailsClosedForMacOSFilesystemRoot(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS Seatbelt posture only applies on darwin")
	}

	dir := t.TempDir()
	writeTestConfig(t, dir, config.DefaultTOML())
	withWorkingDir(t, dir)

	cmd := &cobra.Command{}
	err := wrapCmd.RunE(cmd, []string{"--dry-run"})
	if err == nil {
		t.Fatal("expected macOS filesystem.root dry run to fail closed")
	}
	if !strings.Contains(err.Error(), "filesystem.root cannot be enforced as a root-only sandbox on macOS") {
		t.Fatalf("expected macOS root-only fail-closed error, got: %v", err)
	}
}

func TestWrapDryRunRequiresConfig(t *testing.T) {
	dir := t.TempDir()
	withWorkingDir(t, dir)

	cmd := &cobra.Command{}
	err := wrapCmd.RunE(cmd, []string{"--dry-run"})
	if err == nil {
		t.Fatal("expected dry run to fail without config")
	}
	if !strings.Contains(err.Error(), "no NockLock config found") {
		t.Fatalf("expected missing config error, got: %v", err)
	}
}

func dryRunTestTOML() string {
	return strings.Replace(config.DefaultTOML(), "[filesystem]\nroot = \".\"", "[filesystem]\nroot = \"\"", 1)
}

func writeTestConfig(t *testing.T, dir, contents string) {
	t.Helper()
	nockDir := filepath.Join(dir, config.Dir)
	if err := os.MkdirAll(nockDir, 0o755); err != nil {
		t.Fatalf("create config dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(nockDir, config.File), []byte(contents), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

// withWorkingDir uses os.Chdir, which mutates global process state for every
// goroutine. t.Cleanup restores the previous cwd after the test, but tests that
// call withWorkingDir must not call t.Parallel(); use a subprocess-style helper
// if cwd-sensitive assertions need parallel execution.
func withWorkingDir(t *testing.T, dir string) {
	t.Helper()
	orig, err := os.Getwd()
	if err != nil {
		t.Fatalf("get cwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(orig); err != nil {
			t.Fatalf("restore cwd: %v", err)
		}
	})
}

func captureStdout(t *testing.T, fn func()) string {
	t.Helper()

	orig := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stdout pipe: %v", err)
	}
	defer r.Close()
	os.Stdout = w
	defer func() {
		os.Stdout = orig
	}()

	fn()

	if err := w.Close(); err != nil {
		t.Fatalf("close stdout pipe: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read stdout pipe: %v", err)
	}
	return string(out)
}
