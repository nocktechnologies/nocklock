//go:build integration

package integration_test

import (
	"database/sql"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

// nocklockBin is the path to the compiled nocklock binary, set in TestMain.
var nocklockBin string

// TestMain builds the nocklock binary (and the filesystem fence interposer on
// Linux) once, then runs the integration suite. Cleanup happens after all tests.
func TestMain(m *testing.M) {
	// Build binary to a temp location.
	tmp, err := os.MkdirTemp("", "nocklock-integration-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create temp dir: %v\n", err)
		os.Exit(1)
	}
	binPath := filepath.Join(tmp, "nocklock")
	build := exec.Command("go", "build", "-o", binPath, "./cmd/nocklock")
	build.Dir = projectRoot()
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "failed to build nocklock: %v\n", err)
		os.RemoveAll(tmp)
		os.Exit(1)
	}
	nocklockBin = binPath

	// On Linux, build the filesystem fence interposer and place it next to
	// the binary so that findLibFenceFS() can locate it.
	if runtime.GOOS == "linux" {
		interposerCmd := exec.Command("make", "build-fence-fs")
		interposerCmd.Dir = projectRoot()
		if out, err := interposerCmd.CombinedOutput(); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to build filesystem interposer: %v\n%s\n", err, out)
			os.RemoveAll(tmp)
			os.Exit(1)
		}
		soSrc := filepath.Join(projectRoot(), "internal", "fence", "fs", "interposer", "libfence_fs.so")
		soDst := filepath.Join(tmp, "libfence_fs.so")
		if err := copyFile(soSrc, soDst); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to copy libfence_fs.so: %v\n", err)
			os.RemoveAll(tmp)
			os.Exit(1)
		}
	}

	code := m.Run()
	os.RemoveAll(tmp)
	os.Exit(code)
}

// projectRoot returns the absolute path to the project root (parent of integration/).
func projectRoot() string {
	// This file lives in integration/; go up one level.
	_, file, _, _ := runtime.Caller(0)
	return filepath.Dir(filepath.Dir(file))
}

// copyFile copies the file at src to dst, preserving permissions.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	info, err := in.Stat()
	if err != nil {
		return err
	}

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, info.Mode())
	if err != nil {
		return err
	}
	defer out.Close()

	_, err = io.Copy(out, in)
	return err
}

// testConfig returns a minimal but valid config.toml for integration tests.
// The filesystem fence root is set to "" so it is skipped on non-Linux.
func testConfig() string {
	return `[project]
name = "integration-test"
root = "."

[filesystem]
root = ""
mode = "read-write"
allow = ["~/.claude/", "/tmp/"]
deny = ["~/.ssh/", "~/.aws/", "~/.gnupg/"]

[network]
allow = ["github.com", "api.github.com", "api.anthropic.com"]
allow_all = false

[secrets]
pass = ["HOME", "PATH", "SHELL", "USER", "LANG", "TERM"]
block = ["AWS_*", "STRIPE_*", "*_SECRET*", "*_PASSWORD*", "*_TOKEN*"]

[logging]
db = ".nock/events.db"
level = "info"

[cloud]
enabled = false
api_key = ""
endpoint = "https://cc.nocktechnologies.io/api/fence/events/"
`
}

// setupTestDir creates a temp directory with .nock/config.toml already written.
// Returns the temp dir path. The caller should defer os.RemoveAll(dir).
func setupTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()

	nockDir := filepath.Join(dir, ".nock")
	if err := os.MkdirAll(nockDir, 0o755); err != nil {
		t.Fatalf("failed to create .nock dir: %v", err)
	}
	configPath := filepath.Join(nockDir, "config.toml")
	if err := os.WriteFile(configPath, []byte(testConfig()), 0o600); err != nil {
		t.Fatalf("failed to write config.toml: %v", err)
	}
	return dir
}

// setupTestDirWithConfig creates a temp directory with a custom config.toml.
func setupTestDirWithConfig(t *testing.T, config string) string {
	t.Helper()
	dir := t.TempDir()

	nockDir := filepath.Join(dir, ".nock")
	if err := os.MkdirAll(nockDir, 0o755); err != nil {
		t.Fatalf("failed to create .nock dir: %v", err)
	}
	configPath := filepath.Join(nockDir, "config.toml")
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatalf("failed to write config.toml: %v", err)
	}
	return dir
}

// runNocklock executes the nocklock binary with the given args in the given directory.
// env is appended to the inherited environment. Returns stdout, stderr, and exit code.
func runNocklock(t *testing.T, dir string, env []string, args ...string) (stdout, stderr string, exitCode int) {
	t.Helper()
	cmd := exec.Command(nocklockBin, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)

	var outBuf, errBuf strings.Builder
	cmd.Stdout = &outBuf
	cmd.Stderr = &errBuf

	err := cmd.Run()
	exitCode = 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			t.Fatalf("failed to run nocklock: %v", err)
		}
	}

	return outBuf.String(), errBuf.String(), exitCode
}

// ---------------------------------------------------------------------------
// Test 1: Basic passthrough
// ---------------------------------------------------------------------------

// TestWrapPassthrough verifies that nocklock wrap passes child stdout through
// unchanged and exits with code 0.
func TestWrapPassthrough(t *testing.T) {
	dir := setupTestDir(t)
	stdout, _, exitCode := runNocklock(t, dir, nil, "wrap", "--", "echo", "hello")

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(stdout, "hello") {
		t.Errorf("expected stdout to contain %q, got %q", "hello", stdout)
	}
}

// ---------------------------------------------------------------------------
// Test 2: nocklock init creates config
// ---------------------------------------------------------------------------

// TestInitCreatesConfig verifies that nocklock init creates .nock/config.toml
// containing all six expected TOML sections.
func TestInitCreatesConfig(t *testing.T) {
	dir := t.TempDir()

	_, _, exitCode := runNocklock(t, dir, nil, "init")
	if exitCode != 0 {
		t.Fatalf("nocklock init failed with exit code %d", exitCode)
	}

	configPath := filepath.Join(dir, ".nock", "config.toml")
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("config file not created: %v", err)
	}

	content := string(data)
	for _, section := range []string{"[project]", "[filesystem]", "[network]", "[secrets]", "[logging]", "[cloud]"} {
		if !strings.Contains(content, section) {
			t.Errorf("config missing expected section %q", section)
		}
	}
}

// ---------------------------------------------------------------------------
// Test 3: Secret fence blocks sensitive vars
// ---------------------------------------------------------------------------

// TestSecretFenceBlocks verifies that the secret fence strips AWS_SECRET_ACCESS_KEY
// from the child process environment.
func TestSecretFenceBlocks(t *testing.T) {
	dir := setupTestDir(t)
	env := []string{"AWS_SECRET_ACCESS_KEY=supersecret"}

	stdout, _, exitCode := runNocklock(t, dir, env, "wrap", "--", "printenv", "AWS_SECRET_ACCESS_KEY")

	// printenv returns exit code 1 when the variable is not set.
	// The secret fence should have stripped it, so we expect empty output and non-zero exit.
	if strings.Contains(stdout, "supersecret") {
		t.Errorf("AWS_SECRET_ACCESS_KEY should have been blocked, but output was %q", stdout)
	}
	if exitCode == 0 {
		t.Errorf("expected non-zero exit code (printenv should fail for blocked var), got 0")
	}
}

// ---------------------------------------------------------------------------
// Test 4: Secret fence allows pass-listed vars
// ---------------------------------------------------------------------------

// TestSecretFenceAllows verifies that variables on the pass-list (PATH) are
// forwarded to the child process unchanged.
func TestSecretFenceAllows(t *testing.T) {
	dir := setupTestDir(t)

	stdout, _, exitCode := runNocklock(t, dir, nil, "wrap", "--", "printenv", "PATH")

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d", exitCode)
	}
	realPath := os.Getenv("PATH")
	if realPath == "" {
		t.Skip("PATH is not set in test environment")
	}
	if !strings.Contains(stdout, realPath) {
		t.Errorf("expected stdout to contain real PATH value, got %q", stdout)
	}
}

// ---------------------------------------------------------------------------
// Test 5: Secret fence blocks multiple sensitive vars
// ---------------------------------------------------------------------------

// TestSecretFenceMultipleBlocked verifies that all sensitive variables matching
// block-list patterns are stripped from the child environment.
func TestSecretFenceMultipleBlocked(t *testing.T) {
	dir := setupTestDir(t)
	env := []string{
		"STRIPE_SECRET=stripesecretvalue",
		"DB_PASSWORD=dbpassword123",
		"MY_SECRET_KEY=mysecret456",
	}

	stdout, _, _ := runNocklock(t, dir, env, "wrap", "--", "env")

	for _, blocked := range []string{"STRIPE_SECRET=", "DB_PASSWORD=", "MY_SECRET_KEY="} {
		blocked := blocked // capture
		t.Run(blocked, func(t *testing.T) {
			if strings.Contains(stdout, blocked) {
				t.Errorf("blocked var %q leaked into output", blocked)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Test 6: Network fence blocks unknown domains
// ---------------------------------------------------------------------------

// TestNetworkFenceBlocksUnknownDomain verifies that the network fence proxy
// returns HTTP 403 for domains not on the allowlist (httpbin.org).
func TestNetworkFenceBlocksUnknownDomain(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}

	dir := setupTestDir(t)

	stdout, stderr, exitCode := runNocklock(t, dir, nil,
		"wrap", "--",
		"curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "http://httpbin.org/get",
	)

	if exitCode != 0 {
		t.Fatalf("curl itself failed (exit %d), can't verify fence: stderr=%s", exitCode, stderr)
	}

	// The proxy should return 403 for domains not in the allowlist.
	if !strings.Contains(stdout, "403") {
		t.Errorf("expected HTTP 403 for blocked domain, got stdout=%q stderr=%q", stdout, stderr)
	}
}

// ---------------------------------------------------------------------------
// Test 7: Network fence allows github.com
// ---------------------------------------------------------------------------

// TestNetworkFenceAllowsGithub verifies that the network fence permits requests
// to github.com (on the allowlist). Requires INTEGRATION_NETWORK=1.
func TestNetworkFenceAllowsGithub(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Skip("curl not available")
	}
	if os.Getenv("INTEGRATION_NETWORK") == "" {
		t.Skip("skipping: set INTEGRATION_NETWORK=1 to enable tests requiring live internet")
	}

	dir := setupTestDir(t)

	stdout, stderr, exitCode := runNocklock(t, dir, nil,
		"wrap", "--",
		"curl", "-s", "-o", "/dev/null", "-w", "%{http_code}", "https://github.com",
	)

	if exitCode != 0 {
		t.Errorf("expected exit code 0, got %d; stderr=%q", exitCode, stderr)
	}

	// Accept any 2xx or 3xx response from github.com.
	code := strings.TrimSpace(stdout)
	if len(code) != 3 || (code[0] != '2' && code[0] != '3') {
		t.Errorf("expected 2xx/3xx status from github.com, got %q (stderr=%q)", stdout, stderr)
	}
}

// ---------------------------------------------------------------------------
// Test 8: Event logging records secret_blocked events
// ---------------------------------------------------------------------------

// TestEventLogging verifies that fence events are written to .nock/events.db
// and that secret_blocked events include the variable name.
func TestEventLogging(t *testing.T) {
	dir := setupTestDir(t)
	env := []string{"AWS_SECRET_ACCESS_KEY=supersecret"}

	_, stderr, code := runNocklock(t, dir, env, "wrap", "--", "printenv", "AWS_SECRET_ACCESS_KEY")
	if code != 0 {
		t.Logf("nocklock exited %d, stderr: %s", code, stderr)
	}

	dbPath := filepath.Join(dir, ".nock", "events.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		t.Fatalf("events.db was not created at %s", dbPath)
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("failed to open events.db: %v", err)
	}
	defer db.Close()

	// Check that at least one secret_blocked event was logged.
	var count int
	err = db.QueryRow("SELECT COUNT(*) FROM events WHERE event_type = 'secret_blocked'").Scan(&count)
	if err != nil {
		t.Fatalf("failed to query events: %v", err)
	}
	if count == 0 {
		t.Errorf("expected at least one secret_blocked event, got 0")
	}

	// Verify the blocked event references AWS_SECRET_ACCESS_KEY.
	var detail string
	err = db.QueryRow("SELECT detail FROM events WHERE event_type = 'secret_blocked' AND detail LIKE '%AWS_SECRET_ACCESS_KEY%' LIMIT 1").Scan(&detail)
	if err != nil {
		t.Errorf("expected a secret_blocked event for AWS_SECRET_ACCESS_KEY, query failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Test 9: Filesystem fence blocks (Linux only)
// ---------------------------------------------------------------------------

// TestFilesystemFenceBlocks verifies that the LD_PRELOAD filesystem fence
// returns EACCES for files in a deny-listed directory. Linux only.
func TestFilesystemFenceBlocks(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("filesystem fence is Linux-only")
	}

	// Create a readable file OUTSIDE the allowed directory to use as the deny target.
	sensitiveDir := t.TempDir()
	sensitiveFile := filepath.Join(sensitiveDir, "sensitive.txt")
	if err := os.WriteFile(sensitiveFile, []byte("secret-content"), 0o644); err != nil {
		t.Fatalf("failed to create sensitive file: %v", err)
	}

	// Use a config with filesystem fence enabled, denying the sensitive dir.
	config := fmt.Sprintf(`[project]
name = "integration-test-fs"
root = "."

[filesystem]
root = "."
mode = "read-write"
allow = ["/tmp/"]
deny = [%q]

[network]
allow = []
allow_all = true

[secrets]
pass = ["HOME", "PATH", "SHELL", "USER", "LANG", "TERM"]
block = []

[logging]
db = ".nock/events.db"
level = "info"

[cloud]
enabled = false
api_key = ""
endpoint = "https://cc.nocktechnologies.io/api/fence/events/"
`, sensitiveDir)

	dir := setupTestDirWithConfig(t, config)

	_, stderr, exitCode := runNocklock(t, dir, nil, "wrap", "--", "cat", sensitiveFile)

	if exitCode == 0 {
		t.Errorf("expected non-zero exit code when reading denied file, got 0")
	}
	combined := stderr
	if !strings.Contains(strings.ToLower(combined), "permission denied") &&
		!strings.Contains(strings.ToLower(combined), "eacces") {
		t.Logf("stderr: %s", stderr)
		t.Errorf("expected permission denied or EACCES error for denied file")
	}
}

// ---------------------------------------------------------------------------
// Test 10: Exit code passthrough
// ---------------------------------------------------------------------------

// TestWrapExitCodePassthrough verifies that nocklock wrap forwards the child's
// exit code exactly, including non-zero values.
func TestWrapExitCodePassthrough(t *testing.T) {
	dir := setupTestDir(t)

	_, _, exitCode := runNocklock(t, dir, nil, "wrap", "--", "sh", "-c", "exit 42")

	if exitCode != 42 {
		t.Errorf("expected exit code 42, got %d", exitCode)
	}
}
