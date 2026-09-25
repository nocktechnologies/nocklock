package cli

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/anchorclient"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/spf13/cobra"
)

// plainLaunchTOML is the dry-run test config with the seccomp syscall fence off.
// With the fs root unset and the syscall fence off, wrap execs the child
// directly. The default (required) syscall fence would re-exec THIS test binary
// as the __landlock-exec shim, which a test binary cannot serve; the shim path
// is covered end to end with the real binary in integration/.
func plainLaunchTOML(t *testing.T) string {
	t.Helper()
	toml := dryRunTestTOML()
	// The secret fence is an allowlist. Pass the three vars under test THROUGH it
	// so their presence or absence in the child is decided by wrap's own env
	// handling (the export and the anchor strip), not by the fence dropping them.
	const passTail = "    \"TERM\",\n]"
	if !strings.Contains(toml, passTail) {
		t.Fatal("test setup: could not find the secrets.pass list")
	}
	toml = strings.Replace(toml, passTail,
		"    \"TERM\",\n    \"NOCKLOCK_SESSION_ID\",\n    \"NOCKLOCK_ANCHOR_URL\",\n    \"NOCKLOCK_ANCHOR_TOKEN\",\n]", 1)
	i := strings.Index(toml, "[syscall]")
	if i < 0 {
		t.Fatal("test setup: default config has no [syscall] table")
	}
	tail := strings.Replace(toml[i:], `enforcement = "required"`, `enforcement = "off"`, 1)
	if tail == toml[i:] {
		t.Fatal("test setup: failed to turn the syscall fence off")
	}
	return toml[:i] + tail
}

// runWrapPrintingEnv runs a REAL in-process `nocklock wrap` of a trivial shell
// command that writes NOCKLOCK_SESSION_ID, the anchor URL and the anchor token
// (each as NAME=<value> or NAME=<unset>) to a file, and returns that file's
// lines keyed by name plus every distinct session_id recorded in the run's audit
// DB. The wrap runs with the plain (userspace proxy) launch path, so it needs
// neither root nor the netns helper.
func runWrapPrintingEnv(t *testing.T) (childSees map[string]string, dbSessionIDs []string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("wrap launches a POSIX shell")
	}
	dir := t.TempDir()
	writeTestConfig(t, dir, plainLaunchTOML(t))
	withWorkingDir(t, dir)

	out := filepath.Join(dir, "child-env.txt")
	script := `{ echo "sid=${NOCKLOCK_SESSION_ID-<unset>}"; ` +
		`echo "url=${NOCKLOCK_ANCHOR_URL-<unset>}"; ` +
		`echo "tok=${NOCKLOCK_ANCHOR_TOKEN-<unset>}"; } > "$1"`

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	if err := wrapCmd.RunE(cmd, []string{"--", "sh", "-c", script, "sh", out}); err != nil {
		t.Fatalf("wrap of a trivial command failed: %v", err)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("child did not write its environment report: %v", err)
	}
	childSees = map[string]string{}
	for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			t.Fatalf("malformed child report line %q", line)
		}
		childSees[k] = v
	}

	dbPath := filepath.Join(dir, ".nock", "events.db")
	logger, err := logging.NewLogger(dbPath, dir)
	if err != nil {
		t.Fatalf("reopen audit DB %s: %v", dbPath, err)
	}
	defer logger.Close()
	events, err := logger.Query(logging.QueryOptions{})
	if err != nil {
		t.Fatalf("query audit DB: %v", err)
	}
	seen := map[string]bool{}
	for _, ev := range events {
		if !seen[ev.SessionID] {
			seen[ev.SessionID] = true
			dbSessionIDs = append(dbSessionIDs, ev.SessionID)
		}
	}
	return childSees, dbSessionIDs
}

// The child must see NOCKLOCK_SESSION_ID equal to the session id recorded in the
// audit DB for that run, so a co-located tool can stamp the same id.
func TestWrapExportsSessionIDToChildMatchingAuditDB(t *testing.T) {
	t.Setenv("NOCKLOCK_SESSION_ID", "") // ensure a defined baseline; unset below
	os.Unsetenv("NOCKLOCK_SESSION_ID")

	sees, dbIDs := runWrapPrintingEnv(t)

	if len(dbIDs) != 1 {
		t.Fatalf("expected exactly one session id in the audit DB for this run, got %v", dbIDs)
	}
	got := sees["sid"]
	if got == "" || got == "<unset>" {
		t.Fatalf("child did not receive NOCKLOCK_SESSION_ID (saw %q); audit DB session id is %q", got, dbIDs[0])
	}
	if got != dbIDs[0] {
		t.Fatalf("child NOCKLOCK_SESSION_ID = %q, audit DB session id = %q; they must be equal", got, dbIDs[0])
	}
}

// An inherited NOCKLOCK_SESSION_ID (stale or spoofed) must be OVERWRITTEN with the
// run's real id, never passed through.
func TestWrapOverwritesInheritedSessionID(t *testing.T) {
	t.Setenv("NOCKLOCK_SESSION_ID", "stale")

	sees, dbIDs := runWrapPrintingEnv(t)

	if len(dbIDs) != 1 {
		t.Fatalf("expected exactly one session id in the audit DB for this run, got %v", dbIDs)
	}
	got := sees["sid"]
	if got == "stale" {
		t.Fatalf("inherited NOCKLOCK_SESSION_ID=stale survived into the child; it must be overwritten")
	}
	if got != dbIDs[0] {
		t.Errorf("child NOCKLOCK_SESSION_ID = %q, want the run's real id %q", got, dbIDs[0])
	}
}

// Exporting the session id must not weaken the anchor URL/token stripping: the
// child still sees neither.
func TestWrapSessionIDExportKeepsAnchorEnvStripped(t *testing.T) {
	// A refused local port: teardown's fail-open push fails fast and quietly.
	t.Setenv(anchorclient.EnvURL, "http://127.0.0.1:1")
	t.Setenv(anchorclient.EnvToken, "secret-token-value")
	t.Setenv("NOCKLOCK_SESSION_ID", "stale")

	sees, dbIDs := runWrapPrintingEnv(t)

	if sees["url"] != "<unset>" {
		t.Errorf("anchor URL leaked to the child: %q", sees["url"])
	}
	if sees["tok"] != "<unset>" {
		t.Errorf("anchor token leaked to the child: %q", sees["tok"])
	}
	if len(dbIDs) != 1 || sees["sid"] != dbIDs[0] {
		t.Errorf("child session id %q does not match audit DB ids %v", sees["sid"], dbIDs)
	}
}

// setSessionIDEnv is the single choke point; pin its overwrite semantics directly
// (no duplicate entries, other vars preserved).
func TestSetSessionIDEnvReplacesEveryInheritedEntry(t *testing.T) {
	env := []string{"A=1", "NOCKLOCK_SESSION_ID=stale", "B=2", "NOCKLOCK_SESSION_ID=spoof"}
	got := setSessionIDEnv(env, "real")

	var ids []string
	others := 0
	for _, e := range got {
		if strings.HasPrefix(e, "NOCKLOCK_SESSION_ID=") {
			ids = append(ids, e)
		} else {
			others++
		}
	}
	if len(ids) != 1 || ids[0] != "NOCKLOCK_SESSION_ID=real" {
		t.Fatalf("expected exactly NOCKLOCK_SESSION_ID=real, got %v", ids)
	}
	if others != 2 {
		t.Errorf("expected the 2 unrelated vars preserved, got %d in %v", others, got)
	}
}
