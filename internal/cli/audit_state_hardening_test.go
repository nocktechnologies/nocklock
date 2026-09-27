package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
)

const legacyAnchorName = "chain-anchor" + ".json"

// TestResolveDBPathLeavesUnrelatedProjectFilesAlone: the default logging.db is
// the bare name "events.db", so a project that happens to own a file by that
// name at its root must not have it mistaken for NockLock's own audit log. Only
// the conventional <root>/.nock location counts as a legacy log. The project's
// files are left untouched, and the resolved log still points at the state dir.
func TestResolveDBPathLeavesUnrelatedProjectFilesAlone(t *testing.T) {
	projectRoot, configPath := writeProjectConfig(t, `db = "events.db"`)
	stray := filepath.Join(projectRoot, "events.db")
	const strayContent = "a file this project owns"
	if err := os.WriteFile(stray, []byte(strayContent), 0o600); err != nil {
		t.Fatalf("write stray file: %v", err)
	}
	strayAnchor := filepath.Join(projectRoot, legacyAnchorName)
	if err := os.WriteFile(strayAnchor, []byte("{}"), 0o600); err != nil {
		t.Fatalf("write stray anchor: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	dbPath, _, err := config.ResolveDBPath(cfg, configPath)
	if err != nil {
		t.Fatalf("ResolveDBPath: %v", err)
	}
	if dbPath == stray {
		t.Fatalf("a project file at %s was adopted as the audit log", stray)
	}
	if rel, relErr := filepath.Rel(projectRoot, dbPath); relErr == nil && !strings.HasPrefix(rel, "..") {
		t.Fatalf("event log %q resolved inside the project %q; it should be in the audit state dir", dbPath, projectRoot)
	}

	data, readErr := os.ReadFile(stray)
	if readErr != nil {
		t.Fatalf("project file %s was moved out of the project: %v", stray, readErr)
	}
	if string(data) != strayContent {
		t.Fatalf("project file content = %q, want %q", data, strayContent)
	}
	if _, err := os.Stat(strayAnchor); err != nil {
		t.Fatalf("project file %s was moved out of the project: %v", strayAnchor, err)
	}
}

// TestAuditStateDirWithoutHome pins that NockLock still resolves an audit state
// directory with no home directory available. wrap refuses to start when the
// event log cannot be opened, and containers with no passwd entry for the uid —
// plus CI steps that unset HOME — used to work without a home directory at all.
func TestAuditStateDirWithoutHome(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("HOME", "")

	dir, err := config.AuditStateDir(t.TempDir())
	if err != nil {
		t.Fatalf("no audit state directory without HOME; wrap would refuse to run: %v", err)
	}
	if !filepath.IsAbs(dir) {
		t.Fatalf("audit state directory %q is not absolute", dir)
	}
	// Never /tmp: the shipped presets grant it, and a state dir inside a
	// Landlock-granted tree makes its own deny unenforceable.
	if strings.HasPrefix(dir, "/tmp/") {
		t.Fatalf("fallback audit state directory %q is under /tmp, which the presets grant", dir)
	}
}

// TestResolveDBPathSeparatesProjectsWithoutAConfigFile: `wrap --profile X` in a
// directory with no .nock/config.toml hands ResolveDBPath the sentinel
// "embedded profile X" as the config path, which reduces to "." and used to give
// every such project the SAME audit state directory, interleaving unrelated
// chains in one log. The project root is absolutized before it is hashed.
func TestResolveDBPathSeparatesProjectsWithoutAConfigFile(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	cfg := config.DefaultConfig()
	cfgPtr := &cfg

	resolve := func() string {
		dir, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatalf("resolve temp dir: %v", err)
		}
		t.Chdir(dir)
		dbPath, _, err := config.ResolveDBPath(cfgPtr, "embedded profile claude-code")
		if err != nil {
			t.Fatalf("ResolveDBPath: %v", err)
		}
		return dbPath
	}

	if a, b := resolve(), resolve(); a == b {
		t.Fatalf("two profile-only projects share one event log: %q", a)
	}
}

// TestResolveDBPathAdoptsHandWrittenRelativeLog: a relative logging.db holding a
// separator is a path the operator wrote, and before the relocation it named a
// real in-project log. Abandoning that chain would break the promise that
// NockLock never changes which chain is authoritative.
func TestResolveDBPathAdoptsHandWrittenRelativeLog(t *testing.T) {
	projectRoot, configPath := writeProjectConfig(t, `db = "logs/events.db"`)
	legacy := filepath.Join(projectRoot, "logs", "events.db")
	if err := os.MkdirAll(filepath.Dir(legacy), 0o755); err != nil {
		t.Fatalf("mkdir logs: %v", err)
	}
	if err := os.WriteFile(legacy, []byte("existing chain"), 0o600); err != nil {
		t.Fatalf("write legacy log: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	dbPath, _, err := config.ResolveDBPath(cfg, configPath)
	if err != nil {
		t.Fatalf("ResolveDBPath: %v", err)
	}
	if dbPath != legacy {
		t.Fatalf("event log = %q, want the operator's existing log %q; a new chain would abandon it", dbPath, legacy)
	}
}

// TestResolveDBPathRefusesTwoLegacyCandidates: a project can carry both the
// conventional <root>/.nock/events.db log and a hand-written relative
// logging.db (e.g. "logs/events.db") that also names an existing file.
// ResolveDBPath used to stop scanning at the first candidate it found and
// silently adopt it; if both are real logs it must refuse to pick a side and
// name both instead.
func TestResolveDBPathRefusesTwoLegacyCandidates(t *testing.T) {
	projectRoot, configPath := writeProjectConfig(t, `db = "logs/events.db"`)
	conventional := filepath.Join(projectRoot, config.Dir, "events.db")
	if err := os.WriteFile(conventional, []byte("conventional chain"), 0o600); err != nil {
		t.Fatalf("write conventional log: %v", err)
	}
	handWritten := filepath.Join(projectRoot, "logs", "events.db")
	if err := os.MkdirAll(filepath.Dir(handWritten), 0o755); err != nil {
		t.Fatalf("mkdir logs: %v", err)
	}
	if err := os.WriteFile(handWritten, []byte("hand-written chain"), 0o600); err != nil {
		t.Fatalf("write hand-written log: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	_, _, err = config.ResolveDBPath(cfg, configPath)
	if err == nil {
		t.Fatal("expected two coexisting legacy candidates to be refused")
	}
	if !strings.Contains(err.Error(), "event logs found") {
		t.Fatalf("expected an event-logs-found error, got: %v", err)
	}
	if !strings.Contains(err.Error(), conventional) || !strings.Contains(err.Error(), handWritten) {
		t.Fatalf("expected the error to name both candidates %q and %q, got: %v", conventional, handWritten, err)
	}
}

// TestResolveDBPathRefusesThreeAuditChains: with the conventional in-project
// log, a hand-written relative log, AND the relocated state-dir log all
// present, ResolveDBPath must refuse and name every one of the three -- not
// just the first two it happens to find, which is exactly the bug the "stops
// at the first match" scan used to have.
func TestResolveDBPathRefusesThreeAuditChains(t *testing.T) {
	projectRoot, configPath := writeProjectConfig(t, `db = "logs/events.db"`)
	conventional := filepath.Join(projectRoot, config.Dir, "events.db")
	if err := os.WriteFile(conventional, []byte("conventional chain"), 0o600); err != nil {
		t.Fatalf("write conventional log: %v", err)
	}
	handWritten := filepath.Join(projectRoot, "logs", "events.db")
	if err := os.MkdirAll(filepath.Dir(handWritten), 0o755); err != nil {
		t.Fatalf("mkdir logs: %v", err)
	}
	if err := os.WriteFile(handWritten, []byte("hand-written chain"), 0o600); err != nil {
		t.Fatalf("write hand-written log: %v", err)
	}
	stateDir, err := config.EnsureAuditStateDir(projectRoot)
	if err != nil {
		t.Fatalf("EnsureAuditStateDir: %v", err)
	}
	relocated := filepath.Join(stateDir, "events.db")
	if err := os.WriteFile(relocated, []byte("relocated chain"), 0o600); err != nil {
		t.Fatalf("write relocated log: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	_, _, err = config.ResolveDBPath(cfg, configPath)
	if err == nil {
		t.Fatal("expected three coexisting audit chains to be refused")
	}
	if !strings.Contains(err.Error(), "event logs found") {
		t.Fatalf("expected an event-logs-found error, got: %v", err)
	}
	for _, want := range []string{conventional, handWritten, relocated} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("expected the error to name %q among all three candidates, got: %v", want, err)
		}
	}
}

// TestResolveDBPathRejectsRelativeTraversal: a hand-written relative
// logging.db containing ".." must not be allowed to join outside the project
// root and get adopted as the authoritative log -- that would let a config a
// repository ships aim the audit chain at a file the project does not own.
func TestResolveDBPathRejectsRelativeTraversal(t *testing.T) {
	projectRoot, configPath := writeProjectConfig(t, `db = "../audit/events.db"`)
	outside := filepath.Join(filepath.Dir(projectRoot), "audit", "events.db")
	if err := os.MkdirAll(filepath.Dir(outside), 0o755); err != nil {
		t.Fatalf("mkdir outside dir: %v", err)
	}
	if err := os.WriteFile(outside, []byte("outside chain"), 0o600); err != nil {
		t.Fatalf("write outside log: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if _, _, err := config.ResolveDBPath(cfg, configPath); err == nil {
		t.Fatal("expected a relative logging.db that traverses outside the project to be rejected")
	} else if !strings.Contains(err.Error(), "logging.db") {
		t.Fatalf("expected an error naming logging.db, got: %v", err)
	}
}
