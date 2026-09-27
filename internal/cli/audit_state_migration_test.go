package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
)

// TestMain points the audit state root at a throwaway directory for the whole
// package. Tests here run real `wrap` invocations, and the event log now
// resolves into $XDG_STATE_HOME (config.AuditStateDir) -- without this they
// would scatter test audit chains through the developer's actual
// ~/.local/state/nocklock and leave them behind.
func TestMain(m *testing.M) {
	stateHome, err := os.MkdirTemp("", "nocklock-cli-test-state")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create test audit state root: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv("XDG_STATE_HOME", stateHome); err != nil {
		fmt.Fprintf(os.Stderr, "set XDG_STATE_HOME: %v\n", err)
		os.Exit(1)
	}
	code := m.Run()
	os.RemoveAll(stateHome)
	os.Exit(code)
}

// writeProjectConfig lays out a project with a .nock/config.toml carrying the
// given logging.db line, and points $XDG_STATE_HOME at a scratch directory so
// the audit state root is isolated from the developer's real one.
func writeProjectConfig(t *testing.T, dbLine string) (projectRoot, configPath string) {
	t.Helper()
	projectRoot = t.TempDir()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	nockDir := filepath.Join(projectRoot, config.Dir)
	if err := os.MkdirAll(nockDir, 0o700); err != nil {
		t.Fatalf("mkdir .nock: %v", err)
	}
	configPath = filepath.Join(nockDir, config.File)
	body := "[filesystem]\nroot = \".\"\n\n[logging]\n" + dbLine + "\nlevel = \"info\"\n"
	if err := os.WriteFile(configPath, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return projectRoot, configPath
}

// TestResolveDBPathRelocatesRelativeLogOutsideProject is the core invariant:
// the default (relative) logging.db must not resolve to anywhere inside the
// project, because the fence now grants the project root to the agent and
// Landlock cannot exclude a path beneath a granted directory.
func TestResolveDBPathRelocatesRelativeLogOutsideProject(t *testing.T) {
	projectRoot, configPath := writeProjectConfig(t, `db = ".nock/events.db"`)
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	dbPath, gotRoot, err := config.ResolveDBPath(cfg, configPath)
	if err != nil {
		t.Fatalf("ResolveDBPath: %v", err)
	}
	if gotRoot != projectRoot {
		t.Fatalf("project root = %q, want %q", gotRoot, projectRoot)
	}
	if !filepath.IsAbs(dbPath) {
		t.Fatalf("event log path %q is not absolute", dbPath)
	}
	if rel, err := filepath.Rel(projectRoot, dbPath); err == nil && !strings.HasPrefix(rel, "..") {
		t.Fatalf("event log %q resolved INSIDE the project %q; the fenced agent could edit its own audit trail", dbPath, projectRoot)
	}
	if filepath.Base(dbPath) != "events.db" {
		t.Fatalf("event log base = %q, want events.db", filepath.Base(dbPath))
	}
}

// TestResolveDBPathHonorsAbsoluteLog checks the operator escape hatch: an
// absolute logging.db is used verbatim, never rewritten into the state dir.
func TestResolveDBPathHonorsAbsoluteLog(t *testing.T) {
	want := filepath.Join(t.TempDir(), "custom", "audit.db")
	_, configPath := writeProjectConfig(t, `db = "`+want+`"`)
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	dbPath, _, err := config.ResolveDBPath(cfg, configPath)
	if err != nil {
		t.Fatalf("ResolveDBPath: %v", err)
	}
	if dbPath != want {
		t.Fatalf("event log = %q, want the configured absolute path %q", dbPath, want)
	}
}

// TestResolveDBPathSeparatesProjects guards against two projects sharing one
// audit chain, which would interleave unrelated sessions in a single log.
func TestResolveDBPathSeparatesProjects(t *testing.T) {
	state := t.TempDir()
	resolve := func() string {
		projectRoot := t.TempDir()
		nockDir := filepath.Join(projectRoot, config.Dir)
		if err := os.MkdirAll(nockDir, 0o700); err != nil {
			t.Fatalf("mkdir .nock: %v", err)
		}
		configPath := filepath.Join(nockDir, config.File)
		if err := os.WriteFile(configPath, []byte("[logging]\ndb = \"events.db\"\n"), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		cfg, err := config.Load(configPath)
		if err != nil {
			t.Fatalf("load config: %v", err)
		}
		dbPath, _, err := config.ResolveDBPath(cfg, configPath)
		if err != nil {
			t.Fatalf("ResolveDBPath: %v", err)
		}
		return dbPath
	}
	t.Setenv("XDG_STATE_HOME", state)
	if a, b := resolve(), resolve(); a == b {
		t.Fatalf("two projects share one event log: %q", a)
	}
}

// TestMigratedLegacyAuditChainStillVerifies is acceptance item (c): an audit
// chain an older NockLock wrote to <root>/.nock/events.db keeps verifying after
// it is relocated, and nothing is left behind inside the project.
func TestMigratedLegacyAuditChainStillVerifies(t *testing.T) {
	projectRoot, configPath := writeProjectConfig(t, `db = ".nock/events.db"`)
	legacyDB := filepath.Join(projectRoot, config.Dir, "events.db")

	// Build a real hash chain at the legacy in-project location.
	legacyLogger, err := logging.NewLogger(legacyDB, projectRoot)
	if err != nil {
		t.Fatalf("open legacy event log: %v", err)
	}
	for _, detail := range []string{"first", "second", "third"} {
		if err := legacyLogger.Log(logging.Event{
			EventType: logging.EventFilePassed,
			Category:  "filesystem",
			Detail:    detail,
			SessionID: "legacy-session",
		}); err != nil {
			t.Fatalf("log legacy event %q: %v", detail, err)
		}
	}
	before, err := legacyLogger.VerifyChain()
	if err != nil {
		t.Fatalf("verify legacy chain: %v", err)
	}
	if !before.Intact {
		t.Fatalf("legacy chain not intact before migration: %s", before.BrokenReason)
	}
	if err := legacyLogger.Close(); err != nil {
		t.Fatalf("close legacy event log: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	dbPath, _, err := config.ResolveDBPath(cfg, configPath)
	if err != nil {
		t.Fatalf("ResolveDBPath: %v", err)
	}

	if _, err := os.Lstat(legacyDB); !os.IsNotExist(err) {
		t.Fatalf("legacy event log still inside the project at %s (err=%v); it must MOVE, not be copied, or the agent can still reach it", legacyDB, err)
	}
	if _, err := os.Stat(dbPath); err != nil {
		t.Fatalf("relocated event log missing at %s: %v", dbPath, err)
	}

	migrated, err := logging.NewLogger(dbPath, projectRoot)
	if err != nil {
		t.Fatalf("open relocated event log: %v", err)
	}
	defer migrated.Close()
	after, err := migrated.VerifyChain()
	if err != nil {
		t.Fatalf("verify relocated chain: %v", err)
	}
	if !after.Intact {
		t.Fatalf("relocated chain not intact: %s", after.BrokenReason)
	}
	if after.EntriesVerified != before.EntriesVerified {
		t.Fatalf("relocated chain has %d entries, want %d — the migration dropped rows", after.EntriesVerified, before.EntriesVerified)
	}
	if after.HeadHash != before.HeadHash {
		t.Fatalf("chain head changed across the migration: %q -> %q", before.HeadHash, after.HeadHash)
	}
}

// TestResolveDBPathRefusesTwoAuditChains: if a legacy in-project log and a
// relocated log both exist, NockLock must not silently pick one — a tampered
// chain could otherwise shadow the real one.
func TestResolveDBPathRefusesTwoAuditChains(t *testing.T) {
	projectRoot, configPath := writeProjectConfig(t, `db = ".nock/events.db"`)
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	stateDir, err := config.AuditStateDir(projectRoot)
	if err != nil {
		t.Fatalf("AuditStateDir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(stateDir, "events.db"), []byte("relocated"), 0o600); err != nil {
		t.Fatalf("write relocated log: %v", err)
	}
	if err := os.WriteFile(filepath.Join(projectRoot, config.Dir, "events.db"), []byte("legacy"), 0o600); err != nil {
		t.Fatalf("write legacy log: %v", err)
	}

	if _, _, err := config.ResolveDBPath(cfg, configPath); err == nil {
		t.Fatal("expected two coexisting audit chains to be refused")
	} else if !strings.Contains(err.Error(), "two event logs") {
		t.Fatalf("expected a two-logs error, got: %v", err)
	}
}

// resolvedAuditDB returns the event log path for the project at projectRoot,
// resolved exactly as every nocklock command resolves it. Tests that inspect
// the audit trail after running wrap must use this rather than joining
// <project>/.nock/events.db: the log lives in the audit state directory outside
// the project (config.AuditStateDir).
func resolvedAuditDB(t *testing.T, projectRoot string) string {
	t.Helper()
	configPath := filepath.Join(projectRoot, config.Dir, config.File)
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config for %s: %v", projectRoot, err)
	}
	dbPath, _, err := config.ResolveDBPath(cfg, configPath)
	if err != nil {
		t.Fatalf("resolve event log for %s: %v", projectRoot, err)
	}
	return dbPath
}
