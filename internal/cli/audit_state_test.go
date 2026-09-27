package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
	"github.com/nocktechnologies/nocklock/internal/fence/fs/landlock"
	"github.com/nocktechnologies/nocklock/internal/logging"
)

// TestMain points the audit state root at a throwaway directory for the whole
// package. Tests here run real `wrap` invocations, and the event log now
// resolves into $XDG_STATE_HOME (config.AuditStateDir) -- without this they
// would scatter test audit chains through the developer's actual
// ~/.local/state/nocklock and leave them behind.
func TestMain(m *testing.M) {
	workDir, err := os.Getwd()
	if err != nil {
		fmt.Fprintf(os.Stderr, "locate test working directory: %v\n", err)
		os.Exit(1)
	}
	// The claude-code preset grants /tmp, so placing the audit-state deny under
	// os.TempDir makes that deny unenforceable. Keep it beside the test projects
	// in the package working directory instead.
	stateHome, err := os.MkdirTemp(workDir, "nocklock-cli-test-state")
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

// resolvedTempDir returns a t.TempDir() with symlinks resolved. On macOS it
// lives under /var/folders/..., and /var is a system symlink into /private,
// so an unresolved root would not match the paths NockLock resolves.
func resolvedTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temp dir: %v", err)
	}
	return dir
}

// trustedStateRoot returns a resolved temp dir chmod'd 0700, standing in for
// a state root (XDG_STATE_HOME) an operator actually trusts. t.TempDir()
// itself is not good enough: its per-call leaf is created with
// os.Mkdir(dir, 0777), so under a permissive umask (e.g. 002, common with
// user-private-group setups) it comes back group-writable, which would trip
// config.EnsureAuditStateDir's state-root check for reasons that have nothing
// to do with what the test is checking.
func trustedStateRoot(t *testing.T) string {
	t.Helper()
	dir := resolvedTempDir(t)
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatalf("chmod state root: %v", err)
	}
	return dir
}

// writeProjectConfig lays out a project with a .nock/config.toml carrying the
// given logging.db line, and points $XDG_STATE_HOME at a scratch directory so
// the audit state root is isolated from the developer's real one.
func writeProjectConfig(t *testing.T, dbLine string) (projectRoot, configPath string) {
	t.Helper()
	projectRoot = resolvedTempDir(t)
	t.Setenv("XDG_STATE_HOME", trustedStateRoot(t))
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

// TestLoadRejectsAbsoluteAuditLogEscapingProject: an absolute logging.db is
// only honored inside the project or the audit state directory. Anywhere else is
// refused at config load, so a repository cannot ship a config that aims a
// SQLite write at an arbitrary path.
func TestLoadRejectsAbsoluteAuditLogEscapingProject(t *testing.T) {
	escape := filepath.Join(t.TempDir(), "custom", "audit.db")
	_, configPath := writeProjectConfig(t, `db = "`+escape+`"`)
	if _, err := config.Load(configPath); err == nil {
		t.Fatal("expected an absolute logging.db outside the project to be rejected")
	} else if !strings.Contains(err.Error(), "logging.db") {
		t.Fatalf("expected an error naming logging.db, got: %v", err)
	}
}

// TestResolveDBPathSeparatesProjects guards against two projects sharing one
// audit chain, which would interleave unrelated sessions in a single log.
func TestResolveDBPathSeparatesProjects(t *testing.T) {
	state := trustedStateRoot(t)
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

// TestLegacyAuditChainKeepsWorkingInPlace is acceptance item (c) under the
// no-migration contract: a chain an older NockLock wrote to
// <root>/.nock/events.db keeps being used and keeps verifying, and NockLock does
// NOT move it. Relocating a live SQLite database, its WAL sidecars and its chain
// anchor together is exactly the operation that can half-succeed and leave a
// chain that verifies while missing its tail, so an existing audit trail is left
// alone and the fence gives up the root-mutation grant instead.
func TestLegacyAuditChainKeepsWorkingInPlace(t *testing.T) {
	projectRoot, configPath := writeProjectConfig(t, `db = ".nock/events.db"`)
	legacyDB := filepath.Join(projectRoot, config.Dir, "events.db")

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
		t.Fatalf("legacy chain not intact to begin with: %s", before.BrokenReason)
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
	if dbPath != legacyDB {
		t.Fatalf("event log = %q, want the legacy in-project log %q left exactly where it is", dbPath, legacyDB)
	}

	reopened, err := logging.NewLogger(dbPath, projectRoot)
	if err != nil {
		t.Fatalf("reopen legacy event log: %v", err)
	}
	defer reopened.Close()
	after, err := reopened.VerifyChain()
	if err != nil {
		t.Fatalf("verify legacy chain after resolve: %v", err)
	}
	if !after.Intact {
		t.Fatalf("legacy chain not intact: %s", after.BrokenReason)
	}
	if after.EntriesVerified != before.EntriesVerified || after.HeadHash != before.HeadHash {
		t.Fatalf("legacy chain changed: %d/%q -> %d/%q", before.EntriesVerified, before.HeadHash, after.EntriesVerified, after.HeadHash)
	}
}

// TestLegacyAuditDirCostsTheRootMutationGrant is the other half of the
// trade-off: while the audit trail sits inside the fence root, the root must NOT
// be granted, because Landlock cannot exclude a directory beneath a granted one.
func TestLegacyAuditDirCostsTheRootMutationGrant(t *testing.T) {
	projectRoot, configPath := writeProjectConfig(t, `db = ".nock/events.db"`)
	legacyDB := filepath.Join(projectRoot, config.Dir, "events.db")
	if err := os.WriteFile(legacyDB, []byte("legacy chain"), 0o600); err != nil {
		t.Fatalf("write legacy log: %v", err)
	}
	if err := os.Mkdir(filepath.Join(projectRoot, "src"), 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	dbPath, gotRoot, err := config.ResolveDBPath(cfg, configPath)
	if err != nil {
		t.Fatalf("ResolveDBPath: %v", err)
	}
	if dbPath != legacyDB {
		t.Fatalf("event log = %q, want the legacy in-project log %q", dbPath, legacyDB)
	}
	auditDir := filepath.Dir(dbPath)
	if !pathIsWithinDir(auditDir, gotRoot) {
		t.Fatalf("audit dir %q is not inside the project root %q", auditDir, gotRoot)
	}

	spec, err := landlock.RulesFromConfig(&fsfence.FenceConfig{
		Root:                projectRoot,
		Mode:                "read-write",
		ProtectedRootSubdir: auditDir,
	}, nil, 5)
	if err != nil {
		t.Fatalf("RulesFromConfig: %v", err)
	}
	for _, rule := range spec.Paths {
		if rule.Path == projectRoot {
			t.Fatalf("fence root %q was granted while the audit trail is inside it: %+v", projectRoot, rule)
		}
		if rule.Path == auditDir || strings.HasPrefix(rule.Path, auditDir+string(os.PathSeparator)) {
			t.Fatalf("audit path %q was granted: %+v", rule.Path, spec.Paths)
		}
	}
	// Existing children are still granted, so the agent keeps working inside them.
	var sawSrc bool
	for _, rule := range spec.Paths {
		if rule.Path == filepath.Join(projectRoot, "src") {
			sawSrc = true
		}
	}
	if !sawSrc {
		t.Fatalf("root child src was not granted: %+v", spec.Paths)
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
	stateDir, err := config.EnsureAuditStateDir(projectRoot)
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
	} else if !strings.Contains(err.Error(), "event logs found") {
		t.Fatalf("expected an event-logs-found error, got: %v", err)
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
