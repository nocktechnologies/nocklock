package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
)

// rootAuditFixture configures a relative path that resolves through a project
// symlink to an existing events.db directly in the project root. Bare relative
// names resolve to the state directory, and absolute root-level paths are
// rejected, so this exercises the supported path-resolution route that reaches
// the root-level case.
func rootAuditFixture(t *testing.T) (string, string) {
	t.Helper()
	project := t.TempDir()
	stateHome, err := os.MkdirTemp("", "nocklock-test-state-")
	if err != nil {
		t.Fatalf("create state-home fixture: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(stateHome) })
	if err := os.Chmod(stateHome, 0o700); err != nil {
		t.Fatalf("secure state-home fixture: %v", err)
	}
	t.Setenv("XDG_STATE_HOME", stateHome)
	const defaultDB = `db = "events.db"`
	if !strings.Contains(config.DefaultTOML(), defaultDB) {
		t.Fatal("default config no longer contains the expected logging.db value")
	}
	policy := strings.Replace(config.DefaultTOML(), defaultDB, `db = "logs/events.db"`, 1)
	writeTestConfig(t, project, policy)
	if err := os.Symlink(".", filepath.Join(project, "logs")); err != nil {
		t.Fatalf("create audit path symlink: %v", err)
	}
	dbPath := filepath.Join(project, "events.db")
	if err := os.WriteFile(dbPath, nil, 0o600); err != nil {
		t.Fatalf("create root audit database fixture: %v", err)
	}

	configPath := filepath.Join(project, config.Dir, config.File)
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load root audit config: %v", err)
	}
	resolved, resolvedProject, err := config.ResolveDBPath(cfg, configPath)
	if err != nil {
		t.Fatalf("resolve root audit database: %v", err)
	}
	if resolved != dbPath || resolvedProject != project {
		t.Fatalf("resolved audit location = (%q, %q), want (%q, %q)", resolved, resolvedProject, dbPath, project)
	}
	return project, dbPath
}

// auditSidecarPaths returns the logging package's adjacent files other than the
// database itself, in the order supplied by that package.
func auditSidecarPaths(t *testing.T, dbPath string) []string {
	t.Helper()
	paths := logging.AuditFilePaths(dbPath)
	if len(paths) < 2 || paths[0] != dbPath {
		t.Fatalf("logging.AuditFilePaths(%q) must return the database first; got %q", dbPath, paths)
	}
	return paths[1:]
}
