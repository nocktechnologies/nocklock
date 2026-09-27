package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
)

const legacyAnchorName = "chain-anchor" + ".json"

// TestResolveDBPathLeavesUnrelatedProjectFilesAlone is a negative control for
// the migration. The default logging.db is the bare name "events.db", so a
// project that happens to own a file by that name at its root must NOT have it
// relocated into NockLock's state directory. Only the conventional
// <root>/.nock location is ever migrated from.
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
	if _, _, err := config.ResolveDBPath(cfg, configPath); err != nil {
		t.Fatalf("ResolveDBPath: %v", err)
	}

	data, err := os.ReadFile(stray)
	if err != nil {
		t.Fatalf("project file %s was moved out of the project: %v", stray, err)
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
