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
	t.Setenv("XDG_STATE_HOME", trustedStateRoot(t))
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

// TestResolveDBPathRejectsSymlinkedConventionalLog: canonicalizing candidates
// for de-duplication must not blind the existence scan to a symlink planted
// AT a candidate path. resolveExisting follows a symlink leaf as readily as a
// symlinked ancestor, so canonicalizing before the Lstat that detects a
// symlink -- instead of after -- would silently follow ".nock/events.db" to
// wherever it points and adopt that file as the audit chain, exactly the
// attack the symlink refusal exists to stop.
func TestResolveDBPathRejectsSymlinkedConventionalLog(t *testing.T) {
	projectRoot, configPath := writeProjectConfig(t, `db = "events.db"`)
	outside := filepath.Join(t.TempDir(), "attacker-controlled.db")
	if err := os.WriteFile(outside, []byte("not the real chain"), 0o600); err != nil {
		t.Fatalf("write outside file: %v", err)
	}
	conventional := filepath.Join(projectRoot, config.Dir, "events.db")
	if err := os.Symlink(outside, conventional); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if _, _, err := config.ResolveDBPath(cfg, configPath); err == nil {
		t.Fatal("expected a symlinked conventional log to be refused")
	} else if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected a symlink error, got: %v", err)
	}
}

// TestResolveDBPathRejectsSymlinkedStateDirCandidateCoincidingWithConventional
// covers the specific shape the plain single-candidate symlink test above
// cannot: a symlink planted at a LATER candidate (here, the state-dir one)
// whose target canonicalizes to the SAME file an EARLIER candidate (the
// conventional one) already reaches directly. Deduplicating candidates by
// canonical form before running the symlink check on each of them would drop
// this state-dir candidate from the scan entirely -- its own Lstat, and the
// refusal it should trigger, would never run -- because its canonical form
// looks like a duplicate of the conventional candidate already accepted.
func TestResolveDBPathRejectsSymlinkedStateDirCandidateCoincidingWithConventional(t *testing.T) {
	projectRoot, configPath := writeProjectConfig(t, `db = "events.db"`)
	conventional := filepath.Join(projectRoot, config.Dir, "events.db")
	if err := os.WriteFile(conventional, []byte("real chain"), 0o600); err != nil {
		t.Fatalf("write conventional log: %v", err)
	}

	stateDir, err := config.EnsureAuditStateDir(projectRoot)
	if err != nil {
		t.Fatalf("EnsureAuditStateDir: %v", err)
	}
	relocated := filepath.Join(stateDir, "events.db")
	if err := os.Symlink(conventional, relocated); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if _, _, err := config.ResolveDBPath(cfg, configPath); err == nil {
		t.Fatal("expected a symlinked state-dir candidate to be refused even though it coincides with a real candidate")
	} else if !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("expected a symlink error, got: %v", err)
	}
}

// TestResolveDBPathCanonicalizesSymlinkedStateDirCandidate reproduces, without
// depending on any one platform's temp-dir layout, the shape of the macOS CI
// failure that motivated canonicalizing every ResolveDBPath candidate: the
// project-side candidates are already resolved (writeProjectConfig resolves
// the project root), but the state-dir candidate is built from whatever
// XDG_STATE_HOME says, unresolved. Routing XDG_STATE_HOME through an explicit
// symlink reproduces that same "same file, two spellings" shape portably.
// Without canonicalizing every candidate first, the refusal below would name
// the relocated chain by its symlinked spelling instead of the canonical path
// EnsureAuditStateDir actually created it under.
func TestResolveDBPathCanonicalizesSymlinkedStateDirCandidate(t *testing.T) {
	projectRoot, configPath := writeProjectConfig(t, `db = "events.db"`)

	realStateHome := trustedStateRoot(t)
	linkedStateHome := filepath.Join(t.TempDir(), "state-link")
	if err := os.Symlink(realStateHome, linkedStateHome); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	t.Setenv("XDG_STATE_HOME", linkedStateHome)

	stateDir, err := config.EnsureAuditStateDir(projectRoot)
	if err != nil {
		t.Fatalf("EnsureAuditStateDir: %v", err)
	}
	relocated := filepath.Join(stateDir, "events.db")
	if err := os.WriteFile(relocated, []byte("relocated chain"), 0o600); err != nil {
		t.Fatalf("write relocated log: %v", err)
	}
	conventional := filepath.Join(projectRoot, config.Dir, "events.db")
	if err := os.WriteFile(conventional, []byte("conventional chain"), 0o600); err != nil {
		t.Fatalf("write conventional log: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	_, _, err = config.ResolveDBPath(cfg, configPath)
	if err == nil {
		t.Fatal("expected two coexisting audit chains to be refused")
	}
	if !strings.Contains(err.Error(), relocated) {
		t.Fatalf("expected the error to name the relocated chain at its canonical path %q, got: %v", relocated, err)
	}
	if strings.Contains(err.Error(), linkedStateHome) {
		t.Fatalf("expected the error to use the canonical state-dir spelling, not the symlinked one %q, got: %v", linkedStateHome, err)
	}
}

// TestResolveDBPathRefusesAbsoluteConfiguredAlongsideStateDirChain: an
// absolute logging.db used to be returned immediately, before the state-dir
// candidate was even scanned, so a real chain already sitting in the state
// dir was silently abandoned the moment logging.db was reconfigured to an
// absolute path. It must now join the same candidate scan and be refused when
// a state-dir chain already exists.
func TestResolveDBPathRefusesAbsoluteConfiguredAlongsideStateDirChain(t *testing.T) {
	projectRoot, configPath := writeProjectConfig(t, `db = "events.db"`)
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	stateDir, err := config.EnsureAuditStateDir(projectRoot)
	if err != nil {
		t.Fatalf("EnsureAuditStateDir: %v", err)
	}
	relocated := filepath.Join(stateDir, "events.db")
	if err := os.WriteFile(relocated, []byte("relocated chain"), 0o600); err != nil {
		t.Fatalf("write relocated log: %v", err)
	}

	absDB := filepath.Join(projectRoot, "audit", "events.db")
	cfg.Logging.DB = absDB

	_, _, err = config.ResolveDBPath(cfg, configPath)
	if err == nil {
		t.Fatal("expected an absolute logging.db to be refused when a state-dir chain already exists")
	}
	if !strings.Contains(err.Error(), "event logs found") {
		t.Fatalf("expected an event-logs-found error, got: %v", err)
	}
	if !strings.Contains(err.Error(), relocated) || !strings.Contains(err.Error(), absDB) {
		t.Fatalf("expected the error to name both the state-dir chain %q and the absolute path %q, got: %v", relocated, absDB, err)
	}
}

// TestResolveDBPathAbsoluteConfiguredWithNoConflict is the positive control
// for the refusal above: an absolute logging.db with nothing else on disk
// still resolves to exactly the configured path.
func TestResolveDBPathAbsoluteConfiguredWithNoConflict(t *testing.T) {
	projectRoot, configPath := writeProjectConfig(t, `db = "events.db"`)
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	absDB := filepath.Join(projectRoot, "audit", "events.db")
	cfg.Logging.DB = absDB

	dbPath, _, err := config.ResolveDBPath(cfg, configPath)
	if err != nil {
		t.Fatalf("ResolveDBPath: %v", err)
	}
	if dbPath != absDB {
		t.Fatalf("event log = %q, want the configured absolute path %q", dbPath, absDB)
	}
}

func TestResolveDBPathRenamedLogStillFindsDefaultChain(t *testing.T) {
	tests := []struct {
		name       string
		configured func(string) string
		legacy     bool
	}{
		{
			name: "absolute in-project path",
			configured: func(projectRoot string) string {
				return filepath.Join(projectRoot, "audit", "new.db")
			},
		},
		{
			name: "relative in-project path",
			configured: func(string) string {
				return filepath.Join("audit", "new.db")
			},
		},
		{
			name: "legacy default chain",
			configured: func(string) string {
				return filepath.Join("audit", "new.db")
			},
			legacy: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			projectRoot, configPath := writeProjectConfig(t, `db = "events.db"`)
			cfg, err := config.Load(configPath)
			if err != nil {
				t.Fatalf("load config: %v", err)
			}

			var existing string
			if tt.legacy {
				existing = filepath.Join(projectRoot, config.Dir, "events.db")
			} else {
				stateDir, err := config.EnsureAuditStateDir(projectRoot)
				if err != nil {
					t.Fatalf("EnsureAuditStateDir: %v", err)
				}
				existing = filepath.Join(stateDir, "events.db")
			}
			if err := os.WriteFile(existing, []byte("default chain"), 0o600); err != nil {
				t.Fatalf("write default chain: %v", err)
			}

			cfg.Logging.DB = tt.configured(projectRoot)
			configured := cfg.Logging.DB
			if !filepath.IsAbs(configured) {
				stateDir, err := config.AuditStateDir(projectRoot)
				if err != nil {
					t.Fatalf("AuditStateDir: %v", err)
				}
				configured = filepath.Join(stateDir, filepath.Base(configured))
			}
			_, _, err = config.ResolveDBPath(cfg, configPath)
			if err == nil {
				t.Fatal("expected a renamed logging.db to be refused while the default chain exists")
			}
			if !strings.Contains(err.Error(), "event logs found") {
				t.Fatalf("expected an event-logs-found error, got: %v", err)
			}
			if !strings.Contains(err.Error(), existing) || !strings.Contains(err.Error(), configured) {
				t.Fatalf("expected the error to name the default chain %q and configured path %q, got: %v", existing, configured, err)
			}
		})
	}
}

func TestResolveDBPathDefaultCandidatesDoNotSelfConflict(t *testing.T) {
	projectRoot, configPath := writeProjectConfig(t, `db = "events.db"`)
	stateDir, err := config.EnsureAuditStateDir(projectRoot)
	if err != nil {
		t.Fatalf("EnsureAuditStateDir: %v", err)
	}
	existing := filepath.Join(stateDir, "events.db")
	if err := os.WriteFile(existing, []byte("default chain"), 0o600); err != nil {
		t.Fatalf("write default chain: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	dbPath, _, err := config.ResolveDBPath(cfg, configPath)
	if err != nil {
		t.Fatalf("ResolveDBPath: %v", err)
	}
	if dbPath != existing {
		t.Fatalf("event log = %q, want existing default chain %q", dbPath, existing)
	}
}

func TestResolveDBPathAdoptsExistingRenamedRelativeLogWithoutDefaultChain(t *testing.T) {
	projectRoot, configPath := writeProjectConfig(t, `db = "audit/new.db"`)
	existing := filepath.Join(projectRoot, "audit", "new.db")
	if err := os.MkdirAll(filepath.Dir(existing), 0o755); err != nil {
		t.Fatalf("mkdir audit dir: %v", err)
	}
	if err := os.WriteFile(existing, []byte("renamed chain"), 0o600); err != nil {
		t.Fatalf("write renamed chain: %v", err)
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	dbPath, _, err := config.ResolveDBPath(cfg, configPath)
	if err != nil {
		t.Fatalf("ResolveDBPath: %v", err)
	}
	if dbPath != existing {
		t.Fatalf("event log = %q, want existing renamed chain %q", dbPath, existing)
	}
}

// TestResolveDBPathAbsoluteStateDirRequiresTrustedRoot pins that spelling an
// audit-state path absolutely cannot bypass the trust checks used for the same
// destination when logging.db is relative.
func TestResolveDBPathAbsoluteStateDirRequiresTrustedRoot(t *testing.T) {
	tests := []struct {
		name    string
		mode    os.FileMode
		wantErr bool
	}{
		{name: "trusted", mode: 0o700},
		{name: "group writable", mode: 0o770, wantErr: true},
		{name: "world writable", mode: 0o707, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			projectRoot, configPath := writeProjectConfig(t, `db = "events.db"`)
			stateRoot := trustedStateRoot(t)
			if err := os.Chmod(stateRoot, tt.mode); err != nil {
				t.Fatalf("chmod state root: %v", err)
			}
			t.Setenv("XDG_STATE_HOME", stateRoot)

			stateDir, err := config.AuditStateDir(projectRoot)
			if err != nil {
				t.Fatalf("AuditStateDir: %v", err)
			}
			absDB := filepath.Join(stateDir, "events.db")
			cfg, err := config.Load(configPath)
			if err != nil {
				t.Fatalf("load config: %v", err)
			}
			cfg.Logging.DB = absDB

			dbPath, _, err := config.ResolveDBPath(cfg, configPath)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an absolute audit-state path under an untrusted state root to be refused")
				}
				if !strings.Contains(err.Error(), "writable") {
					t.Fatalf("expected a writable-directory error, got: %v", err)
				}
				if !strings.Contains(err.Error(), stateRoot) {
					t.Fatalf("expected the error to name the state root %q, got: %v", stateRoot, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("ResolveDBPath: %v", err)
			}
			if dbPath != absDB {
				t.Fatalf("event log = %q, want %q", dbPath, absDB)
			}
		})
	}
}

// TestResolveDBPathAbsoluteInStateDirRejectsWritableIntermediate justifies
// walking intermediate components rather than capping nesting depth: an
// absolute logging.db may resolve deeper than the fixed nocklock/<hash>
// components EnsureAuditStateDir validates (validateAuditDBLocation permits
// arbitrary nesting under the state dir). A group-writable directory between
// the state dir and the log is exactly the substitution threat the per-directory
// trust check exists to stop, so it must be refused too.
func TestResolveDBPathAbsoluteInStateDirRejectsWritableIntermediate(t *testing.T) {
	projectRoot, configPath := writeProjectConfig(t, `db = "events.db"`)
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	stateDir, err := config.EnsureAuditStateDir(projectRoot)
	if err != nil {
		t.Fatalf("EnsureAuditStateDir: %v", err)
	}
	intermediate := filepath.Join(stateDir, "sub")
	if err := os.Mkdir(intermediate, 0o777); err != nil {
		t.Fatalf("mkdir intermediate: %v", err)
	}
	if err := os.Chmod(intermediate, 0o777); err != nil {
		t.Fatalf("chmod intermediate: %v", err)
	}
	cfg.Logging.DB = filepath.Join(intermediate, "events.db")

	if _, _, err := config.ResolveDBPath(cfg, configPath); err == nil {
		t.Fatal("expected an absolute logging.db under a group/world-writable intermediate to be refused")
	} else if !strings.Contains(err.Error(), "writable") {
		t.Fatalf("expected a writable-directory error, got: %v", err)
	}
}

// symlinkedAbsoluteStateRoot points XDG_STATE_HOME at a symlink to a trusted
// root and returns both the resolved root and the absolute logging.db an
// absoluteConfigured input would carry: the RAW, symlinked spelling, since
// that is what AuditStateDir returns once XDG_STATE_HOME is a symlink.
func symlinkedAbsoluteStateRoot(t *testing.T, projectRoot string) (resolvedRoot, absDB string) {
	t.Helper()
	resolvedRoot = os.Getenv("XDG_STATE_HOME")
	linked := filepath.Join(t.TempDir(), "state-link")
	if err := os.Symlink(resolvedRoot, linked); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}
	t.Setenv("XDG_STATE_HOME", linked)
	auditDir, err := config.AuditStateDir(projectRoot)
	if err != nil {
		t.Fatalf("AuditStateDir: %v", err)
	}
	return resolvedRoot, filepath.Join(auditDir, "events.db")
}

// TestResolveDBPathAbsoluteInStateDirThroughSymlinkedStateRootChecksStateRoot
// covers a false-positive Gander raised reviewing this PR: it read
// AuditStateDir's raw, uncanonicalized result being compared against the
// already-canonicalized absoluteConfigured as a bypass on a symlinked state
// root. withinDir (config.go) actually resolves both of its arguments before
// comparing, so the gate is correct as written; this pins that so a future
// change to withinDir or AuditStateDir can't silently reopen it.
func TestResolveDBPathAbsoluteInStateDirThroughSymlinkedStateRootChecksStateRoot(t *testing.T) {
	projectRoot, configPath := writeProjectConfig(t, `db = "events.db"`)
	realStateHome, absDB := symlinkedAbsoluteStateRoot(t, projectRoot)

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	cfg.Logging.DB = absDB

	if err := os.Chmod(realStateHome, 0o770); err != nil {
		t.Fatalf("chmod real state root: %v", err)
	}

	if _, _, err := config.ResolveDBPath(cfg, configPath); err == nil {
		t.Fatal("expected an absolute logging.db reached through a symlinked, group-writable state root to be refused")
	} else if !strings.Contains(err.Error(), "writable") || !strings.Contains(err.Error(), realStateHome) {
		t.Fatalf("expected a writable-directory error naming the resolved state root %q, got: %v", realStateHome, err)
	}
}

// TestResolveDBPathAbsoluteInStateDirThroughSymlinkedStateRootWithNestedComponentSucceeds
// is the positive control: with the state root trusted, a symlinked
// XDG_STATE_HOME and a logging.db nested one level below the audit state
// directory must still resolve, exercising the filepath.Rel/
// ensureTrustedComponents walk (config.go) against a symlinked stateDir,
// which the refusal test above cannot reach.
func TestResolveDBPathAbsoluteInStateDirThroughSymlinkedStateRootWithNestedComponentSucceeds(t *testing.T) {
	projectRoot, configPath := writeProjectConfig(t, `db = "events.db"`)
	_, absDB := symlinkedAbsoluteStateRoot(t, projectRoot)
	absDB = filepath.Join(filepath.Dir(absDB), "sub", "events.db")

	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	cfg.Logging.DB = absDB

	dbPath, _, err := config.ResolveDBPath(cfg, configPath)
	if err != nil {
		t.Fatalf("ResolveDBPath with a trusted, symlinked state root: %v", err)
	}
	if dbPath != absDB {
		t.Fatalf("event log = %q, want the configured absolute path %q", dbPath, absDB)
	}
	info, err := os.Stat(filepath.Dir(dbPath))
	if err != nil {
		t.Fatalf("stat nested component: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o700 {
		t.Fatalf("nested component mode = %04o, want 0700", perm)
	}
}
