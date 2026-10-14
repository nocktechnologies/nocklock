//go:build linux || darwin

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
	"github.com/nocktechnologies/nocklock/internal/fence/fs/landlock"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/spf13/cobra"
)

func setupCLIChainIdentity(t *testing.T) (*logging.Logger, *config.Config, string, string) {
	t.Helper()
	project := t.TempDir()
	t.Chdir(project)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	stateRoot := t.TempDir()
	if err := os.Chmod(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_STATE_HOME", stateRoot)
	t.Setenv("NOCKLOCK_ANCHOR_URL", "")
	cfg := config.DefaultConfig()
	cfg.Logging.DB = filepath.Join(project, ".nock", "custom-events.db")
	if err := os.MkdirAll(filepath.Join(project, config.Dir), 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeConfigTOML(filepath.Join(project, config.Dir, config.File), &cfg); err != nil {
		t.Fatal(err)
	}
	key, err := logging.DefaultSigningKeyPath()
	if err != nil {
		t.Fatal(err)
	}
	logger, err := logging.NewLogger(cfg.Logging.DB, project, logging.WithSigning(key))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { logger.Close() })
	if err := logger.Log(logging.Event{Timestamp: time.Now().Add(-48 * time.Hour), EventType: logging.EventFilePassed, Category: "filesystem", Detail: "disposable identity CLI fixture", SessionID: "identity-cli"}); err != nil {
		t.Fatal(err)
	}
	return logger, &cfg, project, key
}

func TestLogPruneRespectsTrustedChainRegistration(t *testing.T) {
	for _, state := range []string{"legacy", "none", "pending", "enrolled", "missing_record"} {
		t.Run(state, func(t *testing.T) {
			logger, cfg, project, key := setupCLIChainIdentity(t)
			if state != "legacy" {
				id, err := logger.InitializeChainIdentity(strings.Repeat("0", 64))
				if err != nil {
					t.Fatal(err)
				}
				if state == "pending" || state == "enrolled" {
					_, err = logger.RegisterChainIdentity(func(logging.ChainIdentity) (*logging.ChainRegistrationConfirmation, error) {
						if state == "pending" {
							return nil, errors.New("simulated timeout")
						}
						return &logging.ChainRegistrationConfirmation{AgentID: id.AgentID, ChainID: id.ChainID}, nil
					})
					if state == "enrolled" && err != nil {
						t.Fatal(err)
					}
				}
				if state == "missing_record" {
					dir, err := config.AuditStateDir(project)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.Remove(filepath.Join(dir, logging.ChainIdentityFileName)); err != nil {
						t.Fatal(err)
					}
				}
			}
			logger.Close()
			cmd := &cobra.Command{}
			cmd.Flags().String("prune", "24h", "")
			err := logCmd.RunE(cmd, nil)
			allowed := state == "legacy" || state == "none"
			if allowed && err != nil {
				t.Fatalf("allowed prune: %v", err)
			}
			if !allowed && (err == nil || !strings.Contains(err.Error(), "remote pin") || !strings.Contains(err.Error(), "chain-identity-move.md")) {
				t.Fatalf("missing actionable refusal: %v", err)
			}
			check, openErr := logging.NewLogger(cfg.Logging.DB, project, logging.WithSigning(key))
			if openErr != nil {
				t.Fatal(openErr)
			}
			defer check.Close()
			stats, statsErr := check.Stats("")
			if statsErr != nil {
				t.Fatal(statsErr)
			}
			want := 1
			if allowed {
				want = 0
			}
			if stats.TotalEvents != want {
				t.Fatalf("events=%d,want%d", stats.TotalEvents, want)
			}
		})
	}
}

func TestWrapProtectsIdentityOutsideConfiguredLogDirectory(t *testing.T) {
	logger, cfg, project, _ := setupCLIChainIdentity(t)
	if err := protectChainIdentity(cfg, logger); err != nil {
		t.Fatalf("legacy control: %v", err)
	}
	futureDir, err := logger.TrustedChainStateDirectory()
	if err != nil || !slices.Contains(cfg.Filesystem.Deny, futureDir) {
		t.Fatalf("future identity not denied before creation: %q, %v", futureDir, err)
	}
	if _, err := logger.ReadChainIdentity(); !errors.Is(err, logging.ErrChainIdentityMissing) {
		t.Fatalf("fence minted identity: %v", err)
	}
	if _, err := logger.InitializeChainIdentity(strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	dir, err := logger.ChainIdentityDirectory()
	if err != nil {
		t.Fatal(err)
	}
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	resolvedProject, err := filepath.EvalSymlinks(project)
	if err != nil {
		t.Fatal(err)
	}
	resolvedDBDir, err := filepath.EvalSymlinks(filepath.Dir(cfg.Logging.DB))
	if err != nil {
		t.Fatal(err)
	}
	if pathIsWithinDir(resolvedDir, resolvedProject) || resolvedDir == resolvedDBDir {
		t.Fatalf("trusted state followed configured in-project DB: %s", dir)
	}
	if err := protectChainIdentity(cfg, logger); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(cfg.Filesystem.Deny, dir) {
		t.Fatalf("trusted directory missing from child deny: %v", cfg.Filesystem.Deny)
	}
	cfg.Filesystem.Root = ""
	if err := protectChainIdentity(cfg, logger); err == nil {
		t.Fatal("disabled filesystem fence accepted trusted identity")
	}
	cfg.Filesystem.Root = project
	cfg.Filesystem.LinuxEnforcement = "off"
	if runtime.GOOS == "linux" {
		if err := protectChainIdentity(cfg, logger); err == nil {
			t.Fatal("userspace-only filesystem fence accepted trusted identity")
		}
	}
}

func TestWrapRefusesUnfencedTrustedIdentityBeforeChild(t *testing.T) {
	logger, cfg, project, key := setupCLIChainIdentity(t)
	if _, err := logger.InitializeChainIdentity(strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	logger.Close()
	cfg.Filesystem.Root = ""
	if err := writeConfigTOML(filepath.Join(project, config.Dir, config.File), cfg); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(project, "child-ran")
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	err := wrapCmd.RunE(cmd, []string{"--", "/usr/bin/touch", marker})
	if err == nil || !strings.Contains(err.Error(), "trusted chain identity") {
		t.Fatalf("expected identity fence refusal: %v", err)
	}
	if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("child ran despite identity refusal: %v", err)
	}
	check, err := logging.NewLogger(cfg.Logging.DB, project, logging.WithSigning(key))
	if err != nil {
		t.Fatal(err)
	}
	defer check.Close()
	blocked := true
	events, err := check.Query(logging.QueryOptions{Blocked: &blocked})
	if err != nil || len(events) != 1 || !strings.Contains(events[0].Detail, "trusted chain identity protection refused") {
		t.Fatalf("refusal missing from audit trail: %+v, %v", events, err)
	}
	verified, err := check.VerifyChainSigned(check.SigningPublicKey(), true)
	if err != nil || !verified.Intact || verified.SigState != "authentic" {
		t.Fatalf("refusal audit chain is not authentic: %+v, %v", verified, err)
	}
}

func TestWrapFutureIdentityLandlockDeny(t *testing.T) {
	logger, _, project, _ := setupCLIChainIdentity(t)
	root := os.Getenv("XDG_STATE_HOME")
	for _, grant := range []string{"none", "read", "write", "root"} {
		t.Run(grant, func(t *testing.T) {
			cfg := config.Config{Filesystem: config.FilesystemConfig{Root: project, Mode: "read-write"}}
			switch grant {
			case "read":
				cfg.Filesystem.Allow = []string{root}
			case "write":
				cfg.Filesystem.AllowRW = []string{root}
			case "root":
				cfg.Filesystem.Root = filepath.Dir(root)
			}
			if err := protectChainIdentity(&cfg, logger); err != nil {
				t.Fatal(err)
			}
			resolved, err := fsfence.ProcessConfig(cfg.Filesystem)
			if err != nil {
				t.Fatal(err)
			}
			_, err = landlock.RulesFromConfig(resolved, nil, 3)
			if grant == "none" {
				if err != nil {
					t.Fatalf("separate writable project refused: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "cannot be enforced by Landlock") {
				t.Fatalf("future identity overlap accepted: %s, %v", grant, err)
			}
		})
	}
	if _, err := logger.ReadChainIdentity(); !errors.Is(err, logging.ErrChainIdentityMissing) {
		t.Fatalf("minted identity: %v", err)
	}
}

func TestWrapFutureIdentityUnderDefaultTempGrant(t *testing.T) {
	logger, cfg, _, _ := setupCLIChainIdentity(t)
	// The normal filesystem preset grants /tmp. A custom state root beneath
	// that broad grant must refuse before any identity has been created.
	root, err := os.MkdirTemp("/tmp", "nocklock-future-state-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(root) })
	t.Setenv("XDG_STATE_HOME", root)
	if err := protectChainIdentity(cfg, logger); err != nil {
		t.Fatal(err)
	}
	resolved, err := fsfence.ProcessConfig(cfg.Filesystem)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := landlock.RulesFromConfig(resolved, nil, 3); err == nil || !strings.Contains(err.Error(), "cannot be enforced by Landlock") {
		t.Fatalf("default broad temp grant accepted future state: %v", err)
	}
}

func TestWrapLegacyUnfencedControlAndFutureStateContainment(t *testing.T) {
	logger, cfg, project, _ := setupCLIChainIdentity(t)
	cfg.Filesystem.Root = ""
	if err := protectChainIdentity(cfg, logger); err != nil {
		t.Fatalf("explicit legacy unfenced control: %v", err)
	}
	cfg.Filesystem.Root = project
	t.Setenv("XDG_STATE_HOME", filepath.Join(project, "attacker-writable-state"))
	if err := protectChainIdentity(cfg, logger); err == nil || !strings.Contains(err.Error(), "outside the fenced project") {
		t.Fatalf("in-project future state accepted: %v", err)
	}
}

func TestTrustedIdentityNonOffLinuxEnforcementRequiresLandlock(t *testing.T) {
	for _, mode := range []string{"", "preferred", "required"} {
		if got := linuxEnforcementMode(mode); got != linuxEnforcementRequired {
			t.Fatalf("%q normalized to %q, not required", mode, got)
		}
	}
	if got := linuxEnforcementMode("off"); got != linuxEnforcementOff {
		t.Fatalf("legacy off control = %q", got)
	}
}
