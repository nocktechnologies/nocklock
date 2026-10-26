package fs

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
)

func builtinFixture(t *testing.T) (*config.Config, string) {
	t.Helper()
	base := t.TempDir()
	home, project := filepath.Join(base, "home"), filepath.Join(base, "project")
	for _, p := range []string{home, project} {
		if err := os.Mkdir(p, 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	cfg := config.DefaultConfig()
	cfg.Filesystem.Root, cfg.Filesystem.Allow = project, nil
	cfg.Filesystem.Deny = []string{filepath.Join(base, "user-private")}
	return &cfg, home
}

func TestBuiltinDeniesSurviveUserDeny(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			cfg, home := builtinFixture(t)
			fc, err := ProcessEffectiveConfig(cfg, goos)
			if err != nil {
				t.Fatal(err)
			}
			for _, rel := range []string{".ssh", ".aws", ".gnupg", ".config", ".kube", ".docker", ".netrc", ".git-credentials", ".nock", filepath.Join("Library", "Keychains")} {
				want, _ := resolvePath(filepath.Join(home, rel))
				if !slices.Contains(fc.DenyPaths, want) {
					t.Errorf("missing built-in %s", rel)
				}
			}
			user, _ := resolvePath(cfg.Filesystem.Deny[0])
			if !slices.Contains(fc.DenyPaths, user) {
				t.Fatal("user deny lost")
			}
			if len(cfg.Filesystem.Deny) != 1 {
				t.Fatal("input mutated")
			}
			for _, rel := range []string{".npmrc", ".pypirc"} {
				p, _ := resolvePath(filepath.Join(home, rel))
				if slices.Contains(fc.DenyPaths, p) {
					t.Errorf("%s must remain opt-in", rel)
				}
			}
		})
	}
}

func TestBuiltinDeniesRefuseHomeAllow(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, field := range []string{"root", "allow", "allow_rw", "child"} {
			t.Run(goos+"/"+field, func(t *testing.T) {
				cfg, home := builtinFixture(t)
				switch field {
				case "root":
					cfg.Filesystem.Root = home
				case "allow":
					cfg.Filesystem.Allow = []string{"~/"}
				case "allow_rw":
					cfg.Filesystem.AllowRW = []string{"~/"}
				case "child":
					cfg.Filesystem.Allow = []string{"~/.ssh/key"}
				}
				_, err := ProcessEffectiveConfig(cfg, goos)
				if err == nil || !strings.Contains(err.Error(), "built-in credential deny") || !strings.Contains(err.Error(), "refusing to start") {
					t.Fatalf("want clear refusal, got %v", err)
				}
			})
		}
	}
}

func TestBuiltinAgentPresetExceptions(t *testing.T) {
	for _, agent := range []string{"", "claude-code", "codex"} {
		t.Run(agent, func(t *testing.T) {
			cfg, home := builtinFixture(t)
			cfg.Project.Runtime, cfg.CommandRuntime = agent, agent
			if agent == "claude-code" {
				cfg.Filesystem.Allow = []string{"~/.claude/"}
			}
			if agent == "codex" {
				cfg.Filesystem.Allow = []string{"~/.codex/"}
			}
			fc, err := ProcessEffectiveConfig(cfg, "darwin")
			if err != nil {
				t.Fatal(err)
			}
			h, _ := resolvePath(home)
			if !slices.Contains(fc.DenyPrefixes, filepath.Join(h, ".env")) {
				t.Fatal("home .env prefix missing")
			}
			if slices.Contains(fc.DenyPrefixes, filepath.Join(h, ".claude")) != (agent != "claude-code") {
				t.Fatal("Claude preset exception incorrect")
			}
			if slices.Contains(fc.DenyPaths, filepath.Join(h, ".codex")) != (agent != "codex") {
				t.Fatal("Codex preset exception incorrect")
			}
			if slices.Contains(fc.DenyPaths, filepath.Join(fc.Root, ".env")) {
				t.Fatal("project .env must remain readable")
			}
		})
	}
}

// project.runtime is written in the project config, which the fenced child
// can change, so it exempts a login store only when the wrapped command runs
// that agent or --profile selects it. Control: the matching cases still exempt.
func TestBuiltinLoginStoreNeedsProfileOrWrappedCommand(t *testing.T) {
	for _, tc := range []struct {
		name, profile, command string
		exempt                 bool
	}{
		{name: "unrelated command", command: config.RuntimeForCommand("/bin/sh")},
		{name: "other agent", command: config.RuntimeForCommand("codex")},
		{name: "wrapped agent", command: config.RuntimeForCommand("/usr/local/bin/claude"), exempt: true},
		{name: "profile", profile: "claude-code", command: config.RuntimeForCommand("/bin/sh"), exempt: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg, home := builtinFixture(t)
			cfg.Project.Runtime = "claude-code"
			cfg.ProfileName, cfg.CommandRuntime = tc.profile, tc.command
			fc, err := ProcessEffectiveConfig(cfg, "darwin")
			if err != nil {
				t.Fatal(err)
			}
			h, _ := resolvePath(home)
			if slices.Contains(fc.DenyPrefixes, filepath.Join(h, ".claude")) == tc.exempt {
				t.Fatalf("Claude login store exempt = %v, want %v", !tc.exempt, tc.exempt)
			}
			if !slices.Contains(fc.DenyPaths, filepath.Join(h, ".codex")) {
				t.Fatal("Codex login store must stay denied")
			}

			// An init-style config also grants the store; without the
			// exemption that grant must refuse startup, not open the store.
			cfg.Filesystem.Allow = []string{"~/.claude/"}
			_, err = ProcessEffectiveConfig(cfg, "darwin")
			if tc.exempt != (err == nil) {
				t.Fatalf("grant of the login store: exempt=%v, err=%v", tc.exempt, err)
			}
			if err != nil && !strings.Contains(err.Error(), "--profile") {
				t.Fatalf("login-store refusal must name --profile: %v", err)
			}
		})
	}
}

func TestBuiltinPrefixProfileProtectsFutureAndCaseAliases(t *testing.T) {
	cfg, home := builtinFixture(t)
	if err := os.WriteFile(filepath.Join(home, ".env.production"), []byte("fake-canary"), 0600); err != nil {
		t.Fatal(err)
	}
	fc, err := ProcessEffectiveConfig(cfg, "darwin")
	if err != nil {
		t.Fatal(err)
	}
	profile, _, err := GenerateEffectiveProfile(fc, false, "test-tag", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, prefix := range fc.DenyPrefixes {
		want := "(regex #" + sbplString("^"+caseFoldPattern(prefix)+".*") + ")"
		if !strings.Contains(profile, want) {
			t.Fatalf("missing future-name prefix: %s", want)
		}
	}
	if !strings.Contains(profile, `[sS][sS][hH]`) {
		t.Fatal("case-insensitive credential rule missing")
	}
	cfg.Filesystem.Allow = []string{"~/.env.future"}
	if _, err := ProcessEffectiveConfig(cfg, "darwin"); err == nil {
		t.Fatal("prefix-covered allow must fail")
	}
}

func TestBuiltinPrefixAliasesStayEnforcedButOutOfPolicy(t *testing.T) {
	cfg, home := builtinFixture(t)
	before, err := ProcessEffectiveConfig(cfg, "darwin")
	if err != nil {
		t.Fatal(err)
	}
	if len(before.PrefixAliasPaths) != 0 {
		t.Fatalf("empty home recorded aliases: %v", before.PrefixAliasPaths)
	}
	names := []string{".env.production", ".claude-backup"}
	for _, name := range names {
		if err := os.WriteFile(filepath.Join(home, name), []byte("fake-canary"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	after, err := ProcessEffectiveConfig(cfg, "darwin")
	if err != nil {
		t.Fatal(err)
	}
	h, _ := resolvePath(home)
	for _, name := range names {
		alias := filepath.Join(h, name)
		if !slices.Contains(after.DenyPaths, alias) || !slices.Contains(after.PrefixAliasPaths, alias) {
			t.Fatalf("%s must be enforced and recorded as a prefix alias", name)
		}
	}
	policy := after.PolicyDenyPaths()
	if !slices.Equal(policy, before.DenyPaths) || !slices.Equal(after.DenyPrefixes, before.DenyPrefixes) {
		t.Fatalf("policy denies changed: %v -> %v", before.DenyPaths, policy)
	}
	if slices.Contains(after.PrefixAliasPaths, filepath.Join(h, ".ssh")) {
		t.Fatal("static deny recorded as a prefix alias")
	}
}
