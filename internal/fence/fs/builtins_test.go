package fs

import (
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
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

func TestMacOSHomeReadRootUsesPasswdHome(t *testing.T) {
	cfg, _ := builtinFixture(t)
	cfg.Filesystem.ConfineHomeReads = true
	account, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		t.Fatal(err)
	}
	want, err := canonicalizeForProfile(account.HomeDir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ProcessEffectiveConfig(cfg, "darwin")
	if err != nil {
		t.Fatal(err)
	}
	if got.HomeReadRoot != want {
		t.Fatalf("home read root = %q, want passwd home %q (HOME is %q)", got.HomeReadRoot, want, os.Getenv("HOME"))
	}
	cfg.Filesystem.ReadAllow = []string{filepath.Join(want, ".ssh")}
	if _, err := ProcessEffectiveConfig(cfg, "darwin"); err == nil || !strings.Contains(err.Error(), "built-in credential deny") {
		t.Fatalf("passwd-home credential grant was accepted: %v", err)
	}
	cfg.Filesystem.ReadAllow = nil
	cfg.Filesystem.Root = ""
	if _, err := ProcessEffectiveConfig(cfg, "darwin"); err == nil {
		t.Fatal("confine_home_reads with no filesystem.root was accepted")
	}
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

func TestBuiltinCaseVariantGrantOnDarwin(t *testing.T) {
	for _, grant := range []string{"~/.SSH/", "~/.Claude/"} {
		t.Run(grant, func(t *testing.T) {
			cfg, _ := builtinFixture(t)
			cfg.Filesystem.Allow = []string{grant}
			if _, err := ProcessEffectiveConfig(cfg, "darwin"); err == nil || !strings.Contains(err.Error(), "built-in credential deny") {
				t.Fatalf("darwin case-variant grant %q: want credential-overlap refusal, got %v", grant, err)
			}
			if _, err := ProcessEffectiveConfig(cfg, "linux"); err != nil {
				t.Fatalf("linux case-variant grant %q should remain separate: %v", grant, err)
			}
		})
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

func TestBuiltinPrefixAliasesWithTrailingHomeSlash(t *testing.T) {
	cfg, home := builtinFixture(t)
	alias := filepath.Join(home, ".env.production")
	if err := os.WriteFile(alias, []byte("fake-canary"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home+string(os.PathSeparator))
	fc, err := ProcessEffectiveConfig(cfg, "darwin")
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolvePath(alias)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(fc.PrefixAliasPaths, resolved) {
		t.Fatalf("trailing HOME slash dropped credential alias %q", resolved)
	}
}

// --profile opencode and --profile goose exempt exactly their own directory
// beneath the built-in ~/.config deny. Controls: the exact grant starts; every
// other grant beneath ~/.config, the other agent's directory, a sibling sharing
// the name as a prefix, a path inside the own directory, ~/.config itself, and
// the same grant without the profile all still refuse.
func TestBuiltinOwnConfigDirExemption(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		for _, tc := range []struct{ profile, own, other string }{
			{"opencode", "opencode", "goose"},
			{"goose", "goose", "opencode"},
		} {
			t.Run(goos+"/"+tc.profile, func(t *testing.T) {
				cfg, home := builtinFixture(t)
				cfg.ProfileName = tc.profile
				cfg.Filesystem.Allow = []string{"~/.config/" + tc.own + "/"}
				fc, err := ProcessEffectiveConfig(cfg, goos)
				if err != nil {
					t.Fatalf("own config grant refused: %v", err)
				}
				h, _ := resolvePath(home)
				dotConfig := filepath.Join(h, ".config")
				if want := filepath.Join(dotConfig, tc.own); fc.OwnConfigDir != want {
					t.Fatalf("OwnConfigDir = %q, want %q", fc.OwnConfigDir, want)
				}
				// Linux leaves the parent to the allow-list default; macOS keeps
				// the Seatbelt deny. Both record it in the signed policy.
				if slices.Contains(fc.DenyPaths, dotConfig) != (goos == "darwin") {
					t.Fatalf("%s enforced deny of %s = %v", goos, dotConfig, fc.DenyPaths)
				}
				if !slices.Contains(fc.PolicyDenyPaths(), dotConfig) {
					t.Fatalf("policy denies dropped %s: %v", dotConfig, fc.PolicyDenyPaths())
				}
				if !slices.Contains(fc.DenyPaths, filepath.Join(h, ".ssh")) {
					t.Fatal("other built-in denies must stay enforced")
				}

				for _, grant := range []string{
					"~/.config/gh/",
					"~/.config/" + tc.other + "/",
					"~/.config/" + tc.own + "-extra/",
					"~/.config/" + tc.own + "/sub/",
					"~/.config/",
					"~/",
				} {
					cfg.Filesystem.Allow = []string{"~/.config/" + tc.own + "/", grant}
					_, err := ProcessEffectiveConfig(cfg, goos)
					if err == nil || !strings.Contains(err.Error(), "built-in credential deny") {
						t.Fatalf("grant %q beside the own config dir: want refusal, got %v", grant, err)
					}
				}

				// project.runtime is writable by the fenced child; alone it
				// exempts nothing, and the refusal names the profile flag.
				cfg.ProfileName, cfg.Project.Runtime = "", tc.profile
				cfg.Filesystem.Allow = []string{"~/.config/" + tc.own + "/"}
				_, err = ProcessEffectiveConfig(cfg, goos)
				if err == nil || !strings.Contains(err.Error(), "--profile "+tc.profile) {
					t.Fatalf("own config grant without the profile: want refusal naming --profile, got %v", err)
				}
			})
		}
	}
}

// A user deny of ~/.config is kept even when the profile grants its own
// directory beneath it, so Landlock refuses the ruleset rather than drop it.
func TestBuiltinOwnConfigDirKeepsUserDeny(t *testing.T) {
	cfg, home := builtinFixture(t)
	cfg.ProfileName = "opencode"
	cfg.Filesystem.Allow = []string{"~/.config/opencode/"}
	cfg.Filesystem.Deny = append(cfg.Filesystem.Deny, "~/.config/")
	fc, err := ProcessEffectiveConfig(cfg, "linux")
	if err != nil {
		t.Fatal(err)
	}
	h, _ := resolvePath(home)
	if !slices.Contains(fc.DenyPaths, filepath.Join(h, ".config")) || fc.OwnConfigParent != "" {
		t.Fatalf("user deny of ~/.config dropped: %v (parent %q)", fc.DenyPaths, fc.OwnConfigParent)
	}
}

// The Seatbelt exception follows the ~/.config deny (Seatbelt applies the last
// matching rule), and a configured deny inside the own directory follows it.
func TestEffectiveProfileOwnConfigDirAllowFollowsDeny(t *testing.T) {
	cfg, home := builtinFixture(t)
	cfg.ProfileName = "goose"
	cfg.Filesystem.Allow = []string{"~/.config/goose/"}
	cfg.Filesystem.Deny = append(cfg.Filesystem.Deny, "~/.config/goose/secrets.yaml")
	fc, err := ProcessEffectiveConfig(cfg, "darwin")
	if err != nil {
		t.Fatal(err)
	}
	profile, _, err := GenerateEffectiveProfile(fc, false, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	own, err := canonicalizeForProfile(filepath.Join(home, ".config", "goose"))
	if err != nil {
		t.Fatal(err)
	}
	dotConfig, _ := resolvePath(filepath.Join(home, ".config"))
	allow := strings.Index(profile, "(allow file-read* (subpath "+sbplString(own)+"))")
	deny := strings.LastIndex(profile, "(regex #"+sbplString("^"+caseFoldPattern(dotConfig)+"(/|$)")+")")
	secret := strings.LastIndex(profile, "(regex #"+sbplString("^"+caseFoldPattern(filepath.Join(fc.OwnConfigDir, "secrets.yaml"))+"(/|$)")+")")
	if allow < 0 || deny < 0 || allow < deny {
		t.Fatalf("own config allow (at %d) must follow the ~/.config deny (at %d):\n%s", allow, deny, profile)
	}
	if secret < allow {
		t.Fatalf("deny inside the own config dir (at %d) must follow its allow (at %d):\n%s", secret, allow, profile)
	}
	if strings.Contains(profile, "(allow file-write* (subpath "+sbplString(own)) {
		t.Fatal("own config exception must not grant writes")
	}

	// Control: without the profile no exception is emitted.
	cfg.ProfileName, cfg.Filesystem.Allow = "", nil
	fc, err = ProcessEffectiveConfig(cfg, "darwin")
	if err != nil {
		t.Fatal(err)
	}
	profile, _, err = GenerateEffectiveProfile(fc, false, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(profile, sbplString(own)+"))") {
		t.Fatalf("exception emitted without the profile:\n%s", profile)
	}
}
