package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// TestOverlayKeySpellingCannotSkipRestriction proves an overlay cannot loosen a
// profile by spelling a key with a character the TOML decoder case-folds onto
// a field name (U+017F "ſ" folds to "s" under strings.EqualFold but not under
// strings.ToLower). Every restricted field is tried with a plain spelling and
// with "ſ" in the table name, the key name, and both.
func TestOverlayKeySpellingCannotSkipRestriction(t *testing.T) {
	base, err := LoadProfile("claude-code")
	if err != nil {
		t.Fatalf("LoadProfile(claude-code): %v", err)
	}
	b := cloneConfig(*base)
	b.Filesystem.Mode = "read-only"
	b.Filesystem.AllowRW = []string{"/tmp/"}
	b.Syscall.ExtraDeny = []string{"ptrace"}

	cases := []struct {
		table, key, value string
		wantBase          bool // the profile value must survive; otherwise only the plain result is required
		get               func(Config) any
	}{
		{"secrets", "pass", `[]`, true, func(c Config) any { return c.Secrets.Pass }},
		{"secrets", "block", `[]`, true, func(c Config) any { return c.Secrets.Block }},
		{"syscall", "enforcement", `"off"`, true, func(c Config) any { return c.Syscall.Enforcement }},
		{"syscall", "socket_families", `[]`, true, func(c Config) any { return c.Syscall.SocketFamilies }},
		{"syscall", "extra_deny", `[]`, true, func(c Config) any { return c.Syscall.ExtraDeny }},
		{"filesystem", "root", `"/"`, true, func(c Config) any { return c.Filesystem.Root }},
		{"filesystem", "linux_enforcement", `"off"`, true, func(c Config) any { return c.Filesystem.LinuxEnforcement }},
		{"filesystem", "allow", `["/"]`, false, func(c Config) any { return c.Filesystem.Allow }},
		{"filesystem", "allow_rw", `["/"]`, false, func(c Config) any { return c.Filesystem.AllowRW }},
		{"filesystem", "deny", `[]`, true, func(c Config) any { return c.Filesystem.Deny }},
		{"filesystem", "mode", `"read-write"`, true, func(c Config) any { return c.Filesystem.Mode }},
		{"network", "allow", `["evil.example"]`, false, func(c Config) any { return c.Network.Allow }},
	}
	fold := func(s string) string { return strings.ReplaceAll(s, "s", "ſ") }

	load := func(t *testing.T, table, key, value string) (*Config, error) {
		t.Helper()
		dir := filepath.Join(t.TempDir(), ".nock")
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "config.toml")
		if err := os.WriteFile(path, []byte("[\""+table+"\"]\n\""+key+"\" = "+value+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		return LoadOverlay(b, path)
	}

	for _, tc := range cases {
		spellings := map[string][2]string{
			"plain":      {tc.table, tc.key},
			"fold-table": {fold(tc.table), tc.key},
			"fold-key":   {tc.table, fold(tc.key)},
			"fold-both":  {fold(tc.table), fold(tc.key)},
		}
		plainCfg, err := load(t, tc.table, tc.key, tc.value)
		if err != nil {
			t.Fatalf("plain overlay [%s] %s = %s refused: %v", tc.table, tc.key, tc.value, err)
		}
		plain := *plainCfg
		for name, sp := range spellings {
			if name != "plain" && sp == spellings["plain"] {
				continue // no "s" to fold in this spelling
			}
			t.Run(tc.table+"."+tc.key+"/"+name, func(t *testing.T) {
				cfg, err := load(t, sp[0], sp[1], tc.value)
				if err != nil {
					return // refusing the overlay is also a safe outcome
				}
				want := tc.get(plain)
				if tc.wantBase {
					want = tc.get(b)
				}
				if got := tc.get(*cfg); !reflect.DeepEqual(got, want) {
					t.Fatalf("overlay [%s] %s = %s gave %v, want %v", sp[0], sp[1], tc.value, got, want)
				}
			})
		}
	}

	// Negative control: the same overlay machinery still honours a tightening.
	cfg, err := load(t, "secrets", "pass", `["HOME"]`)
	if err != nil {
		t.Fatalf("tightening overlay refused: %v", err)
	}
	if !reflect.DeepEqual(cfg.Secrets.Pass, []string{"HOME"}) {
		t.Fatalf("tightening secrets.pass = %v, want [HOME]", cfg.Secrets.Pass)
	}
	cfg, err = load(t, "ſecretſ", "paſſ", `["HOME"]`)
	if err != nil {
		t.Fatalf("ſ-spelled tightening overlay refused: %v", err)
	}
	if !reflect.DeepEqual(cfg.Secrets.Pass, []string{"HOME"}) {
		t.Fatalf("ſ-spelled tightening secrets.pass = %v, want [HOME]", cfg.Secrets.Pass)
	}
}
