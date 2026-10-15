package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestOverlayKeySpellingDecidesNothing proves an overlay restricts a --profile
// fence the same way whether its keys are spelled plainly or with U+017F (long
// s). The TOML decoder folds that rune onto "s" when it matches keys to fields,
// while strings.ToLower leaves it alone, so a presence check on lowercased key
// text would skip the restriction. Each case loosens one restricted field; the
// plain spelling and every folded spelling must land on the same tightened
// value, and a control overlay that tightens must still be honoured.
func TestOverlayKeySpellingDecidesNothing(t *testing.T) {
	base, err := LoadProfile("claude-code")
	if err != nil {
		t.Fatalf("LoadProfile(claude-code): %v", err)
	}
	// The preset is read-write; a read-only base is the only way to loosen mode.
	base.Filesystem.Mode = "read-only"

	cases := []struct {
		table, key, value string
		get               func(Config) any
		want              any
	}{
		{"secrets", "pass", "[]", func(c Config) any { return c.Secrets.Pass }, base.Secrets.Pass},
		{"secrets", "block", "[]", func(c Config) any { return c.Secrets.Block }, base.Secrets.Block},
		{"syscall", "enforcement", `"off"`, func(c Config) any { return c.Syscall.Enforcement }, "required"},
		{"syscall", "socket_families", "[]", func(c Config) any { return c.Syscall.SocketFamilies }, base.Syscall.SocketFamilies},
		{"filesystem", "allow", `["/", "/tmp/"]`, func(c Config) any { return c.Filesystem.Allow }, []string{"/tmp/"}},
		{"filesystem", "allow_rw", `["/etc/"]`, func(c Config) any { return c.Filesystem.AllowRW }, []string{}},
		{"filesystem", "deny", "[]", func(c Config) any { return c.Filesystem.Deny }, base.Filesystem.Deny},
		{"filesystem", "mode", `"read-write"`, func(c Config) any { return c.Filesystem.Mode }, "read-only"},
		{"filesystem", "root", `"/"`, func(c Config) any { return c.Filesystem.Root }, base.Filesystem.Root},
		{"filesystem", "linux_enforcement", `"off"`, func(c Config) any { return c.Filesystem.LinuxEnforcement }, "required"},
	}

	fold := func(s string) string { return strings.ReplaceAll(s, "s", "ſ") }
	for _, tc := range cases {
		variants := map[string]string{
			"plain":        fmt.Sprintf("[%q]\n%q = %s\n", tc.table, tc.key, tc.value),
			"folded table": fmt.Sprintf("[%q]\n%q = %s\n", fold(tc.table), tc.key, tc.value),
		}
		if fold(tc.key) != tc.key {
			variants["folded key"] = fmt.Sprintf("[%q]\n%q = %s\n", tc.table, fold(tc.key), tc.value)
			variants["folded both"] = fmt.Sprintf("[%q]\n%q = %s\n", fold(tc.table), fold(tc.key), tc.value)
		}
		for name, doc := range variants {
			t.Run(tc.table+"."+tc.key+"/"+name, func(t *testing.T) {
				got, err := LoadOverlay(*base, writeOverlayFile(t, doc))
				if err != nil {
					t.Fatalf("LoadOverlay: %v", err)
				}
				if g, w := fmt.Sprint(tc.get(*got)), fmt.Sprint(tc.want); g != w {
					t.Fatalf("%s.%s = %s, want %s (overlay loosened the fence)", tc.table, tc.key, g, w)
				}
			})
		}
	}

	// Negative control: the same folded spelling still carries a tightening.
	got, err := LoadOverlay(*base, writeOverlayFile(t, "[\"ſecrets\"]\n\"paſſ\" = [\"HOME\"]\n"))
	if err != nil {
		t.Fatalf("LoadOverlay: %v", err)
	}
	if fmt.Sprint(got.Secrets.Pass) != "[HOME]" {
		t.Fatalf("secrets.pass = %v, want [HOME]", got.Secrets.Pass)
	}
}

func writeOverlayFile(t *testing.T, content string) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), ".nock")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}
