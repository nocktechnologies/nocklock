package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Case-fold runes the TOML decoder maps onto an ASCII letter when it matches
// keys and table names to struct fields, but strings.ToLower leaves untouched.
// A presence check on lowercased key text would therefore skip the restriction
// for a key spelled with one of these.
const (
	longS  = "ſ" // ſ LATIN SMALL LETTER LONG S, folds onto "s"
	kelvin = "K" // K KELVIN SIGN, folds onto "k"
)

// foldLongS and foldKelvin rewrite an identifier into its folded spelling; both
// are shared by the variant table and the positive control.
func foldLongS(s string) string  { return strings.ReplaceAll(s, "s", longS) }
func foldKelvin(s string) string { return strings.ReplaceAll(s, "k", kelvin) }

// TestOverlayKeySpellingDecidesNothing proves an overlay restricts a --profile
// fence the same way whether its keys are spelled plainly or with a case-fold
// rune. The TOML decoder folds such a rune onto its ASCII letter when it matches
// keys to fields, while strings.ToLower leaves it alone, so a presence check on
// lowercased key text would skip the restriction. Each case loosens one
// restricted field; every spelling that the decoder accepts must land on the
// same tightened value, and a spelling the decoder rejects is a fail-closed
// refusal (the strict profile stands), not a loosening.
func TestOverlayKeySpellingDecidesNothing(t *testing.T) {
	base, err := LoadProfile("claude-code")
	if err != nil {
		t.Fatalf("LoadProfile(claude-code): %v", err)
	}
	// The preset is read-write; a read-only base is the only way to loosen mode.
	base.Filesystem.Mode = "read-only"

	// The []-overlay cases only discriminate a loosening from an untouched field
	// when the base is non-empty: with an empty base, got == want == [] either
	// way. Bind the test to the real preset carrying these restrictions.
	for _, f := range []struct {
		name string
		got  []string
	}{
		{"Secrets.Pass", base.Secrets.Pass},
		{"Secrets.Block", base.Secrets.Block},
		{"Filesystem.Deny", base.Filesystem.Deny},
		{"Syscall.SocketFamilies", base.Syscall.SocketFamilies},
	} {
		if len(f.got) == 0 {
			t.Fatalf("base %s is empty; the []-overlay cases cannot tell a loosening from an untouched field", f.name)
		}
	}

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
		// A disjoint network allow cannot survive the intersection with the base
		// allow list, so the loosened host never reaches the fence.
		{"network", "allow", `["evil.example"]`, func(c Config) any { return c.Network.Allow }, []string{}},
		// A boolean widener is AND-ed with the base, so an overlay that sets it
		// true on a base that has it false stays false.
		{"network", "allow_all", "true", func(c Config) any { return c.Network.AllowAll }, false},
	}

	// Fold transforms applied in a fixed order (long s before Kelvin) so the
	// subtest set is deterministic. A variant is emitted only when the transform
	// actually changes the identifier, so "kelvin key" appears for block and
	// socket_families (the keys that carry a "k") and nowhere a rune is absent.
	folds := []struct {
		name string
		fn   func(string) string
	}{
		{"long-s", foldLongS},
		{"kelvin", foldKelvin},
	}

	for _, tc := range cases {
		doc := func(table, key string) string {
			return fmt.Sprintf("[%q]\n%q = %s\n", table, key, tc.value)
		}
		type variant struct{ name, doc string }
		variants := []variant{{"plain", doc(tc.table, tc.key)}}
		for _, f := range folds {
			ft, fk := f.fn(tc.table), f.fn(tc.key)
			if ft != tc.table {
				variants = append(variants, variant{f.name + " table", doc(ft, tc.key)})
			}
			if fk != tc.key {
				variants = append(variants, variant{f.name + " key", doc(tc.table, fk)})
			}
			if ft != tc.table && fk != tc.key {
				variants = append(variants, variant{f.name + " both", doc(ft, fk)})
			}
		}

		// Decide refusal-vs-load outside the subtest so the counters are not
		// mutated from t.Run closures (which would race under t.Parallel), and so
		// a refusal (a spelling the decoder rejects: fail-closed, the strict
		// profile stands) is distinguished from a loosening.
		foldedChecked := 0
		for _, v := range variants {
			got, err := LoadOverlay(*base, writeOverlayFile(t, v.doc))
			if err != nil {
				t.Logf("%s.%s: LoadOverlay refused the %s spelling (fail-closed): %v", tc.table, tc.key, v.name, err)
				continue
			}
			if v.name != "plain" {
				foldedChecked++
			}
			t.Run(tc.table+"."+tc.key+"/"+v.name, func(t *testing.T) {
				if g, w := fmt.Sprint(tc.get(*got)), fmt.Sprint(tc.want); g != w {
					t.Errorf("%s.%s = %s, want %s (overlay loosened the fence)", tc.table, tc.key, g, w)
				}
			})
		}
		// Guard against a vacuous pass: a decoder that silently dropped every
		// folded spelling would leave each field at base, the equality check
		// would pass, and the test would assert nothing about key spelling. Any
		// case that has folded variants must land at least one of them.
		if len(variants) > 1 && foldedChecked == 0 {
			t.Errorf("%s.%s: every folded spelling was refused; key spelling was never exercised", tc.table, tc.key)
		}
	}

	// Positive control: a folded spelling must not merely be accepted, it must
	// reach the field. A tightening proves the decode happened — a dropped key
	// would leave the base list, not the stricter [HOME]. This is what keeps the
	// []-overlay cases above honest: without it, a decoder that silently ignored
	// the folded key would leave the field at base and the equality check would
	// pass vacuously. The regression this fix prevents shows up in the LOOSENING
	// cases, not here: under the pre-N11810 lowercased-key presence check the
	// folded "pass" key is missed, the restriction is skipped, and the loosening
	// secrets.pass "long-s key" / "long-s both" cases above regress to [] (the
	// pass-everything sentinel, secrets.go Rule 2). This tightening still lands
	// on revert, because the skipped restriction leaves the decoded [HOME].
	t.Run("folded tightening lands", func(t *testing.T) {
		for _, sp := range []struct{ name, table, key string }{
			{"folded key", "secrets", foldLongS("pass")},
			{"folded both", foldLongS("secrets"), foldLongS("pass")},
		} {
			doc := fmt.Sprintf("[%q]\n%q = [\"HOME\"]\n", sp.table, sp.key)
			got, err := LoadOverlay(*base, writeOverlayFile(t, doc))
			if err != nil {
				t.Fatalf("LoadOverlay (%s): %v", sp.name, err)
			}
			if g := fmt.Sprint(got.Secrets.Pass); g != "[HOME]" {
				t.Fatalf("secrets.pass (%s) = %s, want [HOME] (folded tightening was dropped)", sp.name, g)
			}
		}
	})
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
