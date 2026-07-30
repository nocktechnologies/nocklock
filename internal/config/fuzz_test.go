package config

import (
	"os"
	"path/filepath"
	"testing"
)

// FuzzConfigLoad fuzzes the untrusted-config parse surface: Load (project config
// over the secure defaults) and LoadOverlay (a user config layered over an
// embedded profile, which must only ever TIGHTEN the fence). Arbitrary bytes are
// written to a temp config path and fed through both entry points.
//
// Invariants asserted (the ones this codebase actually guarantees — fail-closed):
//
//	Load:
//	  1. never panics on arbitrary bytes;
//	  2. err != nil ⇒ returned config is nil (a parse/validation failure must not
//	     leak a partially-populated — and therefore possibly permissive — config;
//	     the zero-value Config is dangerous: empty Filesystem.Root disables the FS
//	     fence and an empty Secrets.Pass means "pass every non-blocked var");
//	  3. cfg != nil ⇒ Validate(cfg) reports no error-severity entries (Load never
//	     returns a config it would itself reject).
//
//	LoadOverlay over a restrictive profile base:
//	  4. never panics; err != nil ⇒ nil config;
//	  5. the overlay result is NEVER more permissive than the base — the whole
//	     point of the overlay restrictor. Concretely it can never turn a boolean
//	     widener on, never widen an allowlist, never collapse an inverted allowlist
//	     to its permissive empty sentinel, and never redirect the audit-log path.
func FuzzConfigLoad(f *testing.F) {
	seeds := [][]byte{
		[]byte(""),
		[]byte("   "),
		[]byte("not [valid toml !!!"),
		[]byte("[filesystem]\nroot = \".\"\n"),
		// Attempts to WIDEN the fence — these must survive Load (Load is the
		// trusted-project loader) but must be neutralised by LoadOverlay.
		[]byte("[network]\nallow_all = true\nallow_private_ranges = true\n"),
		[]byte("[filesystem]\nallow = [\"/\"]\nmode = \"read-write\"\n"),
		[]byte("[secrets]\npass = [\"TOTALLY_UNRELATED_VAR\"]\n"),
		[]byte("[syscall]\nenforcement = \"off\"\nsocket_families = [\"netlink\"]\nallow_namespaces = true\n"),
		[]byte("[logging]\ndb = \"/tmp/attacker-controlled.db\"\n"),
		[]byte("[cloud]\nenabled = true\napi_key = \"x\"\n"),
		// Values that must be REJECTED (error severity) — fail-closed to nil.
		[]byte("[filesystem]\ndeny = [\"../../etc/passwd\"]\n"),
		[]byte("[filesystem]\nallow = [\"../secrets\"]\n"),
		[]byte("[filesystem]\nmode = \"execute\"\n"),
		[]byte("[logging]\nlevel = \"trace\"\n"),
		[]byte("[unknown_section]\nx = 1\n"),
		// Embedded NUL / separators / unicode in string values.
		[]byte("[filesystem]\nroot = \"/tmp/\x00evil\"\n"),
		[]byte("[project]\nname = \"café\"\n"),
		// Structural oddities.
		[]byte("[filesystem]\nallow = [1, 2, 3]\n"),
		[]byte("[[filesystem]]\n"),
	}
	for _, s := range seeds {
		f.Add(s)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.toml")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write temp config: %v", err)
		}

		// --- Load: trusted-project loader over secure defaults. ---
		// A panic here fails the fuzz automatically; that IS the no-panic assertion.
		cfg, err := Load(path)
		if err != nil {
			if cfg != nil {
				t.Fatalf("Load returned err %v with a NON-nil config %+v: a rejected "+
					"config must be nil, never a partially-populated (possibly permissive) one", err, cfg)
			}
		} else {
			if cfg == nil {
				t.Fatalf("Load returned nil config and nil error")
			}
			for _, e := range Validate(cfg) {
				if e.Severity == "error" {
					t.Fatalf("Load returned a config it would itself reject: %s", e.Error())
				}
			}
		}

		// --- LoadOverlay: user config over a restrictive profile base. ---
		base, perr := LoadProfile("codex")
		if perr != nil {
			t.Fatalf("LoadProfile(codex): %v", perr)
		}
		ov, oerr := LoadOverlay(*base, path)
		if oerr != nil {
			if ov != nil {
				t.Fatalf("LoadOverlay returned err %v with a NON-nil config: rejected must be nil", oerr)
			}
			return
		}
		if ov == nil {
			t.Fatalf("LoadOverlay returned nil config and nil error")
		}
		assertOverlayNotWidened(t, base, ov)
	})
}

// assertOverlayNotWidened encodes the overlay restrictor's fail-closed contract:
// an overlay may tighten the base fence but may NEVER widen it. Any firing here
// is either a real overlay-widening bypass or a too-strict assertion — do not
// paper over it; minimise the input and inspect restrictOverlay /
// overlayDefinedFields before concluding.
func assertOverlayNotWidened(t *testing.T, base, ov *Config) {
	t.Helper()

	// Boolean wideners can never flip from off→on (unconditional in restrictOverlay).
	if ov.Network.AllowAll && !base.Network.AllowAll {
		t.Fatalf("overlay turned network.allow_all ON (base off): fence WIDENED")
	}
	if ov.Network.AllowPrivateRanges && !base.Network.AllowPrivateRanges {
		t.Fatalf("overlay turned network.allow_private_ranges ON (base off): fence WIDENED")
	}
	if ov.Syscall.AllowNamespaces && !base.Syscall.AllowNamespaces {
		t.Fatalf("overlay turned syscall.allow_namespaces ON (base off): fence WIDENED")
	}
	if ov.Cloud.Enabled && !base.Cloud.Enabled {
		t.Fatalf("overlay turned cloud.enabled ON (base off): fence WIDENED")
	}

	// Read-only can never be loosened to read-write.
	if base.Filesystem.Mode == "read-only" && ov.Filesystem.Mode != "read-only" {
		t.Fatalf("overlay loosened filesystem.mode from read-only to %q", ov.Filesystem.Mode)
	}

	// The audit-log path and profile identity are immutable across an overlay.
	if ov.Logging.DB != base.Logging.DB {
		t.Fatalf("overlay redirected logging.db to %q (base %q): audit anchor must be immutable", ov.Logging.DB, base.Logging.DB)
	}
	if ov.ProfileName != base.ProfileName {
		t.Fatalf("overlay changed ProfileName %q -> %q", base.ProfileName, ov.ProfileName)
	}
	// Overlay cannot relocate the filesystem root out from under the profile.
	if ov.Filesystem.Root != base.Filesystem.Root {
		t.Fatalf("overlay changed filesystem.root %q -> %q", base.Filesystem.Root, ov.Filesystem.Root)
	}

	// Allowlists can only narrow: the result must be a subset of the base.
	if !isSubset(ov.Network.Allow, base.Network.Allow) {
		t.Fatalf("overlay widened network.allow beyond base: got %v, base %v", ov.Network.Allow, base.Network.Allow)
	}
	if !isSubset(ov.Filesystem.Allow, base.Filesystem.Allow) {
		t.Fatalf("overlay widened filesystem.allow beyond base: got %v, base %v", ov.Filesystem.Allow, base.Filesystem.Allow)
	}

	// Denylists can only grow: the base denies must all survive.
	if !isSubset(base.Filesystem.Deny, ov.Filesystem.Deny) {
		t.Fatalf("overlay dropped a base filesystem.deny entry: got %v, base %v", ov.Filesystem.Deny, base.Filesystem.Deny)
	}
	if !isSubset(base.Secrets.Block, ov.Secrets.Block) {
		t.Fatalf("overlay dropped a base secrets.block entry: got %v, base %v", ov.Secrets.Block, base.Secrets.Block)
	}

	// Inverted allowlists (empty == "no restriction") must never collapse to the
	// permissive empty sentinel when the base is non-empty.
	if len(base.Secrets.Pass) > 0 && len(ov.Secrets.Pass) == 0 {
		t.Fatalf("overlay collapsed secrets.pass to empty (= pass-all): fence WIDENED")
	}
	if len(base.Syscall.SocketFamilies) > 0 && len(ov.Syscall.SocketFamilies) == 0 {
		t.Fatalf("overlay collapsed syscall.socket_families to empty (= no restriction): fence WIDENED")
	}
	// And when they do not collapse, they still may only narrow (subset of base).
	if !isSubset(ov.Secrets.Pass, base.Secrets.Pass) {
		t.Fatalf("overlay widened secrets.pass beyond base: got %v, base %v", ov.Secrets.Pass, base.Secrets.Pass)
	}
	if !isSubset(ov.Syscall.SocketFamilies, base.Syscall.SocketFamilies) {
		t.Fatalf("overlay widened syscall.socket_families beyond base: got %v, base %v", ov.Syscall.SocketFamilies, base.Syscall.SocketFamilies)
	}
}

// isSubset reports whether every element of sub appears in super.
func isSubset(sub, super []string) bool {
	seen := make(map[string]bool, len(super))
	for _, v := range super {
		seen[v] = true
	}
	for _, v := range sub {
		if !seen[v] {
			return false
		}
	}
	return true
}
