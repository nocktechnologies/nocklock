package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/fence/network/netns"
)

func netnsRequestFixture() netns.Request {
	return netns.Request{
		Argv:   []string{"/bin/cat"},
		Env:    []string{"PATH=/usr/bin"},
		UID:    4242,
		GID:    4242,
		Groups: []int{4242},
	}
}

func mustMarshal(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal fixture: %v", err)
	}
	return b
}

// TestSetupRequestPath pins the argv contract for the `setup` verb: the request
// path rides argv as --request-file (N10711 moved the request off stdin so the
// child keeps the caller's stdin). Anything else must fail closed rather than
// fall back to a stdin read.
func TestSetupRequestPath(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
		ok   bool
	}{
		{"space form", []string{"--request-file", "/tmp/req.json"}, "/tmp/req.json", true},
		{"no args", nil, "", false},
		{"wrong flag", []string{"--other", "/tmp/req.json"}, "", false},
		{"bare path (no flag)", []string{"/tmp/req.json"}, "", false},
		{"equals form rejected (not sudoers-matchable)", []string{"--request-file=/tmp/req.json"}, "", false},
		{"empty space value", []string{"--request-file", ""}, "", false},
		{"extra args", []string{"--request-file", "/tmp/req.json", "extra"}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := setupRequestPath(tc.args)
			if tc.ok && err != nil {
				t.Fatalf("setupRequestPath(%v) unexpected error: %v", tc.args, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("setupRequestPath(%v) = %q, want error", tc.args, got)
			}
			if tc.ok && got != tc.want {
				t.Fatalf("setupRequestPath(%v) = %q, want %q", tc.args, got, tc.want)
			}
		})
	}
}

// TestWriteAndReadSetupRequest round-trips a request through the 0600 file
// channel and confirms the file is created with the mode the helper validates.
func TestWriteAndReadSetupRequest(t *testing.T) {
	t.Setenv("SUDO_UID", strconv.Itoa(os.Getuid()))
	dir := t.TempDir()

	want := netnsRequestFixture()
	reqBytes := mustMarshal(t, want)
	path, err := writeSetupRequest(dir, reqBytes)
	if err != nil {
		t.Fatalf("writeSetupRequest: %v", err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat written request: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Fatalf("request file mode = %#o, want 0600", perm)
	}

	got, err := readSetupRequest(path)
	if err != nil {
		t.Fatalf("readSetupRequest: %v", err)
	}
	if !reflect.DeepEqual(got.Argv, want.Argv) || got.UID != want.UID || got.GID != want.GID {
		t.Fatalf("round-trip mismatch: got %+v want %+v", got, want)
	}
	// readSetupRequest unlinks the single-use file after reading.
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("request file should be unlinked after read, stat err = %v", err)
	}
}

// TestReadSetupRequestFailsClosed is the helper-leg negative control (acceptance
// #4, helper side): a missing, mis-permissioned, foreign-owned, symlinked, or
// non-sudo request must be refused, never read.
func TestReadSetupRequestFailsClosed(t *testing.T) {
	uid := os.Getuid()

	t.Run("missing file", func(t *testing.T) {
		t.Setenv("SUDO_UID", strconv.Itoa(uid))
		if _, err := readSetupRequest(filepath.Join(t.TempDir(), "nope.json")); err == nil {
			t.Fatal("expected error for missing request file")
		}
	})

	t.Run("wrong mode", func(t *testing.T) {
		t.Setenv("SUDO_UID", strconv.Itoa(uid))
		path := filepath.Join(t.TempDir(), "req.json")
		if err := os.WriteFile(path, mustMarshal(t, netnsRequestFixture()), 0o644); err != nil {
			t.Fatalf("write 0644 request: %v", err)
		}
		if _, err := readSetupRequest(path); err == nil {
			t.Fatal("expected error for 0644 request file")
		}
		// SECURITY: a rejected file must NOT be unlinked — the helper runs as root,
		// so deleting an unvalidated (possibly root-owned) path would be an
		// arbitrary file-deletion primitive.
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("rejected request file must not be deleted, stat err = %v", err)
		}
	})

	t.Run("owner mismatch", func(t *testing.T) {
		// Claim a different invoking user than the file's owner.
		t.Setenv("SUDO_UID", strconv.Itoa(uid+1))
		path := filepath.Join(t.TempDir(), "req.json")
		if err := os.WriteFile(path, mustMarshal(t, netnsRequestFixture()), 0o600); err != nil {
			t.Fatalf("write request: %v", err)
		}
		if _, err := readSetupRequest(path); err == nil {
			t.Fatal("expected error when file owner != SUDO_UID")
		}
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("owner-mismatched request file must not be deleted, stat err = %v", err)
		}
	})

	t.Run("sudo_uid unset", func(t *testing.T) {
		t.Setenv("SUDO_UID", "")
		path := filepath.Join(t.TempDir(), "req.json")
		if err := os.WriteFile(path, mustMarshal(t, netnsRequestFixture()), 0o600); err != nil {
			t.Fatalf("write request: %v", err)
		}
		if _, err := readSetupRequest(path); err == nil {
			t.Fatal("expected error when SUDO_UID is unset")
		}
	})

	t.Run("symlink refused", func(t *testing.T) {
		t.Setenv("SUDO_UID", strconv.Itoa(uid))
		dir := t.TempDir()
		target := filepath.Join(dir, "real.json")
		if err := os.WriteFile(target, mustMarshal(t, netnsRequestFixture()), 0o600); err != nil {
			t.Fatalf("write target: %v", err)
		}
		link := filepath.Join(dir, "link.json")
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("symlink: %v", err)
		}
		if _, err := readSetupRequest(link); err == nil {
			t.Fatal("expected O_NOFOLLOW to refuse a symlinked request file")
		}
		// The refused symlink (and its target) must survive: no unlink on a
		// rejected path.
		if _, err := os.Lstat(link); err != nil {
			t.Fatalf("refused symlink must not be deleted, lstat err = %v", err)
		}
		if _, err := os.Stat(target); err != nil {
			t.Fatalf("symlink target must not be deleted, stat err = %v", err)
		}
	})
}

// TestRemoveValidatedRequestBoundToDirectoryFD is the negative control for the
// deferred-unlink race: after the request's parent
// directory is opened, renaming it away and planting a symlink to a victim
// directory at the original path must not redirect the unlink — the victim's
// same-named file (standing in for a root-owned /etc/sudoers.d entry) survives —
// and an entry replaced after validation is not removed either.
func TestRemoveValidatedRequestBoundToDirectoryFD(t *testing.T) {
	base := t.TempDir()
	reqDir := filepath.Join(base, "req")
	victimDir := filepath.Join(base, "victim")
	for _, d := range []string{reqDir, victimDir} {
		if err := os.Mkdir(d, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", d, err)
		}
	}
	const name = "setup-request.json"
	reqPath := filepath.Join(reqDir, name)
	victim := filepath.Join(victimDir, name)
	for _, p := range []string{reqPath, victim} {
		if err := os.WriteFile(p, []byte("{}"), 0o600); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	root, err := os.OpenRoot(reqDir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	defer root.Close()
	fi, err := root.Lstat(name)
	if err != nil {
		t.Fatalf("lstat validated request: %v", err)
	}

	// Swap the parent directory for a symlink to the victim directory.
	moved := filepath.Join(base, "req-moved")
	if err := os.Rename(reqDir, moved); err != nil {
		t.Fatalf("rename request dir: %v", err)
	}
	if err := os.Symlink(victimDir, reqDir); err != nil {
		t.Fatalf("symlink swap: %v", err)
	}

	removeValidatedRequest(root, name, fi)
	if _, err := os.Stat(victim); err != nil {
		t.Fatalf("victim file was deleted through the swapped parent path: %v", err)
	}
	if _, err := os.Stat(filepath.Join(moved, name)); !os.IsNotExist(err) {
		t.Fatalf("validated request should be unlinked from the original directory, stat err = %v", err)
	}

	// An entry replaced after validation (different inode) must not be removed.
	// The validated file is kept alive under another name so its inode cannot be
	// reused by the replacement.
	if err := os.WriteFile(filepath.Join(moved, name), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write second request: %v", err)
	}
	fi2, err := root.Lstat(name)
	if err != nil {
		t.Fatalf("lstat second request: %v", err)
	}
	if err := os.Rename(filepath.Join(moved, name), filepath.Join(moved, name+".old")); err != nil {
		t.Fatalf("rename validated request aside: %v", err)
	}
	if err := os.WriteFile(filepath.Join(moved, name), []byte("{}"), 0o600); err != nil {
		t.Fatalf("write replacement: %v", err)
	}
	removeValidatedRequest(root, name, fi2)
	if _, err := os.Stat(filepath.Join(moved, name)); err != nil {
		t.Fatalf("replaced entry must not be removed, stat err = %v", err)
	}
}
