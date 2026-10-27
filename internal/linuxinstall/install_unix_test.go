//go:build linux || darwin

package linuxinstall

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func sandbox(t *testing.T) (installer, string) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range []string{"bin", "lib", "libexec", "sudoers.d"} {
		if err := os.Mkdir(filepath.Join(root, n), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	i := installer{base: filepath.Join(root, "lib", "nocklock"), link: filepath.Join(root, "bin", "nocklock"), helper: filepath.Join(root, "libexec", "nocklock-egress-helper"), sudoers: filepath.Join(root, "sudoers.d", "nocklock-egress")}
	// Production uses root ownership all the way to /. The fixture uses only
	// its private temp boundary; no environment flag weakens production checks.
	i.trust = func(path string) error {
		for p := path; p != root; p = filepath.Dir(p) {
			if !strings.HasPrefix(p, root+"/") {
				return errors.New("outside fixture")
			}
			st, err := os.Lstat(p)
			if err != nil {
				return err
			}
			if st.Mode().Perm()&0o022 != 0 || (!st.IsDir() && !st.Mode().IsRegular()) {
				return errors.New("untrusted fixture path")
			}
		}
		return nil
	}
	i.verify = func(stage, tag string) error {
		data, err := os.ReadFile(filepath.Join(stage, "SHA256SUMS.sigstore.json"))
		if err != nil {
			return err
		}
		if string(data) != "valid:"+tag {
			return errors.New("wrong signer or signature")
		}
		return nil
	}
	return i, root
}

func assets(t *testing.T, root, tag string) Options {
	t.Helper()
	dir := filepath.Join(root, "downloads-"+tag)
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	a, m := fixture(t, tag, nil)
	name, _ := ArchiveName(tag)
	for n, d := range map[string][]byte{name: a, "SHA256SUMS": m, "SHA256SUMS.sigstore.json": []byte("valid:" + tag), "cosign": []byte("test verifier")} {
		if err := os.WriteFile(filepath.Join(dir, n), d, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return Options{Tag: tag, Artifacts: dir, Cosign: filepath.Join(dir, "cosign")}
}

func TestInstallUpgradeVerifiedRollback(t *testing.T) {
	i, root := sandbox(t)
	one, two := assets(t, root, "v1.0.0"), assets(t, root, "v1.1.0")
	for _, o := range []Options{one, one, two} {
		if err := i.apply(o); err != nil {
			t.Fatal(err)
		}
	}
	if tag, err := i.active(); err != nil || tag != two.Tag {
		t.Fatalf("active %s: %v", tag, err)
	}
	if err := i.apply(one); err == nil || !strings.Contains(err.Error(), "downgrade refused") {
		t.Fatalf("downgrade: %v", err)
	}
	one.Rollback = true
	one.Artifacts = ""
	if err := i.apply(one); err != nil {
		t.Fatal(err)
	}
	if tag, err := i.active(); err != nil || tag != one.Tag {
		t.Fatalf("rollback %s: %v", tag, err)
	}
	if _, err := os.Stat(filepath.Join(i.base, "releases", two.Tag+"-linux-amd64", "nocklock")); err != nil {
		t.Fatal("previous release removed", err)
	}
}

func TestBadSignatureLeavesActiveRelease(t *testing.T) {
	i, root := sandbox(t)
	one, two := assets(t, root, "v1.0.0"), assets(t, root, "v1.1.0")
	if err := i.apply(one); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(two.Artifacts, "SHA256SUMS.sigstore.json"), []byte("candidate identity"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := i.apply(two); err == nil {
		t.Fatal("accepted wrong signer")
	}
	if tag, _ := i.active(); tag != one.Tag {
		t.Fatal("changed activation after verification failure")
	}
	if _, err := os.Stat(filepath.Join(i.base, "releases", two.Tag+"-linux-amd64")); !os.IsNotExist(err) {
		t.Fatal("installed unauthenticated bytes")
	}
}

func TestRollbackRechecksRetainedBytes(t *testing.T) {
	for _, name := range []string{"nocklock", "libfence_fs.so", "SHA256SUMS.sigstore.json"} {
		t.Run(name, func(t *testing.T) {
			i, root := sandbox(t)
			one, two := assets(t, root, "v1.0.0"), assets(t, root, "v1.1.0")
			if err := i.apply(one); err != nil {
				t.Fatal(err)
			}
			if err := i.apply(two); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(i.base, "releases", one.Tag+"-linux-amd64", name), []byte("tampered"), 0o600); err != nil {
				t.Fatal(err)
			}
			one.Rollback = true
			if err := i.apply(one); err == nil {
				t.Fatal("accepted tampered rollback")
			}
			if tag, _ := i.active(); tag != two.Tag {
				t.Fatal("changed activation")
			}
		})
	}
}

func TestBusyAndInterruptedUpdate(t *testing.T) {
	i, root := sandbox(t)
	one, two := assets(t, root, "v1.0.0"), assets(t, root, "v1.1.0")
	if err := i.apply(one); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(filepath.Join(i.base, "install.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if err := unix.Flock(int(f.Fd()), unix.LOCK_SH|unix.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	if err := i.apply(two); err == nil || !strings.Contains(err.Error(), "busy") {
		t.Fatalf("active session: %v", err)
	}
	f.Close()
	// Interrupt after the complete release was staged but before activation.
	if err := os.WriteFile(i.helper, []byte("unmanaged"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := i.apply(two); err == nil {
		t.Fatal("accepted unmanaged helper")
	}
	if tag, _ := i.active(); tag != one.Tag {
		t.Fatal("partial activation")
	}
	if err := os.Remove(i.helper); err != nil {
		t.Fatal(err)
	}
	if err := i.apply(two); err != nil {
		t.Fatal("retry after interruption", err)
	}
}

func TestRefuseUnmanagedAndWritablePaths(t *testing.T) {
	for _, kind := range []string{"binary", "broken-link", "foreign-link", "writable-parent", "symlink-parent", "legacy-library"} {
		t.Run(kind, func(t *testing.T) {
			i, root := sandbox(t)
			o := assets(t, root, "v1.0.0")
			switch kind {
			case "binary":
				os.WriteFile(i.link, []byte("old"), 0o755)
			case "broken-link":
				os.Symlink("/missing", i.link)
			case "foreign-link":
				os.Symlink(o.Cosign, i.link)
			case "writable-parent":
				os.Chmod(filepath.Dir(i.link), 0o777)
			case "symlink-parent":
				os.Symlink(root, i.base)
			case "legacy-library":
				os.Mkdir(i.base, 0o755)
				os.WriteFile(filepath.Join(i.base, "libfence_fs.so"), []byte("old"), 0o755)
			}
			if err := i.apply(o); err == nil {
				t.Fatal("accepted unsafe installation")
			}
		})
	}
}

func TestInputsAreRootStagedBeforeVerification(t *testing.T) {
	i, root := sandbox(t)
	o := assets(t, root, "v1.0.0")
	verify := i.verify
	i.verify = func(stage, tag string) error {
		name, _ := ArchiveName(tag)
		if err := os.WriteFile(filepath.Join(o.Artifacts, name), []byte("concurrent replacement"), 0o600); err != nil {
			return err
		}
		return verify(stage, tag)
	}
	if err := i.apply(o); err != nil {
		t.Fatal("source change affected staged install", err)
	}
	if tag, _ := i.active(); tag != o.Tag {
		t.Fatal("valid staged release not activated")
	}
}

func TestPinnedVerifierRejectsBeforeExecution(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cosign"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := verifySignature(dir, "v1.0.0"); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("untrusted verifier: %v", err)
	}
}

func TestManagedHelperPolicyCannotBroaden(t *testing.T) {
	for _, kind := range []string{"allowed", "extra-grant", "wrong-shim", "wrong-mode", "missing-shim"} {
		t.Run(kind, func(t *testing.T) {
			i, root := sandbox(t)
			o := assets(t, root, "v1.0.0")
			shim, policy := i.helperBytes(), i.policy("agent")
			if kind == "wrong-shim" {
				shim = []byte("#!/bin/sh\nexec /bin/sh\n")
			}
			if kind == "extra-grant" {
				policy = append(policy, []byte("agent ALL=(ALL) NOPASSWD: ALL\n")...)
			}
			if kind != "missing-shim" {
				if err := os.WriteFile(i.helper, shim, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(i.sudoers, policy, 0o440); err != nil {
				t.Fatal(err)
			}
			if kind == "wrong-mode" {
				os.Chmod(i.sudoers, 0o644)
			}
			err := i.apply(o)
			if kind == "allowed" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("unsafe helper accepted")
			}
		})
	}
}
