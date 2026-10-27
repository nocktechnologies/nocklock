//go:build linux || darwin

package installstate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestManagedInvocationRoot(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root-owned filesystem controls run in disposable Linux CI")
	}
	root, err := os.MkdirTemp("/opt", "nocklock-lease-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	for _, dir := range []string{"releases/v1-linux-amd64", "releases/v2-linux-amd64", "bin"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(root, "install.lock")
	if err := os.WriteFile(path, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	one := filepath.Join(root, "releases/v1-linux-amd64/nocklock")
	two := filepath.Join(root, "releases/v2-linux-amd64/nocklock")
	for _, p := range []string{one, two} {
		if err := os.WriteFile(p, []byte("fixture"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(root, "bin/nocklock")
	if err := os.Symlink(one, link); err != nil {
		t.Fatal(err)
	}
	lease, err := AcquireInvocation(one, root, link)
	if err != nil {
		t.Fatal(err)
	}
	if f, err := Lock(path, true); err == nil {
		f.Close()
		t.Fatal("installer accepted active command")
	}
	lease.Close()
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(two, link); err != nil {
		t.Fatal(err)
	}
	if f, err := AcquireInvocation(one, root, link); err == nil {
		f.Close()
		t.Fatal("old executable accepted after switch")
	}
	lease, err = AcquireInvocation(two, root, link)
	if err != nil {
		t.Fatal(err)
	}
	lease.Close()
	if err := os.Chmod(root, 0o777); err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(path, false); err == nil {
		t.Fatal("writable ancestor accepted")
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(one, path); err != nil {
		t.Fatal(err)
	}
	if _, err := Lock(path, false); err == nil {
		t.Fatal("symlink lock accepted")
	}
}
