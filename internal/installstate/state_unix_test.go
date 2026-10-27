//go:build linux || darwin

package installstate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSharedInvocationsExcludeInstaller(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lock")
	first, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := flock(first, false); err != nil {
		t.Fatal(err)
	}
	if err := flock(second, false); err != nil {
		t.Fatal(err)
	}
	installer, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer installer.Close()
	if err := flock(installer, true); err == nil {
		t.Fatal("installer accepted active invocations")
	}
	first.Close()
	second.Close()
	if err := flock(installer, true); err != nil {
		t.Fatal(err)
	}
	invocation, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer invocation.Close()
	if err := flock(invocation, false); err == nil {
		t.Fatal("invocation accepted active installer")
	}
}

func TestSourceInstallUnchanged(t *testing.T) {
	f, err := AcquireInvocation("/usr/bin/nocklock", Base, Link)
	if err != nil || f != nil {
		t.Fatalf("source install: %v %v", f, err)
	}
}
