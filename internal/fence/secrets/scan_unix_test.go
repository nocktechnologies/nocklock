//go:build linux || darwin

package secrets

import (
	"context"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
	"testing"
)

func TestScanRejectsFIFOWithoutOpeningIt(t *testing.T) {
	root := t.TempDir()
	if err := unix.Mkfifo(filepath.Join(root, "pipe"), 0600); err != nil {
		t.Fatal(err)
	}
	r := Scan(context.Background(), root, []string{"."}, nil)
	if r.Complete || len(r.Issues) != 1 {
		t.Fatalf("special file accepted: %+v", r)
	}
}

func TestScanUnreadableInputIsIncomplete(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can read mode-000 files")
	}
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "unreadable"), nil, 0000); err != nil {
		t.Fatal(err)
	}
	r := Scan(context.Background(), root, []string{"."}, nil)
	if r.Complete || len(r.Issues) != 1 {
		t.Fatalf("unreadable file accepted: %+v", r)
	}
}

func TestOpenScanFileRejectsReplacedParent(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "parent"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "parent", "file"), []byte("clean"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	// Replace a previously inspected directory before the open. The final
	// component is still regular, so final-component O_NOFOLLOW is insufficient.
	if _, err := root.Lstat("parent"); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(filepath.Join(dir, "parent"), filepath.Join(dir, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("moved", filepath.Join(dir, "parent")); err != nil {
		t.Fatal(err)
	}
	f, err := openScanFile(root, "parent/file")
	if err == nil {
		f.Close()
		t.Fatal("followed a replaced parent symlink")
	}
}

func TestScanInputRecheckDetectsReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	if err := os.WriteFile(path, []byte("clean"), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	f, err := openScanFile(root, "file")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	before, err := f.Stat()
	if err != nil {
		t.Fatal(err)
	}
	if !scanInputUnchanged(root, "file", f, before) {
		t.Fatal("unchanged file rejected")
	}
	if err := os.Rename(path, filepath.Join(dir, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("other"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	if scanInputUnchanged(root, "file", f, before) {
		t.Fatal("replacement with the same size and timestamp accepted")
	}
}
