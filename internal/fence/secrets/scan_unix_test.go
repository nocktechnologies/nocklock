//go:build linux || darwin

package secrets

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
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

func TestScanInputRecheckDetectsInPlaceRewrite(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	contents := []byte("clean")
	if err := os.WriteFile(path, contents, 0600); err != nil {
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
	if !scanInputUnchanged(root, "file", f, before, contents) {
		t.Fatal("unchanged file rejected")
	}
	// Rewrite the opened file in place, preserving the metadata checked by the
	// prior implementation. The content snapshot must still make this unsafe.
	if err := os.WriteFile(path, []byte("other"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	if scanInputUnchanged(root, "file", f, before, contents) {
		t.Fatal("in-place rewrite with the same metadata accepted")
	}
}

func TestScanInputRecheckDetectsInodeReplacement(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	contents := []byte("clean")
	if err := os.WriteFile(path, contents, 0600); err != nil {
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
	if err := os.Rename(path, filepath.Join(dir, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, before.ModTime(), before.ModTime()); err != nil {
		t.Fatal(err)
	}
	if scanInputUnchanged(root, "file", f, before, contents) {
		t.Fatal("replacement inode with identical contents and metadata accepted")
	}
}

// Context checks at each walk entry provide a deterministic interleaving without
// racing goroutines or adding mutation hooks to the production scanner.
type scanInterleavingContext struct {
	context.Context
	step func()
}

func (c scanInterleavingContext) Err() error {
	c.step()
	return c.Context.Err()
}

func TestScanRejectsTemporaryDirectoryReplacement(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"parent", "replacement"} {
		if err := os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
			t.Fatal(err)
		}
		for _, file := range []string{"a", "b"} {
			if err := os.WriteFile(filepath.Join(dir, name, file), []byte("clean"), 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	// Use the actual directory stream order, which is not guaranteed to be sorted.
	parent, err := os.Open(filepath.Join(dir, "parent"))
	if err != nil {
		t.Fatal(err)
	}
	entries, err := parent.ReadDir(-1)
	parent.Close()
	if err != nil || len(entries) != 2 {
		t.Fatalf("read fixture directory: %v (%d entries)", err, len(entries))
	}
	if err := os.WriteFile(filepath.Join(dir, "parent", entries[0].Name()), []byte(syntheticToken()), 0600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	rename := func(from, to string) {
		t.Helper()
		if err := os.Rename(filepath.Join(dir, from), filepath.Join(dir, to)); err != nil {
			t.Fatal(err)
		}
	}
	checks := 0
	ctx := scanInterleavingContext{Context: context.Background(), step: func() {
		checks++
		switch checks {
		case 2: // Parent is open; substitute clean content before the first child.
			rename("parent", "original")
			rename("replacement", "parent")
		case 3: // Restore before the second child and the parent's final recheck.
			rename("parent", "replacement")
			rename("original", "parent")
		}
	}}
	s := scanner{ctx: ctx, report: ScanReport{Complete: true}, seen: make(map[string]bool)}
	s.walk(root, "parent", 0, nil)
	if checks != 3 {
		t.Fatalf("fixture did not exercise both child opens: %d checks", checks)
	}
	if s.report.Safe() {
		t.Fatal("temporary directory replacement hid the original secret and reported a safe scan")
	}
}

func TestOpenScanChildRejectsNonChildNames(t *testing.T) {
	parent, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	for _, name := range []string{".", "..", "a/b", "/absolute", ""} {
		f, err := openScanChild(parent, name)
		if err == nil {
			f.Close()
			t.Fatalf("non-child name %q accepted", name)
		}
	}
}
