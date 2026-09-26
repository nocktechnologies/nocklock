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
