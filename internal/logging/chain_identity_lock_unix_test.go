//go:build linux || darwin

package logging

import (
	"io/fs"
	"os"
	"syscall"
	"testing"
	"time"
)

type identityFileInfo struct {
	fs.FileInfo
	stat *syscall.Stat_t
}

func (i identityFileInfo) Sys() any { return i.stat }

func TestChainIdentityFileOwnerAndLinks(t *testing.T) {
	f := newIdentityFixture(t)
	initIdentity(t, f)
	info, err := os.Stat(f.record)
	if err != nil {
		t.Fatal(err)
	}
	stat := *info.Sys().(*syscall.Stat_t)
	if err := validateIdentityFileOwner(info); err != nil {
		t.Fatalf("owner positive control: %v", err)
	}
	stat.Uid++
	if err := validateIdentityFileOwner(identityFileInfo{info, &stat}); err == nil {
		t.Fatal("foreign owner accepted")
	}
	stat.Uid--
	stat.Nlink = 2
	if err := validateIdentityFileOwner(identityFileInfo{info, &stat}); err == nil {
		t.Fatal("hard link alias accepted")
	}
}

func TestChainIdentityFIFORefusesWithoutBlocking(t *testing.T) {
	f := newIdentityFixture(t)
	initIdentity(t, f)
	if err := os.Remove(f.record); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(f.record, 0600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := f.logger.ReadChainIdentity(); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("FIFO blocked identity read")
	}
}
