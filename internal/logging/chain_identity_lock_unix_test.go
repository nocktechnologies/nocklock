//go:build linux || darwin

package logging

import (
	"io/fs"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestChainIdentityConcurrentLockCreation(t *testing.T) {
	// Exercise first-open contention directly, before flock/SQLite can hide it.
	// Every opener must retain the same persistent inode; replacing the lock or
	// retrying through an unanchored pathname would split mutual exclusion.
	for round := 0; round < 16; round++ {
		dir := t.TempDir()
		start := make(chan struct{})
		type outcome struct {
			file *os.File
			err  error
		}
		results := make(chan outcome, 8)
		var workers sync.WaitGroup
		for i := 0; i < cap(results); i++ {
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			workers.Add(1)
			go func() {
				defer workers.Done()
				defer root.Close()
				<-start
				f, err := openChainIdentityLock(root)
				results <- outcome{f, err}
			}()
		}
		close(start)
		workers.Wait()
		close(results)
		var first os.FileInfo
		for result := range results {
			if result.err != nil {
				t.Errorf("round %d: concurrent lock creation failed: %v", round, result.err)
				continue
			}
			info, err := result.file.Stat()
			result.file.Close()
			if err != nil {
				t.Fatal(err)
			}
			if first != nil && !os.SameFile(first, info) {
				t.Fatal("concurrent creators opened different lock inodes")
			}
			first = info
		}
	}
}

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
