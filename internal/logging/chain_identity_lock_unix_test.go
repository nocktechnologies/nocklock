//go:build linux || darwin

package logging

import (
	"errors"
	"io/fs"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"
)

func TestChainIdentityConcurrentLockCreation(t *testing.T) {
	if isolateIdentityWaitTest(t) {
		return
	}
	// Exercise first-open contention directly, before flock/SQLite can hide it.
	// Every opener must retain the same persistent inode; replacing the lock or
	// retrying through an unanchored pathname would split mutual exclusion.
	for round := 0; round < 16; round++ {
		dir := t.TempDir()
		start := make(chan struct{})
		type outcome struct {
			file  *os.File
			err   error
			close func()
		}
		results := make(chan outcome, 8)
		release := sync.OnceFunc(func() { close(start) })
		var workers []chan struct{}
		defer func() {
			release()
			for _, done := range workers {
				awaitIdentityTestResult(t, "lock-creation cleanup", done)
			}
		}()
		for i := 0; i < cap(results); i++ {
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan struct{})
			workers = append(workers, done)
			go func() {
				defer close(done)
				defer root.Close()
				select {
				case <-start:
				case <-time.After(5 * time.Second):
					results <- outcome{err: errors.New("lock creator was not started within 5s")}
					return
				}
				f, err := openChainIdentityLock(root)
				var closeFile func()
				if f != nil {
					closeFile = sync.OnceFunc(func() { f.Close() })
					t.Cleanup(closeFile)
				}
				results <- outcome{f, err, closeFile}
			}()
		}
		release()
		opened := make([]outcome, 0, cap(results))
		for i := 0; i < cap(results); i++ {
			opened = append(opened, awaitIdentityTestResult(t, "lock creator", results))
		}
		// Keep every descriptor open until all creators have completed, so
		// unlink/replacement cannot be hidden by inode reuse between opens.
		var first os.FileInfo
		for _, result := range opened {
			if result.err != nil {
				t.Errorf("round %d: concurrent lock creation failed: %v", round, result.err)
				continue
			}
			info, err := result.file.Stat()
			result.close()
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
	if isolateIdentityWaitTest(t) {
		return
	}
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
