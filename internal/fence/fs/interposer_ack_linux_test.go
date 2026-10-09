//go:build linux

package fs

import (
	"bufio"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const ackChildSource = `
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

int main(int argc, char **argv) {
    struct timespec a, b;
    clock_gettime(CLOCK_MONOTONIC, &a);
    int fd;
    if (argc > 2 && argv[2][0] == 'r') {
        fd = (int)syscall(SYS_openat, AT_FDCWD, argv[1], O_RDONLY);
    } else {
        fd = open(argv[1], O_RDONLY);
    }
    int e = errno;
    clock_gettime(CLOCK_MONOTONIC, &b);
    long ms = (b.tv_sec - a.tv_sec) * 1000 + (b.tv_nsec - a.tv_nsec) / 1000000;
    printf("fd=%d errno=%d ms=%ld\n", fd, fd < 0 ? e : 0, ms);
    return 0;
}
`

// ackHarness builds the interposer and a child that opens one path, and runs a
// fake listener that sleeps ackDelay before acknowledging each report.
type ackHarness struct {
	dir      string
	so       string
	child    string
	sock     string
	reports  atomic.Int32
	ackDelay time.Duration
}

func newAckHarness(t *testing.T, ackDelay time.Duration) *ackHarness {
	t.Helper()
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skipf("gcc unavailable: %v", err)
	}
	dir, err := os.MkdirTemp("/tmp", "nlack-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	h := &ackHarness{dir: dir, ackDelay: ackDelay}
	h.so = filepath.Join(dir, "libfence_fs.so")
	if out, err := exec.Command("gcc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror", "-o", h.so, "interposer/libfence_fs.c", "-ldl", "-lpthread").CombinedOutput(); err != nil {
		t.Fatalf("build interposer: %v\n%s", err, out)
	}
	src := filepath.Join(dir, "child.c")
	h.child = filepath.Join(dir, "child")
	if err := os.WriteFile(src, []byte(ackChildSource), 0o600); err != nil {
		t.Fatalf("write child source: %v", err)
	}
	if out, err := exec.Command("gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-o", h.child, src).CombinedOutput(); err != nil {
		t.Fatalf("build child: %v\n%s", err, out)
	}
	h.sock = filepath.Join(dir, "events.sock")
	ln, err := net.Listen("unix", h.sock)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				sc := bufio.NewScanner(c)
				for sc.Scan() {
					h.reports.Add(1)
					time.Sleep(h.ackDelay)
					_, _ = c.Write([]byte{1})
				}
			}()
		}
	}()
	return h
}

var ackChildOut = regexp.MustCompile(`fd=(-?\d+) errno=(\d+) ms=(\d+)`)

// open runs the child against path with the given config and returns fd,
// errno and the milliseconds the open call took.
func (h *ackHarness) open(t *testing.T, waitForAck bool, path, mode string) (fd, errno int, ms int64) {
	t.Helper()
	cfg := &FenceConfig{Root: h.dir, Mode: "read-write", AllowPaths: []string{"/"}, DenyPaths: []string{path}, WaitForAck: waitForAck}
	cmd := exec.Command(h.child, path, mode)
	cmd.Env = append(os.Environ(), EnvLDPreload+"="+h.so, EnvFSAllowed+"="+cfg.Serialize(h.sock))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child failed: %v\n%s", err, out)
	}
	m := ackChildOut.FindStringSubmatch(strings.TrimSpace(string(out)))
	if m == nil {
		t.Fatalf("unparseable child output %q", out)
	}
	fd, _ = strconv.Atoi(m[1])
	errno, _ = strconv.Atoi(m[2])
	ms, _ = strconv.ParseInt(m[3], 10, 64)
	return fd, errno, ms
}

// TestInterposerAckWaitsOnlyWhenConfigured is test 13: with no !ack field a
// denied open returns without waiting for the listener; with it, EACCES
// returns only after the ack.
func TestInterposerAckWaitsOnlyWhenConfigured(t *testing.T) {
	const delay = 150 * time.Millisecond
	h := newAckHarness(t, delay)

	fd, errno, ms := h.open(t, false, "/etc/hostname", "libc")
	if fd >= 0 || errno != 13 {
		t.Fatalf("control: fd=%d errno=%d, want a denied open (EACCES)", fd, errno)
	}
	if ms >= delay.Milliseconds()/2 {
		t.Fatalf("control: denied open took %d ms without !ack; the interposer must not wait", ms)
	}

	fd, errno, ms = h.open(t, true, "/etc/hostname", "libc")
	if fd >= 0 || errno != 13 {
		t.Fatalf("with !ack: fd=%d errno=%d, want EACCES", fd, errno)
	}
	if ms < delay.Milliseconds() {
		t.Fatalf("with !ack: EACCES returned after %d ms, before the %d ms ack", ms, delay.Milliseconds())
	}
}

// TestInterposerAckGivesUpAfterTimeout checks the wait is bounded: a listener
// that never acks cannot hang the child, and the open still returns EACCES.
func TestInterposerAckGivesUpAfterTimeout(t *testing.T) {
	h := newAckHarness(t, 3*time.Second)
	fd, errno, ms := h.open(t, true, "/etc/hostname", "libc")
	if fd >= 0 || errno != 13 {
		t.Fatalf("fd=%d errno=%d, want EACCES", fd, errno)
	}
	if ms < 200 || ms > 1500 {
		t.Fatalf("open returned after %d ms; want the ~250 ms ack timeout", ms)
	}
}
