//go:build linux || darwin

package linuxinstall

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestCommandCancelsProcessGroup(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "survived")
	script := `(sleep 0.3; printf survived > "$1") & wait`
	// Positive control: the descendant actually reaches the marker normally.
	if _, err := commandContext(context.Background(), "/bin/sh", "-c", script, "fixture", marker); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(marker); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := commandContext(ctx, "/bin/sh", "-c", script, "fixture", marker); err == nil {
		t.Fatal("timeout accepted")
	}
	time.Sleep(400 * time.Millisecond)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("descendant survived cancellation")
	}
}

func TestCommandBoundsDetachedPipeWait(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	out, err := commandContext(ctx, os.Args[0], "-test.run=^TestInstallerDetachedHelper$", "--", "spawn-detached")
	pid, parseErr := strconv.Atoi(strings.TrimSpace(string(out)))
	if parseErr != nil {
		t.Fatalf("missing helper PID: %q (%v)", out, err)
	}
	defer unix.Kill(pid, unix.SIGKILL) // intentionally detached fixture, never a host process
	if err == nil {
		t.Fatal("open descendant pipe reported success")
	}
	if time.Since(start) > 4*time.Second {
		t.Fatal("pipe wait exceeded cancellation bound")
	}
}

func TestInstallerDetachedHelper(t *testing.T) {
	if os.Args[len(os.Args)-1] != "spawn-detached" {
		return
	}
	child := exec.Command("/bin/sleep", "30")
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	if err := child.Start(); err != nil {
		os.Exit(2)
	}
	fmt.Fprintln(os.Stdout, child.Process.Pid)
	os.Exit(0)
}
