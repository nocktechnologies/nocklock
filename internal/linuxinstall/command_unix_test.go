//go:build linux || darwin

package linuxinstall

import (
	"context"
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	pidFile := filepath.Join(t.TempDir(), "detached.pid")
	done := make(chan error, 1)
	go func() {
		_, err := commandContext(ctx, os.Args[0], "-test.run=^TestInstallerDetachedHelper$", "--", "spawn-detached", pidFile)
		done <- err
	}()
	// Synchronize with actual descendant startup; a tiny deadline can kill a
	// race-instrumented helper before it has even started on a busy CI host.
	deadline := time.Now().Add(10 * time.Second)
	pid := 0
	for pid == 0 {
		if data, err := os.ReadFile(pidFile); err == nil {
			pid, _ = strconv.Atoi(strings.TrimSpace(string(data)))
		}
		if time.Now().After(deadline) {
			t.Fatal("helper did not publish its PID")
		}
		if pid == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	defer unix.Kill(pid, unix.SIGKILL) // intentionally detached fixture, never a host process
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("open descendant pipe reported success")
		}
	case <-time.After(4 * time.Second):
		t.Fatal("pipe wait exceeded cancellation bound")
	}
}

func TestInstallerDetachedHelper(t *testing.T) {
	if len(os.Args) < 2 || os.Args[len(os.Args)-2] != "spawn-detached" {
		return
	}
	child := exec.Command("/bin/sleep", "30")
	child.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	child.Stdout, child.Stderr = os.Stdout, os.Stderr
	if err := child.Start(); err != nil {
		os.Exit(2)
	}
	if err := os.WriteFile(os.Args[len(os.Args)-1], []byte(strconv.Itoa(child.Process.Pid)), 0o600); err != nil {
		child.Process.Kill()
		os.Exit(2)
	}
	os.Exit(0)
}
