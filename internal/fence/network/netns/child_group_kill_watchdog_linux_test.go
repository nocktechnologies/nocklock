//go:build linux

package netns

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

func runWatchdogTestChild(descendants int) int {
	for i := 0; i < descendants; i++ {
		cmd := exec.Command("/bin/sleep", "30")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Start(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}
	for {
		time.Sleep(time.Hour)
	}
}

// TestChildGroupKillWatchdog_ProcessGroupKilledOnParentExit verifies that when
// a parent process dies, the watchdog kills the entire child process group,
// including any descendants spawned by the child leader.
func TestChildGroupKillWatchdog_ProcessGroupKilledOnParentExit(t *testing.T) {
	// Create a child process and its process group.
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve executable: %v", err)
	}

	// Start a subprocess that will become a process group leader and spawn a descendant.
	cmd := exec.Command(self, "__test-child-spawn-descendant")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start child process: %v", err)
	}

	childPID := cmd.Process.Pid
	childPGID := childPID // Setpgid makes it its own group leader.

	// Give the child time to spawn its descendant.
	time.Sleep(100 * time.Millisecond)

	// Create a pipe for the watchdog to monitor.
	pipeRead, pipeWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	defer pipeRead.Close()

	// Start the watchdog process with the child PGID.
	watchdogReq := ChildGroupKillWatchdogRequest{ChildPGID: childPGID}
	encoded, err := json.Marshal(watchdogReq)
	if err != nil {
		t.Fatalf("encode watchdog request: %v", err)
	}

	watchdogCmd := exec.Command(self, "__netns-child-kill-watchdog")
	watchdogCmd.Stdin = bytes.NewReader(encoded)
	watchdogCmd.Stdout = os.Stdout
	watchdogCmd.Stderr = os.Stderr
	watchdogCmd.ExtraFiles = []*os.File{pipeRead}

	if err := watchdogCmd.Start(); err != nil {
		t.Fatalf("start watchdog: %v", err)
	}

	// Close the write end of the pipe to signal parent death to the watchdog.
	pipeWrite.Close()

	waitCommandExit(t, cmd, time.Second)

	// Wait for watchdog to finish.
	if err := watchdogCmd.Wait(); err != nil {
		t.Fatalf("watchdog exit: %v", err)
	}
}

// TestChildGroupKillWatchdog_ConcurrentDescendantsAllKilled tests that all
// descendants of the child process, not just the leader, are killed when the
// watchdog triggers.
func TestChildGroupKillWatchdog_ConcurrentDescendantsAllKilled(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve executable: %v", err)
	}

	// Start a child that spawns multiple background processes.
	cmd := exec.Command(self, "__test-child-spawn-many-descendants")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		t.Fatalf("start child process: %v", err)
	}

	childPGID := cmd.Process.Pid
	time.Sleep(150 * time.Millisecond)

	// Create and signal parent death via pipe.
	pipeRead, pipeWrite, err := os.Pipe()
	if err != nil {
		t.Fatalf("create pipe: %v", err)
	}
	defer pipeRead.Close()

	watchdogReq := ChildGroupKillWatchdogRequest{ChildPGID: childPGID}
	encoded, err := json.Marshal(watchdogReq)
	if err != nil {
		t.Fatalf("encode watchdog request: %v", err)
	}

	watchdogCmd := exec.Command(self, "__netns-child-kill-watchdog")
	watchdogCmd.Stdin = bytes.NewReader(encoded)
	watchdogCmd.ExtraFiles = []*os.File{pipeRead}

	if err := watchdogCmd.Start(); err != nil {
		t.Fatalf("start watchdog: %v", err)
	}

	pipeWrite.Close()
	waitCommandExit(t, cmd, time.Second)
	waitProcessGroupGone(t, childPGID, 2*time.Second)

	if err := watchdogCmd.Wait(); err != nil {
		t.Fatalf("watchdog exit: %v", err)
	}
}

func waitCommandExit(t *testing.T, cmd *exec.Cmd, timeout time.Duration) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("child exited cleanly; want watchdog signal termination")
		}
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		t.Fatalf("child process %d still alive after watchdog should have killed it", cmd.Process.Pid)
	}
}

func waitProcessGroupGone(t *testing.T, pgid int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		err := syscall.Kill(-pgid, 0)
		if err == syscall.ESRCH {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("process group %d still exists after watchdog kill", pgid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
