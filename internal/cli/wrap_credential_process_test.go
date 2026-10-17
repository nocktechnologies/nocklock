//go:build linux || darwin

package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// credentialOutput bounds both memory and reads after an unreapable process.
// Wait's copying goroutines can still be finishing when the reap deadline wins.
type credentialOutput struct {
	mu   sync.Mutex
	data []byte
}

func (b *credentialOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	const limit = 1 << 20
	if remaining := limit - len(b.data); remaining > 0 {
		b.data = append(b.data, p[:min(len(p), remaining)]...)
	}
	return len(p), nil
}

func (b *credentialOutput) snapshot() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.data...)
}

// runCredentialCommand requires CommandContext(ctx, ...). Cancel kills the
// isolated group, WaitDelay bounds inherited output pipes, and a separate reap
// deadline bounds Wait even if the kernel cannot reap a killed process promptly.
func runCredentialCommand(ctx context.Context, cmd *exec.Cmd, cleanupWait time.Duration) ([]byte, error) {
	var output credentialOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	// Preserve caller options such as Linux Pdeathsig while isolating the
	// command's group for timeout and output-drain cleanup.
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
	killGroup := func() error {
		err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return nil
		}
		return err
	}
	cmd.Cancel = killGroup
	cmd.WaitDelay = cleanupWait
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	var err error
	select {
	case err = <-done:
		// WaitDelay can expire after the leader exits but descendants retain
		// its output pipes. That is a harness failure, even with a zero exit.
		err = errors.Join(err, ctx.Err())
	case <-ctx.Done():
		err = errors.Join(ctx.Err(), killGroup())
		timer := time.NewTimer(cleanupWait)
		defer timer.Stop()
		select {
		case waitErr := <-done:
			err = errors.Join(err, waitErr)
		case <-timer.C:
			err = errors.Join(err, fmt.Errorf("credential probe reap exceeded %s", cleanupWait))
		}
	}
	// Also stop descendants after an early leader exit/output-drain failure.
	err = errors.Join(err, killGroup())
	return output.snapshot(), err
}

func TestCredentialCommandDeadline(t *testing.T) {
	for _, tc := range []struct {
		name, script string
	}{
		{"hanging_wrap", "echo CREDENTIALS_OK; (sleep 0.8; echo survived > \"$1\") & wait"},
		{"exited_wrap_descendant_holds_output", "echo CREDENTIALS_OK; (sleep 0.8; echo survived > \"$1\") & exit 0"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
			defer cancel()
			marker := filepath.Join(t.TempDir(), "descendant-survived")
			cmd := exec.CommandContext(ctx, "/bin/sh", "-c", tc.script, "stub", marker)
			defer func() {
				if cmd.Process != nil {
					_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
				}
			}()
			started := time.Now()
			out, err := runCredentialCommand(ctx, cmd, 100*time.Millisecond)
			if err == nil {
				t.Fatalf("hung stub passed after printing a credential marker: %s", out)
			}
			if !strings.Contains(string(out), "CREDENTIALS_OK") {
				t.Fatalf("negative control never reached its marker: %v\n%s", err, out)
			}
			if took := time.Since(started); took > 2*time.Second {
				t.Fatalf("hung stub exceeded bounded cleanup: %s: %v", took, err)
			}
			t.Logf("hung stub correctly failed in %s: %v", time.Since(started), err)
			// The descendant would write after the leader's deadline if only
			// the leader were killed. Its absence tests group cleanup itself.
			time.Sleep(time.Until(started.Add(time.Second)))
			if _, err := os.Stat(marker); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("descendant survived process-group cleanup: %v", err)
			}
		})
	}
	// Positive control: a completed command still returns success and output.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := runCredentialCommand(ctx, exec.CommandContext(ctx, "/bin/sh", "-c", "echo CREDENTIALS_OK"), 100*time.Millisecond)
	if err != nil || !strings.Contains(string(out), "CREDENTIALS_OK") {
		t.Fatalf("completed control failed: %v\n%s", err, out)
	}
}

func TestCredentialCommandStartFailure(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := runCredentialCommand(ctx, exec.CommandContext(ctx, "/nonexistent-nocklock-credential-probe"), time.Second)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("startup failure = %v, want missing executable", err)
	}
}
