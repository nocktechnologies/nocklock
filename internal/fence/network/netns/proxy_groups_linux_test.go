//go:build linux

package netns

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

const proxyGroupsRequireEnv = "NOCKLOCK_PROXY_GROUPS_REQUIRE"

// TestTransparentProxyDropsSupplementaryGroupsEveryThread starts the real
// transparent-proxy sidecar as root and checks every task after its identity
// drop. It only runs in the dedicated root CI job so ordinary tests on a seat
// host never start a privileged sidecar.
func TestTransparentProxyDropsSupplementaryGroupsEveryThread(t *testing.T) {
	if os.Getenv(proxyGroupsRequireEnv) != "1" {
		t.Skipf("set %s=1 in the dedicated root CI job", proxyGroupsRequireEnv)
	}
	if os.Geteuid() != 0 {
		t.Fatalf("%s=1 requires the test process to run as root", proxyGroupsRequireEnv)
	}

	const testGroup = 12345
	if err := syscall.Setgroups([]int{testGroup}); err != nil {
		t.Fatalf("set negative-control supplementary group: %v", err)
	}
	parentGroups, err := readProcessTaskGroups(os.Getpid())
	if err != nil {
		t.Fatalf("read negative-control task groups: %v", err)
	}
	if len(parentGroups) < 2 {
		t.Fatalf("negative control saw only %d Go thread(s); cannot verify process-wide group behavior", len(parentGroups))
	}
	for tid, groups := range parentGroups {
		if len(groups) != 1 || groups[0] != strconv.Itoa(testGroup) {
			t.Fatalf("negative control thread %s has groups %v, want [%d]", tid, groups, testGroup)
		}
	}

	bridge, err := GenerateBridgeCandidate()
	if err != nil {
		t.Fatalf("generate sidecar bridge config: %v", err)
	}
	payload, err := json.Marshal(EgressConfig{Allow: []string{"example.com"}, Bridge: bridge})
	if err != nil {
		t.Fatalf("encode sidecar config: %v", err)
	}
	payloadReader, payloadWriter, err := os.Pipe()
	if err != nil {
		t.Fatalf("create sidecar payload pipe: %v", err)
	}
	defer payloadReader.Close()
	defer payloadWriter.Close()

	cmd := exec.Command(os.Args[0], "__netns-proxy")
	cmd.ExtraFiles = []*os.File{payloadReader}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start transparent-proxy sidecar as root: %v", err)
	}
	_ = payloadReader.Close()
	if _, err := payloadWriter.Write(payload); err != nil {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		t.Fatalf("write sidecar config: %v", err)
	}
	_ = payloadWriter.Close()

	waitDone := make(chan error, 1)
	go func() { waitDone <- cmd.Wait() }()
	waited := false
	defer func() {
		if waited {
			return
		}
		_ = cmd.Process.Kill()
		<-waitDone
	}()

	if err := waitForProxyIdentityDrop(cmd.Process.Pid); err != nil {
		var waitErr error
		select {
		case waitErr = <-waitDone:
		default:
			_ = cmd.Process.Kill()
			waitErr = <-waitDone
		}
		waited = true
		if waitErr != nil {
			t.Fatalf("sidecar did not drop supplementary groups: %v; sidecar exit: %v; stderr: %s", err, waitErr, strings.TrimSpace(stderr.String()))
		}
		t.Fatalf("sidecar did not drop supplementary groups: %v; stderr: %s", err, strings.TrimSpace(stderr.String()))
	}

	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatalf("stop transparent-proxy sidecar: %v", err)
	}
	select {
	case err := <-waitDone:
		waited = true
		if err != nil {
			t.Fatalf("transparent-proxy sidecar exited after SIGTERM: %v; stderr: %s", err, strings.TrimSpace(stderr.String()))
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		<-waitDone
		waited = true
		t.Fatal("transparent-proxy sidecar did not stop after SIGTERM")
	}
}

func waitForProxyIdentityDrop(pid int) error {
	deadline := time.Now().Add(10 * time.Second)
	cleanSamples := 0
	for time.Now().Before(deadline) {
		fields, err := readProcStatusFields(filepath.Join("/proc", strconv.Itoa(pid), "status"), "Uid")
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("sidecar exited before identity drop")
			}
			return fmt.Errorf("read sidecar credentials: %w", err)
		}
		if len(fields) < 2 {
			return fmt.Errorf("malformed sidecar Uid status: %v", fields)
		}
		uid, err := strconv.Atoi(fields[1])
		if err != nil {
			return fmt.Errorf("parse sidecar effective uid %q: %w", fields[1], err)
		}
		gids, err := readProcStatusFields(filepath.Join("/proc", strconv.Itoa(pid), "status"), "Gid")
		if err != nil {
			return fmt.Errorf("read sidecar gids: %w", err)
		}
		if len(gids) < 2 {
			return fmt.Errorf("malformed sidecar Gid status: %v", gids)
		}
		gid, err := strconv.Atoi(gids[1])
		if err != nil {
			return fmt.Errorf("parse sidecar effective gid %q: %w", gids[1], err)
		}
		if uid == proxyUID && gid == proxyUID {
			tasks, err := readProcessTaskGroups(pid)
			if err == nil && len(tasks) >= 2 {
				for tid, groups := range tasks {
					if len(groups) != 0 {
						return fmt.Errorf("sidecar thread %s retains supplementary groups %v", tid, groups)
					}
				}
				cleanSamples++
				if cleanSamples >= 3 {
					return nil
				}
			} else if err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("read sidecar task groups: %w", err)
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for sidecar uid/gid %d and empty Groups for every thread", proxyUID)
}

func readProcessTaskGroups(pid int) (map[string][]string, error) {
	taskDir := filepath.Join("/proc", strconv.Itoa(pid), "task")
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return nil, err
	}
	groups := make(map[string][]string, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		statusPath := filepath.Join(taskDir, entry.Name(), "status")
		fields, err := readProcStatusFields(statusPath, "Groups")
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		groups[entry.Name()] = fields
	}
	return groups, nil
}

func readProcStatusFields(path, field string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		name, value, ok := strings.Cut(scanner.Text(), ":")
		if ok && name == field {
			return strings.Fields(value), nil
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("%s has no %s field", path, field)
}
