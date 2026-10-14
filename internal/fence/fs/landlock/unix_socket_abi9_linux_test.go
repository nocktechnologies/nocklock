//go:build linux

package landlock

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// TestLandlockABI9UnixSocketIsolation proves the ABI-9 boundary on the actual
// kernel. A lower ABI is an explicit coverage gap, never an enforcement pass.
func TestLandlockABI9UnixSocketIsolation(t *testing.T) {
	abi, err := DetectABI()
	if err != nil {
		t.Fatalf("detect real Landlock ABI: %v", err)
	}
	if abi < MinUnixSocketABI {
		t.Skipf("ABI9_COVERAGE_GAP: real kernel Landlock ABI %d < 9; pathname/abstract isolation proof not run", abi)
	}
	if os.Getenv("NOCKLOCK_ABI9_SOCKET_CHILD") == "1" {
		// Irreversible thread-local policy lives only in this disposable process.
		runtime.LockOSThread()
		allowed := os.Getenv("NOCKLOCK_ABI9_ALLOWED")
		spec := Spec{ABI: abi}
		if err := AddUnixSocketIsolation(&spec, allowed); err != nil {
			t.Fatal(err)
		}
		if err := Apply(spec); err != nil {
			t.Fatal(err)
		}
		if err := connectABI9Socket(allowed); err != nil {
			t.Fatalf("allowed exact pathname socket failed: %v", err)
		}
		for _, name := range []string{"NOCKLOCK_ABI9_DENIED", "NOCKLOCK_ABI9_ABSTRACT"} {
			err := connectABI9Socket(os.Getenv(name))
			if !errors.Is(err, unix.EACCES) && !errors.Is(err, unix.EPERM) {
				t.Fatalf("%s connect=%v; want kernel EACCES/EPERM", name, err)
			}
			t.Logf("%s denied: %v", name, err)
		}
		t.Logf("ABI9_ENFORCEMENT_PASS: ABI=%d exact pathname allowed; unrelated pathname and abstract sockets denied", abi)
		return
	}
	// Keep Unix socket paths comfortably below sockaddr_un's length limit.
	dir, err := os.MkdirTemp("", "nl-abi9-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	addresses := []string{filepath.Join(dir, "allowed.sock"), filepath.Join(dir, "denied.sock"), fmt.Sprintf("@nl-abi9-%d-%d", os.Getpid(), time.Now().UnixNano())}
	for _, address := range addresses {
		listener, err := net.Listen("unix", address)
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		// Positive control: the same unfenced caller can reach every live socket.
		if err := connectABI9Socket(address); err != nil {
			t.Fatalf("unfenced live socket control %q: %v", address, err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestLandlockABI9UnixSocketIsolation$", "-test.v")
	cmd.Env = append(os.Environ(), "NOCKLOCK_ABI9_SOCKET_CHILD=1", "NOCKLOCK_ABI9_ALLOWED="+addresses[0],
		"NOCKLOCK_ABI9_DENIED="+addresses[1], "NOCKLOCK_ABI9_ABSTRACT="+addresses[2])
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ABI9 child failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "ABI9_ENFORCEMENT_PASS:") {
		t.Fatalf("ABI9 child did not complete enforcement controls:\n%s", out)
	}
	t.Logf("unfenced controls connected to all three live sockets; fenced result:\n%s", out)
}

func connectABI9Socket(address string) error {
	fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	return unix.Connect(fd, &unix.SockaddrUnix{Name: address})
}
