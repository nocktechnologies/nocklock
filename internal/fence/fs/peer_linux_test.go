//go:build linux

package fs

import (
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

// This is an ordinary, non-privileged Unix-stream test. The second report is
// written by another process through the inherited connection, demonstrating
// why the captured connector identity is not a per-action writer identity.
func TestConnectionPeerLinuxAcceptedSnapshot(t *testing.T) {
	for _, synchronous := range []bool{false, true} {
		name := "channel"
		if synchronous {
			name = "synchronous"
		}
		t.Run(name, func(t *testing.T) {
			fence, err := NewFence(&FenceConfig{WaitForAck: true}, "unused")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			reports := make(chan FenceEvent, 2)
			if synchronous {
				fence.SetReportHandler(func(event FenceEvent) { reports <- event })
			}
			channel := fence.Listen(ctx)
			var received <-chan FenceEvent = reports
			if !synchronous {
				received = channel
			}
			var conn net.Conn
			t.Cleanup(func() {
				if conn != nil {
					conn.Close()
				}
				cancel()
				fence.Close()
				deadline := time.After(5 * time.Second)
				for {
					select {
					case _, ok := <-channel:
						if !ok {
							return
						}
					case <-deadline:
						t.Error("listener did not drain after connection cleanup")
						return
					}
				}
			})
			conn, err = net.DialTimeout("unix", fence.SocketPath, 5*time.Second)
			if err != nil {
				t.Fatal(err)
			}
			writePeerFrame(t, conn, spoofedPeerReport)
			first := receivePeerFrame(t, received)
			want := peerCredentials{PID: int32(os.Getpid()), UID: uint32(os.Geteuid()), GID: uint32(os.Getegid())}
			if !first.hasPeer || first.peer.credentialsStatus != "captured" || first.peer.credentials != want {
				t.Fatalf("SO_PEERCRED snapshot=%+v, want %+v", first.peer, want)
			}
			exe, err := os.Readlink("/proc/self/exe")
			if err != nil {
				t.Fatal(err)
			}
			if first.peer.executable.Status != "observed" || first.peer.executable.Path != exe {
				t.Fatalf("executable observation=%+v, want %q", first.peer.executable, exe)
			}
			file, err := conn.(*net.UnixConn).File()
			if err != nil {
				t.Fatal(err)
			}
			defer file.Close()
			childCtx, stop := context.WithTimeout(context.Background(), 10*time.Second)
			defer stop()
			cmd := exec.CommandContext(childCtx, os.Args[0], "-test.run=^TestConnectionPeerLinuxInheritedWriter$", "-test.count=1")
			cmd.Env = append(os.Environ(), "NOCKLOCK_TEST_PEER_FD=1")
			cmd.ExtraFiles = []*os.File{file}
			cmd.WaitDelay = time.Second
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("inherited writer: %v\n%s", err, out)
			}
			second := receivePeerFrame(t, received)
			if !second.hasPeer || second.peer != first.peer || second.Path != "/inherited-writer" || cmd.Process.Pid == int(want.PID) {
				t.Fatalf("connection snapshot changed with writer: first=%+v second=%+v child=%d", first.peer, second, cmd.Process.Pid)
			}
			t.Logf("connector pid=%d uid=%d gid=%d; inherited writer pid=%d retained original peer", want.PID, want.UID, want.GID, cmd.Process.Pid)
		})
	}
}

func writePeerFrame(t *testing.T, conn net.Conn, frame string) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, frame+"\n"); err != nil {
		t.Fatal(err)
	}
	var ack [1]byte
	if _, err := io.ReadFull(conn, ack[:]); err != nil || ack[0] != 1 {
		t.Fatalf("ACK=%v, err=%v", ack, err)
	}
}

func receivePeerFrame(t *testing.T, reports <-chan FenceEvent) FenceEvent {
	t.Helper()
	select {
	case event, ok := <-reports:
		if !ok {
			t.Fatal("listener closed before report")
		}
		return event
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for accepted connection report")
		return FenceEvent{}
	}
}

func TestConnectionPeerLinuxInheritedWriter(t *testing.T) {
	if os.Getenv("NOCKLOCK_TEST_PEER_FD") != "1" {
		return
	}
	file := os.NewFile(3, "inherited-peer-socket")
	defer file.Close()
	conn, err := net.FileConn(file)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	writePeerFrame(t, conn, fmt.Sprintf(`{"type":"fs","action":"blocked","path":"/inherited-writer","operation":"open","reason":"writer pid %d"}`, os.Getpid()))
}

func TestConnectionPeerLinuxClosedSocketUnavailable(t *testing.T) {
	listener, err := net.Listen("unix", t.TempDir()+"/peer.sock")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	conn, err := net.DialTimeout("unix", listener.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn.Close()
	peer := captureConnectionPeer(conn)
	if peer != unavailableConnectionPeer() {
		t.Fatalf("closed socket fabricated credentials: %+v", peer)
	}
}
