//go:build linux

package netns

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestHTTPAuthorityPolicy(t *testing.T) {
	for _, tc := range []struct {
		target, host string
		allowed      bool
	}{
		{"/", "allowed.test:80", true}, {"/", "allowed.test", true},
		{"http://allowed.test/", "blocked.test", false}, {"http://allowed.test/", "allowed.test", false},
		{"allowed.test:80", "allowed.test", false}, {"*", "allowed.test", false},
		{"/", "allowed.test:443", false}, {"/", "allowed.test:bad", false},
	} {
		_, host, err := readHTTPHeader(strings.NewReader(fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\n\r\n", tc.target, tc.host)))
		if (err == nil) != tc.allowed {
			t.Errorf("%+v: host=%s error=%v", tc, host, err)
		}
		if tc.allowed && host != "allowed.test" {
			t.Errorf("authority not normalized: %q", host)
		}
	}
}

func tcpPair(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Fatal(e)
	}
	defer l.Close()
	c, e := net.Dial("tcp", l.Addr().String())
	if e != nil {
		t.Fatal(e)
	}
	s, e := l.Accept()
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { c.Close(); s.Close() })
	c.SetDeadline(time.Now().Add(5 * time.Second))
	s.SetDeadline(time.Now().Add(5 * time.Second))
	return c.(*net.TCPConn), s.(*net.TCPConn)
}

func TestTunnelHalfClosePreservesResponse(t *testing.T) {
	client, a := tcpPair(t)
	b, server := tcpPair(t)
	done := make(chan struct{})
	go func() { pipeConnections(a, &bufferedConn{Conn: b, reader: bufio.NewReader(b)}); close(done) }()
	io.WriteString(client, "request")
	client.CloseWrite()
	req, e := io.ReadAll(server)
	if e != nil || string(req) != "request" {
		t.Fatalf("request=%q error=%v", req, e)
	}
	io.WriteString(server, "response after EOF")
	server.CloseWrite()
	got, e := io.ReadAll(client)
	if e != nil || string(got) != "response after EOF" {
		t.Fatalf("response=%q error=%v", got, e)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("tunnel did not finish")
	}
}

func TestForbiddenHTTPFraming(t *testing.T) {
	client, server := tcpPair(t)
	p := transparentProxy{cfg: EgressConfig{Allow: []string{"allowed.test"}}}
	go func() { defer server.Close(); p.handleHTTP(server) }()
	io.WriteString(client, "GET / HTTP/1.1\r\nHost: blocked.test\r\n\r\n")
	r, e := http.ReadResponse(bufio.NewReader(client), nil)
	if e != nil {
		t.Fatal(e)
	}
	b, e := io.ReadAll(r.Body)
	if e != nil {
		t.Fatal(e)
	}
	if r.StatusCode != 403 || r.ContentLength != int64(len(b)) {
		t.Fatalf("status=%d length=%d actual=%d", r.StatusCode, r.ContentLength, len(b))
	}
}

func TestBridgeRollbackEachFailure(t *testing.T) {
	for fail := 1; fail <= 5; fail++ {
		t.Run(strconv.Itoa(fail), func(t *testing.T) {
			useTempSubnetReservationDir(t)
			bridge, err := NewBridgeSpec()
			if err != nil {
				t.Fatal(err)
			}
			var calls []string
			run := func(name string, args ...string) (string, error) {
				calls = append(calls, name+" "+strings.Join(args, " "))
				if len(calls) == fail {
					return "injected", errors.New("failure")
				}
				return "", nil
			}
			if createBridgeWith(bridge, run) == nil {
				t.Fatal("expected failure")
			}
			joined := strings.Join(calls, "\n")
			if fail > 1 && !strings.Contains(joined, "netns del "+bridge.Namespace) {
				t.Fatal("namespace not rolled back")
			}
			if fail > 2 && !strings.Contains(joined, "link del "+bridge.HostInterface) {
				t.Fatal("veth not rolled back")
			}
			if fail <= 2 && strings.Contains(joined, "link del") {
				t.Fatal("deleted unowned veth")
			}
			if _, err := os.Stat(filepath.Join(subnetReservationDir, bridge.ReservationID)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("reservation file after createBridge failure: %v", err)
			}
		})
	}
}

func TestBridgeRollbackEachFailurePreExistingNamespaceIsNotDeleted(t *testing.T) {
	useTempSubnetReservationDir(t)
	bridge, err := NewBridgeSpec()
	if err != nil {
		t.Fatal(err)
	}
	var calls []string
	run := func(name string, args ...string) (string, error) {
		call := name + " " + strings.Join(args, " ")
		calls = append(calls, call)
		if call == "ip netns add "+bridge.Namespace {
			return "File exists", errors.New("failure")
		}
		return "", nil
	}
	if createBridgeWith(bridge, run) == nil {
		t.Fatal("expected pre-existing namespace failure")
	}
	resultErr := errors.New("create bridge")
	cleanupFailedBridge(bridge, false, false, &resultErr, func(bridge BridgeSpec) error {
		calls = append(calls, "ip netns del "+bridge.Namespace)
		return nil
	})
	for _, call := range calls {
		if call == "ip netns del "+bridge.Namespace {
			t.Fatalf("deleted pre-existing namespace: %q", call)
		}
	}
}

func TestSubnetReservationBridgeFailureDoesNotRemoveReplacement(t *testing.T) {
	useTempSubnetReservationDir(t)
	bridge, err := NewBridgeSpec()
	if err != nil {
		t.Fatal(err)
	}
	reservationFile := filepath.Join(subnetReservationDir, bridge.ReservationID)
	const replacementOwner = "different-owner\n"
	run := func(name string, args ...string) (string, error) {
		return "File exists", errors.New("failure")
	}
	if createBridgeWith(bridge, run) == nil {
		t.Fatal("expected create bridge failure")
	}
	if err := os.WriteFile(reservationFile, []byte(replacementOwner), 0600); err != nil {
		t.Fatalf("simulate replacement reservation: %v", err)
	}
	resultErr := errors.New("create bridge")
	cleanupFailedBridge(bridge, false, false, &resultErr, func(bridge BridgeSpec) error {
		return ReleaseSubnetReservation(bridge.ReservationID)
	})

	got, err := os.ReadFile(reservationFile)
	if err != nil {
		t.Fatalf("replacement reservation removed: %v", err)
	}
	if string(got) != replacementOwner {
		t.Fatalf("replacement reservation = %q, want %q", got, replacementOwner)
	}
}

func TestCleanupFailedBridgeGuard(t *testing.T) {
	sentinel := errors.New("cleanup failed")
	for _, tc := range []struct {
		name               string
		bridgeCreated      bool
		resultErr          error
		cleanupTransferred bool
		cleanupErr         error
		wantCalls          int
	}{
		{"created failure not transferred calls cleanup", true, errors.New("create bridge"), false, nil, 1},
		{"bridge never created skips cleanup", false, errors.New("create bridge"), false, nil, 0},
		{"ownership transferred skips cleanup", true, errors.New("create bridge"), true, nil, 0},
		{"no failure skips cleanup", true, nil, false, nil, 0},
		{"cleanup error is joined into resultErr", true, errors.New("create bridge"), false, sentinel, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			resultErr := tc.resultErr
			cleanupFailedBridge(BridgeSpec{}, tc.bridgeCreated, tc.cleanupTransferred, &resultErr, func(BridgeSpec) error {
				calls++
				return tc.cleanupErr
			})
			if calls != tc.wantCalls {
				t.Fatalf("cleanup called %d times, want %d", calls, tc.wantCalls)
			}
			if tc.cleanupErr != nil && !errors.Is(resultErr, tc.cleanupErr) {
				t.Fatalf("resultErr = %v, want it to wrap sentinel %v", resultErr, tc.cleanupErr)
			}
		})
	}
}

func TestSupervisionKillsDescendantOnCancel(t *testing.T) {
	testSupervisionKillsDescendant(t, true)
}

func TestSupervisionKillsDescendantOnProxyDeath(t *testing.T) {
	testSupervisionKillsDescendant(t, false)
}

func testSupervisionKillsDescendant(t *testing.T, cancelNow bool) {
	file := t.TempDir() + "/pid"
	cmd := exec.Command("sh", "-c", `sleep 60 & echo $! > "$1"; wait`, "sh", file)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if e := cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	var pid int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b, _ := os.ReadFile(file)
		pid, _ = strconv.Atoi(strings.TrimSpace(string(b)))
		if pid > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if pid == 0 {
		t.Fatal("descendant not started")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var health []string
	interval := time.Hour
	if cancelNow {
		cancel()
	} else {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		health = []string{l.Addr().String()}
		l.Close()
		interval = 10 * time.Millisecond
	}
	if superviseChildContext(ctx, cmd, health, interval) == nil {
		t.Fatal("expected cancellation")
	}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		b, e := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if os.IsNotExist(e) || strings.Contains(string(b), ") Z ") {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("descendant survived cancellation")
}

// Tracks deadline changes without making this regression depend on wall-clock
// scheduling. The handler must remove the header deadline before tunnel traffic.
type deadlineRecordingConn struct {
	net.Conn
	cleared chan struct{}
}

func (c *deadlineRecordingConn) SetDeadline(d time.Time) error {
	if d.IsZero() {
		select {
		case c.cleared <- struct{}{}:
		default:
		}
	}
	return c.Conn.SetDeadline(d)
}

func TestHTTPHandshakeDeadlineClearedForTunnel(t *testing.T) {
	// The production bridge uses this fixed port. An isolated loopback address
	// supplies a fake CONNECT server without creating namespaces or nft rules.
	ln, err := net.Listen("tcp", "127.0.0.254:15080")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	done := make(chan error, 1)
	go func() {
		conn, e := ln.Accept()
		if e != nil {
			done <- e
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		reader := bufio.NewReader(conn)
		req, e := http.ReadRequest(reader)
		if e != nil {
			done <- e
			return
		}
		if req.Host != "allowed.test:80" {
			done <- fmt.Errorf("CONNECT target %s", req.Host)
			return
		}
		io.WriteString(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
		_, e = http.ReadRequest(reader)
		if e != nil {
			done <- e
			return
		}
		_, e = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
		done <- e
	}()
	client, server := tcpPair(t)
	tracked := &deadlineRecordingConn{Conn: server, cleared: make(chan struct{}, 1)}
	tracked.SetDeadline(time.Now().Add(5 * time.Second))
	p := transparentProxy{cfg: EgressConfig{Allow: []string{"allowed.test"}, Bridge: BridgeSpec{HostAddress: "127.0.0.254"}}}
	go func() { defer server.Close(); p.handleHTTP(tracked) }()
	io.WriteString(client, "GET / HTTP/1.1\r\nHost: allowed.test:80\r\n\r\n")
	client.CloseWrite()
	r, e := http.ReadResponse(bufio.NewReader(client), nil)
	if e != nil {
		t.Fatal(e)
	}
	body, e := io.ReadAll(r.Body)
	if e != nil || string(body) != "ok" {
		t.Fatalf("body=%q error=%v", body, e)
	}
	select {
	case <-tracked.cleared:
	default:
		t.Fatal("header deadline persisted into tunnel")
	}
	if e := <-done; e != nil {
		t.Fatal(e)
	}
}
