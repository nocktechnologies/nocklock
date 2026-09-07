//go:build linux

package network

import (
	"encoding/json"
	"net"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	"golang.org/x/sys/unix"
)

func TestTransparentBrokerPassesOnlyAllowedUpstreamSocket(t *testing.T) {
	target, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	defer target.Close()
	_, port, err := net.SplitHostPort(target.Addr().String())
	if err != nil {
		t.Fatalf("split target address: %v", err)
	}

	var accepted atomic.Int32
	go func() {
		conn, acceptErr := target.Accept()
		if acceptErr == nil {
			accepted.Add(1)
			_ = conn.Close()
		}
	}()

	broker := NewTransparentBroker(config.NetworkConfig{
		Allow:              []string{"localhost"},
		AllowPrivateRanges: true,
	}, nil, "transparent-test")
	path, token, err := broker.Start()
	if err != nil {
		t.Fatalf("broker.Start() error = %v", err)
	}
	defer broker.Stop()

	upstream, err := transparentBrokerDial(path, token, "localhost", port)
	if err != nil {
		t.Fatalf("broker dial allowed host: %v", err)
	}
	_ = upstream.Close()

	deadline := time.Now().Add(time.Second)
	for accepted.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if accepted.Load() != 1 {
		t.Fatal("allowed broker dial did not reach the upstream target")
	}

	if _, err := transparentBrokerDial(path, token, "blocked.test", port); err == nil {
		t.Fatal("broker dial to non-allowlisted host unexpectedly succeeded")
	}
	if accepted.Load() != 1 {
		t.Fatalf("non-allowlisted host reached upstream: accepts = %d, want 1", accepted.Load())
	}
}

func TestProxyAllowAllStillBlocksRawIP(t *testing.T) {
	p := &ProxyServer{allowAll: true}
	if p.isAllowed("203.0.113.12:443") {
		t.Fatal("allow_all must not permit a raw IP destination")
	}
}

func TestTransparentBrokerWatchdogFailsClosedAfterHeartbeatStops(t *testing.T) {
	broker := NewTransparentBroker(config.NetworkConfig{}, nil, "watchdog-test")
	broker.lastPing.Store(time.Now().UnixNano())
	done := make(chan struct{})
	defer close(done)
	fired := make(chan struct{}, 1)
	broker.StartWatchdog(done, 10*time.Millisecond, 1, func() { fired <- struct{}{} })

	select {
	case <-fired:
	case <-time.After(250 * time.Millisecond):
		t.Fatal("transparent broker watchdog did not fail closed after heartbeat stopped")
	}
}

func transparentBrokerDial(path, token, host, port string) (net.Conn, error) {
	conn, err := net.Dial("unix", path)
	if err != nil {
		return nil, err
	}
	unixConn := conn.(*net.UnixConn)
	defer unixConn.Close()
	payload, err := json.Marshal(transparentBrokerRequest{Token: token, Action: "dial", Host: host, Port: port})
	if err != nil {
		return nil, err
	}
	if _, err := unixConn.Write(append(payload, '\n')); err != nil {
		return nil, err
	}
	data := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := unixConn.ReadMsgUnix(data, oob)
	if err != nil || n != 1 || data[0] != 1 {
		return nil, os.ErrPermission
	}
	messages, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, err
	}
	for _, message := range messages {
		fds, parseErr := unix.ParseUnixRights(&message)
		if parseErr != nil || len(fds) != 1 {
			continue
		}
		file := os.NewFile(uintptr(fds[0]), "test-upstream")
		upstream, fileErr := net.FileConn(file)
		_ = file.Close()
		return upstream, fileErr
	}
	return nil, os.ErrInvalid
}
