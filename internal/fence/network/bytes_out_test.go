package network

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
)

func TestProxyRecordsAllowedHTTPWireBytes(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer upstream.Close()
	l, err := logging.NewLogger(filepath.Join(t.TempDir(), "events.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	p := NewProxyServer(config.NetworkConfig{Allow: []string{"allowed.example"}}, l, "session")
	p.dialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	}
	addr, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}
	proxyURL, _ := url.Parse("http://" + addr)
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	resp, err := client.Post("http://allowed.example/upload", "application/octet-stream", bytes.NewReader([]byte("hello")))
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		t.Fatalf("allowed status = %d", resp.StatusCode)
	}
	resp, err = client.Get("http://blocked.example/")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("blocked status = %d", resp.StatusCode)
	}
	if err := p.Stop(); err != nil {
		t.Fatal(err)
	}
	session := "session"
	events, err := l.Query(logging.QueryOptions{SessionID: &session, Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range events {
		if e.EventType == logging.EventNetworkBytesOut {
			found = true
			if !strings.Contains(e.Detail, "host=allowed.example") || strings.Contains(e.Detail, "host=blocked.example") || strings.Contains(e.Detail, "bytes_out=0 ") {
				t.Fatalf("wrong bytes row: %+v", e)
			}
		}
	}
	if !found {
		t.Fatalf("no allowed-host bytes row: %+v", events)
	}
}

func TestProxyStopDrainsActiveConnectBytes(t *testing.T) {
	l, err := logging.NewLogger(filepath.Join(t.TempDir(), "events.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	p := NewProxyServer(config.NetworkConfig{Allow: []string{"allowed.example"}}, l, "session")
	received := make(chan string, 1)
	p.dialFunc = func(context.Context, string, string) (net.Conn, error) {
		upstream, peer := net.Pipe()
		go func() {
			defer peer.Close()
			buf := make([]byte, 5)
			_, _ = io.ReadFull(peer, buf)
			received <- string(buf)
			_, _ = io.Copy(io.Discard, peer)
		}()
		return upstream, nil
	}
	addr, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}
	conn, resp := dialCONNECT(t, addr, "allowed.example:443")
	defer conn.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("CONNECT status = %d", resp.StatusCode)
	}
	if _, err := conn.Write([]byte("hello")); err != nil {
		t.Fatal(err)
	}
	if got := <-received; got != "hello" {
		t.Fatalf("upstream received %q", got)
	}
	done := make(chan error, 1)
	go func() { done <- p.Stop() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Stop did not drain an active CONNECT")
	}
	session := "session"
	events, err := l.Query(logging.QueryOptions{SessionID: &session, Limit: 20})
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, e := range events {
		if e.EventType == logging.EventNetworkBytesOut && strings.Contains(e.Detail, "host=allowed.example bytes_out=5") {
			found = true
		}
	}
	if !found {
		t.Fatalf("CONNECT bytes missing at Stop: %+v", events)
	}
}

func TestProxyStopCancelsConnectBeforeHijack(t *testing.T) {
	l, err := logging.NewLogger(filepath.Join(t.TempDir(), "events.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	p := NewProxyServer(config.NetworkConfig{Allow: []string{"allowed.example"}}, l, "session")
	entered := make(chan struct{})
	p.dialFunc = func(ctx context.Context, _, _ string) (net.Conn, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	addr, err := p.Start()
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, "CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:443\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("CONNECT did not reach upstream dial")
	}
	done := make(chan error, 1)
	go func() { done <- p.Stop() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Stop waited for a pre-hijack CONNECT dial")
	}
}

func TestBytesOutRecorderSignsTotalsAndFlagsOnlyOutlier(t *testing.T) {
	dir := t.TempDir()
	keyDir := filepath.Join(dir, "keys")
	if err := os.Mkdir(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	key := filepath.Join(keyDir, "audit.key")
	l, err := logging.NewLogger(filepath.Join(dir, "events.db"), "", logging.WithSigning(key))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	recorder := NewBytesOutRecorder(l, "session")
	session := "session"
	if err := recorder.Record("API.Example:443", bytesOutThreshold-1); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Record("other.example:443", 200); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Record("api.example:443", 2); err != nil {
		t.Fatal(err)
	}
	if err := recorder.Record("api.example:443", 10); err != nil {
		t.Fatal(err)
	}
	events, err := l.Query(logging.QueryOptions{SessionID: &session, Limit: 20, ByID: true})
	if err != nil {
		t.Fatal(err)
	}
	var flags int
	for _, e := range events {
		if e.EventType == logging.EventNetworkOutlier {
			flags++
			if !e.Blocked || !strings.Contains(e.Detail, "host=api.example") || !strings.Contains(e.Detail, "action=alert_only") {
				t.Fatalf("bad flag: %+v", e)
			}
		}
	}
	if flags != 1 || len(events) != 5 {
		t.Fatalf("events = %+v; want four totals and one flag", events)
	}
	if !strings.Contains(events[2].Detail, "session_bytes_out=104857601") {
		t.Fatalf("missing per-host session total: %+v", events[2])
	}
	blocked := true
	alerts, err := l.Query(logging.QueryOptions{SessionID: &session, Blocked: &blocked, Limit: 20})
	if err != nil || len(alerts) != 1 || alerts[0].EventType != logging.EventNetworkOutlier {
		t.Fatalf("blocked/alert surface = %+v, %v", alerts, err)
	}
	result, err := l.VerifyChainSigned(l.SigningPublicKey(), true)
	if err != nil || !result.Intact || result.SigState != "authentic" {
		t.Fatalf("signed chain: %+v, %v", result, err)
	}
}

func TestCountingConnRecordsOnlyBytesWrittenUpstream(t *testing.T) {
	dir := t.TempDir()
	l, err := logging.NewLogger(filepath.Join(dir, "events.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	left, right := net.Pipe()
	defer right.Close()
	c := &countingConn{Conn: left, host: "allowed.example:443", recorder: NewBytesOutRecorder(l, "session")}
	go func() {
		buf := make([]byte, 5)
		_, _ = right.Read(buf)
	}()
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if n, err := c.Write([]byte("hello")); err != nil || n != 5 {
		t.Fatalf("write = %d, %v", n, err)
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	session := "session"
	events, err := l.Query(logging.QueryOptions{SessionID: &session, Limit: 10})
	if err != nil || len(events) != 1 || !strings.Contains(events[0].Detail, "bytes_out=5") {
		t.Fatalf("events = %+v, %v", events, err)
	}
}

type delayedWriteConn struct {
	net.Conn
	started chan struct{}
	release chan struct{}
	closed  chan struct{}
}

func (c *delayedWriteConn) Write(b []byte) (int, error) {
	close(c.started)
	<-c.release
	return len(b), nil
}

func (c *delayedWriteConn) Close() error {
	close(c.closed)
	return nil
}

func TestCountingConnWaitsForInFlightWriteBeforeReporting(t *testing.T) {
	l, err := logging.NewLogger(filepath.Join(t.TempDir(), "events.db"), "")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	raw := &delayedWriteConn{started: make(chan struct{}), release: make(chan struct{}), closed: make(chan struct{})}
	c := &countingConn{Conn: raw, host: "allowed.example:443", recorder: NewBytesOutRecorder(l, "session")}
	go func() { _, _ = c.Write([]byte("hello")) }()
	<-raw.started
	done := make(chan error, 1)
	go func() { done <- c.Close() }()
	<-raw.closed
	select {
	case err := <-done:
		t.Fatalf("Close returned before the upstream write finished: %v", err)
	default:
	}
	close(raw.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	session := "session"
	events, err := l.Query(logging.QueryOptions{SessionID: &session, Limit: 10})
	if err != nil || len(events) != 1 || !strings.Contains(events[0].Detail, "bytes_out=5") {
		t.Fatalf("events = %+v, %v", events, err)
	}
}
