package network

import (
	"bufio"
	"context"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
)

// failureSink captures what the proxy reports through its blocked-row write
// failure hook.
type failureSink struct {
	mu   sync.Mutex
	errs []error
}

func (s *failureSink) record(_ logging.EventType, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errs = append(s.errs, err)
}

func (s *failureSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.errs)
}

// newFailingAuditProxy returns a proxy whose logger is closed, so every audit
// write fails, with its blocked-row write failure hook wired to a sink.
func newFailingAuditProxy(t *testing.T, cfg config.NetworkConfig) (*ProxyServer, *failureSink) {
	t.Helper()
	logger, err := logging.NewLogger(filepath.Join(t.TempDir(), "events.db"), "")
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("logger.Close: %v", err)
	}
	p := NewProxyServer(cfg, logger, "sid-audit-failure")
	sink := &failureSink{}
	p.SetBlockedWriteFailureHandler(sink.record)
	return p, sink
}

func TestProxyBlockedRowWriteFailureIsReported(t *testing.T) {
	cfg := config.NetworkConfig{Allow: []string{"allowed.example"}}

	t.Run("plain HTTP denial", func(t *testing.T) {
		p, sink := newFailingAuditProxy(t, cfg)
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://blocked.example/", nil))
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d: the denied request must still be refused", rec.Code, http.StatusForbidden)
		}
		if sink.count() != 1 {
			t.Fatalf("reported failures = %d, want 1 for the lost network_blocked row", sink.count())
		}
	})

	t.Run("CONNECT denial", func(t *testing.T) {
		p, sink := newFailingAuditProxy(t, cfg)
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodConnect, "http://blocked.example:443", nil)
		req.Host = "blocked.example:443"
		p.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
		}
		if sink.count() != 1 {
			t.Fatalf("reported failures = %d, want 1", sink.count())
		}
	})

	t.Run("look-back denial row", func(t *testing.T) {
		p, sink := newFailingAuditProxy(t, cfg)
		p.EnableLookback([]config.LookbackRule{{Name: "r1", On: "file_blocked", Then: "deny_egress"}})
		p.recordLookbackBlock(lookbackDesc(http.MethodGet, "allowed.example"), "r1", "7")
		if sink.count() != 1 {
			t.Fatalf("reported failures = %d, want 1", sink.count())
		}
	})

	t.Run("DNS rebind row", func(t *testing.T) {
		p, sink := newFailingAuditProxy(t, cfg)
		p.logDNSRebind(&dnsRebindError{host: "allowed.example", pinned: []net.IP{net.ParseIP("93.184.216.34")}, current: []net.IP{net.ParseIP("192.168.1.20")}})
		if sink.count() != 1 {
			t.Fatalf("reported failures = %d, want 1", sink.count())
		}
	})

	t.Run("degraded row", func(t *testing.T) {
		p, sink := newFailingAuditProxy(t, cfg)
		p.MarkDegraded("test degrade")
		if sink.count() != 1 {
			t.Fatalf("reported failures = %d, want 1", sink.count())
		}
	})
}

// A non-blocked row stays best-effort: losing a network_passed row does not
// fail the run.
func TestProxyPassedRowWriteFailureIsNotReported(t *testing.T) {
	p, sink := newFailingAuditProxy(t, config.NetworkConfig{Allow: []string{"allowed.example"}})
	p.logEvent(logging.EventNetworkPassed, http.MethodGet, "allowed.example", false)
	if sink.count() != 0 {
		t.Fatalf("reported failures = %d, want 0 for a non-blocked row", sink.count())
	}
}

// A blocked row written while another connection holds the write lock waits
// out busy_timeout and lands. Ordinary lock contention must not read as a lost
// row, because a lost blocked row fails the run.
func TestProxyBlockedRowWaitsOutWriteLock(t *testing.T) {
	cases := []struct {
		name  string
		write func(p *ProxyServer)
	}{
		{"allowlist denial", func(p *ProxyServer) {
			p.logEvent(logging.EventNetworkBlocked, http.MethodGet, "blocked.example", true)
		}},
		{"DNS rebind", func(p *ProxyServer) {
			p.logDNSRebind(&dnsRebindError{host: "allowed.example", pinned: []net.IP{net.ParseIP("93.184.216.34")}, current: []net.IP{net.ParseIP("192.168.1.20")}})
		}},
		{"degrade", func(p *ProxyServer) { p.MarkDegraded("test degrade") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dbPath := filepath.Join(t.TempDir(), "events.db")
			logger, err := logging.NewLogger(dbPath, "")
			if err != nil {
				t.Fatalf("NewLogger: %v", err)
			}
			t.Cleanup(func() { logger.Close() })
			// A first row, so the logger's connection is warm and the chain
			// has a predecessor to read.
			if err := logger.Log(logging.Event{Timestamp: time.Now(), EventType: logging.EventNetworkPassed, Category: "network", Detail: "warm", SessionID: "sid"}); err != nil {
				t.Fatalf("warm-up row: %v", err)
			}
			p := NewProxyServer(config.NetworkConfig{Allow: []string{"allowed.example"}}, logger, "sid")
			sink := &failureSink{}
			p.SetBlockedWriteFailureHandler(sink.record)

			wait := holdWriteLock(t, dbPath, 300*time.Millisecond)
			tc.write(p)
			wait()

			if sink.count() != 0 {
				t.Fatalf("failure hook fired %d time(s) under a 300 ms write lock (first: %v); want the write to wait out busy_timeout", sink.count(), sink.errs[0])
			}
			blocked := true
			sid := "sid"
			rows, err := logger.Query(logging.QueryOptions{Blocked: &blocked, SessionID: &sid})
			if err != nil {
				t.Fatalf("Query: %v", err)
			}
			if len(rows) != 1 {
				t.Fatalf("blocked rows = %d, want 1", len(rows))
			}
		})
	}
}

// Each control uses a real local upstream and real proxy connection. Count the
// dial attempts as well as accepted upstream sockets, so scheduling cannot make
// a late accept look like a successful block. CONNECT also exchanges payload.
func TestDurableAuditBeforeEgress(t *testing.T) {
	for _, protocol := range []string{"HTTP", "CONNECT"} {
		for _, mode := range []string{"signed", "closed", "insert-failure", "head-failure", "unsigned", "nil", "default-off"} {
			t.Run(protocol+"/"+mode, func(t *testing.T) {
				var accepted, dialed atomic.Int32
				upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "allowed control") }))
				upstream.Config.ConnState = func(_ net.Conn, s http.ConnState) {
					if s == http.StateNew {
						accepted.Add(1)
					}
				}
				upstream.Start()
				defer upstream.Close()
				dbPath := filepath.Join(t.TempDir(), "events.db")
				key := filepath.Join(t.TempDir(), "keys", "audit.key")
				opts := []logging.Option{logging.WithSigning(key)}
				if mode == "unsigned" {
					opts = nil
				}
				logger, err := logging.NewLogger(dbPath, "", opts...)
				if err != nil {
					t.Fatal(err)
				}
				defer logger.Close()
				pub := logger.SigningPublicKey()
				if mode == "closed" || mode == "default-off" {
					if err := logger.Close(); err != nil {
						t.Fatal(err)
					}
				}
				if mode == "insert-failure" || mode == "head-failure" {
					db, err := sql.Open("sqlite", dbPath)
					if err != nil {
						t.Fatal(err)
					}
					stmt := "CREATE TRIGGER fail_audit BEFORE INSERT ON events WHEN NEW.event_type = 'network_intent' BEGIN SELECT RAISE(ABORT, 'synthetic audit failure'); END"
					if mode == "head-failure" {
						stmt = "CREATE TRIGGER fail_audit BEFORE UPDATE ON chain_head BEGIN SELECT RAISE(ABORT, 'synthetic head failure'); END"
					}
					if _, err := db.Exec(stmt); err != nil {
						t.Fatal(err)
					}
					db.Close()
				}
				if mode == "nil" {
					logger = nil
				}
				strict := mode != "default-off"
				p := NewProxyServer(config.NetworkConfig{Allow: []string{"allowed.example"}, RequireDurableAudit: strict}, logger, "durable-test")
				defer p.transport.CloseIdleConnections()
				sink := &failureSink{}
				p.SetBlockedWriteFailureHandler(sink.record)
				p.dialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
					dialed.Add(1)
					if mode == "signed" {
						// Independent reader proves the signed intent is committed before dial.
						check, err := logging.NewLogger(dbPath, "")
						if err != nil {
							return nil, err
						}
						defer check.Close()
						typ := logging.EventNetworkIntent
						rows, err := check.Query(logging.QueryOptions{EventType: &typ})
						if err != nil {
							return nil, err
						}
						if len(rows) != 1 || rows[0].SessionID != "durable-test" {
							return nil, fmt.Errorf("intent not committed before dial: %+v", rows)
						}
						result, err := check.VerifyChainSigned(pub, true)
						if err != nil || !result.Intact || !result.HeadSigned || result.UnsignedEntries != 0 {
							return nil, fmt.Errorf("intent not authentic: %+v %v", result, err)
						}
					}
					return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
				}
				proxy := httptest.NewServer(p)
				defer proxy.Close()
				var status int
				var payload []byte
				if protocol == "HTTP" {
					proxyURL, _ := url.Parse(proxy.URL)
					transport := &http.Transport{Proxy: http.ProxyURL(proxyURL)}
					defer transport.CloseIdleConnections()
					client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
					resp, err := client.Get("http://allowed.example:80/")
					if err != nil {
						t.Fatal(err)
					}
					status = resp.StatusCode
					payload, err = io.ReadAll(resp.Body)
					resp.Body.Close()
					if err != nil {
						t.Fatal(err)
					}
				} else {
					conn, err := net.DialTimeout("tcp", proxy.Listener.Addr().String(), 5*time.Second)
					if err != nil {
						t.Fatal(err)
					}
					defer conn.Close()
					conn.SetDeadline(time.Now().Add(5 * time.Second))
					fmt.Fprint(conn, "CONNECT allowed.example:443 HTTP/1.1\r\nHost: allowed.example:443\r\n\r\n")
					reader := bufio.NewReader(conn)
					resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
					if err != nil {
						t.Fatal(err)
					}
					status = resp.StatusCode
					if status == http.StatusOK {
						fmt.Fprint(conn, "GET / HTTP/1.1\r\nHost: allowed.example\r\nConnection: close\r\n\r\n")
						response, err := http.ReadResponse(reader, nil)
						if err != nil {
							t.Fatal(err)
						}
						payload, err = io.ReadAll(response.Body)
						response.Body.Close()
						if err != nil {
							t.Fatal(err)
						}
					} else {
						resp.Body.Close()
					}
				}
				allowed := mode == "signed" || mode == "default-off"
				if allowed {
					if status != http.StatusOK || string(payload) != "allowed control" || dialed.Load() != 1 || accepted.Load() != 1 || sink.count() != 0 {
						t.Fatalf("status=%d body=%q dials=%d accepts=%d failures=%d", status, payload, dialed.Load(), accepted.Load(), sink.count())
					}
				} else {
					if status != http.StatusServiceUnavailable || dialed.Load() != 0 || accepted.Load() != 0 || sink.count() != 1 {
						t.Fatalf("status=%d dials=%d accepts=%d failures=%d", status, dialed.Load(), accepted.Load(), sink.count())
					}
				}
			})
		}
	}
}

func TestDurableAuditGatesReusedHTTPConnection(t *testing.T) {
	var requests, dials atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); fmt.Fprint(w, "ok") }))
	defer upstream.Close()
	logger, err := logging.NewLogger(filepath.Join(t.TempDir(), "events.db"), "", logging.WithSigning(filepath.Join(t.TempDir(), "keys", "audit.key")))
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	p := NewProxyServer(config.NetworkConfig{Allow: []string{"allowed.example"}, RequireDurableAudit: true}, logger, "pooled")
	defer p.transport.CloseIdleConnections()
	p.dialFunc = func(ctx context.Context, network, addr string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	}
	for i := 0; i < 2; i++ {
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://allowed.example/", nil))
		want := http.StatusOK
		if i == 1 {
			want = http.StatusServiceUnavailable
		}
		if rec.Code != want {
			t.Fatalf("request %d: status=%d", i, rec.Code)
		}
		if i == 0 {
			if err := logger.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	if requests.Load() != 1 || dials.Load() != 1 {
		t.Fatalf("audit failure forwarded on pooled connection: requests=%d dials=%d", requests.Load(), dials.Load())
	}
}
