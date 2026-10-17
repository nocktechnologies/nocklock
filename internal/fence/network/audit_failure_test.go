package network

import (
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
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
