package cli

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/fence/network"
	"github.com/nocktechnologies/nocklock/internal/logging"
)

// A denied egress request whose network_blocked row cannot be written is
// refused at once and leaves the run-level failure that wrap reads at the
// verdict (audit.failure), so the run exits 2 instead of the child's code.
func TestProxyLostBlockedRowFailsTheRun(t *testing.T) {
	logger, err := logging.NewLogger(filepath.Join(t.TempDir(), "events.db"), "")
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	// A closed logger fails every write, like a full disk or a locked database.
	if err := logger.Close(); err != nil {
		t.Fatalf("logger.Close: %v", err)
	}

	var stderr bytes.Buffer
	cancels := 0
	audit := &auditRecorder{log: logger.LogImmediate, sessionID: "s1", stderr: &stderr, cancel: func() { cancels++ }}
	proxy := network.NewProxyServer(config.NetworkConfig{Allow: []string{"allowed.example"}}, logger, "s1")
	proxy.SetBlockedWriteFailureHandler(audit.fail)

	rec := httptest.NewRecorder()
	proxy.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://blocked.example/", nil))
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d: the denied request must still be refused", rec.Code, http.StatusForbidden)
	}
	if audit.failure() == nil {
		t.Fatal("audit.failure() = nil after a lost network_blocked row, want an error so wrap exits 2")
	}
	if cancels != 1 {
		t.Fatalf("cancels = %d, want 1", cancels)
	}
	if !strings.Contains(stderr.String(), "network_blocked") {
		t.Fatalf("stderr = %q, want the fatal line to name network_blocked", stderr.String())
	}
}
