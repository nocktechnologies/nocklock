package forward

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

func TestForwardCommittedFenceDecisions(t *testing.T) {
	var mu sync.Mutex
	var posts []map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/brain/ops-log/" || r.Method != http.MethodPost || r.Header.Get("X-API-Key") != "test-key" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Error(err)
		}
		mu.Lock()
		posts = append(posts, body)
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	}))
	defer server.Close()
	f := New(server.URL, "test-key")
	l, err := logging.NewLogger(filepath.Join(t.TempDir(), "events.db"), "", logging.WithEventCommitted(f.Enqueue))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, tc := range []struct {
		typ              logging.EventType
		category, detail string
		blocked          bool
	}{
		{logging.EventFileBlocked, "filesystem", "op=read path=/denied reason=policy", true},
		{logging.EventNetworkBlocked, "network", "method=GET host=blocked.test:443 rule=deny", true},
		{logging.EventSecretBlocked, "secret", "SECRET_TOKEN", true},
		{logging.EventNetworkPassed, "network", "method=GET host=allowed.test:443 rule=allow", false},
	} {
		if err := l.Log(logging.Event{Timestamp: time.Now(), EventType: tc.typ, Category: tc.category, Detail: tc.detail, Blocked: tc.blocked, SessionID: "session-1"}); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(posts) != 4 {
		t.Fatalf("got %d posts, want 4", len(posts))
	}
	for i, post := range posts {
		wantSeverity, wantDecision := "high", "block"
		if i == 3 {
			wantSeverity, wantDecision = "info", "allow"
		}
		if post["event_type"] != "other" || post["severity"] != wantSeverity {
			t.Errorf("post %d: %v", i, post)
		}
		data := post["data_blob"].(map[string]any)
		if data["source"] != "nocklock" || data["decision"] != wantDecision || data["session_id"] != "session-1" || data["entry_hash"] == "" || data["action"] == "" || data["target"] == "" {
			t.Errorf("post %d data: %v", i, data)
		}
	}
}

func TestDisabledForwarderMakesNoRequests(t *testing.T) {
	var calls int
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	defer server.Close()
	// An absent [audit.forward] produces an empty URL. Local events still commit.
	f := New("", "")
	l, err := logging.NewLogger(filepath.Join(t.TempDir(), "events.db"), "", logging.WithEventCommitted(f.Enqueue))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := l.Log(logging.Event{Timestamp: time.Now(), EventType: logging.EventFileBlocked, Category: "filesystem", Detail: "/blocked", Blocked: true, SessionID: "s"}); err != nil {
		t.Fatal(err)
	}
	f.Close()
	if calls != 0 {
		t.Fatalf("disabled forwarding made %d network calls", calls)
	}
}

func TestUnreachableCommandDoesNotChangeDecisionOrLoseAudit(t *testing.T) {
	var calls int
	started := make(chan struct{}, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			started <- struct{}{}
			<-release // Command is stalled while the local decision commits.
		}
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()
	f := New(server.URL, "private-test-key")
	var warning bytes.Buffer
	f.warnings = &warning
	l, err := logging.NewLogger(filepath.Join(t.TempDir(), "events.db"), "", logging.WithEventCommitted(f.Enqueue))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	event := logging.Event{Timestamp: time.Now(), EventType: logging.EventNetworkBlocked, Category: "network", Detail: "blocked.test", Blocked: true, SessionID: "s"}
	logged := make(chan error, 1)
	go func() { logged <- l.Log(event) }()
	select {
	case <-started:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("forward request never started")
	}
	select {
	case err := <-logged:
		if err != nil {
			close(release)
			t.Fatal(err)
		}
	case <-time.After(200 * time.Millisecond):
		close(release)
		t.Fatal("local event logging waited on the stalled Command request")
	}
	close(release)
	rows, err := l.Query(logging.QueryOptions{SessionID: &event.SessionID})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || !rows[0].Blocked || rows[0].Detail != event.Detail {
		t.Fatalf("local decision changed or lost: %v", rows)
	}
	f.Close()
	message := warning.String()
	if calls != 3 {
		t.Errorf("retry calls = %d, want 3", calls)
	}
	if !strings.Contains(message, "event remains in events.db") || strings.Contains(message, "private-test-key") {
		t.Errorf("unsafe or missing diagnostic: %q", message)
	}
}

func TestRedirectDoesNotCarryAPIKey(t *testing.T) {
	var redirected bool
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected = true }))
	defer other.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, other.URL, http.StatusFound) }))
	defer server.Close()
	f := New(server.URL, "private-test-key")
	f.Enqueue(logging.Event{EventType: logging.EventSecretBlocked, Detail: "NAME", Blocked: true}, "hash")
	f.Close()
	if redirected {
		t.Fatal("forwarder followed redirect")
	}
}
