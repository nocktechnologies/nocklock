// Package forward sends committed fence decisions to Command's ops log.
package forward

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

const queueSize = 256

type queuedEvent struct {
	event logging.Event
	hash  string
}

// Forwarder posts decisions on a bounded background queue. A nil Forwarder is disabled.
type Forwarder struct {
	url, apiKey string
	client      *http.Client
	warnings    io.Writer
	queue       chan queuedEvent
	done        chan struct{}
	ctx         context.Context
	cancel      context.CancelFunc
	mu          sync.Mutex
	closed      bool
}

// New starts a forwarder for an already-validated Command base URL.
// An empty URL disables forwarding without starting a goroutine or HTTP client.
func New(baseURL, apiKey string) *Forwarder {
	if baseURL == "" {
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	f := &Forwarder{
		url:      strings.TrimRight(baseURL, "/") + "/api/brain/ops-log/",
		apiKey:   apiKey,
		warnings: os.Stderr,
		client: &http.Client{
			Timeout: time.Second,
			// A redirect could carry X-API-Key to a different host.
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		},
		queue: make(chan queuedEvent, queueSize),
		done:  make(chan struct{}),
		ctx:   ctx, cancel: cancel,
	}
	go f.run()
	return f
}

// Enqueue accepts a committed event and hash without waiting for network I/O.
func (f *Forwarder) Enqueue(event logging.Event, hash string) {
	if f == nil {
		return
	}
	switch event.EventType {
	case logging.EventFileBlocked, logging.EventFilePassed,
		logging.EventNetworkBlocked, logging.EventNetworkPassed,
		logging.EventSecretBlocked, logging.EventSecretPassed:
	default:
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return
	}
	select {
	case f.queue <- queuedEvent{event, hash}:
	default:
		fmt.Fprintln(f.warnings, "NockLock: warning: Command forward queue full; event remains in events.db")
	}
}

// Close gives queued events up to two seconds to send, then cancels requests.
func (f *Forwarder) Close() {
	if f == nil {
		return
	}
	f.mu.Lock()
	if !f.closed {
		f.closed = true
		close(f.queue)
	}
	f.mu.Unlock()
	select {
	case <-f.done:
	case <-time.After(2 * time.Second):
		fmt.Fprintln(f.warnings, "NockLock: warning: Command forward deadline exceeded; queued events remain in events.db")
		f.cancel()
		<-f.done
	}
	f.cancel()
}

func (f *Forwarder) run() {
	defer close(f.done)
	for item := range f.queue {
		if f.ctx.Err() != nil {
			return
		}
		f.post(item)
	}
}

func (f *Forwarder) post(item queuedEvent) {
	decision := "allow"
	severity := "info"
	if item.event.Blocked {
		decision, severity = "block", "high"
	}
	summary := fmt.Sprintf("nocklock: %s %s %s", decision, item.event.EventType, item.event.Detail)
	if len(summary) > 500 {
		summary = summary[:500]
	}
	payload := map[string]any{
		"agent": "nocklock", "event_type": "other", "severity": severity,
		"summary": summary,
		"data_blob": map[string]string{
			"source": "nocklock", "tool": string(item.event.EventType),
			"action": string(item.event.EventType), "target": item.event.Detail,
			"decision": decision, "reason": item.event.Detail,
			"fence": "nocklock", "session_id": item.event.SessionID,
			"entry_hash": item.hash,
		},
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return
	}
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			select {
			case <-time.After(time.Duration(100<<(attempt-1)) * time.Millisecond):
			case <-f.ctx.Done():
				return
			}
		}
		req, err := http.NewRequestWithContext(f.ctx, http.MethodPost, f.url, bytes.NewReader(body))
		if err != nil {
			break
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-API-Key", f.apiKey)
		resp, err := f.client.Do(req)
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode >= 200 && resp.StatusCode < 300 {
				return
			}
			if resp.StatusCode < 500 && resp.StatusCode != http.StatusTooManyRequests {
				break
			}
		}
	}
	// Never include the request URL, response body, or credential in diagnostics.
	fmt.Fprintln(f.warnings, "NockLock: warning: Command forward failed; event remains in events.db")
}
