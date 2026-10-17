package cli

import (
	"fmt"
	"io"
	"sync/atomic"
	"time"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

// auditRecorder writes wrap's per-event audit rows. A blocked-event row that
// cannot be written (disk full, DB lock, signing failure) fails the session
// closed: the first failure is announced on stderr, the child is cancelled, and
// the error is kept for the session_end verdict. A failed non-blocked row stays
// best-effort, so telemetry such as the macOS denial tailer's own warnings
// never stops the child.
type auditRecorder struct {
	log       func(logging.Event) error
	sessionID string
	stderr    io.Writer
	cancel    func()
	failed    atomic.Pointer[error]
}

// record writes one event under the recorder's session id. It is safe for
// concurrent use: the fs-event goroutine, the denial tailer and the proxy
// watchdog all write through it, and the proxy reports its own lost blocked
// rows through fail.
func (r *auditRecorder) record(eventType logging.EventType, category, detail string, blocked bool) {
	err := r.log(logging.Event{
		Timestamp: time.Now(),
		EventType: eventType,
		Category:  category,
		Detail:    detail,
		Blocked:   blocked,
		SessionID: r.sessionID,
	})
	if err == nil || !blocked {
		return
	}
	r.fail(eventType, err)
}

// fail records err as the session's blocked-event write failure. The first
// failure is announced on stderr and cancels the child; later ones are
// dropped. It is the network proxy's blocked-row write failure handler too, so
// a denied request whose network_blocked row is lost fails the run the same
// way. Safe for concurrent use.
func (r *auditRecorder) fail(eventType logging.EventType, err error) {
	first := err // only the failure path takes an address, so a success does not allocate
	if r.failed.CompareAndSwap(nil, &first) {
		fmt.Fprintf(r.stderr, "NockLock: fatal: could not record a blocked %s event in the audit log: %v — failing the run\n", eventType, err)
		r.cancel()
	}
}

// failure returns the first blocked-event write error, or nil.
func (r *auditRecorder) failure() error {
	if p := r.failed.Load(); p != nil {
		return *p
	}
	return nil
}
