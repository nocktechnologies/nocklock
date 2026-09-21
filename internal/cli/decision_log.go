package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

// decision_log.go holds the trusted-parent half of the netns egress audit path
// (Nock N10649). The fenced transparent proxy drops to the shared nobody uid and
// has no DB handle or signing key, so it cannot sign an audit row itself. Instead
// it appends plain TSV allow/deny records to a wrap-owned decision-log file; this
// code — running in the trusted `wrap` parent that holds the signing key — reads
// those records and folds each into the signed, hash-chained event log via a
// logging.Logger. Kept out of wrap.go so the reader and the record→Event mapping
// are unit-testable in isolation, with no root, netns, or real proxy required.

// decisionRecord is one parsed egress decision emitted by the transparent proxy.
// The wire format is a single newline-terminated TSV line:
//
//	verdict\tprotocol\thost\tport\treason\n
//
// verdict is "allow" or "deny".
type decisionRecord struct {
	verdict  string
	protocol string
	host     string
	port     string
	reason   string
}

// decisionEventSink is the minimal audit-write surface the reader needs.
// *logging.Logger already satisfies it, so wrap passes the live signed logger;
// tests pass a fake that records each Log call.
type decisionEventSink interface {
	Log(logging.Event) error
}

// parseDecisionRecord parses one decision line (WITHOUT the trailing newline).
// It returns ok=false for any line that is not a well-formed decision record —
// wrong field count, or an unrecognised verdict — so malformed or partial input
// is skipped rather than logged.
func parseDecisionRecord(line string) (decisionRecord, bool) {
	fields := bytes.Split([]byte(line), []byte{'\t'})
	if len(fields) != 5 {
		return decisionRecord{}, false
	}
	rec := decisionRecord{
		verdict:  string(fields[0]),
		protocol: string(fields[1]),
		host:     string(fields[2]),
		port:     string(fields[3]),
		reason:   string(fields[4]),
	}
	if rec.verdict != "allow" && rec.verdict != "deny" {
		return decisionRecord{}, false
	}
	return rec, true
}

// decisionRecordToEvent maps a parsed decision to the signed event the parent
// records. It REUSES the existing network EventTypes — allow → EventNetworkPassed,
// deny → EventNetworkBlocked — and never introduces a new type. SessionID is the
// wrap session's id so the egress rows join the rest of that session's trail.
func decisionRecordToEvent(rec decisionRecord, sessionID string) logging.Event {
	eventType := logging.EventNetworkPassed
	blocked := false
	if rec.verdict == "deny" {
		eventType = logging.EventNetworkBlocked
		blocked = true
	}
	return logging.Event{
		Timestamp: time.Now(),
		EventType: eventType,
		Category:  "network",
		Detail:    fmt.Sprintf("method=%s host=%s:%s rule=%s", rec.protocol, rec.host, rec.port, rec.reason),
		Blocked:   blocked,
		SessionID: sessionID,
	}
}

// decisionLogScanner turns a byte stream of decision records into signed audit
// events. It is fed arbitrary chunks (as they arrive from a growing file) and
// emits ONLY complete, newline-terminated records: a trailing partial line is
// retained in buf until its terminator arrives in a later chunk, so the reader
// never acts on a torn record. It is not safe for concurrent Feed calls; wrap
// drives it from a single reader goroutine.
type decisionLogScanner struct {
	sink      decisionEventSink
	sessionID string
	buf       []byte
}

func newDecisionLogScanner(sink decisionEventSink, sessionID string) *decisionLogScanner {
	return &decisionLogScanner{sink: sink, sessionID: sessionID}
}

// Pending reports whether the scanner is holding an unterminated (partial)
// record — bytes after the last newline that have not yet formed a complete
// line. Mid-stream this is normal (more bytes may arrive), but after the writer
// is provably gone (wrap's FINAL drain) a leftover partial can never complete,
// so it signals an incomplete decision log the caller must fail closed on.
func (s *decisionLogScanner) Pending() bool {
	return len(s.buf) > 0
}

// drainDecisionReader reads r until it is exhausted, feeding every chunk to the
// scanner (which signs each complete record). It returns nil ONLY on a clean
// io.EOF; ANY other read error, or a Feed (signing) failure, is returned so the
// caller FAILS CLOSED. This is the crux of the N3 fix: a non-EOF read error
// (e.g. EIO) must never be mistaken for a clean end of the decision log, which
// would let wrap report success with unread/unsigned decisions.
//
// For a growing regular file, os.File.Read returns io.EOF at the current end and
// a later Read after more bytes are appended returns them — so wrap calls this
// repeatedly to tail the file, and once more after the writer is provably gone.
func drainDecisionReader(r io.Reader, scanner *decisionLogScanner, buf []byte) error {
	for {
		n, err := r.Read(buf)
		if n > 0 {
			if ferr := scanner.Feed(buf[:n]); ferr != nil {
				return ferr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// Feed appends chunk to the scanner's buffer and logs every complete record now
// available. Any bytes after the last newline are kept for the next Feed.
//
// It FAILS CLOSED: on the FIRST sink.Log error it stops and returns that error so
// the caller (wrap's reader goroutine) can cancel the session and exit non-zero.
// A signed audit write that failed must never be silently dropped while wrap
// reports success — the whole point of the feature is that every recorded
// decision is durably signed.
func (s *decisionLogScanner) Feed(chunk []byte) error {
	s.buf = append(s.buf, chunk...)
	for {
		i := bytes.IndexByte(s.buf, '\n')
		if i < 0 {
			return nil
		}
		line := string(s.buf[:i])
		s.buf = s.buf[i+1:]
		if rec, ok := parseDecisionRecord(line); ok {
			if err := s.sink.Log(decisionRecordToEvent(rec, s.sessionID)); err != nil {
				return fmt.Errorf("sign egress decision into audit log: %w", err)
			}
		}
	}
}
