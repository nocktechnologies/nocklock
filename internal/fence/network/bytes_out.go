package network

import (
	"fmt"
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

// bytesOutThreshold is a fixed, alert-only ceiling per host and session.
// A transfer larger than 100 MiB is unusual enough to merit inspection.
const bytesOutThreshold int64 = 100 << 20

type bytesOutSink interface {
	LogImmediate(logging.Event) error
}

// BytesOutRecorder writes cumulative, signed bytes-out totals per host and
// flags the first crossing of the session ceiling. Callers report only bytes
// written to an upstream socket, never bytes merely read from the client.
type BytesOutRecorder struct {
	mu        sync.Mutex
	sink      bytesOutSink
	sessionID string
	totals    map[string]int64
	flagged   map[string]bool
}

// NewBytesOutRecorder creates a recorder for one session.
func NewBytesOutRecorder(sink bytesOutSink, sessionID string) *BytesOutRecorder {
	return &BytesOutRecorder{sink: sink, sessionID: sessionID, totals: make(map[string]int64), flagged: make(map[string]bool)}
}

// Record adds n delivered upstream bytes for host, writing a cumulative total
// and one alert row when that host first exceeds the fixed ceiling.
func (r *BytesOutRecorder) Record(host string, n int64) error {
	if n < 0 {
		return fmt.Errorf("negative upstream byte count")
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(host)
	r.mu.Lock()
	defer r.mu.Unlock()
	total := r.totals[host] + n
	if total < r.totals[host] {
		total = math.MaxInt64
	}
	event := logging.Event{Timestamp: time.Now(), EventType: logging.EventNetworkBytesOut, Category: "network",
		Detail: fmt.Sprintf("host=%s bytes_out=%d session_bytes_out=%d", host, n, total), SessionID: r.sessionID}
	if err := r.sink.LogImmediate(event); err != nil {
		return fmt.Errorf("sign network bytes-out row: %w", err)
	}
	r.totals[host] = total
	if total > bytesOutThreshold && !r.flagged[host] {
		flag := logging.Event{Timestamp: time.Now(), EventType: logging.EventNetworkOutlier, Category: "network",
			Detail:  fmt.Sprintf("host=%s session_bytes_out=%d threshold=%d action=alert_only", host, total, bytesOutThreshold),
			Blocked: true, SessionID: r.sessionID}
		if err := r.sink.LogImmediate(flag); err != nil {
			return fmt.Errorf("sign network outlier row: %w", err)
		}
		r.flagged[host] = true
	}
	return nil
}

// countingConn observes writes actually accepted by the upstream socket.
// Close is the common completion point for HTTP pooled connections and CONNECT.
type countingConn struct {
	net.Conn
	host      string
	recorder  *BytesOutRecorder
	onError   func(error)
	onClose   func()
	bytes     atomic.Int64
	mu        sync.Mutex
	writes    sync.WaitGroup
	closed    bool
	once      sync.Once
	closeErr  error
	reportErr error
}

func (c *countingConn) Write(b []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	c.writes.Add(1)
	c.mu.Unlock()
	n, err := c.Conn.Write(b)
	c.bytes.Add(int64(n))
	c.writes.Done()
	return n, err
}

func (c *countingConn) Close() error {
	c.once.Do(func() {
		if c.onClose != nil {
			defer c.onClose()
		}
		c.mu.Lock()
		c.closed = true
		c.mu.Unlock()
		c.closeErr = c.Conn.Close()
		c.writes.Wait()
		c.reportErr = c.recorder.Record(c.host, c.bytes.Load())
		if c.reportErr != nil && c.onError != nil {
			c.onError(c.reportErr)
		}
	})
	if c.closeErr != nil {
		return c.closeErr
	}
	return c.reportErr
}
