package network

import (
	"context"
	"net"
	"time"
)

// ProxyWatchdog monitors a local TCP proxy by periodically probing its
// address. If the probe fails consecutively failThreshold times, onFailure
// is called — callers use this to kill the child process and exit non-zero
// (fail-closed behaviour).
type ProxyWatchdog struct {
	addr          string
	interval      time.Duration
	failThreshold int
	onFailure     func()
}

// NewProxyWatchdog creates a watchdog for the given proxy address.
//
//   - interval:      how often to probe (e.g. 5*time.Second)
//   - failThreshold: consecutive failures required before onFailure fires (≥1)
//   - onFailure:     called once when the threshold is reached
func NewProxyWatchdog(addr string, interval time.Duration, failThreshold int, onFailure func()) *ProxyWatchdog {
	if failThreshold < 1 {
		failThreshold = 1
	}
	return &ProxyWatchdog{
		addr:          addr,
		interval:      interval,
		failThreshold: failThreshold,
		onFailure:     onFailure,
	}
}

// Start launches the watchdog goroutine. It returns immediately; the goroutine
// runs until ctx is cancelled.
func (w *ProxyWatchdog) Start(ctx context.Context) {
	go w.run(ctx)
}

func (w *ProxyWatchdog) run(ctx context.Context) {
	consecutive := 0
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if w.probe() {
				consecutive = 0
			} else {
				consecutive++
				if consecutive >= w.failThreshold {
					w.onFailure()
					return
				}
			}
		}
	}
}

// probe attempts a TCP connect to the proxy address with a short timeout.
// Returns true if the proxy is reachable.
func (w *ProxyWatchdog) probe() bool {
	conn, err := net.DialTimeout("tcp", w.addr, 500*time.Millisecond)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
