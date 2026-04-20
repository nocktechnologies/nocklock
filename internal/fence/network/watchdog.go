package network

import (
	"context"
	"io"
	"net/http"
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
	transport     *http.Transport
	client        *http.Client
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
	transport := &http.Transport{Proxy: nil}
	return &ProxyWatchdog{
		addr:          addr,
		interval:      interval,
		failThreshold: failThreshold,
		onFailure:     onFailure,
		transport:     transport,
		client: &http.Client{
			Transport: transport,
			Timeout:   500 * time.Millisecond,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return http.ErrUseLastResponse
			},
		},
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
	defer w.transport.CloseIdleConnections()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if w.probe(ctx) {
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

// probe requests the proxy health endpoint with a short timeout.
// Returns true if the proxy is reachable and serving health checks.
func (w *ProxyWatchdog) probe(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+w.addr+ProxyHealthPath, nil)
	if err != nil {
		return false
	}
	resp, err := w.client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode == http.StatusOK
}
