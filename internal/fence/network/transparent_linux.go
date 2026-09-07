//go:build linux

package network

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"golang.org/x/sys/unix"
)

type transparentBrokerRequest struct {
	Token  string `json:"token"`
	Action string `json:"action"`
	Host   string `json:"host,omitempty"`
	Port   string `json:"port,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// TransparentBroker is the host-network half of the netns transparent proxy.
// It receives only authenticated sidecar requests over a per-session Unix
// socket, repeats the allowlist decision, resolves with the host resolver, and
// passes a connected upstream socket back to the unprivileged sidecar.
type TransparentBroker struct {
	allowList          []string
	allowAll           bool
	allowPrivateRanges bool
	dnsCache           *DNSCache
	logger             *logging.Logger
	sessionID          string

	listener *net.UnixListener
	dir      string
	path     string
	token    string
	closed   chan struct{}
	once     sync.Once
	lastPing atomic.Int64
}

// NewTransparentBroker creates an unstarted host-network broker for cfg.
func NewTransparentBroker(cfg config.NetworkConfig, logger *logging.Logger, sessionID string) *TransparentBroker {
	return &TransparentBroker{
		allowList:          cfg.Allow,
		allowAll:           cfg.AllowAll,
		allowPrivateRanges: cfg.AllowPrivateRanges,
		dnsCache:           NewDNSCache(),
		logger:             logger,
		sessionID:          sessionID,
		closed:             make(chan struct{}),
	}
}

// Start creates an authenticated Unix-domain control socket and begins serving
// sidecar requests. The returned path and token must be delivered only to the
// separate proxy uid; neither is a child configuration option.
func (b *TransparentBroker) Start() (path, token string, err error) {
	if b.listener != nil {
		return "", "", errors.New("transparent broker already started")
	}
	dir, err := os.MkdirTemp("", "nocklock-netns-")
	if err != nil {
		return "", "", fmt.Errorf("create transparent broker directory: %w", err)
	}
	if err := os.Chmod(dir, 0o711); err != nil {
		_ = os.RemoveAll(dir)
		return "", "", fmt.Errorf("set transparent broker directory mode: %w", err)
	}
	path = filepath.Join(dir, "broker.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		_ = os.RemoveAll(dir)
		return "", "", fmt.Errorf("listen transparent broker: %w", err)
	}
	if err := os.Chmod(path, 0o666); err != nil {
		_ = listener.Close()
		_ = os.RemoveAll(dir)
		return "", "", fmt.Errorf("set transparent broker socket mode: %w", err)
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		_ = listener.Close()
		_ = os.RemoveAll(dir)
		return "", "", fmt.Errorf("generate transparent broker token: %w", err)
	}
	b.listener = listener
	b.dir = dir
	b.path = path
	b.token = hex.EncodeToString(random)
	go b.serve()
	return b.path, b.token, nil
}

// Stop closes the broker and removes its session-only Unix socket directory.
func (b *TransparentBroker) Stop() error {
	b.once.Do(func() {
		close(b.closed)
		if b.listener != nil {
			_ = b.listener.Close()
		}
		if b.dir != "" {
			_ = os.RemoveAll(b.dir)
		}
	})
	return nil
}

// ProxyHeartbeatSeen reports whether the authenticated netns sidecar has
// completed its startup heartbeat. Callers can use it as a readiness receipt;
// the heartbeat itself is still monitored continuously by StartWatchdog.
func (b *TransparentBroker) ProxyHeartbeatSeen() bool {
	return b.lastPing.Load() != 0
}

// StartWatchdog monitors the sidecar's authenticated heartbeat. A sidecar that
// dies mid-session makes the broker stop receiving pings, so onFailure can kill
// the entire fenced child process group and preserve fail-closed semantics.
func (b *TransparentBroker) StartWatchdog(ctxDone <-chan struct{}, interval time.Duration, failThreshold int, onFailure func()) {
	if interval <= 0 {
		interval = time.Second
	}
	if failThreshold < 1 {
		failThreshold = 1
	}
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		misses := 0
		for {
			select {
			case <-ctxDone:
				return
			case <-ticker.C:
				last := b.lastPing.Load()
				if last != 0 && time.Since(time.Unix(0, last)) <= interval*2 {
					misses = 0
					continue
				}
				misses++
				if misses >= failThreshold {
					if onFailure != nil {
						onFailure()
					}
					return
				}
			}
		}
	}()
}

func (b *TransparentBroker) serve() {
	for {
		conn, err := b.listener.AcceptUnix()
		if err != nil {
			select {
			case <-b.closed:
				return
			default:
				return
			}
		}
		go b.handle(conn)
	}
}

func (b *TransparentBroker) handle(conn *net.UnixConn) {
	defer conn.Close()
	decoder := json.NewDecoder(bufio.NewReader(conn))
	var request transparentBrokerRequest
	if err := decoder.Decode(&request); err != nil || request.Token != b.token {
		b.writeStatus(conn, false)
		return
	}
	switch request.Action {
	case "ping":
		b.lastPing.Store(time.Now().UnixNano())
		b.writeStatus(conn, true)
	case "deny":
		b.log(logging.EventNetworkBlocked, request.Host, request.Reason, true)
		b.writeStatus(conn, true)
	case "dial":
		b.handleDial(conn, request)
	default:
		b.writeStatus(conn, false)
	}
}

func (b *TransparentBroker) handleDial(conn *net.UnixConn, request transparentBrokerRequest) {
	if !b.isAllowed(request.Host) || request.Port == "" {
		b.log(logging.EventNetworkBlocked, request.Host, "broker_allowlist_denied", true)
		b.writeStatus(conn, false)
		return
	}
	if _, err := strconv.ParseUint(request.Port, 10, 16); err != nil {
		b.log(logging.EventNetworkBlocked, request.Host, "broker_invalid_port", true)
		b.writeStatus(conn, false)
		return
	}
	upstream, err := dialWithCache(context.Background(), "tcp", net.JoinHostPort(request.Host, request.Port), b.dnsCache, b.allowPrivateRanges)
	if err != nil {
		b.log(logging.EventNetworkError, request.Host, "broker_upstream_failed", true)
		b.writeStatus(conn, false)
		return
	}
	defer upstream.Close()
	tcp, ok := upstream.(*net.TCPConn)
	if !ok {
		b.log(logging.EventNetworkError, request.Host, "broker_non_tcp_upstream", true)
		b.writeStatus(conn, false)
		return
	}
	file, err := tcp.File()
	if err != nil {
		b.log(logging.EventNetworkError, request.Host, "broker_duplicate_upstream_fd_failed", true)
		b.writeStatus(conn, false)
		return
	}
	defer file.Close()
	if _, _, err := conn.WriteMsgUnix([]byte{1}, unix.UnixRights(int(file.Fd())), nil); err != nil {
		return
	}
	b.log(logging.EventNetworkPassed, request.Host, "broker_upstream_connected", false)
}

func (b *TransparentBroker) writeStatus(conn *net.UnixConn, ok bool) {
	status := byte(0)
	if ok {
		status = 1
	}
	_, _ = conn.Write([]byte{status})
}

func (b *TransparentBroker) isAllowed(hostname string) bool {
	p := ProxyServer{allowList: b.allowList, allowAll: b.allowAll}
	return p.isAllowed(hostname)
}

func (b *TransparentBroker) log(eventType logging.EventType, host, detail string, blocked bool) {
	if b.logger == nil {
		return
	}
	_ = b.logger.Log(logging.Event{
		Timestamp: time.Now(), EventType: eventType, Category: "network",
		Detail:  fmt.Sprintf("transparent_proxy host=%s reason=%s", host, detail),
		Blocked: blocked, SessionID: b.sessionID,
	})
}
