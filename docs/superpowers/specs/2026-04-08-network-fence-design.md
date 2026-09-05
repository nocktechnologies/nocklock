# Network Fence Design — NockLock PR #7

**Date:** 2026-04-08  
**Status:** Approved  
**Branch:** `feature/network-fence`

---

## Overview

The network fence is the third and final fence in NockLock MVP. It prevents the wrapped AI agent from making HTTP/HTTPS requests to domains not in the allowlist. It works by starting a local HTTP proxy on a random high port, injecting the proxy address into the child process's environment, and allowing/blocking each request at the proxy based on the destination hostname.

**Core principle:** Hostname inspection only — no MITM, no certificate injection, no payload inspection. NockLock sees where traffic is going, not what it says.

---

## Architecture

### Proxy Approach

1. `nocklock wrap -- <agent>` starts a local HTTP/HTTPS proxy on `127.0.0.1:<random-port>`
2. `HTTP_PROXY`, `HTTPS_PROXY`, `http_proxy`, `https_proxy` are injected into the child env pointing at the proxy
3. `NO_PROXY` and `no_proxy` are explicitly removed from the child env to prevent bypass
4. The proxy checks each request's destination hostname against `[network].allow` in config
5. Allowed: proxy forwards the request transparently
6. Blocked: proxy returns HTTP 403 with body `"NockLock: domain not in allowlist"` and logs the event
7. On `allow_all = true`: proxy is not started; child env is not modified

### HTTPS (CONNECT method)

HTTPS uses the HTTP CONNECT tunnel mechanism:

1. Client sends `CONNECT api.github.com:443 HTTP/1.1`
2. Proxy extracts hostname, checks allowlist
3. Allowed: hijack the connection, dial the target, pipe bytes bidirectionally with `io.Copy`
4. Blocked: return 403, log event

**No MITM.** The encrypted payload is never inspected. Only the hostname from the CONNECT request is checked.

### Domain Matching Rules

- `"github.com"` in allowlist matches `github.com` AND `*.github.com` (all subdomains)
- `"*.example.com"` matches `sub.example.com` but NOT `example.com`
- Matching is case-insensitive
- Port is stripped before matching
- Raw IP addresses are blocked (no reverse DNS — fail closed for MVP)
- If allowlist is empty and `allow_all = false`: all traffic blocked (correct fail-closed behavior)

### NO_PROXY Bypass Prevention

The child environment must have `NO_PROXY` and `no_proxy` explicitly removed. This happens in the wrap command after the secret fence runs, during network fence setup.

---

## File Structure

```
internal/fence/network/
  proxy.go          # ProxyServer: lifecycle (Start, Stop, Addr)
  proxy_test.go     # Lifecycle and binding tests
  handler.go        # HTTP request handler + isAllowed logic
  handler_test.go   # Allow/block logic unit tests
  connect.go        # HTTPS CONNECT tunnel handler
  connect_test.go   # CONNECT allow/block tests
```

---

## Interfaces

### proxy.go

```go
type ProxyServer struct {
    listener  net.Listener
    allowList []string
    allowAll  bool
    logger    *logging.Logger
    sessionID string
    server    *http.Server
}

func NewProxyServer(cfg config.NetworkConfig, logger *logging.Logger, sessionID string) *ProxyServer
func (p *ProxyServer) Start() (string, error)  // returns "127.0.0.1:PORT"
func (p *ProxyServer) Stop() error
func (p *ProxyServer) Addr() string
```

- Binds to `127.0.0.1:0` (OS assigns random port)
- Logs `EventProxyStart` / `EventProxyStop` (new event types)

### handler.go

```go
func (p *ProxyServer) isAllowed(hostname string) bool
func (p *ProxyServer) ServeHTTP(w http.ResponseWriter, r *http.Request)
```

- `isAllowed` strips port, checks exact match + wildcard subdomain + raw IP block
- `ServeHTTP` routes CONNECT to `handleConnect`, else handles as forward proxy
- Logs `EventNetworkPassed` (allowed) or `EventNetworkBlocked` (blocked)
- Never logs request bodies or headers — hostname and decision only

### connect.go

```go
func (p *ProxyServer) handleConnect(w http.ResponseWriter, r *http.Request)
```

- Hijacks the connection if allowed
- Dials destination with 30s timeout, pipes with 5-minute idle timeout
- Returns 403 with NockLock identifier if blocked

---

## New Event Types

Add to `internal/logging/logger.go`:

```go
EventProxyStart EventType = "proxy_start"
EventProxyStop  EventType = "proxy_stop"
EventNetworkError EventType = "network_error"
```

**Use existing** `EventNetworkPassed` (not a new `EventNetworkAllowed`) for consistency with `EventSecretPassed` / `EventFilePassed`.

---

## Integration with wrap command

```go
// After secret fence, before spawning child:
if !cfg.Network.AllowAll {
    proxy := network.NewProxyServer(cfg.Network, logger, sessionID)
    addr, err := proxy.Start()
    if err != nil {
        // Degrade gracefully — agent still runs, just unfenced
        logEvent(logging.EventNetworkError, "network",
            fmt.Sprintf("proxy start failed: %v", err), false)
        fmt.Fprintf(os.Stderr, "NockLock: warning: network fence failed to start: %v\n", err)
    } else {
        defer proxy.Stop()
        proxyURL := fmt.Sprintf("http://%s", addr)
        childEnv = append(childEnv,
            "HTTP_PROXY="+proxyURL,
            "HTTPS_PROXY="+proxyURL,
            "http_proxy="+proxyURL,
            "https_proxy="+proxyURL,
        )
        // Remove NO_PROXY entries to prevent bypass
        childEnv = removeEnvVars(childEnv, "NO_PROXY", "no_proxy")
        fmt.Fprintf(os.Stderr, "NockLock: network fence active — allowing %d domain(s)\n",
            len(cfg.Network.Allow))
    }
}
```

A helper `removeEnvVars(env []string, keys ...string) []string` removes matching entries by key prefix.

---

## Status Command Update

```
NockLock v0.1.0
Secret fence: active (blocking 8 patterns)
Filesystem fence: active (allow 3, deny 5)
Network fence: active (allowing 7 domains)
Event log: .nock/events.db (142 events, 12 sessions)
Last event: 2026-04-08 22:15:03
```

---

## Testing Requirements (25+ tests)

### handler_test.go
- `isAllowed`: exact hostname match
- `isAllowed`: subdomain wildcard (github.com → api.github.com)
- `isAllowed`: wildcard does NOT match apex (*.example.com ≠ example.com)
- `isAllowed`: case-insensitive
- `isAllowed`: strips port before matching
- `isAllowed`: `allow_all = true` bypasses check
- `isAllowed`: empty allowlist blocks everything
- `isAllowed`: raw IP address blocked

### proxy_test.go
- Proxy starts and binds to localhost
- Proxy binds to random port (not hardcoded)
- Proxy stops cleanly
- Proxy only listens on 127.0.0.1 (not 0.0.0.0)

### connect_test.go
- CONNECT to allowed host returns 200
- CONNECT to blocked host returns 403
- CONNECT response body contains "NockLock"
- CONNECT to raw IP blocked

### HTTP handler tests
- GET to allowed domain proxied successfully
- GET to blocked domain returns 403
- POST to allowed domain proxied successfully

### Integration tests (wrap_test or network_test)
- Proxy env vars set correctly in child environment
- NO_PROXY cleared from child environment
- Network fence skipped when `allow_all = true`
- Events logged for allowed requests
- Events logged for blocked requests

### Edge cases
- Proxy handles concurrent requests
- Proxy handles connection timeout gracefully
- Proxy start failure degrades gracefully (child still runs)

---

## What Is NOT Built

- No MITM / certificate injection (hostname inspection only)
- No DNS-level blocking
- No per-path URL filtering (domain-level only)
- No proxy caching or bandwidth throttling
- No cloud sync of network events

---

## Files to Create

- `internal/fence/network/proxy.go`
- `internal/fence/network/proxy_test.go`
- `internal/fence/network/handler.go`
- `internal/fence/network/handler_test.go`
- `internal/fence/network/connect.go`
- `internal/fence/network/connect_test.go`

## Files to Modify

- `internal/logging/logger.go` — add `EventProxyStart`, `EventProxyStop`, `EventNetworkError`
- `internal/cli/wrap.go` — integrate network fence after secret fence
- `internal/cli/status.go` — show real network fence status
- `internal/config/defaults.go` — no changes (already has `network.allow` defaults)
- `CLAUDE.md`, `CHANGELOG.md`, `README.md` — docs update
