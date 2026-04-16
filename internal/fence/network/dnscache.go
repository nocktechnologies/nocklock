package network

import (
	"context"
	"net"
	"strings"
	"sync"
)

// resolveFunc is the signature of a DNS lookup function. Matches net.Resolver.LookupHost.
type resolveFunc func(ctx context.Context, host string) ([]string, error)

// DNSCache is a session-scoped DNS cache that pins hostname-to-IP mappings on
// first resolution and returns the cached result on all subsequent calls.
//
// This prevents DNS rebinding attacks: an attacker cannot cause a second DNS
// lookup to return a different (e.g. private) IP after the first public lookup
// was allowed.
type DNSCache struct {
	mu      sync.RWMutex
	entries map[string][]net.IP
	resolve resolveFunc
}

// NewDNSCache creates a DNSCache backed by the default system resolver.
func NewDNSCache() *DNSCache {
	return newDNSCacheWithResolver(func(ctx context.Context, host string) ([]string, error) {
		return net.DefaultResolver.LookupHost(ctx, host)
	})
}

// newDNSCacheWithResolver creates a DNSCache with an injectable resolver (for tests).
func newDNSCacheWithResolver(resolve resolveFunc) *DNSCache {
	return &DNSCache{
		entries: make(map[string][]net.IP),
		resolve: resolve,
	}
}

// LookupOrResolve returns cached IPs for host, or resolves and caches on first call.
// The result is pinned for the lifetime of the cache (the nocklock session).
//
// host is canonicalized (lowercased, trailing dot stripped) before lookup and
// storage so that case variations cannot produce divergent cache entries — a
// prerequisite for reliable DNS rebinding prevention.
func (c *DNSCache) LookupOrResolve(ctx context.Context, host string) ([]net.IP, error) {
	// Canonicalize: case-fold + strip trailing dot so "Example.com", "example.com",
	// and "example.com." all resolve to the same pinned entry.
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	// Fast path: already cached.
	c.mu.RLock()
	if ips, ok := c.entries[host]; ok {
		c.mu.RUnlock()
		return ips, nil
	}
	c.mu.RUnlock()

	// Slow path: resolve and cache.
	c.mu.Lock()
	defer c.mu.Unlock()

	// Double-check after acquiring write lock (another goroutine may have resolved).
	if ips, ok := c.entries[host]; ok {
		return ips, nil
	}

	rawAddrs, err := c.resolve(ctx, host)
	if err != nil {
		return nil, err
	}

	ips := make([]net.IP, 0, len(rawAddrs))
	for _, raw := range rawAddrs {
		if ip := net.ParseIP(raw); ip != nil {
			ips = append(ips, ip)
		}
	}

	c.entries[host] = ips
	return ips, nil
}
