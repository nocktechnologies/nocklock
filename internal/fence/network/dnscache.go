package network

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
)

// resolveFunc is the signature of a DNS lookup function. Matches net.Resolver.LookupHost.
type resolveFunc func(ctx context.Context, host string) ([]string, error)

// DNSCache is a session-scoped DNS cache that pins hostname-to-IP mappings on
// first resolution and verifies subsequent resolutions against the pinned set.
//
// This prevents DNS rebinding attacks: an attacker cannot cause a later DNS
// lookup to return a different IP after the first public lookup was allowed.
type DNSCache struct {
	mu      sync.RWMutex
	entries map[string][]net.IP
	resolve resolveFunc
}

type dnsRebindError struct {
	host    string
	pinned  []net.IP
	current []net.IP
}

func (e *dnsRebindError) Error() string {
	return fmt.Sprintf("DNS rebinding detected for %q: pinned=%s current=%s",
		e.host, formatIPs(e.pinned), formatIPs(e.current))
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

// LookupOrResolve resolves host and returns the session-pinned IPs.
// The first resolution pins the IP set for the lifetime of the cache. Each
// subsequent call performs a fresh resolution and requires it to match the
// pinned set exactly, ignoring order. If DNS returns a different set later,
// LookupOrResolve returns a dnsRebindError and no connection should be made.
//
// host is canonicalized (lowercased, trailing dot stripped) before lookup and
// storage so that case variations cannot produce divergent cache entries — a
// prerequisite for reliable DNS rebinding prevention.
func (c *DNSCache) LookupOrResolve(ctx context.Context, host string) ([]net.IP, error) {
	// Canonicalize: case-fold + strip trailing dot so "Example.com", "example.com",
	// and "example.com." all resolve to the same pinned entry.
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	c.mu.Lock()
	defer c.mu.Unlock()

	rawAddrs, err := c.resolve(ctx, host)
	if err != nil {
		return nil, err
	}
	current := parseIPs(rawAddrs)

	if pinned, ok := c.entries[host]; ok {
		if !sameIPSet(pinned, current) {
			return nil, &dnsRebindError{
				host:    host,
				pinned:  cloneIPs(pinned),
				current: cloneIPs(current),
			}
		}
		return cloneIPs(pinned), nil
	}

	c.entries[host] = cloneIPs(current)
	return cloneIPs(current), nil
}

func parseIPs(rawAddrs []string) []net.IP {
	ips := make([]net.IP, 0, len(rawAddrs))
	for _, raw := range rawAddrs {
		if ip := net.ParseIP(raw); ip != nil {
			ips = append(ips, cloneIP(ip))
		}
	}
	return ips
}

func cloneIPs(ips []net.IP) []net.IP {
	out := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		out = append(out, cloneIP(ip))
	}
	return out
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}

func sameIPSet(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	counts := make(map[string]int, len(a))
	for _, ip := range a {
		counts[ip.String()]++
	}
	for _, ip := range b {
		key := ip.String()
		if counts[key] == 0 {
			return false
		}
		counts[key]--
		if counts[key] == 0 {
			delete(counts, key)
		}
	}
	return len(counts) == 0
}

func formatIPs(ips []net.IP) string {
	parts := make([]string, 0, len(ips))
	for _, ip := range ips {
		parts = append(parts, ip.String())
	}
	return strings.Join(parts, ",")
}
