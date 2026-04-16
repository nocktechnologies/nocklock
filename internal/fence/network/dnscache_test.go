package network

import (
	"context"
	"net"
	"sync"
	"testing"
)

// fakeResolver is a controllable DNS resolver for testing.
type fakeResolver struct {
	mu    sync.Mutex
	calls int
	addrs []string // returned on every call
}

func (f *fakeResolver) lookup(_ context.Context, host string) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.addrs, nil
}

func TestDNSCacheFirstLookupResolvesAndCaches(t *testing.T) {
	resolver := &fakeResolver{addrs: []string{"93.184.216.34"}}
	cache := newDNSCacheWithResolver(resolver.lookup)

	ips, err := cache.LookupOrResolve(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 || ips[0].String() != "93.184.216.34" {
		t.Errorf("unexpected IPs: %v", ips)
	}
	if resolver.calls != 1 {
		t.Errorf("expected 1 DNS call, got %d", resolver.calls)
	}
}

func TestDNSCacheSecondLookupReturnsCached(t *testing.T) {
	resolver := &fakeResolver{addrs: []string{"93.184.216.34"}}
	cache := newDNSCacheWithResolver(resolver.lookup)

	_, _ = cache.LookupOrResolve(context.Background(), "example.com")
	ips, err := cache.LookupOrResolve(context.Background(), "example.com")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(ips) != 1 {
		t.Errorf("unexpected IPs: %v", ips)
	}
	// Second lookup must not trigger another DNS query.
	if resolver.calls != 1 {
		t.Errorf("expected 1 DNS call total (cached), got %d", resolver.calls)
	}
}

func TestDNSCachePinsIPAcrossRebind(t *testing.T) {
	// Simulate a rebind: first resolve returns public IP, second returns private.
	callCount := 0
	rebindResolver := func(_ context.Context, _ string) ([]string, error) {
		callCount++
		if callCount == 1 {
			return []string{"93.184.216.34"}, nil // public
		}
		return []string{"192.168.1.1"}, nil // private (rebind attempt)
	}
	cache := newDNSCacheWithResolver(rebindResolver)

	ips1, _ := cache.LookupOrResolve(context.Background(), "target.com")
	ips2, _ := cache.LookupOrResolve(context.Background(), "target.com")

	if ips1[0].String() != "93.184.216.34" || ips2[0].String() != "93.184.216.34" {
		t.Errorf("DNS rebind was not prevented: first=%v second=%v", ips1, ips2)
	}
	if callCount != 1 {
		t.Errorf("expected 1 DNS call (cache should pin), got %d", callCount)
	}
}

// TestDNSCacheCaseVariantsShareEntry verifies that hostname case variations and
// trailing-dot forms all hit the same cache entry, preventing DNS rebinding via
// mixed-case hostnames.
func TestDNSCacheCaseVariantsShareEntry(t *testing.T) {
	resolver := &fakeResolver{addrs: []string{"93.184.216.34"}}
	cache := newDNSCacheWithResolver(resolver.lookup)

	variants := []string{"Example.COM", "EXAMPLE.COM", "example.com.", "Example.com."}
	for _, v := range variants {
		ips, err := cache.LookupOrResolve(context.Background(), v)
		if err != nil {
			t.Fatalf("variant %q: unexpected error: %v", v, err)
		}
		if len(ips) != 1 || ips[0].String() != "93.184.216.34" {
			t.Errorf("variant %q: unexpected IPs: %v", v, ips)
		}
	}
	// All variants must have resolved to the same cache entry — only 1 DNS call.
	if resolver.calls != 1 {
		t.Errorf("expected 1 DNS call for all case variants, got %d", resolver.calls)
	}
}

func TestDNSCacheDifferentHostsAreIndependent(t *testing.T) {
	resolver := &fakeResolver{addrs: []string{"1.2.3.4"}}
	cache := newDNSCacheWithResolver(resolver.lookup)

	_, _ = cache.LookupOrResolve(context.Background(), "foo.com")
	_, _ = cache.LookupOrResolve(context.Background(), "bar.com")

	if resolver.calls != 2 {
		t.Errorf("expected 2 DNS calls for 2 different hosts, got %d", resolver.calls)
	}
}

func TestDNSCacheIsConcurrentSafe(t *testing.T) {
	resolver := &fakeResolver{addrs: []string{"1.1.1.1"}}
	cache := newDNSCacheWithResolver(resolver.lookup)

	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = cache.LookupOrResolve(context.Background(), "concurrent.com")
		}()
	}
	wg.Wait()

	// All IPs should be "1.1.1.1".
	ips, err := cache.LookupOrResolve(context.Background(), "concurrent.com")
	if err != nil || len(ips) != 1 || ips[0].String() != "1.1.1.1" {
		t.Errorf("unexpected result after concurrent access: %v %v", ips, err)
	}
}

func TestIsBlockedIPDefaultBlocksPrivate(t *testing.T) {
	cases := []struct {
		ip      string
		blocked bool
	}{
		{"192.168.1.1", true},
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"169.254.0.1", true},
		{"100.64.0.1", true},     // CGNAT
		{"93.184.216.34", false}, // public
		{"8.8.8.8", false},
	}

	for _, tc := range cases {
		ip := net.ParseIP(tc.ip)
		if isBlockedIP(ip, false) != tc.blocked {
			t.Errorf("isBlockedIP(%s, allowPrivateRanges=false) = %v, want %v",
				tc.ip, !tc.blocked, tc.blocked)
		}
	}
}

func TestIsBlockedIPAllowPrivateRangesPermitsRFC1918(t *testing.T) {
	privateIPs := []string{"192.168.1.1", "10.0.0.1", "172.16.0.1", "127.0.0.1"}
	for _, rawIP := range privateIPs {
		ip := net.ParseIP(rawIP)
		if isBlockedIP(ip, true) {
			t.Errorf("isBlockedIP(%s, allowPrivateRanges=true) should be false", rawIP)
		}
	}
}

func TestIsBlockedIPAllowPrivateRangesStillBlocksMulticast(t *testing.T) {
	// Multicast should always be blocked regardless of allowPrivateRanges.
	ip := net.ParseIP("224.0.0.1")
	if !isBlockedIP(ip, true) {
		t.Error("multicast should be blocked even with allowPrivateRanges=true")
	}
}
