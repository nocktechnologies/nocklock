package netns

import (
	"fmt"
	"net/netip"
	"testing"
)

func TestBridgeCandidateAddressBoundaries(t *testing.T) {
	for _, tc := range []struct {
		id          uint32
		host, child string
	}{
		{0, "169.254.0.1", "169.254.0.2"},
		{10815, "169.254.168.253", "169.254.168.254"},
		{10816, "169.254.171.1", "169.254.171.2"},
		{10879, "169.254.171.253", "169.254.171.254"},
		{16255, "169.254.255.253", "169.254.255.254"},
		{16256, "169.254.0.1", "169.254.0.2"},
		{16383, "169.254.1.253", "169.254.1.254"},
	} {
		t.Run(fmt.Sprint(tc.id), func(t *testing.T) {
			got := bridgeCandidateForID(tc.id)
			if got.HostAddress != tc.host || got.ChildAddress != tc.child || got.ReservationID != tc.host {
				t.Fatalf("id %d: candidate %+v, want host %s child %s", tc.id, got, tc.host, tc.child)
			}
		})
	}
}

func TestBridgeCandidateExcludesMetadataForEverySlot(t *testing.T) {
	reserved := []netip.Prefix{
		netip.MustParsePrefix("169.254.169.0/24"),
		netip.MustParsePrefix("169.254.170.0/24"),
	}
	seen := make(map[netip.Addr]bool)
	check := func(id uint32) {
		t.Helper()
		got := bridgeCandidateForID(id)
		if got != bridgeCandidateForID(id) {
			t.Fatalf("id %d: mapping is not deterministic", id)
		}
		host := netip.MustParseAddr(got.HostAddress)
		child := netip.MustParseAddr(got.ChildAddress)
		if !host.Is4() || !host.IsLinkLocalUnicast() || !child.IsLinkLocalUnicast() || host.Next() != child || host.As4()[3]%4 != 1 {
			t.Fatalf("id %d: invalid /30 endpoints %s, %s", id, host, child)
		}
		for _, block := range reserved {
			if block.Contains(host) || block.Contains(child) {
				t.Fatalf("id %d: metadata subnet allocated: %s, %s", id, host, child)
			}
		}
		name := fmt.Sprintf("%08x", id)
		if got.Namespace != "nln"+name || got.HostInterface != "nlh"+name || got.ChildInterface != "nlc"+name || got.ReservationID != got.HostAddress || got.ReservationToken != "" {
			t.Fatalf("id %d: inconsistent candidate identity: %+v", id, got)
		}
		seen[host] = true
	}
	for id := uint32(0); id < 16384; id++ {
		check(id)
	}
	if len(seen) != 16256 {
		t.Fatalf("covered %d subnets, want all 16256 nonreserved /30s", len(seen))
	}
	for _, id := range []uint32{1 << 16, 1 << 31, ^uint32(0)} {
		check(id)
	}
}
