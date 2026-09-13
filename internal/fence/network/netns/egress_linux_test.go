//go:build linux

package netns

import (
	"net/netip"
	"strings"
	"testing"
)

func TestNewBridgeSpecUsesPrivatePointToPointAddresses(t *testing.T) {
	bridge, err := NewBridgeSpec()
	if err != nil {
		t.Fatalf("NewBridgeSpec() error: %v", err)
	}
	if err := validateEgressConfig(&EgressConfig{Bridge: bridge}, 1000); err != nil {
		t.Fatalf("generated bridge did not validate: %v", err)
	}
	host, _ := netip.ParseAddr(bridge.HostAddress)
	child, _ := netip.ParseAddr(bridge.ChildAddress)
	if !host.IsLinkLocalUnicast() || !child.IsLinkLocalUnicast() {
		t.Fatalf("bridge addresses must be link-local: host=%s child=%s", host, child)
	}
}

func TestEgressRulesetKeepsOnlyTransparentTCPAndProxyPeer(t *testing.T) {
	cfg := EgressConfig{Bridge: BridgeSpec{
		Namespace:      "nln1234abcd",
		HostInterface:  "nlh1234abcd",
		ChildInterface: "nlc1234abcd",
		HostAddress:    "169.254.24.1",
		ChildAddress:   "169.254.24.2",
	}}
	rules := EgressRuleset(cfg)
	for _, want := range []string{
		"tproxy to :15080", "tcp dport { 80, 443 }", "policy drop",
		"meta skuid 65534 ip daddr 169.254.24.1 tcp dport 15080 accept",
		"ip saddr 169.254.24.1 tcp dport 15081 accept",
	} {
		if !strings.Contains(rules, want) {
			t.Fatalf("ruleset missing %q:\n%s", want, rules)
		}
	}
	if strings.Contains(rules, "udp dport 443 accept") || strings.Contains(rules, "sctp accept") {
		t.Fatalf("ruleset widened a denied transport:\n%s", rules)
	}
}

func TestValidateEgressConfigRejectsProxyIdentityForChild(t *testing.T) {
	bridge, err := NewBridgeSpec()
	if err != nil {
		t.Fatalf("NewBridgeSpec() error: %v", err)
	}
	if err := validateEgressConfig(&EgressConfig{Bridge: bridge}, proxyUID); err == nil {
		t.Fatal("validateEgressConfig() accepted the policy proxy uid for the child")
	}
}
