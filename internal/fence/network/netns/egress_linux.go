//go:build linux

package netns

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

const (
	// TransparentProxyPort is the in-namespace TCP listener selected by the
	// tproxy rules. It is not exposed on a host interface.
	TransparentProxyPort = 15080
	// ProxyHealthPort is reachable only over the private veth so the helper can
	// terminate the fenced child if either policy proxy dies.
	ProxyHealthPort = 15081
	proxyUID        = 65534 // the standard, dedicated nobody account
)

// BridgeSpec identifies one private point-to-point veth bridge. The bridge is
// intentionally link-local and the child receives no default route: its only
// non-loopback peer is the host-side allowlist proxy.
type BridgeSpec struct {
	Namespace      string `json:"namespace"`
	HostInterface  string `json:"host_interface"`
	ChildInterface string `json:"child_interface"`
	HostAddress    string `json:"host_address"`
	ChildAddress   string `json:"child_address"`
}

// EgressConfig is the fixed Phase-1b setup supplied to the privileged helper.
// The host-side proxy re-applies Allow before it resolves and dials an upstream;
// the transparent proxy applies the same rules before it can reach that peer.
type EgressConfig struct {
	Allow              []string   `json:"allow"`
	AllowPrivateRanges bool       `json:"allow_private_ranges"`
	Bridge             BridgeSpec `json:"bridge"`
}

// NewBridgeSpec reserves a random link-local /30 identity for one netns run.
// Interface names are derived from the same random token and stay under Linux's
// 15-character interface-name limit.
func NewBridgeSpec() (BridgeSpec, error) {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return BridgeSpec{}, fmt.Errorf("generate private netns bridge id: %w", err)
	}
	id := binary.BigEndian.Uint32(raw[:])
	slot := id & 0x3fff // 16,384 non-overlapping /30s in 169.254.0.0/16.
	octet3 := slot >> 6
	octet4 := (slot & 0x3f) << 2
	nameID := fmt.Sprintf("%08x", id)
	return BridgeSpec{
		Namespace:      "nln" + nameID,
		HostInterface:  "nlh" + nameID,
		ChildInterface: "nlc" + nameID,
		HostAddress:    fmt.Sprintf("169.254.%d.%d", octet3, octet4+1),
		ChildAddress:   fmt.Sprintf("169.254.%d.%d", octet3, octet4+2),
	}, nil
}

func (b BridgeSpec) hostCIDR() string  { return b.HostAddress + "/30" }
func (b BridgeSpec) childCIDR() string { return b.ChildAddress + "/30" }
func (b BridgeSpec) hostProxyAddr() string {
	return b.HostAddress + ":" + strconv.Itoa(TransparentProxyPort)
}
func (b BridgeSpec) childHealthAddr() string {
	return b.ChildAddress + ":" + strconv.Itoa(ProxyHealthPort)
}

func validateEgressConfig(cfg *EgressConfig, childUID int) error {
	if cfg == nil {
		return fmt.Errorf("netns egress setup is missing transparent proxy configuration")
	}
	if childUID == proxyUID {
		return fmt.Errorf("netns egress fence cannot use uid %d because it is reserved for the policy proxy", proxyUID)
	}
	b := cfg.Bridge
	for _, pair := range []struct {
		value  string
		prefix string
	}{
		{b.Namespace, "nln"},
		{b.HostInterface, "nlh"},
		{b.ChildInterface, "nlc"},
	} {
		if len(pair.value) != 11 || !strings.HasPrefix(pair.value, pair.prefix) {
			return fmt.Errorf("invalid private bridge %s name %q", pair.prefix, pair.value)
		}
		for _, r := range pair.value[3:] {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
				return fmt.Errorf("invalid private bridge name %q", pair.value)
			}
		}
	}
	host, err := netip.ParseAddr(b.HostAddress)
	if err != nil || !host.Is4() || !host.IsLinkLocalUnicast() {
		return fmt.Errorf("invalid private bridge host address %q", b.HostAddress)
	}
	child, err := netip.ParseAddr(b.ChildAddress)
	if err != nil || !child.Is4() || !child.IsLinkLocalUnicast() {
		return fmt.Errorf("invalid private bridge child address %q", b.ChildAddress)
	}
	hostBytes := host.As4()
	childBytes := child.As4()
	if hostBytes[0] != childBytes[0] || hostBytes[1] != childBytes[1] || hostBytes[2] != childBytes[2] ||
		hostBytes[3]&^byte(3) != childBytes[3]&^byte(3) || hostBytes[3]&3 != 1 || childBytes[3]&3 != 2 {
		return fmt.Errorf("private bridge addresses %s and %s are not a host/child /30 pair", host, child)
	}
	return nil
}

// EgressRuleset returns the complete Phase-1b nftables policy. The only child
// egress path is transparent TCP interception on ports 80/443; the policy
// proxy's dedicated uid can reach only the host-side allowlist proxy.
func EgressRuleset(cfg EgressConfig) string {
	b := cfg.Bridge
	return fmt.Sprintf(`table inet nocklock {
  chain output_route {
    type route hook output priority mangle; policy accept;
    meta skuid %d ip daddr %s tcp dport %d accept
    meta skuid 0 ip daddr %s tcp dport %d accept
    tcp dport { 80, 443 } tproxy to :%d meta mark set 0x1 accept
  }
  chain input {
    type filter hook input priority filter; policy drop;
    iifname "lo" accept
    ip saddr %s tcp dport %d accept
    ct state established,related accept
  }
  chain output {
    type filter hook output priority filter; policy drop;
    ct state established,related accept
    oifname "lo" accept
    meta skuid %d ip daddr %s tcp dport %d accept
    meta skuid 0 ip daddr %s tcp dport %d accept
  }
  chain forward { type filter hook forward priority filter; policy drop; }
}
`, proxyUID, b.HostAddress, TransparentProxyPort, b.HostAddress, TransparentProxyPort,
		TransparentProxyPort, b.HostAddress, ProxyHealthPort, proxyUID, b.HostAddress,
		TransparentProxyPort, b.HostAddress, TransparentProxyPort)
}
