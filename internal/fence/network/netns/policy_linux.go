//go:build linux

package netns

import "fmt"

const (
	// transparentProxyPort is the local port tproxy sends HTTP(S) connections to.
	transparentProxyPort  = 18080
	transparentMark       = 0x4e4c
	transparentRouteTable = 100
)

// ProxyConfig is the sidecar configuration carried in the helper request. The
// broker lives in the parent network namespace and independently enforces the
// same allowlist before it resolves or dials an upstream host.
type ProxyConfig struct {
	Allow              []string `json:"allow"`
	AllowAll           bool     `json:"allow_all"`
	AllowPrivateRanges bool     `json:"allow_private_ranges"`
	BrokerPath         string   `json:"broker_path"`
	BrokerToken        string   `json:"broker_token"`
}

// Valid reports whether cfg contains the minimum data needed to establish the
// authenticated sidecar-to-broker boundary. An absent broker is never an
// advisory fallback: the helper refuses to exec the child.
func (cfg ProxyConfig) Valid() bool {
	return cfg.BrokerPath != "" && cfg.BrokerToken != ""
}

// TransparentRuleset returns the Phase-1b nftables policy. Only marked TCP
// HTTP(S) and DNS packets can reach the sidecar; every other child-originated
// packet remains blocked by the default-drop output chain. The separate proxy
// uid may send local replies, but cannot use the child identity's packet path.
func TransparentRuleset(proxyUID int) string {
	return fmt.Sprintf(`table inet nocklock {
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    meta skuid %d return
    tcp dport { 80, 443 } meta mark set 0x%x tproxy to :%d accept
    tcp dport 53 meta mark set 0x%x tproxy to :53 accept
    udp dport 53 meta mark set 0x%x tproxy to :53 accept
  }
  chain output_mangle {
    type route hook output priority mangle; policy accept;
    meta skuid %d return
    tcp dport { 80, 443 } meta mark set 0x%x tproxy to :%d accept
    tcp dport 53 meta mark set 0x%x tproxy to :53 accept
    udp dport 53 meta mark set 0x%x tproxy to :53 accept
  }
  chain input {
    type filter hook input priority filter; policy drop;
    iifname "lo" accept
  }
  chain output {
    type filter hook output priority filter; policy drop;
    meta skuid %d accept
    meta mark 0x%x accept
  }
  chain forward { type filter hook forward priority filter; policy drop; }
}
`, proxyUID, transparentMark, transparentProxyPort, transparentMark, transparentMark,
		proxyUID, transparentMark, transparentProxyPort, transparentMark, transparentMark,
		proxyUID, transparentMark)
}
