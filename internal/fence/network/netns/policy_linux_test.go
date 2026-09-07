//go:build linux

package netns

import (
	"strings"
	"testing"
)

func TestTransparentRulesetContainsOnlyTproxyHTTPAndDNSAllowances(t *testing.T) {
	rules := TransparentRuleset(65534)
	for _, want := range []string{
		"tcp dport { 80, 443 } meta mark set",
		"tcp dport 53 meta mark set",
		"udp dport 53 meta mark set",
		"meta skuid 65534 accept",
		"policy drop",
	} {
		if !strings.Contains(rules, want) {
			t.Fatalf("transparent ruleset missing %q:\n%s", want, rules)
		}
	}
	if strings.Contains(rules, "redirect to") {
		t.Fatalf("transparent ruleset must use tproxy, never REDIRECT:\n%s", rules)
	}
}

func TestTransparentRulesetLoadsInFreshNetns(t *testing.T) {
	requireRoot(t)
	ipBin := requireTool(t, "ip")
	nftBin := requireTool(t, "nft")
	ns := setupNetnsBase(t, false)

	out, err := runStdin(TransparentRuleset(65534), ipBin, "netns", "exec", ns.name, nftBin, "-f", "-")
	if err != nil {
		if strings.Contains(strings.ToLower(out), "operation not supported") {
			if strictlyRequired() {
				t.Fatalf("tproxy unsupported in required environment: %v\n%s", err, out)
			}
			t.Skipf("tproxy unsupported in this environment: %v\n%s", err, out)
		}
		t.Fatalf("apply transparent tproxy ruleset: %v\n%s", err, out)
	}
	rules, err := run(ipBin, "netns", "exec", ns.name, nftBin, "list", "ruleset")
	if err != nil {
		t.Fatalf("list transparent ruleset: %v\n%s", err, rules)
	}
	if !strings.Contains(rules, "tproxy to :18080") || strings.Contains(rules, "redirect to") {
		t.Fatalf("loaded ruleset did not preserve required tproxy-only intercept:\n%s", rules)
	}
}
