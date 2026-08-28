//go:build linux

package netns

// Phase-1 FOUNDATION acceptance test (root-gated) — Nock #9916.
//
// The Q6 test (netns_bypass_linux_test.go) proves a capped child cannot REWRITE
// the fence. This test proves the other half of the foundation: that with the
// DefaultDropRuleset base installed, a capped child cannot EGRESS — the
// kernel-enforced hardened (no-network) floor actually denies traffic.
//
// It deliberately reuses the receipted Q6 machinery rather than reinventing it:
//   - setup (privileged parent): setupNetns creates a namespace, brings loopback
//     up, and installs the SINGLE shared DefaultDropRuleset base.
//   - child: the SAME re-exec'd child as Q6 (one TestMain owns the dispatch) —
//     setns into the namespace WHILE privileged, then drop CAP_NET_ADMIN +
//     CAP_SYS_ADMIN from all five sets — but instead of a fence mutation it
//     attempts real egress (runEgressChildIfRequested, dispatched from runChild).
//
// PROVING CAUSALITY (not just a green result). A fresh netns has no route, so an
// "external connect failed" assertion alone would pass against an EMPTY ruleset
// (ENETUNREACH) and prove nothing about the fence. This test therefore anchors on
// a LOOPBACK probe — a connect to 127.0.0.1, which cannot fail for routing
// reasons once `lo` is up — and pairs it with a POSITIVE CONTROL
// (TestNetnsFoundation_LoopbackReachableWithoutDrop_Control) that runs the exact
// same child against the exact same namespace WITHOUT the base and shows the
// loopback connect IS delivered. The only variable between the two is the
// default-drop ruleset, so a loopback denial is attributable to the drop, not to
// a down interface or a missing route — the negative control Q6 has via
// TestQ6_PrivilegedParentCanMutate_Control. The external TCP + UDP/53 probes are
// retained as the DONE-SPEC's literal "external TCP connect fails; UDP/53 fails"
// checks on top of the loopback causal proof.
//
// It self-skips when not root / when ip|nft are missing, and a privileged CI job
// sets NOCKLOCK_NETNS_REQUIRE=1 (mirroring NOCKLOCK_Q6_REQUIRE) so those skips
// become HARD failures — a misconfigured runner cannot report green by skipping.

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"
	"time"
)

// Egress scenario names — the single egress attempt a re-exec'd child makes after
// setns + the five-set cap drop. These extend the Q6 scenario space; runChild
// routes them to runEgressChildIfRequested.
const (
	scenarioLoopbackTCP  = "loopback_tcp"   // connect() to 127.0.0.1 (routing-independent)
	scenarioTCPEgress    = "tcp_egress"     // connect() to an external TCP host
	scenarioUDPDNSEgress = "udp_dns_egress" // DNS query to an external resolver over UDP/53
)

// Exit codes the egress child returns (disjoint from the Q6 codes so a decode is
// unambiguous). exitSetupFailed (from the Q6 file) is reused for setns/cap-drop
// failures, which happen before the egress branch.
const (
	exitEgressDenied  = 30 // egress did NOT reach its target (the required result under the drop)
	exitEgressReached = 31 // egress reached its target (a completed connect / delivered packet)
)

// egressProbeTimeout bounds every egress attempt. Under `policy drop` a SYN is
// silently discarded (connect hangs, no RST), so the assertions are
// timeout-shaped: denial is "did not reach within this bound," not a specific
// errno.
const egressProbeTimeout = 3 * time.Second

// egressTarget is a routable public IP literal (Cloudflare). Using a literal IP
// avoids any DNS lookup — itself denied by the fence — so the probe measures raw
// egress, not name resolution.
const egressTarget = "1.1.1.1"

// loopbackProbeAddr is a loopback port with nothing listening in a fresh netns.
// Reaching it yields ECONNREFUSED (an RST — the packet was delivered over `lo`);
// NOT reaching it (SYN dropped) yields a timeout. That difference is what makes
// loopback a routing-independent test of the drop policy.
const loopbackProbeAddr = "127.0.0.1:65000"

// runEgressChildIfRequested handles the FOUNDATION egress scenarios inside the
// re-exec'd child (called from runChild after setns + cap-drop). It returns
// handled=false for the Q6 mutation scenarios so they take their normal path.
func runEgressChildIfRequested(scenario string) (code int, handled bool) {
	switch scenario {
	case scenarioLoopbackTCP:
		return loopbackTCPResult(), true
	case scenarioTCPEgress:
		return tcpEgressResult(), true
	case scenarioUDPDNSEgress:
		return udpDNSEgressResult(), true
	default:
		return 0, false
	}
}

// loopbackTCPResult connects to a closed loopback port. A completed connect or an
// ECONNREFUSED both mean the packet was DELIVERED over `lo` (egress reached);
// anything else (a timeout under the drop, or ENETUNREACH if `lo` were down)
// means it did not.
func loopbackTCPResult() int {
	conn, err := net.DialTimeout("tcp", loopbackProbeAddr, egressProbeTimeout)
	if err == nil {
		_ = conn.Close()
		return exitEgressReached
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		return exitEgressReached
	}
	return exitEgressDenied
}

// tcpEgressResult attempts a bounded TCP connect to an external host. A completed
// connection means egress reached; any failure to complete is denial.
func tcpEgressResult() int {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(egressTarget, "443"), egressProbeTimeout)
	if err != nil {
		return exitEgressDenied
	}
	_ = conn.Close()
	fmt.Fprintln(os.Stderr, "child: TCP egress COMPLETED — default-drop floor failed")
	return exitEgressReached
}

// udpDNSEgressResult sends a well-formed DNS query to an external resolver over
// UDP/53 and waits for a reply. A received answer proves the packet left the
// namespace and a resolver replied — egress reached. No reply within the bound
// (or a failed send/connect) is denial. This matters because net.Dial("udp", …)
// "succeeds" without sending anything, so the assertion must be about a reply.
func udpDNSEgressResult() int {
	conn, err := net.DialTimeout("udp", net.JoinHostPort(egressTarget, "53"), egressProbeTimeout)
	if err != nil {
		return exitEgressDenied
	}
	defer conn.Close()
	if _, err := conn.Write(dnsQueryExampleCom()); err != nil {
		return exitEgressDenied
	}
	_ = conn.SetReadDeadline(time.Now().Add(egressProbeTimeout))
	buf := make([]byte, 512)
	if n, err := conn.Read(buf); err == nil && n > 0 {
		fmt.Fprintln(os.Stderr, "child: DNS answer received — default-drop floor failed")
		return exitEgressReached
	}
	return exitEgressDenied
}

// dnsQueryExampleCom builds a minimal well-formed DNS query (A? example.com) so a
// live external resolver would actually answer — making a received reply
// unambiguous proof that egress succeeded.
func dnsQueryExampleCom() []byte {
	msg := []byte{
		0x12, 0x34, // transaction id
		0x01, 0x00, // flags: recursion desired
		0x00, 0x01, // qdcount = 1
		0x00, 0x00, // ancount
		0x00, 0x00, // nscount
		0x00, 0x00, // arcount
	}
	for _, label := range []string{"example", "com"} {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0x00)       // root label terminates the name
	msg = append(msg, 0x00, 0x01) // qtype = A
	msg = append(msg, 0x00, 0x01) // qclass = IN
	return msg
}

// TestNetnsFoundation_DefaultDropDeniesEgress is the Phase-1 foundation bar: with
// the default-drop base installed, a capped child in the namespace is denied ALL
// egress — loopback (causal), external TCP, and a UDP/53 DNS query.
func TestNetnsFoundation_DefaultDropDeniesEgress(t *testing.T) {
	requireRoot(t)
	ipBin := requireTool(t, "ip")
	nftBin := requireTool(t, "nft")
	ns := setupNetns(t)

	// Receipt that the base is genuinely installed (guards against a silent
	// no-base drift): the inet table's three base chains must each carry
	// `policy drop`. This proves installation; the loopback control below proves
	// causation.
	rules, err := run(ipBin, "netns", "exec", ns.name, nftBin, "list", "ruleset")
	if err != nil {
		t.Fatalf("list ruleset in namespace %q: %v\n%s", ns.name, err, rules)
	}
	if got := strings.Count(rules, "policy drop"); got != 3 {
		t.Fatalf("default-drop base not installed as expected: want 3 'policy drop' chains, got %d\nruleset:\n%s", got, rules)
	}

	for _, tc := range []struct {
		name     string
		scenario string
	}{
		{"loopback_connect_causal", scenarioLoopbackTCP},
		{"tcp_external_connect", scenarioTCPEgress},
		{"udp_dns_query", scenarioUDPDNSEgress},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code := runChildHelper(t, tc.scenario, ns.path)
			switch code {
			case exitEgressDenied:
				// Required outcome: the default-drop floor held.
			case exitEgressReached:
				t.Fatalf("%s: capped child REACHED its target — the default-drop floor FAILED", tc.name)
			case exitSetupFailed:
				t.Fatalf("%s: child setup (setns / cap-drop) failed — result inconclusive", tc.name)
			default:
				t.Fatalf("%s: child exited %d, want egress denied (%d)", tc.name, code, exitEgressDenied)
			}
		})
	}
}

// TestNetnsFoundation_LoopbackReachableWithoutDrop_Control is the POSITIVE
// CONTROL for the causal loopback probe: the SAME capped child, in the SAME kind
// of namespace with loopback up but WITHOUT the default-drop base, DOES reach the
// loopback target. Paired with the loopback denial above (identical except the
// ruleset), it proves the denial is caused by the drop policy — not by a down
// interface or a missing route.
func TestNetnsFoundation_LoopbackReachableWithoutDrop_Control(t *testing.T) {
	requireRoot(t)
	requireTool(t, "ip")
	requireTool(t, "nft")
	ns := setupNetnsBase(t, false) // loopback up, NO default-drop base

	code := runChildHelper(t, scenarioLoopbackTCP, ns.path)
	switch code {
	case exitEgressReached:
		// Required outcome: loopback IS reachable without the drop, so the denial
		// in the main test is caused by the ruleset.
	case exitEgressDenied:
		t.Fatalf("control: loopback was NOT reachable even without the default-drop base — the main test's denial cannot be attributed to the drop policy (broken setup: is loopback up?)")
	case exitSetupFailed:
		t.Fatalf("control: child setup (setns / cap-drop) failed — result inconclusive")
	default:
		t.Fatalf("control: child exited %d, want egress reached (%d)", code, exitEgressReached)
	}
}
