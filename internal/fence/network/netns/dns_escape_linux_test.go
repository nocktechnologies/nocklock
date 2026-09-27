//go:build linux

package netns

// Root-gated acceptance test for the three July-2026 DNS-based egress-escape
// tricks described in the Hugging Face sandbox-escape writeup, run against the
// netns tproxy egress floor. It reuses the protocol-matrix harness (bridge,
// host TLS upstream, deny log, child credential, re-exec'd in-namespace client)
// so every trick exercises the real packet path, not an in-process
// approximation.
//
// The three tricks, and what NockLock does against each on Linux:
//
//   T1  In-process resolver: the agent resolves an allowlisted name to an
//       attacker-chosen IP (getaddrinfo override) and connects there, or it
//       connects to a raw disallowed IP, or it fires its own UDP/TCP DNS query
//       at an off-namespace resolver.
//   T2  resolv.conf rewrite: the agent points the resolver it sees at 8.8.8.8.
//   T3  /etc/hosts pin: the agent maps the allowlisted name to a disallowed IP
//       in the hosts file it sees.
//
// Mira's code read (this test is its receipt): the tproxy floor redirects every
// TCP:80/443 connection — to ANY destination IP — to the in-namespace
// transparent proxy, which reads the SNI/Host and hands that HOSTNAME to the
// host-side proxy, which resolves it ITSELF outside the child's reach. So the
// tricks only change what the CHILD thinks an address is, never where the proxy
// connects: the centerpiece (T1a) dials a DISALLOWED IP while presenting the
// ALLOWED SNI and must still land on the real allowed upstream (a 200 the child
// reads back — a race-free, synchronous receipt). External resolvers are
// unreachable (default-drop), and the child cannot write the root-owned
// resolv.conf/hosts it sees, so T2/T3 record a write-denied outcome; connecting
// by the allowed NAME afterwards still lands on the allowed upstream.
//
// SAFETY: netns + nft + cap-drop enforcement. CI-only, as root. Never on the
// resident host.

import (
	"fmt"
	"net"
	"os"
	"testing"
)

// dnsEscapeDisallowedIP is the attacker-chosen destination the child is coaxed
// into targeting for the allowlisted name (the getaddrinfo-override vector). It
// is a distinct loopback address from the allowed upstream (127.0.0.1). Nothing
// listens there: the tproxy floor intercepts the connection by port before it
// reaches any address, so a 200 from the allowed upstream proves the proxy
// re-resolved the SNI rather than honoring the dialed IP.
const dnsEscapeDisallowedIP = "127.0.0.2"

// dnsEscapeClientEnv gates the re-exec'd in-namespace client in TestMain.
const dnsEscapeClientEnv = "NOCKLOCK_DNS_ESCAPE_CLIENT"

func TestNetnsDNSEscape(t *testing.T) {
	requireRoot(t)
	requireTool(t, "ip")
	requireTool(t, "nft")

	bridge, err := NewBridgeSpec()
	if err != nil {
		t.Fatalf("NewBridgeSpec() error: %v", err)
	}

	// The allowlisted upstream on 127.0.0.1:443 — where "localhost" really
	// resolves. Its hit counter is the positive proof that egress landed on the
	// allowed host, incremented synchronously before the 200 the child reads.
	httpsHits := startProtocolTLSServer(t)

	denyLog := protocolDenyLog(t)
	t.Setenv("NOCKLOCK_TRANSPARENT_DENY_LOG", denyLog)

	uid, gid, groups := protocolChildCredential(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	req := Request{
		Argv: []string{exe, "-test.run=^$"},
		Env: append(os.Environ(),
			dnsEscapeClientEnv+"=1",
			"NOCKLOCK_DNS_ESCAPE_EXTERNAL="+bridge.HostAddress,
		),
		UID:    uid,
		GID:    gid,
		Groups: groups,
		Egress: &EgressConfig{
			Allow:              []string{"localhost"},
			AllowPrivateRanges: true,
			Bridge:             bridge,
		},
	}

	// A non-zero child exit means one trick was NOT defeated; the wrapped error
	// carries the distinct exit code (see runDNSEscapeClient) so the failing
	// trick is identifiable from the log. The centerpiece assertion is inside the
	// child and race-free: each allowed request must read back the allowed
	// upstream's 200, which only happens when the proxy re-resolves the SNI.
	if err := SetupEgressAndSupervise(req); err != nil {
		t.Fatalf("DNS-escape client reported a defeated trick (or setup failed): %v", err)
	}

	// The allowlisted destination actually served the (SNI-spoofed and by-name)
	// requests — proof they re-resolved to the real allowed host rather than the
	// dialed attacker IP.
	if got := httpsHits.Load(); got == 0 {
		t.Error("allowed HTTPS upstream never reached: the SNI-spoofed request did not re-resolve to the real allowed host")
	}
	// The proxy recorded at least one deny receipt (the raw-IP / no-SNI trick is
	// denied with a "tls" record and an empty host).
	if !curlDenyLogContains(denyLog, "", "tls") {
		contents, readErr := os.ReadFile(denyLog)
		t.Errorf("no transparent-proxy tls deny receipt in %s; expected the raw-IP no-SNI attempt to be recorded. deny-log contents=%q readErr=%v", denyLog, contents, readErr)
	}
}

// runDNSEscapeClient runs inside the netns as the dropped child credential,
// after the transparent proxy and DNS stub are live. It attempts each trick and
// returns a distinct exit code for the first one that is NOT defeated, or 0 when
// all three are defeated and the allowlisted path still works.
func runDNSEscapeClient() int {
	allowedUpstream := net.JoinHostPort("127.0.0.1", "443")
	allowedByName := net.JoinHostPort("localhost", "443")

	// Baseline: the allowlisted path works before any trick — otherwise a later
	// "still works" assertion proves nothing.
	if !protocolHTTPSRequest(allowedUpstream, "localhost") {
		return 55 // baseline allowed HTTPS failed; environment is broken, not fenced
	}

	// T1(a) getaddrinfo override: dial the attacker IP on 443 while presenting the
	// SNI of the ALLOWED name. The tproxy intercepts by port and the proxy
	// re-resolves the SNI, so the request must land on the REAL allowed upstream
	// and read back its 200 — the dialed attacker IP is never honored.
	if !protocolHTTPSRequest(net.JoinHostPort(dnsEscapeDisallowedIP, "443"), "localhost") {
		return 50 // SNI-spoofed request to a disallowed IP did not re-resolve to the allowed upstream
	}
	// T1(b) raw disallowed IP with no SNI: the proxy has no allowlisted name to
	// honor and must terminate it.
	if !protocolDirectIPRejected() {
		return 51 // raw-IP no-SNI TLS was not terminated by the proxy
	}
	// T1(c) own resolver query: direct UDP+TCP/53 to an off-namespace resolver
	// must get no answer (default-drop), so patching the in-process resolver to
	// 8.8.8.8 buys nothing.
	external := os.Getenv("NOCKLOCK_DNS_ESCAPE_EXTERNAL")
	if external == "" || !protocolExternalDNSDenied(external) {
		return 52 // a direct query to an external resolver was answered
	}

	// T2 resolv.conf rewrite: attempt to point the resolver the child sees at
	// 8.8.8.8, RECORD the write outcome, then connect BY THE ALLOWED NAME (which
	// exercises the resolver path) and require it still lands on the allowed
	// upstream. A successful write must not be scored as a pass on its own.
	recordWriteAttempt("T2 resolv.conf", "/etc/resolv.conf", []byte("nameserver "+dnsEscapeDisallowedIP+"\nnameserver 8.8.8.8\n"))
	if !protocolHTTPSRequest(allowedByName, "localhost") {
		return 53 // allowed path broke after the resolv.conf rewrite attempt
	}

	// T3 /etc/hosts pin: attempt to map the allowed name to the attacker IP,
	// RECORD the outcome, then again connect BY THE ALLOWED NAME and require it
	// still lands on the allowed upstream regardless of the write's success.
	recordWriteAttempt("T3 /etc/hosts", "/etc/hosts", []byte(dnsEscapeDisallowedIP+" localhost\n"))
	if !protocolHTTPSRequest(allowedByName, "localhost") {
		return 54 // allowed path broke after the /etc/hosts pin attempt
	}
	return 0
}

// recordWriteAttempt attempts to write payload to path and prints a legible
// per-trick outcome (write_denied(errno) / write_succeeded) to stderr, which the
// -test.v child log captures. It never fails the run itself: a successful write
// is not egress, and the caller re-asserts the allowed path independently.
func recordWriteAttempt(label, path string, payload []byte) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "NockLock DNS-escape %s: write_denied (%v)\n", label, err)
		return
	}
	_, writeErr := f.Write(payload)
	_ = f.Close()
	if writeErr != nil {
		fmt.Fprintf(os.Stderr, "NockLock DNS-escape %s: write_denied (%v)\n", label, writeErr)
		return
	}
	fmt.Fprintf(os.Stderr, "NockLock DNS-escape %s: write_succeeded (fence must still deny egress)\n", label)
}
