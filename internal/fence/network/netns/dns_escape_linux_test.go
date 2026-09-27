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
// resolv.conf/hosts it sees, so T2/T3 REQUIRE a write-denied outcome (a
// successful write fails the run); connecting by the allowed NAME afterwards
// still lands on the allowed upstream.
//
// SAFETY: netns + nft + cap-drop enforcement. CI-only, as root. Never on the
// resident host.

import (
	"errors"
	"fmt"
	"net"
	"os"
	"syscall"
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
	disallowedUpstream := net.JoinHostPort(dnsEscapeDisallowedIP, "443")

	// Baseline: the allowlisted path works before any trick — otherwise a later
	// "still works" assertion proves nothing.
	if !protocolHTTPSRequest(allowedUpstream, "localhost") {
		return 55 // baseline allowed HTTPS failed; environment is broken, not fenced
	}

	// T1(a) getaddrinfo override: dial the attacker IP on 443 while presenting the
	// SNI of the ALLOWED name. The tproxy intercepts by port and the proxy
	// re-resolves the SNI, so the request must land on the REAL allowed upstream
	// and read back its 200 — the dialed attacker IP is never honored.
	if !protocolHTTPSRequest(disallowedUpstream, "localhost") {
		fmt.Fprintln(os.Stderr, "NockLock DNS-escape T1a: FAILED — did not read back the allowed upstream's 200")
		return 50
	}
	fmt.Fprintln(os.Stderr, "NockLock DNS-escape T1a: redirected to allowed upstream, 200 read")

	// T1(b) raw disallowed IP with no SNI: dial the declared disallowed IP
	// (rather than the allowed loopback) so the trick actually targets the
	// disallowed destination. The proxy has no allowlisted name to honor and
	// must terminate it.
	if !protocolDirectIPRejected(disallowedUpstream) {
		fmt.Fprintln(os.Stderr, "NockLock DNS-escape T1b: FAILED — raw-IP no-SNI TLS was not terminated by the proxy")
		return 51
	}
	fmt.Fprintln(os.Stderr, "NockLock DNS-escape T1b: terminated by proxy, deny receipt")

	// T1(c) own resolver query: direct UDP+TCP/53 to an off-namespace resolver
	// must get no answer (default-drop), so patching the in-process resolver to
	// 8.8.8.8 buys nothing.
	external := os.Getenv("NOCKLOCK_DNS_ESCAPE_EXTERNAL")
	if external == "" {
		fmt.Fprintln(os.Stderr, "NockLock DNS-escape T1c: FAILED — no external resolver address configured")
		return 58 // environment misconfigured, not a fenced/unfenced verdict
	}
	if !protocolExternalDNSDenied(external) {
		fmt.Fprintf(os.Stderr, "NockLock DNS-escape T1c: FAILED — external resolver %s answered\n", external)
		return 52 // a direct query to an external resolver was answered
	}
	fmt.Fprintf(os.Stderr, "NockLock DNS-escape T1c: no answer from %s\n", external)

	// T2 resolv.conf rewrite: attempt to point the resolver the child sees at
	// 8.8.8.8. The write itself must fail closed (permission or read-only error);
	// a write that succeeds is scored as a defeated trick, not logged and waved
	// through. Only after the write is confirmed denied does the test connect BY
	// THE ALLOWED NAME (exercising the resolver path) and require it still lands
	// on the allowed upstream.
	if !writeDeniedClosed("T2 resolv.conf", "/etc/resolv.conf", []byte("nameserver "+dnsEscapeDisallowedIP+"\nnameserver 8.8.8.8\n")) {
		return 56 // resolv.conf write was not denied by a permission/read-only error
	}
	if !protocolHTTPSRequest(allowedByName, "localhost") {
		return 53 // allowed path broke after the resolv.conf rewrite attempt
	}

	// T3 /etc/hosts pin: attempt to map the allowed name to the attacker IP. Same
	// fail-closed requirement as T2, then re-assert the allowed name still lands
	// on the allowed upstream.
	if !writeDeniedClosed("T3 /etc/hosts", "/etc/hosts", []byte(dnsEscapeDisallowedIP+" localhost\n")) {
		return 57 // /etc/hosts write was not denied by a permission/read-only error
	}
	if !protocolHTTPSRequest(allowedByName, "localhost") {
		return 54 // allowed path broke after the /etc/hosts pin attempt
	}
	return 0
}

// writeDeniedClosed attempts to write payload to path and prints a legible
// per-trick outcome to stderr — write_denied(errno), write_succeeded, or (for
// any other OpenFile/Write error) a call-out that it wasn't a permission/
// read-only error — which the -test.v child log captures. It reports true
// only when the write was rejected with a permission or read-only error
// (EACCES, EPERM, or EROFS) — the fenced outcome the caller requires. Any
// other outcome, including a successful write, is reported false so the
// caller scores the trick as NOT defeated instead of silently logging it and
// moving on.
func writeDeniedClosed(label, path string, payload []byte) bool {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err == nil {
		_, err = f.Write(payload)
		_ = f.Close()
		if err == nil {
			fmt.Fprintf(os.Stderr, "NockLock DNS-escape %s: write_succeeded (fence must still deny egress)\n", label)
			return false
		}
	}
	if !errors.Is(err, os.ErrPermission) && !errors.Is(err, syscall.EROFS) {
		fmt.Fprintf(os.Stderr, "NockLock DNS-escape %s: write failed for an unexpected reason, not a permission/read-only error (%v)\n", label, err)
		return false
	}
	fmt.Fprintf(os.Stderr, "NockLock DNS-escape %s: write_denied (%v)\n", label, err)
	return true
}
