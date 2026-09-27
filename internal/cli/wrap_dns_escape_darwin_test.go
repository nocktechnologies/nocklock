//go:build darwin

package cli

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/spf13/cobra"

	_ "modernc.org/sqlite"
)

// wrap_dns_escape_darwin_test.go RECORDS what NockLock's macOS egress fence does
// against the three July-2026 DNS-escape tricks. macOS has NO kernel egress floor
// (the Seatbelt profile in sbpl.go carries zero network rules, and the netns
// enforcement spec is explicitly Linux-only): the fence is the local HTTP(S)
// proxy plus HTTP_PROXY injection, which a COOPERATING client honors.
//
// So this test asserts only what is true on macOS and records the rest:
//
//   ASSERTED  A proxied request to a DISALLOWED host is denied at the proxy and
//             signed as a deny row; a proxied request to the ALLOWED host is
//             permitted and signed as an allow row; `verify --audit` finds the
//             chain intact and every signature valid.
//   RECORDED  Direct-IP egress and /etc/hosts pinning are NOT kernel-blocked on
//             macOS — a client that ignores HTTP_PROXY reaches any address, and
//             only root can write the shared /etc/hosts. These are logged as the
//             honest platform limitation, not asserted as blocks (asserting a
//             block macOS does not provide would only invite a fail-open repair).
//
// The proxy resolves the allowlisted hostname ITSELF (network/dnscache.go), so
// the getaddrinfo-override trick cannot steer a PROXIED request off the allowed
// host — but a non-cooperating client is out of the proxy's reach entirely,
// which is the whole reason the Linux netns floor exists.
//
// SAFETY: proxy + Seatbelt only; no root, no kernel mutation. macOS CI job.

const (
	dnsEscapeAllowedHost = "nocklock-allowed.test"
	dnsEscapeDeniedHost  = "nocklock-blocked.test"
)

func dnsEscapeStrictlyRequired() bool { return os.Getenv("NOCKLOCK_DNS_ESCAPE_REQUIRE") == "1" }

// TestWrapMacOSDNSEscapeRecordsProxyEnforcement drives one wrapped session that
// makes a proxied request to an allowed host and a proxied request to a denied
// host, then asserts both decisions were signed and the audit chain verifies.
func TestWrapMacOSDNSEscapeRecordsProxyEnforcement(t *testing.T) {
	requireSandboxExec(t)
	requireProvisionedAllowedHost(t)

	// The allowed upstream the proxy re-resolves the allowlisted name to. Its hit
	// counter proves the allowed destination still works end to end via the proxy.
	allowedHits, allowedAddr := startDNSEscapeUpstream(t)

	project := t.TempDir()
	nockDir := filepath.Join(project, config.Dir)
	if err := os.MkdirAll(nockDir, 0o755); err != nil {
		t.Fatalf("create .nock dir: %v", err)
	}
	// Filesystem fence ON (root-write confinement) so Seatbelt engages exactly as
	// in production; network allowlist of the one allowed host, private ranges on
	// so the proxy may dial the 127.0.0.1 test upstream.
	policy := fmt.Sprintf(`[project]
name = "n10813-dns-escape-darwin"

[filesystem]
root = "/"
mode = "read-write"
allow = []
deny = []

[network]
allow = ["%s"]
allow_all = false
allow_private_ranges = true

[syscall]
enforcement = "off"
`, dnsEscapeAllowedHost)
	writeTestConfig(t, project, policy)
	withWorkingDir(t, project)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	_, port, err := net.SplitHostPort(allowedAddr)
	if err != nil {
		t.Fatalf("split allowed upstream addr %q: %v", allowedAddr, err)
	}
	// One session, both decisions. The denied host needs no DNS (the proxy denies
	// by name before any dial). Trailing `true` makes the session exit 0 whatever
	// curl's per-request status is.
	script := fmt.Sprintf(
		"curl -s --max-time 20 http://%s:%s/ >/dev/null 2>&1; "+
			"curl -s --max-time 20 http://%s/ >/dev/null 2>&1; true",
		dnsEscapeAllowedHost, port, dnsEscapeDeniedHost,
	)
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	if err := wrapCmd.RunE(cmd, []string{"--", "/bin/sh", "-c", script}); err != nil {
		t.Fatalf("wrap should run the child under the Seatbelt + proxy fence: %v", err)
	}

	// The allowed destination actually served the proxied request...
	if got := allowedHits.Load(); got == 0 {
		t.Error("allowed upstream never reached: the proxied request to the allowlisted host did not complete")
	}

	// ...and both decisions landed signed, chained, and verifiable.
	assertMacOSEgressDecisionsSigned(t, project)

	// RECORD the honest platform limitations (not asserted as blocks).
	t.Logf("macOS egress model: proxy + HTTP_PROXY injection only — no kernel egress floor (sbpl.go has no network rules).")
	t.Logf("T1 direct-IP / raw-socket egress: NOT kernel-blocked on macOS; a client ignoring HTTP_PROXY reaches any address. The Linux netns floor closes this; macOS relies on client cooperation.")
	t.Logf("T3 /etc/hosts pin: /etc/hosts is shared with the host and root-owned, so a non-root child cannot pin it; and the proxy re-resolves the allowlisted name itself, so pinning the child's view would not steer a proxied request.")
}

func assertMacOSEgressDecisionsSigned(t *testing.T, project string) {
	t.Helper()
	dbPath := filepath.Join(project, config.Dir, "events.db")
	logger, err := logging.NewLogger(dbPath, project, signingLoggerOpts()...)
	if err != nil {
		t.Fatalf("open event log at %s: %v", dbPath, err)
	}
	defer logger.Close()

	passed := logging.EventNetworkPassed
	blocked := logging.EventNetworkBlocked
	allowRows, err := logger.Query(logging.QueryOptions{EventType: &passed})
	if err != nil {
		t.Fatalf("query allow rows: %v", err)
	}
	denyRows, err := logger.Query(logging.QueryOptions{EventType: &blocked})
	if err != nil {
		t.Fatalf("query deny rows: %v", err)
	}
	if !hasDecisionRow(allowRows, "host="+dnsEscapeAllowedHost) {
		t.Errorf("no signed allow row naming %s; got allow rows: %s", dnsEscapeAllowedHost, detailList(allowRows))
	}
	if !hasDecisionRow(denyRows, "host="+dnsEscapeDeniedHost) {
		t.Errorf("no signed deny row naming %s; got deny rows: %s", dnsEscapeDeniedHost, detailList(denyRows))
	}

	// Authoritative "signed and chained" verdict: the audit-chain verifier exits
	// clean only when the chain is intact AND every signature verifies.
	var buf bytes.Buffer
	if err := runAuditVerify(context.Background(), &buf, ""); err != nil {
		t.Fatalf("verify --audit did not pass (chain/signature failure): %v\n%s", err, buf.String())
	}
}

// requireSandboxExec skips (or, under strict-required mode, fails) when the
// Seatbelt backend is unavailable — mirrors wrap_darwin_test.go's gate.
func requireSandboxExec(t *testing.T) {
	t.Helper()
	if err := fsfence.EnsureSandboxExecAvailable(); err != nil {
		if dnsEscapeStrictlyRequired() {
			t.Fatalf("sandbox-exec unavailable: %v; NOCKLOCK_DNS_ESCAPE_REQUIRE=1 forbids skipping", err)
		}
		t.Skipf("sandbox-exec unavailable: %v", err)
	}
}

// requireProvisionedAllowedHost requires the CI job to have mapped
// dnsEscapeAllowedHost to 127.0.0.1 in /etc/hosts so the proxy resolves the
// allowlisted name to the local upstream (curl 7.86+ auto-bypasses the proxy for
// a literal "localhost", so a real name is used instead). Skips (strict: fails)
// when the name is not provisioned.
func requireProvisionedAllowedHost(t *testing.T) {
	t.Helper()
	addrs, err := net.LookupHost(dnsEscapeAllowedHost)
	loopback := false
	for _, a := range addrs {
		if a == "127.0.0.1" {
			loopback = true
			break
		}
	}
	if err != nil || !loopback {
		msg := fmt.Sprintf("%s must resolve to 127.0.0.1 (add it to /etc/hosts) so the proxy dials the local test upstream", dnsEscapeAllowedHost)
		if dnsEscapeStrictlyRequired() {
			t.Fatalf("%s; strict-required mode forbids skipping: addrs=%v err=%v", msg, addrs, err)
		}
		t.Skipf("%s; skipping: addrs=%v err=%v", msg, addrs, err)
	}
}

// startDNSEscapeUpstream binds a minimal HTTP upstream on an OS-assigned
// 127.0.0.1 port and counts each request it serves, so the test can prove the
// allowed destination still works through the proxy. It returns the hit counter
// and the bound address.
func startDNSEscapeUpstream(t *testing.T) (*atomic.Int32, string) {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen allowed upstream: %v", err)
	}
	hits := &atomic.Int32{}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				r := bufio.NewReader(conn)
				for {
					line, err := r.ReadString('\n')
					if err != nil {
						return
					}
					if line == "\r\n" {
						break
					}
				}
				hits.Add(1)
				_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n")
			}()
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return hits, ln.Addr().String()
}
