//go:build darwin

package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/spf13/cobra"
)

// TestWrapMacOSNetworkFloor drives one wrapped session and probes the Seatbelt
// network floor from INSIDE the fence: the proxy's loopback port is reachable,
// every other destination is kernel-denied, and a client that ignores the
// proxy cannot reach even the allowlisted host.
func TestWrapMacOSNetworkFloor(t *testing.T) {
	requireSandboxExec(t)
	requireProvisionedAllowedHost(t)

	allowedHits, allowedAddr := startDNSEscapeUpstream(t)
	_, port, err := net.SplitHostPort(allowedAddr)
	if err != nil {
		t.Fatalf("split allowed upstream addr %q: %v", allowedAddr, err)
	}

	project := t.TempDir()
	if err := os.MkdirAll(filepath.Join(project, config.Dir), 0o755); err != nil {
		t.Fatalf("create .nock dir: %v", err)
	}
	writeTestConfig(t, project, fmt.Sprintf(`[project]
name = "n11599-network-floor-darwin"

[filesystem]
root = "/"
mode = "read-write"
allow = []
deny = []

[network]
allow = ["%s"]
allow_all = false
allow_private_ranges = true
require_enforced = true

[syscall]
enforcement = "off"
`, dnsEscapeAllowedHost))
	withWorkingDir(t, project)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	out := filepath.Join(project, "floor.out")
	// Each probe appends "<name>=<exit status>" (and the tool's stderr where the
	// errno matters) to out. The proxy_loopback probe is the negative control:
	// the same nc that is denied elsewhere must succeed against the proxy port.
	script := fmt.Sprintf(`
P="${HTTP_PROXY##*:}"
O=%[1]q
nc -z -w 3 127.0.0.1 "$P" >>"$O" 2>&1; echo "proxy_loopback=$?" >>"$O"
nc -z -w 3 1.1.1.1 443 >>"$O" 2>&1; echo "raw_tcp=$?" >>"$O"
nc -z -u -w 3 8.8.8.8 53 >>"$O" 2>&1; echo "raw_dns_udp=$?" >>"$O"
if command -v dig >/dev/null 2>&1; then
  dig +time=2 +tries=1 +short @8.8.8.8 example.com >>"$O" 2>&1; echo "dig_direct=$?" >>"$O"
fi
curl -s --max-time 20 http://%[2]s:%[3]s/ >/dev/null 2>&1; echo "via_proxy=$?" >>"$O"
curl -s --noproxy '*' --max-time 10 http://%[2]s:%[3]s/ >/dev/null 2>&1; echo "noproxy=$?" >>"$O"
true
`, out, dnsEscapeAllowedHost, port)

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	if err := wrapCmd.RunE(cmd, []string{"--", "/bin/sh", "-c", script}); err != nil {
		t.Fatalf("wrap should start with --require-enforced egress satisfied by the Seatbelt floor: %v", err)
	}

	raw, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("probe output missing: %v", err)
	}
	got := string(raw)
	t.Logf("in-fence probe output:\n%s", got)

	mustContain := func(want, why string) {
		t.Helper()
		if !strings.Contains(got, want) {
			t.Errorf("%s: want %q in probe output", why, want)
		}
	}
	mustContain("proxy_loopback=0", "negative control: the proxy's loopback port must stay reachable")
	mustContain("raw_tcp=1", "raw TCP connect to a non-loopback IP must fail")
	if !strings.Contains(got, "Operation not permitted") {
		t.Errorf("raw TCP connect must fail with EPERM (Operation not permitted); output:\n%s", got)
	}
	mustContain("raw_dns_udp=1", "a direct UDP connect to a resolver must fail")
	if strings.Contains(got, "dig_direct=") {
		if strings.Contains(got, "dig_direct=0") && strings.Contains(got, "93.184.") {
			t.Errorf("dig reached the external resolver through the floor:\n%s", got)
		}
	}
	mustContain("via_proxy=0", "curl via the proxy to the allowlisted host must succeed")
	if strings.Contains(got, "noproxy=0") {
		t.Errorf("curl --noproxy to the allowlisted host must fail inside the fence:\n%s", got)
	}
	if hits := allowedHits.Load(); hits != 1 {
		t.Errorf("allowed upstream hits = %d, want exactly 1 (the proxied request; the --noproxy request must never arrive)", hits)
	}
	assertSessionEgressLevel(t, project, string(egressLevelSeatbelt))
}
