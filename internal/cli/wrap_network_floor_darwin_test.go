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
	// Each probe prints one line "<name>: rc=<status> <tool output>". The
	// proxy_loopback probe is the negative control: the same nc that is denied
	// elsewhere must succeed against the proxy port.
	script := fmt.Sprintf(`
P="${HTTP_PROXY##*:}"
O=%[1]q
probe() { n="$1"; shift; r=$("$@" 2>&1); echo "$n: rc=$? $r" | tr '\n' ' ' >>"$O"; echo >>"$O"; }
probe proxy_loopback nc -z -w 3 127.0.0.1 "$P"
probe raw_tcp nc -z -w 3 1.1.1.1 443
probe raw_dns_udp nc -z -u -w 3 8.8.8.8 53
if command -v dig >/dev/null 2>&1; then probe dig_direct dig +time=2 +tries=1 +short @8.8.8.8 example.com; fi
probe via_proxy curl -s -o /dev/null --max-time 20 http://%[2]s:%[3]s/
probe noproxy curl -s -o /dev/null --noproxy '*' --max-time 10 http://%[2]s:%[3]s/
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

	line := func(name string) string {
		for _, l := range strings.Split(got, "\n") {
			if strings.HasPrefix(l, name+": ") {
				return l
			}
		}
		return ""
	}
	if l := line("proxy_loopback"); !strings.Contains(l, "rc=0") {
		t.Errorf("negative control: the proxy's loopback port must stay reachable: %q", l)
	}
	if l := line("raw_tcp"); !strings.Contains(l, "Operation not permitted") || strings.Contains(l, "rc=0") {
		t.Errorf("raw TCP connect to a non-loopback IP must fail with EPERM: %q", l)
	}
	if l := line("raw_dns_udp"); !strings.Contains(l, "Operation not permitted") || strings.Contains(l, "rc=0") {
		t.Errorf("a direct UDP connect to a resolver must fail with EPERM: %q", l)
	}
	if l := line("dig_direct"); l != "" && (strings.Contains(l, "rc=0") && strings.Count(l, ".") > 3) {
		t.Errorf("dig answered from an external resolver through the floor: %q", l)
	}
	if l := line("via_proxy"); !strings.Contains(l, "rc=0") {
		t.Errorf("curl via the proxy to the allowlisted host must succeed: %q", l)
	}
	if l := line("noproxy"); l == "" || strings.Contains(l, "rc=0") {
		t.Errorf("curl --noproxy to the allowlisted host must fail inside the fence: %q", l)
	}
	if hits := allowedHits.Load(); hits != 1 {
		t.Errorf("allowed upstream hits = %d, want exactly 1 (the proxied request; the --noproxy request must never arrive)", hits)
	}
	assertSessionEgressLevel(t, project, string(egressLevelSeatbelt))
}
