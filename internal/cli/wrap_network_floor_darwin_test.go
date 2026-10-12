//go:build darwin

package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/spf13/cobra"
)

// dnsAnswer matches any A/AAAA record in dig's answer section, however many.
var dnsAnswer = regexp.MustCompile(`\sIN\s+(A|AAAA)\s`)

// floorProbePython is the in-fence probe. It prints the OS error by name so the
// test can tell EPERM (the kernel denied it) from a timeout or a refusal.
const floorProbePython = `import errno, socket, sys
mode, host = sys.argv[1], sys.argv[2]
try:
    if mode == "resolve":
        import signal
        signal.alarm(15)
        print("resolved", socket.getaddrinfo(host, None))
    else:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM if mode == "tcp" else socket.SOCK_DGRAM)
        s.settimeout(5)
        s.connect((host, int(sys.argv[3])))
        print("connected")
except socket.gaierror as e:
    print("gaierror", e.errno, e.strerror)
    sys.exit(1)
except OSError as e:
    print(errno.errorcode.get(e.errno, e.errno), e.strerror)
    sys.exit(1)
`

// TestWrapMacOSNetworkFloor drives one wrapped session and probes the Seatbelt
// network floor from INSIDE the fence: the proxy's loopback port is reachable,
// every other destination is kernel-denied, and a client that ignores the
// proxy cannot reach even the allowlisted host.
func TestWrapMacOSNetworkFloor(t *testing.T) {
	requireSandboxExec(t)
	requireProvisionedAllowedHost(t)
	if _, err := exec.LookPath("python3"); err != nil {
		if dnsEscapeStrictlyRequired() {
			t.Fatalf("python3 is required for the in-fence probes: %v", err)
		}
		t.Skipf("python3 not available for the in-fence probes: %v", err)
	}

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
	probePy := filepath.Join(project, "probe.py")
	if err := os.WriteFile(probePy, []byte(floorProbePython), 0o644); err != nil {
		t.Fatalf("write probe script: %v", err)
	}
	uniqueName := fmt.Sprintf("nocklock-floor-%d.example.com", time.Now().UnixNano())
	// Each probe prints one line "<name>: rc=<status> <tool output>"; the python
	// probes print the OS error ("EPERM Operation not permitted"), so a timeout
	// or a refusal cannot pass as kernel-denied. proxy_loopback is the negative
	// control: the same connect that is denied elsewhere must succeed against
	// the proxy port.
	script := fmt.Sprintf(`
P="${HTTP_PROXY##*:}"
O=%[1]q
PY=%[4]q
probe() { n="$1"; shift; r=$("$@" 2>&1); echo "$n: rc=$? $r" | tr '\n' ' ' >>"$O"; echo >>"$O"; }
probe proxy_loopback python3 "$PY" tcp 127.0.0.1 "$P"
probe raw_tcp python3 "$PY" tcp 1.1.1.1 443
probe loopback_other python3 "$PY" tcp 127.0.0.1 %[3]s
probe raw_dns_udp python3 "$PY" udp 8.8.8.8 53
probe resolve_pinned python3 "$PY" resolve %[2]s
probe resolve_unique python3 "$PY" resolve %[6]s
if command -v dig >/dev/null 2>&1; then probe dig_direct dig +time=2 +tries=1 +noall +answer @8.8.8.8 example.com; fi
probe via_proxy curl -s -o /dev/null --max-time 20 http://%[2]s:%[3]s/
probe noproxy curl -s -o /dev/null --noproxy '*' --max-time 10 http://%[2]s:%[3]s/
true
`, out, dnsEscapeAllowedHost, port, probePy, port, uniqueName)

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
	for _, name := range []string{"raw_tcp", "loopback_other", "raw_dns_udp"} {
		if l := line(name); !strings.Contains(l, "EPERM Operation not permitted") {
			t.Errorf("%s must be kernel-denied with EPERM (a timeout or refusal is not a pass): %q", name, l)
		}
	}
	// The resolver rides Mach to mDNSResponder, not a socket the connect rules
	// see. The pinned name resolves outside the fence (requireProvisionedAllowedHost),
	// so a failed lookup inside it proves the Mach deny; the unique name records
	// whether a lookup could leave (it must fail too).
	if l := line("resolve_pinned"); !strings.Contains(l, "gaierror") {
		t.Errorf("getaddrinfo of a name the host resolves must fail inside the fence (resolver Mach service denied): %q", l)
	}
	if l := line("resolve_unique"); !strings.Contains(l, "gaierror") {
		t.Errorf("getaddrinfo of a unique name must not resolve inside the fence: %q", l)
	}
	if l := line("dig_direct"); l != "" && dnsAnswer.MatchString(l) {
		t.Errorf("dig received an answer section from an external resolver through the floor: %q", l)
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
