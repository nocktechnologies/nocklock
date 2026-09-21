//go:build linux

package cli

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

// wrap_egress_audit_linux_test.go is the root/netns ACCEPTANCE test for the
// N10649 egress-decision audit path. Unlike the protocol matrix — which starts
// the sidecars directly and never runs `wrap`, so it does NOT exercise the
// signed-write path — this test drives the WHOLE `nocklock wrap --net-fence=netns`
// pipeline end to end and proves the signed rows land in .nock/events.db.
//
// It deliberately does NOT use requireRoot: the test invokes wrap AS THE RUNNER
// USER (wrap sudo's the privileged helper internally, and the fenced child drops
// to the invoking uid — a root invoker would be rejected as the child credential).
// Instead it self-skips unless the DECIDED privileged path is actually reachable
// via passwordless sudo, exactly as wrap's own preflight probes it. On any dev
// host (helper not installed, or no NOPASSWD sudo) it skips and never runs. Under
// NOCKLOCK_AUDIT_REQUIRE=1 (set by the CI job) a would-be skip HARD-FAILS instead,
// so a misconfigured runner is loud, not green.
//
// SAFETY: this test is the CI-only bar. It must not be run on the resident host.

const netnsHelperInstalledPath = "/usr/libexec/nocklock-egress-helper"

func auditStrictlyRequired() bool { return os.Getenv("NOCKLOCK_AUDIT_REQUIRE") == "1" }

// requireNetnsHelperSudo skips (or, under NOCKLOCK_AUDIT_REQUIRE=1, fails) unless
// `sudo -n <helper> check` succeeds — the identical probe wrap runs before it
// will attempt --net-fence=netns. This self-skips on every host that has not
// installed the helper with the passwordless-sudo policy from the spec.
func requireNetnsHelperSudo(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		const msg = "egress audit acceptance test must run as the UNPRIVILEGED runner user (wrap sudo's the helper itself; a root invoker is rejected as the child credential)"
		if auditStrictlyRequired() {
			t.Fatalf("%s; strict-required mode forbids running as root", msg)
		}
		t.Skipf("%s; skipping", msg)
	}
	out, err := exec.Command("sudo", "-n", netnsHelperInstalledPath, "check").CombinedOutput()
	if err != nil {
		msg := "egress audit acceptance test needs the netns helper installed at " + netnsHelperInstalledPath +
			" with passwordless sudo (sudo -n <helper> check must pass)"
		if auditStrictlyRequired() {
			t.Fatalf("%s; strict-required mode forbids skipping: %v\n%s", msg, err, strings.TrimSpace(string(out)))
		}
		t.Skipf("%s; skipping: %v", msg, err)
	}
}

// nocklockBinary returns the installed nocklock binary to drive. The CI job sets
// NOCKLOCK_TEST_BIN to the freshly built binary; otherwise it is looked up on
// PATH. Under strict-required mode a missing binary fails rather than skips.
func nocklockBinary(t *testing.T) string {
	t.Helper()
	if bin := os.Getenv("NOCKLOCK_TEST_BIN"); bin != "" {
		return bin
	}
	bin, err := exec.LookPath("nocklock")
	if err != nil {
		if auditStrictlyRequired() {
			t.Fatalf("egress audit acceptance test needs the nocklock binary (set NOCKLOCK_TEST_BIN or put it on PATH); strict-required mode forbids skipping: %v", err)
		}
		t.Skipf("egress audit acceptance test needs the nocklock binary on PATH or NOCKLOCK_TEST_BIN: %v", err)
	}
	return bin
}

// TestWrapNetnsEgressDecisionAudit runs one wrapped session that makes one
// allowlisted (example.com:443) and one denied (blocked.test:80) egress attempt,
// then asserts both decisions were signed into .nock/events.db as network events
// naming their hosts, and that `nocklock verify --audit` reports the chain intact
// and signatures valid.
func TestWrapNetnsEgressDecisionAudit(t *testing.T) {
	requireNetnsHelperSudo(t)
	bin := nocklockBinary(t)

	projectDir := t.TempDir()
	nockDir := filepath.Join(projectDir, ".nock")
	if err := os.MkdirAll(nockDir, 0o755); err != nil {
		t.Fatalf("create .nock dir: %v", err)
	}
	// Keep the FILESYSTEM FENCE ON so this test also exercises the child-deny of
	// the decision log (wrap adds the decision-log dir to the child's deny list
	// only when the fs fence is on). root="/" lets sh+curl reach the whole
	// filesystem (the userspace interposer allows everything under root except the
	// deny list, into which wrap injects the audit DB and the decision-log dir),
	// so the fence is genuinely active without breaking the child. The CI job
	// installs libfence_fs.so, which the fs fence requires. linux_enforcement="off"
	// keeps this to the LD_PRELOAD interposer (Landlock cannot subtract a deny from
	// a root="/" grant anyway). syscall enforcement off — curl needs no seccomp
	// interference; the netns egress floor is what we test. netns needs a non-empty
	// allowlist and allow_all=false.
	config := `[project]
name = "n10649-egress-audit"

[filesystem]
root = "/"
mode = "read-write"
linux_enforcement = "off"
allow = []
deny = []

[network]
allow = ["example.com"]
allow_all = false

[syscall]
enforcement = "off"
`
	if err := os.WriteFile(filepath.Join(nockDir, "config.toml"), []byte(config), 0o644); err != nil {
		t.Fatalf("write config.toml: %v", err)
	}

	// One session, both decisions. The denied host needs no real DNS (the stub
	// resolver answers 127.0.0.1 and the Host check denies before any dial); the
	// allowed host needs runner egress, which hosted runners have. Trailing `true`
	// makes the session exit 0 regardless of curl's per-request status.
	script := "curl -s --max-time 20 https://example.com/ >/dev/null 2>&1; " +
		"curl -s --max-time 20 http://blocked.test/ >/dev/null 2>&1; true"
	wrap := exec.Command(bin, "wrap", "--net-fence=netns", "--", "sh", "-c", script)
	wrap.Dir = projectDir
	wrap.Env = os.Environ()
	if out, err := wrap.CombinedOutput(); err != nil {
		t.Fatalf("nocklock wrap --net-fence=netns failed: %v\n%s", err, out)
	}

	// Open the event log and assert both signed rows are present, naming their
	// hosts. Query by EventType + Detail substring — the wrap sessionID is a uuid
	// generated inside wrap and not observable here.
	dbPath := filepath.Join(nockDir, "events.db")
	logger, err := logging.NewLogger(dbPath, projectDir, signingLoggerOpts()...)
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

	if !hasDecisionRow(allowRows, "method=tls", "host=example.com:443") {
		t.Errorf("no signed EventNetworkPassed row naming example.com:443; got allow rows: %s", detailList(allowRows))
	}
	if !hasDecisionRow(denyRows, "method=http", "host=blocked.test:80") {
		t.Errorf("no signed EventNetworkBlocked row naming blocked.test:80; got deny rows: %s", detailList(denyRows))
	}

	// The chain + signatures: `nocklock verify --audit` exits 0 only when the
	// audit chain is intact AND every signature verifies (CONSISTENT). That is the
	// authoritative "signed, chained" assertion for the two rows above.
	verify := exec.Command(bin, "verify", "--audit")
	verify.Dir = projectDir
	verify.Env = os.Environ()
	if out, err := verify.CombinedOutput(); err != nil {
		t.Fatalf("nocklock verify --audit did not pass (chain/signature failure): %v\n%s", err, out)
	}
}

func hasDecisionRow(rows []logging.Event, needles ...string) bool {
	for _, e := range rows {
		if e.Category != "network" {
			continue
		}
		match := true
		for _, n := range needles {
			if !strings.Contains(e.Detail, n) {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

func detailList(rows []logging.Event) string {
	var b strings.Builder
	for _, e := range rows {
		b.WriteString("\n  - ")
		b.WriteString(e.Detail)
	}
	if b.Len() == 0 {
		return "(none)"
	}
	return b.String()
}
