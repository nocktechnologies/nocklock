//go:build linux

package netns

// Q6 post-drop mutation acceptance test (root-gated) — issue #73.
//
// Candidate B of the linux-network-egress-enforcement spec puts the agent in a
// network namespace whose nftables/routes/interfaces are configured by a
// PRIVILEGED parent helper, then hands the namespace to the agent as a child
// with net-admin dropped. That design is only sound if the post-drop child
// genuinely CANNOT rewrite the fence. This test proves exactly that, with the
// positive control the spec demands (absence-of-capability shown against a
// working baseline, not inferred).
//
// Shape (mirrors the seccomp enforcement test's re-exec-helper idiom):
//   - Setup (privileged parent): create a network namespace and apply a
//     default-drop nftables base (IPv4+IPv6 via the `inet` family) in it.
//   - Child: this test binary re-execs itself (via NOCKLOCK_Q6_SCENARIO), enters
//     the namespace with setns(2) WHILE STILL PRIVILEGED, then drops
//     CAP_NET_ADMIN + CAP_SYS_ADMIN from all five capability sets (effective,
//     permitted, inheritable, ambient, and bounding) before attempting one
//     mutation. Each attempt must fail with EPERM.
//   - Positive control: the privileged parent performs the same four ops in the
//     namespace via `ip netns exec` and each must SUCCEED, proving the drop — not
//     a broken setup — is the cause of the child's denials.
//
// Why the child execs the standard tool AFTER dropping caps, rather than issuing
// the netlink syscall in-process: the child stays uid 0, so on execve the kernel
// would normally re-grant a root process the full capability set. The ONLY thing
// that stops the exec'd `nft`/`ip` from regaining CAP_NET_ADMIN across that
// execve is that we cleared it from the BOUNDING set (the permitted set on execve
// for a root file with no file-caps is capped by the bounding set). So this shape
// makes the bounding-set drop — the subtle, load-bearing half of the child cap
// model — actually TESTED, not merely asserted.
//
// Why the child stays uid 0 (Phase-1's child is non-root): keeping uid 0 isolates
// *capability* as the sole gate, with no uid confound — an observed EPERM cannot
// be attributed to "it's just an unprivileged user." It is also the strictly
// harder case: if root-without-net-admin cannot mutate the fence, a non-root
// child without net-admin certainly cannot. So this over-approximates the Phase-1
// child's real credentials rather than under-testing them.
//
// This is a Linux root-gated integration test. It skips cleanly when not root
// (setup needs privilege) and when `ip`/`nft` are absent or nftables is
// unsupported on the kernel. It never runs mutating setup on the default
// (non-root) `go test` path. A privileged CI job should set NOCKLOCK_Q6_REQUIRE=1
// so a misconfigured runner (non-root, or missing iproute2/nftables) FAILS
// instead of silently green-skipping — a skip is not a pass.

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"golang.org/x/sys/unix"
)

// Environment variables the parent uses to drive a re-exec'd child helper.
const (
	scenarioEnv  = "NOCKLOCK_Q6_SCENARIO" // which mutation the child attempts
	netnsPathEnv = "NOCKLOCK_Q6_NETNS"    // filesystem path of the netns to enter
)

// Scenario names: the single mutation op a child helper attempts.
const (
	scenarioNFTAdd   = "nft_add"   // add an nftables table
	scenarioNFTFlush = "nft_flush" // flush the ruleset (destroy the installed fence base)
	scenarioRoute    = "route"     // add a route
	scenarioLink     = "link"      // bring an interface up
)

// Exit codes the child helper returns so the parent can assert precise outcomes.
const (
	exitDeniedEPERM = 10 // the mutation was denied with EPERM (the required result)
	exitAllowed     = 12 // the mutation SUCCEEDED — bypass-resistance FAILED
	exitOtherErr    = 13 // the mutation failed for some non-EPERM reason
	exitSetupFailed = 20 // setns / cap-drop failed; the result is inconclusive
)

// caps is the exact set the child drops from every capability set. Keeping it to
// precisely these two (rather than clearing everything) makes the causal claim
// sharp: only net-admin and sys-admin are removed, so an observed EPERM is caused
// by that drop and nothing else.
var caps = []uintptr{unix.CAP_NET_ADMIN, unix.CAP_SYS_ADMIN}

// epermMarker is the C-locale strerror(EPERM) text emitted by both `nft` and `ip`
// on a capability denial ("Operation not permitted"). Helpers force LC_ALL=C so
// this match is locale-stable.
const epermMarker = "operation not permitted"

// TestMain intercepts the re-exec'd child helper before the test framework runs,
// so the child does exactly one fenced mutation and exits with a decodable code.
func TestMain(m *testing.M) {
	if scenario := os.Getenv(scenarioEnv); scenario != "" {
		os.Exit(runChild(scenario))
	}
	os.Exit(m.Run())
}

// runChild is the privileged-then-dropped child. It enters the pre-created netns
// while it still holds CAP_SYS_ADMIN, drops the fence-relevant capabilities from
// every set, then attempts a single mutation and reports the outcome as an exit
// code.
func runChild(scenario string) int {
	// setns(2) for a network namespace and the per-thread capability state are
	// BOTH per-thread, and Go may fork exec.Command from any thread the goroutine
	// happens to be on. Lock this goroutine to its OS thread and never unlock, so
	// the thread we enter the namespace on and drop caps on is the exact thread
	// the mutation subprocess is fork+exec'd from. Without this the tool could be
	// spawned on a thread still in the host namespace with caps intact.
	runtime.LockOSThread()

	nsPath := os.Getenv(netnsPathEnv)
	if nsPath == "" {
		fmt.Fprintln(os.Stderr, "child: missing netns path")
		return exitSetupFailed
	}

	// Enter the namespace while still privileged (setns(CLONE_NEWNET) needs
	// CAP_SYS_ADMIN). After this, `nft`/`ip` operate on THIS namespace's tables,
	// routes, and interfaces.
	fd, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "child: open netns %s: %v\n", nsPath, err)
		return exitSetupFailed
	}
	if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
		unix.Close(fd)
		fmt.Fprintf(os.Stderr, "child: setns: %v\n", err)
		return exitSetupFailed
	}
	unix.Close(fd)

	// Drop CAP_NET_ADMIN + CAP_SYS_ADMIN from all five capability sets.
	if err := dropCaps(); err != nil {
		fmt.Fprintf(os.Stderr, "child: drop caps: %v\n", err)
		return exitSetupFailed
	}

	// Attempt the mutation via the standard tool, now capless-for-net-admin in
	// every set (the tool is exec'd as a root subprocess but cannot regain the
	// capability because it is gone from the bounding set).
	argv := mutationArgv(scenario)
	out, err := exec.Command(argv[0], argv[1:]...).CombinedOutput()
	if len(out) > 0 {
		fmt.Fprintf(os.Stderr, "child %s output: %s\n", scenario, strings.TrimSpace(string(out)))
	}
	if err == nil {
		return exitAllowed
	}
	if strings.Contains(strings.ToLower(string(out)), epermMarker) {
		return exitDeniedEPERM
	}
	return exitOtherErr
}

// dropCaps removes each capability in `caps` from every capability set of the
// calling thread: bounding, ambient, then effective/permitted/inheritable.
// Bounding is dropped first, while CAP_SETPCAP is still held.
func dropCaps() error {
	// Bounding set — one PR_CAPBSET_DROP per capability. This is what prevents the
	// exec'd root tool from regaining the capability across execve.
	for _, c := range caps {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, c, 0, 0, 0); err != nil {
			return fmt.Errorf("PR_CAPBSET_DROP %d: %w", c, err)
		}
	}

	// Ambient set — clear all. Ambient caps are a subset of the permitted+
	// inheritable pair we clear below, so clearing the whole ambient set is a
	// complete (and simplest) way to ensure neither target cap is ambient.
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_CAP_AMBIENT_CLEAR_ALL: %w", err)
	}

	// Effective, permitted, inheritable — read the current sets, clear exactly the
	// target bits, write them back. Clearing bits is always permitted.
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capget: %w", err)
	}
	for _, c := range caps {
		word := c >> 5 // 32 capabilities per CapUserData word
		bit := uint32(1) << (c & 31)
		data[word].Effective &^= bit
		data[word].Permitted &^= bit
		data[word].Inheritable &^= bit
	}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}
	return nil
}

// mutationArgv maps a scenario to the fence-mutating command the child attempts.
// The child is already inside the target namespace (via setns), so the tools act
// on that namespace directly.
func mutationArgv(scenario string) []string {
	switch scenario {
	case scenarioNFTAdd:
		return []string{"nft", "add", "table", "inet", "nocklock_q6_probe"}
	case scenarioNFTFlush:
		// The canonical fence-rewrite attack: flush the very ruleset the parent
		// installed (spec: "flush the very nftables/routes the fence depends on").
		return []string{"nft", "flush", "ruleset"}
	case scenarioRoute:
		return []string{"ip", "route", "add", "blackhole", "192.0.2.0/24"}
	case scenarioLink:
		return []string{"ip", "link", "set", "dev", "lo", "up"}
	default:
		return []string{"false"}
	}
}

// --- Parent side: gates, namespace setup, and the two assertions. ---

// strictlyRequired reports whether the caller demands the test actually run.
// A privileged CI job sets NOCKLOCK_Q6_REQUIRE=1 so the normally-green skips
// (non-root, or missing ip/nft) become HARD FAILURES — a misconfigured runner
// must not report green by silently skipping. Mirrors the seccomp suite's "a
// skip is not a pass" discipline.
func strictlyRequired() bool { return os.Getenv("NOCKLOCK_Q6_REQUIRE") == "1" }

// requireRoot skips (or, under NOCKLOCK_Q6_REQUIRE=1, fails) unless running as
// root. Setup creates a network namespace and applies an nftables base — both
// need privilege — so a non-root run cannot exercise the test at all.
func requireRoot(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		const msg = "Q6 netns mutation test needs root to create a netns + nftables base"
		if strictlyRequired() {
			t.Fatalf("%s; NOCKLOCK_Q6_REQUIRE=1 forbids skipping", msg)
		}
		t.Skipf("%s; skipping (runs under the privileged CI job)", msg)
	}
}

// requireTool skips (or, under NOCKLOCK_Q6_REQUIRE=1, fails) when a required
// binary is absent from PATH.
func requireTool(t *testing.T, name string) string {
	t.Helper()
	p, err := exec.LookPath(name)
	if err != nil {
		if strictlyRequired() {
			t.Fatalf("Q6 netns mutation test needs %q in PATH (NOCKLOCK_Q6_REQUIRE=1 forbids skipping): %v", name, err)
		}
		t.Skipf("Q6 netns mutation test needs %q in PATH: %v", name, err)
	}
	return p
}

// netnsCounter makes per-test namespace names unique within a run.
var netnsCounter int64

// netnsHandle names a created network namespace and the path used to enter it.
type netnsHandle struct {
	name string
	path string
}

// setupNetns creates a fresh network namespace and installs a default-drop
// nftables base (IPv4+IPv6 via the `inet` family), mirroring the Phase-1 helper's
// intended base policy. It registers cleanup and returns a handle. It skips if
// nftables is unsupported on this kernel and fails hard on any other setup error
// (root + tools are present, so a genuine failure must not be masked as a pass).
func setupNetns(t *testing.T) netnsHandle {
	t.Helper()
	ipBin := requireTool(t, "ip")
	nftBin := requireTool(t, "nft")

	n := atomic.AddInt64(&netnsCounter, 1)
	name := fmt.Sprintf("nocklock-q6-%d-%d", os.Getpid(), n)

	if out, err := run(ipBin, "netns", "add", name); err != nil {
		t.Fatalf("ip netns add %s: %v\n%s", name, err, out)
	}
	t.Cleanup(func() { _, _ = run(ipBin, "netns", "del", name) })

	// Default-drop base over IPv4 and IPv6. The `inet` family covers both address
	// families in a single table, and the drop policies mirror the fence's
	// intended Phase-1 base. (These policies filter packets; they do NOT gate the
	// netlink admin ops under test — capabilities do — so the parent control below
	// still succeeds against this same base.)
	base := "table inet filter {\n" +
		"  chain input   { type filter hook input priority 0; policy drop; }\n" +
		"  chain output  { type filter hook output priority 0; policy drop; }\n" +
		"  chain forward { type filter hook forward priority 0; policy drop; }\n" +
		"}\n"
	out, err := runStdin(base, ipBin, "netns", "exec", name, nftBin, "-f", "-")
	if err != nil {
		low := strings.ToLower(out)
		if strings.Contains(low, "not supported") ||
			strings.Contains(low, "no such file") ||
			strings.Contains(low, "protocol not supported") {
			if strictlyRequired() {
				t.Fatalf("nftables unsupported in required environment: %v\n%s", err, out)
			}
			t.Skipf("nftables unsupported in this environment: %v\n%s", err, out)
		}
		t.Fatalf("apply default-drop nftables base: %v\n%s", err, out)
	}

	// The netns pseudo-file lives under /run/netns (some layouts expose it only
	// via the /var/run symlink). Resolve whichever exists now, so a path mismatch
	// names itself here rather than surfacing later as an opaque child setns
	// failure ("result inconclusive").
	var nsFile string
	for _, cand := range []string{"/run/netns/" + name, "/var/run/netns/" + name} {
		if _, err := os.Stat(cand); err == nil {
			nsFile = cand
			break
		}
	}
	if nsFile == "" {
		t.Fatalf("created netns %q but no nsfs path exists under /run/netns or /var/run/netns", name)
	}

	return netnsHandle{name: name, path: nsFile}
}

// TestQ6_CappedChildCannotMutate is the Q6 mutation-resistance proof: a child in
// the namespace with net-admin/sys-admin dropped from every capability set is
// denied (EPERM) on nftables, route, and interface mutations.
func TestQ6_CappedChildCannotMutate(t *testing.T) {
	requireRoot(t)
	requireTool(t, "ip")
	requireTool(t, "nft")
	ns := setupNetns(t)

	for _, tc := range []struct {
		name     string
		scenario string
	}{
		{"nft_add_table", scenarioNFTAdd},
		{"nft_flush_ruleset", scenarioNFTFlush},
		{"route_add", scenarioRoute},
		{"link_up", scenarioLink},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code := runChildHelper(t, tc.scenario, ns.path)
			switch code {
			case exitDeniedEPERM:
				// Required outcome: the fence held.
			case exitAllowed:
				t.Fatalf("%s: capped child was ALLOWED to mutate the fence — Candidate B bypass-resistance FAILED", tc.name)
			case exitSetupFailed:
				t.Fatalf("%s: child setup (setns / cap-drop) failed — result inconclusive", tc.name)
			case exitOtherErr:
				t.Fatalf("%s: child mutation failed for a non-EPERM reason — expected a capability denial", tc.name)
			default:
				t.Fatalf("%s: child exited %d, want EPERM (%d)", tc.name, code, exitDeniedEPERM)
			}
		})
	}
}

// TestQ6_PrivilegedParentCanMutate_Control is the positive control: the SAME
// four ops, performed by the privileged parent in the SAME kind of namespace,
// must all succeed. It proves the child's denials come from the capability drop,
// not from broken setup.
func TestQ6_PrivilegedParentCanMutate_Control(t *testing.T) {
	requireRoot(t)
	ipBin := requireTool(t, "ip")
	requireTool(t, "nft")
	ns := setupNetns(t)

	for _, tc := range []struct {
		name string
		argv []string
	}{
		{"nft_add_table", []string{"nft", "add", "table", "inet", "nocklock_q6_control"}},
		{"nft_flush_ruleset", []string{"nft", "flush", "ruleset"}},
		{"route_add", []string{"ip", "route", "add", "blackhole", "198.51.100.0/24"}},
		{"link_up", []string{"ip", "link", "set", "dev", "lo", "up"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			args := append([]string{"netns", "exec", ns.name}, tc.argv...)
			out, err := run(ipBin, args...)
			if err != nil {
				t.Fatalf("%s: privileged parent control expected success, got %v\n%s", tc.name, err, out)
			}
		})
	}
}

// runChildHelper re-execs this test binary into a child scenario and returns its
// exit code.
func runChildHelper(t *testing.T, scenario, nsPath string) int {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(),
		scenarioEnv+"="+scenario,
		netnsPathEnv+"="+nsPath,
		"LC_ALL=C", "LANG=C", "LANGUAGE=",
	)
	out, err := cmd.CombinedOutput()
	if len(out) > 0 {
		t.Logf("child %q output:\n%s", scenario, strings.TrimSpace(string(out)))
	}
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	t.Fatalf("child %q run error: %v", scenario, err)
	return -1
}

// run executes a command with a C locale (so tool error strings are stable) and
// returns combined output.
func run(name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C", "LANGUAGE=")
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// runStdin is run with stdin fed from s.
func runStdin(s, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C", "LANGUAGE=")
	cmd.Stdin = strings.NewReader(s)
	out, err := cmd.CombinedOutput()
	return string(out), err
}
