# Red-team bench (N11623)

`bash bench/redteam/run.sh` runs every attack in `attacks.toml` inside its own `nocklock wrap
--net-fence=netns` session, pairs each with the signed row that stopped it, runs both verifiers, and
writes `REPORT.md` and `report.json`. The MCP attacks run on the host, outside the fence, directly
against `nockguard proxy`; the proof is NockGuard's signed policy deny.

Scoring rule: the bench never scores a block it did not observe, and any harness problem fails the
run. An attack is BLOCKED only when it exits with a code it declares as `blocked_exit` and nothing
planted a mark (a file, or a datagram at the host receiver). Any other exit is a HARNESS-FAULT.

The direct-DNS attack is scored by receipt: a host receiver on UDP port 53 (the runner lowers
`net.ipv4.ip_unprivileged_port_start`, or run as root) must log nothing. Whether the client got a
reply does not matter.

## Kernel-dependent companion cases (N11747)

The Linux CI bench also requires `python3 bench/redteam/kernel_cases.py --out
bench/redteam/kernel-report`. It runs the real Go/C Unix-socket and io_uring
controls, retaining raw test JSON, stderr, kernel, source commit and a separate
report. It does not change `attacks.toml`, the main pass bar or breach scoring.

- `unix-wrap` exercises the complete CONFINED wrapper with live pathname and
  abstract listeners, allowed proxy/event sockets, signed boundary rows and
  strict-mode refusal. Below Landlock ABI 9, observed reachable sockets are
  **KNOWN-LIMIT**, not blocked. On ABI 9+, both normal and socket-only policies
  must deny the unrelated sockets while the permitted sockets keep working.
- `abi9` tests the actual kernel directly in a disposable subprocess: an exact
  permitted pathname connects; unrelated pathname and abstract connects must
  return `EACCES` or `EPERM`. All three have unfenced live-listener controls.
  Older kernels produce **SKIP** with `ABI9_COVERAGE_GAP`; that is missing proof.
- `io-uring` first proves an unfenced raw `IORING_OP_SOCKET`/`CONNECT` reaches a
  live TCP listener, then requires the seccomp filter to reject `io_uring_setup`
  with `EPERM`. An unavailable ambient operation is **SKIP** with its reason;
  it is not attributed to NockLock. This probes seccomp directly, not full wrap.

`--require-abi 9` turns the gaps into failures for a capable kernel. It first
prints the kernel's Landlock ABI and exits 1 below 9, before any case runs.
With `--out`, every case must then be **PASS**, and `report.json` gains
`claims` with expected and actual values: the full-wrap probe's unrelated
pathname socket outside `filesystem.root` and abstract socket `DENIED`, the
policy-allowed proxy and event sockets `CONNECTED`, and `io_uring_setup`
`DENIED`. `.github/workflows/landlock-abi9-receipt.yml` runs it in a KVM guest
and signs the result.

A missing test, unexpected skip, failed control or harness fault fails the
required step and the `redteam-bench` job; the main bench then does not run.
Summary/artifact steps still preserve the failure receipts. Every harness
timeout fails, even if the test already emitted a passing result and its leader
exited zero. After group cancellation, output draining and reaping each have a
five-second bound. Explicit unsupported-kernel gaps yield
`PASS_WITH_COVERAGE_GAPS`; they remain visible in the job summary and uploaded
`redteam-report`. An ABI-9 enforcement claim still requires a real ABI-9+ run.

The separate hosted-only credential job reads the final child's five capability
sets, supplementary groups, UID/GID and `NoNewPrivs` after exec: 36 direct drops
at `GOMAXPROCS=2,8,32`, plus six installed netns wrap sessions. Test-only Go
overlays must turn the cross-thread final-exec and per-thread proxy-group drops
red. Original and mutated receipts are uploaded. These jobs require root only
inside a disposable hosted VM; never run their privileged probes on an agent
host. The workflow checks runner-supplied `RUNNER_ENVIRONMENT` and passes it
through sudo unchanged. Installed-wrap probes run in isolated process groups;
the 60-second deadline kills the group, with two-second output/reap bounds.
Unprivileged hanging-stub controls prove that prior success markers cannot mask
a timeout and that permitted same-group descendants are killed. Cancellation
does not claim to kill a privileged helper or a descendant that escaped into
another process group; a timeout, failed kill, or incomplete drain/reap is a
harness failure. They add regression coverage, not a claim of a newly observed
runtime bug.

## Limits

Known limits of this slice, written down rather than fixed:

- `check_setup` runs once, before the first attack. It does not re-check that evidence paths stay
  outside the fence grants while attacks run.
- The NockGuard trail path (`<agent>.audit.jsonl` beside the policy audit path) is a naming
  convention the driver reproduces; the bench does not ask NockGuard where it wrote the trail.
- The symlink test (`test_a_symlinked_log_path_is_refused_and_its_target_untouched`) is vacuous when the victim file is
  absent: it asserts the value it falls back to. The FIFO and dangling-symlink tests carry the
  real refusal check.
- Direct DNS egress is scored by receipt only for a query to the host's outbound address on port
  53; a query to another resolver address is not observed by the bench.
