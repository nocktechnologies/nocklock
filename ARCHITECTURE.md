# Architecture — NockLock

## Overview
NockLock is a Go CLI that wraps AI coding agents with three security fences: filesystem, network, and secret isolation.

**Current state:** The secret and network fences are active, and Linux has a
kernel-enforced root filesystem fence (Landlock plus LD_PRELOAD event logging)
and a seccomp syscall fence. The network fence has two modes: the default
userspace domain-allowlist proxy on Linux and macOS, and on Linux only the
opt-in `nocklock wrap --net-fence=netns` kernel egress fence (a fresh network
namespace with an nftables default-drop floor and a transparent HTTP(S) and
DNS allowlist, set up by a root-owned helper over a constrained sudo grant).
All fence events are logged to a tamper-evident SQLite audit log: a SHA-256
hash chain (v1), Ed25519 signatures over the rows and the chain head (v1.1),
and an external chain-head anchor that can be pushed off-box (v1.2). macOS
has a kernel-enforced Seatbelt write-confinement profile plus sensitive-path
read/write denies (reads outside `filesystem.root` are not confined) and
records its filesystem-fence state in SQLite; per-file deny events remain a
follow-up.

**Target state:** Preserve all three active fence categories while adding an
Endpoint Security macOS backend for read confinement and native per-file events; optional NockCC cloud dashboard sync remains separate.

## Package Structure

```text
cmd/nocklock/           Entry point — calls cli.Execute()
internal/
  cli/                  Cobra command tree
    root.go             Root command + Execute() + exitCodeError
    wrap.go             Primary command — wraps child process with secret + filesystem fences
    init_cmd.go         Creates .nock/config.toml with safe defaults (or from a runtime preset)
    config.go           Prints current config to stdout
    validate.go         Validates a config file and prints the effective policy
    doctor.go           Reports whether each fence can be enforced on this host
    scan.go             `scan` command: secret preflight over selected paths and, with --env, the environment
    verify.go           Adversarial fence self-test; --audit verifies the audit chain and anchors
    anchor.go           `anchor emit` and `anchor push` for the external chain-head anchor
    anchor_push.go      Wrap-teardown off-box anchor push (5s, fail-open); strips NOCKLOCK_ANCHOR_URL/TOKEN from the child
    egress_probe.go     Structured feasibility probe for the Linux netns egress fence
    netns_helper.go     Privileged `__netns-helper` and the `__netns-*` sidecar entry points
    decision_log.go     Per-session egress decision log consumed into the audit chain
    log.go              Views fence event log
    status.go           Shows fence state and event log summary
    version.go          Prints version string
  config/               Configuration
    config.go           Config structs (6 sections) + Load() with strict TOML parsing
    defaults.go         DefaultConfig() + DefaultTOML() — security-first defaults
    config_test.go      Parse, default, error, round-trip tests
  version/              Build info
    version.go          Version string, overridable via ldflags
  anchorclient/         HTTP client that pushes chain-head anchors off-box and fetches the latest one back

  fence/                Fence implementations
    secrets/            Secret fence — environment variable filtering (pass/block lists)
                        scan.go: preflight credential-shape scanner (os.Root traversal, bounded, run before `wrap` launches the child)
    fs/                 Filesystem fence — config processing, Linux enforcement, macOS Seatbelt enforcement
      interposer/       C shared library for LD_PRELOAD interception (Linux only)
      landlock/         Landlock ruleset generation (Linux only)
    syscallfence/       seccomp syscall fence: socket-family and syscall denylist policy
    network/            Network fence: local proxy with domain allowlist (default mode)
      netns/            Linux netns egress fence: privileged helper, default-drop base, tproxy and DNS sidecars
  logging/              Event logging and audit chain
    logger.go           SQLite event store — Log, LogBatch, Query, Stats, Prune
                        plus the hash chain, Ed25519 signing, chain head and anchor primitives
pkg/
  receipt/              Public read-only VerifySession(dbPath, pub, sessionID) for one session's chain
```

## Data Flow

### Current
1. User runs `nocklock wrap -- claude --dangerously-skip-permissions`
2. CLI parses args, loads `.nock/config.toml` (walks up directory tree)
3. Initialize fence engines — if any fence fails to init, abort (fail closed)
4. Secret fence filters environment variables (pass/block lists). When `[secrets]` scan
   settings are configured, the secret preflight then scans the selected paths
   and the filtered environment, and a finding or incomplete scan refuses
   launch and is written to the audit chain (README, "Secret preflight scanning")
5. With `filesystem.root` configured on Linux, the filesystem fence applies
   Landlock and LD_PRELOAD with libfence_fs.so, then opens a Unix socket for events
6. With `filesystem.root` configured on macOS, NockLock builds a canonical
   Seatbelt profile that denies writes outside the root and required runtime
   paths, preserves sensitive-path read/write denies, validates it with
   `sandbox-exec`, and wraps the child with it. Exactly one fence state is recorded
   before launch: ENGAGED, REFUSED-TO-START (the default when the profile
   cannot be applied) or DEGRADED (only via the explicit `filesystem.root = ""`
   or the temporary `filesystem.macos_allow_unfenced` escape hatch)
7. On Linux with `[syscall] enforcement` on, the seccomp fence is installed in
   the child. In the default proxy mode it narrows the child to Unix-domain
   sockets; under `--net-fence=netns` the child keeps its configured IP socket
   families because the kernel floor is the boundary
8. The network fence is configured. In the default proxy mode it starts the
   domain-allowlist proxy when configured. With `--net-fence=netns` (Linux
   only) `wrap` instead prepares the handoff to the privileged helper over
   `sudo -n`; the request travels in a 0600 per-session file whose path rides
   argv, so the caller's stdin reaches the child unchanged (ADR-004). The
   helper creates the namespace, installs the default-drop nftables base,
   starts the tproxy and DNS sidecars (the DNS stub answers UDP and TCP port 53
   inside the namespace; direct resolvers, non-DNS UDP, QUIC, SCTP and raw IP
   get no path out), drops `CAP_NET_ADMIN` and
   `CAP_SYS_ADMIN` from all five capability sets, drops to the invoking user
   and execs the agent, and that exec is the single spawn of the child. If
   privilege cannot be acquired or a sidecar dies, the fence fails closed
9. The child runs with the filtered environment and active fence wiring. It
   is started directly by `wrap` in proxy mode, or by the helper's exec from
   step 8 in netns mode; the child is spawned exactly once
10. Filesystem, network and per-host egress decisions are logged to
    `.nock/events.db` as hash-chained, signed rows; on teardown `wrap` emits a
    chain-head anchor to `<db-dir>/chain-anchor.json` and, when
    `NOCKLOCK_ANCHOR_URL` is set, pushes it off-box
11. NockLock exits with the child's exit code

### Future
- A macOS Endpoint Security backend can add read confinement and native per-file
  deny events.
- Optional: events batched and synced to NockCC cloud dashboard

## Network egress fence (Linux, opt-in)

`nocklock wrap --net-fence=netns` is the kernel-enforced egress fence. It is
opt-in (`internal/cli/flagparse.go`) and Linux-only; on any other platform the
flag refuses rather than falling back to the proxy. Its guarantees are proven
by root-gated CI jobs in `.github/workflows/network-egress.yml`, each run with
a `*_REQUIRE=1` gate so a skipped test fails instead of reporting green:

- `netns-foundation`: with the default-drop base installed, a capability-dropped
  child is denied loopback, external TCP and UDP/53, with a no-drop control.
- `q6-acceptance`: the capped child gets EPERM on nftables, route and interface
  mutation, with a privileged-parent control.
- `netns-protocol-matrix`: allowlisted HTTP and HTTPS succeed end to end,
  non-allowlisted HTTP gets a proxy 403, non-allowlisted TLS is closed at the
  proxy, no-SNI direct-IP TLS is terminated, the fixed DNS stub answers over
  UDP and TCP inside the namespace, direct resolvers get no reply, UDP/443
  (QUIC) and SCTP stay dropped,
  curl, Node and Python succeed over the TCP-only path, and proxy death
  terminates the child.
- `netns-composed-default`: Landlock required, seccomp required, netns and the
  signed audit log compose through a real `nocklock wrap`; one allowlisted fetch
  is permitted, one off-allowlist fetch is refused, both land signed and
  `nocklock verify --audit` passes.
- `egress-helper-install-readme`: the shipped installer produces a sudoers
  drop-in scoped to exactly `check` and `setup --request-file *`, and
  `nocklock doctor` reports the helper ok.

## Key Design Decisions
- See `.claude/decisions/` for Architecture Decision Records
- Go chosen for single-binary distribution and cross-platform support (ADR-001)
- MVP fences use userspace techniques, no root required (ADR-002). The
  Linux netns egress fence is the deliberate exception: it needs a root-owned
  helper reachable through a constrained NOPASSWD sudoers grant
- TOML config with strict parsing — unknown keys are errors (ADR-003)
- The netns setup request travels in a 0600 file named on argv, not on stdin,
  because sudo closes descriptors above 2 and the child must keep its stdin
  (ADR-004)

## Audit database: threat model and the validate-then-open window

`logging.NewLogger` (`internal/logging/logger.go`) validates the DB path
(`validatePath`) and then creates and opens it **by pathname**: `MkdirAll`,
`OpenFile(O_NOFOLLOW)` and `sql.Open("sqlite", dbPath)` each re-resolve the path
after validation. Validation and use are therefore not atomic (N10717).

**In scope (caught).** The static malicious-repo case: a checkout that commits
`.nock/events.db`, or any ancestor of it, as a symlink. Rejected: a symlink at the
final component (`lstat` plus `O_NOFOLLOW`, N8614, including a real DB replaced by
a symlink between sessions), and an ancestor that escapes the project root,
dangles, loops or cannot be canonicalized (`resolveDeepestExisting`, N10714).
`nocklock wrap` opens the DB before the fence is applied, so the repository
contents are the attacker-controlled input here.

**Out of scope (residual).** A concurrent writer running as the **same uid** that
swaps a validated ancestor, or the DB path, for a symlink between validation and
use (including after the inode re-check, before SQLite lazily opens the file). `TestResidual_AncestorSwapBetweenValidateAndOpen` demonstrates that such a
swap redirects the DB outside the project. We accept this because the racer must
already run as the user, and that process already owns everything the swap could
protect: it can read and write `.nock/events.db` directly, read the Ed25519
signing key at `~/.config/nocklock/signing-ed25519.key`, replace the config or
the binary, and ptrace NockLock. A different uid can swap an entry only where it
can write the parent directory, so this holds while the project root and its
ancestors are not group- or world-writable (a shared checkout under `/tmp` or a
shared group directory is outside that assumption). The fenced child of the
current `wrap` is not the racer: it starts after `NewLogger` returns, and for the
default `.nock/events.db` location the filesystem fence denies it the audit
directory. A same-uid process that outlives an earlier session, or a child on a
platform or mode where the fence is not enforced, is the residual case.

**Why not close it in code.** An `os.Root`/`openat` walk from the project root is
not enough on its own: SQLite reopens the database, and its `-wal`/`-shm`
siblings, by pathname. On Linux, keeping the validated directory descriptor open
for the Logger's lifetime and opening `/proc/self/fd/<dirfd>/events.db` does work
with WAL (verified with `modernc.org/sqlite`). macOS has no equivalent, and a
symlink swapped in at the final component would still be followed. That is a
Linux-only mitigation for a race we do not defend against, so it is not built. If
the threat model ever includes a same-uid racer, start from that Linux path;
macOS keeps a documented residual window.

## Diagrams
- `.claude/diagrams/architecture.mermaid` — package dependencies
- `.claude/diagrams/fence-flow.mermaid` — config → fences → child process
- `.claude/diagrams/event-flow.mermaid` — events → SQLite → cloud sync
