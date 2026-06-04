# macOS Filesystem Fence Design — NockLock

**Date:** 2026-06-04
**Status:** Draft (awaiting approval)
**Author:** Mira (CEO, Consumer/Product)
**Branch:** `docs/macos-fs-fence-spec`

---

## Why this spec exists

The filesystem fence is the only NockLock fence that does **not** work on macOS. `internal/fence/fs/fence.go` hard-gates `IsSupported()` to `runtime.GOOS == "linux"` and returns *"filesystem fence is not supported on %s (requires Linux LD_PRELOAD); macOS support coming soon."* The secret fence and network fence already run cross-platform.

NockLock ships via Homebrew (`brew install nocktechnologies/tap/nocklock`), so the largest slice of the audience is on macOS — and for them the headline "Filesystem Fence" silently degrades to a no-op with an error. For a security tool, a fence that isn't there is the worst kind of gap: the user believes `~/.ssh/` is protected and it is not. Closing it is the single highest-value increment for the product right now.

This spec makes the one decision that actually blocks the build: **which interception mechanism replaces LD_PRELOAD on macOS.** Everything else (config plumbing, tests, packaging) follows the existing Linux fence's shape.

---

## Requirements (inherited from the Linux fence)

The macOS fence must preserve NockLock's model:

1. **Fence, not guardrails.** The agent runs with full permissions *inside* the fence; we constrain only what it can reach.
2. **Declarative allowed paths.** Driven by the same `[filesystem]` config the Linux fence uses (project dir allowed; `~/.ssh/`, `~/.aws/`, etc. blocked).
3. **Fail-closed.** If the fence cannot be confirmed active, the agent must not start — matching the network fence's "proxy not healthy → agent does not start" rule. A fence that fails *open* is unacceptable.
4. **Deny semantics.** Blocked reads should surface as a permission error, not data.
5. **Event logging.** Blocked accesses should be recorded to `.nock/events.db` (the logging package already exists).

---

## Mechanism options considered

### Option A — `DYLD_INSERT_LIBRARIES` + dyld interposing (the literal LD_PRELOAD analog)

macOS's equivalent of `LD_PRELOAD` is `DYLD_INSERT_LIBRARIES` with `__attribute__((used)) __interpose`. It is the smallest conceptual delta from the existing Linux interposer.

**Rejected as primary.** It fails-open in exactly the cases that matter:
- **SIP strips `DYLD_*`.** System Integrity Protection removes all `DYLD_*` environment variables when a *protected* or *platform* binary is exec'd (anything under `/bin`, `/usr/bin`, `/System`, and most Apple-signed binaries). AI agent toolchains constantly shell out to `/bin/sh`, system `python3`, `/usr/bin/env`, etc. The moment execution crosses one of those, the interposer is dropped — **silently** — and the fence is gone for that subtree.
- **Library validation / hardened runtime.** Signed targets with library validation refuse to load an unsigned (or differently-signed) inserted dylib.
- **Per-arch + notarization burden** for the inserted dylib.

The combination means the user cannot trust the fence is on. That is disqualifying for a security boundary.

### Option B — Seatbelt / `sandbox-exec` profiles  ✅ DETERMINATION (interim)

macOS ships the Seatbelt sandbox (the same engine behind App Sandbox and Chrome's renderer sandbox). `sandbox-exec -p '<profile>' -- <agent>` runs an arbitrary child under a sandbox profile written in **SBPL** (Scheme-like Sandbox Profile Language).

**Interim profile shape (empirically validated 2026-06-04 — see below):**

```scheme
(version 1)
(allow default)                        ; allow-default base (see "deny-default SIGABRTs")
(deny file-read* file-write*           ; fence the sensitive paths (canonical realpaths!)
    (subpath "/Users/<u>/.ssh")
    (subpath "/Users/<u>/.aws")
    (subpath "/Users/<u>/.config")
    ...)                               ; from [filesystem] block / sensible defaults
```

This is a **denylist** (default-allow, block sensitive), not the strict allowlist the Linux fence uses (default-deny, allow project). The spike below shows **why**: a true `(deny default)` allowlist `SIGABRT`s every process — even `/bin/echo` — because process/dyld startup needs more allows than are practical to enumerate from scratch. The denylist is the shippable interim; strict-allowlist parity comes with Option C (Endpoint Security). This divergence is documented, not hidden (see "Known caveats").

**Why it wins:**
- **No code injection.** The kernel enforces the policy on the child *and all its descendants*, so the `/bin/sh` → child → grandchild problem that kills Option A does not exist. The sandbox is inherited, not env-propagated.
- **Fails closed.** `(deny default)` + explicit allowlist is precisely the fence semantics.
- **Declarative, generated from config.** We compile `[filesystem].allow` into `(subpath ...)` allow rules — same input the Linux fence already parses.
- **Ships today**, no entitlement, no system extension, no root, no notarized kext/sysext.

**Known caveats (must be documented to the user, not hidden):**
- **`sandbox-exec` is deprecated** by Apple (man page says so) but remains present and functional on current macOS (Chrome, many tools still rely on Seatbelt). Treat as interim; track Apple removal.
- **SBPL is officially undocumented/unstable.** We pin a conservative, well-trodden profile shape and test it per-OS-version in CI.
- **Error semantics differ.** The Linux fence carefully returns `ENOENT` on stat-family probes to avoid existence enumeration and `EACCES` on opens. Seatbelt returns its own denial errors and we cannot perfectly replicate the ENOENT-anti-enumeration behavior. **Document this as a known divergence**, not a silent one.
- **Event-logging parity is partial (see below).**

### Option C — Endpoint Security framework (ES)

The supported, modern, durable path: a notarized **system extension** holding `com.apple.developer.endpoint-security.client` (Apple-approved entitlement), running with user approval, subscribing to `AUTH_OPEN`/`AUTH_EXEC` events and returning allow/deny.

**Long-term target, not interim.** It gives true, supported, fine-grained, loggable enforcement — but the distribution model is a notarized system extension with a managed entitlement and an install/approval UX, which is a different product surface from a Homebrew CLI. It is its own epic, not this increment.

---

## Recommendation

Ship **Option B (Seatbelt / `sandbox-exec`)** as the interim macOS filesystem fence now; pursue **Option C (Endpoint Security)** as the durable follow-up. Do **not** ship Option A — a fence that fails open under SIP is worse than an honest "not yet supported."

This gives macOS users real, kernel-enforced, fail-closed filesystem fencing immediately, with the deprecation and event-fidelity caveats stated plainly.

---

## Event logging on macOS (open tradeoff, decided)

The Linux fence streams blocked-access events to NockLock over a Unix socket from the LD_PRELOAD interposer. Seatbelt has no such callback — denials go to the unified system log as sandbox violations.

**Decision for the interim:** accept **enforcement-parity, partial event-parity.**
- v1 (this increment): the fence *enforces* fully; blocked-access events are best-effort via parsing `log stream --predicate 'sender == "Sandbox"'` for the child, or simply omitted with a clear `status` note that per-file deny events are Linux-only for now. Enforcement is the security guarantee; logging is the accountability nicety. Never let the logging gap block shipping the enforcement.
- v2: full event parity arrives naturally with Option C (ES emits authorizable events we already have a sink for).

This is a deliberate, documented reduction — not a silent one — consistent with NockLock's honesty posture.

---

## Empirical validation (2026-06-04, macOS 26.5 / sandbox-exec present)

Spiked the mechanism with `sandbox-exec -f <profile>` on real fixtures before committing the build. Results:

| Test | Result |
|------|--------|
| `(deny default)` + allow project/system from scratch | **`SIGABRT` (rc=134) on EVERY process**, even `/bin/echo` — startup needs more allows than practical to enumerate. Pure allowlist rejected for interim. |
| `(allow default)` + `(deny … (subpath <project-relative /tmp path>))` | **Failed open** — secret was readable. macOS canonicalizes `/tmp`→`/private/tmp`; the un-resolved subpath silently never matched. |
| `(allow default)` + `(deny … (subpath <REALPATH>))` | ✅ secret read → `rc=1 Operation not permitted`; project read → ok; `python3 --version` → ok; **access via the `/tmp` symlink alias also blocked** once the rule is canonical. |
| Same profile vs real `~/.ssh` | ✅ bare `ls ~/.ssh` works; fenced `ls ~/.ssh` → `Operation not permitted`. |

**Two findings that are now hard build requirements:**
1. **Interim is a denylist** (`allow default` + `deny` sensitive paths), not a strict allowlist — deny-default is not viable via raw SBPL. Documented divergence from the Linux fence.
2. **Path canonicalization is MANDATORY and fail-open if skipped.** The SBPL generator MUST resolve every path to its realpath (symlinks, `/tmp`→`/private/tmp`, `/var`→`/private/var`) before emitting `(subpath …)`. A non-canonical rule silently does not match → the fence fails open. This is the #1 correctness requirement and gets an explicit regression test.

---

## Build increment (scoped, for dispatch)

Phase 1 — macOS enforcement (validated above):
- `internal/fence/fs/sbpl.go`: pure, table-tested SBPL generator — emits `(allow default)` + `(deny file-read* file-write* (subpath <realpath>) …)` for each sensitive path. **MUST canonicalize every path (`filepath.EvalSymlinks` + `/tmp`,`/var` resolution) before emitting**; refuse/error on a path that can't be resolved (fail closed, never emit a non-canonical rule).
- `internal/fence/fs/fence_darwin.go`: `IsSupported()` true on darwin; build the profile from config sensitive-paths (with sane defaults: `~/.ssh`, `~/.aws`, `~/.config`, `~/.gnupg`, `~/Library/Keychains`, etc.); build the `sandbox-exec -f <profile> --` argv wrapper.
- `internal/cli/wrap.go`: on darwin, wrap the child argv with `sandbox-exec` instead of injecting `LD_PRELOAD`.
- Fail-closed: if `sandbox-exec` is absent or the profile is rejected, the agent does not start (mirror the network-fence health gate).
- Tests: SBPL generation incl. **a canonicalization regression test** (a `/tmp`-aliased path must emit the `/private/tmp` rule), pure + cross-platform in CI; darwin integration test asserting a denied path → `EPERM` and an allowed path succeeds (gated on `GOOS == darwin`).
- Docs: README "macOS support coming" → supported-with-caveats; state the denylist-vs-allowlist divergence + deprecation + partial event logging honestly.

Phase 2 — event logging via `log stream` parsing (best-effort).
Phase 3 — Endpoint Security system extension (separate epic) — restores strict allowlist + native event stream.

---

## Decisions (made 2026-06-04 — Kevin delegated "it's your project, take it and run")

1. **Ship interim on the deprecated `sandbox-exec`?** YES — present + functional on macOS 26.5, widely relied on; the alternative is no macOS fence. Pin + CI-test per OS version.
2. **Event logging:** accept partial parity for v1. Enforcement is the security guarantee; logging follows in P2/P3.
3. **Default sensitive-path denylist:** ship a curated default set (`~/.ssh`, `~/.aws`, `~/.config`, `~/.gnupg`, `~/Library/Keychains`, cloud/credential dotdirs) + user-extensible via config — rather than a fragile system-read allowlist. Validated that this leaves toolchains (`python3`, etc.) working.
