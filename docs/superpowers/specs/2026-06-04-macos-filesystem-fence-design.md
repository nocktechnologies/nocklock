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

This maps **directly** onto NockLock's model:

```scheme
(version 1)
(deny default)                         ; fail-closed: deny everything not explicitly allowed
(allow process*)                       ; the agent itself runs normally
(allow file-read* file-write*          ; full perms INSIDE the fence
    (subpath "/Users/<u>/project"))
(allow file-read*                      ; read-only system paths the toolchain needs
    (subpath "/usr") (subpath "/bin") (subpath "/System") (literal "/dev/null"))
; everything else — ~/.ssh, ~/.aws, ~/.config — is denied by (deny default)
```

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

## Build increment (scoped, for dispatch)

Phase 1 — macOS enforcement (this PR's follow-on build):
- `internal/fence/fs/fence_darwin.go`: `IsSupported()` true on darwin; compile `[filesystem].allow` → SBPL profile; build `sandbox-exec -p <profile> --` argv wrapper.
- `internal/fence/fs/sbpl.go`: pure, table-tested SBPL profile generator (subpath escaping, default-deny, required system read paths).
- `internal/cli/wrap.go`: on darwin, wrap the child argv with `sandbox-exec` instead of injecting `LD_PRELOAD`.
- Fail-closed: if `sandbox-exec` is absent or the profile is rejected, the agent does not start (mirror the network-fence health gate).
- Tests: SBPL generation (pure, cross-platform CI) + darwin integration test asserting a denied path returns an error and an allowed path succeeds (gated on `GOOS == darwin`).
- Docs: update README ("macOS support coming") → supported-with-caveats; note deprecation + partial event logging.

Phase 2 — event logging via `log stream` parsing (best-effort).
Phase 3 — Endpoint Security system extension (separate epic).

---

## Open questions for approval

1. **Ship interim on a deprecated API?** Recommendation: yes — Seatbelt is still functional and used widely; the alternative is no macOS fence at all. Pin + CI-test per OS version.
2. **Event logging:** accept partial parity for v1 (recommended) or block on `log stream` parsing first? Recommendation: accept partial; enforcement is the guarantee.
3. **System read allowlist:** how broad a default `(subpath "/usr") (subpath "/System")` etc. before agent toolchains break? Needs an empirical pass with a real `claude` run under the profile.
