# ADR-005: grandchild `/proc/self` reads stay denied — accepted limitation

**Status:** Accepted
**Date:** 2026-09-27
**Author:** Beck (AI builder), N10764

## Context
#10757 gave a wrapped Node agent its own procfs reads under the hardened
claude-code posture (Landlock + seccomp required + LD_PRELOAD interposer):
`os.cpus()` reads the system-wide `/proc/cpuinfo`, `/proc/stat`, `/proc/meminfo`
(granted in the preset), and `process.memoryUsage()` reads `/proc/self/stat`,
granted by `landlockProcSelfAllowPaths()` (wrap.go) plus its interposer companion
`allowSelfProcFS()` (landlock_exec.go). Both grant only the curated files in
`fsfence.SelfProcFiles()` (`stat`, `status`, `statm`), never the `/proc/<pid>`
directory.

That fix reaches exactly the **direct** wrapped child. The `__landlock-exec` shim
builds the Landlock ruleset and then `execve`s the child *in place* (same pid), so
each literal `/proc/self/<file>` rule binds to a file inode inside what becomes
the child's own `/proc/<pid>`. Landlock is **inode-bound**: the rule covers those
files, not a descendant's own `/proc/<gcpid>/<file>`.

#10764 is the measured consequence: a Node subprocess spawned by the wrapped Node
agent (an MCP server, a tool — a *grandchild* that execs under a new pid) calls
`process.memoryUsage()` and gets `EACCES: uv_resident_set_memory`. A
`CGO_ENABLED=0` raw-syscall reader (which bypasses the interposer) exec'd as a
grandchild is likewise `DENIED` its own `/proc/self/stat` while the direct child
reads it fine — proving the denial is **Landlock, not the interposer**.
`os.cpus()` is unaffected tree-wide, because the three system files it reads are
granted by path, not pid-scoped.

## Decision
**Accept the limitation. Do not widen the fence to reach grandchildren.** Only the
directly wrapped process gets its own `/proc/self`; a descendant that execs under
a new pid cannot read its own `/proc/self/stat` and `process.memoryUsage()` will
throw `EACCES` there. This is documented in code
(`landlockProcSelfAllowPaths` doc comment) and pinned by
`TestLandlockProcSelfAllowPathsStaysNarrow`, which asserts the grant stays one
read-only literal `/proc/self/<file>` entry per curated file, and
`TestSelfProcFilesExcludesSecretBearingEntries`, which asserts the curated list
never names `environ`/`cmdline`/`mem`/`maps`/`fd` or the directory itself, so a
future "fix" cannot silently widen it to a directory or the broad `/proc` tree.

## Rationale — the options considered, and why each fails
Every path that would reach grandchildren was assessed against the fence's core
guarantees. None is both effective and consistent with the posture.

- **Broad `/proc/` grant — rejected.** Re-opens the same-UID sibling
  `/proc/<pid>/environ` (and `/cmdline`) read that #115 removed. Trading a
  cross-process secret leak for a diagnostic convenience is a net regression.
  `TestClaudeCodePresetGrantsProcSystemFiles` and
  `TestWrapClaudeCodePresetBlocksSiblingProcEnviron` guard against exactly this.

- **Interposer-self (make `libfence_fs.c` intrinsically allow `/proc/<getpid()>`
  in every process) — ineffective end-to-end.** The interposer is a userspace
  LD_PRELOAD layer; Landlock is in the kernel and is evaluated regardless. The
  isolation measurement above (raw-syscall grandchild, no libc, still `DENIED`)
  is the proof: the interposer can never *widen* what Landlock permits.

- **Have the interposer add a per-process Landlock rule at startup — impossible
  by construction.** Landlock rulesets only ever compose by **intersection**: a
  thread's effective policy is every ruleset restricting it, ANDed together.
  `landlock_restrict_self` can only narrow, never re-grant. A descendant cannot
  add back access its parent's ruleset already denies. No one should later attempt
  to "layer a ruleset" to fix this — it cannot work.

- **Per-process PID namespace + fresh `/proc` mount (so `/proc/self` resolves
  per-namespace) — the only *real* fix, and infeasible here.** Three
  host-independent blockers, any one of which is disqualifying:
  1. **It breaks the exec model that makes #10757 correct at all.**
     `unshare(CLONE_NEWPID)` does not move the caller into the new namespace — it
     only affects children created *after*. Getting a per-namespace `/proc/self`
     requires **fork**, abandoning the shim's in-place `execve` (the very property
     that binds `/proc/self` to the child's real pid) and taking on PID-1 duties:
     orphan reaping, and signal + exit-code forwarding for the whole tree.
  2. **It hands the tree namespaced root.** A per-process PID namespace non-root
     needs `CLONE_NEWUSER`. That is precisely the namespace-creation / LPE surface
     that the syscall fence's `allow_namespaces=false` posture exists to deny.
     Creating a user namespace to satisfy a memory-stats read inverts the fence's
     purpose. (Even with `allow_namespaces=true`, the FS-mount primitives —
     `mount`, `pivot_root`, `move_mount`, … — stay denied unconditionally in the
     baseline, so a *fenced* process can never mount its own `/proc`; only a
     pre-fence shim could, which lands back on blockers 1 and 2.)
  3. **It inherits the privileged-helper lifecycle.** Per ADR-004, namespace
     setup on this platform runs through a fixed-vector `sudo` helper, not inline
     in the unprivileged `wrap`. A PID-namespace route would need that whole
     lifecycle (a new sudoers vector, the PID-1 sidecar, the request channel) —
     a large architectural change for a diagnostic call.

## Feasibility measurement (one host data point)
On the reference host (Linux 7.0.0, `apparmor_restrict_unprivileged_userns=1`),
unprivileged user-namespace creation is refused at the `uid_map` write:

```
$ unshare --user --map-root-user echo ok
unshare: write failed /proc/self/uid_map: Operation not permitted
```

So the namespace route does not even start non-root here. This is one data point,
not the load-bearing argument — the architectural blockers above hold on every
host regardless of this sysctl.

## Consequences
- **Accepted scope:** `process.memoryUsage()` works for the directly wrapped Node
  agent and throws `EACCES` in Node subprocesses it spawns. Well-behaved tooling
  treats `process.memoryUsage()` as best-effort telemetry; a tool that hard-fails
  on it is affected in the wrapped tree and must guard the call.
- **`os.cpus()` is unaffected tree-wide** (system-file grants, not pid-scoped), so
  worker-pool sizing is correct for grandchildren.
- **Security posture is unchanged and the narrowness is now pinned:** the #115
  sibling-`environ` block stays green, and a regression test asserts
  `landlockProcSelfAllowPaths()` returns exactly one read-only
  `/proc/self/<file>` per `SelfProcFiles()` entry, so the grant cannot be
  quietly widened to a directory or `/proc` while "resolving" this.
- **Revisit trigger:** if NockLock later adopts a privileged namespace helper for
  another reason (e.g. the persistent SCM_RIGHTS helper deferred in ADR-004), a
  per-tree PID namespace with a fresh `/proc` becomes reachable and this decision
  should be reconsidered as a rider on that work — not before.
