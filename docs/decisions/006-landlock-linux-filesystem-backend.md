# 006: Landlock is the Linux filesystem backend

**Status:** Accepted. Source: `docs/superpowers/specs/2026-06-11-linux-landlock-fence-design.md`; `README.md` "Philosophy".

**Context.** ADR-002 chose `LD_PRELOAD` interposition for the filesystem fence. A userspace interposer fails open against a determined process (static binaries, raw syscalls, a cleared `LD_PRELOAD`).

**Decision.** On Linux the kernel enforces a Landlock root allowlist; the interposer stays as the event reporter and the proxy bridge. The two compose: a denied static binary is still denied by the kernel, it just produces no event.

**Consequences.** Landlock is inode-bound and cannot exclude a path beneath a granted directory, which drives decisions 010 and `.claude/decisions/005-grandchild-procfs-self-limitation.md`. Code: `internal/fence/fs/landlock/`.
