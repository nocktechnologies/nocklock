# Decisions

One short record per major decision. Records 001-005 predate this directory and stay in `.claude/decisions/` so there is one source of truth; 006 onward live here. Add a new record as the next number with status, context, decision and consequences, and cite code or `CHANGELOG.md` for every claim.

| # | Decision | Where |
|---|---|---|
| 001 | Go, not Rust | `.claude/decisions/001-language-go.md` |
| 002 | Fence approaches (interposer, proxy, secret filter) | `.claude/decisions/002-fence-approaches.md` |
| 003 | TOML config with strict parsing | `.claude/decisions/003-config-format-toml.md` |
| 004 | netns setup request travels in a file, not stdin | `.claude/decisions/004-netns-setup-request-channel.md` |
| 005 | Grandchild `/proc/self` reads stay denied | `.claude/decisions/005-grandchild-procfs-self-limitation.md` |
| 006 | Landlock is the Linux filesystem backend | `006-landlock-linux-filesystem-backend.md` |
| 007 | Audit log: hash chain, then signatures, then anchor | `007-audit-log-chain-signature-anchor.md` |
| 008 | Opt-in netns kernel egress fence | `008-netns-kernel-egress-fence.md` |
| 009 | Remove the macOS `macos_allow_unfenced` escape hatch | `009-remove-macos-unfenced-escape.md` |
| 010 | Audit state lives outside the project | `010-audit-state-outside-project.md` |
| 011 | Look-back rules narrow egress, `CONFINED` only | `011-lookback-rules-confined-only.md` |
| 012 | macOS Seatbelt network floor, level `SEATBELT` | `012-macos-seatbelt-network-floor.md` |
| 013 | `claude-code` preset passes the OAuth token | `013-claude-code-preset-passes-oauth-token.md` |
| 014 | Syscall fence is default-allow with a denylist | `014-seccomp-default-allow-denylist.md` |
