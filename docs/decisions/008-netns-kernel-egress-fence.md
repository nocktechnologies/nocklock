# 008: Opt-in network namespace fence for kernel-enforced egress

**Status:** Accepted, shipped v0.5.0 (`CHANGELOG.md`). Source: `docs/superpowers/specs/2026-07-30-linux-network-egress-enforcement.md`.

**Context.** The default proxy is advisory: a client that ignores `HTTP_PROXY` bypasses the allowlist.

**Decision.** `nocklock wrap --net-fence=netns` runs the child in a fresh network namespace behind an nftables default-drop floor, with a transparent HTTP(S) proxy and a DNS stub enforcing `network.allow`. Setup needs root, so a root-owned helper runs behind a constrained sudoers grant. The request travels in a 0600 file (`.claude/decisions/004-netns-setup-request-channel.md`). It is opt-in and fails closed without the helper.

**Consequences.** Strongest Linux egress (`KERNEL`), at the cost of a privileged install step. A complete, supported Linux install is a 1.0 item (`docs/ROADMAP.md`).
