# 007: Audit log is a hash chain, then signed, then anchored

**Status:** Accepted, shipped v0.5.0 (`CHANGELOG.md:563`, `:587`). Source: `docs/superpowers/specs/2026-09-14-tamper-evident-audit-log.md`.

**Context.** The event log was a plain table; anyone with file access could flip a `blocked` row to `passed` or truncate the tail.

**Decision.** v1 SHA-256 hash chain; v1.1 Ed25519 signatures over rows and the chain head with a key kept outside the database; v1.2 a signed chain-head anchor that can be pushed off-box. `verify` reports four states and never conflates them: `AUTHENTIC`, `CONSISTENT`, `FORGED`, `SUSPECT`. The off-box push is fail-open so a network failure never stops an agent.

**Consequences.** A keyless chain cannot resist a writer who recomputes it; a signed chain cannot detect rollback of the whole database; only an off-box anchor can. Without one, the log is tamper-evident, not an unforgeable receipt. See `docs/how-it-works/audit-log.md`.
