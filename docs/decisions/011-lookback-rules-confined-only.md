# 011: Look-back rules only narrow egress, and only at `CONFINED`

**Status:** Accepted, slice 1 shipped v0.7.0 (`CHANGELOG.md`). Source: `docs/design/look-back-rules.md`.

**Context.** Policy over the event history ("a file open was denied, so refuse the next outbound request") needs a trigger the kernel guarantees was observed.

**Decision.** `[[network.lookback]]` supports `on = "file_blocked"` and `then = "deny_egress"`. A rule never adds an allow. `wrap` refuses to start with a rule unless the egress level is `CONFINED` (`internal/cli/egress_level.go`); `SEATBELT` and the rest are refused. Rule names are restricted so the name is safe in a signed denial row.

**Consequences.** Static binaries, raw syscalls and a cleared `LD_PRELOAD` bypass the interposer and never trip a rule. Allowed reads are not logged, so the only trigger is a denial.
