# 010: Audit state lives outside the project

**Status:** Accepted, breaking, shipped v0.6.0 (`CHANGELOG.md`). User-facing text: `README.md` "Event log".

**Context.** The fence grants the project root so the agent can work there, and Landlock cannot exclude a path beneath a granted directory. A log inside the project is editable by the agent it records.

**Decision.** Fresh projects keep `events.db`, its sidecars and the chain anchor in `$XDG_STATE_HOME/nocklock/<project-key>/` (or `~/.local/state/nocklock/<project-key>/`). `wrap` refuses to start when a `filesystem.deny` path is inside the root, when the root is an ancestor of the state directory, when `logging.db` resolves to the project root, or when more than one chain exists. An existing `.nock/events.db` is kept in place, not moved.

**Consequences.** An in-place log restricts creating or removing entries directly in the root (README explains; `nocklock state migrate` is mentioned there as a future release). Code: `internal/config/state.go`.
