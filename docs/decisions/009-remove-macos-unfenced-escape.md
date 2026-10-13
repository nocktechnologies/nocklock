# 009: Remove the macOS `macos_allow_unfenced` escape hatch

**Status:** Accepted, breaking, shipped v0.6.0 (`CHANGELOG.md`).

**Context.** v0.5.0 let a config opt out of the Seatbelt fence when it could not be applied, and announced the key as temporary.

**Decision.** `wrap` always records `REFUSED-TO-START` and does not launch the child when Seatbelt cannot be set up. `macos_allow_unfenced = true` fails to load; `= false` is still accepted.

**Consequences.** Fences fail closed on macOS with no override. v0.6.1 extended the rule: `syscall.enforcement = "required"` with an empty `filesystem.root` also refuses to start (`CHANGELOG.md`).
