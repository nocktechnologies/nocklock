# 013: `claude-code` preset passes `CLAUDE_CODE_OAUTH_TOKEN`

**Status:** Accepted, shipped v0.7.0 (`CHANGELOG.md:17`, `:27`).

**Context.** The macOS fence denies the login keychain, so Claude Code's login must arrive through the environment, and the default secret fence blocked `*_TOKEN*`.

**Decision.** The preset drops the `*_TOKEN*` block pattern and adds `CLAUDE_CODE_OAUTH_TOKEN` to `secrets.pass` (block outranks pass). `pass` is an allowlist, so other tokens stay stripped. The keychain stays closed. `wrap` prints a one-line hint, never a value, when `claude` starts on macOS with neither credential reaching the child.

**Consequences.** Configs created by an earlier `init` keep the old lists because `init` never overwrites; the upgrade steps are in `CHANGELOG.md:27`.
