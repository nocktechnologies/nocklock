# Secret fence

Citations name source files at `v0.9.0` (`f2b0d04`) (no line numbers, so they do not go stale).

## What it does
`wrap` filters the child's environment against `secrets.pass` and `secrets.block`, both glob lists, before the child starts (`internal/cli/wrap.go`; matcher `internal/fence/secrets/secrets.go`). A blocked variable is gone from the child's environment, so the secret fence is absolute for what it covers. Removed names are recorded as individual `secret_blocked` rows; passed names are grouped in a `secret_passed` row (`internal/logging/logger.go`). Linux and macOS.

## Rules that surprise people
- **Block outranks pass.** Adding a name to `secrets.pass` does not help while a `secrets.block` pattern still matches it. Remove the pattern, then add the exact name.
- **A non-empty pass list is an allowlist.** Names that match no pass pattern are stripped. An explicitly empty `pass = []` instead passes every variable that is not blocked; it does not mean "pass nothing". Matching is case-insensitive.
- **`claude-code` preset** drops the `*_TOKEN*` block so `CLAUDE_CODE_OAUTH_TOKEN` can pass; other tokens stay stripped (`CHANGELOG.md`, test `TestClaudeCodePresetPassesOAuthToken` in `internal/cli/wrap_claude_keychain_hint_test.go`). `init` never overwrites an existing config, so a config written by v0.6.x keeps the old lists (`CHANGELOG.md`).
- **Operator credentials are always stripped.** `NOCKLOCK_ANCHOR_URL`, `NOCKLOCK_ANCHOR_TOKEN`, `NOCKLOCK_FORWARD_URL`, `NOCKLOCK_FORWARD_KEY` never reach the child, whatever the config says (README, "Off-box anchor push" and "Forward fence decisions").

## Honest limits
- It filters the environment only. It does not stop the agent reading a secret from a file; that is the filesystem fence (`filesystem-fence.md`) and, before launch, the preflight scan (`secret-preflight.md`).
- It matches names, not values. A secret stored under an allowed name (or an unblocked name when `pass = []`) passes through. Secrets in command arguments are not filtered.
- Pattern defaults are in `README.md` "Configuration" and `internal/config/defaults.go`.

## Tests
`internal/fence/secrets/secrets_test.go`; preset behaviour in `internal/config/profiles_test.go` and `internal/cli/wrap_claude_keychain_hint_test.go`.
