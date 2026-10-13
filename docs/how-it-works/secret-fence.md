# Secret fence

Citations are `file:line` at `origin/main` 89c02fa.

## What it does
`wrap` filters the child's environment against `secrets.pass` and `secrets.block`, both glob lists, before the child starts (`internal/cli/wrap.go:242-247`; matcher `internal/fence/secrets/secrets.go:19,42,76`). A blocked variable is gone from the child's environment, so the secret fence is absolute for what it covers. Each filtered name is recorded as `secret_blocked` or `secret_passed` (`internal/logging/logger.go:28-29`). Linux and macOS.

## Rules that surprise people
- **Block outranks pass.** Adding a name to `secrets.pass` does not help while a `secrets.block` pattern still matches it. Remove the pattern, then add the exact name.
- **Pass is an allowlist.** A variable not in `pass` is stripped.
- **`claude-code` preset** drops the `*_TOKEN*` block so `CLAUDE_CODE_OAUTH_TOKEN` can pass; other tokens stay stripped (`CHANGELOG.md:27`, test `TestClaudeCodePresetPassesOAuthToken` in `internal/cli/wrap_claude_keychain_hint_test.go`). `init` never overwrites an existing config, so a config written by v0.6.x keeps the old lists (`CHANGELOG.md:27`).
- **Operator credentials are always stripped.** `NOCKLOCK_ANCHOR_URL`, `NOCKLOCK_ANCHOR_TOKEN`, `NOCKLOCK_FORWARD_URL`, `NOCKLOCK_FORWARD_KEY` never reach the child, whatever the config says (README, "Off-box anchor push" and "Forward fence decisions").

## Honest limits
- It filters the environment only. It does not stop the agent reading a secret from a file; that is the filesystem fence (`filesystem-fence.md`) and, before launch, the preflight scan (`secret-preflight.md`).
- It matches names. A secret stored under an unlisted name, or passed in argv, is not touched.
- Pattern defaults are in `README.md` "Configuration" and `internal/config/defaults.go`.

## Tests
`internal/fence/secrets/secrets_test.go`; preset behaviour in `internal/config/profiles_test.go` and `internal/cli/wrap_claude_keychain_hint_test.go`.
