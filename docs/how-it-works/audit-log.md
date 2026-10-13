# Audit log

Citations are `file:line` at `origin/main` 89c02fa. Wording of limits follows `README.md` ("Tamper-evident audit log", "Signed audit log", "External chain-head anchor", "Event log").

## What is recorded
Every fence decision is a row in a SQLite `events` table (`internal/logging/logger.go`): secret, file, network, proxy, session, config and filesystem-fence-state events (`logger.go:27-41`). Each row carries a SHA-256 hash linked to the previous row (v1). Query with `nocklock log`, `log --blocked`, `log --stats`, `status`. `log --prune <age>` compacts and re-anchors the chain (`internal/cli/log.go:27`, `logger.go:988`).

## Layers
| Layer | What it adds | Does not give you |
|---|---|---|
| v1 hash chain | Detects altered, reordered or deleted rows | Protection from a writer who recomputes the whole chain and `chain_head` |
| v1.1 Ed25519 | Each row and the chain head are signed with a key outside the database, `~/.config/nocklock/signing-ed25519.key` (mode 0600) | Detection of rollback to an earlier, legitimately signed whole-database snapshot |
| v1.2 anchor | A signed `{version, agent_id, head_hash, row_count, created_at, sig}` stored elsewhere; shorter chain is `TRUNCATION` | Anything if the anchor sits next to `events.db` and the attacker swaps both |

`nocklock verify --audit` reports `AUTHENTIC` (signed, valid), `CONSISTENT` (chain intact, unsigned or no key to check), `FORGED`, or `SUSPECT` (a signed check was required with `--ed25519-pub` but no signing artifacts exist) (`internal/cli/verify.go:352,359`). Anything other than a clean pass exits non-zero. A passing check means the stored rows are internally consistent; it does not prove NockLock recorded them unless signed and checked with the public key (`verify --export-pubkey`).

Anchors use a distinct domain-separation byte (`0x05`; rows `0x01`, head `0x03`) (`internal/logging/anchor.go:43-45`). `nocklock anchor emit` writes one; `wrap` emits `chain-anchor.json` beside the log on teardown. With `NOCKLOCK_ANCHOR_URL` set, `wrap` pushes it off-box under a 5-second timeout and fail-open (`internal/cli/anchor_push.go:18,36`); `verify --against-remote-anchor` fetches the latest (`internal/anchorclient/client.go:114,154`). The NockCC server answers 409 for a lower `row_count`, which makes local rollback observable. `pkg/receipt` verifies one session offline (`pkg/receipt/receipt.go:136`).

## Where the log lives
Outside the project: `$XDG_STATE_HOME/nocklock/<project-key>/` (or `~/.local/state/nocklock/<project-key>/`). The filesystem fence grants the project root and Landlock cannot exclude a path beneath a grant, so a log inside the project would be editable by the agent. An existing `.nock/events.db` stays where it is (the README explains why NockLock does not move it). Path resolution fails closed (`internal/config/state.go`); `wrap` refuses to start when `logging.db` resolves to the project root. Decision record: `docs/decisions/010-audit-state-outside-project.md`.

## Forwarding to Command (opt-in)
`[audit.forward]` sends committed decisions to Command's ops log from a bounded, non-durable queue (`internal/forward/forward.go:43,66`). Failures never change a decision or remove a local row. Both the URL and the key come from the operator environment.

## Honest limits
- Not externally anchored by default; v1 is tamper-evident, not an unforgeable receipt.
- macOS records per-file denials best-effort (`filesystem-fence.md`). The HTTP proxy ignores audit-write errors on the allow path, while the netns path fails closed (`docs/design/look-back-rules.md` section 1, item 5).
- Allowed file reads are never logged, only denials.
- `--prune` removes history and invalidates earlier anchors; `verify` prints a `NOTE`.

## Tests
`internal/logging/*_test.go`, `internal/cli/verify_test.go`, `verify_signing_test.go`, `audit_state_*_test.go`, `anchor_*_test.go`, `internal/anchorclient/client_test.go`, `pkg/receipt/*_test.go`.
