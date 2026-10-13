# Audit log

Citations name source files at `v0.9.0` (`f2b0d04`) (no line numbers, so they do not go stale). Wording of limits follows `README.md` ("Tamper-evident audit log", "Signed audit log", "External chain-head anchor", "Event log").

## What is recorded
Most fence decisions are a row in a SQLite `events` table (`internal/logging/logger.go`): secret, file, network, proxy, session, config and filesystem-fence-state events (`logger.go`). Each row carries a SHA-256 hash linked to the previous row (v1). Query with `nocklock log`, `log --blocked`, `log --stats`, `status`. `log --prune <age>` compacts and re-anchors the chain (`internal/cli/log.go`, `logger.go`).

Not every crossing is logged. No row is written for: allowed file access; file denials that bypass the interposer (static binaries, raw syscalls, cleared `LD_PRELOAD`), so file denials are logged only some of the time; packets dropped by the kernel floor; `ADVISORY` proxy bypass; Linux `CONFINED` AF_UNIX connects.

## Layers
| Layer | What it adds | Does not give you |
|---|---|---|
| v1 hash chain | Detects altered, reordered or deleted rows | Protection from a writer who recomputes the whole chain and `chain_head` |
| v1.1 Ed25519 | Each row and the chain head are signed with a key outside the database, `~/.config/nocklock/signing-ed25519.key` (mode 0600) | Detection of rollback to an earlier, legitimately signed whole-database snapshot |
| v1.2 anchor | A signed `{version, agent_id, head_hash, row_count, created_at, sig}` stored elsewhere; shorter chain is `TRUNCATION` | Anything if the anchor sits next to `events.db` and the attacker swaps both |

`nocklock verify --audit` reports `AUTHENTIC` (signed, valid; printed on the machine that holds the signing key, or when `--ed25519-pub` is supplied), `CONSISTENT` (chain intact, unsigned or no key to check), `FORGED`, or `SUSPECT` (a signed check was required with `--ed25519-pub` but no signing artifacts exist) (`internal/cli/verify.go`). A chain that is not intact prints `TAMPERED`. Exit codes (`writeAuditVerifyResult` in `internal/cli/verify.go`): `AUTHENTIC` and `CONSISTENT` exit `0`; `TAMPERED`, `FORGED` and `SUSPECT` exit `1`. `CONSISTENT` is a pass with no authenticity claim. A passing check means the stored rows are internally consistent; it does not prove NockLock recorded them unless signed and checked with the public key (`verify --export-pubkey`).

Anchors use a distinct domain-separation byte (`0x05`; rows `0x01`, head `0x03`) (`internal/logging/anchor.go`). `nocklock anchor emit` writes one; `wrap` emits `chain-anchor.json` beside the log on teardown. With `NOCKLOCK_ANCHOR_URL` set, `wrap` pushes it off-box under a 5-second timeout and fail-open (`internal/cli/anchor_push.go`); `verify --against-remote-anchor` fetches the latest (`internal/anchorclient/client.go`). The NockCC server answers 409 for a lower `row_count`, which makes local rollback observable. `pkg/receipt` verifies one session offline (`pkg/receipt/receipt.go`).

## Remote-anchor identity limit

The current anchor `agent_id` is only the signing key fingerprint (`internal/logging/anchor.go`); remote verification fetches by that fingerprint (`internal/cli/anchor_push.go`). The managed key is shared across projects, but their audit databases are separate chains. Off-box anchoring therefore requires **one audit chain per identity in a given store**. Two projects using the same key can collide: the shorter chain's push can be rejected as a row-count regression, and verification can report `TRUNCATION` or `TAMPERED` against the other project's anchor even though neither local log changed. Multi-project remote anchoring with a shared identity is unsupported pending a versioned chain namespace. Local `verify --audit` is unaffected.

## Where the log lives
Outside the project: `$XDG_STATE_HOME/nocklock/<project-key>/` (or `~/.local/state/nocklock/<project-key>/`). The filesystem fence grants the project root and Landlock cannot exclude a path beneath a grant, so a log inside the project would be editable by the agent. An existing `.nock/events.db` stays where it is (the README explains why NockLock does not move it). Path resolution fails closed (`internal/config/state.go`); `wrap` refuses to start when `logging.db` resolves to the project root. Decision record: `docs/decisions/010-audit-state-outside-project.md`.

## Replacing the signing key
Use this when the managed key (`~/.config/nocklock/signing-ed25519.key`, or under `$XDG_CONFIG_HOME`) may have been read by something other than NockLock. There is no `rotate` command; the procedure below uses `mv` and `verify --export-pubkey`.

**What happens if you only move the key aside** (observed on Linux, v0.9.0 source plus #187):
- `wrap` refuses to start: `failed to load signing key: lstat ...: no such file or directory`. It does not fall through to unsigned logging.
- `nocklock verify --export-pubkey` creates a new key when none exists. After that, `wrap` still refuses: `audit log signing key does not match the adopted public key fingerprint; refusing to write`.
- `verify --audit` against the old log with the new key reports `FORGED` (`chain_head signing public key fingerprint does not match the supplied key`), exit `1`. Rows signed by the old key are not wrong; they are being checked against the wrong key.

So the old log and the new key cannot share a database. The log must be archived and a new one started. The key is per user, not per project: every project's log under `$XDG_STATE_HOME/nocklock/` has adopted the old key's fingerprint, so repeat steps 3 and 6 for each project you still use.

**Procedure**
1. Record the old public key off-box, before changing anything: `nocklock verify --export-pubkey > old.pub`. It is a public key; keep it somewhere the agent cannot write. Without it you cannot check old rows once the old key file is gone.
2. Stop running wrapped sessions.
3. Archive each project's log. Use `umask 077` (NockLock refuses state directories that are group- or world-writable) and keep the `<root>/nocklock/<project-key>/` layout; `nocklock status` prints the `Event log:` path. Move the database file named there (`events.db` by default; a project with `logging.db = "audit.db"` keeps `audit.db`), its `-wal` and `-shm` sidecars if present, and `chain-anchor.json`, each by name, into `<archive-root>/nocklock/<project-key>/`. Keep the same filename in the archive so the `verify` commands below find it.
4. Move the old key aside by name: `mv "${XDG_CONFIG_HOME:-$HOME/.config}/nocklock/signing-ed25519.key" <somewhere-private>/old-signing-ed25519.key` (`verify --export-pubkey` and `wrap` resolve the key from the same `XDG_CONFIG_HOME`, so run every step in one environment). Once the exposure is dealt with, remove that file by its exact path; the old public key is enough to verify old rows.
5. Create the new key and record its public half: `nocklock verify --export-pubkey > new.pub`.
6. Run `nocklock wrap` as usual. It opens a new log and adopts the new key.

**Checking later**
- New rows: `nocklock verify --audit --ed25519-pub "$(cut -d' ' -f2 new.pub)"` prints `AUTHENTIC`.
- Old rows: point `XDG_STATE_HOME` at the archive root (its `nocklock/` directory and the project directory must be mode 0700): `XDG_STATE_HOME=<archive-root> nocklock verify --audit --ed25519-pub "$(cut -d' ' -f2 old.pub)"` prints `AUTHENTIC`. The same command with the new key, or with no `--ed25519-pub`, prints `FORGED`. `XDG_STATE_HOME=<archive-root> nocklock verify --against-anchor <archive-root>/nocklock/<project-key>/chain-anchor.json --ed25519-pub "$(cut -d' ' -f2 old.pub)"` prints `ANCHOR: OK`.

**Limits**
- Replacing the key does not repair history. Rows signed while the key was exposed no longer prove the agent did not write them (see the v0.9.1 CHANGELOG entry). `AUTHENTIC` against the old key only proves the rows were signed by whoever held it.
- The new log is a fresh chain. Nothing binds it to the archived one, so deleting the archive is undetectable from the new log.
- If you push anchors with `NOCKLOCK_ANCHOR_URL`, the receiving server was given the old public key with each anchor. How a server treats the new key was not tested.

## Forwarding to Command (opt-in)
`[audit.forward]` sends committed decisions to Command's ops log from a bounded, non-durable queue (`internal/forward/forward.go`). Failures never change a decision or remove a local row. Both the URL and the key come from the operator environment.

## Honest limits
- Not externally anchored by default; v1 is tamper-evident, not an unforgeable receipt.
- macOS records per-file denials best-effort (`filesystem-fence.md`). The HTTP proxy ignores audit-write errors on the allow path, while the netns path fails closed (`docs/design/look-back-rules.md` section 1, item 5).
- Allowed file reads are never logged, only denials.
- `--prune` removes history and invalidates earlier anchors; `verify` prints a `NOTE`.

## Tests
`internal/logging/*_test.go`, `internal/cli/verify_test.go`, `verify_signing_test.go`, `audit_state_*_test.go`, `anchor_*_test.go`, `internal/anchorclient/client_test.go`, `pkg/receipt/*_test.go`.
