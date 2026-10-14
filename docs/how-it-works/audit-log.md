# Audit log

Citations name source files at the `v0.9.0` baseline (`f2b0d04`) and later changes listed in `CHANGELOG.md` (no line numbers, so they do not go stale). Wording of limits follows `README.md` ("Tamper-evident audit log", "Signed audit log", "External chain-head anchor", "Event log").

## What is recorded
Most fence decisions are a row in a SQLite `events` table (`internal/logging/logger.go`): secret, file, network, proxy, session, config and filesystem-fence-state events (`logger.go`). Each row carries a SHA-256 hash linked to the previous row (v1). Query with `nocklock log`, `log --blocked`, `log --stats`, `status`. `log --prune <age>` compacts and re-anchors the chain (`internal/cli/log.go`, `logger.go`).

Not every crossing is logged. No row is written for: allowed file access; file denials that bypass the interposer (static binaries, raw syscalls, cleared `LD_PRELOAD`), so file denials are logged only some of the time; packets dropped by the kernel floor; `ADVISORY` proxy bypass; Linux `CONFINED` AF_UNIX connects.

## Layers
| Layer | What it adds | Does not give you |
|---|---|---|
| v1 hash chain | Detects altered, reordered or deleted rows | Protection from a writer who recomputes the whole chain and `chain_head` |
| v1.1 Ed25519 | Each row and the chain head are signed with a key outside the database, `~/.config/nocklock/signing-ed25519.key` (mode 0600) | Detection of rollback to an earlier, legitimately signed whole-database snapshot |
| v1.2 anchor | A signed `{version, agent_id, head_hash, row_count, created_at, sig}` stored elsewhere; shorter chain is `TRUNCATION` | Anything if the anchor sits next to `events.db` and the attacker swaps both |

The managed signing key lives in `$XDG_CONFIG_HOME/nocklock/signing-ed25519.key` when `XDG_CONFIG_HOME` is set, otherwise under `~/.config/nocklock/`. `wrap` denies the resolved key directory to its child. `doctor` checks that directory against the effective Seatbelt deny set or Landlock read grants and reports its path and posture in `doctor --json`. A key under a Landlock grant, such as the project or `/tmp`, makes `wrap` refuse and `doctor` report a gap; a missing Seatbelt deny also prevents a `PROTECTED` verdict (`internal/cli/wrap.go`, `doctor.go`).

`nocklock verify --audit` reports `AUTHENTIC` (signed, valid; printed on the machine that holds the signing key, or when `--ed25519-pub` is supplied), `CONSISTENT` (chain intact, unsigned or no key to check), `FORGED`, or `SUSPECT` (a signed check was required with `--ed25519-pub` but no signing artifacts exist) (`internal/cli/verify.go`). A chain that is not intact prints `TAMPERED`. Exit codes (`writeAuditVerifyResult` in `internal/cli/verify.go`): `AUTHENTIC` and `CONSISTENT` exit `0`; `TAMPERED`, `FORGED` and `SUSPECT` exit `1`. `CONSISTENT` is a pass with no authenticity claim. A passing check means the stored rows are internally consistent; it does not prove NockLock recorded them unless signed and checked with the public key (`verify --export-pubkey`).

Anchors use a distinct domain-separation byte (`0x05`; rows `0x01`, head `0x03`) (`internal/logging/anchor.go`). `nocklock anchor emit` writes one; `wrap` emits `chain-anchor.json` beside the log on teardown. With `NOCKLOCK_ANCHOR_URL` set, `wrap` pushes it off-box under a 5-second timeout and fail-open (`internal/cli/anchor_push.go`); `verify --against-remote-anchor` fetches the latest (`internal/anchorclient/client.go`). The NockCC server answers 409 for a lower `row_count`, which makes local rollback observable. `pkg/receipt` verifies one session offline (`pkg/receipt/receipt.go`).

**Remote anchor limit:** The current anchor identifies a chain by its signing-key fingerprint (`agent_id`), and remote lookup uses that same fingerprint (`internal/logging/anchor.go`, `internal/cli/anchor_push.go`, `internal/anchorclient/client.go`). A remote store therefore supports only one chain per signing key. Two projects using the default managed key share this identity even though they have separate audit databases (`internal/config/state.go`). After the larger project's anchor is stored, the smaller project's valid push is rejected as a rollback, and its remote verification reports `TRUNCATION` (or `TAMPERED`) against the other project's anchor. Until the [chain identity design](../design/anchor-chain-identity.md) is implemented, use a separate anchor store per project, or provision a separate signing key per project by using distinct `XDG_CONFIG_HOME` values from the start (`internal/logging/signing.go`). Changing the key of an existing signed chain is not a workaround. Do not interpret that cross-project `TRUNCATION` or `TAMPERED` verdict as proof that the smaller database was rolled back.

The v2 record and local identity foundations are opt-in library APIs, not an
enabled v2 enrollment/network CLI. `InitializeChainIdentity` explicitly creates
a random ID in the external per-project state directory, mirrored in DB metadata;
`ReadChainIdentity` requires both copies to agree. The trusted record keeps
registration state outside rollbackable DB snapshots. `RegisterChainIdentity`
holds the same process-safe lock as prune, writes and syncs `pending` before its
request callback, and moves to `enrolled` only after exact-pair confirmation.
Every pending retry rewrites and syncs the record before sending again; finding
`pending` on disk does not prove the last directory sync succeeded. A
`ChainIdentityDurabilityError` means replacement committed but durability is
uncertain: preserve the visible state and retry, never restore `none`. A
pending-write failure sends no callback; an enrolled-write failure follows the
already-confirmed remote request and retains the previously durable pending
guard. File and directory barriers stop at the configured state root. State-root establishment separately refreshes its immediate owning-parent
barrier, including when already present; creating missing components syncs each
new entry before descending. Existence alone never proves a completed barrier.
Errors and interrupted requests never clear pending. The callback may read the
DB under that lock, but must not recursively call identity methods or prune.
Later network integration must preserve the original signed registration request
for retries and authenticate the store's confirmation.

Prune remains allowed for legacy chains and initialized identities in state
`none` when the logger has explicit project context. Rootless library callers
must supply that context: a rolled-back DB cannot prove that external state is
absent. The CLI already supplies the project root. Prune waits at most five
seconds for the shared identity lock and holds it through deletion; timeout,
pending/enrolled identities, missing records and mismatched metadata refuse
before changing rows.

With a filesystem fence enabled, `wrap` protects the canonical future trusted
state directory before any identity exists, including when `logging.db` points
inside the project. After any identity exists (`none`, `pending` or `enrolled`),
it also refuses an absent filesystem fence or Linux enforcement set to `off`.
On Linux, valid non-off modes (default, `preferred`, `required`) normalize to
`required`: absent Landlock, failed activation, or a deny beneath a broader grant
stops the child. Legacy sessions explicitly disabling the fence or setting Linux
enforcement to `off` retain their existing degraded behavior; they make no
kernel-backed trusted-state custody claim and should not precede enrollment of
state that an unfenced child could have modified. Follow the
[offline move procedure](../runbooks/chain-identity-move.md) when relocating a
project; never regenerate an ID to bypass a missing record. These local guards
do not resolve the remote one-chain-per-key limitation by themselves.

## Where the log lives
Outside the project: `$XDG_STATE_HOME/nocklock/<project-key>/` (or `~/.local/state/nocklock/<project-key>/`). The filesystem fence grants the project root and Landlock cannot exclude a path beneath a grant, so a log inside the project would be editable by the agent. An existing `.nock/events.db` stays where it is (the README explains why NockLock does not move it). Path resolution fails closed (`internal/config/state.go`); `wrap` refuses to start when `logging.db` resolves to the project root. Decision record: `docs/decisions/010-audit-state-outside-project.md`.

## Replacing the signing key
Use this when the managed key (`~/.config/nocklock/signing-ed25519.key`, or under `$XDG_CONFIG_HOME`) may have been read by something other than NockLock. There is no `rotate` command; the procedure below uses `mv` and `verify --export-pubkey`.

**What happens if you only move the key aside** (observed on Linux, v0.9.0 source plus #187):
- `wrap` refuses to start: `failed to load signing key: lstat ...: no such file or directory`. It does not fall through to unsigned logging.
- `nocklock verify --export-pubkey` creates a new key when none exists. After that, `wrap` still refuses: `audit log signing key does not match the adopted public key fingerprint; refusing to write`.
- `verify --audit` against the old log with the new key reports `FORGED` (`chain_head signing public key fingerprint does not match the supplied key`), exit `1`. Rows signed by the old key are not wrong; they are being checked against the wrong key.

So the old log and the new key cannot share a database. The log must be archived and a new one started. The key is per user, not per project: repeat steps 3 and 6 for every project using that key, including logs at absolute or legacy project-local paths.

**Procedure**
1. Record the old public key off-box, before changing anything: `nocklock verify --export-pubkey > old.pub`. It is a public key; keep it somewhere the agent cannot write. Without it you cannot check old rows once the old key file is gone.
2. Stop running wrapped sessions.
3. Archive each project's log while all wrapped sessions and other log writers remain stopped. From that project's directory, use `nocklock status` to find the resolved `Event log:` path; do not infer it from `logging.db`. Use `umask 077` and a separate private archive directory for each project. Record the original project path (`pwd -P` from its root), resolved DB path, and configured `logging.db` alongside the old public key so the archive stays associated with its project. Move the named DB, its `-wal` and `-shm` sidecars if present, and its sibling `chain-anchor.json` into that archive, each by exact name. Keep the DB's basename and matching sidecar names. This covers a bare filename, a custom basename, an absolute path, and an existing project-local path. Verify the archived copy using **Checking later** below before replacing the key or restarting sessions.
4. Move the old key aside by name: `mv "${XDG_CONFIG_HOME:-$HOME/.config}/nocklock/signing-ed25519.key" <somewhere-private>/old-signing-ed25519.key` (`verify --export-pubkey` and `wrap` resolve the key from the same `XDG_CONFIG_HOME`, so run every step in one environment). Once the exposure is dealt with, remove that file by its exact path; the old public key is enough to verify old rows.
5. Create the new key and record its public half: `nocklock verify --export-pubkey > new.pub`.
6. Run `nocklock wrap` as usual. It opens a new log and adopts the new key.

**Checking later**
- New rows: from the original project, `new_pub=$(cat /absolute/path/to/new.pub) && test -n "$new_pub" && nocklock verify --audit --ed25519-pub "$new_pub"` prints `AUTHENTIC`. Stop if reading the public key fails or it is empty.
- Old rows: use the private verification copy below. Changing only `XDG_STATE_HOME` does **not** redirect an absolute `logging.db`, and a surviving project-local log can take precedence over the archive. The CLI has no config override. A separate directory with its own minimal config avoids both cases without editing the live config.

Set these three absolute paths to one project's archived files, then run the block in a POSIX shell. The public-key file is the complete output of `verify --export-pubkey`. Copy the DB and any sidecars together; never copy a DB while a writer is active.

```sh
(
  set -eu
  umask 077
  archive_db='/absolute/path/to/project-archive/audit.db'
  archive_public_key='/absolute/path/to/project-archive/old.pub'
  archive_anchor='/absolute/path/to/project-archive/chain-anchor.json'

  archived_pub=$(cat "$archive_public_key")
  if [ -z "$archived_pub" ]; then
    printf 'Archived public key is empty; stop and recover the saved key.\n' >&2
    exit 1
  fi
  recovery_dir=$(mktemp -d "${TMPDIR:-/tmp}/nocklock-verify.XXXXXX")
  printf 'Verification workspace: %s\n' "$recovery_dir"
  mkdir "$recovery_dir/.nock"
  cp "$archive_db" "$recovery_dir/.nock/events.db"
  for suffix in -wal -shm; do
    if [ -f "$archive_db$suffix" ]; then
      cp "$archive_db$suffix" "$recovery_dir/.nock/events.db$suffix"
    fi
  done
  printf '[logging]\ndb = "events.db"\n' > "$recovery_dir/.nock/config.toml"
  cd "$recovery_dir"
  export XDG_STATE_HOME="$recovery_dir/state"
  nocklock verify --audit --ed25519-pub "$archived_pub"
  if [ -n "$archive_anchor" ]; then
    if [ ! -f "$archive_anchor" ]; then
      printf "Saved anchor not found at %s; fix the path, or set archive_anchor='' to skip the anchor check on purpose.\n" "$archive_anchor" >&2
      exit 1
    fi
    nocklock verify --against-anchor "$archive_anchor" \
      --ed25519-pub "$archived_pub"
  else
    printf 'Anchor check explicitly skipped: only the audit signature check was run.\n'
  fi
  printf 'Verification copy retained at %s\n' "$recovery_dir"
)
```

Expect `AUDIT: AUTHENTIC` (exit 0) and `ANCHOR: OK` (exit 0). A non-empty anchor path is required to exist; a missing or mistyped path exits 1. Only an intentional `archive_anchor=''` skips the anchor check, prints that only the audit signature check ran, and permits a signature-only exit 0. This checks a saved anchor file, not the remote store; current remote lookup remains tied to the signing-key fingerprint, not the scratch path. A saved anchor can legitimately disagree after pruning; preserve and investigate that result instead of generating a replacement anchor. The old rows checked with the new public key must report `FORGED` (exit 1). Always pass the archived public key explicitly; omitting it can select a different local key or give only an unsigned consistency verdict.

The scratch directory is only a verification workspace: never run `wrap`, `log --prune`, or `anchor emit` there. The copied signed rows, original config evidence, and v1 anchor identity (the signing-key fingerprint) remain unchanged. The scratch directory has a different path-derived state key; it does not become the original project or migrate its identity. Keep the archive inventory to identify the original project. Verification may create SQLite sidecars or update database metadata in the **copy**; the archived files and live config remain untouched. Retain or remove the scratch copy by its exact printed path when finished.

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
- On legacy chains, `--prune` removes history and invalidates earlier anchors;
  `verify` prints a `NOTE`. V2 local pending/enrolled state refuses prune.

## Tests
`internal/logging/*_test.go`, `internal/cli/verify_test.go`, `verify_signing_test.go`, `audit_state_*_test.go`, `anchor_*_test.go`, `internal/anchorclient/client_test.go`, `pkg/receipt/*_test.go`.
