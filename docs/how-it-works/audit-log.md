# Audit log

Citations name source files at the `v0.9.0` baseline (`f2b0d04`) and later changes listed in `CHANGELOG.md` (no line numbers, so they do not go stale). Wording of limits follows `README.md` ("Tamper-evident audit log", "Signed audit log", "External chain-head anchor", "Event log").

## What is recorded
Most fence decisions are a row in a SQLite `events` table (`internal/logging/logger.go`): secret, file, network, proxy, session, config and filesystem-fence-state events (`logger.go`). Each row carries a SHA-256 hash linked to the previous row (v1). Query with `nocklock log`, `log --blocked`, `log --stats`, `status`. `log --prune <age>` compacts and re-anchors the chain (`internal/cli/log.go`, `logger.go`).

Not every crossing is logged. No row is written for: allowed file access; file denials that bypass the interposer (static binaries, raw syscalls, cleared `LD_PRELOAD`), so file denials are logged only some of the time; packets dropped by the kernel floor; `ADVISORY` proxy bypass; Linux `CONFINED` AF_UNIX connects.

Audit and local/remote anchor verification append one shared notice after the
verdict and any boundary notes, including when verification fails:

```text
COVERAGE: LIMITED
Verification checks recorded events; it does not prove that every action was logged.
Individual allowed file accesses are not recorded. Some file denials, kernel-dropped packets, proxy bypasses and Linux CONFINED Unix-socket connections can leave no audit row.
This check does not establish past enforcement or recording coverage.
```

The notice describes recording limits; it is not an overall pass or an assessment
of the current host. Verification does not probe today's fences to infer past
enforcement. Existing authenticity/integrity verdicts and exit codes are unchanged.
An early input or availability error still returns its original error without
inventing an audit verdict. Exporting a public key, anchor enrollment/push, and
live fence-probe output do not acquire this history-verification notice.

### Executable fingerprint on the start row

The signed `session_start` detail is `<command> exec_status=<status> [exec_path="<path>"] [exec_sha256=<hex>] [exec_kind=<kind>]`. NockLock resolves the requested command on the caller's `PATH` (as the launch does) and hashes that file's bytes (`internal/cli/exec_fingerprint.go`). Plain, netns, Landlock and Seatbelt launches all fingerprint the requested command, never NockLock's own binary, `sandbox-exec` or the netns helper placed in front of it.

| `exec_status` | Meaning |
|---|---|
| `hashed` | Regular file, read in full, digest recorded |
| `unresolved` | Not found on `PATH`; the launch then fails |
| `unreadable` | Found but could not be opened or read; no digest |
| `not_regular` | FIFO, device or similar; never read |
| `oversized` | Over 256 MiB; never hashed |

`exec_kind=script` means the file starts with `#!`: the digest covers that script file only, not its interpreter. `exec_kind=launcher` means the basename is a known launcher (`sudo`, `nohup`, `timeout`, `xargs`, `npx`, `uvx`, and similar): the digest identifies the launcher, not the agent it starts. Treat both as "this file", never "the agent".

Limits: the hash is taken before exec, so a file swapped between the hash and the exec is not detected (time-of-check/time-of-use). Not covered: what a script's interpreter, shared libraries, language modules or plugins later load; programs a launcher or script goes on to exec; the launcher list is a fixed heuristic, so an unlisted wrapper is not labelled. A symlink is followed, so the digest is of its target. The row records what NockLock observed, not that the binary is safe or approved; nothing is blocked on a digest.

### Linux interposer connection provenance

New Linux interposer `file_blocked` rows use a version 1 JSON detail envelope
with separate `report` and `connection_peer` sections. `report` preserves the
child's operation, path, reason, type, action and timestamp claims. The collector
attaches `connection_peer` independently; identity-looking child JSON fields
cannot overwrite it. Both ordinary channel logging and synchronous look-back
logging sign the same detail representation.

At the start of each accepted connection's goroutine, the collector reads Linux
`SO_PEERCRED` once before parsing any frames. Slow capture on one connection
does not block the shared accept loop. `credentials_status: "captured"` accompanies numeric PID, UID and GID
(including legitimate zero UID/GID). If credentials cannot be obtained,
`credentials_status: "unavailable"` omits the credentials object and retains the
underlying report. These are the connecting process's credentials at connection
time, as seen from the collector's namespaces. An inherited or passed socket
can be written by a different process; this is **not per-action writer identity
or proof that the reported action happened**.

`executable.status` is `observed` with a path from a later `/proc/<pid>/exe`
read, `unavailable` when that read fails, or `credentials_unavailable` when no
usable PID was captured. This path is not atomically bound to the connection,
authenticated as the executable at connect time, or hashed. Exec, exit, PID
reuse, procfs permissions and namespace visibility can affect the observation.
The snapshot is reused for all frames on that connection.

The envelope lives in the existing signed detail column; signature encoding,
old row bytes and old verification behavior do not change. Existing plain-text
details remain readable. macOS Seatbelt denial details and unrelated events
keep their existing formats. Connection provenance adds no recording coverage;
the limits above still apply. See the [design and test contract](../design/connection-peer-provenance.md).

## Layers
| Layer | What it adds | Does not give you |
|---|---|---|
| v1 hash chain | Detects altered, reordered or deleted rows | Protection from a writer who recomputes the whole chain and `chain_head` |
| v1.1 Ed25519 | Each row and the chain head are signed with a key outside the database, `~/.config/nocklock/signing-ed25519.key` (mode 0600) | Detection of rollback to an earlier, legitimately signed whole-database snapshot |
| v2 remote anchor | An independent signed pair and monotonic off-box head/count detect rollback and divergent prefixes | Protection if the attacker can replace the trusted identity and remote pin, or has the signing key |

The managed signing key lives in `$XDG_CONFIG_HOME/nocklock/signing-ed25519.key` when `XDG_CONFIG_HOME` is set, otherwise under `~/.config/nocklock/`. `wrap` denies the resolved key directory to its child. `doctor` checks that directory against the effective Seatbelt deny set or Landlock read grants and reports its path and posture in `doctor --json`. A key under a Landlock grant, such as the project or `/tmp`, makes `wrap` refuse and `doctor` report a gap; a missing Seatbelt deny also prevents a `PROTECTED` verdict (`internal/cli/wrap.go`, `doctor.go`).

`nocklock verify --audit` reports `AUTHENTIC` (signed, valid; printed on the machine that holds the signing key, or when `--ed25519-pub` is supplied), `CONSISTENT` (chain intact, unsigned or no key to check), `FORGED`, or `SUSPECT` (a signed check was required with `--ed25519-pub` but no signing artifacts exist) (`internal/cli/verify.go`). A chain that is not intact prints `TAMPERED`. Exit codes (`writeAuditVerifyResult` in `internal/cli/verify.go`): `AUTHENTIC` and `CONSISTENT` exit `0`; `TAMPERED`, `FORGED` and `SUSPECT` exit `1`. `CONSISTENT` is a pass with no authenticity claim. A passing check means the stored rows are internally consistent; it does not prove NockLock recorded them unless signed and checked with the public key (`verify --export-pubkey`).

V2 anchors sign the verified `(agent_id, chain_id)` pair, current head/count, timestamp and immutable legacy witness with domain byte `0x06` (`internal/logging/anchor_v2.go`). Independent projects can share a managed key without sharing a stream. V1 file verification preserves its original `0x05` encoding. `anchor emit` verifies the signed chain and uses v2 when a trusted identity exists, otherwise v1. It loads the existing key without generating a key or adopting/re-signing the database (`WithExistingSigning`); an unsigned or stripped log is refused. `pkg/receipt` continues verifying individual sessions offline.

Existing-signing opens used by anchor commands validate the adopted key fingerprint
and signed head before any schema or signing change. Absent, unsigned or stripped
databases are refused without creating directories/files, changing permissions,
or adding tables. SQLite `mode=rw` observes committed WAL pages; this is not an
immutable snapshot. SQLite may manage WAL/SHM sidecars. Valid older signed logs
can receive the v2 metadata table only in the transaction that validated adoption.
Normal wrap's initial signing adoption remains unchanged.

### Explicit enrollment and migration

`anchor enroll` checks the signed local chain and asks the upgraded store whether retained v1 history exists. A key with no legacy pin can establish a new pin. When history belongs to a different project, `anchor enroll --acknowledge-no-legacy-history` explicitly declines that history and uses a zero witness. `anchor migrate` selects the actual owning project, authenticates its retained legacy anchor, proves the local prefix and signs its exact snapshot digest into the new v2 stream. Wrong-project, shorter or divergent local chains cannot migrate. Both commands require remote v2 verification before reporting completion.

The random ID lives in `chain-identity.json` under the trusted external project state directory and is mirrored in DB metadata. Both copies must agree. `anchor-registration.json` durably retains the exact original signed request, mode and migration witness before registration. Under the shared identity/prune lock, the client verifies the local signed prefix and syncs `pending` before sending. A lost response, rejected request or crash after pending is persisted leaves pending; a failure after request persistence but before pending leaves a retained request that also blocks prune; retrying the same command replays the original snapshot. Verified exact-request confirmation moves to `enrolled`; no transition clears pending or enrolled. The operator must restore a missing record, never mint a replacement.

If the original request's rename committed but its directory sync failed,
retry preserves the original signed bytes. The request file was synced before
rename; the next pending write syncs their shared directory and ancestor entries
before any request is sent.

Every pending retry rewrites and syncs the record before sending again; finding
`pending` on disk does not prove the last directory sync succeeded. A
`ChainIdentityDurabilityError` means replacement committed but durability is
uncertain: preserve the visible state and retry, never restore `none`. A
pending-write failure sends no callback; an enrolled-write failure follows the
already-confirmed remote request and retains the previously durable pending
guard. Ordinary state resolution, reads and prune perform no directory fsync.
Only trusted identity and original registration-request writes first sync the configured state root and every
ancestor through the filesystem root, before any DB mirror change or record
rename. This establishes entries that a prior legacy `MkdirAll` may have created;
existence alone does not prove durability. An unreadable ancestor or unsupported
directory sync blocks identity mutation, while legacy logging and verification
remain usable. After record rename, file and directory barriers stop at the
canonical state root. Each new locked mutation performs its own preflight.
An embedding registration callback may read the DB under the shared lock, but
must not recursively call identity methods or prune.

### Remote operations

Set `NOCKLOCK_ANCHOR_URL` and `NOCKLOCK_ANCHOR_TOKEN` in the operator environment. Token errors are redacted and both variables are stripped from the child. Remote commands use only `/api/nocklock/anchors/v2/` (`internal/anchorclient/client_v2.go`):

- `POST register/` explicitly creates a fresh pair; `POST migrate/` conditionally claims the retained legacy witness.
- `GET <agent_id>/<chain_id>/latest/` fetches the expected signed pair. `GET <agent_id>/legacy/` exists solely for explicit enrollment/migration checks.
- `POST` at the v2 root supplies a signed anchor and the previous authenticated snapshot digest as a compare-and-swap precondition. Ordinary push cannot recreate an absent stream.

`anchor push --file` and wrap teardown verify the candidate's signature, identity and local prefix, fetch and authenticate the remote pin, and prove its prefix before sending. The store independently enforces pair identity, immutable witness, monotonic counts, equal-height head agreement and compare-and-swap. A conflict never reports success. Remote counts remain exact uint64 values through verification. Missing identity, missing remote state, unsupported routes, invalid signatures and unavailable stores fail non-zero; no v1 route is a fallback.

The upgraded store retains v1 migration history and freezes ordinary v1 access for a key once it has a v2 stream. Explicit `verify --against-anchor <v1-file>` still works. An old store must be upgraded before using these remote commands.

`wrap` emits `chain-anchor.json` beside the DB and pushes enrolled v2 chains. Its five-second budget starts before the first identity read and bounds identity-lock waits and HTTP together. Failure warns and retains the child's exit code; interactive anchor commands and anchor verification use 30 seconds. Caller cancellation reaches identity-lock acquisition. Synchronous filesystem/SQLite work and in-progress durable writes complete on the caller; these deadlines do not interrupt them. Legacy chains emit local v1 files but require explicit enrollment/migration for any remote push. The real NCC/CLI [acceptance runbook](../runbooks/anchor-v2-ncc-acceptance.md) exercises distinct projects, rollback, missing/swapped state, migration, lost-response retries and moves.

Prune requires explicit project context; rootless library calls refuse even for
legacy databases. On Linux and macOS, neither identity copy may exist, or both
must agree with registration `none`; neither case may have a retained original registration request. A request left before pending was durably written must remain replayable. The external state directory must be
resolvable, accessible, correctly owned, free of forbidden symlinks/permissions,
outside the project and strictly below the state root. Prune holds the shared
identity lock through deletion and waits at most five seconds to acquire it.
Unusable request/state storage, a retained registration request, lock timeout, pending/enrolled state, a missing identity copy,
or corrupt/inconsistent metadata refuses before changing events. These storage
and locking failures also refuse legacy prune. Platforms without identity-lock
support permit only legacy chains with neither identity copy nor a retained registration request. The CLI supplies
the project root; see the [CLI reference](../reference/cli.md) for the full contract.

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
project; never regenerate an ID to bypass a missing record. Complete remote verification at the moved path before another push.

## Where the log lives
Outside the project: `$XDG_STATE_HOME/nocklock/<project-key>/` (or `~/.local/state/nocklock/<project-key>/`). The filesystem fence grants the project root and Landlock cannot exclude a path beneath a grant, so a log inside the project would be editable by the agent. An existing `.nock/events.db` stays where it is (the README explains why NockLock does not move it). Path resolution fails closed (`internal/config/state.go`); `wrap` refuses to start when `logging.db` resolves to the project root. Decision record: `docs/decisions/010-audit-state-outside-project.md`.

## Replacing the signing key
The procedure below applies to **legacy v1 chains without a trusted v2 identity** when the managed key (`~/.config/nocklock/signing-ed25519.key`, or under `$XDG_CONFIG_HOME`) may have been read by something other than NockLock. There is no `rotate` command; it uses `mv` and `verify --export-pubkey`.

**V2 operators must stop before these steps.** Replacing the key while retaining the trusted identity makes the new key disagree with the old pair. Preserve the entire trusted state directory (`chain-identity.json`, persistent lock, original `anchor-registration.json` when present), the DB and sidecars, local anchors and original public key. Use the [offline state-move procedure](../runbooks/chain-identity-move.md) to relocate an intact archive and retain its existing remote pin. Never delete the identity, clear pending/enrolled, or reset its ID to make a replacement key pass. This release does not implement key rotation or signed chain endorsements; an explicit v2 key-replacement/new-chain recovery procedure needs separate validation. The legacy instructions below do not promise that result.

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
6. Run `nocklock wrap` as usual. It opens a new log and adopts the new key. Explicitly enroll the fresh chain before any remote v2 push; this does not claim continuity with the archived legacy chain.

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

Expect `AUDIT: AUTHENTIC` (exit 0) and `ANCHOR: OK` (exit 0). A non-empty anchor path is required to exist; a missing or mistyped path exits 1. Only an intentional `archive_anchor=''` skips the anchor check, prints that only the audit signature check ran, and permits a signature-only exit 0. This checks a saved legacy anchor file, not the remote store. Its identity remains the original signing-key fingerprint; the scratch path does not establish a v2 identity or remote stream. A saved anchor can legitimately disagree after pruning; preserve and investigate that result instead of generating a replacement anchor. The old rows checked with the new public key must report `FORGED` (exit 1). Always pass the archived public key explicitly; omitting it can select a different local key or give only an unsigned consistency verdict.

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
  `verify` prints a `NOTE`. V2 local pending/enrolled state or a retained original registration request refuses prune, including state none after an interrupted write.

## Tests
`internal/logging/*_test.go`, `internal/cli/exec_fingerprint_test.go`, `internal/cli/verify_test.go`, `verify_signing_test.go`, `audit_state_*_test.go`, `anchor_*_test.go`, `internal/anchorclient/client*_test.go`, `pkg/receipt/*_test.go`.
