# Move trusted chain state offline

N11744 adds the local identity and prune guard. V2 enrollment, remote verification
and migration commands are a later slice. This procedure moves local state; it
cannot establish remote verification success. Complete that check with the v2
client and actual store before any subsequent v2 push.

An audit DB with a `chain_id` and no matching external `chain-identity.json`
**must fail closed**. Do not run initialization to repair it, edit an ID, clear
`pending`, or copy another project's record. A project move retains the exact
pair, legacy witness and registration state. A clone intended to become an
independent chain needs an explicit new enrollment instead. All pruning APIs
require the canonical project root even if a restored DB has no identity mirror;
never pass an empty root to bypass the external record. A lock wait times out
after five seconds without deleting rows; stop the competing command before
retrying. If a write reports committed replacement with uncertain durability,
preserve the visible state and retry registration to complete its barriers;
never roll the state back to `none`.

## Record the mapping before moving

1. Stop all NockLock sessions and commands for both source and destination. The
   move is offline: never unlink, replace or move an active `chain-identity.lock`.
2. Back up the DB, any `-wal`/`-shm` sidecars, local anchors and the entire trusted
   state directory together. Retain the original public key for verification.
3. Record the old and new **canonical absolute project roots**, selected DB
   location, old/new state directories, and the identity tuple
   `(agent_id, chain_id, legacy_anchor_digest, registration_state)`. Run
   `nocklock verify --audit` in the old project and require authentic, intact
   results. Validate trusted-record/DB agreement with `Logger.ReadChainIdentity`
   in an embedding caller; the later v2 CLI must make the same check.

The state directory mapping is the existing `config.AuditStateDir` mapping:

```
<absolute XDG_STATE_HOME or ~/.local/state>/nocklock/
    <first 16 lowercase hex characters of SHA256(canonical project-root UTF-8)>
```

Resolve system symlinks and any symlinked state-root base. Compute the new root
using its canonical existing parent plus the intended final directory name;
otherwise `/var` versus `/private/var` on macOS can produce the wrong key. The
random `chain_id` is **not** derived from either path and never changes.

Before modifying anything, require:

- Source DB and record agree, the state directory is a real operator-owned
  directory, and its record/lock are regular operator-owned files without
  symlinks, hard-link aliases or group/world write permission.
- The new project path and new state directory are absent, including dangling
  symlinks. A destination containing even a lock file from an earlier failed
  attempt is a conflict: inspect and resolve it offline; do not overwrite it or
  silently merge state directories.
- The selected DB is within the old project or its trusted state directory.
  Record its relative location so the intended new DB location is unambiguous.

## Move and validate

4. Move the project to the recorded new path with a no-clobber operation. Move
   the **entire** old state directory to the recorded new state directory with
   the same no-clobber rule. Check that the old paths disappeared and the expected
   files arrived; some `mv -n` implementations skip a conflict without a failing
   exit status. Never treat that status alone as success. If crossing filesystems,
   retain the backup and finish copying/syncing every component before removing
   the source or resuming commands.
5. An in-project DB moves with the project while its identity stays in the
   separately moved external state directory. A default external DB and its
   sidecars move inside the state directory. If `logging.db` is an absolute path,
   explicitly update that setting to the recorded destination; keep relative
   configuration relative. Do not redirect the record into the project.
6. Validate the destination with `Logger.ReadChainIdentity`: its result must
   exactly equal the recorded tuple, including `pending`/`enrolled` and the
   legacy digest. Run `nocklock verify --audit` in the destination and require
   the original signed chain to verify. The old state directory must be absent.
   Stop on any mismatch; do not regenerate a missing record or initialize a new ID.
7. Before the next v2 push, remotely verify the preserved expected pair with the
   actual v2 store. A missing/unreachable remote pin is an error. This final step
   is deferred until the v2 CLI/server integration ships; local agreement alone
   does not complete remote migration or prove rollback protection.

If either move fails midway, keep both locations offline and use the saved
mapping and backup to finish or restore the **same** identity. Do not make an
existing destination the source of truth automatically. Pending and enrolled
chains continue refusing prune after a successful move. To bound their growth,
archive the old chain and explicitly enroll a fresh chain; no reset-to-none
operation exists.

`TestChainIdentityOfflineMoveProcedure` executes the local procedure with a
signed disposable in-project DB and external identity. It proves preserved
agreement/enrollment, refusal with a missing record, and destination-conflict
refusal with both source and destination intact. Its verbose output records the
exact path mapping as test evidence. It makes no server or remote verification
claim.
