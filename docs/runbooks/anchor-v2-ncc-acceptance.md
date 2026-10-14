# Anchor v2 acceptance against the real NCC store

Run this gate after the v2 CLI and NCC store are built. It exercises actual
Django bearer authentication, signature validation, migrations, SQLite storage
and HTTP handlers together with the built NockLock CLI. It never contacts the
published NCC service, reads a repository `.env`, or uses a mock anchor store.

```bash
go build -o /tmp/nocklock-anchor-v2 ./cmd/nocklock
NCC_CHECKOUT=/absolute/path/to/nock-command-center \
NCC_PYTHON=/absolute/path/to/its/venv/bin/python \
python3 scripts/test-anchor-v2-ncc.py \
  --nocklock-bin /tmp/nocklock-anchor-v2 \
  --out /tmp/nocklock-anchor-v2-receipt
```

The output directory must not exist. NCC needs its normal installed Python
dependencies and v2 store migrations. `NCC_PYTHON` must retain its virtualenv
launcher path, even when that launcher is a symlink. Go must be available for
the small signed-row fixture. No new runtime dependencies are introduced.

The harness refuses root. It creates a private temporary HOME, XDG config and
state roots, projects, signing identities, server secrets and SQLite database.
The server imports `config.settings.ci` with `NOCKCC_SKIP_DOTENV=1`, explicit
temporary database settings and fresh test secrets. Its settings overlay mounts
only the real anchor routes, keeps caches/queues in memory, and uses no site
middleware or templates. This proves the machine anchor endpoint contract,
not the complete NCC website, deployment middleware or PostgreSQL concurrency.
It binds only `127.0.0.1` on an OS-assigned port. The processes and private
scratch directory are removed on completion or ordinary failure.

`scripts/testdata/anchor-v2-fixture` creates real signed rows through NockLock's
logging package. It accepts only paths inside the marked private harness root.
Enrollment, emission, push, migration, verification and prune all run through
the real CLI. The fixture configuration disables enforcement because this is
an anchor protocol test; no filesystem/network fence claim follows from it.

## Coverage matrix

| Case | End-to-end evidence |
|---|---|
| Shared key, independent projects | Different counts and chain IDs, matching key fingerprints, separate real stored pairs, successful CLI remote verification |
| Swapped pair before count comparison | Serve B's actual signed higher-count latest through A's requested path; A refuses identity before `TRUNCATION`; the real server also rejects URL/body pair disagreement |
| Rollback | Restore A's earlier signed SQLite snapshot, preserve trusted identity, require failed verification/push; the actual store also rejects a direct lower-count CAS update with `row_count_regression`, and A/B pins stay unchanged |
| Missing local identity | Ordinary remote commands never create one; a DB with a missing external record also refuses prune without changing its rows |
| Missing remote pin / old route set | Remove only a disposable fixture pair, require failed verify/push and no recreation; unmount v2 and require actual 404 with no v1 request |
| Legacy migration | Explicit v1 file verification works; wrong project cannot claim the pin; correct owner migrates with a signed witness and freezes v1 reads; an unrelated project requires explicit no-legacy-history acknowledgement and keeps a zero witness |
| Lost committed response and crash | Hold a response after the real NCC registration commits, kill the CLI, require persistent `pending` and prune refusal, then retry the original registration and verify enrollment |
| Validation rejection | Corrupt a registration signature in transit; the actual validator refuses it, store rows stay unchanged, local `pending` remains and prune refuses |
| Offline move | Move the project and entire trusted state directory together; preserve the identity tuple and remotely verify the existing pair |
| Prune positive control | An entirely unenrolled legacy chain can still prune its rows |

Transport fault injection wraps the actual Django application. It never
fabricates an anchor or success response. Removing the temporary pair is a
deliberate store-loss fixture, not an exposed server API or supported recovery
procedure. The held-response case has a bounded wait and force-kills only its
own disposable CLI process group.

Identity state `none` with a present record, registration/prune lock contention,
filesystem aliases/FIFO rejection, failure to durably write pending, and stale
legacy digest/duplicate migration claims retain lower-level Go or NCC tests.
They are explicitly listed as lower-level coverage in the receipt; this harness
does not silently count them as end-to-end passes. The external-DB move is
covered here; the in-project-DB move has the logging package's offline move test.

## Review the receipt

Require process exit zero and `report.json` verdict `PASS` with scope
`CLI-and-real-NCC`. Check each case, the built binary digest, source revisions
and dirty-state indicators. `commands.json` records the CLI argument vectors,
exit codes and output; `requests.jsonl` records methods, requested/effective
paths and actual HTTP status codes. Migration/server logs are included.

Only these evidence files are copied out. The temporary environment, signing
seeds, bearer token, HOME and databases are never exported. Failed cases stop
the run and retain their receipts. A `--server-smoke` run is useful while the
CLI is being developed, but its scope only proves isolated server/auth/storage
startup and cannot satisfy the full integration gate.
