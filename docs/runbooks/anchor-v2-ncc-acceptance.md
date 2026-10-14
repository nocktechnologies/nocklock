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
logging package. Its `init-identity` action initializes a real `none` record for
the prune positive control and direct-handler migration negatives. It accepts
only paths inside the marked private harness root. Enrollment, emission,
migration retries, verification and prune use the real CLI. Some negative cases
also submit an actual CLI-signed anchor directly to the real HTTP handler, to
check server rejection separately from successful CLI preflight refusal. These
are identified in the receipt. The fixture configuration disables enforcement
because this is an anchor protocol test; no filesystem/network fence claim
follows from it.

## Coverage matrix

| Case | End-to-end evidence |
|---|---|
| Shared key, independent projects | Different counts and chain IDs, matching key fingerprints, separate real stored pairs, successful CLI remote verification |
| Swapped pair before count comparison | Serve B's actual signed higher-count latest through A's requested path; A refuses identity before `TRUNCATION`; the real server also rejects URL/body pair disagreement |
| Forged ID, bad signature, malformed response | An ID-only case changes only `chain_id` and retains the original count/signature, proving ID signature binding. Three further cases corrupt the ID plus count, signature plus count, or JSON in an actual successful latest response. CLI authentication/parsing refuses them before a truncation verdict. Real POST validators also reject both forged-ID cases and the bad signature without storage changes |
| Local mirror disagreement | Corrupt only the disposable DB mirror, then require specific CLI verify/push refusal before HTTP or a count verdict; the corrupted DB and remote store stay unchanged |
| Rollback | Restore A's earlier signed SQLite snapshot, preserve trusted identity, require failed verification/push; the actual store also rejects a direct lower-count CAS update with `row_count_regression`, and A/B pins stay unchanged |
| Missing local identity | Verify/push require specific incomplete/missing identity diagnostics without HTTP or minting; the fresh legacy push receives an existing valid v2 file so missing input cannot satisfy the control. A missing external record also blocks prune without changing rows |
| Missing remote pin / old route set | Remove only a disposable fixture pair; each failed verify/push must make exactly one real GET returning `404 not_registered`, without recreation. Unmount v2 and require actual 404 with no v1 request |
| Unreachable store | Reserve an unlistened loopback port; verify/push must fail while connecting (refusal or OS connect timeout), without fallback or local/remote state changes |
| Stale CAS | Pause a real CLI update before its handler, commit a valid intermediate signed update over HTTP, then release the stale request; require real `409 previous_mismatch`, failed CLI exit and preservation of the competing pin |
| Legacy migration | Explicit v1 file verification works; wrong project cannot claim the pin; correct owner migrates with a signed witness and freezes v1 reads; an unrelated project requires explicit no-legacy-history acknowledgement and keeps a zero witness |
| Shorter / divergent migration history | Separate shorter-snapshot and equal-height divergent signed histories fail CLI migration preflight without minting an identity. Fixture-initialized, CLI-signed candidates separately reach the real handler and receive `row_count_regression` / `head_conflict` without mutation |
| Stale migration witness | Pause real CLI migration before its handler, advance the real v1 pin over HTTP, release, and require `legacy_previous_mismatch`; the advanced legacy pin stays intact and local state stays pending |
| Duplicate legacy claimant | Clone the signed DB before either identity exists; migrate the owner, then require the clone's real CLI migration to fail with `legacy_already_claimed`, preserving the owner's pin and a separate pending clone identity |
| Lost committed response and crash | Separate enrollment and migration cases hold the response after the real transaction commits, kill the CLI, require persistent `pending` and prune refusal, then retry. The original request file and both HTTP request hashes match; actual `already_exists` / `already_migrated` confirms the retry |
| V1 compatibility | Separate cases prove real v1 POST/GET before migration, both ordinary operations frozen with `v1_frozen` afterward, and a v2 body rejected by the v1 validator. The migration-only retained legacy anchor and ETag remain unchanged |
| Rejected pending registration and offline move | Corrupt a registration signature in transit; the actual validator refuses it without a remote pin. Preserve the pending tuple/request and signed DB while moving project and external state. Exactly two registration POSTs must have the same original request hash: first `400 invalid_anchor`, then `201 registered`; remote verification must pass |
| Enrolled offline moves | External-DB and in-project-DB cases move the project and entire external trusted state directory together; preserve the tuple, original request and signed DB, then remotely verify the existing pair |
| Explicit fresh fork | Start a new audit DB and explicitly enroll it with the same key; require a new chain ID, independent verification and an unchanged source pin |
| Copied enrolled identity | Copy signed DB plus enrolled identity/request, then append different valid signed histories. CLI prefix checks refuse the copied fork; a direct current-CAS POST receives `head_conflict`, retaining source and fresh-fork pins |
| Prune states | Both an entirely legacy DB and a present `none` identity can prune through the CLI. Pending and enrolled cases require their specific state diagnostic, unchanged local/remote databases and no HTTP |

Transport fault injection wraps the actual Django application. It can corrupt
an invalid response or delay a selected real request/committed response; it
never fabricates a valid signed anchor or success response. All valid records
come from actual signing code. Removing the temporary pair is a
deliberate store-loss fixture, not an exposed server API or supported recovery
procedure. Concurrent cases fingerprint the store **after** their intentional
competing write, then prove the refused operation makes no further change.
Waits are bounded; cleanup kills and reaps only the harness's own CLI/server
process groups. Authentication and the real per-view rate limits remain active;
each case and the final receipt reject any recorded HTTP 429, including requests
made by the CLI. A generic failure cannot satisfy a protocol-negative case.

Registration/prune lock contention and cancellation, filesystem aliases/FIFO
rejection, and durable-write failure/retry barriers retain lower-level Go tests.
They are explicitly listed as lower-level coverage in the receipt; this harness
does not count them as end-to-end passes. The copied-identity case is a negative
fixture, not a supported fork or identity-reset procedure.

## Review the receipt

Require process exit zero and `report.json` verdict `PASS` with scope
`CLI-and-real-NCC`. Check each case, the built binary digest, source revisions
and dirty-state indicators. `commands.json` records the CLI argument vectors,
exit codes and output; `requests.jsonl` records methods, requested/effective
paths, actual HTTP status/error codes, request body hashes and any invalid
response fault. Migration/server logs are included. Each matrix subcase has its
own pass/fail row, while repeated pending/enrolled prune checks appear in the
owning crash, migration or validation case.

Only these evidence files are copied out. The temporary environment, signing
seeds, bearer token, HOME and databases are never exported. Failed cases stop
the run and retain their receipts. A `--server-smoke` run is useful while the
CLI is being developed, but its scope only proves isolated server/auth/storage
startup and cannot satisfy the full integration gate.
