# Runbook: incident (a fence failed, or may have)

Citations name source files at `origin/main` 89c02fa (no line numbers, so they do not go stale). Evidence first, then containment, then fix. Do not "fix" by weakening a fence.

## Triage: which kind?
| Symptom | Likely cause | First move |
|---|---|---|
| `wrap` exits `2`, prints `NockLock: fatal:` or `fix:` | A requested fence cannot engage; it is refusing correctly (`internal/cli/wrap.go`) | `nocklock doctor`; follow the printed fix. This is the fence working, not an incident |
| Agent reached something it should not have | Egress level lower than assumed, a bypass, or a missing config rule | Step 1 below |
| `verify --audit` says `FORGED`, `SUSPECT`, or `ANCHOR: TRUNCATION` / `TAMPERED` | Log was modified, rolled back, or a signing artifact is missing | Step 3 |
| A secret appeared in the agent's context | Env name not blocked, or the secret was read from a file | `docs/how-it-works/secret-fence.md`, `secret-preflight.md` |
| Fence worked before an upgrade, not after | A breaking change | `CHANGELOG.md` "Breaking" and "Security" for the version |

## 1. Establish what the session was
1. Session id and egress level: `nocklock log --session <id>`; the `wrap` banner and the signed fence-state row name the level (`KERNEL`, `CONFINED`, `SEATBELT`, `ADVISORY`, `OFF`). `ADVISORY` and `OFF` are not enforced boundaries (`docs/how-it-works/network-fence.md`).
2. Blocked events: `nocklock log --blocked --session <id>`. Absence of a row is not proof of absence: allowed reads are never logged, macOS denials are best-effort, and static binaries bypass the interposer (`docs/how-it-works/audit-log.md`, `filesystem-fence.md`).
3. Policy in force: `nocklock config` and the signed `config.digest` row (`internal/cli/config_digest.go`).

## 2. Contain
Stop the agent. Rotate any credential that could have been in its environment or readable files. Treat anything not blocked by an enforced level as exposed.

## 3. Check the log's integrity
```
nocklock verify --audit --ed25519-pub <pubkey from verify --export-pubkey, held off-box>
nocklock verify --against-remote-anchor      # if NOCKLOCK_ANCHOR_URL was set
```
Interpret per `docs/how-it-works/audit-log.md`. Preserve `events.db`, its `-wal` / `-shm` sidecars, `chain-anchor.json` and the signing key's fingerprint before changing anything; copy them, do not run `log --prune`.

## 4. Reproduce
Use the same config and platform. `nocklock verify` re-runs the adversarial self-test (`docs/how-it-works/doctor-and-verify.md`); the `-tags=integration` suite and the CI proofs (`.github/workflows/test.yml`, `network-egress.yml`) cover the Linux and macOS boundaries.

## 5. Fix and record
- A confirmed bypass is a security fix: failing test first with a negative control, fix, `### Security` entry in `CHANGELOG.md`, patch release (`release.md`).
- If the boundary is honest but narrower than users assume, fix the docs and the `wrap` / `doctor` wording in the same change. Add the gap to `docs/ROADMAP.md` if it blocks 1.0.
- Add a lesson in `.claude/lessons/` and, if a design choice changed, a record in `docs/decisions/`.
