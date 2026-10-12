# Roadmap to 1.0

Status at `origin/main` 8a65777 (v0.7.0 released, one unreleased test fix). The 1.0 bar below is the one Kevin approved (Telegram 33132, Nock #11662). The release split is a proposal for the release owner to confirm; the four bar items are not.

## The 1.0 bar
1.0 ships when all four hold.

| # | Bar | State at 8a65777 | Tracking |
|---|---|---|---|
| 1 | The Linux `CONFINED` gaps are closed and covered by the red-team bench | Open. Unix-socket reach and `io_uring` are the named gaps. The syscall denylist has no `io_uring` entry (no reference in `internal/`, `internal/fence/syscallfence/denylist.go:25`). No red-team bench is in this repo | N11660 (Unix-socket reach), N11655 (`io_uring`); doc PR #171 (Unix-socket) |
| 2 | Honest `doctor` verdicts | Open on `main`. `doctor` has two verdicts, `PROTECTED` and `GAPS FOUND` (`internal/cli/doctor.go:36-39`) | #168 |
| 3 | A complete Linux install | Open. Today `make install` plus a separate `sudo make install-egress-helper` (`Makefile:28-38`; `docs/setup.md`); no packaged install | design #172 |
| 4 | The CLI, config schema and exit codes written down as the contract we keep | Drafted as "what exists today" in `docs/reference/cli.md`; not yet a promise | this PR (draft); contract text is 0.8 work |

"Closed" for item 1 means a failing red-team case existed, the fix landed, and the case now runs in CI with a negative control. Until then `docs/how-it-works/network-fence.md` must keep naming the gap and must not describe `CONFINED` as complete.

## Path

### 0.7.1: honesty and gaps, no breaking change
- Item 2: ship #168.
- Item 1: land the Unix-socket reach fix (N11660) and the `io_uring` handling (N11655), each with a red-team case; merge #171.
- README claims fix (#166) is held; merge when it is reconciled with `docs/how-it-works/` and `docs/reference/cli.md`.
- Record each fix in `CHANGELOG.md` under `### Security`.

### 0.8: the one release allowed to break
Everything that must change before it is frozen changes here, once, with `### Breaking` entries and upgrade steps (the v0.6.0 pattern: `CHANGELOG.md:82-109`).
- Item 3: the complete Linux install (design #172) lands.
- Item 4: audit `docs/reference/cli.md` line by line; decide for each command, flag, config key and exit code whether it is public, internal (`__*` commands) or to be removed. Resolve the exit-code ambiguity noted there (child `1` / `2` versus `nocklock` `1` / `2`) and decide the fate of two legacy keys: `macos_allow_unfenced` (decoded only so v0.5 configs keep loading, `internal/config/config.go:297-301`) and `filesystem.hardened` (a macOS opt-in that `wrap` now applies under syscall enforcement anyway, `internal/config/config.go:301-304`, `CHANGELOG.md:56-60`).
- Red-team bench runs in CI for every platform that claims a level.

### 1.0: the contract
- Items 1 to 4 hold, verified against the table above.
- `docs/reference/cli.md` becomes the compatibility contract: the CLI surface, the config schema, the exit codes, the egress level names and the `verify --audit` states. After 1.0 a change to any of them is a breaking change, announced under `### Breaking`.
- `CONTRIBUTING.md` and `CLAUDE.md` state the rule; a test pins the exit codes and the schema so the promise is checked, not remembered.

## Not on the 1.0 bar
These are real but do not gate 1.0. They are stated so nobody assumes otherwise.
- macOS read confinement outside `filesystem.root` and complete per-file events (Endpoint Security follow-up, `ARCHITECTURE.md`).
- A Windows fence (`docs/design/windows-feasibility.md`).
- Look-back rules beyond slice 1 (`docs/design/look-back-rules.md`).
- An externally anchored audit log by default (anchors are opt-in; `docs/how-it-works/audit-log.md`).

## Keeping this page honest
When an item closes, change the state column to the commit or release that closed it and link the test. When scope changes, say who approved it and where.
