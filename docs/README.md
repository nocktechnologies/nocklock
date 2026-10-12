# NockLock docs

`README.md` at the repo root is the user-facing guide; `CLAUDE.md` is the contributor map. This set backs them up. If a page and the code disagree, the code wins; fix the page.

| Need | Go to |
|---|---|
| Install, first run, verify | `setup.md` |
| What a fence does and where it stops | `how-it-works/`: `secret-fence`, `filesystem-fence`, `network-fence`, `syscall-fence`, `audit-log`, `secret-preflight`, `doctor-and-verify` |
| Commands, exit codes, config keys | `reference/cli.md` |
| Where code and tests live | `REPO-MAP.md` (deep tree: `../ARCHITECTURE.md`) |
| Cut a release, handle a fence failure | `runbooks/release.md`, `runbooks/incident.md` |
| Why it is built this way | `decisions/` (001-005 in `../.claude/decisions/`) |
| Where it is going | `ROADMAP.md` |
| Specs and designs | `design/` (look-back rules, Windows feasibility), `superpowers/specs/` and `superpowers/plans/` (dated build specs), `../.claude/design/` (verify self-test, macOS fence), `../.claude/diagrams/` (Mermaid) |
| Platform probe records | `probes/` |

## Rules for these pages
- Cite code as `path:line` at a stated commit, or match `README.md` / `CHANGELOG.md`. Do not describe a feature the code does not have.
- State limits next to the claim, not in a footnote.
- Update the page in the same change that alters the behavior; note it in `CHANGELOG.md`.
