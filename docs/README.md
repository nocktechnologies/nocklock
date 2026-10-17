# NockLock docs

The root [README](../README.md) is the user-facing guide; [AGENTS.md](../AGENTS.md) is the contributor map, with the full rule list in [invariants](context/invariants.md). This set backs them up. If a page and the code disagree, the code wins; fix the page.

| Need | Go to |
|---|---|
| Install, first run, verify | [Setup](setup.md) |
| What a fence does and where it stops | [Secrets](how-it-works/secret-fence.md), [filesystem](how-it-works/filesystem-fence.md), [network](how-it-works/network-fence.md), [syscalls](how-it-works/syscall-fence.md), [audit log](how-it-works/audit-log.md), [secret preflight](how-it-works/secret-preflight.md), [doctor and verify](how-it-works/doctor-and-verify.md), [deputies](how-it-works/deputies.md) |
| Commands, exit codes, config keys | [CLI reference](reference/cli.md) |
| Where code and tests live | [Repo map](REPO-MAP.md), [architecture](../ARCHITECTURE.md) |
| Cut a release, handle a fence failure | [Release runbook](runbooks/release.md), [incident runbook](runbooks/incident.md) |
| Report a security vulnerability | [Security policy](../SECURITY.md) |
| Why it is built this way | [Decision records](decisions/) (001–005 in [the original records](../.claude/decisions/)) |
| Where it is going | [Roadmap](ROADMAP.md) |
| Specs and designs | [Designs](design/), [dated build specs](superpowers/specs/), [build plans](superpowers/plans/), [earlier design notes](../.claude/design/), [Mermaid diagrams](../.claude/diagrams/) |
| Platform probe records | [Probes](probes/) |

## Rules for these pages

- Cite code by file path at a stated commit, no line numbers (they go stale), or match `README.md` / `CHANGELOG.md`. Do not describe a feature the code does not have.
- State limits next to the claim, not in a footnote.
- Update the page in the same change that alters the behavior; note it in `CHANGELOG.md`.
