# Review pipeline: NockLock

One card produces one feature PR, based on `next`. Mira owns the gate and merge. Builders own implementation and remediation; they do not merge or push directly to `next` or `main`. `main` remains the default branch and the released line. This is the workflow agreed for N11740; [CONTRIBUTING.md](../../CONTRIBUTING.md) is the contributor entry point and the [release runbook](../../docs/runbooks/release.md) covers batch promotion.

## Build and local verification

Keep the card and PR to one reviewable change. Define the expected behavior and its limits before implementation. Behavior changes need regression tests and allowed-action controls for expected denials. Update `CHANGELOG.md` under `[Unreleased]` and the docs that describe the boundary.

Before requesting the gate, run `go test ./... -v`, `go vet ./...`, and `go fmt ./...`; `gofmt -l .` must print nothing. Review for hardcoded secrets, path traversal, races and subprocess injection. Record relevant platform checks and any untested paths in the PR.

## Review the exact head

1. Open the card PR with base `next` and mark it ready. Record its full head SHA.
2. Obtain both Gander nock-review lenses, **Opus and Sol**, at that exact head. Keep the review receipts with the PR.
3. Require CodeRabbit, `claude-review` and all applicable CI to finish successfully, including the native macOS and root netns proofs. Read failures and skips; a green aggregate or a skipped enforcement job is not evidence that the fence ran.
4. Mira gates the same head against those reviews and checks. If commits change the head, refresh the review receipts and validation before the gate; earlier-head approval does not approve the new code.

GitHub's required-check subset is a minimum, not a substitute for the complete gate below. Gander's two-lens review and Mira's decision are recorded review evidence, not checks enforced by the rulesets listed here.

## Remediation

Mira collects the findings into **one remediation-round spec on the PR**, naming the findings, required changes and acceptance checks. The **same builder** implements that spec in one focused pass, reports how each item was addressed, and returns the new exact head with validation. Reviewers do not make competing fixes on that branch. Remaining or newly discovered blockers go back through Mira; the one-round spec does not permit ignoring findings or merging a failing head.

## GitHub rules and CI coverage

Verified through the repository rules API on **2026-10-14 UTC**:

| Branch / ruleset | Required checks | Update policy |
|---|---|---|
| `next` / [next-batch-gate](https://github.com/nocktechnologies/nocklock/rules/25049433) | `CodeRabbit`, `claude-review`, `build · vet · fmt · test`, `scan`, `macOS DNS-escape · Seatbelt network floor (hosted macOS)`, `netns composed default · Landlock+seccomp+netns+audit compose (root)` | Required checks are non-strict about the base being up to date; an administrator bypass exists. The workflow still requires Mira's gate. |
| `main` / [Copilot Review](https://github.com/nocktechnologies/nocklock/rules/14719190) | All six above, plus `Analyze (go)` | Strict up-to-date checks; no ruleset bypass. Copilot review on push is also configured. |

Both rulesets block deletion and non-fast-forward updates. They do **not** enforce the one-card/one-PR convention, squash-only merging or the manual Gander/Mira gate; those remain workflow requirements. Re-read `gh api repos/nocktechnologies/nocklock/rules/branches/next` and the corresponding `/main` endpoint before changing gates. Rule changes are an owner action, not a way to clear a failed check.

The active tag ruleset [release-tags-immutable](https://github.com/nocktechnologies/nocklock/rules/25049891) targets `refs/tags/v*`, has no bypass, and blocks updates, deletion and force-moves. Creating a new release tag is allowed. Re-check `gh api repos/nocktechnologies/nocklock/rulesets/25049891` when preparing a release; release tags remain immutable.

| Workflow / proof | Runs when | Evidence needed |
|---|---|---|
| `test.yml`: build, vet, fmt, unit tests, Linux preset proof, fuzz smoke | Push to `main` or `next`; PR events; manual dispatch | Successful run for the reviewed head and post-merge batch |
| `test.yml`: macOS SBPL enforcement and full native suite | **Ready PRs only**, including the draft-to-ready transition; skipped on pushes and manual dispatch | Successful ready-PR run; a skipped push job cannot replace it |
| `network-egress.yml`: macOS DNS-escape/Seatbelt network floor, root netns jobs, red-team bench | Push to `main` or `next`; PR events | All applicable jobs pass; the two named ruleset proofs must run |

The two macOS jobs have different scope and triggers. The push-running DNS/network-floor proof does not replace the ready-PR SBPL/full-suite proof. Fork PRs also need attention: the Claude workflow skips external fork heads, while `claude-review` is required; Mira must arrange a reviewed in-repository branch to obtain that check without weakening the rule.

## Merge and release

After the exact head passes the gate, Mira squash-merges the card PR into `next` and checks the resulting push CI. Do not tag or announce it as shipped yet. The release owner promotes the approved batch through **one `next` → `main` PR**, runs the same gate on its final head, and squash-merges it. Tagging, GitHub release creation, tap update and installation smoke follow the [release runbook](../../docs/runbooks/release.md). Mira holds all card merges into `next` from release gating until the back-sync SHA is recorded. If new work lands during that freeze, stop and hand the release back to Mira; builders do not independently reconcile shared branches. Immediately after tagging, before the Homebrew step, the release owner back-syncs `main` into `next` with a real merge commit whose tree equals released main. This single direct push uses the next ruleset's administrator bypass; it is never a squash, reset or force-push. File the required session report even for docs-only work.
