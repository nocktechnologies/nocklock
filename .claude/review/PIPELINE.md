# Review Pipeline — Nock Technologies

Every PR follows this 7-phase pipeline. No shortcuts.

## Phase 1: Plan
- Use superpowers plugin to plan approach
- Use Osmani spec-driven-development skill if needed
- Use Osmani planning-and-task-breakdown skill

## Phase 2: Build
- Osmani incremental-implementation (thin vertical slices)
- Osmani test-driven-development (red-green-refactor)
- Osmani context-engineering (load right context per task)

## Phase 3: Verify
- security-guidance plugin (MANDATORY for files, env, network, subprocess, auth)
- code-simplifier plugin (3 agents review and simplify)
- code-review plugin (5 parallel review agents)
- pr-review-toolkit plugin (structured PR description)

## Phase 4: Codex Gate
- STOP — tell Kevin "Ready for Codex review"
- Run Codex plugin for adversarial audit
- Address ALL findings
- Re-run Phase 3 if findings were significant

## Phase 5: Push + Auto-Review
- Push to feature branch, open PR
- Claude GitHub App auto-review
- Gemini auto-review (public repos)
- Copilot auto-review (where available)
- CodeRabbit auto-review

## Phase 6: Human Review
- Kevin reviews for product/domain fit
- Mara reviews for architecture/strategy fit

## Phase 7: Merge + Docs
- All reviews green → merge
- Update CLAUDE.md if structure changed
- Update CHANGELOG.md with what shipped
- Update README.md if user-facing changes
- Update ARCHITECTURE.md if new modules
- Update Mermaid diagrams if architecture changed
