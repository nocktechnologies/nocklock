@AGENTS.md

Claude Code only: `.claude/hooks/branch-lock.sh` runs before every Bash call and blocks `git checkout` / `git switch` away from the session's first branch. Do not weaken it; delete the gitignored `.branch-lock` to unlock.
