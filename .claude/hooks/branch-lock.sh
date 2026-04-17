#!/usr/bin/env bash
# branch-lock.sh — PreToolUse hook
# Prevents switching branches mid-session. Reads the Bash command from
# Claude Code's JSON payload on stdin, detects git checkout/switch
# operations, and blocks any attempt to leave the locked branch.
#
# Out of scope: git merge, git rebase (apply to current branch, not switches),
# and `-b/-B` / `-c/-C` (intentional new-branch creation from locked branch).
#
# Lock file: .branch-lock in repo root (gitignored)
# Created automatically on first branch-sensitive operation in a session.
# To unlock/reset: rm .branch-lock

set -euo pipefail

# Parse payload once via stdin (avoids ARG_MAX overflow on large inputs).
# Python exits 0 with the Bash command on stdout, or non-zero to skip.
command=$(python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(1)
if d.get("tool_name") != "Bash":
    sys.exit(1)
cmd = d.get("tool_input", {}).get("command", "")
if not cmd:
    sys.exit(1)
sys.stdout.write(cmd)
') || exit 0

# Fast exit: not a git command at all.
printf '%s' "$command" | grep -qE '(^|[[:space:]])git([[:space:]]|$)' || exit 0

repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
lock_file="$repo_root/.branch-lock"

# Portable token-boundary match: "(^|[[:space:]])git <subcmd> " works on
# both GNU and BSD grep, unlike `\b` which is not POSIX ERE.
_match_git_subcmd() {
    printf '%s' "$command" | grep -qE "(^|[[:space:]])git ${1}([[:space:]]|$)"
}

# Extract the first non-flag positional arg after a given prefix.
_first_positional() {
    # Usage: _first_positional "git checkout"
    printf '%s\n' "$command" \
        | sed -E "s/.*(^|[[:space:]])${1}[[:space:]]+//" \
        | tr ' ' '\n' \
        | grep -vE '^(-|$)' \
        | head -1
}

target=""
if _match_git_subcmd "checkout"; then
    # Allow `git checkout .` (standalone dot) — file restore.
    printf '%s' "$command" | grep -qE '(^|[[:space:]])git checkout[[:space:]]+\.([[:space:]]|$)' && exit 0
    # Allow `git checkout -- <paths>` — file restore.
    printf '%s' "$command" | grep -qE '(^|[[:space:]])git checkout[[:space:]]+--([[:space:]]|$)' && exit 0
    # Allow new branch creation: `git checkout -b <name>` / `-B <name>`.
    printf '%s' "$command" | grep -qE '(^|[[:space:]])git checkout[[:space:]]+-[bB]([[:space:]]|$)' && exit 0
    target=$(_first_positional "git checkout")
elif _match_git_subcmd "switch"; then
    # Allow new branch creation: `git switch -c <name>` / `-C <name>`.
    printf '%s' "$command" | grep -qE '(^|[[:space:]])git switch[[:space:]]+-[cC]([[:space:]]|$)' && exit 0
    target=$(_first_positional "git switch")
else
    exit 0
fi

[[ -z "$target" || "$target" == "HEAD" || "$target" == "--" ]] && exit 0

current=$(git -C "$repo_root" rev-parse --abbrev-ref HEAD 2>/dev/null) || exit 0
[[ "$target" == "$current" ]] && exit 0

# Create lock on first branch-sensitive operation this session.
if [[ ! -f "$lock_file" ]]; then
    printf '%s\n' "$current" > "$lock_file"
fi
locked=$(cat "$lock_file")

# Allow switching back to the locked branch.
[[ "$target" == "$locked" ]] && exit 0

printf 'BRANCH LOCK: session is locked to %q. Blocked switch to %q. Remove .branch-lock to unlock.\n' \
    "$locked" "$target" >&2
exit 1
