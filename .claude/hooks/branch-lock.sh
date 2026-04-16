#!/usr/bin/env bash
# branch-lock.sh — PreToolUse hook
# Prevents switching branches mid-session. Reads the Bash command from
# Claude Code's JSON payload, detects branch-switching git operations,
# and blocks any attempt to leave the locked branch.
#
# Lock file: .branch-lock in repo root (gitignored)
# Created automatically on first branch-sensitive operation in a session.
# To unlock/reset: rm .branch-lock

set -euo pipefail

# Capture stdin once — Claude Code passes {"tool_name": "...", "tool_input": {...}}
INPUT=$(cat)

tool_name=$(python3 -c "import sys,json; print(json.loads(sys.argv[1]).get('tool_name',''))" "$INPUT" 2>/dev/null || echo "")
[[ "$tool_name" != "Bash" ]] && exit 0

command=$(python3 -c "import sys,json; print(json.loads(sys.argv[1]).get('tool_input',{}).get('command',''))" "$INPUT" 2>/dev/null || echo "")
echo "$command" | grep -qwE 'git' || exit 0

# Resolve lock file to repo root
repo_root=$(git rev-parse --show-toplevel 2>/dev/null) || exit 0
lock_file="$repo_root/.branch-lock"

# Extract target branch using sed (POSIX-portable, no grep -P)
_extract_after() {
    # Usage: _extract_after "git checkout " "$command"
    echo "$2" | sed -n "s/.*${1}\([a-zA-Z0-9/_.-]*\).*/\1/p" | head -1
}

# Detect branch-switching operations
target=""
if echo "$command" | grep -qE '\bgit checkout '; then
    # Allow file restores: git checkout -- <file>  or  git checkout .
    echo "$command" | grep -qE '\bgit checkout (--[[:space:]]|\.)' && exit 0
    # Allow new branch creation: git checkout -b / -B
    echo "$command" | grep -qE '\bgit checkout -[bB] ' && exit 0
    target=$(_extract_after 'git checkout ' "$command")
elif echo "$command" | grep -qE '\bgit switch '; then
    # Allow new branch creation: git switch -c / -C
    echo "$command" | grep -qE '\bgit switch -[cC] ' && exit 0
    target=$(_extract_after 'git switch ' "$command")
    # Strip leading flags (e.g. --detach)
    [[ "$target" == -* ]] && target=$(_extract_after 'git switch [^a-zA-Z]*' "$command")
elif echo "$command" | grep -qE '\bgit merge '; then
    target=$(_extract_after 'git merge ' "$command")
elif echo "$command" | grep -qE '\bgit rebase '; then
    target=$(_extract_after 'git rebase ' "$command")
else
    exit 0
fi

[[ -z "$target" || "$target" == "HEAD" || "$target" == "--" ]] && exit 0

current=$(git -C "$repo_root" rev-parse --abbrev-ref HEAD 2>/dev/null) || exit 0
[[ "$target" == "$current" ]] && exit 0

# Create lock on first branch-sensitive operation this session
if [[ ! -f "$lock_file" ]]; then
    echo "$current" > "$lock_file"
fi
locked=$(cat "$lock_file")

# Allow switching back to the locked branch
[[ "$target" == "$locked" ]] && exit 0

echo "BRANCH LOCK: session is locked to '$locked'. Blocked switch to '$target'. Remove .branch-lock to unlock." >&2
exit 1
