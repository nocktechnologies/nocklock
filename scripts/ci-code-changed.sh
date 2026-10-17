#!/usr/bin/env bash
# ci-code-changed.sh — decide whether CI runs the test suites.
#
# Prints code=true or code=false and appends it to $GITHUB_OUTPUT when set.
# code=false only for a pull_request whose every changed file is
# documentation: a *.md file anywhere, or anything under docs/. Every other
# event (push, workflow_dispatch) and every other path, .github/ included,
# is code. The checkout must be the PR merge ref with fetch-depth 2, so
# HEAD^1 is the base tip and the diff is exactly what the PR changes. A
# failed diff fails the step, so a broken detector never skips the suite.
set -euo pipefail

code=true
if [ "${GITHUB_EVENT_NAME:-}" = pull_request ]; then
  files="$(git diff --name-only HEAD^1 HEAD)"
  printf 'changed files:\n%s\n' "$files"
  if [ -n "$files" ] && ! grep -qvE '\.md$|^docs/' <<<"$files"; then
    code=false
  fi
fi

echo "code=$code"
if [ -n "${GITHUB_OUTPUT:-}" ]; then
  echo "code=$code" >>"$GITHUB_OUTPUT"
fi
