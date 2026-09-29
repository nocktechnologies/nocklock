#!/usr/bin/env bash
# Exercise the generated default policy with a new home and the full Linux fence.
set -euo pipefail

if [[ "$(uname -s)" != Linux ]]; then
    echo "Linux only" >&2
    exit 1
fi

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
scratch=$(mktemp -d "${HOME}/nocklock-init-default.XXXXXX")
read_only=$(mktemp -d /tmp/nocklock-init-read-only.XXXXXX)
trap 'rm -rf "$scratch" "$read_only"' EXIT

mkdir -p "$scratch/home" "$scratch/project" "$scratch/outside"
cp "$repo/nocklock" "$read_only/nocklock"
cp "$repo/internal/fence/fs/interposer/libfence_fs.so" "$read_only/libfence_fs.so"

run_fenced() {
    (cd "$scratch/project" && env -i HOME="$scratch/home" PATH=/usr/bin:/bin USER=nocklock-test \
        "$read_only/nocklock" "$@")
}

run_fenced init
output=$(run_fenced wrap -- /bin/sh -c 'echo ok' 2>&1) || {
    echo "$output" >&2
    exit 1
}
[[ "$output" == *$'\nok'* ]] || { echo "wrapped shell did not print ok: $output" >&2; exit 1; }

run_fenced wrap -- /bin/sh -c 'echo ok > in-project' >/dev/null
[[ "$(cat "$scratch/project/in-project")" == ok ]] || {
    echo "fence blocked the project-root write" >&2
    exit 1
}

for denied in "$scratch/outside/blocked" "$read_only/blocked"; do
    [[ -w "$(dirname "$denied")" ]] || { echo "negative-control directory is not host-writable" >&2; exit 1; }
    # The second shell has no interposer; a denial here comes from Landlock.
    if output=$(run_fenced wrap -- /usr/bin/env -u LD_PRELOAD /bin/sh -c \
        'test -z "${LD_PRELOAD:-}" || exit 99; echo WRITE_ATTEMPT; echo blocked > "$1"' sh "$denied" 2>&1); then
        echo "fence allowed write to $denied" >&2
        exit 1
    fi
    [[ "$output" == *"WRITE_ATTEMPT"* ]] || { echo "unpreloaded shell did not reach write: $output" >&2; exit 1; }
    [[ ! -e "$denied" ]] || { echo "fence created $denied" >&2; exit 1; }
    [[ "$output" == *"Permission denied"* || "$output" == *"permission denied"* ]] || {
        echo "write failed for an unexpected reason: $output" >&2
        exit 1
    }
done

echo "PASS: init wraps /bin/sh; project write succeeds; Landlock denies sibling and read-only /tmp writes"
