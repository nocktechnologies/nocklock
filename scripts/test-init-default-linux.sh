#!/usr/bin/env bash
# Exercise the generated default policy with a new home and the full Linux fence.
set -euo pipefail
# The interposer trust walk refuses group/world-writable ancestors. Under a
# caller umask of 002 the probe dirs below (and cp's copies) would be created
# group-writable and refused, so pin the mask before creating anything.
umask 022

if [[ "$(uname -s)" != Linux ]]; then
    echo "Linux only" >&2
    exit 1
fi

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
scratch=
read_only=
probe_bin=
trap 'rm -rf -- "$scratch" "$read_only"; if [[ -n "$probe_bin" ]]; then sudo rm -rf -- "$probe_bin"; fi' EXIT
scratch=$(mktemp -d "${HOME}/nocklock-init-default.XXXXXX")
read_only=$(mktemp -d /tmp/nocklock-init-read-only.XXXXXX)

mkdir -p "$scratch/home" "$scratch/project" "$scratch/outside"
# CI-only: install the executable pair beneath the default /usr grant. Agent
# login stores are no longer a generic runtime grant.
[[ "${GITHUB_ACTIONS:-}" == true ]] || { echo "CI only" >&2; exit 1; }
probe_bin=$(sudo mktemp -d /usr/local/lib/nocklock-init-proof.XXXXXX)
sudo chmod 0755 "$probe_bin"
sudo install -m 0755 "$repo/nocklock" "$probe_bin/nocklock"
sudo install -m 0755 "$repo/internal/fence/fs/interposer/libfence_fs.so" "$probe_bin/libfence_fs.so"

run_fenced() {
    (cd "$scratch/project" && env -i HOME="$scratch/home" PATH=/usr/bin:/bin USER=nocklock-test \
        "$probe_bin/nocklock" "$@")
}

run_fenced init
output=$(run_fenced wrap -- /bin/sh -c 'echo ok' 2>&1) || {
    echo "$output" >&2
    exit 1
}
grep -Fxq ok <<<"$output" || { echo "wrapped shell did not print ok: $output" >&2; exit 1; }

# Exercise the runtime data grants without relying on external network access.
run_fenced wrap -- /bin/sh -ec '
    getent passwd "$(id -u)" >/dev/null
    getent group "$(id -g)" >/dev/null
    getent hosts localhost >/dev/null
    date +%Z >/dev/null
    for path in /etc/ld.so.cache /etc/passwd /etc/group /etc/nsswitch.conf /etc/hosts /etc/resolv.conf /etc/localtime; do
        if [ -e "$path" ]; then cat "$path" >/dev/null; fi
    done
    if [ -f /etc/ssl/certs/ca-certificates.crt ] && command -v openssl >/dev/null 2>&1; then
        openssl crl2pkcs7 -nocrl -certfile /etc/ssl/certs/ca-certificates.crt >/dev/null
    fi
' >/dev/null

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

# Verify must stage its own Linux executable pair under trusted ancestors too.
# A skipped filesystem probe would hide the original /var/tmp staging regression.
# Capture the exit status and JSON without letting -e end the script. This script
# owns only the filesystem result, so it asserts exactly one filesystem check and
# that it is PASS. The exit code is deliberately NOT asserted: verify exits
# nonzero for any failing fence check, including ones outside this script's scope
# (e.g. the syscall probe, which some hosted runners break independently of this
# PR; carded as N11822). The full JSON and status are printed whenever the exit
# is nonzero so any such result stays visible rather than silently tolerated.
verify_status=0
run_fenced verify --json > "$scratch/verify.json" 2> "$scratch/verify.err" || verify_status=$?
python3 - "$scratch/verify.json" "$scratch/verify.err" "$verify_status" <<'PYVERIFY'
import json, sys
path, err_path, status = sys.argv[1], sys.argv[2], int(sys.argv[3])
raw = open(path).read()
err = open(err_path).read()
def fail(message):
    sys.exit("verify: %s (exit %d)\nstdout: %s\nstderr: %s" % (message, status, raw, err))
# A nonzero exit is not asserted (see the shell comment above), but print the
# full report and status so a surprising nonzero exit is never silent.
if status != 0:
    print("verify: exited %d; full report follows:\nstdout: %s\nstderr: %s"
          % (status, raw, err), file=sys.stderr)
try:
    checks = json.loads(raw)["checks"]
except (ValueError, KeyError):
    fail("no parsable JSON report")
filesystem = [c for c in checks if c["fence"] == "filesystem"]
if len(filesystem) != 1 or filesystem[0]["result"] != "PASS":
    fail("expected exactly one filesystem check with result PASS")
PYVERIFY

echo "PASS: init wraps /bin/sh; project write succeeds; Landlock denies sibling and read-only /tmp writes; verify filesystem PASS"
