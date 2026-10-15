#!/usr/bin/env bash
# Exercise the generated default policy with a new home and the full Linux fence.
set -euo pipefail

if [[ "$(uname -s)" != Linux ]]; then
    echo "Linux only" >&2
    exit 1
fi

repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
scratch=
read_only=
trap 'rm -rf -- "$scratch" "$read_only"' EXIT
scratch=$(mktemp -d "${HOME}/nocklock-init-default.XXXXXX")
read_only=$(mktemp -d /tmp/nocklock-init-read-only.XXXXXX)

mkdir -p "$scratch/home" "$scratch/project" "$scratch/outside"
# The interposer must not have /tmp's world-writable ancestor. ~/.claude
# already has a default read-only grant; retain /tmp for its separate deny test.
probe_bin="$scratch/home/.claude/nocklock-test"
mkdir -p "$probe_bin"
cp "$repo/nocklock" "$probe_bin/nocklock"
cp "$repo/internal/fence/fs/interposer/libfence_fs.so" "$probe_bin/libfence_fs.so"

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
# Capture the exit status and JSON without letting -e end the script, so a
# failing check is reported by name instead of as a silent exit 1.
verify_status=0
run_fenced verify --json > "$scratch/verify.json" 2> "$scratch/verify.err" || verify_status=$?
python3 - "$scratch/verify.json" "$scratch/verify.err" "$verify_status" <<'PYVERIFY'
import json, sys
path, err_path, status = sys.argv[1], sys.argv[2], int(sys.argv[3])
raw = open(path).read()
err = open(err_path).read()
def fail(message):
    sys.exit("verify: %s (exit %d)\nstdout: %s\nstderr: %s" % (message, status, raw, err))
try:
    checks = json.loads(raw)["checks"]
except (ValueError, KeyError):
    fail("no parsable JSON report")
# The syscall probe needs unprivileged user namespaces, which hosted runners
# can restrict; that is a property of the host, not of the filesystem fence
# this script exercises. Any other FAIL, and every filesystem result, is fatal.
host_limited = "unshare(CLONE_NEWUSER) unavailable"
failed = ["%s (%s)" % (c["fence"], c.get("detail", "")) for c in checks
          if c["result"] == "FAIL" and not (c["fence"] == "syscall" and host_limited in c.get("detail", ""))]
if failed:
    fail("failing check(s): " + ", ".join(failed))
filesystem = [c for c in checks if c["fence"] == "filesystem"]
if len(filesystem) != 1 or filesystem[0]["result"] != "PASS":
    fail("filesystem check is not a single PASS")
for c in checks:
    if c["result"] == "FAIL":
        print("verify: tolerated host limitation: %s: %s" % (c["fence"], c["detail"]), file=sys.stderr)
PYVERIFY

echo "PASS: init wraps /bin/sh; project write succeeds; Landlock denies sibling and read-only /tmp writes; verify filesystem PASS"
