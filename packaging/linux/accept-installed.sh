#!/usr/bin/env bash
# Run only as the new, unprivileged CI account, outside the source checkout.
set -euo pipefail
export LC_ALL=C
[[ $(id -u) != 0 && $(id -un) == nocklock-candidate ]]
[[ $# == 2 && $1 =~ ^[0-9a-f]{40}$ && $2 == /* ]]
commit=$1
evidence=$2
mkdir -m 0700 "$evidence"
bin=/usr/local/bin/nocklock
"$bin" version | tee "$evidence/version.txt"
grep -Fxq "NockLock v0.0.0-candidate.$commit" "$evidence/version.txt"
readlink -f "$bin" > "$evidence/installed-path.txt"
grep -Fxq "/usr/local/lib/nocklock/releases/nocklock-candidate-$commit-linux-amd64/nocklock" "$evidence/installed-path.txt"
sudo -k
sudo -n -l | tee "$evidence/sudo-l.txt" >/dev/null
if sudo -n /usr/bin/true 2>/dev/null; then
  echo 'FAIL: acceptance user has an unrelated passwordless root grant' >&2
  exit 1
fi
/usr/bin/python3 -I - "$evidence/sudo-l.txt" <<'PY'
import re, sys
text = open(sys.argv[1]).read().split('may run the following commands', 1)[1]
text = text.split('\n', 1)[1]
entries = re.sub(r'^\s*\([^)]*\)\s*NOPASSWD:\s*', '', text, flags=re.M)
entries = {x.strip() for x in re.split(r',\s+(?=/)', entries.strip())}
assert entries == {'/usr/libexec/nocklock-egress-helper check', '/usr/libexec/nocklock-egress-helper setup --request-file *'}, entries
PY
sudo -n /usr/libexec/nocklock-egress-helper check | tee "$evidence/helper-check.txt" >/dev/null

# Stock Ubuntu login shape: umask 002 under a private group. A 0775 project
# owned by this account's private group must load; the same project at 0777
# must still be refused.
trust=$(mktemp -d "$HOME/nocklock-accept-trust.XXXXXX")
[[ $(stat --format=%G "$trust") == "$(id -un)" && $(id -gn) == "$(id -un)" ]]
chmod 0775 "$trust"
(cd "$trust" && "$bin" init > "$evidence/trust-init.txt")
for trust_mode in 0775 0777; do
  chmod "$trust_mode" "$trust"
  stat --format='%n uid=%U gid=%G mode=%a' "$trust" > "$evidence/trust-$trust_mode.stat"
  (cd "$trust" && "$bin" doctor --json > "$evidence/trust-$trust_mode.json") || true
done
/usr/bin/python3 -I - "$evidence/trust-0775.json" "$evidence/trust-0777.json" <<'PY'
import json, sys
def config(path):
    report = json.load(open(path))
    return next(c for c in report["checks"] if c["name"] == "config")
loaded = config(sys.argv[1])
assert loaded["status"] == "loaded", ("0775 private-group project refused", loaded)
refused = config(sys.argv[2])
assert refused["status"] != "loaded", ("0777 project loaded", refused)
assert "group- or world-writable (mode 0777)" in refused["message"], refused
PY
chmod 0700 "$trust"

for mode in proxy netns; do
  fixture=$(mktemp -d "$HOME/nocklock-accept-$mode.XXXXXX")
  record="$evidence/$mode"
  mkdir "$fixture/project" "$fixture/outside" "$record"
  cd "$fixture/project"
  "$bin" init > "$record/init.txt"
  doctor_exit=0
  "$bin" doctor --json > "$record/doctor.json" || doctor_exit=$?
  /usr/bin/python3 -I /usr/local/bin/nocklock-check-acceptance-ci.py "$record/doctor.json" "$doctor_exit"
  cat > probe.py <<'PY'
import errno, pathlib, sys
pathlib.Path('allowed.txt').write_text('allowed\n')
assert pathlib.Path('allowed.txt').read_text() == 'allowed\n'
try:
    pathlib.Path(sys.argv[1]).write_text('must be denied\n')
except OSError as exc:
    if exc.errno not in (errno.EACCES, errno.EPERM):
        raise
    print('OUTSIDE_WRITE_DENIED errno=' + str(exc.errno))
else:
    raise SystemExit('FAIL: outside write succeeded')
print('ALLOW_AND_DENY_PASS')
PY
  /usr/bin/python3 -I - "$fixture/outside/control.txt" <<'PY'
import pathlib, sys
pathlib.Path(sys.argv[1]).write_text('host positive control\n')
PY
  mode_args=()
  level=CONFINED
  if [[ $mode == netns ]]; then mode_args=(--net-fence=netns); level=KERNEL; fi
  timeout --kill-after=5s 60s "$bin" wrap "${mode_args[@]}" --require-enforced-egress -- \
    /usr/bin/python3 -I probe.py "$fixture/outside/forbidden.txt" > "$record/wrap.txt" 2>&1
  grep -Fxq ALLOW_AND_DENY_PASS "$record/wrap.txt"
  [[ -f allowed.txt && ! -e "$fixture/outside/forbidden.txt" ]]
  "$bin" verify --export-pubkey > "$record/public-key.txt"
  pub=$(cat "$record/public-key.txt")
  [[ -n $pub ]]
  "$bin" verify --audit --ed25519-pub "$pub" > "$record/audit.txt"
  grep -q '^AUDIT: AUTHENTIC' "$record/audit.txt"
  "$bin" log --json > "$record/events.json"
  /usr/bin/python3 -I - "$record/events.json" "$level" "$record/receipt.json" "$commit" "$doctor_exit" <<'PY'
import json, sys
events = json.load(open(sys.argv[1]))
starts = [e for e in events if e['EventType'] == 'session_start']
assert len(starts) == 1, 'expected exactly one session in a fresh project'
assert starts[0]['egress_level'] == sys.argv[2], starts[0]
receipt = dict(kind='ci-candidate-acceptance-not-release', commit=sys.argv[4],
               egress_level=starts[0]['egress_level'], audit='AUTHENTIC',
               filesystem_allow=True, filesystem_deny_errno=True,
               doctor_exit=int(sys.argv[5]), session_id=starts[0]['SessionID'])
with open(sys.argv[3], 'w') as f: json.dump(receipt, f, indent=2)
PY
done
printf 'ACCEPTED candidate %s: signed CONFINED and KERNEL; evidence %s\n' "$commit" "$evidence"
