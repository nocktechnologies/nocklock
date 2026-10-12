#!/usr/bin/env bash
# Red-team bench runner (N11623). Builds a scratch fence project, then hands off
# to redteam.py, which runs every attack in attacks.toml inside `nocklock wrap`,
# runs both `verify` commands, and writes REPORT.md + report.json next to this
# script. Exit 0 only if the whole pass bar holds.
#
# Needs: nocklock (NOCKLOCK_BIN or on PATH) with the netns egress helper and
# libfence_fs.so installed, nockguard (NOCKGUARD_BIN or on PATH), python3 >= 3.11,
# and runner egress to example.com for the negative control.
set -euo pipefail

here=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
nocklock=${NOCKLOCK_BIN:-$(command -v nocklock || true)}
nockguard=${NOCKGUARD_BIN:-$(command -v nockguard || true)}
[ -x "$nocklock" ] || { echo "run.sh: set NOCKLOCK_BIN or put nocklock on PATH" >&2; exit 2; }
[ -x "$nockguard" ] || { echo "run.sh: set NOCKGUARD_BIN or put nockguard on PATH" >&2; exit 2; }

# The scratch root must sit outside every directory the fence grants (/tmp/ is in the
# stock allow list and the fs-event socket lives there, so /tmp/ stays granted), or the
# evidence the verifiers read (canary, audit state, NockGuard key and trail) would be
# reachable from inside the fence. redteam.py re-checks that against the written config
# and stops with SETUP-FAULT before any attack runs. Left in place for inspection.
base=${RUNNER_TEMP:-$HOME/.cache/nocklock-bench}
mkdir -p "$base"
work=$(mktemp -d "$base/work.XXXXXX")
umask 077
mkdir -p "$work/root/.nock" "$work/root/logs" "$work/outside" "$work/bin" "$work/policy" "$work/state" \
  "$work/sock" "$work/home/.nockguard/logs"

printf 'bench-canary-not-a-real-secret\n' > "$work/outside/canary.txt"
cp "$here/mcp_client.py" "$here/mcp_upstream.py" "$work/bin/"

# NockGuard: default-deny policy for the bench agent, signed trail via the per-agent
# Ed25519 key that keygen drops under $HOME/.nockguard/keys. The proxy runs on the host
# side (redteam.py brokers it behind $work/sock); the fenced child gets neither the
# key, the trail, the policy nor the nockguard binary, only the broker's socket.
cat > "$work/policy/policy.yaml" <<POLICY
agents:
  bench:
    allow:
      - "docs_get"
    deny:
      - "*delete*"
  default:
    mode: deny
audit:
  enabled: true
  path: $work/home/.nockguard/logs/audit.jsonl
POLICY
HOME="$work/home" "$nockguard" keygen --agent bench >/dev/null

cat > "$work/root/.nock/config.toml" <<CONFIG
[project]
name = "redteam-bench"
root = "."

[filesystem]
root = "."
mode = "read-write"
linux_enforcement = "required"
allow = [
    "/tmp/", "/usr/", "/bin/", "/lib/", "/lib64/",
    "/etc/ld.so.cache", "/etc/passwd", "/etc/group", "/etc/nsswitch.conf",
    "/etc/hosts", "/etc/resolv.conf", "/etc/localtime",
    "/etc/ssl/certs/", "/etc/pki/tls/certs/", "/etc/pki/ca-trust/extracted/",
    "$work/bin/", "$work/sock/",
]
allow_rw = []
deny = []

[network]
allow = ["example.com"]
allow_all = false
require_enforced = true

[secrets]
pass = ["HOME", "PATH", "SHELL", "USER", "LANG", "TERM"]
block = ["AWS_*", "STRIPE_*", "DATABASE_URL", "ANTHROPIC_API_KEY", "OPENAI_API_KEY", "*_SECRET*", "*_PASSWORD*", "*_TOKEN*"]

[syscall]
enforcement = "required"
allow_namespaces = false
socket_families = ["unix", "inet", "inet6"]

[logging]
db = "events.db"
level = "info"
CONFIG

exec python3 "$here/redteam.py" --work "$work" --out "$here" \
  --nocklock "$nocklock" --nockguard "$nockguard"
