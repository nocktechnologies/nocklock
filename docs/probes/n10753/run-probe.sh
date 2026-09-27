#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
PROBE_DIR="${ROOT}/docs/probes/n10753"
OUT="${PROBE_DIR}/output.txt"

WORK="$(mktemp -d "${TMPDIR:-/tmp}/nocklock-n10753-probe.XXXXXX")"
trap 'kill "${PROXY_PID:-}" 2>/dev/null || true; rm -rf "${WORK}"' EXIT

{
    echo "# NockLock N10753 AF_INET-to-AF_UNIX Node/undici probe"
    echo "date_utc=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "repo_head=$(git -C "${ROOT}" rev-parse --short HEAD)"
    echo "kernel=$(uname -a)"
    echo "node=$(node --version)"
    echo "claude=$(claude --version 2>/dev/null || true)"
    echo "gcc=$(gcc --version | head -n 1)"
    echo

    gcc -shared -fPIC -O2 -Wall -Wextra -o "${WORK}/inet_to_unix_probe.so" "${PROBE_DIR}/inet_to_unix_probe.c" -ldl
    echo "compiled_shim=${WORK}/inet_to_unix_probe.so"

    SOCK="${WORK}/proxy.sock"
    READY="${WORK}/proxy.ready"
    PROXY_LOG="${WORK}/proxy.log"
    python3 "${PROBE_DIR}/unix_connect_proxy.py" --socket "${SOCK}" --ready "${READY}" --allow api.anthropic.com >"${PROXY_LOG}" 2>&1 &
    PROXY_PID=$!

    for _ in $(seq 1 100); do
        [[ -S "${SOCK}" && -f "${READY}" ]] && break
        sleep 0.05
    done
    if [[ ! -S "${SOCK}" ]]; then
        echo "proxy_failed_to_start"
        cat "${PROXY_LOG}" || true
        exit 1
    fi

    PORT="$(python3 - <<'PY'
import socket
s=socket.socket()
s.bind(("127.0.0.1", 0))
print(s.getsockname()[1])
s.close()
PY
)"
    echo "proxy_unix_socket=${SOCK}"
    echo "proxy_advertised_tcp=127.0.0.1:${PORT}"
    echo

    run_case() {
        local name="$1"
        shift
        local case_log="${WORK}/${name}.log"
        echo "## case: ${name}"
        set +e
        (
            export HTTPS_PROXY="http://127.0.0.1:${PORT}"
            export HTTP_PROXY="http://127.0.0.1:${PORT}"
            export NO_PROXY=""
            export NODE_USE_ENV_PROXY=1
            export NOCKLOCK_PROBE_PROXY_HOST=127.0.0.1
            export NOCKLOCK_PROBE_PROXY_PORT="${PORT}"
            export NOCKLOCK_PROBE_UNIX_SOCKET="${SOCK}"
            "$@" node --use-env-proxy "${PROBE_DIR}/fetch_via_proxy.mjs"
        ) >"${case_log}" 2>&1
        local status=$?
        set -e
        echo "exit=${status}"
        sed 's/^/  /' "${case_log}"
        echo
    }

    run_case "control-no-preload" env
    run_case "preload-no-fakes" env LD_PRELOAD="${WORK}/inet_to_unix_probe.so"
    run_case "preload-fake-tcp-and-names" env LD_PRELOAD="${WORK}/inet_to_unix_probe.so" NOCKLOCK_PROBE_FAKE_TCP=1 NOCKLOCK_PROBE_FAKE_NAMES=1

    echo "## proxy log"
    sed 's/^/  /' "${PROXY_LOG}"
} | tee "${OUT}"
