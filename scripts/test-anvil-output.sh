#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="${repo_root}/scripts/anvil-output.py"
temp_dir="$(mktemp -d)"
trap 'rm -rf "${temp_dir}"' EXIT
output_file="${temp_dir}/review.txt"

check() {
  local label="$1" expected="$2" content="$3" actual
  printf '%s' "${content}" > "${output_file}"
  actual="$(python3 "${script}" verdict "${output_file}")"
  if [[ "${actual}" != "${expected}" ]]; then
    echo "FAIL ${label}: expected ${expected}, got ${actual}" >&2
    exit 1
  fi
  echo "PASS ${label}"
}

check "sentinel passes" clean $'ANVIL_NO_FINDINGS\n'
check "finding fails" findings $'- [P1] Unsafe redirect - src/main.go:42\n'
check "free-form fails closed" unparseable $'The review looks fine.\n'
check "finding overrides sentinel" findings $'ANVIL_NO_FINDINGS\n- [P2] Unexpected write - src/main.go:17\n'
check "sentinel with extra prose fails closed" unparseable $'ANVIL_NO_FINDINGS\nExtra prose\n'
