#!/bin/sh
# install-egress-helper.sh — install NockLock's privileged Linux network-egress
# helper on a host.
#
# It writes two artifacts, both of which the netns egress fence needs at runtime:
#
#   1. A tiny root-owned shim at /usr/libexec/nocklock-egress-helper that execs
#      `nocklock __netns-helper "$@"`. The fixed, root-owned path is the boundary
#      the sudoers policy names.
#   2. A constrained NOPASSWD sudoers grant at /etc/sudoers.d/nocklock-egress
#      that lets the unprivileged `nocklock wrap` user run exactly the two helper
#      vectors (`check`, `setup --request-file <path>`) via passwordless sudo. The
#      child argv, env, and the credential to drop to travel in a 0600 per-session
#      request FILE (only the path rides argv), never on argv itself, so the fixed
#      policy is a real boundary rather than an argument-injection surface. Moving
#      the request off stdin lets sudo pass the caller's real stdin through to the
#      fenced child unchanged (N10711).
#
# Run it with root privilege, e.g. `sudo scripts/install-egress-helper.sh` or
# `sudo make install-egress-helper`. It is idempotent and fail-closed: it never
# leaves a broken file under /etc/sudoers.d — the sudoers drop-in is validated
# with `visudo -cf` (as the final root-owned 0440 file) before it is moved into
# place.
#
# The grant is written for the unprivileged user that runs `nocklock wrap`.
# Resolution order: --user <name>, then $NOCKLOCK_EGRESS_USER, then $SUDO_USER,
# then `logname`, then the current user.

set -eu

HELPER_PATH="/usr/libexec/nocklock-egress-helper"
SUDOERS_PATH="/etc/sudoers.d/nocklock-egress"
BINARY_PATH="/usr/local/bin/nocklock"

err() {
	printf 'install-egress-helper: %s\n' "$1" >&2
	exit 1
}

# --- parse arguments -------------------------------------------------------
user_override=""
while [ $# -gt 0 ]; do
	case "$1" in
	--user)
		[ $# -ge 2 ] || err "--user requires a value"
		user_override="$2"
		shift 2
		;;
	--user=*)
		user_override="${1#--user=}"
		shift
		;;
	-h | --help)
		printf 'Usage: %s [--user <name>]\n' "$0"
		printf 'Installs the root-owned egress helper shim and its NOPASSWD sudoers grant.\n'
		printf 'The target user defaults to $NOCKLOCK_EGRESS_USER, then $SUDO_USER, then logname.\n'
		exit 0
		;;
	*)
		err "unknown argument: $1"
		;;
	esac
done

# --- must be root ----------------------------------------------------------
if [ "$(id -u)" -ne 0 ]; then
	err "must run as root (try: sudo $0)"
fi

# --- the binary must already be installed ----------------------------------
if [ ! -x "$BINARY_PATH" ]; then
	err "nocklock binary not found at $BINARY_PATH — install it first (make install)"
fi

# --- resolve the unprivileged grant user -----------------------------------
target_user="$user_override"
[ -n "$target_user" ] || target_user="${NOCKLOCK_EGRESS_USER:-}"
[ -n "$target_user" ] || target_user="${SUDO_USER:-}"
[ -n "$target_user" ] || target_user="$(logname 2>/dev/null || true)"
[ -n "$target_user" ] || target_user="$(id -un)"

[ -n "$target_user" ] || err "could not determine the target user; pass --user <name>"
if [ "$target_user" = "root" ]; then
	err "refusing to grant the NOPASSWD egress policy to root (pass the unprivileged wrap user via --user <name> or NOCKLOCK_EGRESS_USER)"
fi
if ! id "$target_user" >/dev/null 2>&1; then
	err "target user '$target_user' does not exist"
fi

# --- temp files, cleaned up on any exit ------------------------------------
# The sudoers file is staged INSIDE /etc/sudoers.d as a dotted .tmp name: sudo
# ignores any include filename containing a '.', so the staged file is inert even
# if left behind, and the final move is an atomic same-directory rename (never a
# truncated, host-breaking sudoers file).
tmp_shim=""
staged_sudoers=""
cleanup() {
	[ -z "$tmp_shim" ] || rm -f "$tmp_shim"
	[ -z "$staged_sudoers" ] || rm -f "$staged_sudoers"
}
# Signal handlers must exit, not return: returning would resume the install with
# the temp files already removed, recreating the predictable path without O_EXCL.
# `exit` runs the EXIT trap, so cleanup fires once.
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

tmp_shim="$(mktemp)"
# Ensure the sudoers.d directory exists before staging a temp file inside it.
mkdir -p "$(dirname "$SUDOERS_PATH")"
staged_sudoers="$(mktemp "${SUDOERS_PATH}.XXXXXXXX")"

# --- write the shim (byte-exact, proven in CI) -----------------------------
cat >"$tmp_shim" <<'SHIM'
#!/bin/sh
exec /usr/local/bin/nocklock __netns-helper "$@"
SHIM

mkdir -p /usr/libexec
install -m 0755 -o root -g root "$tmp_shim" "$HELPER_PATH"

# --- build the sudoers policy (byte-exact alias block + user grant) --------
# The two Cmnd_Alias lines are emitted from a quoted heredoc so the trailing
# line-continuation backslash and its alignment survive verbatim; the user grant
# is printed separately so the resolved user is substituted safely.
{
	cat <<'ALIAS'
Cmnd_Alias NOCKLOCK_EGRESS = /usr/libexec/nocklock-egress-helper check, \
                             /usr/libexec/nocklock-egress-helper setup --request-file *
ALIAS
	printf '%s ALL = (root) NOPASSWD: NOCKLOCK_EGRESS\n' "$target_user"
} >"$staged_sudoers"

# Make the staged file match the real install state (root:root, 0440) BEFORE
# validating: visudo -c checks owner and mode as well as syntax.
chown root:root "$staged_sudoers"
chmod 0440 "$staged_sudoers"

if ! visudo -cf "$staged_sudoers" >/dev/null 2>&1; then
	visudo -cf "$staged_sudoers" >&2 || true
	err "refusing to install: the generated sudoers file failed visudo validation (no change made)"
fi

# Atomic same-directory rename: /etc/sudoers.d/nocklock-egress is either the old
# content or the new, never a truncated file that would break host-wide sudo.
mv -f "$staged_sudoers" "$SUDOERS_PATH"

printf 'Installed %s (0755 root:root)\n' "$HELPER_PATH"
printf 'Installed %s (0440 root:root) granting %s the NOPASSWD egress policy\n' "$SUDOERS_PATH" "$target_user"

# --- preflight AS THE TARGET USER ------------------------------------------
# The script runs as root, and root never needs a sudo password, so a bare
# `sudo -n ... check` here would prove nothing. Run it as the unprivileged
# target user, which is the credential the NOPASSWD grant actually covers.
if su -s /bin/sh "$target_user" -c "sudo -n $HELPER_PATH check" >/dev/null 2>&1; then
	printf 'Preflight OK: sudo -n %s check succeeds as %s\n' "$HELPER_PATH" "$target_user"
else
	printf 'Preflight FAIL: sudo -n %s check did not succeed as %s\n' "$HELPER_PATH" "$target_user" >&2
	printf '  The files are installed; check that `ip` and `nft` are present and that sudo picked up the drop-in.\n' >&2
	exit 1
fi
