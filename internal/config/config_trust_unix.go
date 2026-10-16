//go:build unix

package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// checkConfigTrust refuses a config file that a user other than the invoker (or
// root) could rewrite before the next run. It walks the file and every ancestor
// directory up to the filesystem root and refuses the config when any of them is
// group- or world-writable, owned by another user, or a symlink --
// StrictModes-style, the same rule sshd applies to its own config.
//
// What it defends is the cross-user case: on a shared host another user could
// plant a config in a world-writable directory the config search walks into, or
// own a directory in the chain and swap a component out from under the file. A
// same-user change to a config the invoker already owns is out of scope here --
// the fence root is granted read-write, so the invoker (and a child running as
// the invoker) can write an invoker-owned 0644 config that passes this check;
// the signed config.digest row is what surfaces such a change
// (internal/cli/config_digest.go).
//
// The group/world-WRITE bit is the one that matters: it is what lets another
// user replace the file or swap a directory out from under it. The sticky bit is
// deliberately NOT treated as an exemption -- a planted .nock/config.toml under a
// 1777 /tmp is the headline case.
//
// A symlink component is refused outright rather than followed: the walk is
// lexical, so a symlink's target is outside what it can vouch for, and os.ReadFile
// would follow it to that unexamined path. This mirrors ensureTrustedDir, which
// refuses a symlinked audit state directory for the same reason; FindConfig
// already resolves the directory chain, so a normal layout has no symlink
// components here.
func checkConfigTrust(path string) error {
	if isTruthyEnv(os.Getenv(AllowUntrustedConfigEnv)) {
		return nil
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("refusing to use the config file %s: its path could not be resolved: %w", path, err)
	}
	uid := configTrustUID()
	// Walk root -> leaf so the error names the shallowest offending component,
	// which is the one an operator fixes first. filepath.Abs cleans the path, so
	// the only empty element Split yields is the leading one; Join("/", "")
	// re-checks the root harmlessly.
	current := string(os.PathSeparator)
	for _, name := range strings.Split(abs, string(os.PathSeparator)) {
		current = filepath.Join(current, name)
		if reason := checkConfigComponent(current, uid); reason != nil {
			return fmt.Errorf("refusing to use the config file %s: %w", abs, reason)
		}
	}
	return nil
}

// checkConfigComponent returns the reason one component of the config path fails
// the trust rule, or nil when it passes. The caller names the config file; this
// reports only the component and its fix.
func checkConfigComponent(component string, uid uint32) error {
	info, err := configTrustLstat(component)
	if err != nil {
		return fmt.Errorf("cannot check the trust of %s: %w", component, err)
	}
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a symlink, whose target this check cannot vouch for; replace it with the real path, or set %s to accept a known-safe layout",
			component, AllowUntrustedConfigEnv)
	}
	if mode.Perm()&0o022 != 0 {
		return fmt.Errorf("%s is group- or world-writable (mode %04o); run 'chmod go-w %s', or set %s to accept a known-safe layout",
			component, mode.Perm(), component, AllowUntrustedConfigEnv)
	}
	if owner, ok := fileOwnerUID(info); ok && owner != 0 && owner != uid {
		return fmt.Errorf("%s is owned by uid %d, not root or the invoking uid %d; chown it, or set %s to accept a known-safe layout",
			component, owner, uid, AllowUntrustedConfigEnv)
	}
	return nil
}

// isTruthyEnv reports whether an environment value opts in. It is deliberately
// value-based, not presence-based: an empty value leaves the trust walk on, so
// `NOCKLOCK_ALLOW_UNTRUSTED_CONFIG=` does not silently disable it.
func isTruthyEnv(v string) bool {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}
