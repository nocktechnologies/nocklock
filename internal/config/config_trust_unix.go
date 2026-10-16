//go:build unix

package config

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// maxConfigSymlinks bounds symlink expansion in the config path walk, matching
// the kernel's own limit.
const maxConfigSymlinks = 40

// configTrustError marks a trust refusal from the config path walk, as opposed
// to an I/O failure, so readTrustedConfig words the two differently.
type configTrustError struct{ error }

// readTrustedConfig returns the contents of the config file at path after
// checking that a user other than the invoker (or root) could not rewrite it
// before the next run. It resolves path itself, one component at a time the way
// the kernel does, and checks every directory the resolution passes through:
// each ancestor of the file, each directory that holds a symlink, and each
// directory a symlink leads into. It then opens the resolved file without
// following a final symlink, checks the open handle with fstat, and reads from
// that handle, so the file that is checked is the file that is read. A ".."
// after a symlink is resolved against the symlink's target, not lexically.
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
// A symlink is followed when the directory holding it passes and the link is
// owned by root or the invoker: a system symlink such as /var -> /private/var on
// macOS loads. A symlink planted in a writable directory such as /tmp is refused
// on that directory, and a symlink into a writable or foreign-owned directory is
// refused on its target. The leaf is checked again on the open handle, so it
// cannot be swapped between check and read. Directories are checked by path; a
// trusted directory cannot be swapped by another user, which is the property the
// walk proves, but the walk has the same time-of-check window as any path walk if
// the invoker itself changes the tree.
func readTrustedConfig(path string) ([]byte, error) {
	if isTruthyEnv(os.Getenv(AllowUntrustedConfigEnv)) {
		return readConfigFile(path)
	}
	// The REAL uid, not the effective one and never SUDO_UID, matching the
	// deliberate choice in the interposer trust walk.
	uid := uint32(os.Getuid())
	resolved, leaf, err := resolveTrustedConfigPath(path, uid)
	if err != nil {
		var refusal configTrustError
		if errors.As(err, &refusal) {
			return nil, fmt.Errorf("refusing to use the config file %s: %w", path, err)
		}
		return nil, configReadError(path, err)
	}
	// Refuse a FIFO or device before opening it; O_NONBLOCK keeps one swapped in
	// after the walk from hanging the open, and the fstat check below refuses it.
	if !leaf.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing to use the config file %s: %s is not a regular file (mode %s)", path, resolved, leaf.Mode())
	}
	f, err := os.OpenFile(resolved, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, configReadError(path, err)
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, configReadError(path, err)
	}
	if !info.Mode().IsRegular() || !os.SameFile(leaf, info) {
		return nil, fmt.Errorf("refusing to use the config file %s: %s changed while it was being checked", path, resolved)
	}
	if reason := checkConfigComponent(resolved, info, uid); reason != nil {
		return nil, fmt.Errorf("refusing to use the config file %s: %w", path, reason)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, configReadError(path, err)
	}
	return data, nil
}

// resolveTrustedConfigPath resolves path component by component, following
// symlinks the way the kernel does, and refuses it when any directory it passes
// through, any symlink it follows, or the final file fails the trust rule. It
// returns the resolved path and the final component's Lstat info. A refusal
// is a configTrustError; any other error is an I/O failure such as a missing file.
//
// The walk goes root -> leaf, so a refusal names the shallowest offending
// component, which is the one an operator fixes first.
func resolveTrustedConfigPath(path string, uid uint32) (string, os.FileInfo, error) {
	if !filepath.IsAbs(path) {
		// Not filepath.Abs: it cleans "link/.." lexically, which is the bug this
		// walk exists to avoid.
		wd, err := os.Getwd()
		if err != nil {
			return "", nil, err
		}
		path = wd + string(os.PathSeparator) + path
	}
	current := string(os.PathSeparator)
	info, err := checkedLstat(current, uid)
	if err != nil {
		return "", nil, err
	}
	pending := strings.Split(path, string(os.PathSeparator))
	links := 0
	for len(pending) > 0 {
		name := pending[0]
		pending = pending[1:]
		switch name {
		case "", ".":
			continue
		}
		if !info.IsDir() {
			return "", nil, fmt.Errorf("%s: %w", current, syscall.ENOTDIR)
		}
		if name == ".." {
			// current is already resolved, so its lexical parent is its real one,
			// and every directory above it was checked on the way down.
			current = filepath.Dir(current)
			if info, err = configTrustLstat(current); err != nil {
				return "", nil, err
			}
			continue
		}
		next := filepath.Join(current, name)
		nextInfo, err := configTrustLstat(next)
		if err != nil {
			return "", nil, err
		}
		if nextInfo.Mode()&os.ModeSymlink != 0 {
			// The directory holding the link was checked; the link itself must
			// belong to root or the invoker. Its mode bits mean nothing on Linux.
			if owner, ok := fileOwnerUID(nextInfo); ok && owner != 0 && owner != uid {
				return "", nil, configTrustError{fmt.Errorf("%s is a symlink owned by uid %d, not root or the invoking uid %d; replace it, or set %s to accept a known-safe layout",
					next, owner, uid, AllowUntrustedConfigEnv)}
			}
			if links++; links > maxConfigSymlinks {
				return "", nil, fmt.Errorf("%s: %w", path, syscall.ELOOP)
			}
			target, err := os.Readlink(next)
			if err != nil {
				return "", nil, err
			}
			if filepath.IsAbs(target) {
				current = string(os.PathSeparator)
				if info, err = checkedLstat(current, uid); err != nil {
					return "", nil, err
				}
			}
			pending = append(strings.Split(target, string(os.PathSeparator)), pending...)
			continue
		}
		if reason := checkConfigComponent(next, nextInfo, uid); reason != nil {
			return "", nil, configTrustError{reason}
		}
		current, info = next, nextInfo
	}
	return current, info, nil
}

// checkedLstat returns the Lstat info for a directory the walk restarts from
// (the filesystem root), refusing it when it fails the trust rule.
func checkedLstat(dir string, uid uint32) (os.FileInfo, error) {
	info, err := configTrustLstat(dir)
	if err != nil {
		return nil, err
	}
	if reason := checkConfigComponent(dir, info, uid); reason != nil {
		return nil, configTrustError{reason}
	}
	return info, nil
}

// checkConfigComponent returns the reason one resolved component of the config
// path fails the trust rule, or nil when it passes. StrictModes-style, the same
// rule sshd applies to its own config. The caller names the config file; this
// reports only the component and its fix.
//
// The group/world-WRITE bit is the one that matters: it is what lets another
// user replace the file or swap a directory out from under it. The sticky bit is
// deliberately NOT treated as an exemption -- a planted .nock/config.toml under a
// 1777 /tmp is the headline case.
func checkConfigComponent(component string, info os.FileInfo, uid uint32) error {
	mode := info.Mode()
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
