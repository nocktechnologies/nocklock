package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// verifyLibFenceTrust is the production trust check for a filesystem fence
// library candidate: root or the invoking user may own the file and every
// directory above it, and none of them may be group- or world-writable.
func verifyLibFenceTrust(path string) error {
	euid := uint32(os.Geteuid())
	return checkLibFenceTrust(path, "", func(uid uint32) bool { return uid == 0 || uid == euid })
}

// checkLibFenceTrust refuses path unless the library and all of its ancestors
// are owned by a uid accepted by trustedOwner and are not group/world-writable
// (StrictModes-style). Symlinks are checked twice: every component of the
// path as given (the link itself must be trustworthy, so a swapped link in a
// writable directory is refused) and every component of the fully resolved
// target. Ancestors at or above trustedFrom (when non-empty) are skipped: a
// test seam, since t.TempDir sits under a sticky world-writable /tmp. Ownership comes from Lstat, so tests drive it through a trustedOwner
// seam instead of chown.
func checkLibFenceTrust(path, trustedFrom string, trustedOwner func(uint32) bool) error {
	if err := checkPathChainTrust(path, trustedFrom, trustedOwner); err != nil {
		return err
	}
	real, err := filepath.EvalSymlinks(path)
	if err != nil {
		return fmt.Errorf("cannot resolve filesystem fence library %q: %w", path, err)
	}
	if real != filepath.Clean(path) {
		if err := checkPathChainTrust(real, trustedFrom, trustedOwner); err != nil {
			return fmt.Errorf("%w (reached through symlink from %q)", err, path)
		}
	}
	fi, err := os.Stat(real)
	if err != nil {
		return fmt.Errorf("cannot inspect filesystem fence library %q: %w", real, err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("filesystem fence library %q is not a regular file", real)
	}
	return nil
}

func checkPathChainTrust(path, trustedFrom string, trustedOwner func(uint32) bool) error {
	cur := string(os.PathSeparator)
	parts := strings.Split(strings.TrimPrefix(filepath.Clean(path), cur), cur)
	for i := -1; i < len(parts); i++ {
		if i >= 0 {
			cur = filepath.Join(cur, parts[i])
		}
		if trustedFrom != "" && sameOrAncestor(cur, trustedFrom) {
			continue
		}
		fi, err := os.Lstat(cur)
		if err != nil {
			return fmt.Errorf("cannot inspect %q while checking filesystem fence library trust: %w", cur, err)
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			return errors.New("cannot determine file ownership on this platform; refusing filesystem fence library")
		}
		if !trustedOwner(st.Uid) {
			return fmt.Errorf("%q is owned by uid %d, not root or the invoking user", cur, st.Uid)
		}
		if fi.Mode()&os.ModeSymlink == 0 && fi.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%q is group- or world-writable (mode %#o)", cur, fi.Mode().Perm())
		}
	}
	return nil
}

// unsafeLibFenceCandidates returns one message per installed library candidate
// that the resolver would refuse, for doctor to report.
func unsafeLibFenceCandidates() []string {
	var exePath string
	if exe, err := os.Executable(); err == nil {
		exePath = exe
	}
	var unsafe []string
	for _, c := range libFenceCandidatePaths(exePath, nil) {
		if ok, _ := fileExists(c); !ok {
			continue
		}
		if err := verifyLibFenceTrust(c); err != nil {
			unsafe = append(unsafe, fmt.Sprintf("%s: %v", c, err))
		}
	}
	return unsafe
}

// sameOrAncestor reports whether dir is path or one of its ancestors.
func sameOrAncestor(dir, path string) bool {
	rel, err := filepath.Rel(dir, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}
