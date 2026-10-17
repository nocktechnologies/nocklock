//go:build linux || darwin

package cli

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// interposerFilesystem keeps ownership and path-replacement tests unprivileged.
// Production always uses the invoking process's real UID, never SUDO_UID.
type interposerFilesystem struct {
	lstat    func(string) (os.FileInfo, error)
	readlink func(string) (string, error)
	uid      uint32
}

// realInterposerFilesystem is the production ownership view: the invoking
// process's real UID, never SUDO_UID (see the interposerFilesystem comment).
// Every production trust-walk entry point builds the filesystem the same way, so
// the real-UID invariant is written once.
func realInterposerFilesystem() interposerFilesystem {
	return interposerFilesystem{lstat: os.Lstat, readlink: os.Readlink, uid: uint32(os.Getuid())}
}

func trustedInterposerPath(path string) (string, error) {
	return inspectInterposerPath(path, realInterposerFilesystem())
}

func trustedInterposerDirectory(path string) (string, error) {
	return inspectTrustedPath(path, realInterposerFilesystem(), os.ModeDir, nil)
}

// trustedInterposerPathInProject is the production trust walk the library
// resolver uses: it inspects a candidate file and, during the walk, refuses it
// if any visited path lies inside the project (projectDirs). The resolver treats
// that refusal as a reason to try the next candidate, not to fail the launch.
func trustedInterposerPathInProject(path string, projectDirs []string) (string, error) {
	return inspectTrustedPath(path, realInterposerFilesystem(), 0, projectDirs)
}

type interposerNode struct {
	path   string
	device uint64
	inode  uint64
	owner  uint32
	mode   fs.FileMode
	target string
}

func (fsys interposerFilesystem) inspect(path string, info os.FileInfo) (interposerNode, error) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return interposerNode{}, fmt.Errorf("cannot determine owner of %q", path)
	}
	if st.Uid != 0 && st.Uid != fsys.uid {
		return interposerNode{}, fmt.Errorf("%q is owned by uid %d; require root or invoking uid %d", path, st.Uid, fsys.uid)
	}
	mode := info.Mode()
	// Symlink permission bits do not control replacement on Unix. Its owner
	// and containing directory are checked, as is every component of its target.
	if mode&os.ModeSymlink == 0 && mode.Perm()&0o022 != 0 {
		return interposerNode{}, fmt.Errorf("%q is group/world-writable (mode %04o); remove group/world write permission", path, mode.Perm())
	}
	if !mode.IsRegular() && !mode.IsDir() && mode&os.ModeSymlink == 0 {
		return interposerNode{}, fmt.Errorf("%q is not a regular file, directory, or symlink", path)
	}
	node := interposerNode{path: path, device: uint64(st.Dev), inode: uint64(st.Ino), owner: st.Uid, mode: mode}
	if mode&os.ModeSymlink != 0 {
		target, err := fsys.readlink(path)
		if err != nil {
			return interposerNode{}, fmt.Errorf("cannot read symlink %q: %v", path, err)
		}
		node.target = target
	}
	return node, nil
}

// inspectInterposerPath validates both the original spelling and every symlink
// target, including ancestors. It returns a canonical path only after a second
// observation confirms the device/inode, owner, mode and link targets are stable.
// This is bounded StrictModes-style validation, not lifetime FD pinning: root or
// the invoking UID can still change a trusted file after validation returns.
func inspectInterposerPath(path string, fsys interposerFilesystem) (string, error) {
	return inspectTrustedPath(path, fsys, 0, nil)
}

// inspectTrustedPath also validates directory ancestry before verification copies
// an executable or library there. The library entry point still requires a file.
//
// When projectDirs is non-empty (the library resolver passes the raw and
// canonical working directory), the walk additionally refuses any candidate for
// which a visited path — the original spelling, every ancestor, every symlink
// and every symlink-target hop — lies inside the project, by its raw or canonical
// spelling against either working-directory spelling. The refusal is the sentinel
// errTrustedPathWithinProject so the resolver can skip the candidate. This is a
// bounded check (at most 40 symlinks) with the same TOCTOU window as the rest of
// the walk; it says nothing about paths outside this candidate's walk.
func inspectTrustedPath(path string, fsys interposerFilesystem, wantType fs.FileMode, projectDirs []string) (string, error) {
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("filesystem fence library path must be absolute: %q", path)
	}
	initial, err := fsys.lstat(path)
	if err != nil {
		// Only a missing initial candidate lets the resolver try another location.
		return "", err
	}
	nodes := make([]interposerNode, 0, 16)
	seen := make(map[string]interposerNode)
	observe := func(path string, info os.FileInfo) (interposerNode, error) {
		// The project check runs before ownership, permission and dedup checks so
		// that a project-owned candidate is always reported as such (and skipped by
		// the resolver), never masked by a permission error that would fail closed
		// on the whole launch instead of falling back to the next candidate.
		if visitedPathWithinProject(path, projectDirs) {
			return interposerNode{}, fmt.Errorf("%w: %q", errTrustedPathWithinProject, path)
		}
		node, err := fsys.inspect(path, info)
		if err != nil {
			return interposerNode{}, err
		}
		if previous, ok := seen[path]; ok {
			if previous != node {
				return interposerNode{}, fmt.Errorf("filesystem fence library path changed during validation at %q", path)
			}
		} else {
			seen[path] = node
			nodes = append(nodes, node)
		}
		return node, nil
	}
	if _, err := observe(path, initial); err != nil {
		return "", err
	}
	current := string(os.PathSeparator)
	root, err := fsys.lstat(current)
	if err != nil {
		return "", fmt.Errorf("cannot inspect filesystem root: %v", err)
	}
	final, err := observe(current, root)
	if err != nil {
		return "", err
	}
	remaining := strings.Split(path, string(os.PathSeparator))
	links := 0
	for len(remaining) > 0 {
		part := remaining[0]
		remaining = remaining[1:]
		switch part {
		case "", ".":
			continue
		case "..":
			current = filepath.Dir(current)
			continue
		}
		current = filepath.Join(current, part)
		info, err := fsys.lstat(current)
		if err != nil {
			return "", fmt.Errorf("filesystem fence library path disappeared or became unreadable at %q: %v", current, err)
		}
		node, err := observe(current, info)
		if err != nil {
			return "", err
		}
		if node.mode&os.ModeSymlink != 0 {
			links++
			if links > 40 {
				return "", fmt.Errorf("too many symlinks in filesystem fence library path %q", path)
			}
			if filepath.IsAbs(node.target) {
				current = string(os.PathSeparator)
			} else {
				current = filepath.Dir(current)
			}
			// Do not clean the target: a component before '..' must be checked.
			remaining = append(strings.Split(node.target, string(os.PathSeparator)), remaining...)
			continue
		}
		if len(remaining) > 0 && !node.mode.IsDir() {
			return "", fmt.Errorf("filesystem fence library ancestor %q is not a directory", current)
		}
		final = node
	}
	if final.mode.Type() != wantType || final.path != current {
		kind := "regular file"
		if wantType == os.ModeDir {
			kind = "directory"
		}
		return "", fmt.Errorf("filesystem fence path %q is not a %s", current, kind)
	}
	for _, previous := range nodes {
		info, err := fsys.lstat(previous.path)
		if err != nil {
			return "", fmt.Errorf("filesystem fence library path changed during validation at %q: %v", previous.path, err)
		}
		now, err := fsys.inspect(previous.path, info)
		if err != nil {
			return "", err
		}
		if previous != now {
			return "", fmt.Errorf("filesystem fence library path changed during validation at %q", previous.path)
		}
	}
	return current, nil
}
