//go:build linux || darwin

// Package installstate coordinates immutable Linux releases with running CLIs.
package installstate

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

const (
	// Base is the root-owned system installation directory.
	Base = "/usr/local/lib/nocklock"
	// Link is the single activation point for the CLI and helper.
	Link = "/usr/local/bin/nocklock"
)

// Trusted refuses links, foreign owners, writable ancestors and special files.
func Trusted(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return fmt.Errorf("require a clean absolute install path: %q", path)
	}
	for p := path; ; p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil {
			return err
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 || info.Mode().Perm()&0o022 != 0 ||
			(!info.IsDir() && !info.Mode().IsRegular()) || (p != path && !info.IsDir()) {
			return fmt.Errorf("untrusted install path %s: require root ownership, no links and no group/other writes", p)
		}
		if p == "/" {
			return nil
		}
	}
}

// Lock opens an existing trusted lock without following links and never waits.
// The installer creates this file once; replacing or deleting it is forbidden.
func Lock(path string, exclusive bool) (*os.File, error) {
	if err := Trusted(path); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	info, err := f.Stat()
	if err != nil || !info.Mode().IsRegular() {
		f.Close()
		return nil, fmt.Errorf("require a regular install lock: %s", path)
	}
	if err := flock(f, exclusive); err != nil {
		f.Close()
		return nil, fmt.Errorf("installation busy: stop running NockLock commands or wait for the installer: %w", err)
	}
	return f, nil
}

func flock(f *os.File, exclusive bool) error {
	mode := unix.LOCK_SH
	if exclusive {
		mode = unix.LOCK_EX
	}
	return unix.Flock(int(f.Fd()), mode|unix.LOCK_NB)
}

// AcquireInvocation holds a shared lease for a versioned executable. After
// locking it checks activation again: an old inode loaded just before a switch
// must refuse, rather than launch with the new release's helper.
func AcquireInvocation(executable, base, link string) (*os.File, error) {
	if filepath.Dir(filepath.Dir(executable)) != filepath.Join(base, "releases") {
		return nil, nil // source and package-manager installs are unchanged
	}
	f, err := Lock(filepath.Join(base, "install.lock"), false)
	if err != nil {
		return nil, err
	}
	active, err := filepath.EvalSymlinks(link)
	if err != nil || active != executable {
		f.Close()
		return nil, fmt.Errorf("release changed or is inactive; rerun via %s", link)
	}
	return f, nil
}
