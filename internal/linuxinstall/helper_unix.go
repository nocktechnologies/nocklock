//go:build linux || darwin

package linuxinstall

import (
	"bytes"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
)

var userPattern = regexp.MustCompile(`^[a-z_][a-z0-9_-]*[$]?$`)

func (i installer) helperBytes() []byte {
	// The managed CLI checks its active release under the shared install lock
	// before servicing the helper. No archive-supplied shell code runs as root.
	return []byte("#!/bin/sh\n# NockLock managed install protocol 1\nexec " + i.link + " __netns-helper \"$@\"\n")
}

func (i installer) policy(name string) []byte {
	return []byte("# NockLock managed install protocol 1\n" + name + " ALL=(root) NOPASSWD: " + i.helper + " check, " + i.helper + " setup --request-file *\n")
}

func (i installer) prepareHelper(name string) error {
	existing := false
	for _, path := range []string{i.helper, i.sudoers} {
		if st, err := os.Lstat(path); err == nil {
			if err := i.trust(path); err != nil {
				return err
			}
			mode := os.FileMode(0o755)
			if path == i.sudoers {
				mode = 0o440
			}
			if st.Mode().Perm() != mode {
				return fmt.Errorf("unexpected mode on %s; require %04o", path, mode)
			}
			data, err := boundedRead(path, 4096)
			if err != nil {
				return err
			}
			if path == i.helper && !bytes.Equal(data, i.helperBytes()) {
				return fmt.Errorf("unmanaged helper at %s; migrate explicitly", path)
			}
			if path == i.sudoers {
				pattern := regexp.MustCompile(`^# NockLock managed install protocol 1\n([a-z_][a-z0-9_-]*[$]?) ALL=`)
				match := pattern.FindSubmatch(data)
				if len(match) != 2 || !bytes.Equal(data, i.policy(string(match[1]))) {
					return fmt.Errorf("unmanaged sudoers policy at %s; migrate explicitly", path)
				}
			}
			existing = true
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if name == "" {
		if existing {
			for _, path := range []string{i.helper, i.sudoers} {
				if err := i.trust(path); err != nil {
					return fmt.Errorf("incomplete helper installation: %w", err)
				}
			}
		}
		return nil
	}
	if !userPattern.MatchString(name) {
		return fmt.Errorf("invalid local account name; pass --egress-user with a non-root account")
	}
	account, err := user.Lookup(name)
	if err != nil {
		return err
	}
	if account.Uid == "0" {
		return fmt.Errorf("refusing a root egress grant; select the unprivileged wrap account")
	}
	for _, path := range []string{"/usr/bin/sudo", "/usr/sbin/visudo", "/usr/sbin/ip", "/usr/sbin/nft"} {
		// ip is a /bin symlink on some images; resolve the system tool once,
		// then validate its complete real path before any grant is written.
		real, err := filepath.EvalSymlinks(path)
		if err != nil {
			return fmt.Errorf("install sudo, iproute2 and nftables first: %w", err)
		}
		if err := i.trust(real); err != nil {
			return err
		}
	}
	for _, path := range []string{filepath.Dir(i.helper), filepath.Dir(i.sudoers)} {
		if err := i.directory(path); err != nil {
			return err
		}
	}
	// A dotted temporary policy is ignored by sudo even after an interruption.
	temp, err := os.MkdirTemp(filepath.Dir(i.sudoers), ".nocklock-policy-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(temp)
	policy := filepath.Join(temp, "policy")
	if err := writeNew(policy, i.policy(name), 0o440); err != nil {
		return err
	}
	if _, err := command("/usr/sbin/visudo", "-cf", policy); err != nil {
		return err
	}
	tempHelper, err := os.MkdirTemp(filepath.Dir(i.helper), ".nocklock-helper-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tempHelper)
	shim := filepath.Join(tempHelper, "helper")
	if err := writeNew(shim, i.helperBytes(), 0o755); err != nil {
		return err
	}
	if err := os.Rename(shim, i.helper); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(i.helper)); err != nil {
		return err
	}
	if err := os.Rename(policy, i.sudoers); err != nil {
		return err
	}
	return syncDir(filepath.Dir(i.sudoers))
}
