//go:build linux || darwin

package linuxinstall

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/nocktechnologies/nocklock/internal/installstate"
	"golang.org/x/sys/unix"
)

// CosignSHA256 pins the already-approved Cosign v3.1.3 Linux amd64 verifier.
const CosignSHA256 = "4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71"
const issuer = "https://token.actions.githubusercontent.com"
const identityPrefix = "https://github.com/nocktechnologies/nocklock/.github/workflows/release.yml@refs/tags/"

// Options selects local release assets. No URL or signer override is accepted.
type Options struct {
	Tag        string
	Artifacts  string
	Cosign     string
	Rollback   bool
	EgressUser string
}

type installer struct {
	base, link, helper, sudoers string
	trust                       func(string) error
	verify                      func(string, string) error
}

// Run installs or rolls back on the explicitly supported host. It never downloads
// or executes an archive-supplied script, changes configs or removes old releases.
func Run(o Options) error {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		return fmt.Errorf("run the reviewed installer as root on Ubuntu 24.04 amd64")
	}
	if _, err := ArchiveName(o.Tag); err != nil {
		return err
	}
	unix.Umask(0o077)
	osRelease, err := os.ReadFile("/etc/os-release")
	if err != nil {
		return err
	}
	fields := map[string]string{}
	for _, line := range strings.Split(string(osRelease), "\n") {
		if k, v, ok := strings.Cut(line, "="); ok {
			fields[k] = strings.Trim(v, "\"")
		}
	}
	if fields["ID"] != "ubuntu" || fields["VERSION_ID"] != "24.04" {
		return fmt.Errorf("only Ubuntu 24.04 amd64 is supported")
	}
	if err := installstate.Trusted("/usr/bin/getconf"); err != nil {
		return err
	}
	out, err := command("/usr/bin/getconf", "GNU_LIBC_VERSION")
	if err != nil || strings.TrimSpace(string(out)) != "glibc 2.39" {
		return fmt.Errorf("require glibc 2.39; install on the supported host")
	}
	i := installer{base: installstate.Base, link: installstate.Link, helper: "/usr/libexec/nocklock-egress-helper", sudoers: "/etc/sudoers.d/nocklock-egress", trust: installstate.Trusted, verify: verifySignature}
	return i.apply(o)
}

func command(name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	return commandContext(ctx, name, args...)
}

func commandContext(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LC_ALL=C"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		err := unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
		if errors.Is(err, unix.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	// sudo may create a separate session. Even then an inherited output pipe
	// cannot hold this installer (and its lease) past the cancellation budget.
	cmd.WaitDelay = 2 * time.Second
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%s failed: %w: %s", name, err, out)
	}
	return out, nil
}

func verifySignature(stage, tag string) error {
	verifier := filepath.Join(stage, "cosign")
	data, err := boundedRead(verifier, 200<<20)
	if err != nil {
		return err
	}
	if hash(data) != CosignSHA256 {
		return fmt.Errorf("Cosign v3.1.3 checksum mismatch; acquire the pinned linux-amd64 verifier")
	}
	if err := os.Chmod(verifier, 0o700); err != nil {
		return err
	}
	_, err = command(verifier, "verify-blob", filepath.Join(stage, "SHA256SUMS"), "--bundle", filepath.Join(stage, "SHA256SUMS.sigstore.json"), "--certificate-identity", identityPrefix+tag, "--certificate-oidc-issuer", issuer)
	return err
}

func boundedRead(path string, limit int64) ([]byte, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !st.Mode().IsRegular() || st.Size() > limit {
		return nil, fmt.Errorf("require bounded regular input file: %s", path)
	}
	d, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(d)) > limit {
		return nil, fmt.Errorf("input grew beyond size limit: %s", path)
	}
	return d, nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Chmod(mode); err != nil {
		return err
	}
	return f.Sync()
}

func syncDir(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

func (i installer) directory(path string) error {
	if err := i.trust(filepath.Dir(path)); err != nil {
		return err
	}
	if err := os.Mkdir(path, 0o755); err != nil {
		if !os.IsExist(err) {
			return err
		}
	} else if err := os.Chmod(path, 0o755); err != nil {
		return err
	} else {
		if err := syncDir(path); err != nil {
			return err
		}
		if err := syncDir(filepath.Dir(path)); err != nil {
			return err
		}
	}
	if err := i.trust(path); err != nil {
		return err
	}
	st, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return fmt.Errorf("require directory: %s", path)
	}
	return nil
}

func (i installer) active() (string, error) {
	st, err := os.Lstat(i.link)
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	if st.Mode()&os.ModeSymlink == 0 {
		return "", fmt.Errorf("refusing unmanaged installation at %s; migrate it explicitly", i.link)
	}
	target, err := os.Readlink(i.link)
	if err != nil {
		return "", err
	}
	tag := strings.TrimSuffix(filepath.Base(filepath.Dir(target)), "-linux-amd64")
	if !tagPattern.MatchString(tag) || target != filepath.Join(i.base, "releases", tag+"-linux-amd64", "nocklock") {
		return "", fmt.Errorf("refusing unmanaged CLI link %s", i.link)
	}
	if err := i.trust(target); err != nil {
		return "", err
	}
	return tag, nil
}

func older(tag, active string) bool {
	a, b := strings.Split(tag[1:], "."), strings.Split(active[1:], ".")
	for n := range a {
		x, _ := new(big.Int).SetString(a[n], 10)
		y, _ := new(big.Int).SetString(b[n], 10)
		if c := x.Cmp(y); c != 0 {
			return c < 0
		}
	}
	return false
}

func (i installer) apply(o Options) error {
	filename, err := ArchiveName(o.Tag)
	if err != nil {
		return err
	}
	for _, p := range []string{filepath.Dir(i.base), filepath.Dir(i.link)} {
		if err := i.trust(p); err != nil {
			return err
		}
	}
	// Never adopt a source install or the earlier fresh-only candidate layout.
	active, err := i.active()
	if err != nil {
		return err
	}
	if active == "" {
		if _, err := os.Lstat(i.base); err == nil {
			if err := i.trust(i.base); err != nil {
				return err
			}
		} else if !os.IsNotExist(err) {
			return err
		}
		if entries, err := os.ReadDir(i.base); err == nil {
			for _, entry := range entries {
				if entry.Name() != "install.lock" && entry.Name() != "releases" && !strings.HasPrefix(entry.Name(), ".stage-") {
					return fmt.Errorf("unmanaged installation in %s; migrate explicitly", i.base)
				}
			}
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if err := i.directory(i.base); err != nil {
		return err
	}
	lockPath := filepath.Join(i.base, "install.lock")
	if err := writeNew(lockPath, nil, 0o644); err != nil && !os.IsExist(err) {
		return err
	}
	if err := syncDir(i.base); err != nil {
		return err
	}
	if err := i.trust(lockPath); err != nil {
		return err
	}
	fd, err := unix.Open(lockPath, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	lock := os.NewFile(uintptr(fd), lockPath)
	defer lock.Close()
	info, err := lock.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("require a regular install lock: %s", lockPath)
	}
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		return fmt.Errorf("installation busy: stop all NockLock commands and retry: %w", err)
	}
	// Another installer may have changed activation before this lock was acquired.
	active, err = i.active()
	if err != nil {
		return err
	}
	if !o.Rollback && active != "" && older(o.Tag, active) {
		return fmt.Errorf("downgrade refused; use rollback --tag %s explicitly", o.Tag)
	}
	if o.Rollback && active == "" {
		return fmt.Errorf("rollback requires an existing managed installation")
	}
	if o.Rollback && o.EgressUser != "" {
		return fmt.Errorf("rollback does not change helper authorization")
	}
	if err := i.directory(filepath.Join(i.base, "releases")); err != nil {
		return err
	}
	stage, err := os.MkdirTemp(i.base, ".stage-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(stage) // only this invocation's private staging tree
	if err := i.trust(stage); err != nil {
		return err
	}
	release := filepath.Join(i.base, "releases", o.Tag+"-linux-amd64")
	source := o.Artifacts
	if o.Rollback {
		source = release
		if err := i.trust(release); err != nil {
			return err
		}
	}
	for name, limit := range map[string]int64{filename: maxArchive, "SHA256SUMS": 4096, "SHA256SUMS.sigstore.json": 2 << 20, "cosign": 200 << 20} {
		path := filepath.Join(source, name)
		if name == "cosign" {
			path = o.Cosign
		} else if o.Rollback {
			if err := i.trust(path); err != nil {
				return err
			}
		}
		d, err := boundedRead(path, limit)
		if err != nil {
			return err
		}
		if err := writeNew(filepath.Join(stage, name), d, 0o600); err != nil {
			return err
		}
	}
	// Only root-staged copies are authenticated; inputs are never reopened later.
	if err := i.verify(stage, o.Tag); err != nil {
		return err
	}
	archive, err := boundedRead(filepath.Join(stage, filename), maxArchive)
	if err != nil {
		return err
	}
	manifest, err := boundedRead(filepath.Join(stage, "SHA256SUMS"), 4096)
	if err != nil {
		return err
	}
	files, err := Validate(archive, manifest, o.Tag)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(release); err == nil {
		if err := i.checkRelease(release, files); err != nil {
			return err
		}
		// Same-tag retries must preserve the exact signed archive too.
		old, err := boundedRead(filepath.Join(release, filename), maxArchive)
		if err != nil {
			return err
		}
		if !bytes.Equal(old, archive) {
			return fmt.Errorf("refusing replaced bytes under existing tag %s", o.Tag)
		}
	} else if !os.IsNotExist(err) {
		return err
	} else {
		if o.Rollback {
			return fmt.Errorf("rollback target is not installed: %s", o.Tag)
		}
		pending := filepath.Join(stage, "release")
		if err := os.Mkdir(pending, 0o755); err != nil {
			return err
		}
		if err := os.Chmod(pending, 0o755); err != nil {
			return err
		}
		for n, d := range files {
			if err := writeNew(filepath.Join(pending, n), d, os.FileMode(payloadModes[n])); err != nil {
				return err
			}
		}
		for _, n := range []string{filename, "SHA256SUMS", "SHA256SUMS.sigstore.json"} {
			d, err := os.ReadFile(filepath.Join(stage, n))
			if err != nil {
				return err
			}
			if err := writeNew(filepath.Join(pending, n), d, 0o644); err != nil {
				return err
			}
		}
		if err := syncDir(pending); err != nil {
			return err
		}
		if err := os.Rename(pending, release); err != nil {
			return err
		}
		if err := syncDir(filepath.Dir(release)); err != nil {
			return err
		}
	}
	if err := i.prepareHelper(o.EgressUser); err != nil {
		return err
	}
	if active != o.Tag {
		// A new sibling symlink followed by rename is the sole activation change.
		tmp, err := os.MkdirTemp(filepath.Dir(i.link), ".nocklock-switch-")
		if err != nil {
			return err
		}
		defer os.RemoveAll(tmp)
		link := filepath.Join(tmp, "nocklock")
		if err := os.Symlink(filepath.Join(release, "nocklock"), link); err != nil {
			return err
		}
		if err := os.Rename(link, i.link); err != nil {
			return err
		}
		if err := syncDir(filepath.Dir(i.link)); err != nil {
			return fmt.Errorf("activation changed but directory sync failed; inspect %s: %w", i.link, err)
		}
	}
	if o.EgressUser != "" {
		// The helper needs a shared lease too. Downgrade ours, then recheck
		// activation because flock conversion can briefly release the old lock.
		if err := unix.Flock(fd, unix.LOCK_SH|unix.LOCK_NB); err != nil {
			return fmt.Errorf("CLI %s installed; installation changed during helper validation, retry: %w", o.Tag, err)
		}
		if now, err := i.active(); err != nil || now != o.Tag {
			return fmt.Errorf("CLI activation changed during helper validation; inspect %s and retry", i.link)
		}
		_, err := command("/usr/bin/sudo", "-u", o.EgressUser, "--", "/usr/bin/sudo", "-n", i.helper, "check")
		if err != nil {
			return fmt.Errorf("CLI %s installed; netns setup incomplete: %w", o.Tag, err)
		}
	}
	return nil
}

func (i installer) checkRelease(release string, files map[string][]byte) error {
	if err := i.trust(release); err != nil {
		return err
	}
	for n, want := range files {
		path := filepath.Join(release, n)
		if err := i.trust(path); err != nil {
			return err
		}
		got, err := boundedRead(path, maxArchive)
		if err != nil {
			return err
		}
		st, err := os.Stat(path)
		if err != nil {
			return err
		}
		if !bytes.Equal(got, want) || st.Mode().Perm() != os.FileMode(payloadModes[n]) {
			return fmt.Errorf("installed release modified at %s; refusing activation", path)
		}
	}
	return nil
}
