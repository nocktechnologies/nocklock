package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// maxFingerprintBytes bounds how much of the resolved executable is read. A
// larger file is recorded as oversized rather than hashed.
const maxFingerprintBytes = 256 << 20

// Observation statuses recorded in the signed session-start row.
const (
	execHashed     = "hashed"
	execUnresolved = "unresolved"
	execUnreadable = "unreadable"
	execNotRegular = "not_regular"
	execOversized  = "oversized"
)

// launcherNames are commands that exec another program. Their hash identifies
// the launcher, never the agent they start.
var launcherNames = map[string]bool{
	"env": true, "sudo": true, "doas": true, "nohup": true, "timeout": true,
	"xargs": true, "nice": true, "setsid": true, "stdbuf": true, "chroot": true,
	"npx": true, "bunx": true, "pnpx": true, "uvx": true, "pipx": true,
}

// execFingerprint is what NockLock observed about the requested command just
// before launch.
type execFingerprint struct {
	Path   string
	SHA256 string
	Status string
	Kind   string // "", "script" or "launcher"
}

// Detail renders the fingerprint as key=value fields for the start row.
func (f execFingerprint) Detail() string {
	d := fmt.Sprintf(" exec_status=%s", f.Status)
	if f.Path != "" {
		d += fmt.Sprintf(" exec_path=%q", f.Path)
	}
	if f.SHA256 != "" {
		d += " exec_sha256=" + f.SHA256
	}
	if f.Kind != "" {
		d += " exec_kind=" + f.Kind
	}
	return d
}

// fingerprintExecutable hashes the already-resolved executable at path. The
// caller resolves the requested command (e.g. via resolveChildArgv) once and
// passes that same path here, so the file fingerprinted is always the file
// that gets exec'd — this function does not re-resolve or search PATH. It
// always describes the requested command, never a NockLock shim, sandbox-exec
// or netns helper placed in front of it. It reads at most maxFingerprintBytes
// from a regular file and never blocks on a FIFO or device. It cannot fail the
// launch: every outcome is a status. The hash is taken before exec, so the
// file can change in between.
func fingerprintExecutable(path string) execFingerprint {
	fp := execFingerprint{Path: path}
	if launcherNames[filepath.Base(path)] {
		fp.Kind = "launcher"
	}
	// O_NONBLOCK so opening a FIFO cannot hang; the type check uses the open fd.
	f, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		fp.Status = execUnreadable
		return fp
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		fp.Status = execUnreadable
		return fp
	}
	if !info.Mode().IsRegular() {
		fp.Status = execNotRegular
		return fp
	}
	if info.Size() > maxFingerprintBytes {
		fp.Status = execOversized
		return fp
	}
	h := sha256.New()
	// Read one byte past the cap so a file that grew after Stat is caught.
	n, err := io.Copy(h, io.LimitReader(f, maxFingerprintBytes+1))
	if err != nil {
		fp.Status = execUnreadable
		return fp
	}
	if n > maxFingerprintBytes {
		fp.Status = execOversized
		return fp
	}
	fp.Status = execHashed
	fp.SHA256 = hex.EncodeToString(h.Sum(nil))
	if fp.Kind == "" {
		var magic [2]byte
		if _, err := f.ReadAt(magic[:], 0); err == nil && magic == [2]byte{'#', '!'} {
			fp.Kind = "script"
		}
	}
	return fp
}
