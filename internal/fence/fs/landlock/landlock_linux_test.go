//go:build linux

package landlock

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
)

const landlockProbeEnv = "NOCKLOCK_LANDLOCK_PROBE"
const socketOnlyReferProbeEnv = "NOCKLOCK_SOCKET_ONLY_REFER_PROBE"

func TestLandlockSocketOnlyPreservesCrossDirectoryOperations(t *testing.T) {
	if os.Getenv(socketOnlyReferProbeEnv) != "" {
		runSocketOnlyReferProbe(t)
		return
	}

	abi, err := DetectABI()
	if err != nil {
		t.Fatalf("detect Landlock ABI: %v", err)
	}
	if abi < MinUnixSocketABI {
		t.Skipf("pathname Unix-socket isolation requires Landlock ABI v%d; detected v%d", MinUnixSocketABI, abi)
	}

	root := t.TempDir()
	leftDir := filepath.Join(root, "left")
	rightDir := filepath.Join(root, "right")
	for _, dir := range []string{leftDir, rightDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatalf("create %q: %v", dir, err)
		}
	}
	source := filepath.Join(leftDir, "source")
	moved := filepath.Join(rightDir, "moved")
	hardlink := filepath.Join(rightDir, "hardlink")
	if err := os.WriteFile(source, []byte("socket-only filesystem posture"), 0o600); err != nil {
		t.Fatalf("create source file: %v", err)
	}
	socketPath := filepath.Join(root, "allowed.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("create throwaway Unix socket: %v", err)
	}
	defer listener.Close()

	cmd := exec.Command(os.Args[0], "-test.run=^TestLandlockSocketOnlyPreservesCrossDirectoryOperations$")
	cmd.Env = append(os.Environ(),
		socketOnlyReferProbeEnv+"=1",
		"NOCKLOCK_SOCKET_ONLY_REFER_PATH="+socketPath,
		"NOCKLOCK_SOCKET_ONLY_REFER_SOURCE="+source,
		"NOCKLOCK_SOCKET_ONLY_REFER_MOVED="+moved,
		"NOCKLOCK_SOCKET_ONLY_REFER_HARDLINK="+hardlink,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("socket-only Landlock child failed: %v\n%s", err, output)
	}
	if _, err := os.Stat(source); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source remained after cross-directory rename: %v", err)
	}
	movedInfo, err := os.Stat(moved)
	if err != nil {
		t.Fatalf("renamed file is missing: %v", err)
	}
	linkInfo, err := os.Stat(hardlink)
	if err != nil {
		t.Fatalf("cross-directory hard link is missing: %v", err)
	}
	if !os.SameFile(movedInfo, linkInfo) {
		t.Fatal("cross-directory hard link does not reference the renamed file")
	}
}

func runSocketOnlyReferProbe(t *testing.T) {
	t.Helper()
	socketPath := os.Getenv("NOCKLOCK_SOCKET_ONLY_REFER_PATH")
	source := os.Getenv("NOCKLOCK_SOCKET_ONLY_REFER_SOURCE")
	moved := os.Getenv("NOCKLOCK_SOCKET_ONLY_REFER_MOVED")
	hardlink := os.Getenv("NOCKLOCK_SOCKET_ONLY_REFER_HARDLINK")
	if socketPath == "" || source == "" || moved == "" || hardlink == "" {
		t.Fatal("socket-only Landlock probe paths are required")
	}
	abi, err := DetectABI()
	if err != nil || abi < MinUnixSocketABI {
		t.Fatalf("detect supported Landlock ABI in child: abi=%d err=%v", abi, err)
	}
	spec := Spec{ABI: abi}
	if err := AddUnixSocketIsolation(&spec, socketPath); err != nil {
		t.Fatalf("build socket-only Landlock rules: %v", err)
	}
	if err := Apply(spec); err != nil {
		t.Fatalf("apply socket-only Landlock rules: %v", err)
	}
	if err := os.Rename(source, moved); err != nil {
		t.Fatalf("cross-directory rename failed: %v", err)
	}
	if err := os.Link(moved, hardlink); err != nil {
		t.Fatalf("cross-directory hard link failed: %v", err)
	}
}

func TestLandlockAllowRWPaths(t *testing.T) {
	if os.Getenv(landlockProbeEnv) != "" {
		runLandlockProbe(t)
		return
	}

	if abi, err := DetectABI(); err != nil {
		t.Fatalf("detect Landlock ABI: %v", err)
	} else if abi == 0 {
		t.Skip("Landlock unavailable")
	}

	root := t.TempDir()
	readOnly := filepath.Join(t.TempDir(), "readonly")
	readWrite := filepath.Join(t.TempDir(), "readwrite")
	for _, dir := range []string{readOnly, readWrite} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatalf("create %q: %v", dir, err)
		}
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestLandlockAllowRWPaths$")
	cmd.Env = append(os.Environ(),
		landlockProbeEnv+"=1",
		"NOCKLOCK_LANDLOCK_ROOT="+root,
		"NOCKLOCK_LANDLOCK_RO="+readOnly,
		"NOCKLOCK_LANDLOCK_RW="+readWrite,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Landlock child failed: %v\n%s", err, output)
	}
}

// TestLandlockChildCanMutateRootButNotRelocatedAudit is the end-to-end
// acceptance test for the two requirements that used to collide: the fenced
// child CAN create and remove entries directly in the fence root, and it CANNOT
// touch its own audit trail. They coexist only because the audit state now lives
// outside the fence root (config.AuditStateDir) — while the log sat in
// <root>/.nock, granting the root granted the log with it, since a Landlock rule
// on a subdirectory cannot narrow a grant on its parent.
//
// The probe is a CGO_ENABLED=0 static binary, so the LD_PRELOAD interposer
// cannot load into it and every result is the kernel ruleset's doing alone.
func TestLandlockChildCanMutateRootButNotRelocatedAudit(t *testing.T) {
	if abi, err := DetectABI(); err != nil {
		t.Fatalf("detect Landlock ABI: %v", err)
	} else if abi == 0 {
		t.Skip("Landlock unavailable")
	}

	root := t.TempDir()
	// The audit state root, standing in for config.AuditStateDir: a sibling of
	// the fence root, never a descendant of it.
	auditDir := t.TempDir()
	auditDB := filepath.Join(auditDir, "events.db")
	const auditContent = "signed audit data"
	if err := os.WriteFile(auditDB, []byte(auditContent), 0o600); err != nil {
		t.Fatalf("create relocated audit database: %v", err)
	}
	// A deny path must also sit outside the granted root: with the root granted
	// as one hierarchy, a deny inside it is unenforceable and RulesFromConfig
	// fails closed (TestRulesFromConfigRejectsDenyInsideGrantedRoot).
	denied := filepath.Join(t.TempDir(), "denied-later")

	probe := filepath.Join(t.TempDir(), "landlock-static-probe")
	build := exec.Command("go", "build", "-o", probe, "./testdata/staticprobe")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CGO-disabled Landlock probe: %v\n%s", err, output)
	}

	cmd := exec.Command(probe, root, auditDB, denied)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("fenced static child: %v\n%s", err, output)
	}

	// Verify from OUTSIDE the fence that the audit trail is byte-identical: the
	// probe checked the errno, this checks that nothing landed anyway.
	if data, err := os.ReadFile(auditDB); err != nil {
		t.Fatalf("read audit database after static child: %v", err)
	} else if string(data) != auditContent {
		t.Fatalf("audit database content = %q, want %q", data, auditContent)
	}
	if entries, err := os.ReadDir(auditDir); err != nil {
		t.Fatalf("read audit directory after static child: %v", err)
	} else if len(entries) != 1 {
		t.Fatalf("audit directory has %d entries, want only the event log: %v", len(entries), entries)
	}
	if _, err := os.Stat(denied); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("denied path was created by static child: %v", err)
	}
	// The child's own writes in the root were cleaned up by the probe, so a
	// leftover entry means a remove was silently skipped.
	if entries, err := os.ReadDir(root); err != nil {
		t.Fatalf("read fence root after static child: %v", err)
	} else if len(entries) != 0 {
		t.Fatalf("fence root has %d leftover entries, want none: %v", len(entries), entries)
	}
}

func runLandlockProbe(t *testing.T) {
	t.Helper()
	root := os.Getenv("NOCKLOCK_LANDLOCK_ROOT")
	readOnly := os.Getenv("NOCKLOCK_LANDLOCK_RO")
	readWrite := os.Getenv("NOCKLOCK_LANDLOCK_RW")
	if root == "" || readOnly == "" || readWrite == "" {
		t.Fatal("Landlock probe paths are required")
	}

	abi, err := DetectABI()
	if err != nil || abi == 0 {
		t.Fatalf("detect Landlock ABI in child: abi=%d err=%v", abi, err)
	}
	spec, err := RulesFromConfig(&fsfence.FenceConfig{
		Root:         root,
		Mode:         "read-write",
		AllowPaths:   []string{readOnly},
		AllowRWPaths: []string{readWrite},
	}, nil, abi)
	if err != nil {
		t.Fatalf("build Landlock rules: %v", err)
	}
	if err := Apply(spec); err != nil {
		t.Fatalf("apply Landlock rules: %v", err)
	}

	if err := os.WriteFile(filepath.Join(readWrite, "state"), []byte("ok"), 0o600); err != nil {
		t.Fatalf("write allow_rw path: %v", err)
	}
	if err := os.WriteFile(filepath.Join(readOnly, "blocked"), []byte("blocked"), 0o600); err == nil {
		t.Fatal("read-only allow path unexpectedly accepted a write")
	} else if !errors.Is(err, syscall.EACCES) && !errors.Is(err, syscall.EPERM) {
		t.Fatalf("read-only allow path write error = %v, want EACCES or EPERM", err)
	}

	if _, err := os.Stat(filepath.Join(readOnly, "blocked")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read-only write left %q behind: %v", filepath.Join(readOnly, "blocked"), err)
	}
	if _, err := os.Stat(filepath.Join(readWrite, "state")); err != nil {
		t.Fatalf("read-write state missing: %v", err)
	}
}
