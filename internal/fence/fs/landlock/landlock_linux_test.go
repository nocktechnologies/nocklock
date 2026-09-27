//go:build linux

package landlock

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"

	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
)

const landlockProbeEnv = "NOCKLOCK_LANDLOCK_PROBE"

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

func TestLandlockStaticChildCannotMutateProtectedRootDescendants(t *testing.T) {
	if abi, err := DetectABI(); err != nil {
		t.Fatalf("detect Landlock ABI: %v", err)
	} else if abi == 0 {
		t.Skip("Landlock unavailable")
	}

	root := t.TempDir()
	auditDir := filepath.Join(root, ".nock")
	if err := os.Mkdir(auditDir, 0o700); err != nil {
		t.Fatalf("create protected audit directory: %v", err)
	}
	auditDB := filepath.Join(auditDir, "events.db")
	if err := os.WriteFile(auditDB, []byte("signed audit data"), 0o600); err != nil {
		t.Fatalf("create protected audit database: %v", err)
	}
	denied := filepath.Join(root, "denied-later")

	probe := filepath.Join(t.TempDir(), "landlock-static-probe")
	build := exec.Command("go", "build", "-o", probe, "./testdata/staticprobe")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CGO-disabled Landlock probe: %v\n%s", err, output)
	}

	cmd := exec.Command(probe, root, auditDB, denied)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("static child mutated a protected root descendant: %v\n%s", err, output)
	}
	if data, err := os.ReadFile(auditDB); err != nil {
		t.Fatalf("read protected audit database after static child: %v", err)
	} else if string(data) != "signed audit data" {
		t.Fatalf("protected audit database content = %q, want original content", data)
	}
	if _, err := os.Stat(denied); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("denied path was created by static child: %v", err)
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
