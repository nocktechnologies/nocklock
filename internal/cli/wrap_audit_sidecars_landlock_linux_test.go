//go:build linux

package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
	"github.com/nocktechnologies/nocklock/internal/fence/fs/landlock"
)

// TestLandlockProtectsRootAuditSidecars proves the kernel fence prevents a
// child from creating, overwriting, deleting, or renaming every adjacent audit
// file when logging.db is configured in the project root. The probe calls
// Landlock directly, with no LD_PRELOAD interposer, so these denials come from
// the kernel ruleset.
func TestLandlockProtectsRootAuditSidecars(t *testing.T) {
	project, dbPath := rootAuditFixture(t)
	abi, err := landlock.DetectABI()
	if err != nil {
		t.Fatalf("detect Landlock ABI: %v", err)
	}
	if abi == 0 {
		if auditStrictlyRequired() {
			t.Fatal("Landlock is required by NOCKLOCK_AUDIT_REQUIRE=1 but unavailable")
		}
		t.Skip("Landlock is unavailable")
	}

	configPath := filepath.Join(project, config.Dir, config.File)
	workDir := filepath.Join(project, "work")
	if err := os.Mkdir(workDir, 0o700); err != nil {
		t.Fatalf("create positive-control directory: %v", err)
	}
	probe := buildLandlockAuditProbe(t, project)
	buildSpec := func() landlock.Spec {
		t.Helper()
		cfg, err := config.Load(configPath)
		if err != nil {
			t.Fatalf("load root audit config: %v", err)
		}
		resolvedDB, resolvedProject, err := config.ResolveDBPath(cfg, configPath)
		if err != nil {
			t.Fatalf("resolve root audit database: %v", err)
		}
		if resolvedDB != dbPath || resolvedProject != project {
			t.Fatalf("audit location changed during test: (%q, %q)", resolvedDB, resolvedProject)
		}
		cfg.Filesystem.Root = project
		// Keep unrelated host paths out of this focused ruleset: CI may not have
		// the default ~/.claude allow path, and neither it nor /tmp is needed by
		// the project-root audit enforcement probe.
		cfg.Filesystem.Allow = nil
		cfg.Filesystem.Deny = append(cfg.Filesystem.Deny, auditDenyPaths(dbPath, project)...)
		resolved, err := fsfence.ProcessConfig(cfg.Filesystem)
		if err != nil {
			t.Fatalf("process root audit filesystem config: %v", err)
		}
		if pathIsWithinDir(filepath.Dir(dbPath), resolved.Root) {
			resolved.ProtectedRootSubdir = filepath.Dir(dbPath)
		}
		spec, err := landlock.RulesFromConfig(resolved, landlockProcSelfAllowPaths(), abi)
		if err != nil {
			t.Fatalf("build Landlock rules for root audit database: %v", err)
		}
		return spec
	}
	specPath := filepath.Join(t.TempDir(), "landlock.json")
	writeSpec := func(spec landlock.Spec) {
		t.Helper()
		encoded, err := landlock.MarshalSpec(spec)
		if err != nil {
			t.Fatalf("encode Landlock rules: %v", err)
		}
		if err := os.WriteFile(specPath, []byte(encoded), 0o600); err != nil {
			t.Fatalf("write Landlock rules: %v", err)
		}
	}
	writeSpec(buildSpec())
	sidecars := auditSidecarPaths(t, dbPath)
	if len(sidecars) == 0 {
		t.Fatal("logging package returned no audit sidecars")
	}

	runProbe := func(action string) string {
		t.Helper()
		args := []string{specPath, action}
		args = append(args, sidecars...)
		out, err := exec.Command(probe, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("Landlock probe %s failed: %v\n%s", action, err, out)
		}
		return string(out)
	}
	assertAllDenied := func(action string, out string) {
		t.Helper()
		for _, path := range sidecars {
			want := "DENIED " + action + " " + path
			if !strings.Contains(out, want) {
				t.Errorf("Landlock did not prove %s denial for %q; output:\n%s", action, path, out)
			}
		}
	}

	createOut := runProbe("create")
	assertAllDenied("create", createOut)
	for _, path := range sidecars {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("child created audit sidecar %q: %v", path, err)
		}
	}

	for _, path := range sidecars {
		if err := os.WriteFile(path, []byte("audit-fixture"), 0o600); err != nil {
			t.Fatalf("create audit sidecar fixture %q: %v", path, err)
		}
	}
	writeSpec(buildSpec())
	for _, action := range []string{"overwrite", "delete", "rename"} {
		assertAllDenied(action, runProbe(action))
		for _, path := range sidecars {
			if got, err := os.ReadFile(path); err != nil || string(got) != "audit-fixture" {
				t.Fatalf("sidecar %q changed after child %s attempt: %q, %v", path, action, got, err)
			}
			if _, err := os.Lstat(path + ".renamed"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("child renamed audit sidecar %q: %v", path, err)
			}
		}
	}

	// A normal file in an existing project subdirectory remains writable.
	control := filepath.Join(workDir, "allowed.txt")
	controlOut, err := exec.Command(probe, specPath, "create", control).CombinedOutput()
	if err != nil || !strings.Contains(string(controlOut), "ALLOWED create "+control) {
		t.Fatalf("Landlock denied an unrelated project write: %v\n%s", err, controlOut)
	}
}

func buildLandlockAuditProbe(t *testing.T, project string) string {
	t.Helper()
	probePath := filepath.Join(project, "audit-sidecar-probe")
	build := exec.Command("go", "build", "-o", probePath, "./testdata/landlock-audit-probe")
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build static Landlock probe: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = os.Remove(probePath) })
	return probePath
}
