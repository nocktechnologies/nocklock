package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/fence/secrets"
)

func TestDoctorProjectDotEnvPartial(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, doctorTestTOML(false))
	withWorkingDir(t, dir)
	caps := doctorCapabilities{goos: "linux", fsBackend: func() error { return nil }, landlockABI: func() (int, error) { return 9, nil }, syscallBackend: func() bool { return true }, networkBackend: func() error { return nil }, sandboxExec: func() error { return nil }, now: time.Now}
	if got := runDoctor(caps); got.Verdict != doctorVerdictProtected {
		t.Fatalf("control verdict %s: %+v", got.Verdict, got.Checks)
	}
	canary := "fake-dotenv-canary-only"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("API_TOKEN="+canary), 0600); err != nil {
		t.Fatal(err)
	}
	got := runDoctor(caps)
	if got.Verdict != doctorVerdictPartial || doctorExitCode(got.Verdict) != 3 {
		t.Fatalf("want PARTIAL: %+v", got)
	}
	encoded, _ := json.Marshal(got)
	if strings.Contains(string(encoded), canary) {
		t.Fatal("doctor exposed secret-shaped value")
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), filepath.Join(dir, ".env.link")); err != nil {
		t.Fatal(err)
	}
	if incomplete := runDoctor(caps); incomplete.Verdict != doctorVerdictPartial {
		t.Fatalf("actual match must remain PARTIAL even when inspection is incomplete: %+v", incomplete)
	}
}

func TestDoctorLargeProjectWithoutDotEnvStaysProtected(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, doctorTestTOML(false))
	withWorkingDir(t, dir)
	deps := filepath.Join(dir, "node_modules")
	if err := os.Mkdir(deps, 0700); err != nil {
		t.Fatal(err)
	}
	for i := 0; i <= secrets.MaxScanEntries; i++ {
		if err := os.WriteFile(filepath.Join(deps, fmt.Sprintf("module-%d.js", i)), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	caps := doctorCapabilities{goos: "linux", fsBackend: func() error { return nil }, landlockABI: func() (int, error) { return 9, nil }, syscallBackend: func() bool { return true }, networkBackend: func() error { return nil }, sandboxExec: func() error { return nil }, now: time.Now}
	got := runDoctor(caps)
	if got.Verdict != doctorVerdictProtected {
		t.Fatalf("large dependency tree changed verdict: %+v", got)
	}
	for _, check := range got.Checks {
		if check.Name == "project-dotenv" && (check.Status != "clear" || !strings.Contains(check.Message, "Deeper files were not checked")) {
			t.Fatalf("shallow scope not clear: %+v", check)
		}
	}
}

func TestDoctorIncompleteDotEnvIsInformational(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, doctorTestTOML(false))
	withWorkingDir(t, dir)
	if err := os.Symlink(filepath.Join(t.TempDir(), "missing"), filepath.Join(dir, ".env.link")); err != nil {
		t.Fatal(err)
	}
	caps := doctorCapabilities{goos: "linux", fsBackend: func() error { return nil }, landlockABI: func() (int, error) { return 9, nil }, syscallBackend: func() bool { return true }, networkBackend: func() error { return nil }, sandboxExec: func() error { return nil }, now: time.Now}
	got := runDoctor(caps)
	if got.Verdict != doctorVerdictProtected || doctorExitCode(got.Verdict) != 0 {
		t.Fatalf("incomplete dotenv check changed verdict: %+v", got)
	}
	for _, check := range got.Checks {
		if check.Name == "project-dotenv" {
			if check.Status != "not-checked" || check.Severity != doctorInfo || !strings.Contains(check.Message, "not checked") {
				t.Fatalf("incomplete check should be informational: %+v", check)
			}
			return
		}
	}
	t.Fatal("missing project-dotenv check")
}

func TestDoctorDotEnvExpandsHomeWithoutReportingValues(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.WriteFile(filepath.Join(home, ".ENV.local"), []byte("TOKEN=fake-only"), 0600); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Filesystem.Root = "~"
	check := projectDotEnvDoctorCheck(&cfg)
	if check.Status != "readable-secret" {
		t.Fatalf("home dotenv check: %+v", check)
	}
}
