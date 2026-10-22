package cli

import (
	"encoding/json"
	"github.com/nocktechnologies/nocklock/internal/config"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
