package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/spf13/cobra"
)

func TestDoctorProtectedConfig(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, doctorTestTOML(false))
	withWorkingDir(t, dir)

	restore := stubDoctorCapabilities(doctorCapabilities{
		goos:           "linux",
		fsBackend:      func() error { return nil },
		landlockABI:    func() (int, error) { return 3, nil },
		syscallBackend: func() bool { return true },
		networkBackend: func() error { return nil },
		sandboxExec:    func() error { return nil },
		now:            func() time.Time { return time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC) },
	})
	defer restore()

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})

	err := doctorCmd.RunE(cmd, nil)
	if err != nil {
		t.Fatalf("doctor should pass protected config: %v", err)
	}
	if !strings.Contains(out.String(), "VERDICT: PROTECTED") {
		t.Fatalf("expected protected verdict, got:\n%s", out.String())
	}
}

func TestDoctorNetworkAllowAllWarnsButDoesNotFail(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, doctorTestTOML(true))
	withWorkingDir(t, dir)

	restore := stubDoctorCapabilities(doctorCapabilities{
		goos:           "linux",
		fsBackend:      func() error { return nil },
		landlockABI:    func() (int, error) { return 3, nil },
		syscallBackend: func() bool { return true },
		networkBackend: func() error { return nil },
		sandboxExec:    func() error { return nil },
		now:            func() time.Time { return time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC) },
	})
	defer restore()

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})

	err := doctorCmd.RunE(cmd, nil)
	if err != nil {
		t.Fatalf("allow_all warning should not fail doctor: %v", err)
	}
	if !strings.Contains(out.String(), "Network fence is OFF") {
		t.Fatalf("expected allow_all warning, got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "VERDICT: PROTECTED") {
		t.Fatalf("warnings alone should keep protected verdict, got:\n%s", out.String())
	}
}

func TestDoctorConfiguredFenceUnavailableFails(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, doctorTestTOML(false))
	withWorkingDir(t, dir)

	restore := stubDoctorCapabilities(doctorCapabilities{
		goos:           "linux",
		fsBackend:      func() error { return nil },
		landlockABI:    func() (int, error) { return 0, nil },
		syscallBackend: func() bool { return true },
		networkBackend: func() error { return nil },
		sandboxExec:    func() error { return nil },
		now:            func() time.Time { return time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC) },
	})
	defer restore()

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})

	err := doctorCmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("doctor should fail when configured filesystem fence cannot be kernel-enforced")
	}
	var exitErr *exitCodeError
	if !errors.As(err, &exitErr) || exitErr.code != 1 {
		t.Fatalf("expected exit status 1, got %v", err)
	}
	if !strings.Contains(out.String(), "configured-but-backend-missing") ||
		!strings.Contains(out.String(), "VERDICT: GAPS FOUND") {
		t.Fatalf("expected critical gap output, got:\n%s", out.String())
	}
}

func TestDoctorMissingConfigShowsInitHint(t *testing.T) {
	dir := t.TempDir()
	withWorkingDir(t, dir)

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})

	err := doctorCmd.RunE(cmd, nil)
	if err == nil {
		t.Fatal("doctor should fail without config")
	}
	if !strings.Contains(out.String(), "run nocklock init") {
		t.Fatalf("expected init hint, got:\n%s", out.String())
	}
}

func TestDoctorJSONShape(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, doctorTestTOML(false))
	withWorkingDir(t, dir)

	dbPath := filepath.Join(dir, ".nock", "events.db")
	logger, err := logging.NewLogger(dbPath, dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := logger.Log(logging.Event{
		Timestamp: time.Date(2026, 6, 18, 11, 30, 0, 0, time.UTC),
		EventType: logging.EventNetworkBlocked,
		Category:  "network",
		Detail:    "blocked.example",
		Blocked:   true,
		SessionID: "doctor-test",
	}); err != nil {
		t.Fatal(err)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}

	restore := stubDoctorCapabilities(doctorCapabilities{
		goos:           "linux",
		fsBackend:      func() error { return nil },
		landlockABI:    func() (int, error) { return 3, nil },
		syscallBackend: func() bool { return true },
		networkBackend: func() error { return nil },
		sandboxExec:    func() error { return nil },
		now:            func() time.Time { return time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC) },
	})
	defer restore()

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().Bool("json", false, "")
	if err := cmd.Flags().Set("json", "true"); err != nil {
		t.Fatal(err)
	}
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})

	err = doctorCmd.RunE(cmd, nil)
	if err != nil {
		t.Fatalf("doctor --json should pass: %v", err)
	}

	var got doctorReport
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid json output: %v\n%s", err, out.String())
	}
	if got.Verdict != doctorVerdictProtected {
		t.Fatalf("verdict = %q, want %q", got.Verdict, doctorVerdictProtected)
	}
	if got.Activity.Last24hBlocked != 1 || got.Activity.AllTimeBlocked != 1 {
		t.Fatalf("activity = %+v, want one recent/all-time block", got.Activity)
	}
	if len(got.Checks) == 0 {
		t.Fatal("expected structured checks")
	}
}

func doctorTestTOML(allowAll bool) string {
	toml := config.DefaultTOML()
	if allowAll {
		toml = strings.Replace(toml, "allow_all = false", "allow_all = true", 1)
	}
	return toml
}

func stubDoctorCapabilities(c doctorCapabilities) func() {
	orig := currentDoctorCapabilities
	currentDoctorCapabilities = c
	return func() { currentDoctorCapabilities = orig }
}
