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

func TestDoctorNetworkAllowlistInertUnderSyscallFenceWarns(t *testing.T) {
	// Default config on Linux: syscall fence "required" + network fenced with a
	// curated allowlist. The syscall fence forces unix-only sockets, so the TCP
	// proxy that enforces the allowlist is unreachable and the allowlist is
	// inert. Doctor must surface that footgun (as a warning, not a failure).
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

	if err := doctorCmd.RunE(cmd, nil); err != nil {
		t.Fatalf("inert-allowlist warning should not fail doctor: %v", err)
	}
	if !strings.Contains(out.String(), "Network allowlist is inert on Linux") {
		t.Fatalf("expected inert-allowlist warning, got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "VERDICT: PROTECTED") {
		t.Fatalf("warning alone should keep protected verdict, got:\n%s", out.String())
	}
}

func TestDoctorNetworkAllowlistNotInertWhenSyscallOff(t *testing.T) {
	// With the syscall fence off, the child keeps IP sockets and the proxy-based
	// allowlist actually functions — no inert-allowlist warning should appear.
	dir := t.TempDir()
	// Target the [syscall] enforcement line specifically (line-start), not the
	// filesystem's linux_enforcement line which also contains the substring.
	toml := strings.Replace(doctorTestTOML(false), "\nenforcement = \"required\"", "\nenforcement = \"off\"", 1)
	writeTestConfig(t, dir, toml)
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

	if err := doctorCmd.RunE(cmd, nil); err != nil {
		t.Fatalf("doctor should pass with syscall off: %v", err)
	}
	if strings.Contains(out.String(), "Network allowlist is inert") {
		t.Fatalf("did not expect inert-allowlist warning with syscall off, got:\n%s", out.String())
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

func TestDoctorEgressHelperCheck(t *testing.T) {
	cases := []struct {
		name       string
		goos       string
		state      egressHelperState
		wantSev    doctorSeverity
		wantStatus string
		wantFix    bool
	}{
		{
			name:       "linux installed and reachable is ok",
			goos:       "linux",
			state:      egressHelperState{exists: true, regular: true, rootOwned: true, executable: true, securePerms: true, sudoOK: true},
			wantSev:    doctorOK,
			wantStatus: "installed",
			wantFix:    false,
		},
		{
			name:       "linux group- or world-writable helper is an insecure-perms warning",
			goos:       "linux",
			state:      egressHelperState{exists: true, regular: true, rootOwned: true, executable: true, securePerms: false, sudoOK: true},
			wantSev:    doctorWarning,
			wantStatus: "insecure-perms",
			wantFix:    true,
		},
		{
			name:       "linux non-regular helper is a not-regular warning",
			goos:       "linux",
			state:      egressHelperState{exists: true, regular: false},
			wantSev:    doctorWarning,
			wantStatus: "not-regular",
			wantFix:    true,
		},
		{
			name:       "linux missing is a warning with a fix",
			goos:       "linux",
			state:      egressHelperState{},
			wantSev:    doctorWarning,
			wantStatus: "missing",
			wantFix:    true,
		},
		{
			name:       "linux present but sudo unreachable is a warning",
			goos:       "linux",
			state:      egressHelperState{exists: true, regular: true, rootOwned: true, executable: true, securePerms: true, sudoOK: false},
			wantSev:    doctorWarning,
			wantStatus: "sudo-unreachable",
			wantFix:    true,
		},
		{
			name:       "darwin is informational not-applicable",
			goos:       "darwin",
			state:      egressHelperState{},
			wantSev:    doctorInfo,
			wantStatus: "not-applicable",
			wantFix:    false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			state := tc.state
			caps := doctorCapabilities{
				goos:         tc.goos,
				egressHelper: func() egressHelperState { return state },
			}
			got := egressHelperDoctorCheck(caps)
			if got.Name != "egress-helper" {
				t.Fatalf("check name = %q, want egress-helper", got.Name)
			}
			if got.Severity != tc.wantSev {
				t.Fatalf("severity = %q, want %q", got.Severity, tc.wantSev)
			}
			if got.Status != tc.wantStatus {
				t.Fatalf("status = %q, want %q", got.Status, tc.wantStatus)
			}
			if tc.wantFix && got.Fix == "" {
				t.Fatalf("expected a Fix for %q, got none (message: %s)", tc.name, got.Message)
			}
			if !tc.wantFix && got.Fix != "" {
				t.Fatalf("did not expect a Fix for %q, got %q", tc.name, got.Fix)
			}
		})
	}
}

func TestDoctorEgressHelperNilCapabilityDegradesToWarning(t *testing.T) {
	// The six existing capability literals leave egressHelper nil; the check must
	// degrade to a warning rather than panic.
	caps := doctorCapabilities{goos: "linux"}
	got := egressHelperDoctorCheck(caps)
	if got.Severity != doctorWarning {
		t.Fatalf("nil egress capability should degrade to a warning, got %q", got.Severity)
	}
	if got.Status != "missing" {
		t.Fatalf("nil egress capability status = %q, want missing", got.Status)
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
