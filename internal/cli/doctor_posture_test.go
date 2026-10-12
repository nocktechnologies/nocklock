package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/spf13/cobra"
)

// doctorExitFromErr turns doctor's RunE result into the process exit code.
func doctorExitFromErr(err error) int {
	var exitErr *exitCodeError
	if errors.As(err, &exitErr) {
		return exitErr.code
	}
	if err != nil {
		return -1
	}
	return doctorExitProtected
}

func runDoctorJSON(t *testing.T, toml, goos string) (doctorReport, int) {
	t.Helper()
	dir := t.TempDir()
	writeTestConfig(t, dir, toml)
	withWorkingDir(t, dir)
	defer stubDoctorCapabilities(doctorCapabilities{
		goos:           goos,
		fsBackend:      func() error { return nil },
		landlockABI:    func() (int, error) { return 3, nil },
		syscallBackend: func() bool { return true },
		networkBackend: func() error { return nil },
		sandboxExec:    func() error { return nil },
		now:            func() time.Time { return time.Date(2026, 6, 18, 12, 0, 0, 0, time.UTC) },
	})()

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.Flags().Bool("json", true, "")
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	code := doctorExitFromErr(doctorCmd.RunE(cmd, nil))
	var got doctorReport
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, out.String())
	}
	return got, code
}

func postures(r doctorReport) map[string]doctorPosture {
	m := map[string]doctorPosture{}
	for _, b := range r.Boundaries {
		m[b.Name] = b.Posture
	}
	return m
}

// TestDoctorAllDisabledIsUnprotected is the N11640 repro: every boundary off
// must not read PROTECTED or exit 0.
func TestDoctorAllDisabledIsUnprotected(t *testing.T) {
	toml := "[filesystem]\nroot = \"\"\n\n[network]\nallow_all = true\n\n[syscall]\nenforcement = \"off\"\n\n[secrets]\npass = []\nblock = []\n"
	for _, goos := range []string{"linux", "darwin"} {
		got, code := runDoctorJSON(t, toml, goos)
		if got.Verdict != doctorVerdictUnprotected || code != doctorExitUnprotected {
			t.Fatalf("%s: verdict=%q exit=%d, want UNPROTECTED/%d", goos, got.Verdict, code, doctorExitUnprotected)
		}
		for name, p := range postures(got) {
			if p != postureDisabled {
				t.Fatalf("%s: %s posture = %q, want disabled", goos, name, p)
			}
		}
		if got.EgressLevel != egressLevelOff {
			t.Fatalf("%s: egress = %q, want OFF", goos, got.EgressLevel)
		}
	}
}

// TestDoctorDefaultInitConfigPosture pins what the default `init` config reads
// as on each platform (Linux CONFINED, macOS v0.7.0 Seatbelt floor).
func TestDoctorDefaultInitConfigPosture(t *testing.T) {
	for goos, wantLevel := range map[string]egressLevel{"linux": egressLevelConfined, "darwin": egressLevelSeatbelt} {
		got, code := runDoctorJSON(t, config.DefaultTOML(), goos)
		if got.Verdict != doctorVerdictProtected || code != 0 {
			t.Fatalf("%s: verdict=%q exit=%d, want PROTECTED/0", goos, got.Verdict, code)
		}
		if got.EgressLevel != wantLevel {
			t.Fatalf("%s: egress = %q, want %q", goos, got.EgressLevel, wantLevel)
		}
		for name, p := range postures(got) {
			if p != postureEnforced {
				t.Fatalf("%s: %s posture = %q, want enforced", goos, name, p)
			}
		}
	}
}

// TestDoctorPartialNamesDisabledBoundary: one disabled boundary is PARTIAL.
func TestDoctorPartialNamesDisabledBoundary(t *testing.T) {
	toml := strings.Replace(config.DefaultTOML(), "allow_all = false", "allow_all = true", 1)
	got, code := runDoctorJSON(t, toml, "linux")
	if got.Verdict != doctorVerdictPartial || code != doctorExitPartial {
		t.Fatalf("verdict=%q exit=%d, want PARTIAL/%d", got.Verdict, code, doctorExitPartial)
	}
	if p := postures(got); p["network"] != postureDisabled || p["filesystem"] != postureEnforced {
		t.Fatalf("postures = %v", p)
	}
}
