package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
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
	return runDoctorJSONWithABI(t, toml, goos, 9)
}

func runDoctorJSONWithABI(t *testing.T, toml, goos string, abi int) (doctorReport, int) {
	t.Helper()
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("XDG_STATE_HOME", filepath.Join(home, "state"))
	t.Setenv("XDG_DATA_HOME", filepath.Join(home, "data"))
	writeTestConfig(t, dir, toml)
	withWorkingDir(t, dir)
	defer stubDoctorCapabilities(doctorCapabilities{
		goos:           goos,
		fsBackend:      func() error { return nil },
		landlockABI:    func() (int, error) { return abi, nil },
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

func requireBoundaries(t *testing.T, r doctorReport) {
	t.Helper()
	if len(r.Boundaries) == 0 {
		t.Fatal("report has no boundaries")
	}
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
			t.Fatalf("%s: verdict=%q exit=%d gaps=%+v, want PROTECTED/0", goos, got.Verdict, code, got.Gaps)
		}
		if got.EgressLevel != wantLevel {
			t.Fatalf("%s: egress = %q, want %q", goos, got.EgressLevel, wantLevel)
		}
		requireBoundaries(t, got)
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

// TestDoctorUnreachableEgressIsUnavailable: UNREACHABLE egress cannot enforce,
// so the network boundary reads unavailable and the verdict is not PROTECTED.
func TestDoctorUnreachableEgressIsUnavailable(t *testing.T) {
	toml := strings.Replace(config.DefaultTOML(), "[filesystem]\nroot = \".\"", "[filesystem]\nroot = \"\"", 1)
	got, code := runDoctorJSON(t, toml, "linux")
	if got.EgressLevel != egressLevelUnreachable {
		t.Fatalf("egress = %q, want UNREACHABLE", got.EgressLevel)
	}
	if p := postures(got); p["network"] != postureUnavailable {
		t.Fatalf("network posture = %q, want unavailable", p["network"])
	}
	if got.Verdict != doctorVerdictGapsFound || code != doctorExitGapsFound {
		t.Fatalf("verdict=%q exit=%d, want GAPS FOUND/%d", got.Verdict, code, doctorExitGapsFound)
	}
}

func TestDoctorUnixSocketBoundaryUnavailableIsPartial(t *testing.T) {
	got, code := runDoctorJSONWithABI(t, config.DefaultTOML(), "linux", 8)
	if got.Verdict != doctorVerdictPartial || code != doctorExitPartial {
		t.Fatalf("verdict=%q exit=%d, want PARTIAL/%d", got.Verdict, code, doctorExitPartial)
	}
	if p := postures(got); p["unix-sockets"] != postureUnavailable {
		t.Fatalf("Unix-socket posture = %q, want unavailable", p["unix-sockets"])
	}
	for _, check := range got.Checks {
		if check.Group == "Fences" && check.Name == "unix-sockets" {
			if check.Severity != doctorWarning || check.Status != "unavailable" || !strings.Contains(check.Message, "reason=landlock_abi_8_below_9") {
				t.Fatalf("Unix-socket check = %+v, want warning/unavailable with ABI reason", check)
			}
			if !strings.Contains(check.Fix, "Landlock ABI v9") || !strings.Contains(check.Fix, "require_unix_socket_isolation = true") {
				t.Fatalf("Unix-socket options = %q, want ABI 9 and strict refusal", check.Fix)
			}
			return
		}
	}
	t.Fatal("doctor JSON omitted the Unix-socket check")
}

func TestDoctorStrictUnixSocketSettingReportsWrapRefusal(t *testing.T) {
	toml := strings.Replace(config.DefaultTOML(), "require_unix_socket_isolation = false", "require_unix_socket_isolation = true", 1)
	got, code := runDoctorJSONWithABI(t, toml, "linux", 8)
	if got.Verdict != doctorVerdictGapsFound || code != doctorExitGapsFound {
		t.Fatalf("verdict=%q exit=%d, want GAPS FOUND/%d", got.Verdict, code, doctorExitGapsFound)
	}
	for _, check := range got.Checks {
		if check.Group == "Fences" && check.Name == "unix-sockets" {
			if check.Severity != doctorCritical || check.Status != "will-refuse" || !strings.Contains(check.Message, "Wrap will refuse") {
				t.Fatalf("strict Unix-socket check = %+v, want critical/will-refuse", check)
			}
			return
		}
	}
	t.Fatal("doctor JSON omitted the strict Unix-socket check")
}
