package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
)

func TestRunVerifyAggregatesPassFailSkip(t *testing.T) {
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
		now:            func() time.Time { return time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC) },
	})
	defer restore()
	restoreFS := stubVerifyFilesystemBackend(nil)
	defer restoreFS()
	restoreControl := stubVerifyPositiveControl(nil)
	defer restoreControl()

	runner := func(_ context.Context, _ *config.Config, _ string, fence string, _ map[string]string) (probeResult, error) {
		switch fence {
		case "network":
			return probeResult{Fence: fence, Attempted: true, Blocked: false, Detail: "reached example.com"}, errors.New("exit status 1")
		default:
			return probeResult{Fence: fence, Attempted: true, Blocked: true, Detail: "blocked"}, nil
		}
	}

	report, err := runVerify(context.Background(), currentDoctorCapabilities, runner)
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Passed != 3 || report.Summary.Failed != 1 || report.Summary.Skipped != 0 {
		t.Fatalf("summary = %+v, want 3 pass, 1 fail, 0 skip", report.Summary)
	}
}

func TestRunVerifySkipsOffAndUnsupportedFences(t *testing.T) {
	dir := t.TempDir()
	toml := strings.Replace(doctorTestTOML(true), `root = "."`, `root = ""`, 1)
	toml = strings.Replace(toml, `enforcement = "required"`, `enforcement = "off"`, 1)
	writeTestConfig(t, dir, toml)
	withWorkingDir(t, dir)

	restore := stubDoctorCapabilities(doctorCapabilities{
		goos:           "linux",
		fsBackend:      func() error { return nil },
		landlockABI:    func() (int, error) { return 0, nil },
		syscallBackend: func() bool { return false },
		networkBackend: func() error { return nil },
		sandboxExec:    func() error { return nil },
		now:            func() time.Time { return time.Date(2026, 7, 23, 12, 0, 0, 0, time.UTC) },
	})
	defer restore()
	restoreFS := stubVerifyFilesystemBackend(errors.New("missing backend"))
	defer restoreFS()
	restoreControl := stubVerifyPositiveControl(nil)
	defer restoreControl()

	runs := 0
	runner := func(_ context.Context, _ *config.Config, _ string, fence string, _ map[string]string) (probeResult, error) {
		runs++
		return probeResult{Fence: fence, Attempted: true, Blocked: true, Detail: "blocked"}, nil
	}

	report, err := runVerify(context.Background(), currentDoctorCapabilities, runner)
	if err != nil {
		t.Fatal(err)
	}
	if runs != 1 {
		t.Fatalf("runner called %d times, want only secret probe to run", runs)
	}
	if report.Summary.Passed != 1 || report.Summary.Skipped != 3 || report.Summary.Failed != 0 {
		t.Fatalf("summary = %+v, want 1 pass, 0 fail, 3 skip", report.Summary)
	}
}

func stubVerifyFilesystemBackend(err error) func() {
	orig := verifyFilesystemBackend
	verifyFilesystemBackend = func() (string, error) {
		if err != nil {
			return "", err
		}
		return "/usr/local/lib/nocklock/libfence_fs.so", nil
	}
	return func() { verifyFilesystemBackend = orig }
}

func stubVerifyPositiveControl(err error) func() {
	orig := verifyPositiveControlRunner
	verifyPositiveControlRunner = func(context.Context, string, map[string]string) error {
		return err
	}
	return func() { verifyPositiveControlRunner = orig }
}

func TestVerifyCheckFromProbeClassifiesOpenConfigEscape(t *testing.T) {
	check := verifyCheckFromProbe("filesystem", probeResult{
		Fence:     "filesystem",
		Attempted: true,
		Blocked:   false,
		Detail:    "read outside-root canary",
	}, errors.New("exit status 1"))

	if check.Result != verifyFail {
		t.Fatalf("result = %s, want FAIL", check.Result)
	}
}

func TestCreateFilesystemCanaryFallsBackForBroadAllow(t *testing.T) {
	dir := t.TempDir()
	cfg := config.DefaultConfig()
	cfg.Filesystem.Root = dir
	cfg.Filesystem.Allow = []string{"/"}

	path, _, cleanup, err := createFilesystemCanary(&cfg, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if pathWithinAny(path, []string{dir}) {
		t.Fatalf("canary path %q is inside root %q", path, dir)
	}
}

func TestVerifyReportSucceededRequiresAtLeastOnePass(t *testing.T) {
	report := verifyReport{Summary: verifySummary{Skipped: 4}}
	if verifyReportSucceeded(report) {
		t.Fatal("all-skip report should not succeed")
	}

	report = verifyReport{Summary: verifySummary{Passed: 1, Skipped: 3}}
	if !verifyReportSucceeded(report) {
		t.Fatal("report with a pass and no failures should succeed")
	}

	report = verifyReport{Summary: verifySummary{Passed: 1, Failed: 1}}
	if verifyReportSucceeded(report) {
		t.Fatal("report with failures should not succeed")
	}
}

func TestSelectOffAllowlistNetworkTargetSkipsAllowedHosts(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Network.Allow = []string{"verify.nocklock.invalid", "*.invalid"}

	target, err := selectOffAllowlistNetworkTarget(&cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(target, "nocklock-verify-canary.test") {
		t.Fatalf("target = %q, want .test fallback", target)
	}
}
