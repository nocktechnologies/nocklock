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
	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/spf13/cobra"
)

func TestDoctorSigningKeyPolicyNegativeControls(t *testing.T) {
	project := resolvedTempDir(t)
	keyDir := filepath.Join(project, "xdg", "nocklock")
	for _, goos := range []string{"darwin", "linux"} {
		t.Run(goos, func(t *testing.T) {
			caps := doctorCapabilities{goos: goos, landlockABI: func() (int, error) { return 9, nil }}
			for _, denied := range []bool{false, true} {
				cfg := config.FilesystemConfig{Root: project}
				if denied {
					cfg.Deny = []string{keyDir}
				}
				resolved, err := fsfence.ProcessConfig(cfg)
				if err != nil {
					t.Fatal(err)
				}
				check := signingKeyFenceCheck(keyDir, resolved, "required", caps)
				posture := doctorCheckPosture(check)
				if goos == "darwin" && denied {
					if check.Severity != doctorOK || posture != postureEnforced {
						t.Fatalf("Seatbelt deny must protect key: %+v, %s", check, posture)
					}
				} else if check.Severity != doctorCritical || posture == postureEnforced {
					t.Fatalf("key under grant without enforceable deny must be a gap: %+v, %s", check, posture)
				} else if !denied && check.Status != "readable" {
					t.Fatalf("pre-fix policy must expose a readable key, got %+v", check)
				} else if denied && goos == "linux" && check.Status != "will-refuse" {
					t.Fatalf("Landlock must refuse the overlapping deny, got %+v", check)
				}
			}
		})
	}
}

func TestDoctorSigningKeyMissingFromDenyPathsFailsClosed(t *testing.T) {
	project := resolvedTempDir(t)
	keyDir := filepath.Join(project, "xdg", "nocklock")
	other := filepath.Join(project, "other")
	for _, tc := range []struct {
		name string
		fs   *fsfence.FenceConfig
	}{
		{"nil config", nil},
		{"empty deny paths", &fsfence.FenceConfig{Root: project}},
		{"different deny path", &fsfence.FenceConfig{Root: project, DenyPaths: []string{other}}},
	} {
		for _, goos := range []string{"darwin", "linux"} {
			t.Run(tc.name+"/"+goos, func(t *testing.T) {
				caps := doctorCapabilities{goos: goos, landlockABI: func() (int, error) { return 9, nil }}
				check := signingKeyFenceCheck(keyDir, tc.fs, "required", caps)
				if check.Severity != doctorCritical || check.Status != "readable" {
					t.Fatalf("missing deny must be a reported gap: %+v", check)
				}
			})
		}
	}
}

func TestDoctorSigningKeyLinuxLandlockProbe(t *testing.T) {
	base := resolvedTempDir(t)
	project := filepath.Join(base, "project")
	keyDir := filepath.Join(base, "private", "nocklock")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	resolved, err := fsfence.ProcessConfig(config.FilesystemConfig{Root: project, Deny: []string{keyDir}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name         string
		enforcement  string
		probe        func() (int, error)
		wantSeverity doctorSeverity
		wantStatus   string
	}{
		{"nil probe is unavailable", "required", nil, doctorCritical, "unavailable"},
		{"probe error is unavailable", "required", func() (int, error) { return 0, errors.New("boom") }, doctorCritical, "unavailable"},
		// wrap refuses with "preferred" too (linuxEnforcementMode maps it to "required").
		{"preferred and Landlock unavailable still refuses", "preferred", func() (int, error) { return 0, nil }, doctorCritical, "unavailable"},
		{"off is advisory without probing", "off", nil, doctorWarning, "advisory"},
		{"available Landlock protects key outside grants", "required", func() (int, error) { return 9, nil }, doctorOK, "denied"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			check := signingKeyFenceCheck(keyDir, resolved, tc.enforcement, doctorCapabilities{goos: "linux", landlockABI: tc.probe})
			if check.Severity != tc.wantSeverity || check.Status != tc.wantStatus {
				t.Fatalf("got %+v, want %s/%s", check, tc.wantSeverity, tc.wantStatus)
			}
		})
	}
}

func TestWithManagedSigningKeyDenyDoesNotMutateInput(t *testing.T) {
	base := resolvedTempDir(t)
	t.Setenv("XDG_CONFIG_HOME", base)
	in := make([]string, 1, 4)
	in[0] = "/etc/secret"
	out, keyDir, err := withManagedSigningKeyDeny(in)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(base, "nocklock"); keyDir != want || len(out) != 2 || out[1] != want || out[0] != "/etc/secret" {
		t.Fatalf("deny = %v, keyDir = %s, want key dir %s appended", out, keyDir, want)
	}
	if len(in) != 1 || in[:2][1] != "" {
		t.Fatalf("input deny list was modified: %v", in[:2])
	}
}

func TestDoctorSigningKeyNoFenceReportsResolvedDirectory(t *testing.T) {
	base := resolvedTempDir(t)
	target := filepath.Join(base, "real")
	if err := os.MkdirAll(filepath.Join(target, "nocklock"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", link)
	check, key := signingKeyDoctorCheck(&config.Config{}, "", doctorCapabilities{goos: "linux"})
	if want := filepath.Join(target, "nocklock"); check.Status != "not-enforced" || key == nil || key.Directory != want {
		t.Fatalf("no-fence check = %+v, key = %+v, want directory %s", check, key, want)
	}
}

func TestDoctorSigningKeyReportsBuiltinDenyRefusalAsFilesystemCause(t *testing.T) {
	home := resolvedTempDir(t)
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", resolvedTempDir(t))
	caps := doctorCapabilities{goos: "linux", landlockABI: func() (int, error) { return 9, nil }}

	refused := &config.Config{Filesystem: config.FilesystemConfig{Root: home}}
	check, key := signingKeyDoctorCheck(refused, "", caps)
	if check.Severity != doctorCritical || check.Status != "will-refuse" || key == nil ||
		!strings.Contains(check.Message, "built-in credential deny") || strings.Contains(check.Fix, "signing key path") {
		t.Fatalf("built-in deny refusal must name the filesystem cause: %+v", check)
	}

	project := filepath.Join(home, "project")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatal(err)
	}
	allowed := &config.Config{Filesystem: config.FilesystemConfig{Root: project}}
	if check, _ := signingKeyDoctorCheck(allowed, "", caps); check.Status == "will-refuse" || strings.Contains(check.Message, "built-in credential deny") {
		t.Fatalf("config without a refusal must still judge the key: %+v", check)
	}
}

func TestDoctorSigningKeyRelocatedXDG(t *testing.T) {
	for _, tc := range []struct {
		name, goos, xdg string
		wantVerdict     doctorVerdict
		wantStatus      string
	}{
		{"Seatbelt denies key in project", "darwin", "project", doctorVerdictProtected, "denied"},
		{"Landlock refuses key in project", "linux", "project", doctorVerdictGapsFound, "will-refuse"},
		{"Landlock refuses key under tmp grant", "linux", "tmp", doctorVerdictGapsFound, "will-refuse"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			project := t.TempDir()
			writeTestConfig(t, project, doctorTestTOML(false))
			withWorkingDir(t, project)
			keyRoot := filepath.Join(project, "xdg")
			realParent := project
			if tc.xdg == "tmp" {
				keyRoot = filepath.Join("/tmp", "nocklock-doctor-signing-key-test")
				realParent = "/tmp"
			}
			realParent, err := filepath.EvalSymlinks(realParent)
			if err != nil {
				t.Fatal(err)
			}
			wantKeyDir := filepath.Join(realParent, "xdg", "nocklock")
			if tc.xdg == "tmp" {
				wantKeyDir = filepath.Join(realParent, "nocklock-doctor-signing-key-test", "nocklock")
			}
			t.Setenv("XDG_CONFIG_HOME", keyRoot)
			stateRoot := t.TempDir()
			if err := os.Chmod(stateRoot, 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("XDG_STATE_HOME", stateRoot)
			defer stubDoctorCapabilities(doctorCapabilities{
				goos: tc.goos, fsBackend: func() error { return nil },
				landlockABI:    func() (int, error) { return 9, nil },
				syscallBackend: func() bool { return true }, networkBackend: func() error { return nil },
				sandboxExec: func() error { return nil }, now: time.Now,
			})()
			report := runDoctor(currentDoctorCapabilities)
			if report.Verdict != tc.wantVerdict {
				t.Fatalf("verdict = %s, want %s; gaps=%+v", report.Verdict, tc.wantVerdict, report.Gaps)
			}
			if report.SigningKey == nil || report.SigningKey.Directory != wantKeyDir {
				t.Fatalf("JSON signing key directory = %+v, want %s", report.SigningKey, wantKeyDir)
			}
			var keyCheck doctorCheck
			for _, check := range report.Checks {
				if check.Name == "signing-key" {
					keyCheck = check
				}
			}
			if keyCheck.Status != tc.wantStatus || report.SigningKey.Posture != postures(report)["signing-key"] {
				t.Fatalf("signing key check/posture = %+v/%+v", keyCheck, report.SigningKey)
			}
			var out bytes.Buffer
			if err := renderDoctorJSON(&out, report); err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(out.Bytes(), []byte(`"signing_key"`)) || !bytes.Contains(out.Bytes(), []byte(`"directory"`)) {
				t.Fatalf("JSON omits signing key path/posture: %s", out.String())
			}
		})
	}
}

func TestDoctorSigningKeyResolvesXDGSymlink(t *testing.T) {
	project := t.TempDir()
	writeTestConfig(t, project, doctorTestTOML(false))
	withWorkingDir(t, project)
	base := t.TempDir()
	target := filepath.Join(base, "real-config")
	if err := os.MkdirAll(filepath.Join(target, "nocklock"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "config-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", link)
	wantKeyDir, err := filepath.EvalSymlinks(filepath.Join(target, "nocklock"))
	if err != nil {
		t.Fatal(err)
	}
	stateRoot := t.TempDir()
	if err := os.Chmod(stateRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_STATE_HOME", stateRoot)
	defer stubDoctorCapabilities(doctorCapabilities{
		goos: "darwin", sandboxExec: func() error { return nil },
		syscallBackend: func() bool { return true }, networkBackend: func() error { return nil },
		now: time.Now,
	})()
	report := runDoctor(currentDoctorCapabilities)
	if report.Verdict != doctorVerdictProtected || report.SigningKey == nil || report.SigningKey.Directory != wantKeyDir || report.SigningKey.Posture != postureEnforced {
		t.Fatalf("symlinked XDG directory must resolve to the denied real path: %+v", report.SigningKey)
	}
}

func TestDoctorProtectedConfig(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, doctorTestTOML(false))
	withWorkingDir(t, dir)

	restore := stubDoctorCapabilities(doctorCapabilities{
		goos:           "linux",
		fsBackend:      func() error { return nil },
		landlockABI:    func() (int, error) { return 9, nil },
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

func TestUnixSocketDoctorCheckReportsLandlockPosture(t *testing.T) {
	cases := []struct {
		name       string
		goos       string
		abi        int
		allowAll   bool
		require    bool
		noFSRoot   bool
		syscall    string
		wantSev    doctorSeverity
		wantStatus string
		wantFix    string
	}{
		{name: "ABI 9 enforces both socket types", goos: "linux", abi: 9, wantSev: doctorOK, wantStatus: "enforceable"},
		{name: "older ABI is partial", goos: "linux", abi: 8, wantSev: doctorWarning, wantStatus: "unavailable", wantFix: "require_unix_socket_isolation = true"},
		{name: "Landlock unavailable is partial", goos: "linux", abi: 0, wantSev: doctorWarning, wantStatus: "unavailable", wantFix: "require_unix_socket_isolation = true"},
		{name: "strict config reports refusal", goos: "linux", abi: 8, require: true, wantSev: doctorCritical, wantStatus: "will-refuse", wantFix: "require_unix_socket_isolation = false"},
		{name: "network allow-all makes boundary not applicable", goos: "linux", abi: 8, allowAll: true, wantSev: doctorInfo, wantStatus: "not-applicable"},
		{name: "syscall off cannot reach CONFINED", goos: "linux", abi: 9, syscall: "off", wantSev: doctorInfo, wantStatus: "not-applicable"},
		{name: "strict setting refuses non-CONFINED egress", goos: "linux", abi: 9, syscall: "off", require: true, wantSev: doctorCritical, wantStatus: "will-refuse", wantFix: "CONFINED"},
		{name: "missing filesystem bridge cannot reach CONFINED", goos: "linux", abi: 9, noFSRoot: true, wantSev: doctorInfo, wantStatus: "not-applicable"},
		{name: "macOS is not applicable", goos: "darwin", wantSev: doctorInfo, wantStatus: "not-applicable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.DefaultConfig()
			cfg.Network.AllowAll = tc.allowAll
			cfg.Network.RequireUnixSocketIsolation = tc.require
			if tc.noFSRoot {
				cfg.Filesystem.Root = ""
			}
			if tc.syscall != "" {
				cfg.Syscall.Enforcement = tc.syscall
			}
			check := unixSocketDoctorCheck(&cfg, doctorCapabilities{
				goos:           tc.goos,
				syscallBackend: func() bool { return true },
				landlockABI:    func() (int, error) { return tc.abi, nil },
			})
			if check.Severity != tc.wantSev || check.Status != tc.wantStatus {
				t.Fatalf("unix-socket doctor check = %+v, want severity=%q status=%q", check, tc.wantSev, tc.wantStatus)
			}
			if tc.wantFix != "" && !strings.Contains(check.Fix, tc.wantFix) {
				t.Fatalf("unix-socket doctor fix = %q, want it to contain %q", check.Fix, tc.wantFix)
			}
			if tc.wantStatus == "unavailable" && (!strings.Contains(check.Message, "reachable") || !strings.Contains(check.Message, "reason=")) {
				t.Fatalf("unavailable posture must explain reachable sockets and the reason: %+v", check)
			}
			if tc.wantStatus == "will-refuse" && !strings.Contains(check.Message, "Wrap will refuse") {
				t.Fatalf("strict posture must say wrap will refuse: %+v", check)
			}
		})
	}
}

func TestDoctorUnavailableUnixSocketBoundaryIsPartial(t *testing.T) {
	cfg := config.DefaultConfig()
	check := unixSocketDoctorCheck(&cfg, doctorCapabilities{
		goos:           "linux",
		syscallBackend: func() bool { return true },
		landlockABI:    func() (int, error) { return 8, nil },
	})
	checks := []doctorCheck{
		doctorOKCheck("Fences", "filesystem", "enforceable", ""),
		check,
		doctorOKCheck("Fences", "syscall", "enforceable", ""),
		doctorOKCheck("Fences", "network", "enforceable", ""),
		doctorOKCheck("Fences", "secrets", "enforceable", ""),
	}
	report := finishDoctorReport(checks, doctorBoundaries(&cfg, "linux", egressLevelConfined, checks), doctorActivity{})
	if report.Verdict != doctorVerdictPartial {
		t.Fatalf("doctor verdict = %q, want %q for unavailable Unix-socket isolation; gaps=%+v", report.Verdict, doctorVerdictPartial, report.Gaps)
	}
	if check.Severity != doctorWarning || check.Status != "unavailable" || !strings.Contains(check.Message, "reason=landlock_abi_8_below_9") {
		t.Fatalf("doctor boundary = %+v, want ABI 8 unavailable with reason", check)
	}
	var out bytes.Buffer
	renderDoctorHuman(&out, report)
	if !strings.Contains(out.String(), "VERDICT: PARTIAL") ||
		!strings.Contains(out.String(), "Landlock ABI v9 or later") ||
		!strings.Contains(out.String(), "network.require_unix_socket_isolation = true") {
		t.Fatalf("doctor must show PARTIAL and the two real options:\n%s", out.String())
	}
}

func TestDoctorNetworkAllowAllWarnsButDoesNotFail(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, doctorTestTOML(true))
	withWorkingDir(t, dir)

	restore := stubDoctorCapabilities(doctorCapabilities{
		goos:           "linux",
		fsBackend:      func() error { return nil },
		landlockABI:    func() (int, error) { return 9, nil },
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

	if got := doctorExitFromErr(doctorCmd.RunE(cmd, nil)); got != doctorExitPartial {
		t.Fatalf("allow_all must exit %d (PARTIAL), got %d", doctorExitPartial, got)
	}
	if !strings.Contains(out.String(), "Network fence is OFF") {
		t.Fatalf("expected allow_all warning, got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "VERDICT: PARTIAL") || !strings.Contains(out.String(), "- network: disabled") {
		t.Fatalf("allow_all must be PARTIAL and name network, got:\n%s", out.String())
	}
}

func TestDoctorNetworkAllowlistBridgeDoesNotWarnWithFilesystemInterposer(t *testing.T) {
	// Default config on Linux: syscall fence "required" + network fenced with a
	// curated allowlist. The proxy-mode syscall policy narrows the child to
	// unix-only sockets, and the filesystem interposer now bridges the configured
	// proxy address to a Unix socket, so this is no longer an inert allowlist.
	dir := t.TempDir()
	writeTestConfig(t, dir, doctorTestTOML(false))
	withWorkingDir(t, dir)

	restore := stubDoctorCapabilities(doctorCapabilities{
		goos:           "linux",
		fsBackend:      func() error { return nil },
		landlockABI:    func() (int, error) { return 9, nil },
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
		t.Fatalf("doctor should not fail: %v", err)
	}
	if strings.Contains(out.String(), "Network allowlist cannot be reached") {
		t.Fatalf("did not expect bridge warning with filesystem interposer, got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "VERDICT: PROTECTED") {
		t.Fatalf("expected protected verdict, got:\n%s", out.String())
	}
}

func TestDoctorNetworkAllowlistWarnsWhenBridgeInterposerDisabled(t *testing.T) {
	dir := t.TempDir()
	toml := strings.Replace(doctorTestTOML(false), "[filesystem]\nroot = \".\"", "[filesystem]\nroot = \"\"", 1)
	writeTestConfig(t, dir, toml)
	withWorkingDir(t, dir)

	restore := stubDoctorCapabilities(doctorCapabilities{
		goos:           "linux",
		fsBackend:      func() error { return nil },
		landlockABI:    func() (int, error) { return 9, nil },
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

	if got := doctorExitFromErr(doctorCmd.RunE(cmd, nil)); got != doctorExitGapsFound {
		t.Fatalf("unreachable bridge must exit %d (GAPS FOUND), got %d", doctorExitGapsFound, got)
	}
	if !strings.Contains(out.String(), "Network allowlist cannot be reached") {
		t.Fatalf("expected bridge warning, got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "VERDICT: GAPS FOUND") {
		t.Fatalf("warning alone must not read PROTECTED, got:\n%s", out.String())
	}
}

func TestDoctorNetworkAllowlistNotInertWhenSyscallOff(t *testing.T) {
	// With the syscall fence off, the proxy is advisory because clients can ignore
	// HTTP_PROXY and make direct connections outside the allowlist.
	dir := t.TempDir()
	// Target the [syscall] enforcement line specifically (line-start), not the
	// filesystem's linux_enforcement line which also contains the substring.
	toml := strings.Replace(doctorTestTOML(false), "\nenforcement = \"required\"", "\nenforcement = \"off\"", 1)
	writeTestConfig(t, dir, toml)
	withWorkingDir(t, dir)

	restore := stubDoctorCapabilities(doctorCapabilities{
		goos:           "linux",
		fsBackend:      func() error { return nil },
		landlockABI:    func() (int, error) { return 9, nil },
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

	if got := doctorExitFromErr(doctorCmd.RunE(cmd, nil)); got != doctorExitPartial {
		t.Fatalf("syscall off must exit %d (PARTIAL), got %d", doctorExitPartial, got)
	}
	if strings.Contains(out.String(), "Network allowlist cannot be reached") {
		t.Fatalf("did not expect bridge warning with syscall off, got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "ADVISORY: clients that ignore HTTP_PROXY can reach any host") {
		t.Fatalf("expected advisory egress warning with syscall off, got:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "network-egress-advisory") {
		t.Fatalf("expected named network-egress-advisory check, got:\n%s", out.String())
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
	if !errors.As(err, &exitErr) || exitErr.code != doctorExitGapsFound {
		t.Fatalf("expected exit status 2, got %v", err)
	}
	if !strings.Contains(out.String(), "configured-but-backend-missing") ||
		!strings.Contains(out.String(), "VERDICT: GAPS FOUND") {
		t.Fatalf("expected critical gap output, got:\n%s", out.String())
	}
}

func TestFilesystemDoctorCheckDarwinReportsSeatbeltEnforceable(t *testing.T) {
	cfg := &config.Config{}
	cfg.Filesystem.Root = t.TempDir()

	check := filesystemDoctorCheck(cfg, doctorCapabilities{
		goos: "darwin",
		sandboxExec: func() error {
			return nil
		},
	})

	if check.Severity != doctorOK || check.Status != "enforceable" {
		t.Fatalf("darwin filesystem check = %+v, want enforceable Seatbelt result", check)
	}
	if !strings.Contains(check.Message, "Seatbelt") || !strings.Contains(check.Message, "root-write confinement") {
		t.Fatalf("darwin filesystem message must describe Seatbelt write confinement, got %q", check.Message)
	}
	if check.Fix != "" {
		t.Fatalf("enforceable Seatbelt check should not require a fix, got %q", check.Fix)
	}
}

func TestFilesystemDoctorCheckDarwinMissingSeatbeltIsCritical(t *testing.T) {
	cfg := &config.Config{}
	cfg.Filesystem.Root = t.TempDir()

	check := filesystemDoctorCheck(cfg, doctorCapabilities{
		goos:        "darwin",
		sandboxExec: func() error { return errors.New("sandbox-exec not found") },
	})

	if check.Severity != doctorCritical || check.Status != "configured-but-backend-missing" {
		t.Fatalf("darwin missing-Seatbelt check = %+v, want critical backend-missing", check)
	}
	if strings.Contains(check.Message+check.Fix, "macos_allow_unfenced") {
		t.Fatalf("doctor must not mention the removed macos_allow_unfenced hatch, got %+v", check)
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
		landlockABI:    func() (int, error) { return 9, nil },
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

// TestSyscallDoctorCheckDarwin pins doctor's macOS syscall verdict to the rule
// wrap enforces (macOSSyscallHardening). The default config that `nocklock init`
// writes must pass its own doctor.
func TestSyscallDoctorCheckDarwin(t *testing.T) {
	darwin := doctorCapabilities{goos: "darwin", sandboxExec: func() error { return nil }}
	defaultCfg := func(t *testing.T) *config.Config {
		cfg := config.DefaultConfig()
		return &cfg
	}

	t.Run("default config passes", func(t *testing.T) {
		cfg := defaultCfg(t)
		if cfg.Filesystem.Hardened {
			t.Fatal("test premise: default config leaves filesystem.hardened unset")
		}
		check := syscallDoctorCheck(cfg, darwin)
		if check.Severity != doctorOK || check.Status != "enforceable" {
			t.Fatalf("darwin default-config syscall check = %+v, want enforceable", check)
		}
	})
	t.Run("required without root is critical", func(t *testing.T) {
		cfg := defaultCfg(t)
		cfg.Filesystem.Root = ""
		check := syscallDoctorCheck(cfg, darwin)
		if check.Severity != doctorCritical || !strings.Contains(check.Message, "filesystem.root") {
			t.Fatalf("check = %+v, want critical naming filesystem.root", check)
		}
	})
	t.Run("preferred without root warns that nothing is applied", func(t *testing.T) {
		cfg := defaultCfg(t)
		cfg.Syscall.Enforcement = "preferred"
		cfg.Filesystem.Root = ""
		check := syscallDoctorCheck(cfg, darwin)
		if check.Severity != doctorWarning || check.Status != "not-applied" {
			t.Fatalf("check = %+v, want not-applied warning", check)
		}
	})
	t.Run("missing sandbox-exec is critical", func(t *testing.T) {
		caps := darwin
		caps.sandboxExec = func() error { return errors.New("sandbox-exec not found") }
		check := syscallDoctorCheck(defaultCfg(t), caps)
		if check.Severity != doctorCritical {
			t.Fatalf("check = %+v, want critical", check)
		}
	})
	t.Run("off is not configured", func(t *testing.T) {
		cfg := defaultCfg(t)
		cfg.Syscall.Enforcement = "off"
		cfg.Filesystem.Root = ""
		if check := syscallDoctorCheck(cfg, darwin); check.Status != "not-configured" {
			t.Fatalf("check = %+v, want not-configured", check)
		}
	})
}
