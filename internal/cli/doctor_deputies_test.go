package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/spf13/cobra"
)

// deputyFixture is one hermetic host: a project directory holding .nock/, a
// home directory outside it, and a short directory for fixture sockets (Unix
// socket paths are limited to about 104 bytes).
type deputyFixture struct {
	project, home, sockDir string
	sockets                []deputyTarget
	sudoOK                 bool
	notWritable            map[string]bool
}

func newDeputyFixture(t *testing.T) *deputyFixture {
	t.Helper()
	base := resolvedTempDir(t)
	f := &deputyFixture{project: filepath.Join(base, "project"), home: isolatedTestHome(t)}
	if err := os.Mkdir(f.project, 0o700); err != nil {
		t.Fatal(err)
	}
	sockDir, err := os.MkdirTemp("", "nld")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(sockDir) })
	if f.sockDir, err = filepath.EvalSymlinks(sockDir); err != nil {
		t.Fatal(err)
	}
	f.notWritable = map[string]bool{}
	return f
}

// socket creates a listening Unix socket at sockDir/rel and registers it as a
// container socket candidate.
func (f *deputyFixture) socket(t *testing.T, name, rel string) string {
	t.Helper()
	path := f.listen(t, rel)
	f.sockets = append(f.sockets, deputyTarget{name: name, path: path, what: name + " fixture", why: whyContainerSocket})
	return path
}

func (f *deputyFixture) listen(t *testing.T, rel string) string {
	t.Helper()
	path := filepath.Join(f.sockDir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	return path
}

// file creates base/rel (a directory when rel ends in "/").
func (f *deputyFixture) file(t *testing.T, base, rel string) string {
	t.Helper()
	path := filepath.Join(base, rel)
	if strings.HasSuffix(rel, "/") {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("# fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func (f *deputyFixture) host(goos string) deputyHost {
	return deputyHost{
		home:          f.home,
		xdgConfigHome: filepath.Join(f.home, ".config"),
		runtimeDir:    filepath.Join(f.sockDir, "run"),
		sockets:       f.sockets,
		writable: func(p string) bool {
			return !f.notWritable[p] && pathWritableByUser(p)
		},
		sudo: func(context.Context) error {
			if f.sudoOK {
				return nil
			}
			return errors.New("a password is required")
		},
	}
}

// run runs `doctor --json` against the fixture with stubbed fence backends.
func (f *deputyFixture) run(t *testing.T, toml, goos string, abi int) (doctorReport, int) {
	t.Helper()
	t.Setenv("HOME", f.home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(string(os.PathSeparator), "nocklock-doctor-test", filepath.Base(filepath.Dir(f.project))))
	stateHome := t.TempDir()
	if err := os.Chmod(stateHome, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_STATE_HOME", stateHome)
	t.Setenv("XDG_DATA_HOME", filepath.Join(f.home, "data"))
	writeTestConfig(t, f.project, toml)
	withWorkingDir(t, f.project)
	defer stubDoctorCapabilities(doctorCapabilities{
		goos:           goos,
		fsBackend:      func() error { return nil },
		landlockABI:    func() (int, error) { return abi, nil },
		syscallBackend: func() bool { return true },
		networkBackend: func() error { return nil },
		sandboxExec:    func() error { return nil },
		deputies:       func(goos string) deputyHost { return f.host(goos) },
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

func deputyRows(r doctorReport) []doctorCheck {
	var rows []doctorCheck
	for _, c := range r.Checks {
		if c.Group == doctorDeputyGroup {
			rows = append(rows, c)
		}
	}
	return rows
}

// deputyRow finds the Deputies row whose message names path (or name, for
// rows with no path).
func deputyRow(t *testing.T, r doctorReport, name, path string) doctorCheck {
	t.Helper()
	for _, c := range deputyRows(r) {
		if c.Name == name && (path == "" || strings.Contains(c.Message, path)) {
			return c
		}
	}
	t.Fatalf("no %s deputy row for %q; rows=%+v", name, path, deputyRows(r))
	return doctorCheck{}
}

func requireDeputyStatus(t *testing.T, c doctorCheck, wantBlocked bool) {
	t.Helper()
	if wantBlocked {
		if c.Severity != doctorOK || c.Status != "blocked" || !strings.Contains(c.Message, ": blocked by the fence") {
			t.Fatalf("deputy row = %+v, want ok/blocked", c)
		}
		return
	}
	if c.Severity != doctorWarning || c.Status != "reachable" || !strings.Contains(c.Message, "not blocked by the fence, because") {
		t.Fatalf("deputy row = %+v, want warning/reachable", c)
	}
}

func boundaryCheck(r doctorReport, name string) doctorCheck {
	for _, c := range r.Checks {
		if c.Group == "Fences" && c.Name == name {
			return c
		}
	}
	return doctorCheck{}
}

// TestDoctorDeputyDockerSocketKeepsPartial is the acceptance pair: a reachable
// docker.sock below Landlock ABI 9 is listed and doctor reads PARTIAL; at ABI 9
// the same socket is blocked and the default config stays PROTECTED.
func TestDoctorDeputyDockerSocketKeepsPartial(t *testing.T) {
	f := newDeputyFixture(t)
	sock := f.socket(t, "docker-socket", "docker.sock")

	got, code := f.run(t, config.DefaultTOML(), "linux", 8)
	if got.Verdict != doctorVerdictPartial || code != doctorExitPartial {
		t.Fatalf("verdict=%q exit=%d, want PARTIAL/%d; rows=%+v", got.Verdict, code, doctorExitPartial, deputyRows(got))
	}
	if len(got.Gaps) != 0 {
		t.Fatalf("a reachable deputy must not be a gap: %+v", got.Gaps)
	}
	row := deputyRow(t, got, "docker-socket", sock)
	requireDeputyStatus(t, row, false)
	if !strings.Contains(row.Message, "privileged container") || !strings.Contains(row.Message, "ABI v9") {
		t.Fatalf("row must say why it matters and why it is not blocked: %+v", row)
	}

	f2 := newDeputyFixture(t)
	sock2 := f2.socket(t, "docker-socket", "docker.sock")
	got, code = f2.run(t, config.DefaultTOML(), "linux", 9)
	if got.Verdict != doctorVerdictProtected || code != doctorExitProtected {
		t.Fatalf("ABI 9: verdict=%q exit=%d, want PROTECTED; rows=%+v", got.Verdict, code, deputyRows(got))
	}
	requireDeputyStatus(t, deputyRow(t, got, "docker-socket", sock2), true)
}

// TestDoctorDeputyStrictSocketOptionStillRefuses: with
// network.require_unix_socket_isolation = true below ABI 9 the verdict and the
// unix-sockets row are what they were before the deputy scan (GAPS FOUND,
// will-refuse); the socket is still listed.
func TestDoctorDeputyStrictSocketOptionStillRefuses(t *testing.T) {
	toml := strings.Replace(config.DefaultTOML(), "require_unix_socket_isolation = false", "require_unix_socket_isolation = true", 1)
	f := newDeputyFixture(t)
	sock := f.socket(t, "docker-socket", "docker.sock")
	got, code := f.run(t, toml, "linux", 8)
	if got.Verdict != doctorVerdictGapsFound || code != doctorExitGapsFound {
		t.Fatalf("verdict=%q exit=%d, want GAPS FOUND/%d", got.Verdict, code, doctorExitGapsFound)
	}
	us := boundaryCheck(got, "unix-sockets")
	if us.Severity != doctorCritical || us.Status != "will-refuse" || !strings.Contains(us.Message, "Wrap will refuse") {
		t.Fatalf("unix-sockets row = %+v, want critical/will-refuse", us)
	}
	if len(got.Gaps) != 1 || got.Gaps[0].Name != "unix-sockets" {
		t.Fatalf("gaps = %+v, want only the unix-sockets refusal", got.Gaps)
	}
	requireDeputyStatus(t, deputyRow(t, got, "docker-socket", sock), false)
}

// TestDoctorDeputyScanKeepsDefaultVerdicts: with the scan enabled and nothing
// reachable, the default config is PROTECTED on both platforms and the section
// says so.
func TestDoctorDeputyScanKeepsDefaultVerdicts(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		t.Run(goos, func(t *testing.T) {
			f := newDeputyFixture(t)
			got, code := f.run(t, config.DefaultTOML(), goos, 9)
			if got.Verdict != doctorVerdictProtected || code != doctorExitProtected {
				t.Fatalf("verdict=%q exit=%d, want PROTECTED; rows=%+v", got.Verdict, code, deputyRows(got))
			}
			rows := deputyRows(got)
			if len(rows) != 1 || rows[0].Status != "none-found" || rows[0].Severity != doctorInfo {
				t.Fatalf("rows = %+v, want one none-found info row", rows)
			}
		})
	}
}

// TestDoctorDeputyWorseVerdictsUnchanged: a reachable deputy never lifts or
// lowers GAPS FOUND or UNPROTECTED.
func TestDoctorDeputyWorseVerdictsUnchanged(t *testing.T) {
	allOff := "[filesystem]\nroot = \"\"\n\n[network]\nallow_all = true\n\n[syscall]\nenforcement = \"off\"\n\n[secrets]\npass = []\nblock = []\n"
	unreachable := strings.Replace(config.DefaultTOML(), "[filesystem]\nroot = \".\"", "[filesystem]\nroot = \"\"", 1)
	for _, tc := range []struct {
		name, toml string
		want       doctorVerdict
		code       int
	}{
		{"unprotected", allOff, doctorVerdictUnprotected, doctorExitUnprotected},
		{"gaps found", unreachable, doctorVerdictGapsFound, doctorExitGapsFound},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newDeputyFixture(t)
			f.socket(t, "docker-socket", "docker.sock")
			f.sudoOK = true
			got, code := f.run(t, tc.toml, "linux", 9)
			if got.Verdict != tc.want || code != tc.code {
				t.Fatalf("verdict=%q exit=%d, want %q/%d", got.Verdict, code, tc.want, tc.code)
			}
			if reachableDeputies(got.Checks) == 0 {
				t.Fatalf("expected reachable deputies to be listed: %+v", deputyRows(got))
			}
		})
	}
}

// TestDoctorDeputyLinuxRows covers each Linux deputy type with fixtures, for the
// default fence and for configurations that leave each type open.
func TestDoctorDeputyLinuxRows(t *testing.T) {
	landlockOff := strings.Replace(config.DefaultTOML(), `linux_enforcement = "required"`, `linux_enforcement = "off"`, 1)
	noNNP := strings.Replace(landlockOff, `enforcement = "required"`, `enforcement = "off"`, 1)
	if noNNP == landlockOff {
		t.Fatal("default TOML no longer carries syscall enforcement = \"required\"; update this test")
	}

	t.Run("default fence", func(t *testing.T) {
		f := newDeputyFixture(t)
		containerd := f.socket(t, "containerd-socket", "containerd/containerd.sock")
		podman := f.socket(t, "podman-socket", "podman/podman.sock")
		bus := f.listen(t, "run/bus")
		bashrc := f.file(t, f.home, ".bashrc")
		fish := f.file(t, f.home, ".config/fish/config.fish")
		units := f.file(t, f.home, ".config/systemd/user/")
		userClaude := f.file(t, f.home, ".claude/settings.json")
		userCodex := f.file(t, f.home, ".codex/config.toml")
		userCursor := f.file(t, f.home, ".cursor/hooks.json")
		userGemini := f.file(t, f.home, ".gemini/settings.json")
		projClaude := f.file(t, f.project, ".claude/settings.json")
		projHooks := f.file(t, f.project, ".claude/hooks/")
		projMCP := f.file(t, f.project, ".mcp.json")
		projCodex := f.file(t, f.project, ".codex/config.toml")
		projCursor := f.file(t, f.project, ".cursor/mcp.json")
		projGemini := f.file(t, f.project, ".gemini/settings.json")
		f.sudoOK = true

		got, code := f.run(t, config.DefaultTOML(), "linux", 9)
		for _, tc := range []struct {
			name, path string
			blocked    bool
		}{
			{"containerd-socket", containerd, true},
			{"podman-socket", podman, true},
			{"systemd-user-bus", bus, true},
			{"shell-startup", bashrc, true},
			{"shell-startup", fish, true},
			{"systemd-user-units", units, true},
			{"agent-config", userClaude, true},
			{"agent-config", userCodex, true},
			{"agent-config", userCursor, true},
			{"agent-config", userGemini, true},
			// Project config sits inside filesystem.root, which the agent may write.
			{"agent-config", projClaude, false},
			{"agent-config", projHooks, false},
			{"agent-config", projMCP, false},
			{"agent-config", projCodex, false},
			{"agent-config", projCursor, false},
			{"agent-config", projGemini, false},
			// Landlock and seccomp set no_new_privs, so sudo cannot elevate.
			{"sudo-no-prompt", "", true},
		} {
			requireDeputyStatus(t, deputyRow(t, got, tc.name, tc.path), tc.blocked)
		}
		if got.Verdict != doctorVerdictPartial || code != doctorExitPartial {
			t.Fatalf("verdict=%q exit=%d, want PARTIAL for writable project agent config", got.Verdict, code)
		}
	})

	t.Run("below ABI 9 sockets and bus are reachable", func(t *testing.T) {
		f := newDeputyFixture(t)
		containerd := f.socket(t, "containerd-socket", "containerd/containerd.sock")
		podman := f.socket(t, "podman-socket", "podman/podman.sock")
		bus := f.listen(t, "run/bus")
		got, _ := f.run(t, config.DefaultTOML(), "linux", 8)
		requireDeputyStatus(t, deputyRow(t, got, "containerd-socket", containerd), false)
		requireDeputyStatus(t, deputyRow(t, got, "podman-socket", podman), false)
		requireDeputyStatus(t, deputyRow(t, got, "systemd-user-bus", bus), false)
	})

	t.Run("Landlock off leaves home writable", func(t *testing.T) {
		f := newDeputyFixture(t)
		bashrc := f.file(t, f.home, ".zshrc")
		units := f.file(t, f.home, ".config/systemd/user/")
		f.sudoOK = true
		got, _ := f.run(t, landlockOff, "linux", 9)
		row := deputyRow(t, got, "shell-startup", bashrc)
		requireDeputyStatus(t, row, false)
		if !strings.Contains(row.Message, "userspace fence") {
			t.Fatalf("row must say only the userspace fence applies: %+v", row)
		}
		requireDeputyStatus(t, deputyRow(t, got, "systemd-user-units", units), false)
		// The syscall fence still sets no_new_privs.
		requireDeputyStatus(t, deputyRow(t, got, "sudo-no-prompt", ""), true)
	})

	t.Run("no Landlock and no seccomp leaves sudo reachable", func(t *testing.T) {
		f := newDeputyFixture(t)
		f.sudoOK = true
		got, _ := f.run(t, noNNP, "linux", 9)
		row := deputyRow(t, got, "sudo-no-prompt", "")
		requireDeputyStatus(t, row, false)
		if !strings.Contains(row.Message, "acts as root") {
			t.Fatalf("sudo row must say why it matters: %+v", row)
		}
	})

	t.Run("allow_rw grant makes a home path writable", func(t *testing.T) {
		f := newDeputyFixture(t)
		units := f.file(t, f.home, ".config/systemd/user/")
		toml := strings.Replace(config.DefaultTOML(), "allow_rw = []", "allow_rw = [\""+filepath.Join(f.home, ".config")+"\"]", 1)
		got, _ := f.run(t, toml, "linux", 9)
		requireDeputyStatus(t, deputyRow(t, got, "systemd-user-units", units), false)
	})

	t.Run("not writable, missing, or failed sudo is not listed", func(t *testing.T) {
		f := newDeputyFixture(t)
		ro := f.file(t, f.home, ".profile")
		// Neither the file nor its folder: no write route and no replace route.
		f.notWritable[ro] = true
		f.notWritable[f.home] = true
		notSock := f.file(t, f.sockDir, "plain/docker.sock")
		f.sockets = append(f.sockets, deputyTarget{name: "docker-socket", path: notSock, what: "not a socket", why: whyContainerSocket})
		f.sockets = append(f.sockets, deputyTarget{name: "docker-socket", path: filepath.Join(f.sockDir, "missing.sock"), what: "missing", why: whyContainerSocket})
		got, code := f.run(t, config.DefaultTOML(), "linux", 8)
		rows := deputyRows(got)
		if len(rows) != 1 || rows[0].Status != "none-found" {
			t.Fatalf("rows = %+v, want none-found", rows)
		}
		// ABI 8 alone is still PARTIAL from the unix-sockets boundary.
		if got.Verdict != doctorVerdictPartial || code != doctorExitPartial {
			t.Fatalf("verdict=%q exit=%d", got.Verdict, code)
		}
	})
}

// TestDoctorDeputyDarwinRows covers the macOS rows with fixtures. The platform
// is the injected caps.goos, so these run on every test host, and the fixture
// sockets and access checks run for real on macOS CI.
func TestDoctorDeputyDarwinRows(t *testing.T) {
	allowAll := strings.Replace(config.DefaultTOML(), "allow_all = false", "allow_all = true", 1)

	t.Run("default fence", func(t *testing.T) {
		f := newDeputyFixture(t)
		desktop := f.socket(t, "docker-socket", "docker-run/docker.sock")
		agents := f.file(t, f.home, "Library/LaunchAgents/")
		zprofile := f.file(t, f.home, ".zprofile")
		fish := f.file(t, f.home, ".config/fish/config.fish")
		units := f.file(t, f.home, ".config/systemd/user/")
		bus := f.listen(t, "run/bus")
		projCursor := f.file(t, f.project, ".cursor/hooks.json")
		f.sudoOK = true
		got, code := f.run(t, config.DefaultTOML(), "darwin", 0)
		requireDeputyStatus(t, deputyRow(t, got, "docker-socket", desktop), true)
		requireDeputyStatus(t, deputyRow(t, got, "launch-agents", agents), true)
		requireDeputyStatus(t, deputyRow(t, got, "shell-startup", zprofile), true)
		requireDeputyStatus(t, deputyRow(t, got, "shell-startup", fish), true)
		requireDeputyStatus(t, deputyRow(t, got, "agent-config", projCursor), false)
		sudo := deputyRow(t, got, "sudo-no-prompt", "")
		requireDeputyStatus(t, sudo, false)
		if !strings.Contains(sudo.Message, "Seatbelt does not stop sudo") {
			t.Fatalf("macOS sudo row must say why: %+v", sudo)
		}
		for _, c := range deputyRows(got) {
			if c.Name == "systemd-user-units" || c.Name == "systemd-user-bus" || strings.Contains(c.Message, units) || strings.Contains(c.Message, bus) {
				t.Fatalf("Linux-only row on macOS: %+v", c)
			}
		}
		if got.Verdict != doctorVerdictPartial || code != doctorExitPartial {
			t.Fatalf("verdict=%q exit=%d, want PARTIAL", got.Verdict, code)
		}
	})

	t.Run("project deny path is blocked", func(t *testing.T) {
		f := newDeputyFixture(t)
		projClaude := f.file(t, f.project, ".claude/settings.json")
		toml := strings.Replace(config.DefaultTOML(), "deny = [\n", "deny = [\n    \""+filepath.Join(f.project, ".claude")+"\",\n", 1)
		got, code := f.run(t, toml, "darwin", 0)
		requireDeputyStatus(t, deputyRow(t, got, "agent-config", projClaude), true)
		if got.Verdict != doctorVerdictProtected || code != doctorExitProtected {
			t.Fatalf("verdict=%q exit=%d, want PROTECTED; rows=%+v", got.Verdict, code, deputyRows(got))
		}
	})

	t.Run("no network floor leaves sockets reachable", func(t *testing.T) {
		f := newDeputyFixture(t)
		desktop := f.socket(t, "docker-socket", "docker-run/docker.sock")
		got, _ := f.run(t, allowAll, "darwin", 0)
		row := deputyRow(t, got, "docker-socket", desktop)
		requireDeputyStatus(t, row, false)
		if !strings.Contains(row.Message, "Seatbelt network floor") {
			t.Fatalf("row must say why: %+v", row)
		}
	})
}

// TestDeputyTargetsPerPlatform pins the candidate lists to the platform.
func TestDeputyTargetsPerPlatform(t *testing.T) {
	home := filepath.Join(string(os.PathSeparator), "h")
	paths := func(ts []deputyTarget) []string {
		var out []string
		for _, x := range ts {
			out = append(out, x.path)
		}
		return out
	}
	linux := paths(containerSocketTargets("linux", home, "/run/user/1000"))
	for _, want := range []string{"/var/run/docker.sock", "/run/containerd/containerd.sock", "/run/podman/podman.sock", "/run/user/1000/docker.sock", "/run/user/1000/podman/podman.sock"} {
		if !slices.Contains(linux, want) {
			t.Fatalf("linux sockets %v missing %s", linux, want)
		}
	}
	darwin := paths(containerSocketTargets("darwin", home, ""))
	for _, want := range []string{"/var/run/docker.sock", filepath.Join(home, ".docker", "run", "docker.sock")} {
		if !slices.Contains(darwin, want) {
			t.Fatalf("darwin sockets %v missing %s", darwin, want)
		}
	}
	if got := containerSocketTargets("windows", home, ""); got != nil {
		t.Fatalf("unsupported platform sockets = %v", got)
	}
	h := deputyHost{home: home, xdgConfigHome: filepath.Join(home, ".config")}
	lw := paths(writableDeputyTargets("linux", h))
	dw := paths(writableDeputyTargets("darwin", h))
	units, agents := filepath.Join(home, ".config", "systemd", "user"), filepath.Join(home, "Library", "LaunchAgents")
	if !slices.Contains(lw, units) || slices.Contains(lw, agents) {
		t.Fatalf("linux writable targets wrong: %v", lw)
	}
	if !slices.Contains(dw, agents) || slices.Contains(dw, units) {
		t.Fatalf("darwin writable targets wrong: %v", dw)
	}
}

// TestPasswordlessSudoProbeCannotHang runs the probe against a fake sudo: it
// passes exactly `-k -n true`, and a sudo that never returns is cut off by the
// timeout. Real sudo is never run.
func TestPasswordlessSudoProbeCannotHang(t *testing.T) {
	bin := t.TempDir()
	argsFile := filepath.Join(bin, "args")
	fake := filepath.Join(bin, "sudo")
	write := func(body string) {
		if err := os.WriteFile(fake, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
			t.Fatal(err)
		}
	}

	write("printf '%s ' \"$@\" > " + argsFile + "\nexit 0\n")
	if err := runSudoProbe(context.Background(), fake); err != nil {
		t.Fatalf("fake passwordless sudo: %v", err)
	}
	// -k ignores a cached sudo login for this call and does not refresh it;
	// -n fails at once instead of prompting.
	if b, _ := os.ReadFile(argsFile); strings.TrimSpace(string(b)) != "-k -n true" {
		t.Fatalf("sudo args = %q, want -k -n true", b)
	}

	write("exit 1\n")
	if err := runSudoProbe(context.Background(), fake); err == nil {
		t.Fatal("a sudo that needs a password must not count as passwordless")
	}

	write("exec /bin/sleep 30\n")
	start := time.Now()
	if err := runSudoProbe(context.Background(), fake); err == nil {
		t.Fatal("a hung sudo must not count as passwordless")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("probe took %s; the timeout must cut it off", d)
	}
}

// TestPasswordlessSudoProbeIgnoresPATH: the probe runs sudo only from its fixed
// absolute path, never a sudo found on PATH, and skips the probe when that path
// is missing or not a root-owned executable. Real sudo is never run.
func TestPasswordlessSudoProbeIgnoresPATH(t *testing.T) {
	bin := t.TempDir()
	marker := filepath.Join(bin, "ran")
	planted := "#!/bin/sh\ntouch " + marker + "\nexit 0\n"
	if err := os.WriteFile(filepath.Join(bin, "sudo"), []byte(planted), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	orig := sudoBinary
	t.Cleanup(func() { sudoBinary = orig })

	// Missing absolute sudo: skipped, the PATH sudo is not run.
	sudoBinary = filepath.Join(t.TempDir(), "sudo")
	if err := passwordlessSudoProbe(context.Background()); err == nil {
		t.Fatal("a missing sudo must not count as passwordless")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the probe ran a sudo found on PATH")
	}

	// A sudo at the fixed path that this user owns is not trusted or run.
	sudoBinary = filepath.Join(bin, "sudo")
	if _, err := trustedSudoPath(); err == nil {
		t.Fatal("a sudo owned by this user must not be trusted")
	}
	if err := passwordlessSudoProbe(context.Background()); err == nil {
		t.Fatal("an untrusted sudo must not count as passwordless")
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the probe ran an untrusted sudo")
	}

	// A directory is not a regular executable.
	sudoBinary = bin
	if _, err := trustedSudoPath(); err == nil {
		t.Fatal("a directory must not be trusted as sudo")
	}
}

// TestDoctorDeputyHumanOutput checks the human report lists the section and
// names deputies in the PARTIAL summary. Run with -v to see a sample report.
func TestDoctorDeputyHumanOutput(t *testing.T) {
	f := newDeputyFixture(t)
	f.socket(t, "docker-socket", "docker.sock")
	f.sockets[0].what = "Docker daemon socket"
	f.file(t, f.home, ".bashrc")
	f.file(t, f.project, ".claude/settings.json")
	f.sudoOK = true
	report, _ := f.run(t, config.DefaultTOML(), "linux", 8)
	var out bytes.Buffer
	renderDoctorHuman(&out, report)
	s := out.String()
	for _, want := range []string{"\nDeputies\n", "docker-socket [reachable]", "shell-startup [blocked]", "sudo-no-prompt [blocked]", "VERDICT: PARTIAL", "- deputies: 2 reachable and not blocked by the fence"} {
		if !strings.Contains(s, want) {
			t.Fatalf("human output missing %q:\n%s", want, s)
		}
	}
	t.Logf("sample report:\n%s", s)
}

// TestDoctorDeputySymlinkedConfigIsReplaceable: a project config that is a
// symlink to a file outside every write grant is still reachable, because the
// project folder is granted read-write and the agent can unlink the symlink and
// create a regular file in its place. The controls show the other routes.
func TestDoctorDeputySymlinkedConfigIsReplaceable(t *testing.T) {
	link := func(t *testing.T, target, path string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
	}
	f := newDeputyFixture(t)
	outside := f.file(t, f.home, "dotfiles/claude-settings.json")
	projClaude := filepath.Join(f.project, ".claude", "settings.json")
	link(t, outside, projClaude)
	// A home startup file linked into the project is writable through its
	// target, which sits inside the root grant.
	inProject := f.file(t, f.project, "shared/bashrc")
	bashrc := filepath.Join(f.home, ".bashrc")
	link(t, inProject, bashrc)
	// A home startup file linked to another home file: both routes are
	// outside every grant.
	zshrcTarget := f.file(t, f.home, "dotfiles/zshrc")
	zshrc := filepath.Join(f.home, ".zshrc")
	link(t, zshrcTarget, zshrc)

	got, code := f.run(t, config.DefaultTOML(), "linux", 9)
	row := deputyRow(t, got, "agent-config", projClaude)
	requireDeputyStatus(t, row, false)
	if !strings.Contains(row.Message, "can replace it") {
		t.Fatalf("symlinked config row must name the replace route: %+v", row)
	}
	if got.Verdict != doctorVerdictPartial || code != doctorExitPartial {
		t.Fatalf("verdict=%q exit=%d, want PARTIAL/%d", got.Verdict, code, doctorExitPartial)
	}
	row = deputyRow(t, got, "shell-startup", bashrc)
	requireDeputyStatus(t, row, false)
	if !strings.Contains(row.Message, "the path is inside a write grant") {
		t.Fatalf("symlink into the root must name the write route: %+v", row)
	}
	requireDeputyStatus(t, deputyRow(t, got, "shell-startup", zshrc), true)
}

// TestDoctorDeputyProjectLinkToHomeFileNotDeduplicated: a project config that
// is a symlink to the matching home file must keep its own row. Home targets
// are listed first, so deduplicating on the resolved target dropped the
// replaceable project entry behind the blocked home row and left PROTECTED.
func TestDoctorDeputyProjectLinkToHomeFileNotDeduplicated(t *testing.T) {
	f := newDeputyFixture(t)
	homeSettings := f.file(t, f.home, ".claude/settings.json")
	projSettings := filepath.Join(f.project, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(projSettings), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(homeSettings, projSettings); err != nil {
		t.Fatal(err)
	}
	got, code := f.run(t, config.DefaultTOML(), "linux", 9)
	requireDeputyStatus(t, deputyRow(t, got, "agent-config", homeSettings), true)
	row := deputyRow(t, got, "agent-config", projSettings)
	requireDeputyStatus(t, row, false)
	if !strings.Contains(row.Message, "can replace it") {
		t.Fatalf("project link row must name the replace route: %+v", row)
	}
	if got.Verdict != doctorVerdictPartial || code != doctorExitPartial {
		t.Fatalf("verdict=%q exit=%d, want PARTIAL/%d; rows=%+v", got.Verdict, code, doctorExitPartial, deputyRows(got))
	}
}

// TestDoctorDeputySymlinkedProjectConfigDir: a project config folder that is a
// symlink to a folder outside every write grant is still reachable. The agent
// can unlink project/.claude, which sits inside the project write grant, and
// create a real folder holding its own settings.json. Both routes through the
// symlink resolve outside the grant, so only the listed path shows this. The
// home file behind the link keeps its own blocked row.
func TestDoctorDeputySymlinkedProjectConfigDir(t *testing.T) {
	f := newDeputyFixture(t)
	homeSettings := f.file(t, f.home, ".claude/settings.json")
	if err := os.Symlink(filepath.Join(f.home, ".claude"), filepath.Join(f.project, ".claude")); err != nil {
		t.Fatal(err)
	}
	projSettings := filepath.Join(f.project, ".claude", "settings.json")
	// A linked folder whose target is no home candidate.
	cursorHooks := f.file(t, f.home, "dotfiles/cursor/hooks.json")
	if err := os.Symlink(filepath.Dir(cursorHooks), filepath.Join(f.project, ".cursor")); err != nil {
		t.Fatal(err)
	}
	projCursor := filepath.Join(f.project, ".cursor", "hooks.json")

	got, code := f.run(t, config.DefaultTOML(), "linux", 9)
	requireDeputyStatus(t, deputyRow(t, got, "agent-config", homeSettings), true)
	for _, p := range []string{projSettings, projCursor} {
		row := deputyRow(t, got, "agent-config", p)
		requireDeputyStatus(t, row, false)
		if !strings.Contains(row.Message, "a folder on its path") {
			t.Fatalf("linked folder row must name the folder route: %+v", row)
		}
	}
	if got.Verdict != doctorVerdictPartial || code != doctorExitPartial {
		t.Fatalf("verdict=%q exit=%d, want PARTIAL/%d; rows=%+v", got.Verdict, code, doctorExitPartial, deputyRows(got))
	}
}

// TestDoctorDeputySymlinkedSocketCountsOnce: two candidate paths that resolve
// to one socket (macOS Docker Desktop: /var/run/docker.sock links to the
// daemon socket under the home directory) are one deputy, not two.
func TestDoctorDeputySymlinkedSocketCountsOnce(t *testing.T) {
	f := newDeputyFixture(t)
	real := f.socket(t, "docker-socket", "real/docker.sock")
	link := filepath.Join(f.sockDir, "link.sock")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	f.sockets = append(f.sockets, deputyTarget{name: "docker-socket", path: link, what: "docker-socket fixture", why: whyContainerSocket})

	got, _ := f.run(t, config.DefaultTOML(), "linux", 8)
	n := 0
	for _, r := range deputyRows(got) {
		if r.Name == "docker-socket" {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("one daemon reached through two paths must be one row, got %d: %+v", n, deputyRows(got))
	}
	if c := reachableDeputies(got.Checks); c != 1 {
		t.Fatalf("reachableDeputies = %d, want 1", c)
	}
}

// TestPasswordlessSudoProbeKillsDescendants: a sudo that starts a helper and
// waits must not leave that helper running after the timeout. Real sudo is
// never run.
func TestPasswordlessSudoProbeKillsDescendants(t *testing.T) {
	bin := t.TempDir()
	pidFile := filepath.Join(bin, "child.pid")
	fake := filepath.Join(bin, "sudo")
	script := "#!/bin/sh\n/bin/sleep 30 &\necho $! > " + pidFile + "\nwait\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := runSudoProbe(context.Background(), fake); err == nil {
		t.Fatal("a hung sudo must not count as passwordless")
	}
	if d := time.Since(start); d > 10*time.Second {
		t.Fatalf("probe took %s; the timeout must cut it off", d)
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		t.Fatalf("bad child pid %q", b)
	}
	// Once ESRCH is seen the pid may be reused, so the cleanup must not kill it.
	exited := false
	t.Cleanup(func() {
		if !exited {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	// The killed child is reaped by its new parent; allow a moment for that.
	deadline := time.Now().Add(5 * time.Second)
	for {
		gone, esrch := processGone(pid)
		if esrch {
			exited = true
		}
		if gone {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("helper pid %d still exists after the probe timed out", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// requireHelperGone reads the pid a fake probe wrote to pidFile and fails
// unless that process is gone within a few seconds. A helper killed with its
// group is reaped by its new parent, so it may take a moment.
func requireHelperGone(t *testing.T, pidFile string) {
	t.Helper()
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("fake probe did not record its helper: %v", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 {
		t.Fatalf("bad helper pid %q", b)
	}
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(50 * time.Millisecond) {
		if gone, _ := processGone(pid); gone {
			return
		}
		if time.Now().After(deadline) {
			// Not ESRCH yet, so the pid is still the helper's.
			_ = syscall.Kill(pid, syscall.SIGKILL)
			t.Fatalf("helper pid %d outlived the probe", pid)
		}
	}
}

// A sudo that starts a background helper and exits 0 at once still counts as
// passwordless, and the helper is killed with the probe's group.
func TestPasswordlessSudoProbeKillsHelperOnExit(t *testing.T) {
	bin := t.TempDir()
	pidFile := filepath.Join(bin, "child.pid")
	fake := filepath.Join(bin, "sudo")
	script := "#!/bin/sh\n/bin/sleep 30 &\necho $! > " + pidFile + "\nexit 0\n"
	if err := os.WriteFile(fake, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := runSudoProbe(context.Background(), fake); err != nil {
		t.Fatalf("a sudo that exits 0 must count as passwordless: %v", err)
	}
	requireHelperGone(t, pidFile)
}

// processGone reports whether pid has exited. An unreaped zombie counts as
// gone: it runs nothing, and a parent that never reaps it (a minimal PID 1 or a
// subreaper) would otherwise fail the check. esrch reports that the pid no
// longer exists at all, after which it may be reused.
func processGone(pid int) (gone, esrch bool) {
	if errors.Is(syscall.Kill(pid, 0), syscall.ESRCH) {
		return true, true
	}
	if runtime.GOOS == "linux" {
		b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
		if err == nil {
			// The state follows the parenthesised command name, which may
			// itself contain ") ".
			s := string(b)
			if i := strings.LastIndexByte(s, ')'); i >= 0 && strings.HasPrefix(strings.TrimSpace(s[i+1:]), "Z") {
				return true, false
			}
		}
	}
	return false, false
}

// TestProcessGoneTreatsZombieAsGone: an exited child its parent has not reaped
// is a zombie, which processGone must count as gone.
func TestProcessGoneTreatsZombieAsGone(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("zombie state is read from /proc on Linux")
	}
	cmd := exec.Command("/bin/true")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	pid := cmd.Process.Pid
	t.Cleanup(func() { _ = cmd.Wait() })
	deadline := time.Now().Add(5 * time.Second)
	for {
		b, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
		if err != nil {
			t.Fatal(err)
		}
		if s := string(b); strings.HasPrefix(strings.TrimSpace(s[strings.LastIndexByte(s, ')')+1:]), "Z") {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("child %d never became a zombie: %s", pid, b)
		}
		time.Sleep(10 * time.Millisecond)
	}
	if gone, esrch := processGone(pid); !gone || esrch {
		t.Fatalf("processGone(zombie %d) = gone %v, esrch %v; want gone, no ESRCH", pid, gone, esrch)
	}
}
