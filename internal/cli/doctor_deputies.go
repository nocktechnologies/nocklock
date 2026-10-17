package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
	"golang.org/x/sys/unix"
)

// A deputy is a more-privileged helper the fenced agent can ask to act for it:
// a container daemon socket, the systemd user bus, a startup file or agent
// config that an unfenced program later runs or loads, or passwordless sudo.
// Doctor lists the deputies that exist and are reachable for this user, says
// whether the fence blocks each one, and fixes nothing.

const doctorDeputyGroup = "Deputies"

// deputyHost is the host view the deputy scan reads. Production fills it from
// the environment (defaultDeputyHost); tests inject fixture paths and fakes.
type deputyHost struct {
	home          string
	xdgConfigHome string
	runtimeDir    string
	// projectRoot is the directory holding .nock/, where project-level agent
	// config lives. Set by runDoctor from the config path.
	projectRoot string
	// sockets are the container daemon socket paths to look for.
	sockets []deputyTarget
	// tempWriteDirs are the per-user temporary and cache directories the macOS
	// Seatbelt profile also grants for writes.
	tempWriteDirs []string
	// writable reports whether this user may write (or, for a socket, connect
	// to) an existing path.
	writable func(path string) bool
	// sudo runs the non-interactive passwordless sudo probe; nil skips it.
	sudo func(ctx context.Context) error
}

// deputyTarget is one candidate path and the words doctor uses for it.
type deputyTarget struct {
	name string
	path string
	what string
	why  string
}

// defaultDeputyHost reads the invoking user's environment. It touches nothing:
// paths are only stat'ed and access(2)-checked, and sudo runs only as `sudo -n`.
func defaultDeputyHost(goos string) deputyHost {
	home, _ := os.UserHomeDir()
	xdgConfig := os.Getenv("XDG_CONFIG_HOME")
	if xdgConfig == "" && home != "" {
		xdgConfig = filepath.Join(home, ".config")
	}
	runtimeDir := os.Getenv("XDG_RUNTIME_DIR")
	if runtimeDir == "" && goos == "linux" {
		runtimeDir = filepath.Join("/run/user", fmt.Sprint(os.Getuid()))
	}
	var tempDirs []string
	if goos == "darwin" {
		tempDirs = append(tempDirs, "/private/tmp", os.TempDir())
		if cache, err := os.UserCacheDir(); err == nil {
			tempDirs = append(tempDirs, cache)
		}
	}
	h := deputyHost{
		home:          home,
		xdgConfigHome: xdgConfig,
		runtimeDir:    runtimeDir,
		tempWriteDirs: tempDirs,
		writable:      pathWritableByUser,
	}
	h.sockets = containerSocketTargets(goos, home, runtimeDir)
	if os.Geteuid() != 0 {
		h.sudo = passwordlessSudoProbe
	}
	return h
}

// pathWritableByUser is access(path, W_OK) for the real user.
func pathWritableByUser(path string) bool {
	return unix.Access(path, unix.W_OK) == nil
}

// passwordlessSudoProbe runs `sudo -n true` with a short timeout and no stdin.
// -n makes sudo fail at once instead of prompting, so it cannot hang on a
// password; the timeout covers a slow PAM or directory lookup. Success means
// sudo runs without a prompt right now: a NOPASSWD rule or a cached sudo login
// both count, because both are reachable at scan time. The probe runs in its
// own process group and a timeout kills the whole group, so a helper that sudo
// (or a wrapper earlier in PATH) started cannot outlive the probe.
func passwordlessSudoProbe(ctx context.Context) error {
	sudo, err := exec.LookPath("sudo")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, sudo, "-n", "true")
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		// The group id is the child's pid (Setpgid with Pgid 0).
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	cmd.WaitDelay = time.Second
	return cmd.Run()
}

const (
	whyContainerSocket = "Whoever can talk to it can start a privileged container that mounts the host."
	whyUserBus         = "It can start or change user services that run outside the fence."
)

// containerSocketTargets lists the container daemon sockets to look for.
func containerSocketTargets(goos, home, runtimeDir string) []deputyTarget {
	t := func(name, path, what string) deputyTarget {
		return deputyTarget{name: name, path: path, what: what, why: whyContainerSocket}
	}
	switch goos {
	case "linux":
		out := []deputyTarget{
			t("docker-socket", "/var/run/docker.sock", "Docker daemon socket"),
			t("docker-socket", "/run/docker.sock", "Docker daemon socket"),
			t("containerd-socket", "/run/containerd/containerd.sock", "containerd socket"),
			t("podman-socket", "/run/podman/podman.sock", "Podman socket"),
		}
		if runtimeDir != "" {
			out = append(out,
				t("docker-socket", filepath.Join(runtimeDir, "docker.sock"), "rootless Docker socket"),
				t("podman-socket", filepath.Join(runtimeDir, "podman", "podman.sock"), "rootless Podman socket"),
			)
		}
		if home != "" {
			out = append(out, t("docker-socket", filepath.Join(home, ".docker", "desktop", "docker.sock"), "Docker Desktop socket"))
		}
		return out
	case "darwin":
		out := []deputyTarget{t("docker-socket", "/var/run/docker.sock", "Docker socket")}
		if home != "" {
			out = append(out,
				t("docker-socket", filepath.Join(home, ".docker", "run", "docker.sock"), "Docker Desktop socket"),
				t("docker-socket", filepath.Join(home, "Library", "Containers", "com.docker.docker", "Data", "docker.raw.sock"), "Docker Desktop socket"),
			)
		}
		return out
	default:
		return nil
	}
}

// writableDeputyTargets lists the files and directories that become a deputy
// when the agent can write them.
func writableDeputyTargets(goos string, h deputyHost) []deputyTarget {
	var out []deputyTarget
	add := func(name, path, what, why string) {
		if path != "" {
			out = append(out, deputyTarget{name: name, path: path, what: what, why: why})
		}
	}
	const (
		whyStartup     = "Your shell runs it the next time you open a terminal, outside the fence."
		whyAgentConfig = "The agent tool loads it on its next run, outside the fence, and it can name commands to run."
		whyUnitDir     = "A unit placed here runs as you outside the fence when the service manager loads it."
	)
	if h.home != "" {
		for _, f := range []string{".bashrc", ".bash_profile", ".bash_login", ".profile", ".zshenv", ".zprofile", ".zshrc", ".zlogin"} {
			add("shell-startup", filepath.Join(h.home, f), "shell startup file", whyStartup)
		}
	}
	if h.xdgConfigHome != "" {
		add("shell-startup", filepath.Join(h.xdgConfigHome, "fish", "config.fish"), "shell startup file", whyStartup)
	}
	switch goos {
	case "linux":
		if h.xdgConfigHome != "" {
			add("systemd-user-units", filepath.Join(h.xdgConfigHome, "systemd", "user"), "systemd user unit directory", whyUnitDir)
		}
	case "darwin":
		if h.home != "" {
			add("launch-agents", filepath.Join(h.home, "Library", "LaunchAgents"), "LaunchAgents directory", whyUnitDir)
		}
	}
	agent := func(base, what string, rels ...string) {
		if base == "" {
			return
		}
		for _, rel := range rels {
			add("agent-config", filepath.Join(base, rel), what, whyAgentConfig)
		}
	}
	agent(h.home, "Claude Code user config", ".claude.json", filepath.Join(".claude", "settings.json"), filepath.Join(".claude", "hooks"))
	agent(h.home, "Codex user config", filepath.Join(".codex", "config.toml"))
	agent(h.home, "Cursor user config", filepath.Join(".cursor", "mcp.json"), filepath.Join(".cursor", "hooks.json"))
	agent(h.home, "Gemini CLI user config", filepath.Join(".gemini", "settings.json"))
	agent(h.projectRoot, "Claude Code project config", ".mcp.json", filepath.Join(".claude", "settings.json"), filepath.Join(".claude", "settings.local.json"), filepath.Join(".claude", "hooks"))
	agent(h.projectRoot, "Codex project config", filepath.Join(".codex", "config.toml"))
	agent(h.projectRoot, "Cursor project config", filepath.Join(".cursor", "mcp.json"), filepath.Join(".cursor", "hooks.json"))
	agent(h.projectRoot, "Gemini CLI project config", filepath.Join(".gemini", "settings.json"))
	return out
}

// deputyFence is what the wrapped agent's fence does to each deputy type,
// derived from the checks doctor already computed for this config and host.
type deputyFence struct {
	// writesConfined: a kernel filesystem fence (Landlock or Seatbelt) limits
	// writes to writeGrants; false means writes are not kernel-limited.
	writesConfined bool
	writeGrants    []string
	// writeDenies win over writeGrants (Seatbelt enforces them; Landlock wrap
	// refuses to start when one overlaps a grant).
	writeDenies []string
	// socketsBlocked: the fence blocks connect() to Unix sockets.
	socketsBlocked bool
	// noNewPrivs: the fenced process runs with no_new_privs, so sudo cannot
	// raise privileges.
	noNewPrivs bool
	// fsReason, socketReason and sudoReason say why a deputy is not blocked.
	fsReason, socketReason, sudoReason string
}

// doctorDeputyFence maps the fence checks onto deputy types.
func doctorDeputyFence(cfg *config.Config, caps doctorCapabilities, checks []doctorCheck, h deputyHost) deputyFence {
	byName := map[string]doctorCheck{}
	for _, c := range checks {
		if c.Group == "Fences" {
			byName[c.Name] = c
		}
	}
	f := deputyFence{}

	fsOK := byName["filesystem"].Severity == doctorOK
	switch {
	case cfg.Filesystem.Root == "":
		f.fsReason = "no filesystem fence is configured"
	case !fsOK:
		f.fsReason = "the filesystem fence cannot be enforced on this host"
	case caps.goos == "linux" && linuxEnforcementMode(cfg.Filesystem.LinuxEnforcement) == linuxEnforcementOff:
		f.fsReason = "Landlock is off by config, so only the userspace fence applies"
	case caps.goos == "linux" || caps.goos == "darwin":
		resolved, err := fsfence.ProcessConfig(cfg.Filesystem)
		if err != nil || resolved == nil {
			f.fsReason = "the filesystem fence config does not resolve"
			break
		}
		f.writesConfined = true
		if resolved.Mode == "read-write" {
			f.writeGrants = append(f.writeGrants, resolved.Root)
		}
		f.writeDenies = append(f.writeDenies, resolved.DenyPaths...)
		if caps.goos == "linux" {
			f.writeGrants = append(f.writeGrants, resolved.AllowRWPaths...)
		} else {
			f.writeGrants = append(f.writeGrants, h.tempWriteDirs...)
			f.writeDenies = append(f.writeDenies, fsfence.DefaultSensitivePaths()...)
		}
	default:
		f.fsReason = "this platform has no filesystem fence"
	}

	switch caps.goos {
	case "linux":
		f.socketsBlocked = byName["unix-sockets"].Status == "enforceable"
		f.socketReason = "Landlock Unix-socket isolation needs CONFINED egress and Landlock ABI v9"
		landlockOn := fsOK && cfg.Filesystem.Root != "" && linuxEnforcementMode(cfg.Filesystem.LinuxEnforcement) != linuxEnforcementOff
		seccompOn := byName["syscall"].Severity == doctorOK
		f.noNewPrivs = landlockOn || seccompOn
		f.sudoReason = "neither Landlock nor the syscall fence is active, so no_new_privs is not set"
	case "darwin":
		f.socketsBlocked = doctorEgressLevel(cfg, caps) == egressLevelSeatbelt
		f.socketReason = "the Seatbelt network floor is not in effect"
		f.sudoReason = "Seatbelt does not stop sudo, and the elevated process can reach system services"
	default:
		f.socketReason = "this platform has no Unix-socket fence"
		f.sudoReason = "this platform has no privilege fence"
	}
	return f
}

// writeBlocked reports whether the fence stops the agent writing p, which the
// caller has already made canonical (callers decide whether to follow a final
// symlink).
func (f deputyFence) writeBlocked(p string) bool {
	if !f.writesConfined {
		return false
	}
	for _, d := range f.writeDenies {
		if canonicalPathWithin(p, d) {
			return true
		}
	}
	for _, g := range f.writeGrants {
		if canonicalPathWithin(p, g) {
			return false
		}
	}
	return true
}

// canonicalPathWithin is pathIsWithinDir without resolving p, so a final
// symlink in p is judged by its own location rather than its target.
func canonicalPathWithin(p, dir string) bool {
	d := resolvePathBestEffort(dir)
	if d == "" || d == filepath.Dir(d) {
		return false
	}
	rel, err := filepath.Rel(d, filepath.Clean(p))
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

// fileDeputyAccess decides whether the agent can change what a file or
// directory deputy at path holds. There are two routes: write through path to
// its resolved target, or replace the entry itself through its parent
// directory (unlink a symlink or rename the file, then create a new one). A
// symlink to a target outside every write grant is therefore still reachable
// when its folder is inside one. listed reports whether this user has either
// route on the host; blocked reports whether the fence stops every route the
// user has; reason names the first open route.
func (f deputyFence) fileDeputyAccess(path string, writable func(string) bool) (listed, blocked bool, reason string) {
	if _, err := os.Lstat(path); err != nil {
		return false, false, ""
	}
	_, statErr := os.Stat(path)
	targetW := statErr == nil && writable(path)
	parent := filepath.Dir(path)
	parentW := writable(parent)
	if !targetW && !parentW {
		return false, false, ""
	}
	if !f.writesConfined {
		return true, false, f.fsReason
	}
	if targetW && !f.writeBlocked(resolvePathBestEffort(path)) {
		return true, false, "the path is inside a write grant"
	}
	// The entry itself, not where a final symlink points.
	entry := filepath.Join(resolvePathBestEffort(parent), filepath.Base(path))
	if parentW && !f.writeBlocked(entry) {
		return true, false, "its folder is inside a write grant, so the agent can replace it"
	}
	return true, true, ""
}

// deputyDoctorChecks lists each reachable deputy as a check in the Deputies
// group: ok/"blocked" when the fence stops it, warning/"reachable" when it
// does not. A reachable deputy never adds a gap; runDoctor lowers PROTECTED
// to PARTIAL instead.
func deputyDoctorChecks(cfg *config.Config, caps doctorCapabilities, checks []doctorCheck, h deputyHost) []doctorCheck {
	f := doctorDeputyFence(cfg, caps, checks, h)
	writable := h.writable
	if writable == nil {
		writable = func(string) bool { return false }
	}
	var out []doctorCheck
	seen := map[string]bool{}
	row := func(name, what, path, why string, blocked bool, reason string) {
		if path != "" {
			key := resolvePathBestEffort(path)
			if seen[key] {
				return
			}
			seen[key] = true
		}
		subject := what
		if path != "" {
			subject = fmt.Sprintf("%s %s", what, path)
		}
		if blocked {
			out = append(out, doctorOKCheck(doctorDeputyGroup, name, "blocked",
				fmt.Sprintf("%s: blocked by the fence. %s", subject, why)))
			return
		}
		out = append(out, doctorCheck{
			Group:    doctorDeputyGroup,
			Name:     name,
			Severity: doctorWarning,
			Status:   "reachable",
			Message:  fmt.Sprintf("%s: not blocked by the fence, because %s. %s", subject, reason, why),
		})
	}

	sockets := append([]deputyTarget(nil), h.sockets...)
	if caps.goos == "linux" && h.runtimeDir != "" {
		sockets = append(sockets, deputyTarget{name: "systemd-user-bus", path: filepath.Join(h.runtimeDir, "bus"), what: "systemd user bus", why: whyUserBus})
	}
	for _, s := range sockets {
		fi, err := os.Stat(s.path)
		if err != nil || fi.Mode()&os.ModeSocket == 0 || !writable(s.path) {
			continue
		}
		row(s.name, s.what, s.path, s.why, f.socketsBlocked, f.socketReason)
	}
	for _, w := range writableDeputyTargets(caps.goos, h) {
		listed, blocked, reason := f.fileDeputyAccess(w.path, writable)
		if !listed {
			continue
		}
		row(w.name, w.what, w.path, w.why, blocked, reason)
	}
	if h.sudo != nil && h.sudo(context.Background()) == nil {
		row("sudo-no-prompt", "sudo runs without a password prompt right now (a NOPASSWD rule or a cached sudo login)", "",
			"A command run through sudo acts as root.", f.noNewPrivs, f.sudoReason)
	}
	if len(out) == 0 {
		out = append(out, doctorCheck{Group: doctorDeputyGroup, Name: "deputies", Severity: doctorInfo, Status: "none-found",
			Message: "No reachable container socket, user service path, writable startup or agent config file, or sudo without a password prompt found."})
	}
	return out
}

// reachableDeputies counts deputies the fence does not block.
func reachableDeputies(checks []doctorCheck) int {
	n := 0
	for _, c := range checks {
		if c.Group == doctorDeputyGroup && c.Status == "reachable" {
			n++
		}
	}
	return n
}
