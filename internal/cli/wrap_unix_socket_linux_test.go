//go:build linux

package cli

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/fence/fs/landlock"
	"github.com/nocktechnologies/nocklock/internal/fence/syscallfence"
	"github.com/nocktechnologies/nocklock/internal/logging"
)

const confinedUnixSocketProbe = `package main

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"io"
	"os"
	"strings"
	"syscall"
	"time"
)

func dialAndSend(address, payload string) bool {
	conn, err := net.Dial("unix", address)
	if err != nil {
		return false
	}
	_, _ = conn.Write([]byte(payload))
	_ = conn.Close()
	return true
}

func reportBlockedFile() bool {
	fields := strings.Split(os.Getenv("NOCKLOCK_FS_ALLOWED"), "\x1f")
	if len(fields) < 3 {
		return false
	}
	conn, err := net.Dial("unix", fields[2])
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintln(conn, "{\"type\":\"file\",\"action\":\"blocked\",\"path\":\"/n11660-outside\",\"operation\":\"open\",\"reason\":\"socket-probe\"}"); err != nil {
		return false
	}
	ack := []byte{0}
	if _, err := io.ReadFull(conn, ack); err != nil {
		return false
	}
	return ack[0] == 1
}

func proxyGet(proxySocket, targetURL string) int {
	target, err := url.Parse(targetURL)
	if err != nil {
		return 0
	}
	conn, err := net.Dial("unix", proxySocket)
	if err != nil {
		return 0
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", targetURL, target.Host); err != nil {
		return 0
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return 0
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

func main() {
	pathConnected := dialAndSend(os.Args[1], "probe-path")
	abstractConnected := dialAndSend("@"+os.Args[2], "probe-abstract")
	eventAcked := reportBlockedFile()
	proxyStatus := proxyGet(os.Getenv("NOCKLOCK_PROXY_UNIX_SOCKET"), os.Args[3])
	fd, inetErr := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if inetErr == nil {
		_ = syscall.Close(fd)
	}
	inetState := "ERROR"
	if inetErr == nil {
		inetState = "CONNECTED"
	} else if inetErr == syscall.EPERM {
		inetState = "DENIED"
	}
	fmt.Printf("path=%s abstract=%s event=%s proxy=%s lookback=%d inet=%s\n", state(pathConnected), state(abstractConnected), state(eventAcked), state(proxyStatus != 0), proxyStatus, inetState)
}

func state(connected bool) string {
	if connected {
		return "CONNECTED"
	}
	return "DENIED"
}
`

// TestWrapUnixSocketReachability exercises the real Linux wrapper with
// throwaway pathname and abstract listeners. Below ABI 9, default wrap must run
// with a signed reachable-socket boundary; ABI 9+ must block both listeners.
func TestWrapUnixSocketReachability(t *testing.T) {
	if !syscallfence.Supported() {
		t.Skip("seccomp-BPF is unavailable for the CONFINED egress probe")
	}
	moduleCache, err := exec.Command("go", "env", "GOMODCACHE").Output()
	if err != nil {
		t.Fatalf("locate Go module cache before isolating HOME: %v", err)
	}
	t.Setenv("GOMODCACHE", strings.TrimSpace(string(moduleCache)))
	// A library under /tmp is intentionally refused, even in a private child
	// directory. Keep only the disposable executable pair under the real home.
	trustedHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	binDir, err := os.MkdirTemp(trustedHome, ".nocklock-socket-probe-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(binDir) })
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(home, ".config"))
	t.Setenv("XDG_STATE_HOME", trustedStateRoot(t))
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skipf("gcc unavailable for the filesystem interposer: %v", err)
	}
	abi, abiErr := landlock.DetectABI()
	_, boundaryReason := unixSocketBoundaryStatus(abi, abiErr)
	bin, projectDir, probePath := buildUnixSocketWrapFixture(t, binDir)
	listeners, stopServers := startThrowawayUnixSocketServers(t)
	defer stopServers()
	proveThrowawaySocketControls(t, listeners)
	var targetRequests atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetRequests.Add(1)
		_, _ = io.WriteString(w, "unexpectedly reached test target")
	}))
	defer target.Close()
	targetURL := strings.Replace(target.URL, "127.0.0.1:", "localhost:", 1)
	configPath := filepath.Join(projectDir, ".nock", "config.toml")
	baseConfig, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("read fixture config: %v", err)
	}
	var probeRan, reachableSubtestRan, strictRefusalSubtestRan bool

	runWrap := func(t *testing.T, linuxEnforcement string, requireUnixSocketIsolation bool) ([]byte, error) {
		t.Helper()
		configText := strings.Replace(string(baseConfig), "linux_enforcement = \"preferred\"", fmt.Sprintf("linux_enforcement = %q", linuxEnforcement), 1)
		configText = strings.Replace(configText, "require_unix_socket_isolation = false", fmt.Sprintf("require_unix_socket_isolation = %t", requireUnixSocketIsolation), 1)
		if !strings.Contains(configText, "require_unix_socket_isolation = ") {
			t.Fatal("fixture config is missing the strict Unix-socket setting")
		}
		if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
			t.Fatalf("write fixture config: %v", err)
		}
		args := []string{"wrap", "--allow-private-ranges", "--", probePath, listeners.path, listeners.abstract, targetURL}
		cmd := exec.Command(bin, args...)
		cmd.Dir = projectDir
		for _, entry := range os.Environ() {
			if !strings.HasPrefix(entry, "XDG_RUNTIME_DIR=") {
				cmd.Env = append(cmd.Env, entry)
			}
		}
		cmd.Env = append(cmd.Env, "XDG_RUNTIME_DIR=/tmp")
		return cmd.CombinedOutput()
	}

	t.Run("default below ABI 9 runs and records reachability", func(t *testing.T) {
		if abi >= landlock.MinUnixSocketABI {
			t.Skipf("not run: Landlock ABI %d >= 9", abi)
		}
		probeRan = true
		reachableSubtestRan = true
		output, err := runWrap(t, "preferred", false)
		if err != nil {
			t.Fatalf("default CONFINED wrap failed on Landlock ABI v%d: %v\n%s", abi, err, output)
		}
		if !strings.Contains(string(output), "NockLock: WARNING:") || !strings.Contains(string(output), "reason="+boundaryReason) {
			t.Fatalf("default reachable-socket warning is missing its ABI reason:\n%s", output)
		}
		if got := strings.Count(string(output), "NockLock: WARNING:"); got != 1 {
			t.Fatalf("default reachable-socket posture printed %d warning lines, want exactly one:\n%s", got, output)
		}
		assertSocketProbeOutput(t, output, "path=CONNECTED", "abstract=CONNECTED", "event=CONNECTED", "proxy=CONNECTED", "lookback=403", "inet=DENIED")
		assertReachableUnixSocketAudit(t, bin, projectDir, boundaryReason)
	})

	t.Run("strict config refuses below ABI 9", func(t *testing.T) {
		if abi >= landlock.MinUnixSocketABI {
			t.Skipf("not run: Landlock ABI %d >= 9", abi)
		}
		strictRefusalSubtestRan = true
		output, err := runWrap(t, "preferred", true)
		if err == nil {
			t.Fatalf("strict CONFINED wrap ran on Landlock ABI v%d:\n%s", abi, output)
		}
		if !strings.Contains(string(output), "CONFINED egress cannot block pathname and abstract Unix sockets") ||
			!strings.Contains(string(output), "network.require_unix_socket_isolation is true") {
			t.Fatalf("strict refusal did not explain the unavailable boundary:\n%s", output)
		}
	})

	t.Run("Landlock ABI 9 enforcement with filesystem rules", func(t *testing.T) {
		if abi < landlock.MinUnixSocketABI {
			t.Skipf("not run: Landlock ABI %d < 9", abi)
		}
		probeRan = true
		output, err := runWrap(t, "preferred", false)
		// bench/redteam/kernel_cases.py reads this line into its receipt, so
		// log it before any failure.
		for _, line := range strings.Split(string(output), "\n") {
			if strings.HasPrefix(line, "path=") {
				t.Logf("ABI9_WRAP_PROBE %s", line)
			}
		}
		if err != nil {
			t.Fatalf("CONFINED wrap failed on Landlock ABI v%d: %v\n%s", abi, err, output)
		}
		assertSocketProbeOutput(t, output, "path=DENIED", "abstract=DENIED", "event=CONNECTED", "proxy=CONNECTED", "lookback=403", "inet=DENIED", "Unix-socket isolation active")
	})

	t.Run("Landlock ABI 9 synthesized socket-only spec is applied", func(t *testing.T) {
		if abi < landlock.MinUnixSocketABI {
			t.Skipf("not run: Landlock ABI %d < 9", abi)
		}
		probeRan = true
		output, err := runWrap(t, "off", false)
		if err != nil {
			t.Fatalf("socket-only CONFINED wrap failed on Landlock ABI v%d: %v\n%s", abi, err, output)
		}
		assertSocketProbeOutput(t, output, "path=DENIED", "abstract=DENIED", "event=CONNECTED", "proxy=CONNECTED", "lookback=403", "inet=DENIED", "Unix-socket isolation active")
	})

	if got := targetRequests.Load(); got != 0 {
		t.Fatalf("proxy forwarded %d request(s) to the throwaway target after a filesystem look-back trigger", got)
	}

	accepted := stopServers()
	if probeRan && abi < landlock.MinUnixSocketABI {
		for _, record := range []string{"path:probe-path", "abstract:probe-abstract"} {
			if !accepted[record] {
				t.Errorf("below-ABI negative control listener did not receive %q: %v", record, accepted)
			}
		}
	} else if probeRan && (accepted["path:probe-path"] || accepted["abstract:probe-abstract"]) {
		t.Fatalf("Landlock allowed an external socket payload: %v", accepted)
	}
	if probeRan || strictRefusalSubtestRan {
		assertUnixSocketProbeAuditEvents(t, projectDir, boundaryReason, probeRan, reachableSubtestRan, strictRefusalSubtestRan)
	}
}

func assertReachableUnixSocketAudit(t *testing.T, bin, projectDir, boundaryReason string) {
	t.Helper()
	configPath := filepath.Join(projectDir, ".nock", "config.toml")
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load fixture config for reachable-socket audit check: %v", err)
	}
	dbPath, root, err := config.ResolveDBPath(cfg, configPath)
	if err != nil {
		t.Fatalf("resolve fixture audit log: %v", err)
	}
	logger, err := logging.NewLogger(dbPath, root)
	if err != nil {
		t.Fatalf("open fixture audit log: %v", err)
	}
	eventType := logging.EventSessionStart
	events, err := logger.Query(logging.QueryOptions{EventType: &eventType, Limit: 1000})
	if err != nil {
		logger.Close()
		t.Fatalf("query session-start audit rows: %v", err)
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("close fixture audit log: %v", err)
	}
	reason := fmt.Sprintf("unix_sockets=reachable reason=%s", boundaryReason)
	found := false
	for _, event := range events {
		if event.EgressLevel == string(egressLevelConfined) && strings.Contains(event.Detail, reason) {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("signed CONFINED session-start row missing %q; rows: %+v", reason, events)
	}
	verify := exec.Command(bin, "verify", "--audit")
	verify.Dir = projectDir
	verify.Env = os.Environ()
	output, err := verify.CombinedOutput()
	if err != nil {
		t.Fatalf("nocklock verify --audit failed after reachable-socket wrap: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "AUDIT: AUTHENTIC") {
		t.Fatalf("nocklock verify --audit did not authenticate the reachable-socket row:\n%s", output)
	}
}

type throwawaySocketListeners struct {
	path     string
	abstract string
	all      []net.Listener
}

func startThrowawayUnixSocketServers(t *testing.T) (throwawaySocketListeners, func() map[string]bool) {
	t.Helper()
	id := fmt.Sprintf("n11660-%d-%d", os.Getpid(), time.Now().UnixNano())
	servers := throwawaySocketListeners{
		path:     filepath.Join(os.TempDir(), id+".sock"),
		abstract: id,
	}
	for _, socket := range []struct{ label, address string }{
		{"path", servers.path},
		{"abstract", "@" + servers.abstract},
	} {
		listener, err := net.Listen("unix", socket.address)
		if err != nil {
			t.Fatalf("listen on throwaway %s socket: %v", socket.label, err)
		}
		servers.all = append(servers.all, listener)
	}
	observed := make(chan string, 8)
	var acceptors sync.WaitGroup
	for i, listener := range servers.all {
		name := []string{"path", "abstract"}[i]
		acceptors.Add(1)
		go func() {
			defer acceptors.Done()
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				payload, _ := io.ReadAll(conn)
				_ = conn.Close()
				observed <- name + ":" + string(payload)
			}
		}()
	}
	stopped := false
	var accepted map[string]bool
	stop := func() map[string]bool {
		if stopped {
			return accepted
		}
		stopped = true
		for _, listener := range servers.all {
			_ = listener.Close()
		}
		acceptors.Wait()
		close(observed)
		accepted = make(map[string]bool)
		for record := range observed {
			accepted[record] = true
		}
		return accepted
	}
	return servers, stop
}

func proveThrowawaySocketControls(t *testing.T, servers throwawaySocketListeners) {
	t.Helper()
	for _, target := range []struct {
		name    string
		address string
	}{
		{"pathname", servers.path},
		{"abstract", "@" + servers.abstract},
	} {
		conn, err := net.Dial("unix", target.address)
		if err != nil {
			t.Fatalf("negative control could not connect to throwaway %s socket: %v", target.name, err)
		}
		if _, err := conn.Write([]byte("control-" + target.name)); err != nil {
			t.Fatalf("negative control could not write to throwaway %s socket: %v", target.name, err)
		}
		_ = conn.Close()
	}
}

func buildUnixSocketWrapFixture(t *testing.T, binDir string) (bin, projectDir, probePath string) {
	t.Helper()
	testDir := t.TempDir()
	projectDir = filepath.Join(testDir, "project")
	if err := os.MkdirAll(filepath.Join(projectDir, ".nock"), 0o700); err != nil {
		t.Fatalf("create fixture project: %v", err)
	}
	if err := os.MkdirAll(binDir, 0o700); err != nil {
		t.Fatalf("create fixture bin directory: %v", err)
	}
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	moduleRoot := filepath.Clean(filepath.Join(filepath.Dir(source), "..", ".."))
	bin = filepath.Join(binDir, "nocklock")
	build := exec.Command("go", "build", "-o", bin, "./cmd/nocklock")
	build.Dir = moduleRoot
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build nocklock test fixture: %v\n%s", err, output)
	}
	interposer := filepath.Join(moduleRoot, "internal", "fence", "fs", "interposer", "libfence_fs.c")
	sharedLib := filepath.Join(binDir, "libfence_fs.so")
	buildLib := exec.Command("gcc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror", "-o", sharedLib, interposer, "-ldl", "-lpthread")
	if output, err := buildLib.CombinedOutput(); err != nil {
		t.Fatalf("build filesystem interposer fixture: %v\n%s", err, output)
	}
	probeSource := filepath.Join(projectDir, "probe.go")
	probePath = filepath.Join(projectDir, "probe")
	if err := os.WriteFile(probeSource, []byte(confinedUnixSocketProbe), 0o600); err != nil {
		t.Fatalf("write Unix-socket probe source: %v", err)
	}
	probeBuild := exec.Command("go", "build", "-o", probePath, probeSource)
	probeBuild.Dir = moduleRoot
	probeBuild.Env = append(os.Environ(), "CGO_ENABLED=0")
	if output, err := probeBuild.CombinedOutput(); err != nil {
		t.Fatalf("build static Unix-socket probe: %v\n%s", err, output)
	}
	config := fmt.Sprintf(`[project]
name = "n11660-unix-socket-probe"

[filesystem]
root = %q
mode = "read-write"
linux_enforcement = "preferred"
allow = []
deny = []

[network]
allow = ["localhost"]
allow_all = false
allow_private_ranges = true
require_unix_socket_isolation = false

[[network.lookback]]
name = "socket-probe"
on = "file_blocked"
then = "deny_egress"

[syscall]
enforcement = "required"
`, projectDir)
	if err := os.WriteFile(filepath.Join(projectDir, ".nock", "config.toml"), []byte(config), 0o600); err != nil {
		t.Fatalf("write fixture config: %v", err)
	}
	return bin, projectDir, probePath
}

func assertSocketProbeOutput(t *testing.T, output []byte, expected ...string) {
	t.Helper()
	for _, value := range expected {
		if !strings.Contains(string(output), value) {
			t.Errorf("probe output missing %q:\n%s", value, output)
		}
	}
}

func assertUnixSocketProbeAuditEvents(t *testing.T, projectDir, boundaryReason string, probeRan, reachableSubtestRan, strictRefusalSubtestRan bool) {
	t.Helper()
	configPath := filepath.Join(projectDir, ".nock", "config.toml")
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load fixture config for audit check: %v", err)
	}
	dbPath, root, err := config.ResolveDBPath(cfg, configPath)
	if err != nil {
		t.Fatalf("resolve fixture audit log: %v", err)
	}
	logger, err := logging.NewLogger(dbPath, root)
	if err != nil {
		t.Fatalf("open fixture audit log: %v", err)
	}
	defer logger.Close()
	events, err := logger.Query(logging.QueryOptions{Limit: 1000})
	if err != nil {
		t.Fatalf("query fixture audit log: %v", err)
	}
	fileTriggerRecorded := false
	lookbackDenied := false
	reachableSessionRecorded := false
	strictRefusalRecorded := false
	reason := fmt.Sprintf("unix_sockets=reachable reason=%s", boundaryReason)
	for _, event := range events {
		if event.EventType == logging.EventFileBlocked && event.Blocked && strings.Contains(event.Detail, "/n11660-outside") {
			fileTriggerRecorded = true
		}
		if event.EventType == logging.EventNetworkBlocked && event.Blocked && strings.Contains(event.Detail, "rule=lookback:socket-probe trigger=") {
			lookbackDenied = true
		}
		if event.EventType == logging.EventSessionStart && event.EgressLevel == "CONFINED" && strings.Contains(event.Detail, reason) {
			reachableSessionRecorded = true
		}
		if event.EventType == logging.EventNetworkError && event.Blocked && strings.Contains(event.Detail, "network.require_unix_socket_isolation is true") {
			strictRefusalRecorded = true
		}
	}
	if probeRan && (!fileTriggerRecorded || !lookbackDenied) {
		t.Fatalf("filesystem event socket did not trigger and audit look-back enforcement; file trigger=%t look-back denial=%t events=%+v", fileTriggerRecorded, lookbackDenied, events)
	}
	if reachableSubtestRan && !reachableSessionRecorded {
		t.Fatalf("below-ABI session-start reachability row must be audited; reachable=%t events=%+v", reachableSessionRecorded, events)
	}
	if strictRefusalSubtestRan && !strictRefusalRecorded {
		t.Fatalf("strict below-ABI refusal must be audited; strict refusal=%t events=%+v", strictRefusalRecorded, events)
	}
	verified, err := logger.VerifyChain()
	if err != nil || !verified.Intact || verified.SignedEntries == 0 {
		t.Fatalf("Unix-socket posture rows are not in an intact signed audit chain: result=%+v err=%v", verified, err)
	}
}
