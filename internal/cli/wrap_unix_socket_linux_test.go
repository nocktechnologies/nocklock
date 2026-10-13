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

// TestWrapConfinedUnixSocketReachability exercises the N11650 probe through
// the real Linux wrapper using only throwaway pathname and abstract listeners.
// ABI 9+ must deny both external listeners while preserving the proxy and
// filesystem event sockets, including look-back enforcement. Older kernels
// must refuse unless explicitly opted in; that run proves the listeners work.
func TestWrapConfinedUnixSocketReachability(t *testing.T) {
	if !syscallfence.Supported() {
		t.Skip("seccomp-BPF is unavailable for the CONFINED egress probe")
	}
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skipf("gcc unavailable for the filesystem interposer: %v", err)
	}
	abi, err := landlock.DetectABI()
	if err != nil {
		t.Fatalf("detect Landlock ABI: %v", err)
	}
	bin, projectDir, probePath := buildUnixSocketWrapFixture(t)
	listeners, stopServers := startThrowawayUnixSocketServers(t)
	defer stopServers()
	proveThrowawaySocketControls(t, listeners)
	targetRequests := make(chan struct{}, 1)
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetRequests <- struct{}{}
		_, _ = io.WriteString(w, "unexpectedly reached test target")
	}))
	defer target.Close()
	targetURL := strings.Replace(target.URL, "127.0.0.1:", "localhost:", 1)

	runWrap := func(allowUnixSockets bool) ([]byte, error) {
		args := []string{"wrap", "--allow-private-ranges"}
		if allowUnixSockets {
			args = append(args, "--allow-unix-sockets")
		}
		args = append(args, "--", probePath, listeners.path, listeners.abstract, targetURL)
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

	if abi < landlock.MinUnixSocketABI {
		output, err := runWrap(false)
		if err == nil {
			t.Fatalf("CONFINED wrap unexpectedly ran on Landlock ABI v%d without the Unix-socket opt-in:\n%s", abi, output)
		}
		if !strings.Contains(string(output), "CONFINED egress cannot block pathname and abstract Unix sockets") {
			t.Fatalf("refusal did not explain the missing Unix-socket enforcement:\n%s", output)
		}
		output, err = runWrap(true)
		if err != nil {
			t.Fatalf("explicit --allow-unix-sockets control failed on ABI v%d: %v\n%s", abi, err, output)
		}
		if !strings.Contains(string(output), "WARNING: --allow-unix-sockets explicitly permits access") {
			t.Fatalf("explicit opt-in did not print its warning:\n%s", output)
		}
		assertSocketProbeOutput(t, output, "path=CONNECTED", "abstract=CONNECTED", "event=CONNECTED", "proxy=CONNECTED", "lookback=403", "inet=DENIED")
	} else {
		output, err := runWrap(false)
		if err != nil {
			t.Fatalf("CONFINED wrap failed on Landlock ABI v%d: %v\n%s", abi, err, output)
		}
		assertSocketProbeOutput(t, output, "path=DENIED", "abstract=DENIED", "event=CONNECTED", "proxy=CONNECTED", "lookback=403", "inet=DENIED")
		if !strings.Contains(string(output), "Unix-socket isolation active") {
			t.Fatalf("wrap did not report Unix-socket isolation:\n%s", output)
		}
		configPath := filepath.Join(projectDir, ".nock", "config.toml")
		configBytes, err := os.ReadFile(configPath)
		if err != nil {
			t.Fatalf("read fixture config: %v", err)
		}
		configOff := strings.Replace(string(configBytes), `linux_enforcement = "preferred"`, `linux_enforcement = "off"`, 1)
		if configOff == string(configBytes) {
			t.Fatal("fixture config did not set preferred Linux enforcement")
		}
		if err := os.WriteFile(configPath, []byte(configOff), 0o600); err != nil {
			t.Fatalf("disable filesystem Landlock in fixture: %v", err)
		}
		output, err = runWrap(false)
		if err != nil {
			t.Fatalf("socket-only CONFINED wrap failed on Landlock ABI v%d: %v\n%s", abi, err, output)
		}
		assertSocketProbeOutput(t, output, "path=DENIED", "abstract=DENIED", "event=CONNECTED", "proxy=CONNECTED", "lookback=403", "inet=DENIED")
		if !strings.Contains(string(output), "Unix-socket isolation active") {
			t.Fatalf("socket-only wrap did not report Unix-socket isolation:\n%s", output)
		}
	}
	select {
	case <-targetRequests:
		t.Fatal("proxy forwarded a request to the throwaway target after a filesystem look-back trigger")
	default:
	}

	accepted := stopServers()
	if abi < landlock.MinUnixSocketABI {
		for _, record := range []string{"path:probe-path", "abstract:probe-abstract"} {
			if !accepted[record] {
				t.Errorf("negative control listener did not receive %q: %v", record, accepted)
			}
		}
	} else if accepted["path:probe-path"] || accepted["abstract:probe-abstract"] {
		t.Fatalf("Landlock allowed an external socket payload: %v", accepted)
	}
	assertUnixSocketProbeAuditEvents(t, projectDir, abi < landlock.MinUnixSocketABI)
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

func buildUnixSocketWrapFixture(t *testing.T) (bin, projectDir, probePath string) {
	t.Helper()
	testDir := t.TempDir()
	projectDir = filepath.Join(testDir, "project")
	binDir := filepath.Join(testDir, "bin")
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

func assertUnixSocketProbeAuditEvents(t *testing.T, projectDir string, expectFallback bool) {
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
	refusalRecorded := false
	optInRecorded := false
	fileTriggerRecorded := false
	lookbackDenied := false
	for _, event := range events {
		if event.EventType == logging.EventNetworkError && event.Blocked && strings.Contains(event.Detail, "CONFINED egress cannot block pathname and abstract Unix sockets") {
			refusalRecorded = true
		}
		if event.EventType == logging.EventNetworkPassed && !event.Blocked && strings.Contains(event.Detail, "--allow-unix-sockets explicitly permits access") {
			optInRecorded = true
		}
		if event.EventType == logging.EventFileBlocked && event.Blocked && strings.Contains(event.Detail, "/n11660-outside") {
			fileTriggerRecorded = true
		}
		if event.EventType == logging.EventNetworkBlocked && event.Blocked && strings.Contains(event.Detail, "rule=lookback:socket-probe trigger=") {
			lookbackDenied = true
		}
	}
	if !fileTriggerRecorded || !lookbackDenied {
		t.Fatalf("filesystem event socket did not trigger and audit look-back enforcement; file trigger=%t look-back denial=%t events=%+v", fileTriggerRecorded, lookbackDenied, events)
	}
	if expectFallback && (!refusalRecorded || !optInRecorded) {
		t.Fatalf("unsupported-kernel refusal and explicit opt-in must both be audited; refusal=%t opt-in=%t events=%+v", refusalRecorded, optInRecorded, events)
	}
}
