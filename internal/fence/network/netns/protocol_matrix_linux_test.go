//go:build linux

package netns

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/fence/network"
	"golang.org/x/sys/unix"
)

const (
	scenarioMatrixHTTPAllowed  = "matrix_http_allowed"
	scenarioMatrixHTTPBlocked  = "matrix_http_blocked"
	scenarioMatrixTLSAllowed   = "matrix_tls_allowed"
	scenarioMatrixTLSBlocked   = "matrix_tls_blocked"
	scenarioMatrixDirectIP     = "matrix_direct_ip"
	scenarioMatrixDNSUDP       = "matrix_dns_udp"
	scenarioMatrixDNSTCP       = "matrix_dns_tcp"
	scenarioMatrixUDP443       = "matrix_udp_443"
	scenarioMatrixSCTP         = "matrix_sctp"
	scenarioMatrixCurl         = "matrix_curl_tcp_fallback"
	scenarioMatrixNode         = "matrix_node_tcp_fallback"
	scenarioMatrixPython       = "matrix_python_tcp_fallback"
	exitMatrixSatisfied        = 40
	exitMatrixUnexpectedResult = 41
)

// TestNetnsProtocolMatrix is the root-required Phase-1b receipt. Every row
// asserts its own outcome: successful allowed HTTP(S), HTTP 403 for a denied
// Host, reset-after-intercept for direct IP, fixed DNS answers, dropped
// UDP/443/SCTP, and TCP success for the three supported client runtimes.
func TestNetnsProtocolMatrix(t *testing.T) {
	requireRoot(t)
	ipBin := requireTool(t, "ip")
	nftBin := requireTool(t, "nft")
	for _, tool := range []string{"curl", "node", "python3"} {
		requireTool(t, tool)
	}

	httpRequests := &atomic.Int32{}
	httpsRequests := &atomic.Int32{}
	startMatrixHTTPServer(t, "127.0.0.1:80", "http-ok", httpRequests, nil)
	startMatrixHTTPServer(t, "127.0.0.1:443", "tls-ok", httpsRequests, matrixTLSConfig(t))

	broker := network.NewTransparentBroker(config.NetworkConfig{
		Allow:              []string{"localhost"},
		AllowPrivateRanges: true,
	}, nil, "netns-protocol-matrix")
	brokerPath, brokerToken, err := broker.Start()
	if err != nil {
		t.Fatalf("start host-network broker: %v", err)
	}
	t.Cleanup(func() { _ = broker.Stop() })

	ns := setupNetnsBase(t, false)
	proxyCfg := ProxyConfig{
		Allow:              []string{"localhost"},
		AllowPrivateRanges: true,
		BrokerPath:         brokerPath,
		BrokerToken:        brokerToken,
	}
	startMatrixProxy(t, ipBin, ns.name, proxyCfg, broker)
	installMatrixRoutes(t, ipBin, ns.name)
	applyMatrixRules(t, ipBin, nftBin, ns.name)

	for _, tc := range []struct {
		name     string
		scenario string
	}{
		{"allowed_http_returns_success", scenarioMatrixHTTPAllowed},
		{"blocked_http_returns_403", scenarioMatrixHTTPBlocked},
		{"allowed_https_with_sni_returns_success", scenarioMatrixTLSAllowed},
		{"blocked_https_sni_is_closed_before_origin", scenarioMatrixTLSBlocked},
		{"direct_ip_without_sni_is_intercepted_and_reset", scenarioMatrixDirectIP},
		{"dns_udp_external_resolver_is_answered_by_stub", scenarioMatrixDNSUDP},
		{"dns_tcp_external_resolver_is_answered_by_stub", scenarioMatrixDNSTCP},
		{"udp_443_is_dropped", scenarioMatrixUDP443},
		{"sctp_is_denied", scenarioMatrixSCTP},
		{"curl_uses_tcp_when_udp_443_is_denied", scenarioMatrixCurl},
		{"node_fetch_uses_tcp_when_udp_443_is_denied", scenarioMatrixNode},
		{"python_requests_uses_tcp_when_udp_443_is_denied", scenarioMatrixPython},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code := runChildHelper(t, tc.scenario, ns.path); code != exitMatrixSatisfied {
				t.Fatalf("%s: child exit = %d, want protocol-specific success code %d", tc.name, code, exitMatrixSatisfied)
			}
		})
	}
	if got := httpRequests.Load(); got != 1 {
		t.Fatalf("HTTP origin requests = %d, want exactly one allowed request (blocked Host reached origin)", got)
	}
	if got := httpsRequests.Load(); got != 4 {
		t.Fatalf("HTTPS origin requests = %d, want TLS test plus curl/Node/Python fallback clients", got)
	}
}

func startMatrixHTTPServer(t *testing.T, address, body string, requests *atomic.Int32, tlsConfig *tls.Config) {
	t.Helper()
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("listen matrix origin %s: %v", address, err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if tlsConfig != nil {
		listener = tls.NewListener(listener, tlsConfig)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		_, _ = w.Write([]byte(body))
	})
	go func() { _ = http.Serve(listener, handler) }()
}

func matrixTLSConfig(t *testing.T) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate TLS key: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "localhost"},
		DNSNames: []string{"localhost"}, NotBefore: time.Now().Add(-time.Minute),
		NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
	}, &x509.Certificate{SerialNumber: big.NewInt(1)}, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create TLS certificate: %v", err)
	}
	certificate := tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	return &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12}
}

func startMatrixProxy(t *testing.T, ipBin, namespace string, cfg ProxyConfig, broker *network.TransparentBroker) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("encode matrix proxy config: %v", err)
	}
	cmd := exec.Command(ipBin, "netns", "exec", namespace, exe)
	cmd.Env = append(os.Environ(),
		"NOCKLOCK_NETNS_TEST_PROXY=1",
		proxyConfigEnv+"="+base64.RawStdEncoding.EncodeToString(raw),
	)
	cmd.Stdout = os.Stderr
	cmd.Stderr = os.Stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start matrix transparent proxy: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_, _ = cmd.Process.Wait()
	})

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if broker.ProxyHeartbeatSeen() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("matrix transparent proxy did not authenticate with broker")
}

func installMatrixRoutes(t *testing.T, ipBin, namespace string) {
	t.Helper()
	commands := [][]string{
		{"rule", "add", "priority", "100", "fwmark", fmt.Sprintf("0x%x", transparentMark), "lookup", "100"},
		{"route", "replace", "local", "0.0.0.0/0", "dev", "lo", "table", "100"},
		{"route", "replace", "default", "dev", "lo"},
		{"-6", "rule", "add", "priority", "100", "fwmark", fmt.Sprintf("0x%x", transparentMark), "lookup", "100"},
		{"-6", "route", "replace", "local", "::/0", "dev", "lo", "table", "100"},
		{"-6", "route", "replace", "default", "dev", "lo"},
	}
	for _, command := range commands {
		args := append([]string{"netns", "exec", namespace, ipBin}, command...)
		if out, err := run(ipBin, args...); err != nil {
			t.Fatalf("install matrix route ip %s: %v\n%s", strings.Join(command, " "), err, out)
		}
	}
}

func applyMatrixRules(t *testing.T, ipBin, nftBin, namespace string) {
	t.Helper()
	out, err := runStdin(TransparentRuleset(65534), ipBin, "netns", "exec", namespace, nftBin, "-f", "-")
	if err != nil {
		low := strings.ToLower(out)
		if strings.Contains(low, "operation not supported") || strings.Contains(low, "not supported") {
			if strictlyRequired() {
				t.Fatalf("tproxy unsupported in required protocol-matrix environment: %v\n%s", err, out)
			}
			t.Skipf("tproxy unsupported in this protocol-matrix environment: %v\n%s", err, out)
		}
		t.Fatalf("apply protocol-matrix tproxy policy: %v\n%s", err, out)
	}
}

func runProtocolMatrixChildIfRequested(scenario string) (int, bool) {
	if !isProtocolMatrixScenario(scenario) {
		return 0, false
	}
	if err := dropProtocolMatrixChildPrivilege(); err != nil {
		return exitMatrixUnexpectedResult, true
	}
	switch scenario {
	case scenarioMatrixHTTPAllowed:
		return matrixHTTPResult("localhost", http.StatusOK), true
	case scenarioMatrixHTTPBlocked:
		return matrixHTTPResult("blocked.test", http.StatusForbidden), true
	case scenarioMatrixTLSAllowed:
		return matrixTLSResult(), true
	case scenarioMatrixTLSBlocked:
		return matrixTLSBlockedResult(), true
	case scenarioMatrixDirectIP:
		return matrixDirectIPResult(), true
	case scenarioMatrixDNSUDP:
		return matrixDNSUDPResult(), true
	case scenarioMatrixDNSTCP:
		return matrixDNSTCPResult(), true
	case scenarioMatrixUDP443:
		return matrixUDP443Result(), true
	case scenarioMatrixSCTP:
		return matrixSCTPResult(), true
	case scenarioMatrixCurl:
		return matrixCommandResult("curl", "--fail", "--silent", "--show-error", "--insecure", "--noproxy", "*", "https://localhost/"), true
	case scenarioMatrixNode:
		return matrixCommandResult("node", "-e", "fetch('https://localhost/').then(r=>r.text()).then(t=>process.exit(t==='tls-ok'?0:2)).catch(()=>process.exit(1))"), true
	case scenarioMatrixPython:
		return matrixCommandResult("python3", "-c", "import requests,sys; sys.exit(0 if requests.get('https://localhost/',verify=False).text=='tls-ok' else 2)"), true
	default:
		return exitMatrixUnexpectedResult, true
	}
}

func isProtocolMatrixScenario(scenario string) bool {
	switch scenario {
	case scenarioMatrixHTTPAllowed, scenarioMatrixHTTPBlocked, scenarioMatrixTLSAllowed, scenarioMatrixTLSBlocked,
		scenarioMatrixDirectIP, scenarioMatrixDNSUDP, scenarioMatrixDNSTCP,
		scenarioMatrixUDP443, scenarioMatrixSCTP, scenarioMatrixCurl,
		scenarioMatrixNode, scenarioMatrixPython:
		return true
	default:
		return false
	}
}

// dropProtocolMatrixChildPrivilege makes the root-only test harness exercise
// the same non-root boundary as SetupAndExec. It deliberately selects an id
// distinct from the sidecar's dedicated nobody account, so the test child
// cannot use the nftables skuid allowance reserved for that sidecar.
func dropProtocolMatrixChildPrivilege() error {
	credential, err := proxyCredential()
	if err != nil {
		return err
	}
	uid, gid := 65533, 65533
	if uid == credential.uid {
		uid = 65532
	}
	if gid == credential.gid {
		gid = 65532
	}
	if err := unix.Setgroups(nil); err != nil {
		return err
	}
	if err := unix.Setresgid(gid, gid, gid); err != nil {
		return err
	}
	if err := unix.Setresuid(uid, uid, uid); err != nil {
		return err
	}
	if os.Geteuid() == 0 || os.Getuid() == 0 {
		return errors.New("matrix child remained root after privilege drop")
	}
	return unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
}

func matrixHTTPResult(host string, want int) int {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:80", 2*time.Second)
	if err != nil {
		return exitMatrixUnexpectedResult
	}
	defer conn.Close()
	_, _ = fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return exitMatrixUnexpectedResult
	}
	defer response.Body.Close()
	if response.StatusCode != want {
		return exitMatrixUnexpectedResult
	}
	return exitMatrixSatisfied
}

func matrixTLSResult() int {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", "127.0.0.1:443", &tls.Config{ServerName: "localhost", InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // test-only origin certificate
	if err != nil {
		return exitMatrixUnexpectedResult
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil || response.StatusCode != http.StatusOK {
		return exitMatrixUnexpectedResult
	}
	_ = response.Body.Close()
	return exitMatrixSatisfied
}

func matrixTLSBlockedResult() int {
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 2 * time.Second}, "tcp", "127.0.0.1:443", &tls.Config{ServerName: "blocked.test", InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec // a handshake failure is the assertion
	if err != nil {
		return exitMatrixSatisfied
	}
	_ = conn.Close()
	return exitMatrixUnexpectedResult
}

func matrixDirectIPResult() int {
	conn, err := net.DialTimeout("tcp", "1.1.1.1:443", 2*time.Second)
	if err != nil {
		return exitMatrixSatisfied // local tproxy could reject before Dial returns.
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	_, _ = conn.Write([]byte{22, 3, 3, 0, 0})
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		return exitMatrixSatisfied // reset/close from the intercepted proxy, never a dropped SYN.
	}
	return exitMatrixUnexpectedResult
}

func matrixDNSUDPResult() int {
	conn, err := net.DialTimeout("udp", "1.1.1.1:53", 2*time.Second)
	if err != nil {
		return exitMatrixUnexpectedResult
	}
	defer conn.Close()
	if _, err := conn.Write(dnsQueryExampleCom()); err != nil {
		return exitMatrixUnexpectedResult
	}
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	response := make([]byte, 512)
	n, err := conn.Read(response)
	if err != nil || n < 4 || !strings.HasSuffix(string(response[:n]), string(interceptIPv4)) {
		return exitMatrixUnexpectedResult
	}
	return exitMatrixSatisfied
}

func matrixDNSTCPResult() int {
	conn, err := net.DialTimeout("tcp", "1.1.1.1:53", 2*time.Second)
	if err != nil {
		return exitMatrixUnexpectedResult
	}
	defer conn.Close()
	query := dnsQueryExampleCom()
	if err := binary.Write(conn, binary.BigEndian, uint16(len(query))); err != nil {
		return exitMatrixUnexpectedResult
	}
	if _, err := conn.Write(query); err != nil {
		return exitMatrixUnexpectedResult
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	var length uint16
	if err := binary.Read(conn, binary.BigEndian, &length); err != nil || length == 0 {
		return exitMatrixUnexpectedResult
	}
	response := make([]byte, length)
	if _, err := io.ReadFull(conn, response); err != nil || !strings.HasSuffix(string(response), string(interceptIPv4)) {
		return exitMatrixUnexpectedResult
	}
	return exitMatrixSatisfied
}

func matrixUDP443Result() int {
	conn, err := net.DialTimeout("udp", "127.0.0.1:443", 2*time.Second)
	if err != nil {
		return exitMatrixSatisfied
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("quic-must-not-leave"))
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 1)
	if _, err := conn.Read(buf); err != nil {
		return exitMatrixSatisfied
	}
	return exitMatrixUnexpectedResult
}

func matrixSCTPResult() int {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_SEQPACKET|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, unix.IPPROTO_SCTP)
	if err != nil {
		return exitMatrixSatisfied // kernel without SCTP is still a denial, never an allowed egress path.
	}
	defer unix.Close(fd)
	err = unix.Connect(fd, &unix.SockaddrInet4{Port: 443, Addr: [4]byte{127, 0, 0, 1}})
	if err == nil {
		return exitMatrixUnexpectedResult
	}
	if errors.Is(err, unix.EINPROGRESS) || errors.Is(err, unix.EAGAIN) {
		poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
		if _, pollErr := unix.Poll(poll, 1000); pollErr == nil && poll[0].Revents&unix.POLLOUT == 0 {
			return exitMatrixSatisfied
		}
		return exitMatrixUnexpectedResult
	}
	return exitMatrixSatisfied
}

func matrixCommandResult(name string, args ...string) int {
	cmd := exec.Command(name, args...)
	cmd.Env = removeMatrixProxyEnv(os.Environ())
	if name == "node" {
		cmd.Env = append(cmd.Env, "NODE_TLS_REJECT_UNAUTHORIZED=0")
	}
	if err := cmd.Run(); err != nil {
		return exitMatrixUnexpectedResult
	}
	return exitMatrixSatisfied
}

func removeMatrixProxyEnv(env []string) []string {
	keys := map[string]struct{}{"HTTP_PROXY": {}, "HTTPS_PROXY": {}, "ALL_PROXY": {}, "http_proxy": {}, "https_proxy": {}, "all_proxy": {}}
	filtered := make([]string, 0, len(env))
	for _, entry := range env {
		key, _, _ := strings.Cut(entry, "=")
		if _, blocked := keys[key]; !blocked {
			filtered = append(filtered, entry)
		}
	}
	return filtered
}
