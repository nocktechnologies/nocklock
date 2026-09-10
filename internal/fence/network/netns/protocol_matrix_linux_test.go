//go:build linux

package netns

// Root-gated Phase-1b protocol matrix. Unlike the foundation test, this test
// starts the exact sidecar commands that SetupEgressAndSupervise uses: a host
// resolver/dial proxy across a private veth, then an in-namespace transparent
// proxy plus fixed-answer DNS stub. The re-exec'd client inherits the capped
// child's resolver mount and credential, so every row exercises the packet path
// rather than an in-process approximation.

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/fence/network"
	"golang.org/x/sys/unix"
)

func TestNetnsProtocolMatrix(t *testing.T) {
	requireRoot(t)
	requireTool(t, "ip")
	requireTool(t, "nft")

	bridge, err := NewBridgeSpec()
	if err != nil {
		t.Fatalf("NewBridgeSpec() error: %v", err)
	}
	httpHits := startProtocolHTTPServer(t)
	httpsHits := startProtocolTLSServer(t)

	uid, gid, groups := protocolChildCredential(t)
	exe, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	req := Request{
		Argv:   []string{exe, "-test.run=^$"},
		Env:    append(os.Environ(), "NOCKLOCK_PROTOCOL_CLIENT=1", "NOCKLOCK_PROTOCOL_EXTERNAL="+bridge.HostAddress),
		UID:    uid,
		GID:    gid,
		Groups: groups,
		Egress: &EgressConfig{
			Allow:              []string{"localhost"},
			AllowPrivateRanges: true,
			Bridge:             bridge,
		},
	}

	if err := SetupEgressAndSupervise(req); err != nil {
		t.Fatalf("Phase-1b helper/protocol client failed: %v", err)
	}
	if got := httpHits.Load(); got == 0 {
		t.Fatal("allowed HTTP never reached the host-side upstream")
	}
	if got := httpsHits.Load(); got == 0 {
		t.Fatal("allowed HTTPS never reached the host-side upstream")
	}
	assertProxyDeathTerminatesChild(t)
}

func protocolChildCredential(t *testing.T) (int, int, []int) {
	t.Helper()
	uid, err := strconv.Atoi(os.Getenv("SUDO_UID"))
	if err != nil || uid <= 0 {
		t.Fatalf("protocol matrix must run through sudo with SUDO_UID set, got %q", os.Getenv("SUDO_UID"))
	}
	gid, err := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err != nil || gid <= 0 {
		t.Fatalf("protocol matrix must run through sudo with SUDO_GID set, got %q", os.Getenv("SUDO_GID"))
	}
	u, err := user.LookupId(strconv.Itoa(uid))
	if err != nil {
		t.Fatalf("look up sudo user %d: %v", uid, err)
	}
	groupStrings, err := u.GroupIds()
	if err != nil {
		t.Fatalf("look up groups for sudo user %d: %v", uid, err)
	}
	groups := make([]int, 0, len(groupStrings))
	for _, raw := range groupStrings {
		value, err := strconv.Atoi(raw)
		if err != nil {
			t.Fatalf("parse sudo-user group %q: %v", raw, err)
		}
		groups = append(groups, value)
	}
	return uid, gid, groups
}

// runProtocolMatrixClient is invoked by TestMain only after the helper has
// dropped the real child credential and bound its private resolver mount.
func runProtocolMatrixClient() int {
	if !protocolHTTPSRequest("localhost") {
		return 41 // allowed HTTPS must make a positive end-to-end request
	}
	if !protocolHTTPRequest("localhost") {
		return 42 // allowed HTTP must make a positive end-to-end request
	}
	if !protocolHTTPDenied("blocked.example") {
		return 43 // non-allowed HTTP must be a proxy 403, not a packet drop
	}
	if !protocolTLSDenied("blocked.example") {
		return 44 // non-allowed HTTPS must close at the proxy before upstream
	}
	if !protocolDirectIPRejected() {
		return 45 // no-SNI direct-IP TLS must be terminated by the proxy
	}
	if !protocolDNSStub() {
		return 46 // UDP and TCP DNS must both answer from the fixed stub
	}
	external := os.Getenv("NOCKLOCK_PROTOCOL_EXTERNAL")
	if external == "" || !protocolExternalDNSDenied(external) {
		return 47 // direct UDP/TCP DNS to the veth peer must not get a reply
	}
	if !protocolUDPAndSCTPDenied(external) {
		return 48 // QUIC's UDP/443 and SCTP remain packet-dropped
	}
	if !protocolTCPFallbackClients() {
		return 49 // curl, Node, and Python succeed over the TCP-only path
	}
	return 0
}

func protocolHTTPSRequest(serverName string) bool {
	conn, err := tls.Dial("tcp", "127.0.0.1:443", &tls.Config{ServerName: serverName, InsecureSkipVerify: true}) //nolint:gosec // local root-test endpoint
	if err != nil {
		return false
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+serverName+"\r\nConnection: close\r\n\r\n")
	response, err := io.ReadAll(conn)
	return err == nil && bytesContains(response, "200 OK")
}

func protocolHTTPRequest(host string) bool {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:80", 4*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n")
	response, err := io.ReadAll(conn)
	return err == nil && bytesContains(response, "200 OK")
}

func protocolHTTPDenied(host string) bool {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:80", 4*time.Second)
	if err != nil {
		return false
	}
	defer conn.Close()
	_, _ = io.WriteString(conn, "GET / HTTP/1.1\r\nHost: "+host+"\r\nConnection: close\r\n\r\n")
	response, err := io.ReadAll(conn)
	return err == nil && bytesContains(response, "403 Forbidden")
}

func protocolTLSDenied(host string) bool {
	_, err := tls.Dial("tcp", "127.0.0.1:443", &tls.Config{ServerName: host, InsecureSkipVerify: true}) //nolint:gosec // verifies proxy close, not a certificate
	return err != nil
}

func protocolDirectIPRejected() bool {
	conn, err := net.DialTimeout("tcp", "127.0.0.1:443", 4*time.Second)
	if err != nil {
		return true
	}
	defer conn.Close()
	_, _ = conn.Write(testClientHello(""))
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	var one [1]byte
	_, err = conn.Read(one[:])
	return err != nil
}

func protocolDNSStub() bool {
	for _, networkName := range []string{"udp", "tcp"} {
		query := testDNSQuery("blocked.example", 1)
		if networkName == "udp" {
			conn, err := net.DialTimeout("udp", "127.0.0.1:53", 2*time.Second)
			if err != nil {
				return false
			}
			_, _ = conn.Write(query)
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 512)
			n, err := conn.Read(buf)
			conn.Close()
			if err != nil || !strings.HasSuffix(string(buf[:n]), string([]byte{127, 0, 0, 1})) {
				return false
			}
			continue
		}
		conn, err := net.DialTimeout("tcp", "127.0.0.1:53", 2*time.Second)
		if err != nil {
			return false
		}
		var size [2]byte
		binary.BigEndian.PutUint16(size[:], uint16(len(query)))
		_, _ = conn.Write(size[:])
		_, _ = conn.Write(query)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		if _, err := io.ReadFull(conn, size[:]); err != nil {
			conn.Close()
			return false
		}
		response := make([]byte, binary.BigEndian.Uint16(size[:]))
		_, err = io.ReadFull(conn, response)
		conn.Close()
		if err != nil || !strings.HasSuffix(string(response), string([]byte{127, 0, 0, 1})) {
			return false
		}
	}
	return true
}

func protocolExternalDNSDenied(host string) bool {
	for _, networkName := range []string{"udp", "tcp"} {
		conn, err := net.DialTimeout(networkName, net.JoinHostPort(host, "53"), time.Second)
		if err != nil {
			continue
		}
		_, _ = conn.Write(testDNSQuery("bypass.example", 1))
		_ = conn.SetReadDeadline(time.Now().Add(time.Second))
		var one [1]byte
		_, readErr := conn.Read(one[:])
		conn.Close()
		if readErr == nil {
			return false
		}
	}
	return true
}

func protocolUDPAndSCTPDenied(host string) bool {
	udp, err := net.DialTimeout("udp", net.JoinHostPort(host, "443"), time.Second)
	if err != nil {
		return true
	}
	_, _ = udp.Write([]byte("quic"))
	_ = udp.SetReadDeadline(time.Now().Add(time.Second))
	var one [1]byte
	_, readErr := udp.Read(one[:])
	udp.Close()
	if readErr == nil {
		return false
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_NONBLOCK, unix.IPPROTO_SCTP)
	if err != nil {
		return true // no SCTP support is a denied transport, not an allow.
	}
	defer unix.Close(fd)
	ip := net.ParseIP(host).To4()
	if ip == nil {
		return false
	}
	var addr [4]byte
	copy(addr[:], ip)
	err = unix.Connect(fd, &unix.SockaddrInet4{Port: 443, Addr: addr})
	if err != nil && err != unix.EINPROGRESS {
		return true
	}
	poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLOUT}}
	if _, err := unix.Poll(poll, 1000); err != nil || poll[0].Revents == 0 {
		return true
	}
	soErr, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ERROR)
	return err != nil || soErr != 0
}

func curlSupportsHTTP3(version string) bool {
	for _, line := range strings.Split(version, "\n") {
		if strings.HasPrefix(line, "Features:") {
			for _, feature := range strings.Fields(strings.TrimPrefix(line, "Features:")) {
				if feature == "HTTP3" {
					return true
				}
			}
		}
	}
	return false
}

func TestCurlHTTP3FeatureDetection(t *testing.T) {
	if curlSupportsHTTP3("curl help mentions --http3\nFeatures: HTTP2 SSL\n") {
		t.Fatal("help text is not compiled HTTP3 capability")
	}
	if !curlSupportsHTTP3("curl 8.x\nFeatures: HTTP2 HTTP3 SSL\n") {
		t.Fatal("compiled HTTP3 capability missed")
	}
}

func protocolTCPFallbackClients() bool {
	curlArgs := []string{"--fail", "--silent", "--show-error", "--insecure", "https://localhost/"}
	if version, err := exec.Command("curl", "--version").CombinedOutput(); err == nil && curlSupportsHTTP3(string(version)) {
		// curl's --http3 mode first attempts QUIC and falls back to TCP when the
		// UDP/443 path is denied; --http3-only would not test fallback.
		curlArgs = append([]string{"--http3"}, curlArgs...)
	} else {
		fmt.Fprintln(os.Stderr, "curl lacks compiled HTTP3: validating TCP path only; QUIC-to-TCP fallback is not measured on this runner")
	}
	commands := [][]string{
		append([]string{"curl"}, curlArgs...),
		{"node", "-e", "fetch(\"https://localhost/\").then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"},
		{"python3", "-c", "import requests; requests.get('https://localhost/', verify=False, timeout=10).raise_for_status()"},
	}
	for _, argv := range commands {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.Env = append(os.Environ(), "NODE_TLS_REJECT_UNAUTHORIZED=0", "PYTHONWARNINGS=ignore")
		output, err := cmd.CombinedOutput()
		cancel()
		if err != nil {
			fmt.Fprintf(os.Stderr, "TCP fallback %s failed: %v: %s\n", argv[0], err, output)
			return false
		}
	}
	return true
}

func TestProxyDeathTerminatesChild(t *testing.T) {
	assertProxyDeathTerminatesChild(t)
}

func assertProxyDeathTerminatesChild(t *testing.T) {
	t.Helper()
	p := network.NewProxyServer(config.NetworkConfig{Allow: []string{"localhost"}}, nil, "watchdog-test")
	addr, err := p.Start()
	if err != nil {
		t.Fatalf("start watchdog control proxy: %v", err)
	}
	defer p.Stop()
	child := exec.Command("/bin/sleep", "30")
	child.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := child.Start(); err != nil {
		t.Fatalf("start watchdog child: %v", err)
	}
	time.AfterFunc(100*time.Millisecond, func() { _ = p.Stop() })
	err = superviseChild(child, []string{addr})
	if err == nil || !strings.Contains(err.Error(), "proxy died") {
		t.Fatalf("superviseChild() error = %v, want proxy-death child termination", err)
	}
}

func startProtocolHTTPServer(t *testing.T) *atomic.Int32 {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:80")
	if err != nil {
		t.Fatalf("listen local HTTP upstream on port 80: %v", err)
	}
	hits := &atomic.Int32{}
	go serveProtocolHTTP(ln, hits, nil)
	t.Cleanup(func() { _ = ln.Close() })
	return hits
}

func startProtocolTLSServer(t *testing.T) *atomic.Int32 {
	t.Helper()
	cert, err := testTLSCertificate()
	if err != nil {
		t.Fatalf("create local TLS certificate: %v", err)
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:443")
	if err != nil {
		t.Fatalf("listen local HTTPS upstream on port 443: %v", err)
	}
	hits := &atomic.Int32{}
	go serveProtocolHTTP(ln, hits, &tls.Config{Certificates: []tls.Certificate{cert}})
	t.Cleanup(func() { _ = ln.Close() })
	return hits
}

func serveProtocolHTTP(ln net.Listener, hits *atomic.Int32, tlsConfig *tls.Config) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			if tlsConfig != nil {
				conn = tls.Server(conn, tlsConfig)
			}
			reader := bufio.NewReader(conn)
			if _, err := httpReadHeader(reader); err != nil {
				return
			}
			hits.Add(1)
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 3\r\nConnection: close\r\n\r\nok\n")
		}()
	}
}

func httpReadHeader(r *bufio.Reader) ([]byte, error) {
	var data []byte
	for len(data) < maxHTTPHeaderBytes {
		line, err := r.ReadBytes('\n')
		if err != nil {
			return nil, err
		}
		data = append(data, line...)
		if bytesContains(data, "\r\n\r\n") {
			return data, nil
		}
	}
	return nil, fmt.Errorf("HTTP header too large")
}

func testTLSCertificate() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func bytesContains(b []byte, substring string) bool { return strings.Contains(string(b), substring) }
