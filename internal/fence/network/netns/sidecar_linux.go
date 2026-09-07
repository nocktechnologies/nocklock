//go:build linux

package netns

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	proxyConfigEnv  = "NOCKLOCK_NETNS_PROXY_CONFIG"
	proxyReadyFDEnv = "NOCKLOCK_NETNS_PROXY_READY_FD"
	maxClientHello  = 64 << 10
)

var (
	interceptIPv4 = []byte{127, 0, 0, 1}
	interceptIPv6 = net.ParseIP("::1").To16()
)

type brokerRequest struct {
	Token  string `json:"token"`
	Action string `json:"action"`
	Host   string `json:"host,omitempty"`
	Port   string `json:"port,omitempty"`
	Reason string `json:"reason,omitempty"`
}

// StartPolicyProxy runs the unprivileged transparent HTTP(S) policy proxy and
// fixed-answer DNS stub. It must start inside the prepared child network
// namespace while privileged so it can create transparent listeners; it then
// permanently drops to the dedicated nobody account before accepting untrusted
// child traffic.
func StartPolicyProxy(cfg ProxyConfig) error {
	if !cfg.Valid() {
		return errors.New("transparent proxy requires an authenticated broker path and token")
	}
	credential, err := proxyCredential()
	if err != nil {
		return err
	}

	tcp4, err := listenTransparent("tcp4", "0.0.0.0", transparentProxyPort)
	if err != nil {
		return fmt.Errorf("listen transparent IPv4 HTTP(S): %w", err)
	}
	defer tcp4.Close()
	tcp6, err := listenTransparent("tcp6", "::", transparentProxyPort)
	if err != nil {
		return fmt.Errorf("listen transparent IPv6 HTTP(S): %w", err)
	}
	defer tcp6.Close()
	dnsTCP4, err := listenTransparent("tcp4", "0.0.0.0", 53)
	if err != nil {
		return fmt.Errorf("listen transparent IPv4 DNS/TCP: %w", err)
	}
	defer dnsTCP4.Close()
	dnsTCP6, err := listenTransparent("tcp6", "::", 53)
	if err != nil {
		return fmt.Errorf("listen transparent IPv6 DNS/TCP: %w", err)
	}
	defer dnsTCP6.Close()
	dnsUDP4, err := listenTransparentUDP("udp4", "0.0.0.0", 53)
	if err != nil {
		return fmt.Errorf("listen transparent IPv4 DNS/UDP: %w", err)
	}
	defer dnsUDP4.Close()
	dnsUDP6, err := listenTransparentUDP("udp6", "::", 53)
	if err != nil {
		return fmt.Errorf("listen transparent IPv6 DNS/UDP: %w", err)
	}
	defer dnsUDP6.Close()

	if err := dropProxyPrivilege(credential); err != nil {
		return fmt.Errorf("drop transparent proxy privileges: %w", err)
	}
	if err := brokerPing(cfg); err != nil {
		return fmt.Errorf("confirm transparent proxy broker: %w", err)
	}
	notifyProxyReady(nil)

	go proxyHeartbeat(cfg)
	for _, listener := range []net.Listener{tcp4, tcp6} {
		go serveTransparentTCP(listener, cfg)
	}
	for _, listener := range []net.Listener{dnsTCP4, dnsTCP6} {
		go serveDNSTCP(listener)
	}
	for _, conn := range []*net.UDPConn{dnsUDP4, dnsUDP6} {
		go serveDNSUDP(conn)
	}
	select {}
}

// StartPolicyProxyFromEnv is the hidden helper-command entrypoint. Keeping the
// configuration in one encoded value avoids admitting untrusted command-line
// flags to the root-owned helper surface.
func StartPolicyProxyFromEnv() error {
	encoded := os.Getenv(proxyConfigEnv)
	if encoded == "" {
		return errors.New("transparent proxy configuration is missing")
	}
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return fmt.Errorf("decode transparent proxy configuration: %w", err)
	}
	var cfg ProxyConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return fmt.Errorf("parse transparent proxy configuration: %w", err)
	}
	if err := StartPolicyProxy(cfg); err != nil {
		notifyProxyReady(err)
		return err
	}
	return nil
}

type proxyUser struct {
	uid int
	gid int
}

func proxyCredential() (proxyUser, error) {
	u, err := user.Lookup("nobody")
	if err != nil {
		return proxyUser{}, fmt.Errorf("lookup dedicated transparent proxy user nobody: %w", err)
	}
	uid, err := strconv.Atoi(u.Uid)
	if err != nil || uid <= 0 {
		return proxyUser{}, fmt.Errorf("transparent proxy user nobody has invalid uid %q", u.Uid)
	}
	gid, err := strconv.Atoi(u.Gid)
	if err != nil || gid <= 0 {
		return proxyUser{}, fmt.Errorf("transparent proxy user nobody has invalid gid %q", u.Gid)
	}
	return proxyUser{uid: uid, gid: gid}, nil
}

func dropProxyPrivilege(credential proxyUser) error {
	if err := unix.Setgroups(nil); err != nil {
		return fmt.Errorf("clear supplementary groups: %w", err)
	}
	if err := unix.Setresgid(credential.gid, credential.gid, credential.gid); err != nil {
		return fmt.Errorf("setresgid(%d): %w", credential.gid, err)
	}
	if err := unix.Setresuid(credential.uid, credential.uid, credential.uid); err != nil {
		return fmt.Errorf("setresuid(%d): %w", credential.uid, err)
	}
	if os.Geteuid() == 0 || os.Getuid() == 0 {
		return errors.New("transparent proxy uid did not drop from root")
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("set NO_NEW_PRIVS: %w", err)
	}
	return nil
}

func listenTransparent(network, host string, port int) (net.Listener, error) {
	addr := net.JoinHostPort(host, strconv.Itoa(port))
	lc := net.ListenConfig{Control: transparentSocketControl(network)}
	return lc.Listen(context.Background(), network, addr)
}

func listenTransparentUDP(network, host string, port int) (*net.UDPConn, error) {
	addr, err := net.ResolveUDPAddr(network, net.JoinHostPort(host, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	lc := net.ListenConfig{Control: transparentSocketControl(network)}
	packet, err := lc.ListenPacket(context.Background(), network, addr.String())
	if err != nil {
		return nil, err
	}
	udp, ok := packet.(*net.UDPConn)
	if !ok {
		_ = packet.Close()
		return nil, fmt.Errorf("transparent %s listener is %T, want *net.UDPConn", network, packet)
	}
	return udp, nil
}

func transparentSocketControl(network string) func(string, string, syscall.RawConn) error {
	return func(_, _ string, raw syscall.RawConn) error {
		var controlErr error
		err := raw.Control(func(fd uintptr) {
			if strings.HasSuffix(network, "6") {
				controlErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_TRANSPARENT, 1)
				return
			}
			controlErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_TRANSPARENT, 1)
		})
		if err != nil {
			return err
		}
		return controlErr
	}
}

func serveTransparentTCP(listener net.Listener, cfg ProxyConfig) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go handleTransparentTCP(conn, cfg)
	}
}

func handleTransparentTCP(conn net.Conn, cfg ProxyConfig) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	host, port := originalDestination(conn)
	if ip := net.ParseIP(host); ip != nil && !ip.IsLoopback() {
		denyConnection(conn, cfg, "direct_ip_without_name", "", false)
		return
	}
	if port == "80" {
		handleTransparentHTTP(conn, cfg)
		return
	}
	if port == "443" {
		handleTransparentTLS(conn, cfg)
		return
	}
	denyConnection(conn, cfg, "unsupported_destination_port", "", false)
}

func originalDestination(conn net.Conn) (host, port string) {
	host, port, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return "", ""
	}
	return host, port
}

func handleTransparentHTTP(conn net.Conn, cfg ProxyConfig) {
	reader := bufio.NewReader(conn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		denyConnection(conn, cfg, "invalid_http", "", true)
		return
	}
	host := canonicalHostname(req.Host)
	if !allowedHost(cfg, host) {
		denyConnection(conn, cfg, "host_not_allowed", host, true)
		return
	}
	upstream, err := brokerDial(cfg, host, "80")
	if err != nil {
		denyConnection(conn, cfg, "upstream_denied", host, true)
		return
	}
	defer upstream.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))
	_ = upstream.SetDeadline(time.Now().Add(5 * time.Minute))
	if err := req.Write(upstream); err != nil {
		return
	}
	pipeConnections(conn, reader, upstream)
}

func handleTransparentTLS(conn net.Conn, cfg ProxyConfig) {
	reader := bufio.NewReader(conn)
	preface, err := readTLSClientHello(reader)
	if err != nil {
		denyConnection(conn, cfg, "missing_sni", "", false)
		return
	}
	host, err := tlsClientHelloServerName(preface)
	if err != nil || !allowedHost(cfg, host) {
		denyConnection(conn, cfg, "sni_not_allowed", host, false)
		return
	}
	upstream, err := brokerDial(cfg, host, "443")
	if err != nil {
		denyConnection(conn, cfg, "upstream_denied", host, false)
		return
	}
	defer upstream.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))
	_ = upstream.SetDeadline(time.Now().Add(5 * time.Minute))
	if _, err := upstream.Write(preface); err != nil {
		return
	}
	pipeConnections(conn, reader, upstream)
}

func pipeConnections(client net.Conn, clientReader io.Reader, upstream net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		_, _ = io.Copy(upstream, clientReader)
		_ = upstream.Close()
	}()
	go func() {
		defer wg.Done()
		_, _ = io.Copy(client, upstream)
		_ = client.Close()
	}()
	wg.Wait()
}

func allowedHost(cfg ProxyConfig, hostname string) bool {
	host := canonicalHostname(hostname)
	if host == "" || net.ParseIP(host) != nil {
		return false
	}
	if cfg.AllowAll {
		return true
	}
	for _, entry := range cfg.Allow {
		entry = strings.TrimSuffix(strings.ToLower(entry), ".")
		if strings.HasPrefix(entry, "*.") {
			if strings.HasSuffix(host, entry[1:]) {
				return true
			}
			continue
		}
		if host == entry || strings.HasSuffix(host, "."+entry) {
			return true
		}
	}
	return false
}

func canonicalHostname(hostname string) string {
	host := hostname
	if h, _, err := net.SplitHostPort(hostname); err == nil {
		host = h
	}
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

func denyConnection(conn net.Conn, cfg ProxyConfig, reason, host string, httpResponse bool) {
	brokerDeny(cfg, reason, host)
	if httpResponse {
		_, _ = io.WriteString(conn, "HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 34\r\nContent-Type: text/plain\r\n\r\nNockLock: domain not in allowlist\n")
		return
	}
	if tcp, ok := conn.(*net.TCPConn); ok {
		_ = tcp.SetLinger(0) // explicit reset proves interception instead of a dropped SYN.
	}
}

func readTLSClientHello(reader *bufio.Reader) ([]byte, error) {
	var records []byte
	var handshake []byte
	for len(records) < maxClientHello {
		header := make([]byte, 5)
		if _, err := io.ReadFull(reader, header); err != nil {
			return nil, err
		}
		if header[0] != 22 {
			return nil, errors.New("first TLS record is not a handshake")
		}
		length := int(binary.BigEndian.Uint16(header[3:5]))
		if length == 0 || length > 16<<10 || len(records)+5+length > maxClientHello {
			return nil, errors.New("invalid or oversized TLS record")
		}
		payload := make([]byte, length)
		if _, err := io.ReadFull(reader, payload); err != nil {
			return nil, err
		}
		records = append(records, header...)
		records = append(records, payload...)
		handshake = append(handshake, payload...)
		if len(handshake) >= 4 {
			want := 4 + int(handshake[1])<<16 + int(handshake[2])<<8 + int(handshake[3])
			if handshake[0] != 1 {
				return nil, errors.New("first TLS handshake is not ClientHello")
			}
			if want <= len(handshake) {
				return records, nil
			}
			if want > maxClientHello {
				return nil, errors.New("oversized TLS ClientHello")
			}
		}
	}
	return nil, errors.New("TLS ClientHello exceeds limit")
}

func tlsClientHelloServerName(records []byte) (string, error) {
	if len(records) < 9 || records[0] != 22 {
		return "", errors.New("missing TLS ClientHello")
	}
	var handshake []byte
	for offset := 0; offset+5 <= len(records); {
		if records[offset] != 22 {
			return "", errors.New("non-handshake TLS record")
		}
		length := int(binary.BigEndian.Uint16(records[offset+3 : offset+5]))
		if offset+5+length > len(records) {
			return "", errors.New("truncated TLS record")
		}
		handshake = append(handshake, records[offset+5:offset+5+length]...)
		offset += 5 + length
	}
	if len(handshake) < 4 || handshake[0] != 1 {
		return "", errors.New("missing TLS ClientHello handshake")
	}
	length := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if length+4 > len(handshake) {
		return "", errors.New("truncated TLS ClientHello")
	}
	body := handshake[4 : 4+length]
	if len(body) < 35 {
		return "", errors.New("short TLS ClientHello")
	}
	offset := 35 + int(body[34])
	if offset+2 > len(body) {
		return "", errors.New("short TLS session id")
	}
	cipherLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2 + cipherLen
	if offset+1 > len(body) {
		return "", errors.New("short TLS cipher suites")
	}
	compressionLen := int(body[offset])
	offset += 1 + compressionLen
	if offset+2 > len(body) {
		return "", errors.New("TLS ClientHello has no extensions")
	}
	extensionsLen := int(binary.BigEndian.Uint16(body[offset : offset+2]))
	offset += 2
	if offset+extensionsLen > len(body) {
		return "", errors.New("truncated TLS extensions")
	}
	end := offset + extensionsLen
	for offset+4 <= end {
		typ := binary.BigEndian.Uint16(body[offset : offset+2])
		size := int(binary.BigEndian.Uint16(body[offset+2 : offset+4]))
		offset += 4
		if offset+size > end {
			return "", errors.New("truncated TLS extension")
		}
		if typ == 0 {
			return parseServerName(body[offset : offset+size])
		}
		offset += size
	}
	return "", errors.New("TLS ClientHello has no SNI")
}

func parseServerName(data []byte) (string, error) {
	if len(data) < 5 {
		return "", errors.New("short TLS SNI extension")
	}
	listLen := int(binary.BigEndian.Uint16(data[:2]))
	if listLen+2 > len(data) || data[2] != 0 {
		return "", errors.New("invalid TLS SNI extension")
	}
	nameLen := int(binary.BigEndian.Uint16(data[3:5]))
	if nameLen == 0 || 5+nameLen > len(data) {
		return "", errors.New("invalid TLS SNI hostname")
	}
	return strings.ToLower(string(data[5 : 5+nameLen])), nil
}

func serveDNSUDP(conn *net.UDPConn) {
	buf := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		response, err := fixedDNSAnswer(buf[:n])
		if err == nil {
			_, _ = conn.WriteToUDP(response, addr)
		}
	}
}

func serveDNSTCP(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			var length uint16
			if err := binary.Read(conn, binary.BigEndian, &length); err != nil || length == 0 || length > 4096 {
				return
			}
			query := make([]byte, length)
			if _, err := io.ReadFull(conn, query); err != nil {
				return
			}
			response, err := fixedDNSAnswer(query)
			if err != nil || len(response) > 65535 {
				return
			}
			_ = binary.Write(conn, binary.BigEndian, uint16(len(response)))
			_, _ = conn.Write(response)
		}()
	}
}

func fixedDNSAnswer(query []byte) ([]byte, error) {
	if len(query) < 17 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return nil, errors.New("DNS request must contain exactly one question")
	}
	offset := 12
	for {
		if offset >= len(query) {
			return nil, errors.New("truncated DNS name")
		}
		labelLen := int(query[offset])
		if labelLen&0xc0 != 0 || labelLen > 63 {
			return nil, errors.New("compressed DNS queries are not supported")
		}
		offset++
		if labelLen == 0 {
			break
		}
		offset += labelLen
	}
	if offset+4 > len(query) {
		return nil, errors.New("truncated DNS question")
	}
	qtype := binary.BigEndian.Uint16(query[offset : offset+2])
	questionEnd := offset + 4
	answerIP := interceptIPv4
	if qtype == 28 {
		answerIP = interceptIPv6
	}
	response := append([]byte{}, query[:2]...)
	response = append(response, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)
	response = append(response, query[12:questionEnd]...)
	response = append(response, 0xc0, 0x0c)
	response = binary.BigEndian.AppendUint16(response, qtype)
	response = binary.BigEndian.AppendUint16(response, 1)
	response = binary.BigEndian.AppendUint32(response, 60)
	response = binary.BigEndian.AppendUint16(response, uint16(len(answerIP)))
	response = append(response, answerIP...)
	return response, nil
}

func brokerPing(cfg ProxyConfig) error {
	return brokerRequestStatus(cfg, brokerRequest{Token: cfg.BrokerToken, Action: "ping"})
}

func brokerDeny(cfg ProxyConfig, reason, host string) {
	_ = brokerRequestStatus(cfg, brokerRequest{Token: cfg.BrokerToken, Action: "deny", Reason: reason, Host: host})
}

func brokerDial(cfg ProxyConfig, host, port string) (net.Conn, error) {
	conn, err := net.DialTimeout("unix", cfg.BrokerPath, 2*time.Second)
	if err != nil {
		return nil, err
	}
	unixConn, ok := conn.(*net.UnixConn)
	if !ok {
		_ = conn.Close()
		return nil, errors.New("broker connection is not Unix")
	}
	defer unixConn.Close()
	request := brokerRequest{Token: cfg.BrokerToken, Action: "dial", Host: host, Port: port}
	payload, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	if _, err := unixConn.Write(append(payload, '\n')); err != nil {
		return nil, err
	}
	data := make([]byte, 1)
	oob := make([]byte, unix.CmsgSpace(4))
	n, oobn, _, _, err := unixConn.ReadMsgUnix(data, oob)
	if err != nil || n != 1 || data[0] != 1 {
		return nil, errors.New("broker denied upstream connection")
	}
	messages, err := unix.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return nil, err
	}
	for _, message := range messages {
		fds, parseErr := unix.ParseUnixRights(&message)
		if parseErr != nil || len(fds) != 1 {
			continue
		}
		file := os.NewFile(uintptr(fds[0]), "nocklock-upstream")
		upstream, fileErr := net.FileConn(file)
		_ = file.Close()
		if fileErr != nil {
			return nil, fileErr
		}
		return upstream, nil
	}
	return nil, errors.New("broker response carried no upstream socket")
}

func brokerRequestStatus(cfg ProxyConfig, request brokerRequest) error {
	conn, err := net.DialTimeout("unix", cfg.BrokerPath, 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	payload, err := json.Marshal(request)
	if err != nil {
		return err
	}
	if _, err := conn.Write(append(payload, '\n')); err != nil {
		return err
	}
	status := []byte{0}
	if _, err := io.ReadFull(conn, status); err != nil {
		return err
	}
	if status[0] != 1 {
		return errors.New("broker rejected request")
	}
	return nil
}

func proxyHeartbeat(cfg ProxyConfig) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		_ = brokerPing(cfg)
	}
}

func notifyProxyReady(startErr error) {
	fdText := os.Getenv(proxyReadyFDEnv)
	if fdText == "" {
		return
	}
	fd, err := strconv.Atoi(fdText)
	if err != nil || fd < 3 {
		return
	}
	message := []byte{1}
	if startErr != nil {
		message = append([]byte{0}, []byte(startErr.Error())...)
	}
	_, _ = unix.Write(fd, message)
	_ = unix.Close(fd)
}
