//go:build linux

package netns

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/nocktechnologies/nocklock/internal/fence/network"
	"golang.org/x/sys/unix"
)

const (
	maxDNSMessage      = 4096
	maxHTTPHeaderBytes = 64 << 10
	maxTLSHelloBytes   = 128 << 10
)

type transparentProxy struct {
	cfg       EgressConfig
	tcp       []net.Listener
	dnsTCP    []net.Listener
	dnsUDP    []net.PacketConn
	health    net.Listener
	healthSrv *http.Server
}

// RunTransparentProxy starts the namespace-local DNS stub and transparent TCP
// proxy. It binds its privileged sockets before dropping to the dedicated proxy
// identity, then serves until its supervisor terminates it.
func RunTransparentProxy(cfg EgressConfig) error {
	p, err := startTransparentProxy(cfg)
	if err != nil {
		return err
	}
	if err := dropProxyIdentity(); err != nil {
		p.close()
		return err
	}
	p.serve()

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGTERM, syscall.SIGINT)
	defer signal.Stop(signals)
	<-signals
	p.close()
	return nil
}

func startTransparentProxy(cfg EgressConfig) (*transparentProxy, error) {
	if err := validateEgressConfig(&cfg, 1000); err != nil {
		return nil, err
	}
	p := &transparentProxy{cfg: cfg}
	closeOnError := func(err error) (*transparentProxy, error) {
		p.close()
		return nil, err
	}

	for _, spec := range []struct {
		network string
		address string
	}{
		{"tcp4", "0.0.0.0:" + strconv.Itoa(TransparentProxyPort)},
		{"tcp6", "[::]:" + strconv.Itoa(TransparentProxyPort)},
	} {
		ln, err := listenTransparent(spec.network, spec.address)
		if err != nil {
			return closeOnError(fmt.Errorf("listen transparent %s on %s: %w", spec.network, spec.address, err))
		}
		p.tcp = append(p.tcp, ln)
	}
	for _, networkName := range []string{"udp4", "udp6"} {
		address := "127.0.0.1:53"
		if networkName == "udp6" {
			address = "[::1]:53"
		}
		pc, err := net.ListenPacket(networkName, address)
		if err != nil {
			return closeOnError(fmt.Errorf("listen DNS %s on %s: %w", networkName, address, err))
		}
		p.dnsUDP = append(p.dnsUDP, pc)
	}
	for _, networkName := range []string{"tcp4", "tcp6"} {
		address := "127.0.0.1:53"
		if networkName == "tcp6" {
			address = "[::1]:53"
		}
		ln, err := net.Listen(networkName, address)
		if err != nil {
			return closeOnError(fmt.Errorf("listen DNS %s on %s: %w", networkName, address, err))
		}
		p.dnsTCP = append(p.dnsTCP, ln)
	}
	health, err := net.Listen("tcp4", "0.0.0.0:"+strconv.Itoa(ProxyHealthPort))
	if err != nil {
		return closeOnError(fmt.Errorf("listen transparent proxy health endpoint: %w", err))
	}
	p.health = health
	p.healthSrv = &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != network.ProxyHealthPath || (r.Method != http.MethodGet && r.Method != http.MethodHead) {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodGet {
				_, _ = w.Write([]byte("ok\n"))
			}
		}),
		ReadHeaderTimeout: 5 * time.Second,
	}
	return p, nil
}

func (p *transparentProxy) serve() {
	for _, ln := range p.tcp {
		go p.serveTCP(ln)
	}
	for _, ln := range p.dnsTCP {
		go p.serveDNSTCP(ln)
	}
	for _, pc := range p.dnsUDP {
		go p.serveDNSUDP(pc)
	}
	go func() { _ = p.healthSrv.Serve(p.health) }()
}

func (p *transparentProxy) close() {
	for _, ln := range p.tcp {
		_ = ln.Close()
	}
	for _, ln := range p.dnsTCP {
		_ = ln.Close()
	}
	for _, pc := range p.dnsUDP {
		_ = pc.Close()
	}
	if p.healthSrv != nil {
		_ = p.healthSrv.Close()
	}
	if p.health != nil {
		_ = p.health.Close()
	}
}

func listenTransparent(networkName, address string) (net.Listener, error) {
	lc := net.ListenConfig{
		Control: func(networkName, _ string, raw syscall.RawConn) error {
			var controlErr error
			if err := raw.Control(func(fd uintptr) {
				if networkName == "tcp4" {
					controlErr = unix.SetsockoptInt(int(fd), unix.SOL_IP, unix.IP_TRANSPARENT, 1)
					return
				}
				controlErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_TRANSPARENT, 1)
				if controlErr == nil {
					controlErr = unix.SetsockoptInt(int(fd), unix.SOL_IPV6, unix.IPV6_V6ONLY, 1)
				}
			}); err != nil {
				return err
			}
			return controlErr
		},
	}
	return lc.Listen(nil, networkName, address)
}

func dropProxyIdentity() error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("transparent proxy must start as root to bind DNS and transparent sockets")
	}
	if err := unix.Setgroups(nil); err != nil {
		return fmt.Errorf("clear transparent proxy groups: %w", err)
	}
	if err := unix.Setresgid(proxyUID, proxyUID, proxyUID); err != nil {
		return fmt.Errorf("drop transparent proxy gid: %w", err)
	}
	if err := unix.Setresuid(proxyUID, proxyUID, proxyUID); err != nil {
		return fmt.Errorf("drop transparent proxy uid: %w", err)
	}
	if os.Geteuid() == 0 || os.Getegid() == 0 {
		return fmt.Errorf("transparent proxy credential did not drop to uid/gid %d", proxyUID)
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("latch transparent proxy no_new_privs: %w", err)
	}
	return nil
}

func (p *transparentProxy) serveTCP(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go p.handleTCP(conn)
	}
}

func (p *transparentProxy) handleTCP(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Minute))
	_, port, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		return
	}
	switch port {
	case "443":
		p.handleTLS(conn)
	case "80":
		p.handleHTTP(conn)
	default:
		// A direct connection to the proxy listener has no original HTTP(S)
		// destination and must not become a general tunnel.
		return
	}
}

func (p *transparentProxy) handleTLS(client net.Conn) {
	hello, host, err := readTLSClientHello(client)
	if err != nil || !network.IsAllowedHost(p.cfg.Allow, false, host) {
		fmt.Fprintln(os.Stderr, "NockLock: transparent TLS connection denied (missing or disallowed SNI)")
		return
	}
	upstream, err := openHostTunnel(client, p.cfg.Bridge.hostProxyAddr(), host, "443")
	if err != nil {
		fmt.Fprintln(os.Stderr, "NockLock: transparent TLS upstream tunnel failed")
		return
	}
	defer upstream.Close()
	if _, err := upstream.Write(hello); err != nil {
		return
	}
	pipeConnections(client, upstream)
}

func (p *transparentProxy) handleHTTP(client net.Conn) {
	header, host, err := readHTTPHeader(client)
	if err != nil {
		return
	}
	if !network.IsAllowedHost(p.cfg.Allow, false, host) {
		fmt.Fprintln(os.Stderr, "NockLock: transparent HTTP connection denied (disallowed Host)")
		_, _ = io.WriteString(client, "HTTP/1.1 403 Forbidden\r\nContent-Length: 35\r\nConnection: close\r\n\r\nNockLock: domain not in allowlist\n")
		return
	}
	upstream, err := openHostTunnel(client, p.cfg.Bridge.hostProxyAddr(), host, "80")
	if err != nil {
		_, _ = io.WriteString(client, "HTTP/1.1 502 Bad Gateway\r\nConnection: close\r\n\r\n")
		return
	}
	defer upstream.Close()
	if _, err := upstream.Write(header); err != nil {
		return
	}
	pipeConnections(client, upstream)
}

func readHTTPHeader(r io.Reader) ([]byte, string, error) {
	var raw bytes.Buffer
	for raw.Len() < maxHTTPHeaderBytes {
		var one [1]byte
		if _, err := io.ReadFull(r, one[:]); err != nil {
			return nil, "", fmt.Errorf("read HTTP header: %w", err)
		}
		raw.WriteByte(one[0])
		if raw.Len() >= 4 && bytes.HasSuffix(raw.Bytes(), []byte("\r\n\r\n")) {
			break
		}
	}
	if raw.Len() >= maxHTTPHeaderBytes {
		return nil, "", fmt.Errorf("HTTP header exceeds %d bytes", maxHTTPHeaderBytes)
	}
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(raw.Bytes())))
	if err != nil || req.Host == "" {
		return nil, "", fmt.Errorf("parse HTTP Host header")
	}
	return raw.Bytes(), req.Host, nil
}

func readTLSClientHello(r io.Reader) ([]byte, string, error) {
	var wire, handshake bytes.Buffer
	for wire.Len() < maxTLSHelloBytes {
		header := make([]byte, 5)
		if _, err := io.ReadFull(r, header); err != nil {
			return nil, "", fmt.Errorf("read TLS record header: %w", err)
		}
		length := int(binary.BigEndian.Uint16(header[3:]))
		if header[0] != 22 || length == 0 || length > maxTLSHelloBytes-wire.Len()-len(header) {
			return nil, "", fmt.Errorf("invalid TLS ClientHello record")
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(r, body); err != nil {
			return nil, "", fmt.Errorf("read TLS ClientHello record: %w", err)
		}
		wire.Write(header)
		wire.Write(body)
		handshake.Write(body)
		host, complete, err := parseClientHelloSNI(handshake.Bytes())
		if err != nil {
			return nil, "", err
		}
		if complete {
			return wire.Bytes(), host, nil
		}
	}
	return nil, "", fmt.Errorf("TLS ClientHello exceeds %d bytes", maxTLSHelloBytes)
}

// parseClientHelloSNI returns complete=false while more TLS handshake bytes are
// needed. A complete ClientHello without a usable SNI is an error so raw-IP TLS
// is closed by the proxy instead of falling through to packet dropping.
func parseClientHelloSNI(handshake []byte) (host string, complete bool, err error) {
	if len(handshake) < 4 {
		return "", false, nil
	}
	if handshake[0] != 1 {
		return "", false, fmt.Errorf("first TLS handshake is not ClientHello")
	}
	declared := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if declared > maxTLSHelloBytes {
		return "", false, fmt.Errorf("TLS ClientHello exceeds %d bytes", maxTLSHelloBytes)
	}
	if len(handshake) < 4+declared {
		return "", false, nil
	}
	b := handshake[4 : 4+declared]
	if len(b) < 35 { // legacy_version + random + session-id length
		return "", false, fmt.Errorf("truncated TLS ClientHello")
	}
	off := 34
	sessionLen := int(b[off])
	off++
	if off+sessionLen+2 > len(b) {
		return "", false, fmt.Errorf("truncated TLS session id")
	}
	off += sessionLen
	cipherLen := int(binary.BigEndian.Uint16(b[off:]))
	off += 2
	if cipherLen == 0 || off+cipherLen+1 > len(b) {
		return "", false, fmt.Errorf("truncated TLS cipher suites")
	}
	off += cipherLen
	compressionLen := int(b[off])
	off++
	if off+compressionLen+2 > len(b) {
		return "", false, fmt.Errorf("truncated TLS compression methods")
	}
	off += compressionLen
	extensionsLen := int(binary.BigEndian.Uint16(b[off:]))
	off += 2
	if off+extensionsLen != len(b) {
		return "", false, fmt.Errorf("invalid TLS extension length")
	}
	end := off + extensionsLen
	for off < end {
		if off+4 > end {
			return "", false, fmt.Errorf("truncated TLS extension")
		}
		typ := binary.BigEndian.Uint16(b[off:])
		length := int(binary.BigEndian.Uint16(b[off+2:]))
		off += 4
		if off+length > end {
			return "", false, fmt.Errorf("invalid TLS extension length")
		}
		if typ == 0 {
			return parseServerNameExtension(b[off : off+length])
		}
		off += length
	}
	return "", true, fmt.Errorf("TLS ClientHello has no SNI")
}

func parseServerNameExtension(b []byte) (string, bool, error) {
	if len(b) < 2 {
		return "", true, fmt.Errorf("truncated TLS SNI extension")
	}
	listLen := int(binary.BigEndian.Uint16(b))
	if listLen+2 != len(b) {
		return "", true, fmt.Errorf("invalid TLS SNI extension length")
	}
	for off := 2; off < len(b); {
		if off+3 > len(b) {
			return "", true, fmt.Errorf("truncated TLS SNI name")
		}
		nameType := b[off]
		nameLen := int(binary.BigEndian.Uint16(b[off+1:]))
		off += 3
		if nameLen == 0 || off+nameLen > len(b) {
			return "", true, fmt.Errorf("invalid TLS SNI name")
		}
		if nameType == 0 {
			host := strings.ToLower(string(b[off : off+nameLen]))
			if strings.ContainsRune(host, '\x00') {
				return "", true, fmt.Errorf("invalid TLS SNI name")
			}
			return host, true, nil
		}
		off += nameLen
	}
	return "", true, fmt.Errorf("TLS ClientHello has no DNS SNI")
}

func openHostTunnel(_ net.Conn, proxyAddr, host, port string) (net.Conn, error) {
	upstream, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(context.Background(), "tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	target := net.JoinHostPort(host, port)
	if _, err := fmt.Fprintf(upstream, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target); err != nil {
		_ = upstream.Close()
		return nil, err
	}
	reader := bufio.NewReader(upstream)
	resp, err := http.ReadResponse(reader, &http.Request{Method: http.MethodConnect})
	if err != nil || resp.StatusCode != http.StatusOK {
		_ = upstream.Close()
		return nil, fmt.Errorf("host allowlist proxy denied transparent tunnel")
	}
	return &bufferedConn{Conn: upstream, reader: reader}, nil
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func pipeConnections(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(b, a)
		_ = b.Close()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(a, b)
		_ = a.Close()
		done <- struct{}{}
	}()
	<-done
	<-done
}

func (p *transparentProxy) serveDNSUDP(conn net.PacketConn) {
	buf := make([]byte, maxDNSMessage)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			return
		}
		if response, ok := fixedDNSResponse(buf[:n]); ok {
			_, _ = conn.WriteTo(response, peer)
		}
	}
}

func (p *transparentProxy) serveDNSTCP(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			var length [2]byte
			if _, err := io.ReadFull(conn, length[:]); err != nil {
				return
			}
			n := int(binary.BigEndian.Uint16(length[:]))
			if n == 0 || n > maxDNSMessage {
				return
			}
			query := make([]byte, n)
			if _, err := io.ReadFull(conn, query); err != nil {
				return
			}
			response, ok := fixedDNSResponse(query)
			if !ok || len(response) > 65535 {
				return
			}
			binary.BigEndian.PutUint16(length[:], uint16(len(response)))
			_, _ = conn.Write(length[:])
			_, _ = conn.Write(response)
		}()
	}
}

// fixedDNSResponse answers A and AAAA queries for every syntactically-valid
// name with the transparent intercept address. It intentionally does not
// consult the allowlist: the TCP policy proxy owns every allow/deny decision.
func fixedDNSResponse(query []byte) ([]byte, bool) {
	if len(query) < 12 || binary.BigEndian.Uint16(query[4:]) != 1 {
		return nil, false
	}
	questionEnd, ok := skipDNSName(query, 12)
	if !ok || questionEnd+4 > len(query) {
		return nil, false
	}
	questionEnd += 4
	if questionEnd != len(query) {
		return nil, false
	}
	qtype := binary.BigEndian.Uint16(query[questionEnd-4:])
	flags := binary.BigEndian.Uint16(query[2:])
	response := make([]byte, questionEnd, questionEnd+28)
	copy(response[:2], query[:2])
	binary.BigEndian.PutUint16(response[2:], 0x8080|(flags&0x0100)) // QR + RA + preserve RD
	binary.BigEndian.PutUint16(response[4:], 1)
	copy(response[12:], query[12:questionEnd])
	if qtype != 1 && qtype != 28 {
		return response, true
	}
	binary.BigEndian.PutUint16(response[6:], 1)
	response = append(response, 0xc0, 0x0c)
	answer := make([]byte, 10)
	binary.BigEndian.PutUint16(answer, qtype)
	binary.BigEndian.PutUint16(answer[2:], 1)
	binary.BigEndian.PutUint32(answer[4:], 30)
	if qtype == 1 {
		binary.BigEndian.PutUint16(answer[8:], 4)
		response = append(response, answer...)
		response = append(response, 127, 0, 0, 1)
	} else {
		binary.BigEndian.PutUint16(answer[8:], 16)
		response = append(response, answer...)
		response = append(response, make([]byte, 15)...)
		response = append(response, 1)
	}
	return response, true
}

func skipDNSName(message []byte, off int) (int, bool) {
	for steps := 0; steps < len(message); steps++ {
		if off >= len(message) {
			return 0, false
		}
		length := int(message[off])
		if length == 0 {
			return off + 1, true
		}
		if length&0xc0 == 0xc0 {
			if off+1 >= len(message) {
				return 0, false
			}
			return off + 2, true
		}
		if length&0xc0 != 0 || length > 63 || off+1+length > len(message) {
			return 0, false
		}
		off += 1 + length
	}
	return 0, false
}
