//go:build linux

package netns

import (
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestTLSClientHelloServerName(t *testing.T) {
	hello := testClientHello("api.allowed.test")
	host, err := tlsClientHelloServerName(hello)
	if err != nil {
		t.Fatalf("tlsClientHelloServerName() error = %v", err)
	}
	if host != "api.allowed.test" {
		t.Fatalf("tlsClientHelloServerName() = %q, want api.allowed.test", host)
	}
}

func TestTLSClientHelloServerNameRejectsMissingSNI(t *testing.T) {
	if _, err := tlsClientHelloServerName(testClientHello("")); err == nil {
		t.Fatal("tlsClientHelloServerName() succeeded without SNI")
	}
}

func TestCanonicalHostnameStripsPortBeforeBrokerDial(t *testing.T) {
	if got := canonicalHostname("api.allowed.test:80"); got != "api.allowed.test" {
		t.Fatalf("canonicalHostname() = %q, want api.allowed.test", got)
	}
}

func TestOriginalDestinationRecognizesHostAndPort(t *testing.T) {
	if host, port := originalDestination(testAddrConn{addr: "203.0.113.5:443"}); host != "203.0.113.5" || port != "443" {
		t.Fatalf("originalDestination() = %q:%q, want 203.0.113.5:443", host, port)
	}
}

func TestProxyConfigRequiresBrokerAuthentication(t *testing.T) {
	if (ProxyConfig{}).Valid() {
		t.Fatal("empty proxy config must not be valid")
	}
	if !(ProxyConfig{BrokerPath: "/tmp/broker", BrokerToken: "token"}).Valid() {
		t.Fatal("proxy config with broker path and token must be valid")
	}
}

func TestFixedDNSAnswerReturnsInterceptAddress(t *testing.T) {
	query := dnsQuery("allowed.test", 1)
	response, err := fixedDNSAnswer(query)
	if err != nil {
		t.Fatalf("fixedDNSAnswer() error = %v", err)
	}
	if got := binary.BigEndian.Uint16(response[6:8]); got != 1 {
		t.Fatalf("answer count = %d, want 1", got)
	}
	if got := response[len(response)-4:]; string(got) != string(interceptIPv4) {
		t.Fatalf("A answer = %v, want %v", got, interceptIPv4)
	}
}

func TestFixedDNSAnswerReturnsIPv6InterceptAddress(t *testing.T) {
	query := dnsQuery("allowed.test", 28)
	response, err := fixedDNSAnswer(query)
	if err != nil {
		t.Fatalf("fixedDNSAnswer() error = %v", err)
	}
	if got := binary.BigEndian.Uint16(response[len(response)-18 : len(response)-16]); got != 16 {
		t.Fatalf("AAAA rdlength = %d, want 16", got)
	}
	if got := response[len(response)-16:]; string(got) != string(interceptIPv6) {
		t.Fatalf("AAAA answer = %v, want %v", got, interceptIPv6)
	}
}

func dnsQuery(name string, qtype uint16) []byte {
	msg := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	for _, label := range splitDNSName(name) {
		msg = append(msg, byte(len(label)))
		msg = append(msg, label...)
	}
	msg = append(msg, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return msg
}

func splitDNSName(name string) []string {
	var labels []string
	start := 0
	for i := 0; i <= len(name); i++ {
		if i == len(name) || name[i] == '.' {
			labels = append(labels, name[start:i])
			start = i + 1
		}
	}
	return labels
}

func testClientHello(serverName string) []byte {
	body := make([]byte, 0, 96)
	body = append(body, 0x03, 0x03)          // legacy version
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session id length
	body = append(body, 0, 2, 0x13, 0x01)    // cipher suites
	body = append(body, 1, 0)                // compression methods
	if serverName != "" {
		sni := make([]byte, 0, len(serverName)+5)
		sni = append(sni, 0, byte(len(serverName)+3))  // server_name_list length
		sni = append(sni, 0, 0, byte(len(serverName))) // host_name + length
		sni = append(sni, serverName...)
		ext := make([]byte, 0, len(sni)+4)
		ext = append(ext, 0, 0, byte(len(sni)>>8), byte(len(sni)))
		ext = append(ext, sni...)
		body = append(body, byte(len(ext)>>8), byte(len(ext)))
		body = append(body, ext...)
	} else {
		body = append(body, 0, 0)
	}

	handshake := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	record := append([]byte{22, 3, 3, byte(len(handshake) >> 8), byte(len(handshake))}, handshake...)
	return record
}

type testAddrConn struct{ addr string }

func (c testAddrConn) Read([]byte) (int, error)         { return 0, nil }
func (c testAddrConn) Write([]byte) (int, error)        { return 0, nil }
func (c testAddrConn) Close() error                     { return nil }
func (c testAddrConn) LocalAddr() net.Addr              { return testAddr(c.addr) }
func (c testAddrConn) RemoteAddr() net.Addr             { return testAddr("127.0.0.1:1") }
func (c testAddrConn) SetDeadline(time.Time) error      { return nil }
func (c testAddrConn) SetReadDeadline(time.Time) error  { return nil }
func (c testAddrConn) SetWriteDeadline(time.Time) error { return nil }

type testAddr string

func (a testAddr) Network() string { return "tcp" }
func (a testAddr) String() string  { return string(a) }
