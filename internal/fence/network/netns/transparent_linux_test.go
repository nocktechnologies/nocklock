//go:build linux

package netns

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func TestParseClientHelloSNI(t *testing.T) {
	record := testClientHello("Api.Allowed.test")
	host, complete, err := parseClientHelloSNI(record[5:])
	if err != nil {
		t.Fatalf("parseClientHelloSNI() error: %v", err)
	}
	if !complete || host != "api.allowed.test" {
		t.Fatalf("parseClientHelloSNI() = (%q, %t), want (api.allowed.test, true)", host, complete)
	}
}

func TestParseClientHelloWithoutSNIRejectsDirectIP(t *testing.T) {
	record := testClientHello("")
	_, complete, err := parseClientHelloSNI(record[5:])
	if !complete || err == nil {
		t.Fatalf("parseClientHelloSNI() = complete=%t err=%v, want complete missing-SNI rejection", complete, err)
	}
}

func TestReadHTTPHeaderUsesHostAndPreservesExactHeader(t *testing.T) {
	const wire = "GET /release HTTP/1.1\r\nHost: packages.allowed.test\r\nX-Trace: exact\r\n\r\nbody"
	header, host, err := readHTTPHeader(strings.NewReader(wire))
	if err != nil {
		t.Fatalf("readHTTPHeader() error: %v", err)
	}
	if host != "packages.allowed.test" {
		t.Fatalf("host = %q, want packages.allowed.test", host)
	}
	if string(header) != strings.TrimSuffix(wire, "body") {
		t.Fatalf("header was rewritten: %q", header)
	}
}

func TestFixedDNSResponseAnswersEveryNameWithInterceptAddress(t *testing.T) {
	query := testDNSQuery("blocked.example", 1)
	response, ok := fixedDNSResponse(query)
	if !ok {
		t.Fatal("fixedDNSResponse() rejected a valid A query")
	}
	if got := binary.BigEndian.Uint16(response[6:]); got != 1 {
		t.Fatalf("answer count = %d, want 1", got)
	}
	if !bytes.HasSuffix(response, []byte{127, 0, 0, 1}) {
		t.Fatalf("A response did not use intercept address: %x", response)
	}

	query = testDNSQuery("blocked.example", 28)
	response, ok = fixedDNSResponse(query)
	if !ok || !bytes.HasSuffix(response, append(make([]byte, 15), 1)) {
		t.Fatalf("AAAA response did not use ::1 intercept address: %x", response)
	}
}

func testClientHello(serverName string) []byte {
	body := make([]byte, 34)
	body[0], body[1] = 0x03, 0x03
	body = append(body, 0)                // session id length
	body = append(body, 0, 2, 0x13, 0x01) // one cipher suite
	body = append(body, 1, 0)             // null compression
	extensions := []byte{}
	if serverName != "" {
		name := []byte(serverName)
		sni := make([]byte, 5+len(name))
		binary.BigEndian.PutUint16(sni, uint16(3+len(name)))
		sni[2] = 0
		binary.BigEndian.PutUint16(sni[3:], uint16(len(name)))
		copy(sni[5:], name)
		extension := make([]byte, 4+len(sni))
		binary.BigEndian.PutUint16(extension, 0)
		binary.BigEndian.PutUint16(extension[2:], uint16(len(sni)))
		copy(extension[4:], sni)
		extensions = append(extensions, extension...)
	}
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)
	handshake := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)
	record := []byte{22, 3, 1, byte(len(handshake) >> 8), byte(len(handshake))}
	return append(record, handshake...)
}

func testDNSQuery(name string, qtype uint16) []byte {
	query := []byte{0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	for _, label := range strings.Split(name, ".") {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, byte(qtype>>8), byte(qtype), 0, 1)
	return query
}
