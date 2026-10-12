package network

import (
	"net"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
)

// TestProxyStartOnServesHandedListener: the proxy serves exactly the listener it
// was given (no rebind), and refuses a second start.
func TestProxyStartOnServesHandedListener(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	p := NewProxyServer(config.NetworkConfig{}, nil, "s1")
	addr, err := p.StartOn(ln)
	if err != nil {
		t.Fatalf("StartOn: %v", err)
	}
	defer p.Stop()
	if addr != ln.Addr().String() {
		t.Errorf("addr = %s, want the handed listener %s", addr, ln.Addr())
	}
	if _, err := p.StartOn(ln); err == nil {
		t.Error("second StartOn must be refused")
	}
}
