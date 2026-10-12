package cli

import (
	"errors"
	"net"
	"strconv"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
)

// TestDoctorSeatbeltAdvisoryNeedsSandboxExec pins doctor to what wrap does: the
// SEATBELT floor exists only when sandbox-exec is usable, so a darwin host
// without it must still see the ADVISORY warning.
func TestDoctorSeatbeltAdvisoryNeedsSandboxExec(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Filesystem.Root = "."
	cfg.Network.AllowAll = false
	cfg.Network.Allow = []string{"example.com"}

	has := func(sandboxExec func() error) bool {
		caps := doctorCapabilities{goos: "darwin", sandboxExec: sandboxExec}
		for _, c := range sanityDoctorChecks(&cfg, "", caps) {
			if c.Name == "network-egress-advisory" {
				return true
			}
		}
		return false
	}
	if has(func() error { return nil }) {
		t.Error("sandbox-exec available with filesystem.root set: floor applies, no advisory expected")
	}
	if !has(func() error { return errors.New("sandbox-exec not found") }) {
		t.Error("sandbox-exec missing: wrap cannot apply the floor, doctor must warn ADVISORY")
	}
}

// TestReserveSeatbeltProxyListenersHoldsV6 covers the loopback-hold rule: the
// proxy's port is also held on [::1], and a taken [::1] port refuses.
func TestReserveSeatbeltProxyListenersHoldsV6(t *testing.T) {
	probe, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("IPv6 loopback unavailable: %v", err)
	}
	taken := probe.Addr().(*net.TCPAddr).Port
	defer probe.Close()

	if _, err := holdLoopbackV6(taken); err == nil {
		t.Fatalf("[::1]:%d is pre-bound; holdLoopbackV6 must refuse", taken)
	}

	proxy, hold, err := reserveSeatbeltProxyListeners()
	if err != nil {
		t.Fatalf("reserveSeatbeltProxyListeners: %v", err)
	}
	defer proxy.Close()
	if hold != nil {
		defer hold.Close()
	}
	port := strconv.Itoa(proxy.Addr().(*net.TCPAddr).Port)
	if second, err := net.Listen("tcp6", net.JoinHostPort("::1", port)); err == nil {
		second.Close()
		t.Errorf("[::1]:%s must stay held while the session runs", port)
	}
}
