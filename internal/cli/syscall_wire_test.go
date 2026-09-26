package cli

import (
	"encoding/json"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/fence/syscallfence"
)

func TestSyscallEnforcementMode(t *testing.T) {
	cases := map[string]syscallfence.Mode{
		"required":  syscallfence.ModeRequired,
		"preferred": syscallfence.ModePreferred,
		"":          syscallfence.ModeRequired, // empty defaults fail closed
		"off":       syscallfence.ModeOff,
		"garbage":   syscallfence.ModeOff, // unknown -> off (no behaviour change)
	}
	for in, want := range cases {
		if got := syscallEnforcementMode(in); got != want {
			t.Errorf("syscallEnforcementMode(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestBuildSyscallPolicy_OffIsNoOp(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Syscall.Enforcement = "off"
	if _, ok := buildSyscallPolicy(&cfg, networkFenceProxy); ok {
		t.Error("enforcement=off must return ok=false (zero behaviour change)")
	}
}

func TestBuildSyscallPolicy_AbsentTableDefaultsRequired(t *testing.T) {
	// An absent [syscall] block leaves Enforcement empty; the wiring must treat
	// empty as required and install fail-closed on Linux.
	cfg := config.Config{}
	policy, ok := buildSyscallPolicy(&cfg, networkFenceProxy)
	if !ok {
		t.Fatal("empty enforcement should default to required -> ok=true")
	}
	if policy.Mode != syscallfence.ModeRequired {
		t.Errorf("policy.Mode = %q, want required", policy.Mode)
	}
}

func TestBuildSyscallPolicy_MapsAllFields(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Network.AllowAll = true
	cfg.Syscall.Enforcement = "required"
	cfg.Syscall.AllowNamespaces = true
	cfg.Syscall.SocketFamilies = []string{"unix", "inet"}
	cfg.Syscall.ExtraDeny = []string{"chroot"}

	policy, ok := buildSyscallPolicy(&cfg, networkFenceOff)
	if !ok {
		t.Fatal("required enforcement should yield ok=true")
	}
	if policy.Mode != syscallfence.ModeRequired {
		t.Errorf("Mode = %q, want required", policy.Mode)
	}
	if !policy.AllowNamespaces {
		t.Error("AllowNamespaces not mapped")
	}
	if len(policy.AllowedSocketFamilies) != 2 {
		t.Errorf("AllowedSocketFamilies = %v, want [unix inet]", policy.AllowedSocketFamilies)
	}
	if len(policy.ExtraDenySyscalls) != 1 || policy.ExtraDenySyscalls[0] != "chroot" {
		t.Errorf("ExtraDenySyscalls = %v, want [chroot]", policy.ExtraDenySyscalls)
	}
}

func TestWrapNetworkFenceMode(t *testing.T) {
	// The security-critical mapping wrap.go feeds to buildSyscallPolicy. netns
	// MUST win over allow_all: otherwise a netns child would be narrowed back to
	// unix-only and lose all allowlisted egress (N10710).
	cases := []struct {
		useNetns bool
		allowAll bool
		want     networkFenceMode
	}{
		{useNetns: true, allowAll: false, want: networkFenceNetns},
		{useNetns: true, allowAll: true, want: networkFenceNetns}, // netns wins
		{useNetns: false, allowAll: true, want: networkFenceOff},
		{useNetns: false, allowAll: false, want: networkFenceProxy},
	}
	for _, c := range cases {
		if got := wrapNetworkFenceMode(c.useNetns, c.allowAll); got != c.want {
			t.Errorf("wrapNetworkFenceMode(useNetns=%t, allowAll=%t) = %d, want %d",
				c.useNetns, c.allowAll, got, c.want)
		}
	}
}

func TestBuildSyscallPolicy_ProxyModeRestrictsSocketsToUnix(t *testing.T) {
	// The userspace-proxy restricted mode narrows the child to unix sockets so
	// it cannot open raw IP sockets that bypass the proxy.
	cfg := config.DefaultConfig()
	cfg.Network.AllowAll = false
	cfg.Syscall.SocketFamilies = []string{"unix", "inet", "inet6"}
	policy, ok := buildSyscallPolicy(&cfg, networkFenceProxy)
	if !ok {
		t.Fatal("default syscall policy should be active")
	}
	if len(policy.AllowedSocketFamilies) != 1 || policy.AllowedSocketFamilies[0] != "unix" {
		t.Fatalf("proxy-mode syscall policy must allow only unix sockets, got %v", policy.AllowedSocketFamilies)
	}
}

func TestBuildSyscallPolicy_NetnsModeAllowsInetFamilies(t *testing.T) {
	// Under the netns egress floor the kernel default-drop plus transparent
	// proxy is the enforcement boundary, so the child MUST keep its configured
	// inet/inet6 families — narrowing to unix-only would block allowlisted
	// egress (N10710).
	cfg := config.DefaultConfig()
	cfg.Network.AllowAll = false
	cfg.Syscall.SocketFamilies = []string{"unix", "inet", "inet6"}
	policy, ok := buildSyscallPolicy(&cfg, networkFenceNetns)
	if !ok {
		t.Fatal("default syscall policy should be active")
	}
	if len(policy.AllowedSocketFamilies) != 3 {
		t.Fatalf("netns-mode syscall policy must preserve inet/inet6 families, got %v", policy.AllowedSocketFamilies)
	}
	var haveInet, haveInet6 bool
	for _, fam := range policy.AllowedSocketFamilies {
		switch fam {
		case "inet":
			haveInet = true
		case "inet6":
			haveInet6 = true
		}
	}
	if !haveInet || !haveInet6 {
		t.Fatalf("netns-mode syscall policy must allow inet and inet6, got %v", policy.AllowedSocketFamilies)
	}
}

func TestBuildSyscallPolicy_AllowAllPreservesConfiguredSocketFamilies(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Network.AllowAll = true
	cfg.Syscall.SocketFamilies = []string{"unix", "inet", "inet6"}
	policy, ok := buildSyscallPolicy(&cfg, networkFenceOff)
	if !ok {
		t.Fatal("default syscall policy should be active")
	}
	if len(policy.AllowedSocketFamilies) != 3 {
		t.Fatalf("network allow_all=true should preserve configured socket families, got %v", policy.AllowedSocketFamilies)
	}
}

func TestMarshalSyscallPolicy_RoundTrips(t *testing.T) {
	in := syscallfence.Policy{
		AllowedSocketFamilies: []string{"unix", "inet", "inet6"},
		AllowNamespaces:       false,
		ExtraDenySyscalls:     []string{"acct"},
		Mode:                  syscallfence.ModeRequired,
	}
	encoded, err := marshalSyscallPolicy(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out syscallfence.Policy
	if err := json.Unmarshal([]byte(encoded), &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out.Mode != in.Mode || out.AllowNamespaces != in.AllowNamespaces {
		t.Errorf("round-trip mismatch: in=%+v out=%+v", in, out)
	}
	if len(out.AllowedSocketFamilies) != 3 || len(out.ExtraDenySyscalls) != 1 {
		t.Errorf("round-trip lost slice data: %+v", out)
	}
}
