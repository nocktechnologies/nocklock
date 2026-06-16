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
		"":          syscallfence.ModePreferred, // empty defaults to preferred
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
	if _, ok := buildSyscallPolicy(&cfg); ok {
		t.Error("enforcement=off must return ok=false (zero behaviour change)")
	}
}

func TestBuildSyscallPolicy_AbsentTableDefaultsPreferred(t *testing.T) {
	// An absent [syscall] block leaves Enforcement empty; the wiring must treat
	// empty as preferred and install (the opt-in default is on-where-supported).
	cfg := config.Config{}
	policy, ok := buildSyscallPolicy(&cfg)
	if !ok {
		t.Fatal("empty enforcement should default to preferred -> ok=true")
	}
	if policy.Mode != syscallfence.ModePreferred {
		t.Errorf("policy.Mode = %q, want preferred", policy.Mode)
	}
}

func TestBuildSyscallPolicy_MapsAllFields(t *testing.T) {
	cfg := config.DefaultConfig()
	cfg.Syscall.Enforcement = "required"
	cfg.Syscall.AllowNamespaces = true
	cfg.Syscall.SocketFamilies = []string{"unix", "inet"}
	cfg.Syscall.ExtraDeny = []string{"chroot"}

	policy, ok := buildSyscallPolicy(&cfg)
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
