package cli

import (
	"encoding/json"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/fence/syscallfence"
)

// syscallEnforcementMode resolves the configured enforcement string to a Mode.
// An empty value defaults to "preferred" (install where supported; do not fail
// closed on a kernel that lacks seccomp).
func syscallEnforcementMode(raw string) syscallfence.Mode {
	switch raw {
	case "required":
		return syscallfence.ModeRequired
	case "off":
		return syscallfence.ModeOff
	case "preferred", "":
		return syscallfence.ModePreferred
	default:
		// Unknown values are rejected by config validation before we get here;
		// treat anything else conservatively as off (no behaviour change).
		return syscallfence.ModeOff
	}
}

// buildSyscallPolicy maps the [syscall] config block to a syscallfence.Policy.
// It returns (policy, true) when the fence should be installed, or (_, false)
// when enforcement is off — in which case NO syscall env is set and there is
// ZERO behaviour change (the opt-in discipline).
func buildSyscallPolicy(cfg *config.Config) (syscallfence.Policy, bool) {
	mode := syscallEnforcementMode(cfg.Syscall.Enforcement)
	if mode == syscallfence.ModeOff {
		return syscallfence.Policy{}, false
	}
	return syscallfence.Policy{
		AllowedSocketFamilies: append([]string(nil), cfg.Syscall.SocketFamilies...),
		AllowNamespaces:       cfg.Syscall.AllowNamespaces,
		ExtraDenySyscalls:     append([]string(nil), cfg.Syscall.ExtraDeny...),
		Mode:                  mode,
	}, true
}

// marshalSyscallPolicy serializes the policy for the NOCKLOCK_SYSCALL_POLICY env
// var consumed by the __landlock-exec shim.
func marshalSyscallPolicy(p syscallfence.Policy) (string, error) {
	data, err := json.Marshal(p)
	if err != nil {
		return "", err
	}
	return string(data), nil
}
