package cli

import (
	"encoding/json"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/fence/syscallfence"
)

// syscallEnforcementMode resolves the configured enforcement string to a Mode.
// An empty value defaults to "required" so absent legacy config still fails
// closed on a kernel that lacks seccomp.
func syscallEnforcementMode(raw string) syscallfence.Mode {
	switch raw {
	case "required":
		return syscallfence.ModeRequired
	case "off":
		return syscallfence.ModeOff
	case "preferred":
		return syscallfence.ModePreferred
	case "":
		return syscallfence.ModeRequired
	default:
		// Unknown values are rejected by config validation before we get here;
		// treat anything else conservatively as off (no behaviour change).
		return syscallfence.ModeOff
	}
}

// networkFenceMode is the network fence active for this wrap invocation.
// buildSyscallPolicy takes it EXPLICITLY rather than inferring "a fence is on"
// from network.allow_all, because the netns egress fence and the userspace
// proxy need OPPOSITE socket-family policies (N10710).
type networkFenceMode int

const (
	// networkFenceOff means no network fence (network.allow_all = true): the
	// child keeps its configured socket families.
	networkFenceOff networkFenceMode = iota
	// networkFenceProxy is the userspace HTTP(S) proxy allowlist. The child is
	// narrowed to unix sockets so it cannot open raw IP sockets that bypass the
	// proxy.
	networkFenceProxy
	// networkFenceNetns is the kernel netns default-drop plus transparent proxy.
	// The child MUST be able to create inet/inet6 sockets — the kernel egress
	// floor, not a socket-family denial, is the enforcement boundary — so its
	// configured families are preserved.
	networkFenceNetns
)

// wrapNetworkFenceMode maps wrap's runtime network selection to the fence mode
// buildSyscallPolicy consumes. netns wins over allow_all (the netns path rejects
// allow_all at run time anyway), and a fenced allowlist with neither is the
// userspace proxy. Extracted so this security-critical mapping is unit-tested:
// a reorder that let allow_all shadow netns would silently narrow the netns
// child back to unix-only and block all allowlisted egress (N10710).
func wrapNetworkFenceMode(useNetns, allowAll bool) networkFenceMode {
	switch {
	case useNetns:
		return networkFenceNetns
	case allowAll:
		return networkFenceOff
	default:
		return networkFenceProxy
	}
}

// buildSyscallPolicy maps the [syscall] config block to a syscallfence.Policy.
// It returns (policy, true) when the fence should be installed, or (_, false)
// when enforcement is off — in which case NO syscall env is set and there is
// ZERO behaviour change (the opt-in discipline). netFence selects the child's
// socket-family policy per the network mode in effect.
func buildSyscallPolicy(cfg *config.Config, netFence networkFenceMode) (syscallfence.Policy, bool) {
	mode := syscallEnforcementMode(cfg.Syscall.Enforcement)
	if mode == syscallfence.ModeOff {
		return syscallfence.Policy{}, false
	}
	socketFamilies := append([]string(nil), cfg.Syscall.SocketFamilies...)
	// Only the userspace-proxy mode narrows the child to unix sockets; netns
	// (kernel floor is the boundary) and allow_all (no fence) keep the
	// configured families (see networkFenceMode).
	if netFence == networkFenceProxy {
		socketFamilies = []string{"unix"}
	}
	return syscallfence.Policy{
		AllowedSocketFamilies: socketFamilies,
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
