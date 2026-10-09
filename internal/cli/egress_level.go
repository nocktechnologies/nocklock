package cli

import (
	"fmt"

	"github.com/nocktechnologies/nocklock/internal/config"
)

type egressLevel string

const (
	egressLevelKernel      egressLevel = "KERNEL"
	egressLevelConfined    egressLevel = "CONFINED"
	egressLevelAdvisory    egressLevel = "ADVISORY"
	egressLevelOff         egressLevel = "OFF"
	egressLevelUnreachable egressLevel = "UNREACHABLE"
)

// effectiveEgressLevel reports the network boundary a wrap invocation can
// provide from its platform and configured enforcement layers.
func effectiveEgressLevel(goos, netFence string, allowAll, syscallEnforced, fsInterposer bool) egressLevel {
	if allowAll {
		return egressLevelOff
	}
	if netFence == "netns" {
		if goos == "linux" {
			return egressLevelKernel
		}
		return egressLevelUnreachable
	}
	if goos == "linux" && syscallEnforced {
		if fsInterposer {
			return egressLevelConfined
		}
		return egressLevelUnreachable
	}
	return egressLevelAdvisory
}

func egressLevelMeetsRequirement(level egressLevel) bool {
	return level == egressLevelKernel || level == egressLevelConfined
}

// lookbackLevelError refuses look-back rules unless egress is CONFINED. At
// ADVISORY a client that ignores HTTP_PROXY reaches any host, and the netns
// path runs its proxy without the signing logger, so the rule could not hold.
func lookbackLevelError(rules []config.LookbackRule, level egressLevel, goos string) error {
	if len(rules) == 0 || level == egressLevelConfined {
		return nil
	}
	fix := "run on Linux with the default proxy mode, syscall enforcement and the filesystem interposer enabled, and network.allow_all = false"
	if goos != "linux" {
		fix = "look-back rules are Linux-only (macOS cannot reach CONFINED egress)"
	}
	return fmt.Errorf("network.lookback rules require effective egress level CONFINED, but it is %s; %s", level, fix)
}

func egressRequirementMessage(level egressLevel, goos string) string {
	fix := "use --net-fence=netns on Linux"
	switch level {
	case egressLevelOff:
		if goos == "linux" {
			fix = "set network.allow and network.allow_all = false, then use --net-fence=netns on Linux"
		} else {
			fix = "set network.allow and network.allow_all = false; macOS cannot provide enforced egress today, so run on Linux with --net-fence=netns"
		}
	case egressLevelUnreachable:
		if goos == "linux" {
			fix = "enable the Linux filesystem interposer for the proxy bridge, or use --net-fence=netns on Linux"
		} else {
			fix = "macOS cannot provide enforced egress today; run on Linux with --net-fence=netns"
		}
	case egressLevelAdvisory:
		if goos == "linux" {
			fix = "use --net-fence=netns on Linux, or enable Linux syscall enforcement and the filesystem interposer for CONFINED proxy mode"
		} else {
			fix = "macOS cannot provide enforced egress today; run on Linux with --net-fence=netns"
		}
	}
	return fmt.Sprintf("effective egress level is %s; %s", level, fix)
}

func egressBanner(level egressLevel, domainCount int) string {
	switch level {
	case egressLevelKernel:
		return fmt.Sprintf("NockLock: network fence active — %d domain(s), KERNEL-enforced (netns)", domainCount)
	case egressLevelConfined:
		return fmt.Sprintf("NockLock: network fence active — %d domain(s), CONFINED (syscall fence; proxy bridge only)", domainCount)
	case egressLevelAdvisory:
		return fmt.Sprintf("NockLock: WARNING: network fence is ADVISORY — userspace proxy only, configured allowlist has %d domain(s); a client that ignores HTTP_PROXY can reach any host", domainCount)
	case egressLevelOff:
		return "NockLock: WARNING: network fence is OFF — allow_all = true; the agent can reach any host"
	case egressLevelUnreachable:
		return "NockLock: fatal: network egress is UNREACHABLE — syscall enforcement restricts proxy-mode children to Unix sockets, but the filesystem interposer proxy bridge is disabled"
	default:
		return fmt.Sprintf("NockLock: network egress level is unknown (%q)", level)
	}
}
