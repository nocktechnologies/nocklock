package cli

import (
	"fmt"

	"github.com/nocktechnologies/nocklock/internal/fence/fs/landlock"
)

func unixSocketBoundaryStatus(abi int, detectErr error) (string, string) {
	if detectErr != nil {
		return "unavailable", "landlock_abi_unavailable"
	}
	if abi < landlock.MinUnixSocketABI {
		return "unavailable", fmt.Sprintf("landlock_abi_%d_below_%d", abi, landlock.MinUnixSocketABI)
	}
	return "enforceable", ""
}

func unixSocketBoundaryMessage(abi int, detectErr error) string {
	status, reason := unixSocketBoundaryStatus(abi, detectErr)
	if status == "enforceable" {
		return fmt.Sprintf("Landlock ABI v%d supports pathname and abstract Unix-socket isolation.", abi)
	}
	if detectErr != nil {
		return fmt.Sprintf("Landlock ABI detection failed: %v; pathname and abstract Unix sockets remain reachable (reason=%s).", detectErr, reason)
	}
	return fmt.Sprintf("Landlock ABI v%d is below required ABI v%d; pathname and abstract Unix sockets remain reachable (reason=%s).", abi, landlock.MinUnixSocketABI, reason)
}

func confinedUnixSocketPolicy(abi int, detectErr error, require bool) (bool, string, error) {
	status, _ := unixSocketBoundaryStatus(abi, detectErr)
	if status == "enforceable" {
		return true, "", nil
	}

	boundary := unixSocketBoundaryMessage(abi, detectErr)
	if require {
		return false, "", fmt.Errorf("CONFINED egress cannot block pathname and abstract Unix sockets: %s; network.require_unix_socket_isolation is true", boundary)
	}
	return false, boundary, nil
}

func strictUnixSocketIsolationModeError(goos string, level egressLevel, require bool) error {
	if !require {
		return nil
	}
	if goos != "linux" || level != egressLevelConfined {
		return fmt.Errorf("network.require_unix_socket_isolation requires Linux CONFINED egress; detected %s with egress level %s", goos, level)
	}
	return nil
}
