package cli

import (
	"fmt"

	"github.com/nocktechnologies/nocklock/internal/fence/fs/landlock"
)

func confinedUnixSocketPolicy(abi int, detectErr error, allow bool) (bool, string, error) {
	if detectErr == nil && abi >= landlock.MinUnixSocketABI {
		return true, "", nil
	}

	reason := "Landlock is unavailable"
	if detectErr != nil {
		reason = fmt.Sprintf("Landlock capability detection failed: %v", detectErr)
	} else if abi > 0 {
		reason = fmt.Sprintf("Landlock ABI v%d is below required ABI v%d", abi, landlock.MinUnixSocketABI)
	}
	if !allow {
		return false, "", fmt.Errorf("CONFINED egress cannot block pathname and abstract Unix sockets: %s; upgrade to Landlock ABI v%d or pass --allow-unix-sockets to explicitly accept local socket reachability", reason, landlock.MinUnixSocketABI)
	}
	return false, fmt.Sprintf("--allow-unix-sockets explicitly permits access to user-accessible Unix sockets because CONFINED mode cannot enforce full Unix-socket isolation (%s)", reason), nil
}
