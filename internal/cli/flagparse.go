package cli

import "fmt"

// WrapFlags holds the NockLock flags parsed from wrap command args.
// These appear before the "--" separator and are consumed by NockLock,
// not forwarded to the child process.
type WrapFlags struct {
	AllowPrivateRanges bool // --allow-private-ranges: permit RFC1918/loopback connections
	DryRun             bool // --dry-run: validate config without starting fences or child process
}

// parseWrapFlags splits wrap command args into NockLock flags and child args.
//
// Since wrapCmd has DisableFlagParsing=true, cobra passes all tokens as raw
// args. NockLock flags appear before the first "--" separator; everything after
// "--" is the child command and its arguments.
//
// If no "--" is present, all args are treated as child args unless every arg
// is a recognized NockLock flag. This allows `nocklock wrap --dry-run` while
// preserving the historical no-separator child-command behavior.
// An unrecognised token before "--" is an error.
func parseWrapFlags(args []string) (WrapFlags, []string, error) {
	var flags WrapFlags
	separatorIdx := -1

	for i, a := range args {
		if a == "--" {
			separatorIdx = i
			break
		}
	}

	// Everything before the separator (or all args if no separator) is the
	// nocklock flag region. Everything after is the child command.
	var nockArgs []string
	var childArgs []string

	if separatorIdx == -1 {
		// No "--": parse as NockLock flags only when every token is a known
		// NockLock flag. Otherwise, keep the historical behavior: all tokens
		// belong to the child command.
		if allRecognizedWrapFlags(args) {
			nockArgs = args
		} else {
			childArgs = args
		}
	} else {
		nockArgs = args[:separatorIdx]
		if separatorIdx+1 < len(args) {
			childArgs = args[separatorIdx+1:]
		}
	}

	for _, a := range nockArgs {
		switch a {
		case "--allow-unfenced":
			return WrapFlags{}, nil, fmt.Errorf("--allow-unfenced has been removed: NockLock now fails closed when the network fence is unavailable")
		case "--allow-private-ranges":
			flags.AllowPrivateRanges = true
		case "--dry-run":
			flags.DryRun = true
		default:
			return WrapFlags{}, nil, fmt.Errorf("unknown nocklock flag %q (place child flags after --)", a)
		}
	}

	return flags, childArgs, nil
}

func allRecognizedWrapFlags(args []string) bool {
	if len(args) == 0 {
		return false
	}
	for _, a := range args {
		switch a {
		case "--allow-unfenced", "--allow-private-ranges", "--dry-run":
		default:
			return false
		}
	}
	return true
}
