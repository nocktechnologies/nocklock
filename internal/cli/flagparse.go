package cli

import "fmt"

// WrapFlags holds the NockLock flags parsed from wrap command args.
// These appear before the "--" separator and are consumed by NockLock,
// not forwarded to the child process.
type WrapFlags struct {
	AllowUnfenced      bool // --allow-unfenced: degrade gracefully if proxy fails (not recommended)
	AllowPrivateRanges bool // --allow-private-ranges: permit RFC1918/loopback connections
}

// parseWrapFlags splits wrap command args into NockLock flags and child args.
//
// Since wrapCmd has DisableFlagParsing=true, cobra passes all tokens as raw
// args. NockLock flags appear before the first "--" separator; everything after
// "--" is the child command and its arguments.
//
// If no "--" is present, all args are treated as child args (no NockLock flags).
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
		// No "--": no nocklock flags, all args are the child command.
		childArgs = args
	} else {
		nockArgs = args[:separatorIdx]
		if separatorIdx+1 < len(args) {
			childArgs = args[separatorIdx+1:]
		}
	}

	for _, a := range nockArgs {
		switch a {
		case "--allow-unfenced":
			flags.AllowUnfenced = true
		case "--allow-private-ranges":
			flags.AllowPrivateRanges = true
		default:
			return WrapFlags{}, nil, fmt.Errorf("unknown nocklock flag %q (place child flags after --)", a)
		}
	}

	return flags, childArgs, nil
}
