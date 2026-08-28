package cli

import "fmt"

// WrapFlags holds the NockLock flags parsed from wrap command args.
// These appear before the "--" separator and are consumed by NockLock,
// not forwarded to the child process.
type WrapFlags struct {
	AllowPrivateRanges bool // --allow-private-ranges: permit RFC1918/loopback connections
	DryRun             bool // --dry-run: validate config without starting fences or child process
	Profile            string
	// NetFence opts into a kernel-enforced network egress fence. "" (default)
	// keeps the existing userspace-proxy posture unchanged; "netns" selects the
	// privileged-helper network-namespace default-drop floor (Linux only).
	NetFence string
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

	for i := 0; i < len(nockArgs); i++ {
		a := nockArgs[i]
		switch a {
		case "--allow-unfenced":
			return WrapFlags{}, nil, fmt.Errorf("--allow-unfenced has been removed: NockLock now fails closed when the network fence is unavailable")
		case "--allow-private-ranges":
			flags.AllowPrivateRanges = true
		case "--dry-run":
			flags.DryRun = true
		case "--profile":
			if i+1 >= len(nockArgs) {
				return WrapFlags{}, nil, fmt.Errorf("--profile requires a profile name")
			}
			i++
			flags.Profile = nockArgs[i]
		case "--net-fence":
			if i+1 >= len(nockArgs) {
				return WrapFlags{}, nil, fmt.Errorf("--net-fence requires a value (netns)")
			}
			i++
			if err := setNetFence(&flags, nockArgs[i]); err != nil {
				return WrapFlags{}, nil, err
			}
		default:
			if value, ok := splitWrapFlagValue(a, "--profile="); ok {
				if value == "" {
					return WrapFlags{}, nil, fmt.Errorf("--profile requires a profile name")
				}
				flags.Profile = value
				continue
			}
			if value, ok := splitWrapFlagValue(a, "--net-fence="); ok {
				if err := setNetFence(&flags, value); err != nil {
					return WrapFlags{}, nil, err
				}
				continue
			}
			return WrapFlags{}, nil, fmt.Errorf("unknown nocklock flag %q (place child flags after --)", a)
		}
	}

	return flags, childArgs, nil
}

func allRecognizedWrapFlags(args []string) bool {
	if len(args) == 0 {
		return false
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch a {
		case "--allow-unfenced", "--allow-private-ranges", "--dry-run":
		case "--profile", "--net-fence":
			if i+1 >= len(args) {
				return false
			}
			i++
		default:
			_, isProfile := splitWrapFlagValue(a, "--profile=")
			_, isNetFence := splitWrapFlagValue(a, "--net-fence=")
			if !isProfile && !isNetFence {
				return false
			}
		}
	}
	return true
}

// setNetFence validates and records the --net-fence value. Only "netns" is
// recognized today; an unknown value is rejected rather than silently ignored, so
// a typo never degrades to the default (no fence).
func setNetFence(flags *WrapFlags, value string) error {
	switch value {
	case "netns":
		flags.NetFence = value
		return nil
	case "":
		return fmt.Errorf("--net-fence requires a value (netns)")
	default:
		return fmt.Errorf("unknown --net-fence value %q (supported: netns)", value)
	}
}

func splitWrapFlagValue(arg, prefix string) (string, bool) {
	if len(arg) < len(prefix) || arg[:len(prefix)] != prefix {
		return "", false
	}
	return arg[len(prefix):], true
}
