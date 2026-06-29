package config

import (
	"fmt"
	"strings"
)

// ValidationError describes a single validation failure with a severity level.
type ValidationError struct {
	Field    string // TOML field path, e.g. "filesystem.mode"
	Message  string // human-readable description
	Severity string // "error" or "warning"
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("%s: %s", e.Field, e.Message)
}

// Validate performs semantic validation on a parsed Config.
// It returns a slice of ValidationErrors (empty means valid).
// Callers must check for any entry with Severity == "error" to determine
// whether the config should be rejected.
func Validate(cfg *Config) []ValidationError {
	var errs []ValidationError

	// filesystem.mode must be one of the known values.
	switch cfg.Filesystem.Mode {
	case "read-write", "read-only", "":
		// valid
	default:
		errs = append(errs, ValidationError{
			Field:    "filesystem.mode",
			Message:  fmt.Sprintf("invalid value %q: must be \"read-write\", \"read-only\", or \"\"", cfg.Filesystem.Mode),
			Severity: "error",
		})
	}

	// logging.level must be a recognised level.
	switch cfg.Logging.Level {
	case "info", "debug", "warn", "error", "":
		// valid
	default:
		errs = append(errs, ValidationError{
			Field:    "logging.level",
			Message:  fmt.Sprintf("invalid value %q: must be \"info\", \"debug\", \"warn\", \"error\", or \"\"", cfg.Logging.Level),
			Severity: "error",
		})
	}

	// filesystem.linux_enforcement controls the Linux kernel-enforced Landlock
	// layer. Empty is accepted for old configs and defaults to "required".
	switch cfg.Filesystem.LinuxEnforcement {
	case "required", "preferred", "off", "":
		// valid
	default:
		errs = append(errs, ValidationError{
			Field:    "filesystem.linux_enforcement",
			Message:  fmt.Sprintf("invalid value %q: must be \"required\", \"preferred\", \"off\", or \"\"", cfg.Filesystem.LinuxEnforcement),
			Severity: "error",
		})
	}

	// syscall.enforcement controls the Linux seccomp-BPF syscall fence. Empty is
	// accepted (defaults to "required").
	switch cfg.Syscall.Enforcement {
	case "required", "preferred", "off", "":
		// valid
	default:
		errs = append(errs, ValidationError{
			Field:    "syscall.enforcement",
			Message:  fmt.Sprintf("invalid value %q: must be \"required\", \"preferred\", \"off\", or \"\"", cfg.Syscall.Enforcement),
			Severity: "error",
		})
	}

	// syscall.socket_families entries must be recognised address-family names.
	for _, fam := range cfg.Syscall.SocketFamilies {
		switch fam {
		case "unix", "local", "inet", "ipv4", "inet6", "ipv6", "netlink":
			// valid
		default:
			errs = append(errs, ValidationError{
				Field:    "syscall.socket_families",
				Message:  fmt.Sprintf("unknown socket family %q: must be one of unix, inet, inet6, netlink", fam),
				Severity: "error",
			})
		}
	}

	// cloud.enabled=true requires api_key.
	if cfg.Cloud.Enabled && cfg.Cloud.APIKey == "" {
		errs = append(errs, ValidationError{
			Field:    "cloud.api_key",
			Message:  "cloud.enabled is true but cloud.api_key is empty",
			Severity: "error",
		})
	}

	// filesystem.deny entries must not contain path traversal.
	for _, p := range cfg.Filesystem.Deny {
		if containsTraversal(p) {
			errs = append(errs, ValidationError{
				Field:    "filesystem.deny",
				Message:  fmt.Sprintf("entry %q contains path traversal (\"../\")", p),
				Severity: "error",
			})
		}
	}

	// filesystem.allow entries must not contain path traversal.
	for _, p := range cfg.Filesystem.Allow {
		if containsTraversal(p) {
			errs = append(errs, ValidationError{
				Field:    "filesystem.allow",
				Message:  fmt.Sprintf("entry %q contains path traversal (\"../\")", p),
				Severity: "error",
			})
		}
	}

	return errs
}

// EffectivePolicy returns a human-readable summary of the active policy.
func (cfg *Config) EffectivePolicy() string {
	var b strings.Builder

	b.WriteString("NockLock effective policy:\n")
	if cfg.ProfileName != "" {
		fmt.Fprintf(&b, "  Profile: %s (embedded base; project config overlays can only tighten)\n", cfg.ProfileName)
	}

	// Network
	privateRanges := "blocked"
	if cfg.Network.AllowPrivateRanges {
		privateRanges = "allowed"
	}
	if cfg.Network.AllowAll {
		b.WriteString("  Network: ALLOW ALL (allow_all = true)\n")
	} else {
		fmt.Fprintf(&b, "  Network: DENY (default) — %d allowed domain(s): %s; private_ranges=%s\n",
			len(cfg.Network.Allow),
			strings.Join(cfg.Network.Allow, ", "),
			privateRanges)
	}

	// Filesystem
	mode := cfg.Filesystem.Mode
	if mode == "" {
		mode = "read-write"
	}
	linuxEnforcement := cfg.Filesystem.LinuxEnforcement
	if linuxEnforcement == "" || linuxEnforcement == "preferred" {
		linuxEnforcement = "required"
	}
	root := cfg.Filesystem.Root
	if root == "" {
		root = "."
	}
	fmt.Fprintf(&b, "  Filesystem: root=%s mode=%s linux_enforcement=%s", root, mode, linuxEnforcement)
	if len(cfg.Filesystem.Deny) > 0 {
		fmt.Fprintf(&b, " deny=%d path(s)", len(cfg.Filesystem.Deny))
	}
	if cfg.Filesystem.Hardened {
		b.WriteString(" hardened=true")
	}
	b.WriteString("\n")

	// Syscall (Linux seccomp-BPF). Empty enforcement defaults to "required".
	syscallEnforcement := cfg.Syscall.Enforcement
	if syscallEnforcement == "" {
		syscallEnforcement = "required"
	}
	if syscallEnforcement == "off" {
		b.WriteString("  Syscall: off\n")
	} else {
		fmt.Fprintf(&b, "  Syscall: enforcement=%s allow_namespaces=%t socket_families=%d (Linux only)\n",
			syscallEnforcement, cfg.Syscall.AllowNamespaces, len(cfg.Syscall.SocketFamilies))
	}

	// Secrets
	fmt.Fprintf(&b, "  Secrets: block=%d pattern(s), pass=%d pattern(s)\n",
		len(cfg.Secrets.Block), len(cfg.Secrets.Pass))

	// Cloud
	if cfg.Cloud.Enabled {
		b.WriteString("  Cloud sync: enabled\n")
	} else {
		b.WriteString("  Cloud sync: disabled\n")
	}

	b.WriteString("  Default policy: DENY")

	return b.String()
}

// containsTraversal reports whether a path contains ".." components.
func containsTraversal(p string) bool {
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}
