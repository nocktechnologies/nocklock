package config

import (
	"fmt"
	"io/fs"
	"net/url"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
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
	for _, p := range cfg.Secrets.ScanPaths {
		if !fs.ValidPath(filepath.ToSlash(p)) || filepath.IsAbs(p) {
			errs = append(errs, ValidationError{Field: "secrets.scan_paths", Message: "use project-relative paths without '..' or empty components", Severity: "error"})
		}
	}
	for _, name := range cfg.Secrets.ScanEnvAllow {
		if !envScanName.MatchString(name) {
			errs = append(errs, ValidationError{Field: "secrets.scan_env_allow", Message: "use exact environment names (letters, digits and underscores), not globs or values", Severity: "error"})
		}
	}

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

	// The v0.5 macOS escape hatch was removed in v0.6.0; false/absent still loads.
	if cfg.Filesystem.MacOSAllowUnfenced {
		errs = append(errs, ValidationError{
			Field:    "filesystem.macos_allow_unfenced",
			Message:  "macos_allow_unfenced was removed in v0.6.0; NockLock now always refuses to start unfenced on macOS; restore sandbox-exec or remove the key",
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

	if cfg.Audit.Forward.Enabled {
		f := cfg.Audit.Forward
		u, err := url.Parse(f.URL)
		validURL := false
		if err == nil && u != nil && u.Host != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && (u.Path == "" || u.Path == "/") {
			loopback := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"
			validURL = u.Scheme == "https" || (u.Scheme == "http" && loopback)
		}
		if !validURL {
			errs = append(errs, ValidationError{Field: "audit.forward.url", Message: "enabled forwarding requires a Command base URL (HTTPS, or HTTP on localhost) without a path, query, fragment, or credentials", Severity: "error"})
		}
		if f.APIKeyEnv != ForwardKeyEnv {
			errs = append(errs, ValidationError{Field: "audit.forward.api_key_env", Message: fmt.Sprintf("enabled forwarding requires api_key_env = %q; use a dedicated operator credential", ForwardKeyEnv), Severity: "error"})
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

	// filesystem.allow_rw entries must not contain path traversal.
	for _, p := range cfg.Filesystem.AllowRW {
		if strings.TrimSpace(p) == "" {
			errs = append(errs, ValidationError{
				Field:    "filesystem.allow_rw",
				Message:  "entries must not be empty",
				Severity: "error",
			})
			continue
		}
		if containsTraversal(p) {
			errs = append(errs, ValidationError{
				Field:    "filesystem.allow_rw",
				Message:  fmt.Sprintf("entry %q contains path traversal (\"../\")", p),
				Severity: "error",
			})
		}
	}

	errs = append(errs, validateLookback(cfg.Network.Lookback)...)

	return errs
}

// lookbackBlockedTypes are the event types the code writes with blocked=1. A
// look-back trigger is a blocked row, so an `on` outside this set could never
// trip and must not load as a silent no-op.
var lookbackBlockedTypes = []string{"file_blocked", "secret_blocked", "network_blocked", "network_error", "filesystem_fence_state", "session_end"}

func validateLookback(rules []LookbackRule) []ValidationError {
	var errs []ValidationError
	bad := func(i int, key, msg string) {
		errs = append(errs, ValidationError{Field: fmt.Sprintf("network.lookback[%d].%s", i, key), Message: msg, Severity: "error"})
	}
	seen := map[string]bool{}
	for i, r := range rules {
		if strings.TrimSpace(r.Name) == "" {
			bad(i, "name", "must not be empty; the name is cited in the signed denial rows")
		} else if seen[r.Name] {
			bad(i, "name", fmt.Sprintf("duplicate rule name %q", r.Name))
		}
		seen[r.Name] = true
		switch {
		case r.On == LookbackTriggerFileBlocked:
		case slices.Contains(lookbackBlockedTypes, r.On):
			bad(i, "on", fmt.Sprintf("%q is not supported yet: this release accepts only %q", r.On, LookbackTriggerFileBlocked))
		default:
			bad(i, "on", fmt.Sprintf("%q can never trip: a trigger is an event written with blocked=1, one of %s", r.On, strings.Join(lookbackBlockedTypes, ", ")))
		}
		if r.Then != LookbackActionDenyEgress {
			bad(i, "then", fmt.Sprintf("invalid value %q: must be %q", r.Then, LookbackActionDenyEgress))
		}
		if r.Within != "" {
			if d, err := time.ParseDuration(r.Within); err != nil || d <= 0 {
				bad(i, "within", fmt.Sprintf("invalid value %q: must be a positive duration such as \"10m\", or omitted for the rest of the session", r.Within))
			}
		}
	}
	return errs
}

// WithinDuration returns the rule's window; zero means the rest of the session.
func (r LookbackRule) WithinDuration() time.Duration {
	d, _ := time.ParseDuration(r.Within)
	return d
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

	for _, r := range cfg.Network.Lookback {
		window := r.Within
		if window == "" {
			window = "session"
		}
		fmt.Fprintf(&b, "  Look-back rule %q: %s within %s -> %s\n", r.Name, r.On, window, r.Then)
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
	if len(cfg.Filesystem.AllowRW) > 0 {
		fmt.Fprintf(&b, " allow_rw=%d path(s)", len(cfg.Filesystem.AllowRW))
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
		fmt.Fprintf(&b, "  Syscall: enforcement=%s allow_namespaces=%t socket_families=%d (Linux seccomp; macOS hardened SBPL)\n",
			syscallEnforcement, cfg.Syscall.AllowNamespaces, len(cfg.Syscall.SocketFamilies))
	}

	// Secrets
	fmt.Fprintf(&b, "  Secrets: block=%d pattern(s), pass=%d pattern(s)\n",
		len(cfg.Secrets.Block), len(cfg.Secrets.Pass))
	if cfg.Secrets.ScanEnv || len(cfg.Secrets.ScanPaths) > 0 {
		fmt.Fprintf(&b, "  Secret preflight: environment=%t paths=%d env_exceptions=%d (required before launch)\n",
			cfg.Secrets.ScanEnv, len(cfg.Secrets.ScanPaths), len(cfg.Secrets.ScanEnvAllow))
	}

	// Cloud
	if cfg.Cloud.Enabled {
		b.WriteString("  Cloud sync: enabled\n")
	} else {
		b.WriteString("  Cloud sync: disabled\n")
	}

	b.WriteString("  Default policy: DENY")

	return b.String()
}

var envScanName = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// containsTraversal reports whether a path contains ".." components.
func containsTraversal(p string) bool {
	for _, part := range strings.Split(p, "/") {
		if part == ".." {
			return true
		}
	}
	return false
}
