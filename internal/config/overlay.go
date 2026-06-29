package config

import (
	"fmt"
	"os"
	"strings"

	"github.com/BurntSushi/toml"
)

func restrictOverlay(base, overlay Config, fields map[string]bool) Config {
	cfg := overlay
	cfg.ProfileName = base.ProfileName

	if fields["filesystem.allow"] {
		cfg.Filesystem.Allow = intersectStrings(base.Filesystem.Allow, overlay.Filesystem.Allow)
	}
	if fields["filesystem.deny"] {
		cfg.Filesystem.Deny = unionStrings(base.Filesystem.Deny, overlay.Filesystem.Deny)
	}
	if fields["filesystem.mode"] {
		cfg.Filesystem.Mode = restrictiveFilesystemMode(base.Filesystem.Mode, overlay.Filesystem.Mode)
	}
	if fields["filesystem.root"] && overlay.Filesystem.Root != base.Filesystem.Root {
		cfg.Filesystem.Root = base.Filesystem.Root
	}
	if fields["filesystem.linux_enforcement"] {
		cfg.Filesystem.LinuxEnforcement = restrictiveEnforcement(base.Filesystem.LinuxEnforcement, overlay.Filesystem.LinuxEnforcement)
	}
	cfg.Filesystem.Hardened = base.Filesystem.Hardened || overlay.Filesystem.Hardened

	if fields["network.allow"] {
		cfg.Network.Allow = intersectStrings(base.Network.Allow, overlay.Network.Allow)
	}
	cfg.Network.AllowAll = base.Network.AllowAll && overlay.Network.AllowAll
	cfg.Network.AllowPrivateRanges = base.Network.AllowPrivateRanges && overlay.Network.AllowPrivateRanges

	if fields["secrets.pass"] {
		// secrets.pass has INVERTED semantics: an empty pass list means "pass
		// every non-blocked var" (secrets.go Rule 2). A disjoint overlay must
		// never collapse a restrictive (non-empty) base to that permissive empty
		// sentinel — that would LOOSEN the secret fence. Fail closed to base.
		cfg.Secrets.Pass = tightenInvertedAllowlist(base.Secrets.Pass, overlay.Secrets.Pass)
	}
	if fields["secrets.block"] {
		cfg.Secrets.Block = unionStrings(base.Secrets.Block, overlay.Secrets.Block)
	}

	if fields["syscall.enforcement"] {
		cfg.Syscall.Enforcement = restrictiveEnforcement(base.Syscall.Enforcement, overlay.Syscall.Enforcement)
	}
	cfg.Syscall.AllowNamespaces = base.Syscall.AllowNamespaces && overlay.Syscall.AllowNamespaces
	if fields["syscall.socket_families"] {
		// socket_families also has INVERTED semantics: empty means "no socket
		// restriction" (config.go). Same fail-closed-to-base guard as pass.
		cfg.Syscall.SocketFamilies = tightenInvertedAllowlist(base.Syscall.SocketFamilies, overlay.Syscall.SocketFamilies)
	}
	if fields["syscall.extra_deny"] {
		cfg.Syscall.ExtraDeny = unionStrings(base.Syscall.ExtraDeny, overlay.Syscall.ExtraDeny)
	}

	// The audit-log DB path is the accountability anchor of a profile. A user
	// overlay must not be able to redirect it (e.g. to /dev/null) and silently
	// defeat the preset's audit guarantee — keep the profile's logging path.
	cfg.Logging.DB = base.Logging.DB

	if overlay.Cloud.Enabled && !base.Cloud.Enabled {
		cfg.Cloud.Enabled = false
		cfg.Cloud.APIKey = ""
		cfg.Cloud.Endpoint = base.Cloud.Endpoint
	}

	return cfg
}

// tightenInvertedAllowlist intersects an allowlist whose EMPTY value means "no
// restriction" (secrets.pass, syscall.socket_families). Intersection can only
// narrow such a list, EXCEPT when a disjoint overlay empties a non-empty base —
// which flips it to the permissive empty sentinel and LOOSENS the fence. In that
// case keep the (more restrictive) base. An overlay can tighten, never loosen.
func tightenInvertedAllowlist(base, overlay []string) []string {
	result := intersectStrings(base, overlay)
	if len(base) > 0 && len(result) == 0 {
		return append([]string(nil), base...)
	}
	return result
}

func cloneConfig(cfg Config) Config {
	cfg.Filesystem.Allow = append([]string(nil), cfg.Filesystem.Allow...)
	cfg.Filesystem.Deny = append([]string(nil), cfg.Filesystem.Deny...)
	cfg.Network.Allow = append([]string(nil), cfg.Network.Allow...)
	cfg.Secrets.Pass = append([]string(nil), cfg.Secrets.Pass...)
	cfg.Secrets.Block = append([]string(nil), cfg.Secrets.Block...)
	cfg.Syscall.SocketFamilies = append([]string(nil), cfg.Syscall.SocketFamilies...)
	cfg.Syscall.ExtraDeny = append([]string(nil), cfg.Syscall.ExtraDeny...)
	return cfg
}

func overlayDefinedFields(path string) (map[string]bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config at %s: %w", path, err)
	}
	var raw map[string]any
	if _, err := toml.Decode(string(data), &raw); err != nil {
		return nil, fmt.Errorf("failed to parse config at %s: %w", path, err)
	}
	fields := make(map[string]bool)
	collectTOMLFields(fields, nil, raw)
	return fields, nil
}

func collectTOMLFields(fields map[string]bool, prefix []string, value any) {
	switch typed := value.(type) {
	case map[string]any:
		for key, nested := range typed {
			collectTOMLFields(fields, append(prefix, strings.ToLower(key)), nested)
		}
	default:
		if len(prefix) > 0 {
			fields[strings.Join(prefix, ".")] = true
		}
	}
}

func addMetadataFields(fields map[string]bool, md toml.MetaData) {
	fieldNames := map[string]string{
		"filesystem":       "filesystem",
		"filesystemconfig": "filesystem",
		"network":          "network",
		"networkconfig":    "network",
		"secrets":          "secrets",
		"secretsconfig":    "secrets",
		"syscall":          "syscall",
		"syscallconfig":    "syscall",
		"cloud":            "cloud",
		"cloudconfig":      "cloud",
	}
	keyNames := map[string]string{
		"allow":                "allow",
		"deny":                 "deny",
		"mode":                 "mode",
		"root":                 "root",
		"linuxenforcement":     "linux_enforcement",
		"linux_enforcement":    "linux_enforcement",
		"allowall":             "allow_all",
		"allow_all":            "allow_all",
		"allowprivateranges":   "allow_private_ranges",
		"allow_private_ranges": "allow_private_ranges",
		"pass":                 "pass",
		"block":                "block",
		"enforcement":          "enforcement",
		"allownamespaces":      "allow_namespaces",
		"allow_namespaces":     "allow_namespaces",
		"socketfamilies":       "socket_families",
		"socket_families":      "socket_families",
		"extradeny":            "extra_deny",
		"extra_deny":           "extra_deny",
		"enabled":              "enabled",
	}
	for _, key := range md.Keys() {
		if len(key) < 2 {
			continue
		}
		section, ok := fieldNames[strings.ToLower(key[len(key)-2])]
		if !ok {
			section = strings.ToLower(key[len(key)-2])
		}
		name, ok := keyNames[strings.ToLower(key[len(key)-1])]
		if !ok {
			name = strings.ToLower(key[len(key)-1])
		}
		fields[section+"."+name] = true
	}
}

func restrictiveFilesystemMode(base, overlay string) string {
	if base == "read-only" || overlay == "read-only" {
		return "read-only"
	}
	if base == "" {
		base = "read-write"
	}
	if overlay == "" {
		overlay = "read-write"
	}
	return base
}

func restrictiveEnforcement(base, overlay string) string {
	rank := map[string]int{
		"required":  3,
		"":          3,
		"preferred": 2,
		"off":       1,
	}
	if rank[overlay] > rank[base] {
		return overlay
	}
	return base
}

func intersectStrings(a, b []string) []string {
	seen := make(map[string]bool, len(b))
	for _, value := range b {
		seen[value] = true
	}
	out := make([]string, 0, len(a))
	added := make(map[string]bool, len(a))
	for _, value := range a {
		if seen[value] && !added[value] {
			out = append(out, value)
			added[value] = true
		}
	}
	return out
}

func unionStrings(a, b []string) []string {
	out := make([]string, 0, len(a)+len(b))
	seen := make(map[string]bool, len(a)+len(b))
	for _, values := range [][]string{a, b} {
		for _, value := range values {
			if seen[value] {
				continue
			}
			out = append(out, value)
			seen[value] = true
		}
	}
	return out
}
