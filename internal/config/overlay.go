package config

import "slices"

// restrictOverlay applies every restriction unconditionally. The overlay is
// decoded over a copy of base, so a field the overlay did not set equals base
// and restricts to itself; a field it set is compared with base by value.
// Key spelling decides nothing, so a key that the decoder folds to a field
// (for example U+017F for "s") cannot skip a restriction.
func restrictOverlay(base, overlay Config) Config {
	cfg := overlay
	cfg.ProfileName = base.ProfileName

	cfg.Filesystem.Allow = intersectStrings(base.Filesystem.Allow, overlay.Filesystem.Allow)
	cfg.Filesystem.AllowRW = intersectStrings(base.Filesystem.AllowRW, overlay.Filesystem.AllowRW)
	cfg.Filesystem.Deny = unionStrings(base.Filesystem.Deny, overlay.Filesystem.Deny)
	cfg.Filesystem.Mode = restrictiveFilesystemMode(base.Filesystem.Mode, overlay.Filesystem.Mode)
	if overlay.Filesystem.Root != base.Filesystem.Root {
		cfg.Filesystem.Root = base.Filesystem.Root
	}
	cfg.Filesystem.LinuxEnforcement = restrictiveEnforcement(base.Filesystem.LinuxEnforcement, overlay.Filesystem.LinuxEnforcement)
	cfg.Filesystem.Hardened = base.Filesystem.Hardened || overlay.Filesystem.Hardened

	cfg.Network.Allow = intersectStrings(base.Network.Allow, overlay.Network.Allow)
	cfg.Network.AllowAll = base.Network.AllowAll && overlay.Network.AllowAll
	cfg.Network.AllowPrivateRanges = base.Network.AllowPrivateRanges && overlay.Network.AllowPrivateRanges
	cfg.Network.RequireEnforced = base.Network.RequireEnforced || overlay.Network.RequireEnforced
	cfg.Network.RequireUnixSocketIsolation = base.Network.RequireUnixSocketIsolation || overlay.Network.RequireUnixSocketIsolation
	// Look-back rules only narrow egress, so an overlay adds to the base's.
	cfg.Network.Lookback = slices.Clone(base.Network.Lookback)
	cfg.Network.Lookback = append(cfg.Network.Lookback, overlay.Network.Lookback...)

	// secrets.pass has INVERTED semantics: an empty pass list means "pass
	// every non-blocked var" (secrets.go Rule 2). A disjoint overlay must
	// never collapse a restrictive (non-empty) base to that permissive empty
	// sentinel — that would LOOSEN the secret fence. Fail closed to base.
	cfg.Secrets.Pass = tightenInvertedAllowlist(base.Secrets.Pass, overlay.Secrets.Pass)
	cfg.Secrets.Block = unionStrings(base.Secrets.Block, overlay.Secrets.Block)
	cfg.Secrets.ScanEnv = base.Secrets.ScanEnv || overlay.Secrets.ScanEnv
	cfg.Secrets.ScanPaths = unionStrings(base.Secrets.ScanPaths, overlay.Secrets.ScanPaths)
	cfg.Secrets.ScanEnvAllow = intersectStrings(base.Secrets.ScanEnvAllow, overlay.Secrets.ScanEnvAllow)

	cfg.Syscall.Enforcement = restrictiveEnforcement(base.Syscall.Enforcement, overlay.Syscall.Enforcement)
	cfg.Syscall.AllowNamespaces = base.Syscall.AllowNamespaces && overlay.Syscall.AllowNamespaces
	// socket_families also has INVERTED semantics: empty means "no socket
	// restriction" (config.go). Same fail-closed-to-base guard as pass.
	cfg.Syscall.SocketFamilies = tightenInvertedAllowlist(base.Syscall.SocketFamilies, overlay.Syscall.SocketFamilies)
	cfg.Syscall.ExtraDeny = unionStrings(base.Syscall.ExtraDeny, overlay.Syscall.ExtraDeny)

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
	cfg.Filesystem.AllowRW = append([]string(nil), cfg.Filesystem.AllowRW...)
	cfg.Filesystem.Deny = append([]string(nil), cfg.Filesystem.Deny...)
	cfg.Network.Allow = append([]string(nil), cfg.Network.Allow...)
	cfg.Secrets.Pass = append([]string(nil), cfg.Secrets.Pass...)
	cfg.Secrets.Block = append([]string(nil), cfg.Secrets.Block...)
	cfg.Secrets.ScanPaths = append([]string(nil), cfg.Secrets.ScanPaths...)
	cfg.Secrets.ScanEnvAllow = append([]string(nil), cfg.Secrets.ScanEnvAllow...)
	cfg.Syscall.SocketFamilies = append([]string(nil), cfg.Syscall.SocketFamilies...)
	cfg.Syscall.ExtraDeny = append([]string(nil), cfg.Syscall.ExtraDeny...)
	cfg.Network.Lookback = slices.Clone(cfg.Network.Lookback)
	return cfg
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
