package config

// DefaultConfig returns a Config with sensible security-first defaults.
func DefaultConfig() Config {
	return Config{
		Project: ProjectConfig{
			Name: "",
			Root: ".",
		},
		Filesystem: FilesystemConfig{
			Root:             ".",
			Mode:             "read-write",
			LinuxEnforcement: "required",
			Allow: []string{
				"~/.claude/",
				"/tmp/",
				"/usr/",
				"/bin/",
				"/lib/",
				"/lib64/",
				"/etc/",
			},
			AllowRW: []string{},
			Deny: []string{
				"~/.ssh/",
				"~/.aws/",
				"~/.gnupg/",
				"~/.nock/",
			},
		},
		Network: NetworkConfig{
			Allow: []string{
				"github.com",
				"api.github.com",
				"api.anthropic.com",
				"registry.npmjs.org",
				"pypi.org",
				"rubygems.org",
				"crates.io",
			},
			AllowAll: false,
		},
		Secrets: SecretsConfig{
			ScanPaths:    []string{},
			ScanEnvAllow: []string{},
			Pass: []string{
				"HOME",
				"PATH",
				"SHELL",
				"USER",
				"LANG",
				"TERM",
			},
			Block: []string{
				"AWS_*",
				"STRIPE_*",
				"DATABASE_URL",
				"ANTHROPIC_API_KEY",
				"OPENAI_API_KEY",
				"*_SECRET*",
				"*_PASSWORD*",
				"*_TOKEN*",
			},
		},
		Syscall: SyscallConfig{
			Enforcement:     "required",
			AllowNamespaces: false,
			SocketFamilies:  []string{"unix", "inet", "inet6"},
		},
		Logging: LoggingConfig{
			DB:    "events.db",
			Level: "info",
		},
		Cloud: CloudConfig{
			Enabled:  false,
			APIKey:   "",
			Endpoint: "https://cc.nocktechnologies.io/api/fence/events/",
		},
	}
}

// DefaultTOML returns the default config as a TOML string for writing to disk.
func DefaultTOML() string {
	return `[project]
name = ""
root = "."

[filesystem]
root = "."
mode = "read-write"
linux_enforcement = "required"
# TEMPORARY macOS v0.5 compatibility escape hatch. When true, a missing or
# rejected Seatbelt profile is logged as DEGRADED and the child runs unfenced.
# It is removed in v0.6; leave false for the fail-closed security default.
macos_allow_unfenced = false
allow = [
    "~/.claude/",
    "/tmp/",
    "/usr/",
    "/bin/",
    "/lib/",
    "/lib64/",
    "/etc/",
]
# Linux only: paths explicitly granted read-write access. allow stays read-only.
allow_rw = []
deny = [
    "~/.ssh/",
    "~/.aws/",
    "~/.gnupg/",
    "~/.nock/",
]

[network]
allow = [
    "github.com",
    "api.github.com",
    "api.anthropic.com",
    "registry.npmjs.org",
    "pypi.org",
    "rubygems.org",
    "crates.io",
]
allow_all = false
# Refuse wrap unless egress is kernel-enforced or Linux syscall-confined.
require_enforced = false

[secrets]
# Optional local preflight. A finding or incomplete scan prevents launch.
# Paths are relative to the project containing this .nock directory.
scan_env = false
scan_paths = []
scan_env_allow = []
pass = [
    "HOME",
    "PATH",
    "SHELL",
    "USER",
    "LANG",
    "TERM",
]
block = [
    "AWS_*",
    "STRIPE_*",
    "DATABASE_URL",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "*_SECRET*",
    "*_PASSWORD*",
    "*_TOKEN*",
]

[syscall]
# Linux seccomp-BPF syscall fence (no-op on macOS).
# enforcement: "required" (fail closed), "preferred" (install if supported),
# or "off" (disabled).
enforcement = "required"
allow_namespaces = false
socket_families = [
    "unix",
    "inet",
    "inet6",
]

[logging]
# A relative db goes to NockLock's audit state directory OUTSIDE this project
# ($XDG_STATE_HOME/nocklock/<project>), keeping only the filename. The fence
# grants the project root to the agent so it can create files there, and
# Landlock cannot exclude a path beneath a granted directory - so an event log
# stored in the project would be editable by the agent it records. An existing
# .nock/events.db is left where it is and keeps being used; while it sits inside
# the fence root the agent cannot create entries directly in the root. An
# absolute path is allowed only inside the project or the audit state directory.
db = "events.db"
level = "info"

[cloud]
enabled = false
api_key = ""
endpoint = "https://cc.nocktechnologies.io/api/fence/events/"
`
}
