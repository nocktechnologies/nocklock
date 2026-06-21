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
			},
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
			DB:    ".nock/events.db",
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
allow = [
    "~/.claude/",
    "/tmp/",
]
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

[secrets]
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
db = ".nock/events.db"
level = "info"

[cloud]
enabled = false
api_key = ""
endpoint = "https://cc.nocktechnologies.io/api/fence/events/"
`
}
