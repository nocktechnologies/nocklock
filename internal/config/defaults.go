package config

// DefaultConfig returns a Config with sensible security-first defaults.
func DefaultConfig() Config {
	return Config{
		Project: ProjectConfig{
			Name: "",
			Root: ".",
		},
		Filesystem: FilesystemConfig{
			Allow: []string{
				".",
				"~/.claude/",
				"/tmp/",
			},
			Deny: []string{
				"~/.ssh/",
				"~/.aws/",
				"~/.gnupg/",
				"~/.nock/",
				"../",
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
allow = [
    ".",
    "~/.claude/",
    "/tmp/",
]
deny = [
    "~/.ssh/",
    "~/.aws/",
    "~/.gnupg/",
    "~/.nock/",
    "../",
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

[logging]
db = ".nock/events.db"
level = "info"

[cloud]
enabled = false
api_key = ""
endpoint = "https://cc.nocktechnologies.io/api/fence/events/"
`
}
