# NockLock CLI Skeleton Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the NockLock CLI skeleton with cobra commands, TOML config parsing, passthrough wrap, and project structure — no fence implementations.

**Architecture:** Single Go binary using cobra for CLI and BurntSushi/toml for config. Six commands (version, init, wrap, config, log, status). The `wrap` command is a passthrough that spawns a child process and forwards stdio. Config lives in `.nock/config.toml` per project.

**Tech Stack:** Go 1.22+, spf13/cobra, BurntSushi/toml

---

## File Structure

```
nocklock/
├── cmd/nocklock/main.go              — Entry point, calls cli.Execute()
├── internal/
│   ├── cli/
│   │   ├── root.go                   — Root cobra command, global setup
│   │   ├── version.go                — version subcommand
│   │   ├── init_cmd.go               — init subcommand (generates config)
│   │   ├── wrap.go                   — wrap subcommand (passthrough)
│   │   ├── config.go                 — config subcommand (prints config)
│   │   ├── log.go                    — log subcommand (stub)
│   │   └── status.go                 — status subcommand (stub)
│   ├── config/
│   │   ├── config.go                 — Config struct, Load(), TOML parsing
│   │   ├── defaults.go               — DefaultConfig(), DefaultTOML()
│   │   └── config_test.go            — Tests for parsing, defaults, missing file
│   └── version/
│       └── version.go                — Version var (injected via ldflags)
├── .nock/config.toml.example         — Example config file
├── CLAUDE.md                         — Repo context for Claude Code
├── Makefile                          — Build targets
└── README.md                         — Updated with adapted pitch
```

---

### Task 1: Go Module + Dependencies

**Files:**
- Create: `go.mod`

- [ ] **Step 1: Initialize Go module**

```bash
cd /c/Dev/nocklock
go mod init github.com/nocktechnologies/nocklock
```

- [ ] **Step 2: Add dependencies**

```bash
go get github.com/spf13/cobra@latest
go get github.com/BurntSushi/toml@latest
```

- [ ] **Step 3: Verify go.mod looks correct**

```bash
cat go.mod
```

Expected: module line + require block with cobra and toml.

- [ ] **Step 4: Commit**

```bash
git checkout -b feature/cli-skeleton
git add go.mod go.sum
git commit -m "chore: initialize Go module with cobra and toml dependencies"
```

---

### Task 2: Version Package

**Files:**
- Create: `internal/version/version.go`

- [ ] **Step 1: Create the version package**

```go
// internal/version/version.go
package version

import "fmt"

// Version is set at build time via ldflags.
var Version = "0.1.0"

// BuildInfo returns the formatted version string.
func BuildInfo() string {
	return fmt.Sprintf("NockLock v%s (dev)", Version)
}
```

- [ ] **Step 2: Verify it compiles**

```bash
go build ./internal/version/
```

Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add internal/version/version.go
git commit -m "feat: add version package with build-time injection"
```

---

### Task 3: Config Struct + TOML Parsing

**Files:**
- Create: `internal/config/config.go`
- Create: `internal/config/defaults.go`
- Create: `internal/config/config_test.go`

- [ ] **Step 1: Write the failing tests**

Create `internal/config/config_test.go`:

```go
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseConfig(t *testing.T) {
	tomlContent := `
[project]
name = "test-project"
root = "."

[filesystem]
allow = ["."]
deny = ["~/.ssh/"]

[network]
allow = ["github.com"]
allow_all = false

[secrets]
pass = ["HOME"]
block = ["AWS_*"]

[logging]
db = ".nock/events.db"
level = "info"

[cloud]
enabled = false
api_key = ""
endpoint = "https://cc.nocktechnologies.io/api/fence/events/"
`
	dir := t.TempDir()
	nockDir := filepath.Join(dir, ".nock")
	if err := os.MkdirAll(nockDir, 0o755); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(nockDir, "config.toml")
	if err := os.WriteFile(configPath, []byte(tomlContent), 0o644); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(configPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if cfg.Project.Name != "test-project" {
		t.Errorf("expected project name 'test-project', got %q", cfg.Project.Name)
	}
	if cfg.Network.AllowAll != false {
		t.Error("expected allow_all to be false")
	}
	if len(cfg.Filesystem.Allow) != 1 || cfg.Filesystem.Allow[0] != "." {
		t.Errorf("unexpected filesystem allow: %v", cfg.Filesystem.Allow)
	}
	if len(cfg.Secrets.Block) != 1 || cfg.Secrets.Block[0] != "AWS_*" {
		t.Errorf("unexpected secrets block: %v", cfg.Secrets.Block)
	}
	if cfg.Cloud.Endpoint != "https://cc.nocktechnologies.io/api/fence/events/" {
		t.Errorf("unexpected cloud endpoint: %q", cfg.Cloud.Endpoint)
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()

	if cfg.Project.Root != "." {
		t.Errorf("expected default root '.', got %q", cfg.Project.Root)
	}
	if cfg.Network.AllowAll != false {
		t.Error("expected default allow_all to be false")
	}
	if cfg.Logging.Level != "info" {
		t.Errorf("expected default log level 'info', got %q", cfg.Logging.Level)
	}
	if cfg.Cloud.Enabled != false {
		t.Error("expected cloud to be disabled by default")
	}

	// Verify sensitive dirs are denied by default
	found := false
	for _, d := range cfg.Filesystem.Deny {
		if d == "~/.ssh/" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected ~/.ssh/ in default deny list")
	}

	// Verify secret patterns are blocked by default
	found = false
	for _, b := range cfg.Secrets.Block {
		if b == "AWS_*" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected AWS_* in default block list")
	}
}

func TestConfigNotFound(t *testing.T) {
	_, err := Load("/nonexistent/path/config.toml")
	if err == nil {
		t.Fatal("expected error for missing config, got nil")
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
go test ./internal/config/ -v
```

Expected: compilation failure — `Load` and `DefaultConfig` not defined.

- [ ] **Step 3: Create config.go with Config struct and Load function**

Create `internal/config/config.go`:

```go
// Package config handles TOML configuration parsing for NockLock.
package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// Config is the top-level NockLock configuration.
type Config struct {
	Project    ProjectConfig    `toml:"project"`
	Filesystem FilesystemConfig `toml:"filesystem"`
	Network    NetworkConfig    `toml:"network"`
	Secrets    SecretsConfig    `toml:"secrets"`
	Logging    LoggingConfig    `toml:"logging"`
	Cloud      CloudConfig      `toml:"cloud"`
}

// ProjectConfig identifies the project being fenced.
type ProjectConfig struct {
	Name string `toml:"name"`
	Root string `toml:"root"`
}

// FilesystemConfig defines filesystem access boundaries.
type FilesystemConfig struct {
	Allow []string `toml:"allow"`
	Deny  []string `toml:"deny"`
}

// NetworkConfig defines network egress boundaries.
type NetworkConfig struct {
	Allow    []string `toml:"allow"`
	AllowAll bool     `toml:"allow_all"`
}

// SecretsConfig defines environment variable filtering rules.
type SecretsConfig struct {
	Pass  []string `toml:"pass"`
	Block []string `toml:"block"`
}

// LoggingConfig configures local event logging.
type LoggingConfig struct {
	DB    string `toml:"db"`
	Level string `toml:"level"`
}

// CloudConfig configures optional NockCC dashboard sync.
type CloudConfig struct {
	Enabled  bool   `toml:"enabled"`
	APIKey   string `toml:"api_key"`
	Endpoint string `toml:"endpoint"`
}

// Load reads and parses a TOML config file at the given path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config at %s: %w", path, err)
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config at %s: %w", path, err)
	}

	return &cfg, nil
}
```

- [ ] **Step 4: Create defaults.go**

Create `internal/config/defaults.go`:

```go
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

// DefaultTOML returns the default config as a TOML string.
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
```

- [ ] **Step 5: Run tests to verify they pass**

```bash
go test ./internal/config/ -v
```

Expected: all 3 tests PASS.

- [ ] **Step 6: Commit**

```bash
git add internal/config/
git commit -m "feat: add config struct, TOML parsing, defaults, and tests"
```

---

### Task 4: CLI Commands — Root + Version

**Files:**
- Create: `internal/cli/root.go`
- Create: `internal/cli/version.go`
- Create: `cmd/nocklock/main.go`

- [ ] **Step 1: Create root.go**

```go
// Package cli defines the cobra command tree for NockLock.
package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "nocklock",
	Short: "AI agent security fence",
	Long:  "NockLock wraps AI coding agents with filesystem, network, and secret isolation.",
}

// Execute runs the root command.
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
```

- [ ] **Step 2: Create version.go**

```go
package cli

import (
	"fmt"

	"github.com/nocktechnologies/nocklock/internal/version"
	"github.com/spf13/cobra"
)

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print NockLock version",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(version.BuildInfo())
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
```

- [ ] **Step 3: Create main.go**

```go
// Package main is the entry point for the NockLock CLI.
package main

import "github.com/nocktechnologies/nocklock/internal/cli"

func main() {
	cli.Execute()
}
```

- [ ] **Step 4: Build and test**

```bash
go build -o nocklock.exe ./cmd/nocklock
./nocklock.exe version
```

Expected: `NockLock v0.1.0 (dev)`

- [ ] **Step 5: Commit**

```bash
git add cmd/nocklock/main.go internal/cli/root.go internal/cli/version.go
git commit -m "feat: add root command, version command, and CLI entry point"
```

---

### Task 5: Init Command

**Files:**
- Create: `internal/cli/init_cmd.go`

- [ ] **Step 1: Create init_cmd.go**

```go
package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize NockLock config in current directory",
	RunE: func(cmd *cobra.Command, args []string) error {
		nockDir := ".nock"
		configPath := filepath.Join(nockDir, "config.toml")

		if _, err := os.Stat(configPath); err == nil {
			fmt.Printf("Config already exists at %s\n", configPath)
			return nil
		}

		if err := os.MkdirAll(nockDir, 0o755); err != nil {
			return fmt.Errorf("failed to create %s directory: %w", nockDir, err)
		}

		if err := os.WriteFile(configPath, []byte(config.DefaultTOML()), 0o644); err != nil {
			return fmt.Errorf("failed to write config: %w", err)
		}

		fmt.Printf("NockLock initialized. Config at %s\n", configPath)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(initCmd)
}
```

- [ ] **Step 2: Build and test**

```bash
go build -o nocklock.exe ./cmd/nocklock
./nocklock.exe init
cat .nock/config.toml
./nocklock.exe init
```

Expected first run: `NockLock initialized. Config at .nock/config.toml`
Expected second run: `Config already exists at .nock/config.toml`

- [ ] **Step 3: Clean up generated config**

```bash
rm -rf .nock/config.toml
```

(Keep .nock dir for the example file later.)

- [ ] **Step 4: Commit**

```bash
git add internal/cli/init_cmd.go
git commit -m "feat: add init command to generate default config"
```

---

### Task 6: Wrap Command (Passthrough)

**Files:**
- Create: `internal/cli/wrap.go`

- [ ] **Step 1: Create wrap.go**

```go
package cli

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/nocktechnologies/nocklock/internal/version"
	"github.com/spf13/cobra"
)

var wrapCmd = &cobra.Command{
	Use:   "wrap -- <command> [args...]",
	Short: "Wrap a command with NockLock fences",
	Long:  "Wraps an AI agent command with filesystem, network, and secret isolation.",
	// Disable flag parsing after -- so child command flags aren't consumed by cobra.
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Strip leading "--" if present
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}

		if len(args) == 0 {
			return fmt.Errorf("no command specified. Usage: nocklock wrap -- <command> [args...]")
		}

		fmt.Fprintf(os.Stderr, "%s — fences not yet active (coming in PR #3-6)\n", version.BuildInfo())

		child := exec.Command(args[0], args[1:]...)
		child.Stdin = os.Stdin
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr

		if err := child.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				os.Exit(exitErr.ExitCode())
			}
			return fmt.Errorf("failed to run command: %w", err)
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(wrapCmd)
}
```

- [ ] **Step 2: Build and test**

```bash
go build -o nocklock.exe ./cmd/nocklock
./nocklock.exe wrap -- echo "hello from inside the fence"
```

Expected stderr: `NockLock v0.1.0 (dev) — fences not yet active (coming in PR #3-6)`
Expected stdout: `hello from inside the fence`

- [ ] **Step 3: Test exit code forwarding**

```bash
./nocklock.exe wrap -- bash -c "exit 42"; echo "Exit code: $?"
```

Expected: `Exit code: 42`

- [ ] **Step 4: Commit**

```bash
git add internal/cli/wrap.go
git commit -m "feat: add wrap command with passthrough child process spawning"
```

---

### Task 7: Config, Log, Status Commands (Stubs)

**Files:**
- Create: `internal/cli/config.go`
- Create: `internal/cli/log.go`
- Create: `internal/cli/status.go`

- [ ] **Step 1: Create config.go**

```go
package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Print current NockLock config",
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath := filepath.Join(".nock", "config.toml")

		data, err := os.ReadFile(configPath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Println("No config found. Run `nocklock init` to create one.")
				return nil
			}
			return fmt.Errorf("failed to read config: %w", err)
		}

		fmt.Print(string(data))
		return nil
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
```

- [ ] **Step 2: Create log.go**

```go
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var logCmd = &cobra.Command{
	Use:   "log",
	Short: "View fence event log",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("No fence events recorded. Events will appear here once fences are active.")
	},
}

func init() {
	rootCmd.AddCommand(logCmd)
}
```

- [ ] **Step 3: Create status.go**

```go
package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show active fenced sessions",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println("No active fenced sessions.")
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
```

- [ ] **Step 4: Build and test all three**

```bash
go build -o nocklock.exe ./cmd/nocklock
./nocklock.exe config
./nocklock.exe log
./nocklock.exe status
```

Expected:
- config: `No config found. Run &#96;nocklock init&#96; to create one.`
- log: `No fence events recorded. Events will appear here once fences are active.`
- status: `No active fenced sessions.`

- [ ] **Step 5: Commit**

```bash
git add internal/cli/config.go internal/cli/log.go internal/cli/status.go
git commit -m "feat: add config, log, and status commands"
```

---

### Task 8: Makefile + Example Config + CLAUDE.md

**Files:**
- Create: `Makefile`
- Create: `.nock/config.toml.example`
- Create: `CLAUDE.md`

- [ ] **Step 1: Create Makefile**

```makefile
.PHONY: build test clean install fmt vet lint

VERSION ?= 0.1.0
LDFLAGS := -ldflags "-X github.com/nocktechnologies/nocklock/internal/version.Version=$(VERSION)"

build:
	go build $(LDFLAGS) -o nocklock ./cmd/nocklock

test:
	go test ./... -v

clean:
	rm -f nocklock

install: build
	mv nocklock /usr/local/bin/

fmt:
	go fmt ./...

vet:
	go vet ./...

lint: fmt vet
```

- [ ] **Step 2: Create .nock/config.toml.example**

This is the same content as `DefaultTOML()` but with comments for documentation:

```toml
# .nock/config.toml — NockLock fence configuration
# Generated by `nocklock init`. Edit to customize.

[project]
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
```

- [ ] **Step 3: Create CLAUDE.md**

```markdown
# CLAUDE.md — NockLock

## Project
NockLock is an AI agent security fence. Go CLI that wraps coding agents with filesystem, network, and secret isolation.

## Stack
- Go 1.22+
- cobra (CLI framework)
- BurntSushi/toml (config parser)
- SQLite (event logging — PR #4)

## Commands
- `go build ./cmd/nocklock` — build
- `go test ./... -v` — run all tests
- `go fmt ./...` — format
- `go vet ./...` — lint

## Pre-Push Checklist
1. `go test ./... -v` — all tests pass
2. `go vet ./...` — no warnings
3. `go fmt ./...` — code formatted
4. Self-review for: hardcoded secrets, path traversal, race conditions, subprocess injection

## Architecture
- cmd/nocklock/ — entry point
- internal/cli/ — cobra commands
- internal/config/ — TOML config parsing
- internal/fence/ — fence implementations (filesystem, network, secrets)
- internal/logging/ — SQLite event logging
- internal/version/ — version info

## Code Standards
- All exported functions need doc comments
- Error messages must be actionable
- Fences fail closed (if fence can't initialize, block everything)
- No external dependencies without discussion
- Config changes must be backwards compatible
```

- [ ] **Step 4: Test Makefile**

```bash
make build
./nocklock version
make test
make lint
```

Expected: build succeeds, version prints, all tests pass, no lint warnings.

- [ ] **Step 5: Commit**

```bash
git add Makefile .nock/config.toml.example CLAUDE.md
git commit -m "chore: add Makefile, example config, and CLAUDE.md"
```

---

### Task 9: Update README.md

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Replace README.md with adapted content**

Adapt the draft from DESIGN_NOCK_CLI_ARCHITECTURE.md section 8. Change `nock` to `nocklock`. Be honest about current state. Keep the pitch compelling.

```markdown
# nocklock

AI agent security fence. Prevent your coding agents from escaping their sandbox.

## The Problem

AI coding agents (Claude Code, Cursor, Copilot, Windsurf) run with full access
to your filesystem, network, and environment variables. One prompt injection,
one hallucinated command, one bad dependency — and your agent can:

- Read your SSH keys and AWS credentials
- Exfiltrate code to external servers
- Delete files outside the project directory
- Access production databases
- Push to repos it shouldn't touch

## The Solution

NockLock wraps your agent in an invisible fence. Three boundaries:

- **Filesystem fence** — agent can only read/write inside the project directory
- **Network fence** — agent can only reach approved domains (GitHub, npm, PyPI)
- **Secret fence** — agent only sees environment variables you explicitly allow

Zero config defaults. The fence is invisible until something hits it.

> **Current status:** NockLock is in early development. The CLI skeleton and config
> system are working. Fence implementations are coming in upcoming PRs.

## Install (from source)

```bash
git clone https://github.com/nocktechnologies/nocklock.git
cd nocklock
go build -o nocklock ./cmd/nocklock
```

## Usage

```bash
# Initialize fence config in your project
cd my-project
nocklock init

# View your config
nocklock config

# Wrap your agent (passthrough mode — fences coming soon)
nocklock wrap -- claude --dangerously-skip-permissions

# Check version
nocklock version
```

## What It Will Look Like (once fences are active)

```
$ nocklock log
2026-04-05 02:14:33 | filesystem | BLOCKED | open ~/.ssh/id_rsa
2026-04-05 02:14:35 | network    | BLOCKED | CONNECT evil.com:443
2026-04-05 02:15:01 | secret     | BLOCKED | env AWS_SECRET_ACCESS_KEY
2026-04-05 02:15:44 | filesystem | allowed | open src/main.py
```

Your agent never knew the fence was there. You sleep better at night.

## Roadmap

- [x] CLI skeleton + config system (PR #1)
- [ ] Secret fence — environment variable filtering (PR #3)
- [ ] Filesystem fence — LD_PRELOAD/DYLD_INSERT_LIBRARIES (PR #5)
- [ ] Network fence — local proxy with domain allowlist (PR #6)
- [ ] SQLite event logging (PR #4)
- [ ] Homebrew tap + CI (PR #8)

## Dashboard (Coming Soon)

Connect to [NockCC](https://nocktechnologies.io) for cloud monitoring:
- See fence events across all your machines
- Get Telegram/Slack alerts on blocked escape attempts
- Team visibility — know what every developer's agents are doing

## License

MIT
```

- [ ] **Step 2: Verify README reads well**

```bash
cat README.md
```

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: update README with project pitch and current status"
```

---

### Task 10: Update .gitignore + Final Verification

**Files:**
- Modify: `.gitignore`

- [ ] **Step 1: Add nocklock binary to .gitignore**

Add to `.gitignore`:

```
# NockLock binary
nocklock
```

- [ ] **Step 2: Full test suite**

```bash
go test ./... -v
go vet ./...
go fmt ./...
```

Expected: all tests pass, no warnings, no formatting changes.

- [ ] **Step 3: Full CLI smoke test**

```bash
go build -o nocklock.exe ./cmd/nocklock
./nocklock.exe version
./nocklock.exe init
cat .nock/config.toml
./nocklock.exe config
./nocklock.exe wrap -- echo "hello from inside the fence"
./nocklock.exe log
./nocklock.exe status
```

Expected outputs:
- version: `NockLock v0.1.0 (dev)`
- init: `NockLock initialized. Config at .nock/config.toml`
- config: prints the TOML config
- wrap: banner on stderr + `hello from inside the fence` on stdout
- log: `No fence events recorded. Events will appear here once fences are active.`
- status: `No active fenced sessions.`

- [ ] **Step 4: Clean up test artifacts**

```bash
rm -rf .nock/config.toml nocklock.exe
```

- [ ] **Step 5: Commit .gitignore**

```bash
git add .gitignore
git commit -m "chore: add nocklock binary to .gitignore"
```
