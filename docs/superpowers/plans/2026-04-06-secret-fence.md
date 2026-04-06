# Secret Fence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement environment variable filtering so `nocklock wrap` strips sensitive vars (AWS keys, API tokens, database credentials) from child processes.

**Architecture:** New `internal/fence/secrets/` package with a `Fence` struct that filters `[]string` env vars using glob patterns. Block always wins over pass. Integration into the wrap command sets `cmd.Env` on the child process. Status and config commands updated to show fence state.

**Tech Stack:** Go stdlib only (`path/filepath`, `strings`, `os`). No new dependencies.

---

### Task 1: Create secret fence engine — tests first

**Files:**
- Create: `internal/fence/secrets/secrets.go` (stub only — enough to compile)
- Create: `internal/fence/secrets/secrets_test.go` (full test suite)

- [ ] **Step 1: Create package stub so tests compile**

Create `internal/fence/secrets/secrets.go` with type signatures and zero-value returns:

```go
// Package secrets implements environment variable filtering for NockLock.
package secrets

// Fence filters environment variables based on pass/block glob patterns.
type Fence struct {
	PassPatterns  []string
	BlockPatterns []string
}

// NewFence creates a secret fence from config patterns.
func NewFence(pass, block []string) *Fence {
	return &Fence{PassPatterns: pass, BlockPatterns: block}
}

// Filter takes the full environment (os.Environ() format: "KEY=VALUE")
// and returns a filtered environment with blocked vars removed.
// Returns (filtered env, blocked var names).
func (f *Fence) Filter(environ []string) ([]string, []string) {
	return environ, nil
}

// Match checks if an env var name matches any pattern in the list.
// Supports glob patterns (*, ?) via filepath.Match.
// Matching is case-insensitive.
func Match(name string, patterns []string) bool {
	return false
}
```

- [ ] **Step 2: Write the full test suite**

Create `internal/fence/secrets/secrets_test.go`:

```go
package secrets

import (
	"sort"
	"testing"
)

// helper: extract var names from "KEY=VALUE" slice
func varNames(env []string) []string {
	var names []string
	for _, e := range env {
		for i := 0; i < len(e); i++ {
			if e[i] == '=' {
				names = append(names, e[:i])
				break
			}
		}
	}
	sort.Strings(names)
	return names
}

func TestFilterEmptyLists(t *testing.T) {
	f := NewFence(nil, nil)
	env := []string{"HOME=/Users/kevin", "PATH=/usr/bin", "AWS_SECRET=hunter2"}
	filtered, blocked := f.Filter(env)
	if len(blocked) != 0 {
		t.Errorf("expected no blocked vars, got %v", blocked)
	}
	if len(filtered) != len(env) {
		t.Errorf("expected all %d vars to pass, got %d", len(env), len(filtered))
	}
}

func TestFilterBlockOnly(t *testing.T) {
	f := NewFence(nil, []string{"AWS_*"})
	env := []string{"HOME=/Users/kevin", "AWS_ACCESS_KEY_ID=AKIA123", "AWS_SECRET_ACCESS_KEY=secret", "PATH=/usr/bin"}
	filtered, blocked := f.Filter(env)

	sort.Strings(blocked)
	expected := []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}
	if len(blocked) != 2 || blocked[0] != expected[0] || blocked[1] != expected[1] {
		t.Errorf("expected blocked %v, got %v", expected, blocked)
	}

	names := varNames(filtered)
	if len(names) != 2 || names[0] != "HOME" || names[1] != "PATH" {
		t.Errorf("expected [HOME PATH] in filtered, got %v", names)
	}
}

func TestFilterPassOnly(t *testing.T) {
	f := NewFence([]string{"HOME", "PATH"}, nil)
	env := []string{"HOME=/Users/kevin", "PATH=/usr/bin", "SECRET=bad", "LANG=en_US"}
	filtered, blocked := f.Filter(env)

	sort.Strings(blocked)
	if len(blocked) != 2 || blocked[0] != "LANG" || blocked[1] != "SECRET" {
		t.Errorf("expected blocked [LANG SECRET], got %v", blocked)
	}

	names := varNames(filtered)
	if len(names) != 2 || names[0] != "HOME" || names[1] != "PATH" {
		t.Errorf("expected [HOME PATH], got %v", names)
	}
}

func TestFilterPassAndBlock(t *testing.T) {
	f := NewFence([]string{"HOME", "PATH", "AWS_REGION"}, []string{"AWS_*"})
	env := []string{"HOME=/Users/kevin", "PATH=/usr/bin", "AWS_REGION=us-east-1", "LANG=en_US"}
	filtered, blocked := f.Filter(env)

	// AWS_REGION matches pass AND block — block wins
	sort.Strings(blocked)
	if len(blocked) != 2 || blocked[0] != "AWS_REGION" || blocked[1] != "LANG" {
		t.Errorf("expected blocked [AWS_REGION LANG], got %v", blocked)
	}

	names := varNames(filtered)
	if len(names) != 2 || names[0] != "HOME" || names[1] != "PATH" {
		t.Errorf("expected [HOME PATH], got %v", names)
	}
}

func TestBlockPrecedence(t *testing.T) {
	// Var explicitly in pass AND matches block pattern → BLOCKED
	f := NewFence([]string{"GITHUB_TOKEN"}, []string{"*_TOKEN*"})
	env := []string{"GITHUB_TOKEN=ghp_abc123"}
	filtered, blocked := f.Filter(env)
	if len(blocked) != 1 || blocked[0] != "GITHUB_TOKEN" {
		t.Errorf("expected GITHUB_TOKEN blocked, got blocked=%v", blocked)
	}
	if len(filtered) != 0 {
		t.Errorf("expected empty filtered, got %v", filtered)
	}
}

func TestGlobPrefix(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"AWS_*", "AWS_ACCESS_KEY_ID", true},
		{"AWS_*", "AWS_SECRET_ACCESS_KEY", true},
		{"AWS_*", "AWS_SESSION_TOKEN", true},
		{"AWS_*", "HOME", false},
		{"STRIPE_*", "STRIPE_SECRET_KEY", true},
		{"STRIPE_*", "STRIPE_PUBLISHABLE_KEY", true},
		{"STRIPE_*", "MY_STRIPE", false},
	}
	for _, tt := range tests {
		got := Match(tt.name, []string{tt.pattern})
		if got != tt.want {
			t.Errorf("Match(%q, [%q]) = %v, want %v", tt.name, tt.pattern, got, tt.want)
		}
	}
}

func TestGlobSuffix(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"*_SECRET", "DATABASE_SECRET", true},
		{"*_SECRET", "MY_SECRET", true},
		{"*_SECRET", "SECRET_KEY", false},
		{"*_SECRET", "DATABASE_SECRET_KEY", false},
	}
	for _, tt := range tests {
		got := Match(tt.name, []string{tt.pattern})
		if got != tt.want {
			t.Errorf("Match(%q, [%q]) = %v, want %v", tt.name, tt.pattern, got, tt.want)
		}
	}
}

func TestGlobContains(t *testing.T) {
	tests := []struct {
		pattern string
		name    string
		want    bool
	}{
		{"*_SECRET*", "DATABASE_SECRET", true},
		{"*_SECRET*", "MY_SECRET_KEY", true},
		{"*_SECRET*", "SECRET_THING", false}, // no leading underscore
		{"*_PASSWORD*", "DB_PASSWORD", true},
		{"*_PASSWORD*", "DB_PASSWORD_FILE", true},
		{"*_PASSWORD*", "PASSWORD_FILE", false}, // no leading underscore
		{"*_TOKEN*", "GITHUB_TOKEN", true},
		{"*_TOKEN*", "SLACK_TOKEN", true},
		{"*_TOKEN*", "TOKEN_VALUE", false}, // no leading underscore
		{"*_TOKEN*", "MY_TOKEN_FILE", true},
	}
	for _, tt := range tests {
		got := Match(tt.name, []string{tt.pattern})
		if got != tt.want {
			t.Errorf("Match(%q, [%q]) = %v, want %v", tt.name, tt.pattern, got, tt.want)
		}
	}
}

func TestGlobExact(t *testing.T) {
	if !Match("DATABASE_URL", []string{"DATABASE_URL"}) {
		t.Error("exact match DATABASE_URL should match")
	}
	if Match("DATABASE_URL_2", []string{"DATABASE_URL"}) {
		t.Error("DATABASE_URL should not match DATABASE_URL_2")
	}
}

func TestCaseInsensitive(t *testing.T) {
	// Lowercase pattern matches uppercase name
	if !Match("AWS_ACCESS_KEY_ID", []string{"aws_*"}) {
		t.Error("aws_* should match AWS_ACCESS_KEY_ID (case-insensitive)")
	}
	// Uppercase pattern matches lowercase name
	if !Match("aws_access_key_id", []string{"AWS_*"}) {
		t.Error("AWS_* should match aws_access_key_id (case-insensitive)")
	}
	// Exact match case-insensitive
	if !Match("database_url", []string{"DATABASE_URL"}) {
		t.Error("DATABASE_URL should match database_url (case-insensitive)")
	}
}

func TestEdgeCaseEmptyEnvironment(t *testing.T) {
	f := NewFence([]string{"HOME"}, []string{"AWS_*"})
	filtered, blocked := f.Filter(nil)
	if len(filtered) != 0 || len(blocked) != 0 {
		t.Errorf("expected empty results for nil env, got filtered=%v blocked=%v", filtered, blocked)
	}

	filtered, blocked = f.Filter([]string{})
	if len(filtered) != 0 || len(blocked) != 0 {
		t.Errorf("expected empty results for empty env, got filtered=%v blocked=%v", filtered, blocked)
	}
}

func TestEdgeCaseNoValue(t *testing.T) {
	f := NewFence(nil, []string{"SECRET"})
	env := []string{"SECRET=", "HOME=/Users/kevin"}
	filtered, blocked := f.Filter(env)
	if len(blocked) != 1 || blocked[0] != "SECRET" {
		t.Errorf("expected SECRET blocked even with no value, got %v", blocked)
	}
	if len(filtered) != 1 {
		t.Errorf("expected 1 filtered var, got %d", len(filtered))
	}
}

func TestEdgeCaseEqualsInValue(t *testing.T) {
	f := NewFence(nil, []string{"OTHER"})
	env := []string{"KEY=val=ue=more", "OTHER=x"}
	filtered, blocked := f.Filter(env)
	if len(blocked) != 1 || blocked[0] != "OTHER" {
		t.Errorf("expected OTHER blocked, got %v", blocked)
	}
	if len(filtered) != 1 || filtered[0] != "KEY=val=ue=more" {
		t.Errorf("expected KEY=val=ue=more preserved, got %v", filtered)
	}
}

func TestEdgeCaseEmptyName(t *testing.T) {
	f := NewFence([]string{"HOME"}, []string{"AWS_*"})
	env := []string{"=VALUE", "HOME=/Users/kevin"}
	filtered, blocked := f.Filter(env)
	// Empty-name entries should pass through (not matched by any pattern)
	found := false
	for _, e := range filtered {
		if e == "=VALUE" {
			found = true
		}
	}
	if !found {
		t.Error("expected =VALUE to pass through (empty name)")
	}
	_ = blocked
}

func TestEdgeCaseNoEqualsSign(t *testing.T) {
	f := NewFence(nil, []string{"WEIRD"})
	env := []string{"NOEQUALS", "HOME=/Users/kevin"}
	filtered, blocked := f.Filter(env)
	// Entries with no = sign should pass through unchanged
	if len(blocked) != 0 {
		t.Errorf("expected no blocked vars, got %v", blocked)
	}
	if len(filtered) != 2 {
		t.Errorf("expected 2 filtered vars, got %d", len(filtered))
	}
}

func TestEdgeCaseDuplicatePatterns(t *testing.T) {
	f := NewFence(nil, []string{"AWS_*", "AWS_*", "AWS_*"})
	env := []string{"AWS_KEY=x", "HOME=/Users/kevin"}
	filtered, blocked := f.Filter(env)
	if len(blocked) != 1 || blocked[0] != "AWS_KEY" {
		t.Errorf("duplicate patterns should not cause double-blocking, got blocked=%v", blocked)
	}
	if len(filtered) != 1 {
		t.Errorf("expected 1 filtered var, got %d", len(filtered))
	}
}

func TestDefaultConfigPatterns(t *testing.T) {
	pass := []string{"HOME", "PATH", "SHELL", "USER", "LANG", "TERM"}
	block := []string{
		"AWS_*", "STRIPE_*", "DATABASE_URL",
		"ANTHROPIC_API_KEY", "OPENAI_API_KEY",
		"*_SECRET*", "*_PASSWORD*", "*_TOKEN*",
	}
	f := NewFence(pass, block)

	env := []string{
		"HOME=/Users/kevin",
		"PATH=/usr/bin",
		"SHELL=/bin/zsh",
		"USER=kevin",
		"LANG=en_US.UTF-8",
		"TERM=xterm-256color",
		"AWS_ACCESS_KEY_ID=AKIA123",
		"AWS_SECRET_ACCESS_KEY=secret",
		"STRIPE_SECRET_KEY=sk_live_xxx",
		"DATABASE_URL=postgres://localhost/db",
		"ANTHROPIC_API_KEY=sk-ant-xxx",
		"OPENAI_API_KEY=sk-xxx",
		"GITHUB_TOKEN=ghp_abc",
		"DB_PASSWORD=pass123",
		"MY_SECRET_KEY=secret",
	}

	filtered, blocked := f.Filter(env)

	// All pass vars should be in filtered
	passNames := varNames(filtered)
	for _, p := range pass {
		found := false
		for _, n := range passNames {
			if n == p {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %s to pass through with default config", p)
		}
	}

	// All sensitive vars should be blocked
	sort.Strings(blocked)
	expectedBlocked := []string{
		"ANTHROPIC_API_KEY", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
		"DATABASE_URL", "DB_PASSWORD", "GITHUB_TOKEN",
		"MY_SECRET_KEY", "OPENAI_API_KEY", "STRIPE_SECRET_KEY",
	}
	if len(blocked) != len(expectedBlocked) {
		t.Fatalf("expected %d blocked vars, got %d: %v", len(expectedBlocked), len(blocked), blocked)
	}
	for i, name := range expectedBlocked {
		if blocked[i] != name {
			t.Errorf("blocked[%d] = %q, want %q", i, blocked[i], name)
		}
	}

	// Filtered should contain exactly the 6 pass vars
	if len(filtered) != 6 {
		t.Errorf("expected 6 filtered vars, got %d: %v", len(filtered), varNames(filtered))
	}
}

func TestMatchMultiplePatterns(t *testing.T) {
	patterns := []string{"HOME", "AWS_*", "*_TOKEN*"}
	if !Match("HOME", patterns) {
		t.Error("HOME should match")
	}
	if !Match("AWS_KEY", patterns) {
		t.Error("AWS_KEY should match")
	}
	if !Match("GITHUB_TOKEN", patterns) {
		t.Error("GITHUB_TOKEN should match")
	}
	if Match("LANG", patterns) {
		t.Error("LANG should not match")
	}
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `go test ./internal/fence/secrets/ -v`
Expected: Most tests FAIL (stub returns input unchanged, Match returns false).

- [ ] **Step 4: Commit test suite and stub**

```bash
git add internal/fence/secrets/secrets.go internal/fence/secrets/secrets_test.go
git commit -m "test: add comprehensive secret fence tests with stub implementation"
```

---

### Task 2: Implement the secret fence engine

**Files:**
- Modify: `internal/fence/secrets/secrets.go`

- [ ] **Step 1: Implement Match function**

Replace the `Match` function in `internal/fence/secrets/secrets.go`:

```go
// Match checks if an env var name matches any pattern in the list.
// Supports glob patterns (*, ?) via filepath.Match.
// Matching is case-insensitive.
func Match(name string, patterns []string) bool {
	lowerName := strings.ToLower(name)
	for _, p := range patterns {
		matched, err := filepath.Match(strings.ToLower(p), lowerName)
		if err != nil {
			// Invalid pattern — skip it rather than crashing.
			continue
		}
		if matched {
			return true
		}
	}
	return false
}
```

Add imports at the top of the file:

```go
import (
	"path/filepath"
	"strings"
)
```

- [ ] **Step 2: Implement Filter function**

Replace the `Filter` method in `internal/fence/secrets/secrets.go`:

```go
// Filter takes the full environment (os.Environ() format: "KEY=VALUE")
// and returns a filtered environment with blocked vars removed.
// Returns (filtered env, blocked var names).
func (f *Fence) Filter(environ []string) ([]string, []string) {
	var filtered []string
	var blocked []string

	for _, entry := range environ {
		name, _, hasEquals := strings.Cut(entry, "=")

		// Entries with no = sign or empty name: pass through unchanged.
		if !hasEquals || name == "" {
			filtered = append(filtered, entry)
			continue
		}

		// Rule 1: If var matches any block pattern → BLOCKED.
		if Match(name, f.BlockPatterns) {
			blocked = append(blocked, name)
			continue
		}

		// Rule 2: If pass list is empty → all non-blocked vars pass.
		// Rule 3: If pass list is non-empty → var must match a pass pattern.
		if len(f.PassPatterns) == 0 || Match(name, f.PassPatterns) {
			filtered = append(filtered, entry)
		} else {
			blocked = append(blocked, name)
		}
	}

	return filtered, blocked
}
```

- [ ] **Step 3: Run all tests to verify they pass**

Run: `go test ./internal/fence/secrets/ -v`
Expected: ALL PASS

- [ ] **Step 4: Run existing tests to verify no regressions**

Run: `go test ./... -v`
Expected: ALL PASS (5 existing + new tests)

- [ ] **Step 5: Run go vet**

Run: `go vet ./...`
Expected: Zero warnings

- [ ] **Step 6: Commit implementation**

```bash
git add internal/fence/secrets/secrets.go
git commit -m "feat: implement secret fence engine with glob pattern matching"
```

---

### Task 3: Integrate secret fence into wrap command

**Files:**
- Modify: `internal/cli/wrap.go:1-57`

- [ ] **Step 1: Update wrap command to load config and apply fence**

Replace the entire contents of `internal/cli/wrap.go`:

```go
package cli

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/nocktechnologies/nocklock/internal/config"
	secrets "github.com/nocktechnologies/nocklock/internal/fence/secrets"
	"github.com/nocktechnologies/nocklock/internal/version"
	"github.com/spf13/cobra"
)

var wrapCmd = &cobra.Command{
	Use:   "wrap -- <command> [args...]",
	Short: "Wrap a command with NockLock fences",
	Long:  "Wraps an AI agent command with filesystem, network, and secret isolation.",
	// Disable all flag parsing so every token is passed through as a raw argument.
	// Cobra will not consume any flags; we manually strip the leading "--" below.
	DisableFlagParsing: true,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Strip leading "--" if present
		if len(args) > 0 && args[0] == "--" {
			args = args[1:]
		}

		if len(args) == 0 {
			return fmt.Errorf("no command specified. Usage: nocklock wrap -- <command> [args...]")
		}

		// Attempt to load config for fence setup.
		configPath := filepath.Join(config.Dir, config.File)
		cfg, err := config.Load(configPath)

		var childEnv []string
		if err != nil {
			// No config or bad config — warn and run passthrough.
			fmt.Fprintf(os.Stderr, "%s — no config found, running without fences\n", version.BuildInfo())
			childEnv = os.Environ()
		} else {
			// Apply secret fence.
			fence := secrets.NewFence(cfg.Secrets.Pass, cfg.Secrets.Block)
			var blocked []string
			childEnv, blocked = fence.Filter(os.Environ())

			if len(blocked) > 0 {
				fmt.Fprintf(os.Stderr, "NockLock: secret fence active — blocked %d environment variable(s)\n", len(blocked))
				if cfg.Logging.Level == "debug" {
					fmt.Fprintf(os.Stderr, "  blocked: %s\n", strings.Join(blocked, ", "))
				}
			} else {
				fmt.Fprintf(os.Stderr, "NockLock: secret fence active — no variables blocked\n")
			}
		}

		child := exec.Command(args[0], args[1:]...)
		child.Env = childEnv
		child.Stdin = os.Stdin
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr

		if err := child.Run(); err != nil {
			if exitErr, ok := err.(*exec.ExitError); ok {
				code := exitErr.ExitCode()
				if code < 0 {
					// Negative exit code means signal termination (Unix) or abnormal exit.
					// Fall back to 1 for cross-platform safety.
					code = 1
				}
				cmd.SilenceErrors = true
				cmd.SilenceUsage = true
				return &exitCodeError{code: code}
			}
			return fmt.Errorf("failed to run %q: %w", args[0], err)
		}
		return nil
	},
}

func init() {
	rootCmd.AddCommand(wrapCmd)
}
```

- [ ] **Step 2: Build to verify compilation**

Run: `go build ./cmd/nocklock`
Expected: Builds successfully

- [ ] **Step 3: Run all tests**

Run: `go test ./... -v`
Expected: ALL PASS

- [ ] **Step 4: Run go vet**

Run: `go vet ./...`
Expected: Zero warnings

- [ ] **Step 5: Commit**

```bash
git add internal/cli/wrap.go
git commit -m "feat: integrate secret fence into wrap command"
```

---

### Task 4: Update status command

**Files:**
- Modify: `internal/cli/status.go:1-19`

- [ ] **Step 1: Update status command to show fence state**

Replace the entire contents of `internal/cli/status.go`:

```go
package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/version"
	"github.com/spf13/cobra"
)

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show active fenced sessions",
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath := filepath.Join(config.Dir, config.File)
		cfg, err := config.Load(configPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "No config found. Run 'nocklock init' first.")
			return nil
		}

		fmt.Println(version.BuildInfo())

		// Secret fence status
		blockCount := len(cfg.Secrets.Block)
		if blockCount > 0 {
			fmt.Printf("Secret fence: active (blocking %d patterns)\n", blockCount)
		} else {
			fmt.Println("Secret fence: not configured")
		}

		// Placeholder for future fences
		fmt.Println("Filesystem fence: not active")
		fmt.Println("Network fence: not active")

		return nil
	},
}

func init() {
	rootCmd.AddCommand(statusCmd)
}
```

- [ ] **Step 2: Build and verify**

Run: `go build ./cmd/nocklock && go vet ./...`
Expected: Builds clean, no vet warnings

- [ ] **Step 3: Commit**

```bash
git add internal/cli/status.go
git commit -m "feat: update status command to show fence state"
```

---

### Task 5: Update config command with fence summary

**Files:**
- Modify: `internal/cli/config.go:1-36`

- [ ] **Step 1: Update config command to show pattern counts**

Replace the entire contents of `internal/cli/config.go`:

```go
package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/spf13/cobra"
)

var configCmd = &cobra.Command{
	Use:   "config",
	Short: "Print current NockLock config",
	RunE: func(cmd *cobra.Command, args []string) error {
		configPath := filepath.Join(config.Dir, config.File)

		data, err := os.ReadFile(configPath)
		if err != nil {
			if os.IsNotExist(err) {
				fmt.Fprintln(os.Stderr, "No config found. Run `nocklock init` to create one.")
				return nil
			}
			return fmt.Errorf("failed to read config at %s: %w", configPath, err)
		}

		if _, err := os.Stdout.Write(data); err != nil {
			return fmt.Errorf("failed to write config to stdout: %w", err)
		}

		// Load parsed config to show fence summary.
		cfg, err := config.Load(configPath)
		if err != nil {
			// Raw TOML was already printed; skip summary on parse error.
			return nil
		}

		fmt.Printf("\n# Fence summary:\n")
		fmt.Printf("#   Secret fence: %d pass patterns, %d block patterns\n",
			len(cfg.Secrets.Pass), len(cfg.Secrets.Block))

		return nil
	},
}

func init() {
	rootCmd.AddCommand(configCmd)
}
```

- [ ] **Step 2: Build and verify**

Run: `go build ./cmd/nocklock && go vet ./...`
Expected: Builds clean, no vet warnings

- [ ] **Step 3: Commit**

```bash
git add internal/cli/config.go
git commit -m "feat: add fence summary to config command output"
```

---

### Task 6: Final verification and branch push

**Files:** None (verification only)

- [ ] **Step 1: Run full test suite**

Run: `go test ./... -v`
Expected: ALL PASS (existing 5 + new secret fence tests)

- [ ] **Step 2: Run go vet**

Run: `go vet ./...`
Expected: Zero warnings

- [ ] **Step 3: Run go fmt**

Run: `gofmt -l ./internal/fence/ ./internal/cli/`
Expected: No files listed (all formatted)

- [ ] **Step 4: Build binary**

Run: `go build ./cmd/nocklock`
Expected: Clean build

- [ ] **Step 5: Manual smoke test**

Run from the project root (which has `.nock/config.toml.example` — copy it first):

```bash
cp .nock/config.toml.example .nock/config.toml
export AWS_SECRET_ACCESS_KEY=hunter2
export STRIPE_SECRET_KEY=sk_live_xxx
./nocklock wrap -- env | grep -c AWS
# Expected: 0
./nocklock wrap -- env | grep -c STRIPE
# Expected: 0
./nocklock wrap -- env | grep HOME
# Expected: HOME=/Users/kevin
./nocklock status
# Expected: Secret fence: active (blocking 8 patterns)
./nocklock config
# Expected: raw TOML + fence summary
rm .nock/config.toml
```

- [ ] **Step 6: Push branch and open PR**

```bash
git push -u origin feature/secret-fence
```

Then open PR from `feature/secret-fence` → `main` with the description from the spec.
