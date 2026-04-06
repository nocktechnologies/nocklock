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
