package cli

import (
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/fence/secrets"
)

func TestClaudeKeychainHint(t *testing.T) {
	tests := []struct {
		name    string
		goos    string
		args    []string
		environ []string
		want    string
	}{
		{"darwin claude unset", "darwin", []string{"claude", "-p", "hi"}, []string{"HOME=/h"}, claudeKeychainHintText},
		{"darwin absolute claude path", "darwin", []string{"/opt/homebrew/bin/claude"}, nil, claudeKeychainHintText},
		{"oauth token set", "darwin", []string{"claude"}, []string{"CLAUDE_CODE_OAUTH_TOKEN=x"}, ""},
		{"api key set", "darwin", []string{"claude"}, []string{"ANTHROPIC_API_KEY=x"}, ""},
		{"empty value counts as unset", "darwin", []string{"claude"}, []string{"ANTHROPIC_API_KEY="}, claudeKeychainHintText},
		{"other basename", "darwin", []string{"claude-code"}, nil, ""},
		{"other command", "darwin", []string{"codex"}, nil, ""},
		{"linux", "linux", []string{"claude"}, nil, ""},
		{"no args", "darwin", nil, nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := claudeKeychainHint(tc.goos, tc.args, tc.environ); got != tc.want {
				t.Fatalf("hint = %q, want %q", got, tc.want)
			}
		})
	}
	if strings.Contains(claudeKeychainHintText, "\n") {
		t.Fatal("hint must be a single line")
	}
}

// TestClaudeCodePresetPassesOAuthToken proves the preset lets the setup-token
// credential through the secret fence (despite the *_TOKEN* block) while an
// unrelated token stays blocked.
func TestClaudeCodePresetPassesOAuthToken(t *testing.T) {
	cfg, err := config.LoadProfile("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	fence, err := secrets.NewFence(cfg.Secrets.Pass, cfg.Secrets.Block)
	if err != nil {
		t.Fatal(err)
	}
	passed, blocked := fence.Filter([]string{
		"PATH=/bin", "CLAUDE_CODE_OAUTH_TOKEN=a", "ANTHROPIC_API_KEY=b", "GITHUB_TOKEN=c", "OPENAI_API_KEY=d",
	})
	joined := strings.Join(passed, "\n")
	for _, want := range []string{"CLAUDE_CODE_OAUTH_TOKEN=a", "ANTHROPIC_API_KEY=b"} {
		if !strings.Contains(joined, want) {
			t.Errorf("%s should pass; got %v", want, passed)
		}
	}
	for _, name := range []string{"GITHUB_TOKEN", "OPENAI_API_KEY"} {
		if strings.Contains(joined, name+"=") || !strings.Contains(strings.Join(blocked, ","), name) {
			t.Errorf("%s should be blocked; passed=%v blocked=%v", name, passed, blocked)
		}
	}
}
