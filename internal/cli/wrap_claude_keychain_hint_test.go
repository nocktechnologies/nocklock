package cli

import (
	"fmt"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/fence/secrets"
)

func TestClaudeKeychainHint(t *testing.T) {
	stripped := func(name string) string { return fmt.Sprintf(claudeHintStrippedFormat, name, name) }
	tests := []struct {
		name    string
		goos    string
		args    []string
		parent  []string
		environ []string
		want    string
	}{
		{"darwin claude unset", "darwin", []string{"claude", "-p", "hi"}, []string{"HOME=/h"}, []string{"HOME=/h"}, claudeHintUnset},
		{"darwin absolute claude path", "darwin", []string{"/opt/homebrew/bin/claude"}, nil, nil, claudeHintUnset},
		{"oauth token stripped", "darwin", []string{"claude"}, []string{"CLAUDE_CODE_OAUTH_TOKEN=sekrit"}, nil, stripped("CLAUDE_CODE_OAUTH_TOKEN")},
		{"api key stripped", "darwin", []string{"claude"}, []string{"ANTHROPIC_API_KEY=sekrit"}, nil, stripped("ANTHROPIC_API_KEY")},
		{"oauth token passed", "darwin", []string{"claude"}, []string{"CLAUDE_CODE_OAUTH_TOKEN=x"}, []string{"CLAUDE_CODE_OAUTH_TOKEN=x"}, ""},
		{"api key passed", "darwin", []string{"claude"}, []string{"ANTHROPIC_API_KEY=x"}, []string{"ANTHROPIC_API_KEY=x"}, ""},
		{"empty value counts as unset", "darwin", []string{"claude"}, []string{"ANTHROPIC_API_KEY="}, []string{"ANTHROPIC_API_KEY="}, claudeHintUnset},
		{"other basename", "darwin", []string{"claude-code"}, nil, nil, ""},
		{"other command", "darwin", []string{"codex"}, nil, nil, ""},
		{"linux", "linux", []string{"claude"}, nil, nil, ""},
		{"no args", "darwin", nil, nil, nil, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := claudeKeychainHint(tc.goos, tc.args, tc.parent, tc.environ)
			if got != tc.want {
				t.Fatalf("hint = %q, want %q", got, tc.want)
			}
			if strings.Contains(got, "sekrit") {
				t.Fatalf("hint leaked a value: %q", got)
			}
		})
	}
	for _, want := range []string{"remove the secrets.block pattern", "*_TOKEN*", "to secrets.pass", "nocklock init --runtime claude-code"} {
		if !strings.Contains(stripped("CLAUDE_CODE_OAUTH_TOKEN"), want) {
			t.Fatalf("stripped hint missing %q", want)
		}
	}
	for _, h := range []string{claudeHintUnset, stripped("CLAUDE_CODE_OAUTH_TOKEN")} {
		if strings.Contains(h, "\n") {
			t.Fatal("hint must be a single line")
		}
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
