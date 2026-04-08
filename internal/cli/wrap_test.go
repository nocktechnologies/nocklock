package cli

import (
	"strings"
	"testing"
)

// TestRemoveEnvVars covers the removeEnvVars helper used to clear NO_PROXY.
func TestRemoveEnvVarsRemovesMatchingKeys(t *testing.T) {
	env := []string{
		"HOME=/home/user",
		"NO_PROXY=localhost",
		"no_proxy=127.0.0.1",
		"PATH=/usr/bin",
	}
	result := removeEnvVars(env, "NO_PROXY", "no_proxy")

	for _, entry := range result {
		if strings.HasPrefix(entry, "NO_PROXY=") || strings.HasPrefix(entry, "no_proxy=") {
			t.Errorf("removeEnvVars left %q in result", entry)
		}
	}
	if len(result) != 2 {
		t.Errorf("expected 2 remaining entries, got %d: %v", len(result), result)
	}
}

func TestRemoveEnvVarsPreservesOtherVars(t *testing.T) {
	env := []string{"HOME=/home/user", "PATH=/usr/bin", "TERM=xterm"}
	result := removeEnvVars(env, "NO_PROXY")
	if len(result) != len(env) {
		t.Errorf("expected %d entries unchanged, got %d", len(env), len(result))
	}
}

func TestRemoveEnvVarsEmptyInput(t *testing.T) {
	result := removeEnvVars(nil, "NO_PROXY")
	if len(result) != 0 {
		t.Errorf("expected empty result, got %v", result)
	}
}

func TestRemoveEnvVarsNoKeysSpecified(t *testing.T) {
	env := []string{"A=1", "B=2"}
	result := removeEnvVars(env)
	if len(result) != 2 {
		t.Errorf("expected 2 entries with no keys to remove, got %d", len(result))
	}
}

func TestRemoveEnvVarsExactKeyWithoutEquals(t *testing.T) {
	// An env entry without "=" is unusual but should match on bare key.
	env := []string{"WEIRD_ENTRY", "NORMAL=value"}
	result := removeEnvVars(env, "WEIRD_ENTRY")
	if len(result) != 1 || result[0] != "NORMAL=value" {
		t.Errorf("expected only NORMAL=value, got %v", result)
	}
}
