package config

import "testing"

// TestClaudeCodePresetIncludesSystemReadPaths guards the fix for the field
// report where even /bin/echo was denied under the claude-code preset: the
// child could not resolve its dynamic loader or exec system binaries until the
// standard system read paths were added to the filesystem allow list. Landlock
// and the interposer deny everything outside the root and this allow list, so
// these entries are load-bearing for the preset to run any real program.
func TestClaudeCodePresetIncludesSystemReadPaths(t *testing.T) {
	cfg, err := LoadProfile("claude-code")
	if err != nil {
		t.Fatalf("LoadProfile(claude-code): %v", err)
	}

	have := make(map[string]bool)
	for _, p := range cfg.Filesystem.Allow {
		have[p] = true
	}

	for _, want := range []string{"/usr/", "/etc/", "/sys/"} {
		if !have[want] {
			t.Errorf("claude-code preset filesystem.allow missing system read path %q; have %v", want, cfg.Filesystem.Allow)
		}
	}
	for _, forbidden := range []string{"/proc/", "/dev/"} {
		if have[forbidden] {
			t.Errorf("claude-code preset must not broadly grant %q; have %v", forbidden, cfg.Filesystem.Allow)
		}
	}
}
