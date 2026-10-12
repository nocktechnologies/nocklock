package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/spf13/cobra"
)

// TestStatusNeverClaimsActive: right after init no wrap session exists, so
// status must say "configured" and never "active".
func TestStatusNeverClaimsActive(t *testing.T) {
	dir := t.TempDir()
	writeTestConfig(t, dir, config.DefaultTOML())
	withWorkingDir(t, dir)

	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	cmd.SetErr(&bytes.Buffer{})
	if err := statusCmd.RunE(cmd, nil); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	if strings.Contains(strings.ToLower(got), "active (") || strings.Contains(got, ": active") {
		t.Fatalf("status claims an active fence:\n%s", got)
	}
	for _, want := range []string{"Secret fence: configured", "Filesystem fence: configured", "Network fence: configured", "no active session"} {
		if !strings.Contains(got, want) {
			t.Fatalf("status missing %q:\n%s", want, got)
		}
	}
}
