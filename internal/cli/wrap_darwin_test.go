//go:build darwin

package cli

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
	"github.com/spf13/cobra"

	_ "modernc.org/sqlite"
)

// TestWrapMacOSFilesystemFenceRecordsOneEngagedState proves the wrap command,
// not merely the component helper, records precisely one filesystem-fence
// state after a Seatbelt profile is accepted and before its child runs.
func TestWrapMacOSFilesystemFenceRecordsOneEngagedState(t *testing.T) {
	if err := fsfence.EnsureSandboxExecAvailable(); err != nil {
		if os.Getenv("NOCKLOCK_SANDBOX_REQUIRE") == "1" {
			t.Fatalf("sandbox-exec unavailable: %v; NOCKLOCK_SANDBOX_REQUIRE=1 forbids skipping", err)
		}
		t.Skipf("sandbox-exec unavailable: %v", err)
	}

	project := t.TempDir()
	policy := strings.Replace(config.DefaultTOML(), "allow_all = false", "allow_all = true", 1)
	writeTestConfig(t, project, policy)
	withWorkingDir(t, project)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	if err := wrapCmd.RunE(cmd, []string{"--", "/usr/bin/true"}); err != nil {
		t.Fatalf("wrap should launch an allowed command under Seatbelt: %v", err)
	}

	dbPath := filepath.Join(project, config.Dir, "events.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer db.Close()

	rows, err := db.Query(`SELECT detail FROM events WHERE event_type = 'filesystem_fence_state' AND detail LIKE 'macOS filesystem-fence %'`)
	if err != nil {
		t.Fatalf("query fence state: %v", err)
	}
	defer rows.Close()

	var states []string
	for rows.Next() {
		var detail string
		if err := rows.Scan(&detail); err != nil {
			t.Fatalf("scan fence state: %v", err)
		}
		states = append(states, detail)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate fence state: %v", err)
	}
	if len(states) != 1 {
		t.Fatalf("expected exactly one macOS filesystem fence state, got %d: %q", len(states), states)
	}
	if !strings.Contains(states[0], "ENGAGED") || !strings.Contains(states[0], "Seatbelt profile applied") {
		t.Fatalf("expected an engaged Seatbelt state record, got %q", states[0])
	}
}
