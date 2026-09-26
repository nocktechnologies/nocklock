//go:build darwin

package cli

import (
	"context"
	"database/sql"
	"errors"
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

	states := macOSFilesystemFenceStates(t, db)
	if len(states) != 1 {
		t.Fatalf("expected exactly one macOS filesystem fence state, got %d: %q", len(states), states)
	}
	if !strings.Contains(states[0], "ENGAGED") || !strings.Contains(states[0], "Seatbelt profile applied") {
		t.Fatalf("expected an engaged Seatbelt state record, got %q", states[0])
	}
}

// TestWrapMacOSFilesystemFenceRefusesBeforeLaunchingChild proves a missing
// Seatbelt backend does not start the child under the default fail-closed
// policy, and records precisely one refusal state instead.
func TestWrapMacOSFilesystemFenceRefusesBeforeLaunchingChild(t *testing.T) {
	project := t.TempDir()
	writeTestConfig(t, project, config.DefaultTOML())
	withWorkingDir(t, project)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	oldEnsure := ensureSandboxExecAvailable
	ensureSandboxExecAvailable = func() error { return errors.New("sandbox-exec unavailable") }
	t.Cleanup(func() { ensureSandboxExecAvailable = oldEnsure })

	marker := filepath.Join(project, "child-ran")
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	err := wrapCmd.RunE(cmd, []string{"--", "/usr/bin/touch", marker})
	if err == nil {
		t.Fatal("wrap started the child despite an unavailable Seatbelt backend")
	}
	if _, statErr := os.Stat(marker); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("fail-closed wrap ran the child: stat marker = %v", statErr)
	}

	dbPath := filepath.Join(project, config.Dir, "events.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer db.Close()

	states := macOSFilesystemFenceStates(t, db)
	if len(states) != 1 || !strings.Contains(states[0], "REFUSED-TO-START") {
		t.Fatalf("expected exactly one refusal state, got %q", states)
	}
}

// TestWrapMacOSFilesystemFenceOptOutRecordsDegraded proves the temporary,
// explicit compatibility opt-out is loud and audited before it starts an
// unfenced child when Seatbelt cannot be applied.
func TestWrapMacOSFilesystemFenceOptOutRecordsDegraded(t *testing.T) {
	project := t.TempDir()
	policy := strings.Replace(config.DefaultTOML(), "macos_allow_unfenced = false", "macos_allow_unfenced = true", 1)
	writeTestConfig(t, project, policy)
	withWorkingDir(t, project)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	oldEnsure := ensureSandboxExecAvailable
	ensureSandboxExecAvailable = func() error { return errors.New("sandbox-exec unavailable") }
	t.Cleanup(func() { ensureSandboxExecAvailable = oldEnsure })

	marker := filepath.Join(project, "child-ran")
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	if err := wrapCmd.RunE(cmd, []string{"--", "/usr/bin/touch", marker}); err != nil {
		t.Fatalf("explicit macOS compatibility opt-out should start the child: %v", err)
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatalf("opt-out child did not run: %v", err)
	}

	dbPath := filepath.Join(project, config.Dir, "events.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer db.Close()

	states := macOSFilesystemFenceStates(t, db)
	if len(states) != 1 || !strings.Contains(states[0], "DEGRADED") || !strings.Contains(states[0], "macos_allow_unfenced=true") {
		t.Fatalf("expected exactly one explicit degraded state, got %q", states)
	}
}

func macOSFilesystemFenceStates(t *testing.T, db *sql.DB) []string {
	t.Helper()

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
	return states
}
