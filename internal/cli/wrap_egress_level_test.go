package cli

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"io"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/spf13/cobra"
)

func TestWrapSessionStartRecordsSignedAdvisoryEgressLevel(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("wrap launches a POSIX command")
	}
	project := t.TempDir()
	writeTestConfig(t, project, plainLaunchTOML(t))
	withWorkingDir(t, project)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("NOCKLOCK_ANCHOR_URL", "")
	t.Setenv("NOCKLOCK_ANCHOR_TOKEN", "")

	stderr, err := runWrapCapturingStderr(t, []string{"--", "true"})
	if err != nil {
		t.Fatalf("wrap with syscall enforcement off should start in advisory mode: %v\n%s", err, stderr)
	}
	if !strings.Contains(stderr, "WARNING: network fence is ADVISORY") ||
		!strings.Contains(stderr, "a client that ignores HTTP_PROXY can reach any host") {
		t.Fatalf("wrap did not clearly warn that the proxy is advisory:\n%s", stderr)
	}

	dbPath := resolvedAuditDB(t, project)
	logger, err := logging.NewLogger(dbPath, project)
	if err != nil {
		t.Fatalf("open audit DB: %v", err)
	}
	start := logging.EventSessionStart
	events, err := logger.Query(logging.QueryOptions{EventType: &start, Limit: 10, ByID: true})
	if err != nil {
		logger.Close()
		t.Fatalf("query session-start event: %v", err)
	}
	if len(events) != 1 {
		logger.Close()
		t.Fatalf("session-start events = %d, want 1", len(events))
	}
	if events[0].EgressLevel != string(egressLevelAdvisory) {
		logger.Close()
		t.Fatalf("session-start egress level = %q, want ADVISORY", events[0].EgressLevel)
	}
	if events[0].Detail != "true" {
		logger.Close()
		t.Fatalf("session-start detail = %q, want command true", events[0].Detail)
	}
	if err := logger.Close(); err != nil {
		t.Fatalf("close audit DB: %v", err)
	}

	var audit bytes.Buffer
	if err := runAuditVerify(context.Background(), &audit, ""); err != nil {
		t.Fatalf("verify --audit failed for the signed egress-level event: %v\n%s", err, audit.String())
	}
	if !strings.Contains(audit.String(), "AUDIT: AUTHENTIC") {
		t.Fatalf("verify --audit did not authenticate the egress-level field:\n%s", audit.String())
	}

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open audit DB for tamper control: %v", err)
	}
	var signedDetail string
	if err := db.QueryRow("SELECT detail FROM events WHERE event_type = ?", string(logging.EventSessionStart)).Scan(&signedDetail); err != nil {
		db.Close()
		t.Fatalf("read signed event detail: %v", err)
	}
	tamperedDetail := strings.Replace(signedDetail, `"egress_level":"ADVISORY"`, `"egress_level":"KERNEL"`, 1)
	if tamperedDetail == signedDetail {
		db.Close()
		t.Fatalf("negative control could not locate the signed egress field in %q", signedDetail)
	}
	if _, err := db.Exec("UPDATE events SET detail = ? WHERE event_type = ?", tamperedDetail, string(logging.EventSessionStart)); err != nil {
		db.Close()
		t.Fatalf("tamper with signed egress field: %v", err)
	}
	if err := db.Close(); err != nil {
		t.Fatalf("close tampered audit DB: %v", err)
	}
	audit.Reset()
	if err := runAuditVerify(context.Background(), &audit, ""); err == nil {
		t.Fatalf("verify --audit accepted a changed egress level:\n%s", audit.String())
	}
	if !strings.Contains(audit.String(), "AUDIT: TAMPERED") {
		t.Fatalf("tampered egress level was not reported as a broken signed chain:\n%s", audit.String())
	}
}

func TestWrapRequireEnforcedEgressRejectsAdvisoryAndOff(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("wrap configuration test requires the POSIX test environment")
	}
	tests := []struct {
		name       string
		configEdit func(string) string
		args       []string
		wantLevel  string
	}{
		{
			name: "config rejects advisory proxy",
			configEdit: func(toml string) string {
				return strings.Replace(toml, "require_enforced = false", "require_enforced = true", 1)
			},
			args:      []string{"--", "sh", "-c", "touch child-started"},
			wantLevel: "ADVISORY",
		},
		{
			name: "flag rejects disabled network",
			configEdit: func(toml string) string {
				return strings.Replace(toml, "allow_all = false", "allow_all = true", 1)
			},
			args:      []string{"--require-enforced-egress", "--", "sh", "-c", "touch child-started"},
			wantLevel: "OFF",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			project := t.TempDir()
			writeTestConfig(t, project, tt.configEdit(plainLaunchTOML(t)))
			withWorkingDir(t, project)
			t.Setenv("XDG_CONFIG_HOME", t.TempDir())
			t.Setenv("NOCKLOCK_ANCHOR_URL", "")
			t.Setenv("NOCKLOCK_ANCHOR_TOKEN", "")

			stderr, err := runWrapCapturingStderr(t, tt.args)
			var exitErr *exitCodeError
			if !errors.As(err, &exitErr) || exitErr.code != 2 {
				t.Fatalf("wrap error = %v, want exit status 2\n%s", err, stderr)
			}
			if !strings.Contains(stderr, "effective egress level is "+tt.wantLevel) {
				t.Fatalf("refusal did not name %s:\n%s", tt.wantLevel, stderr)
			}
			if !strings.Contains(stderr, "--net-fence=netns") {
				t.Fatalf("refusal did not include the Linux netns fix:\n%s", stderr)
			}
			if _, err := os.Stat("child-started"); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("child ran despite required egress refusal; stat error = %v", err)
			}
		})
	}
}

func runWrapCapturingStderr(t *testing.T, args []string) (string, error) {
	t.Helper()
	original := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr pipe: %v", err)
	}
	os.Stderr = w
	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	runErr := wrapCmd.RunE(cmd, args)
	_ = w.Close()
	os.Stderr = original
	defer r.Close()
	data, readErr := io.ReadAll(r)
	if readErr != nil {
		t.Fatalf("read captured stderr: %v", readErr)
	}
	return string(data), runErr
}

func TestWrapRequireEnforcedEgressRejectsUnreachableWithoutStartingFence(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("UNREACHABLE is the Linux proxy-bridge posture")
	}
	project := t.TempDir()
	toml := plainLaunchTOML(t)
	toml = strings.Replace(toml, "enforcement = \"off\"", "enforcement = \"required\"", 1)
	toml = strings.Replace(toml, "require_enforced = false", "require_enforced = true", 1)
	writeTestConfig(t, project, toml)
	withWorkingDir(t, project)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	t.Setenv("NOCKLOCK_ANCHOR_URL", "")
	t.Setenv("NOCKLOCK_ANCHOR_TOKEN", "")

	stderr, err := runWrapCapturingStderr(t, []string{"--", "sh", "-c", "touch child-started"})
	var exitErr *exitCodeError
	if !errors.As(err, &exitErr) || exitErr.code != 2 {
		t.Fatalf("wrap error = %v, want exit status 2\n%s", err, stderr)
	}
	if !strings.Contains(stderr, "UNREACHABLE") || !strings.Contains(stderr, "enable the Linux filesystem interposer") {
		t.Fatalf("refusal did not name UNREACHABLE and its fix:\n%s", stderr)
	}
	if strings.Contains(stderr, "network fence is ADVISORY") {
		t.Fatalf("UNREACHABLE posture was mislabeled advisory:\n%s", stderr)
	}
	if _, err := os.Stat("child-started"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("child ran despite unreachable egress; stat error = %v", err)
	}
}
