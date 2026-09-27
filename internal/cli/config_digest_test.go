package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/spf13/cobra"
)

func TestWrapRecordsUnchangedConfigDigestWithoutWarning(t *testing.T) {
	if filepath.Separator == '\\' {
		t.Skip("wrap test launches a POSIX command")
	}
	dir := t.TempDir()
	writeTestConfig(t, dir, plainLaunchTOML(t))
	withWorkingDir(t, dir)

	run := func() string {
		var runErr error
		stderr := captureStderr(t, func() {
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			runErr = wrapCmd.RunE(cmd, []string{"--", "/bin/true"})
		})
		if runErr != nil {
			t.Fatalf("wrap: %v", runErr)
		}
		return stderr
	}
	if stderr := run(); strings.Contains(stderr, "effective config changed") {
		t.Fatalf("first wrap warned about a prior config digest:\n%s", stderr)
	}
	if stderr := run(); strings.Contains(stderr, "effective config changed") {
		t.Fatalf("unchanged config warned:\n%s", stderr)
	}

	records := digestRecords(t, resolvedAuditDB(t, dir), dir)
	if len(records) != 2 {
		t.Fatalf("config.digest rows = %d, want 2", len(records))
	}
	if records[0].Digest == "" || records[0].ConfigPath == "" || records[0].ConfigMTime == "" {
		t.Fatalf("first config.digest record missing required metadata: %+v", records[0])
	}
	if records[0].ConfigPath != filepath.Join(dir, config.Dir, config.File) {
		t.Fatalf("config.digest config path = %q", records[0].ConfigPath)
	}
	if records[1].Digest != records[0].Digest {
		t.Fatalf("unchanged config digests differ: %s != %s", records[1].Digest, records[0].Digest)
	}
	if records[1].PreviousDigest != records[0].Digest {
		t.Fatalf("second config.digest previous_digest = %q, want %q", records[1].PreviousDigest, records[0].Digest)
	}
}

func TestConfigDigestCanonicalizesPolicyAndExcludesCloudAPIKey(t *testing.T) {
	project := t.TempDir()
	configPath := filepath.Join(project, config.Dir, config.File)
	cfg := config.DefaultConfig()
	cfg.Network.Allow = []string{"b.example", "a.example"}
	cfg.Cloud.APIKey = "must-not-be-recorded"
	first, err := newConfigDigestRecord(&cfg, configPath, filepath.Join(project, "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Network.Allow = []string{"a.example", "b.example"}
	second, err := newConfigDigestRecord(&cfg, configPath, filepath.Join(project, "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest || !bytes.Equal(first.Policy, second.Policy) {
		t.Fatalf("equivalent policy ordering changed digest: %s != %s", first.Digest, second.Digest)
	}
	if bytes.Contains(first.Policy, []byte(cfg.Cloud.APIKey)) {
		t.Fatalf("canonical policy leaked cloud.api_key: %s", first.Policy)
	}
}

func TestConfigDigestResolvesFilesystemPolicyPaths(t *testing.T) {
	if filepath.Separator == '\\' {
		t.Skip("symlink fixture is POSIX-only")
	}
	project := t.TempDir()
	root := filepath.Join(project, "real-root")
	if err := os.Mkdir(root, 0o700); err != nil {
		t.Fatal(err)
	}
	rootLink := filepath.Join(project, "root-link")
	if err := os.Symlink(root, rootLink); err != nil {
		t.Fatal(err)
	}
	withWorkingDir(t, project)

	cfg := config.DefaultConfig()
	cfg.Filesystem.Root = rootLink
	cfg.Filesystem.AllowRW = []string{filepath.Join(rootLink, "scratch")}
	record, err := newConfigDigestRecord(&cfg, filepath.Join(project, config.Dir, config.File), filepath.Join(project, "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	var policy struct {
		Filesystem struct {
			Root    string   `json:"root"`
			AllowRW []string `json:"allow_rw"`
		} `json:"filesystem"`
	}
	if err := json.Unmarshal(record.Policy, &policy); err != nil {
		t.Fatal(err)
	}
	if policy.Filesystem.Root != root {
		t.Fatalf("canonical filesystem root = %q, want %q", policy.Filesystem.Root, root)
	}
	if got, want := policy.Filesystem.AllowRW, []string{filepath.Join(root, "scratch")}; len(got) != 1 || got[0] != want[0] {
		t.Fatalf("canonical filesystem allow_rw = %q, want %q", got, want)
	}
}

func TestConfigDigestAllowRWChangeWarnsAndStaysSigned(t *testing.T) {
	project := t.TempDir()
	configPath := filepath.Join(project, config.Dir, config.File)
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("[project]\nroot = \".\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dbPath := filepath.Join(project, "events.db")
	keyDir := t.TempDir()
	if err := os.Chmod(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(keyDir, "audit.key")
	logger, err := logging.NewLogger(dbPath, project, logging.WithSigning(keyPath))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer logger.Close()

	cfg := config.DefaultConfig()
	cfg.Project.Root = "."
	cfg.Filesystem.Root = project
	if err := recordConfigDigest(logger, &cfg, configPath, dbPath, "first", io.Discard); err != nil {
		t.Fatalf("first config digest: %v", err)
	}
	cfg.Filesystem.AllowRW = []string{"scratch"}
	var warning strings.Builder
	if err := recordConfigDigest(logger, &cfg, configPath, dbPath, "second", &warning); err != nil {
		t.Fatalf("changed config digest: %v", err)
	}
	if !strings.Contains(warning.String(), "filesystem.allow_rw") {
		t.Fatalf("allow_rw warning did not name the changed field:\n%s", warning.String())
	}

	records := digestRecords(t, dbPath, project)
	if len(records) != 2 || records[0].Digest == records[1].Digest {
		t.Fatalf("config digest rows = %+v, want two distinct digests", records)
	}
	if records[1].PreviousDigest != records[0].Digest {
		t.Fatalf("changed row previous_digest = %q, want %q", records[1].PreviousDigest, records[0].Digest)
	}
	pub, err := logging.LoadPublicKeyFile(keyPath)
	if err != nil {
		t.Fatalf("load audit public key: %v", err)
	}
	result, err := logger.VerifyChainSigned(pub, true)
	if err != nil {
		t.Fatalf("VerifyChainSigned: %v", err)
	}
	if !result.Intact || result.SigState != "authentic" || result.SigVerified != 2 {
		t.Fatalf("config.digest rows did not verify as signed: %+v", result)
	}
}

func TestRunAuditVerifyReportsDigestHistory(t *testing.T) {
	project, configPath := writeProjectConfig(t, `db = "events.db"`)
	withWorkingDir(t, project)
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	dbPath := resolvedAuditDB(t, project)
	logger, err := logging.NewLogger(dbPath, project)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	if err := recordConfigDigest(logger, cfg, configPath, dbPath, "one", io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := logger.Log(logging.Event{EventType: logging.EventSessionStart, Category: "session", Detail: "first", SessionID: "one"}); err != nil {
		t.Fatal(err)
	}
	cfg.Filesystem.AllowRW = []string{"scratch"}
	if err := recordConfigDigest(logger, cfg, configPath, dbPath, "two", io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := logger.Log(logging.Event{EventType: logging.EventSessionStart, Category: "session", Detail: "second", SessionID: "two"}); err != nil {
		t.Fatal(err)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}

	var output strings.Builder
	if err := runAuditVerify(context.Background(), &output, ""); err != nil {
		t.Fatalf("runAuditVerify: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), "Config digest history: 2 row(s), 1 change(s)") {
		t.Fatalf("config digest history missing or wrong:\n%s", output.String())
	}
}

func TestRunAuditVerifyRejectsSessionWithoutConfigDigest(t *testing.T) {
	project, _ := writeProjectConfig(t, `db = "events.db"`)
	withWorkingDir(t, project)
	dbPath := resolvedAuditDB(t, project)
	logger, err := logging.NewLogger(dbPath, project)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	if err := logger.Log(logging.Event{EventType: logging.EventSessionStart, Category: "session", Detail: "start", SessionID: "missing-digest"}); err != nil {
		t.Fatal(err)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}

	var output strings.Builder
	err = runAuditVerify(context.Background(), &output, "")
	if err == nil {
		t.Fatalf("runAuditVerify passed despite missing config.digest:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "CONFIG DIGEST: INCOMPLETE") || !strings.Contains(output.String(), "missing-digest") {
		t.Fatalf("missing config.digest was not reported:\n%s", output.String())
	}
}

func digestRecords(t *testing.T, dbPath, projectRoot string) []configDigestRecord {
	t.Helper()
	logger, err := logging.NewLogger(dbPath, projectRoot)
	if err != nil {
		t.Fatalf("open audit log: %v", err)
	}
	defer logger.Close()
	eventType := logging.EventConfigDigest
	events, err := logger.Query(logging.QueryOptions{EventType: &eventType, ByID: true, Limit: 100})
	if err != nil {
		t.Fatalf("query config.digest rows: %v", err)
	}
	records := make([]configDigestRecord, len(events))
	for i, event := range events {
		if err := json.Unmarshal([]byte(event.Detail), &records[i]); err != nil {
			t.Fatalf("decode config.digest row %d: %v", event.ID, err)
		}
	}
	return records
}
