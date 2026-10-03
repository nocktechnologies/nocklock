package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

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
			runErr = wrapCmd.RunE(cmd, []string{"--", "/usr/bin/true"})
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
	wantConfigPath, err := filepath.EvalSymlinks(filepath.Join(dir, config.Dir, config.File))
	if err != nil {
		t.Fatalf("resolve config path: %v", err)
	}
	if records[0].ConfigPath != wantConfigPath {
		t.Fatalf("config.digest config path = %q, want %q", records[0].ConfigPath, wantConfigPath)
	}
	if records[1].Digest != records[0].Digest {
		t.Fatalf("unchanged config digests differ: %s != %s", records[1].Digest, records[0].Digest)
	}
	if records[1].PreviousDigest != records[0].Digest {
		t.Fatalf("second config.digest previous_digest = %q, want %q", records[1].PreviousDigest, records[0].Digest)
	}
}

func TestWrapSymlinkedProjectRecordsCanonicalConfigPathAndVerifies(t *testing.T) {
	if filepath.Separator == '\\' {
		t.Skip("wrap test launches a POSIX command")
	}

	fixture := t.TempDir()
	project := filepath.Join(fixture, "project")
	projectLink := filepath.Join(fixture, "project-link")
	if err := os.Mkdir(project, 0o700); err != nil {
		t.Fatalf("create project: %v", err)
	}
	if err := os.Symlink(project, projectLink); err != nil {
		t.Fatalf("create project symlink: %v", err)
	}
	writeTestConfig(t, project, plainLaunchTOML(t))
	withWorkingDir(t, projectLink)
	t.Setenv("PWD", projectLink)
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())

	configPath, err := config.FindConfig()
	if err != nil {
		t.Fatalf("find config through symlink: %v", err)
	}
	wantConfigPath, err := filepath.EvalSymlinks(filepath.Join(projectLink, config.Dir, config.File))
	if err != nil {
		t.Fatalf("resolve config path: %v", err)
	}
	if configPath != wantConfigPath {
		t.Fatalf("FindConfig path = %q, want canonical path %q", configPath, wantConfigPath)
	}

	cmd := &cobra.Command{}
	cmd.SetContext(context.Background())
	if err := wrapCmd.RunE(cmd, []string{"--", "/usr/bin/true"}); err != nil {
		t.Fatalf("wrap through symlinked project: %v", err)
	}

	var verifyOut strings.Builder
	if err := runAuditVerify(context.Background(), &verifyOut, ""); err != nil {
		t.Fatalf("verify --audit after symlinked wrapped session: %v\n%s", err, verifyOut.String())
	}

	records := digestRecords(t, resolvedAuditDB(t, projectLink), projectLink)
	if len(records) != 1 {
		t.Fatalf("config.digest rows = %d, want 1", len(records))
	}
	if records[0].ConfigPath != wantConfigPath {
		t.Fatalf("config.digest config path = %q, want canonical path %q", records[0].ConfigPath, wantConfigPath)
	}
}

func TestConfigDigestCanonicalizesPolicyAndExcludesCloudAPIKey(t *testing.T) {
	project := t.TempDir()
	configPath := filepath.Join(project, config.Dir, config.File)
	cfg := config.DefaultConfig()
	cfg.Network.Allow = []string{"b.example", "a.example"}
	cfg.Cloud.APIKey = "must-not-be-recorded"
	first, err := newConfigDigestRecord(&cfg, configPath, filepath.Join(project, "events.db"), "proxy")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Network.Allow = []string{"a.example", "b.example"}
	second, err := newConfigDigestRecord(&cfg, configPath, filepath.Join(project, "events.db"), "proxy")
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest || !bytes.Equal(first.Policy, second.Policy) {
		t.Fatalf("equivalent policy ordering changed digest: %s != %s", first.Digest, second.Digest)
	}
	cfg.Network.RequireEnforced = true
	third, err := newConfigDigestRecord(&cfg, configPath, filepath.Join(project, "events.db"), "proxy")
	if err != nil {
		t.Fatal(err)
	}
	if second.Digest == third.Digest {
		t.Fatal("network.require_enforced change did not change the config digest")
	}
	if bytes.Contains(first.Policy, []byte(cfg.Cloud.APIKey)) {
		t.Fatalf("canonical policy leaked cloud.api_key: %s", first.Policy)
	}
}

func TestConfigDigestCoversRequireEnforcedCLIFlag(t *testing.T) {
	project := t.TempDir()
	configPath := filepath.Join(project, config.Dir, config.File)
	cfg := config.DefaultConfig()
	base, err := newConfigDigestRecord(&cfg, configPath, filepath.Join(project, "events.db"), "proxy")
	if err != nil {
		t.Fatal(err)
	}
	effective := effectiveWrapConfig(&cfg, WrapFlags{RequireEnforcedEgress: true})
	flagged, err := newConfigDigestRecord(&effective, configPath, filepath.Join(project, "events.db"), "proxy")
	if err != nil {
		t.Fatal(err)
	}
	if base.Digest == flagged.Digest {
		t.Fatal("--require-enforced-egress did not change the signed config digest")
	}
	if !jsonPathPresent(flagged.Policy, "network.require_enforced") {
		t.Fatalf("effective policy omitted network.require_enforced: %s", flagged.Policy)
	}
}

var configDigestPolicyFields = map[string]string{
	"ProfileName":                   "profile",
	"Project.Name":                  "project.name",
	"Project.Root":                  "project.root",
	"Filesystem.Root":               "filesystem.root",
	"Filesystem.Mode":               "filesystem.mode",
	"Filesystem.LinuxEnforcement":   "filesystem.linux_enforcement",
	"Filesystem.Allow":              "filesystem.allow",
	"Filesystem.AllowRW":            "filesystem.allow_rw",
	"Filesystem.Deny":               "filesystem.deny",
	"Filesystem.MacOSAllowUnfenced": "filesystem.macos_allow_unfenced",
	"Filesystem.Hardened":           "filesystem.hardened",
	"Network.Allow":                 "network.allow",
	"Network.AllowAll":              "network.allow_all",
	"Network.AllowPrivateRanges":    "network.allow_private_ranges",
	"Network.RequireEnforced":       "network.require_enforced",
	"Secrets.Pass":                  "secrets.pass",
	"Secrets.Block":                 "secrets.block",
	"Secrets.ScanEnv":               "secrets.scan_env",
	"Secrets.ScanPaths":             "secrets.scan_paths",
	"Secrets.ScanEnvAllow":          "secrets.scan_env_allow",
	"Syscall.Enforcement":           "syscall.enforcement",
	"Syscall.AllowNamespaces":       "syscall.allow_namespaces",
	"Syscall.SocketFamilies":        "syscall.socket_families",
	"Syscall.ExtraDeny":             "syscall.extra_deny",
	"Logging.DB":                    "logging.db",
	"Logging.Level":                 "logging.level",
	"Audit.Forward.Enabled":         "audit.forward.enabled",
	"Audit.Forward.URL":             "audit.forward.url",
	"Audit.Forward.APIKeyEnv":       "audit.forward.api_key_env",
	"Cloud.Enabled":                 "cloud.enabled",
	"Cloud.Endpoint":                "cloud.endpoint",
}

// configDigestNotSecurityRelevantFields requires an explicit decision for any
// future config field that does not belong in the digest.
var configDigestNotSecurityRelevantFields = map[string]struct{}{
	"Cloud.APIKey": {}, // A credential, never policy data; including it would leak a secret into the audit log.
}

func TestConfigDigestCoversTopLevelConfigFields(t *testing.T) {
	cfg := config.DefaultConfig()
	record, err := newConfigDigestRecord(&cfg, filepath.Join(t.TempDir(), config.Dir, config.File), filepath.Join(t.TempDir(), "events.db"), "proxy")
	if err != nil {
		t.Fatal(err)
	}
	fieldPaths := configDigestFieldPaths(reflect.TypeFor[config.Config](), "")
	for _, fieldPath := range fieldPaths {
		if policyPath, covered := configDigestPolicyFields[fieldPath]; covered {
			if !jsonPathPresent(record.Policy, policyPath) {
				t.Errorf("config field %s is mapped to missing policy field %q", fieldPath, policyPath)
			}
			continue
		}
		if _, excluded := configDigestNotSecurityRelevantFields[fieldPath]; !excluded {
			t.Errorf("config field %s is neither canonicalized nor explicitly marked not security-relevant", fieldPath)
		}
	}
	for fieldName := range configDigestPolicyFields {
		if !slices.Contains(fieldPaths, fieldName) {
			t.Errorf("stale canonical policy mapping for removed config field %s", fieldName)
		}
	}
}

func configDigestFieldPaths(configType reflect.Type, prefix string) []string {
	var paths []string
	for i := 0; i < configType.NumField(); i++ {
		field := configType.Field(i)
		path := field.Name
		if prefix != "" {
			path = prefix + "." + path
		}
		if field.Type.Kind() == reflect.Struct {
			paths = append(paths, configDigestFieldPaths(field.Type, path)...)
			continue
		}
		paths = append(paths, path)
	}
	return paths
}

func jsonPathPresent(document json.RawMessage, path string) bool {
	current := document
	for _, field := range strings.Split(path, ".") {
		var object map[string]json.RawMessage
		if err := json.Unmarshal(current, &object); err != nil {
			return false
		}
		value, found := object[field]
		if !found {
			return false
		}
		current = value
	}
	return true
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
	record, err := newConfigDigestRecord(&cfg, filepath.Join(project, config.Dir, config.File), filepath.Join(project, "events.db"), "proxy")
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
	wantRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	if policy.Filesystem.Root != wantRoot {
		t.Fatalf("canonical filesystem root = %q, want %q", policy.Filesystem.Root, wantRoot)
	}
	if got, want := policy.Filesystem.AllowRW, []string{filepath.Join(wantRoot, "scratch")}; len(got) != 1 || got[0] != want[0] {
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
	if err := recordConfigDigest(logger, &cfg, configPath, dbPath, "first", "proxy", io.Discard); err != nil {
		t.Fatalf("first config digest: %v", err)
	}
	cfg.Filesystem.AllowRW = []string{"scratch"}
	var warning strings.Builder
	if err := recordConfigDigest(logger, &cfg, configPath, dbPath, "second", "proxy", &warning); err != nil {
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

func TestConfigDigestNetworkFenceModeChangesAndWarns(t *testing.T) {
	project, configPath := writeProjectConfig(t, `db = "events.db"`)
	dbPath := resolvedAuditDB(t, project)
	logger, err := logging.NewLogger(dbPath, project)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	defer logger.Close()
	cfg, err := config.Load(configPath)
	if err != nil {
		t.Fatal(err)
	}

	if err := recordConfigDigest(logger, cfg, configPath, dbPath, "proxy", "proxy", io.Discard); err != nil {
		t.Fatalf("record proxy digest: %v", err)
	}
	var warning strings.Builder
	if err := recordConfigDigest(logger, cfg, configPath, dbPath, "netns", "netns", &warning); err != nil {
		t.Fatalf("record netns digest: %v", err)
	}
	if !strings.Contains(warning.String(), "network.mode") {
		t.Fatalf("net-fence warning did not name the changed field:\n%s", warning.String())
	}

	records := digestRecords(t, dbPath, project)
	if len(records) != 2 || records[0].Digest == records[1].Digest {
		t.Fatalf("network fence mode did not change the digest: %+v", records)
	}
}

func TestConfigDigestPredecessorsFollowCommittedOrder(t *testing.T) {
	project, configPath := writeProjectConfig(t, `db = "events.db"`)
	dbPath := resolvedAuditDB(t, project)
	logger, err := logging.NewLogger(dbPath, project)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Close()
		t.Fatal(err)
	}
	if err := recordConfigDigest(logger, cfg, configPath, dbPath, "baseline", "proxy", io.Discard); err != nil {
		logger.Close()
		t.Fatal(err)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}

	const writers = 8
	start := make(chan struct{})
	errs := make(chan error, writers)
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		cfgCopy := *cfg
		cfgCopy.Network.Allow = []string{string(rune('a'+i)) + ".example"}
		wg.Add(1)
		go func(sessionID string, current config.Config) {
			defer wg.Done()
			<-start
			concurrentLogger, err := logging.NewLogger(dbPath, project)
			if err != nil {
				errs <- err
				return
			}
			err = recordConfigDigest(concurrentLogger, &current, configPath, dbPath, sessionID, "proxy", io.Discard)
			if closeErr := concurrentLogger.Close(); err == nil {
				err = closeErr
			}
			errs <- err
		}(string(rune('a'+i)), cfgCopy)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}

	records := digestRecords(t, dbPath, project)
	if len(records) != writers+1 {
		t.Fatalf("config.digest rows = %d, want %d", len(records), writers+1)
	}
	for i := 1; i < len(records); i++ {
		if records[i].PreviousDigest != records[i-1].Digest {
			t.Fatalf("record %d previous_digest = %q, want committed predecessor %q", i, records[i].PreviousDigest, records[i-1].Digest)
		}
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
	if err := recordConfigDigest(logger, cfg, configPath, dbPath, "one", "proxy", io.Discard); err != nil {
		t.Fatal(err)
	}
	if err := logger.Log(logging.Event{EventType: logging.EventSessionStart, Category: "session", Detail: "first", SessionID: "one"}); err != nil {
		t.Fatal(err)
	}
	cfg.Filesystem.AllowRW = []string{"scratch"}
	if err := recordConfigDigest(logger, cfg, configPath, dbPath, "two", "proxy", io.Discard); err != nil {
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

func TestRunAuditVerifyTreatsPreAdoptionSessionsAsLegacy(t *testing.T) {
	project, configPath := writeProjectConfig(t, `db = "events.db"`)
	withWorkingDir(t, project)
	dbPath := resolvedAuditDB(t, project)
	logger, err := logging.NewLogger(dbPath, project)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	if err := logger.Log(logging.Event{EventType: logging.EventSessionStart, Category: "session", Detail: "legacy", SessionID: "legacy"}); err != nil {
		logger.Close()
		t.Fatal(err)
	}
	if err := logger.Log(logging.Event{EventType: logging.EventSessionStart, Category: "session", Detail: "empty legacy ID"}); err != nil {
		logger.Close()
		t.Fatalf("log legacy start with empty session ID: %v", err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Close()
		t.Fatal(err)
	}
	if err := recordConfigDigest(logger, cfg, configPath, dbPath, "post-adoption", "proxy", io.Discard); err != nil {
		logger.Close()
		t.Fatal(err)
	}
	if err := logger.Log(logging.Event{EventType: logging.EventSessionStart, Category: "session", Detail: "post-adoption", SessionID: "post-adoption"}); err != nil {
		logger.Close()
		t.Fatal(err)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}

	var output strings.Builder
	if err := runAuditVerify(context.Background(), &output, ""); err != nil {
		t.Fatalf("runAuditVerify rejected a pre-adoption session: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), "1 legacy session(s)") {
		t.Fatalf("legacy sessions were not counted:\n%s", output.String())
	}
}

func TestRunAuditVerifyRejectsSessionWithoutConfigDigest(t *testing.T) {
	project, configPath := writeProjectConfig(t, `db = "events.db"`)
	withWorkingDir(t, project)
	dbPath := resolvedAuditDB(t, project)
	logger, err := logging.NewLogger(dbPath, project)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Close()
		t.Fatal(err)
	}
	if err := recordConfigDigest(logger, cfg, configPath, dbPath, "adoption", "proxy", io.Discard); err != nil {
		logger.Close()
		t.Fatal(err)
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

func TestRunAuditVerifyAllowsSetupEventsWhileConfigDigestIsPending(t *testing.T) {
	tests := []struct {
		name          string
		digestSession string
		events        []logging.Event
		wantMissing   string
	}{
		{
			name:          "setup event before session start",
			digestSession: "session",
			events: []logging.Event{
				{EventType: logging.EventProxyStart, SessionID: "session"},
				{EventType: logging.EventSessionStart, SessionID: "session"},
				{EventType: logging.EventFilePassed, SessionID: "session"},
			},
		},
		{
			name:          "setup failure before session start",
			digestSession: "session",
			events: []logging.Event{
				{EventType: logging.EventProxyStart, SessionID: "session"},
			},
		},
		{
			name:          "session without digest after adoption",
			digestSession: "adoption",
			events: []logging.Event{
				{EventType: logging.EventSessionStart, SessionID: "missing"},
			},
			wantMissing: "missing",
		},
		{
			name:          "session start with empty ID after adoption",
			digestSession: "adoption",
			events: []logging.Event{
				{EventType: logging.EventSessionStart},
			},
			wantMissing: "(empty)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			project, configPath := writeProjectConfig(t, `db = "events.db"`)
			withWorkingDir(t, project)
			keyRoot := filepath.Join(t.TempDir(), "xdg-config")
			t.Setenv("XDG_CONFIG_HOME", keyRoot)
			dbPath := resolvedAuditDB(t, project)
			logger, err := logging.NewLogger(dbPath, project, logging.WithSigning(filepath.Join(keyRoot, "nocklock", "signing-ed25519.key")))
			if err != nil {
				t.Fatalf("NewLogger: %v", err)
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				logger.Close()
				t.Fatal(err)
			}
			if err := recordConfigDigest(logger, cfg, configPath, dbPath, tt.digestSession, "proxy", io.Discard); err != nil {
				logger.Close()
				t.Fatalf("record config digest: %v", err)
			}
			for _, event := range tt.events {
				if err := logger.Log(event); err != nil {
					logger.Close()
					t.Fatalf("log %s for %s: %v", event.EventType, event.SessionID, err)
				}
			}
			if err := logger.Close(); err != nil {
				t.Fatal(err)
			}

			var output strings.Builder
			err = runAuditVerify(context.Background(), &output, "")
			if tt.wantMissing == "" {
				if err != nil {
					t.Fatalf("runAuditVerify rejected setup events covered by the digest: %v\n%s", err, output.String())
				}
			} else if err == nil || !strings.Contains(output.String(), tt.wantMissing) {
				t.Fatalf("runAuditVerify did not report missing digest for %q: %v\n%s", tt.wantMissing, err, output.String())
			}
		})
	}
}

func TestRunAuditVerifyRejectsPostAdoptionStartReusingLegacyID(t *testing.T) {
	project, configPath := writeProjectConfig(t, `db = "events.db"`)
	withWorkingDir(t, project)
	dbPath := resolvedAuditDB(t, project)
	logger, err := logging.NewLogger(dbPath, project)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	if err := logger.Log(logging.Event{EventType: logging.EventSecretPassed, Category: "secret", Detail: "legacy event", SessionID: "reused"}); err != nil {
		logger.Close()
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Close()
		t.Fatal(err)
	}
	if err := recordConfigDigest(logger, cfg, configPath, dbPath, "adoption", "proxy", io.Discard); err != nil {
		logger.Close()
		t.Fatal(err)
	}
	if err := logger.Log(logging.Event{EventType: logging.EventSessionStart, Category: "session", Detail: "post-adoption start", SessionID: "reused"}); err != nil {
		logger.Close()
		t.Fatal(err)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}

	var output strings.Builder
	err = runAuditVerify(context.Background(), &output, "")
	if err == nil {
		t.Fatalf("runAuditVerify accepted a post-adoption start with a reused legacy ID:\n%s", output.String())
	}
	if !strings.Contains(output.String(), "CONFIG DIGEST: INCOMPLETE") || !strings.Contains(output.String(), "reused") {
		t.Fatalf("reused session ID was not reported as missing:\n%s", output.String())
	}
}

func TestRunAuditVerifyRequiresOneDigestPerSessionStart(t *testing.T) {
	project, configPath := writeProjectConfig(t, `db = "events.db"`)
	withWorkingDir(t, project)
	dbPath := resolvedAuditDB(t, project)
	logger, err := logging.NewLogger(dbPath, project)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Close()
		t.Fatal(err)
	}
	if err := recordConfigDigest(logger, cfg, configPath, dbPath, "reused", "proxy", io.Discard); err != nil {
		logger.Close()
		t.Fatal(err)
	}
	if err := logger.Log(logging.Event{EventType: logging.EventSessionStart, Category: "session", Detail: "first", SessionID: "reused"}); err != nil {
		logger.Close()
		t.Fatal(err)
	}
	if err := logger.Log(logging.Event{EventType: logging.EventSessionStart, Category: "session", Detail: "second", SessionID: "reused"}); err != nil {
		logger.Close()
		t.Fatal(err)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}

	var output strings.Builder
	err = runAuditVerify(context.Background(), &output, "")
	if err == nil || !strings.Contains(output.String(), "CONFIG DIGEST: INCOMPLETE") || !strings.Contains(output.String(), "reused") {
		t.Fatalf("runAuditVerify accepted two session starts with one digest: %v\n%s", err, output.String())
	}
}

func TestRunAuditVerifyAllowsLegacySessionToFinishAfterAdoption(t *testing.T) {
	project, configPath := writeProjectConfig(t, `db = "events.db"`)
	withWorkingDir(t, project)
	dbPath := resolvedAuditDB(t, project)
	logger, err := logging.NewLogger(dbPath, project)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	if err := logger.Log(logging.Event{EventType: logging.EventSessionStart, Category: "session", Detail: "legacy start", SessionID: "legacy"}); err != nil {
		logger.Close()
		t.Fatal(err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Close()
		t.Fatal(err)
	}
	if err := recordConfigDigest(logger, cfg, configPath, dbPath, "post-adoption", "proxy", io.Discard); err != nil {
		logger.Close()
		t.Fatal(err)
	}
	if err := logger.Log(logging.Event{EventType: logging.EventSessionEnd, Category: "session", Detail: "legacy end", SessionID: "legacy"}); err != nil {
		logger.Close()
		t.Fatal(err)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}

	var output strings.Builder
	if err := runAuditVerify(context.Background(), &output, ""); err != nil {
		t.Fatalf("runAuditVerify rejected a legacy session that finished after adoption: %v\n%s", err, output.String())
	}
	if !strings.Contains(output.String(), "1 legacy session(s)") {
		t.Fatalf("legacy session was not counted:\n%s", output.String())
	}
}

func TestRunAuditVerifyRejectsInvalidConfigDigest(t *testing.T) {
	project, configPath := writeProjectConfig(t, `db = "events.db"`)
	withWorkingDir(t, project)
	dbPath := resolvedAuditDB(t, project)
	logger, err := logging.NewLogger(dbPath, project)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Close()
		t.Fatal(err)
	}
	record, err := newConfigDigestRecord(cfg, configPath, dbPath, "proxy")
	if err != nil {
		logger.Close()
		t.Fatal(err)
	}
	record.Digest = strings.Repeat("0", len(record.Digest))
	detail, err := json.Marshal(record)
	if err != nil {
		logger.Close()
		t.Fatal(err)
	}
	if err := logger.Log(logging.Event{EventType: logging.EventConfigDigest, Category: "config", Detail: string(detail), SessionID: "invalid"}); err != nil {
		logger.Close()
		t.Fatal(err)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}

	var output strings.Builder
	err = runAuditVerify(context.Background(), &output, "")
	if err == nil || !strings.Contains(err.Error(), "digest does not match canonical policy") {
		t.Fatalf("runAuditVerify accepted an invalid config digest: %v\n%s", err, output.String())
	}
}

func TestRunAuditVerifyRejectsInvalidConfigDigestPredecessor(t *testing.T) {
	project, configPath := writeProjectConfig(t, `db = "events.db"`)
	withWorkingDir(t, project)
	dbPath := resolvedAuditDB(t, project)
	logger, err := logging.NewLogger(dbPath, project)
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Close()
		t.Fatal(err)
	}
	record, err := newConfigDigestRecord(cfg, configPath, dbPath, "proxy")
	if err != nil {
		logger.Close()
		t.Fatal(err)
	}
	record.PreviousDigest = "unexpected"
	detail, err := json.Marshal(record)
	if err != nil {
		logger.Close()
		t.Fatal(err)
	}
	if err := logger.Log(logging.Event{EventType: logging.EventConfigDigest, Category: "config", Detail: string(detail), SessionID: "invalid"}); err != nil {
		logger.Close()
		t.Fatal(err)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}

	var output strings.Builder
	err = runAuditVerify(context.Background(), &output, "")
	if err == nil || !strings.Contains(err.Error(), "predecessor before the first digest") {
		t.Fatalf("runAuditVerify accepted an invalid config digest predecessor: %v\n%s", err, output.String())
	}
}

func TestRunAuditVerifyAllowsOnlyTheFirstRetainedDigestPredecessorAfterPrune(t *testing.T) {
	tests := []struct {
		name             string
		thirdPredecessor string
		unverifiedPrune  bool
		wantError        string
	}{
		{name: "authenticated prune boundary"},
		{name: "later digest link remains checked", thirdPredecessor: "broken-link", wantError: "predecessor does not match the previous digest"},
		{name: "unverified prune boundary rejected", unverifiedPrune: true, wantError: "predecessor before the first digest"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			project, configPath := writeProjectConfig(t, `db = "events.db"`)
			withWorkingDir(t, project)
			keyRoot := filepath.Join(t.TempDir(), "xdg-config")
			t.Setenv("XDG_CONFIG_HOME", keyRoot)
			dbPath := resolvedAuditDB(t, project)
			logger, err := logging.NewLogger(dbPath, project, logging.WithSigning(filepath.Join(keyRoot, "nocklock", "signing-ed25519.key")))
			if err != nil {
				t.Fatalf("NewLogger: %v", err)
			}
			cfg, err := config.Load(configPath)
			if err != nil {
				logger.Close()
				t.Fatal(err)
			}

			logDigest := func(sessionID string, timestamp time.Time, previous string) string {
				t.Helper()
				record, err := newConfigDigestRecord(cfg, configPath, dbPath, "proxy")
				if err != nil {
					t.Fatalf("new config digest: %v", err)
				}
				record.PreviousDigest = previous
				detail, err := json.Marshal(record)
				if err != nil {
					t.Fatalf("marshal config digest: %v", err)
				}
				if err := logger.Log(logging.Event{
					Timestamp: timestamp,
					EventType: logging.EventConfigDigest,
					Category:  "config",
					Detail:    string(detail),
					SessionID: sessionID,
				}); err != nil {
					t.Fatalf("log config digest: %v", err)
				}
				return record.Digest
			}

			now := time.Now().UTC()
			firstDigest := logDigest("old", now.Add(-48*time.Hour), "")
			logDigest("retained", now, firstDigest)
			if tt.thirdPredecessor != "" {
				logDigest("later", now.Add(time.Second), tt.thirdPredecessor)
			}
			pruned, err := logger.Prune(24 * time.Hour)
			if err != nil {
				logger.Close()
				t.Fatalf("Prune: %v", err)
			}
			if pruned != 1 {
				logger.Close()
				t.Fatalf("Prune removed %d events, want 1", pruned)
			}
			if tt.unverifiedPrune {
				chain, err := logger.VerifyChainSigned(nil, false)
				if err != nil {
					logger.Close()
					t.Fatalf("VerifyChainSigned without a key: %v", err)
				}
				if chain.PrunedAt == nil || chain.SigState != "unverified" {
					logger.Close()
					t.Fatalf("unverified result = %+v, want a prune with unverified signatures", chain)
				}
				_, err = inspectConfigDigestHistory(logger, chain)
				if err == nil || !strings.Contains(err.Error(), tt.wantError) {
					logger.Close()
					t.Fatalf("inspectConfigDigestHistory trusted an unverified prune: %v", err)
				}
				if err := logger.Close(); err != nil {
					t.Fatal(err)
				}
				return
			}
			if err := logger.Close(); err != nil {
				t.Fatal(err)
			}

			var output strings.Builder
			err = runAuditVerify(context.Background(), &output, "")
			if tt.wantError == "" {
				if err != nil {
					t.Fatalf("runAuditVerify rejected the first retained digest after prune: %v\n%s", err, output.String())
				}
				if !strings.Contains(output.String(), "NOTE: chain was re-anchored by a prune") || !strings.Contains(output.String(), "1 row(s)") {
					t.Fatalf("verification did not report the authenticated prune and retained digest:\n%s", output.String())
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantError) {
				t.Fatalf("runAuditVerify did not reject the later broken digest link: %v\n%s", err, output.String())
			}
		})
	}
}

func TestRunAuditVerifyIgnoresRetainedRowsForPrunedSession(t *testing.T) {
	project, configPath := writeProjectConfig(t, `db = "events.db"`)
	withWorkingDir(t, project)
	keyRoot := filepath.Join(t.TempDir(), "xdg-config")
	t.Setenv("XDG_CONFIG_HOME", keyRoot)
	dbPath := resolvedAuditDB(t, project)
	logger, err := logging.NewLogger(dbPath, project, logging.WithSigning(filepath.Join(keyRoot, "nocklock", "signing-ed25519.key")))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		logger.Close()
		t.Fatal(err)
	}

	logDigest := func(sessionID string, timestamp time.Time, previous string) string {
		t.Helper()
		record, err := newConfigDigestRecord(cfg, configPath, dbPath, "proxy")
		if err != nil {
			t.Fatalf("new config digest: %v", err)
		}
		record.PreviousDigest = previous
		detail, err := json.Marshal(record)
		if err != nil {
			t.Fatalf("marshal config digest: %v", err)
		}
		if err := logger.Log(logging.Event{
			Timestamp: timestamp,
			EventType: logging.EventConfigDigest,
			Category:  "config",
			Detail:    string(detail),
			SessionID: sessionID,
		}); err != nil {
			t.Fatalf("log config digest: %v", err)
		}
		return record.Digest
	}

	now := time.Now().UTC()
	oldDigest := logDigest("old", now.Add(-49*time.Hour), "")
	if err := logger.Log(logging.Event{
		Timestamp: now.Add(-48 * time.Hour),
		EventType: logging.EventSessionStart,
		Category:  "session",
		Detail:    "old session start",
		SessionID: "old",
	}); err != nil {
		logger.Close()
		t.Fatalf("log old session start: %v", err)
	}
	logDigest("new", now.Add(-23*time.Hour), oldDigest)
	if err := logger.Log(logging.Event{
		Timestamp: now.Add(-22 * time.Hour),
		EventType: logging.EventSessionStart,
		Category:  "session",
		Detail:    "new session start",
		SessionID: "new",
	}); err != nil {
		logger.Close()
		t.Fatalf("log newer session start: %v", err)
	}
	if err := logger.Log(logging.Event{
		Timestamp: now,
		EventType: logging.EventSessionEnd,
		Category:  "session",
		Detail:    "old session end",
		SessionID: "old",
	}); err != nil {
		logger.Close()
		t.Fatalf("log old session end: %v", err)
	}

	pruned, err := logger.Prune(24 * time.Hour)
	if err != nil {
		logger.Close()
		t.Fatalf("Prune: %v", err)
	}
	if pruned != 2 {
		logger.Close()
		t.Fatalf("Prune removed %d events, want old digest and old start", pruned)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}

	var output strings.Builder
	if err := runAuditVerify(context.Background(), &output, ""); err != nil {
		t.Fatalf("runAuditVerify rejected retained rows for a pruned session: %v\n%s", err, output.String())
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
