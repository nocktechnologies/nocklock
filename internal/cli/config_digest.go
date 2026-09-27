package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
	"github.com/nocktechnologies/nocklock/internal/logging"
)

// configDigestRecord is the signed detail of a config.digest audit event. It
// deliberately excludes cloud.api_key: a policy audit record must not copy a
// credential into the event database.
type configDigestRecord struct {
	Digest         string          `json:"digest"`
	ConfigPath     string          `json:"config_path"`
	PreviousDigest string          `json:"previous_digest,omitempty"`
	ConfigMTime    string          `json:"config_mtime,omitempty"`
	Policy         json.RawMessage `json:"policy"`
}

// recordConfigDigest appends the current effective policy to the audit chain
// before the child starts. A changed policy is advisory, but an unrecordable
// policy is a fail-closed launch error.
func recordConfigDigest(logger *logging.Logger, cfg *config.Config, configPath, dbPath, sessionID string, stderr io.Writer) error {
	record, err := newConfigDigestRecord(cfg, configPath, dbPath)
	if err != nil {
		return err
	}

	previous, err := latestConfigDigest(logger)
	if err != nil {
		return err
	}
	if previous != nil {
		record.PreviousDigest = previous.Digest
	}

	detail, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("serialize config digest: %w", err)
	}
	if err := logger.Log(logging.Event{
		Timestamp: time.Now(),
		EventType: logging.EventConfigDigest,
		Category:  "config",
		Detail:    string(detail),
		SessionID: sessionID,
	}); err != nil {
		return fmt.Errorf("append config.digest audit row: %w", err)
	}

	if previous != nil && previous.Digest != record.Digest {
		fields := changedConfigPolicyFields(previous.Policy, record.Policy)
		if len(fields) == 0 {
			fields = []string{"canonical policy"}
		}
		mtime := record.ConfigMTime
		if mtime == "" {
			mtime = "unavailable"
		}
		fmt.Fprintf(stderr, "NockLock: warning: effective config changed since the previous wrap (digest %s -> %s; fields: %s; config mtime: %s)\n",
			previous.Digest, record.Digest, strings.Join(fields, ", "), mtime)
	}
	return nil
}

func newConfigDigestRecord(cfg *config.Config, configPath, dbPath string) (configDigestRecord, error) {
	policy, err := canonicalPolicy(cfg, configPath, dbPath)
	if err != nil {
		return configDigestRecord{}, fmt.Errorf("serialize canonical config policy: %w", err)
	}
	sum := sha256.Sum256(policy)

	path := configPath
	if !strings.HasPrefix(path, "embedded profile ") {
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
	}
	record := configDigestRecord{
		Digest:     hex.EncodeToString(sum[:]),
		ConfigPath: path,
		Policy:     policy,
	}
	if info, err := os.Stat(configPath); err == nil {
		record.ConfigMTime = info.ModTime().UTC().Format(time.RFC3339Nano)
	}
	return record, nil
}

// canonicalPolicy serializes the resolved security and audit policy in stable
// key order. cloud.api_key is deliberately absent: a policy audit record must
// never copy a credential into the event database.
func canonicalPolicy(cfg *config.Config, configPath, dbPath string) (json.RawMessage, error) {
	projectRoot := filepath.Dir(filepath.Dir(configPath))
	if abs, err := filepath.Abs(projectRoot); err == nil {
		projectRoot = abs
	}
	filesystem := map[string]any{
		"root":                 canonicalConfigPath(projectRoot, cfg.Filesystem.Root),
		"mode":                 cfg.Filesystem.Mode,
		"linux_enforcement":    cfg.Filesystem.LinuxEnforcement,
		"allow":                canonicalConfigPaths(projectRoot, cfg.Filesystem.Allow),
		"allow_rw":             canonicalConfigPaths(projectRoot, cfg.Filesystem.AllowRW),
		"deny":                 canonicalConfigPaths(projectRoot, cfg.Filesystem.Deny),
		"macos_allow_unfenced": cfg.Filesystem.MacOSAllowUnfenced,
		"hardened":             cfg.Filesystem.Hardened,
	}
	if cfg.Filesystem.Root != "" {
		resolved, err := fsfence.ProcessConfig(cfg.Filesystem)
		if err != nil {
			return nil, fmt.Errorf("resolve filesystem policy: %w", err)
		}
		filesystem["root"] = resolved.Root
		filesystem["mode"] = resolved.Mode
		filesystem["allow"] = canonicalStrings(resolved.AllowPaths)
		filesystem["allow_rw"] = canonicalStrings(resolved.AllowRWPaths)
		filesystem["deny"] = canonicalStrings(resolved.DenyPaths)
	}
	policy := map[string]any{
		"profile": cfg.ProfileName,
		"project": map[string]any{
			"name": cfg.Project.Name,
			"root": canonicalConfigPath(projectRoot, cfg.Project.Root),
		},
		"filesystem": filesystem,
		"network": map[string]any{
			"allow":                canonicalStrings(cfg.Network.Allow),
			"allow_all":            cfg.Network.AllowAll,
			"allow_private_ranges": cfg.Network.AllowPrivateRanges,
		},
		"secrets": map[string]any{
			"pass":           canonicalStrings(cfg.Secrets.Pass),
			"block":          canonicalStrings(cfg.Secrets.Block),
			"scan_env":       cfg.Secrets.ScanEnv,
			"scan_paths":     canonicalConfigPaths(projectRoot, cfg.Secrets.ScanPaths),
			"scan_env_allow": canonicalStrings(cfg.Secrets.ScanEnvAllow),
		},
		"syscall": map[string]any{
			"enforcement":      cfg.Syscall.Enforcement,
			"allow_namespaces": cfg.Syscall.AllowNamespaces,
			"socket_families":  canonicalStrings(cfg.Syscall.SocketFamilies),
			"extra_deny":       canonicalStrings(cfg.Syscall.ExtraDeny),
		},
		"logging": map[string]any{
			"db":    filepath.Clean(dbPath),
			"level": cfg.Logging.Level,
		},
		"cloud": map[string]any{
			"enabled":  cfg.Cloud.Enabled,
			"endpoint": cfg.Cloud.Endpoint,
		},
	}
	encoded, err := json.Marshal(policy)
	return json.RawMessage(encoded), err
}

func canonicalConfigPaths(projectRoot string, paths []string) []string {
	out := make([]string, len(paths))
	for i, path := range paths {
		out[i] = canonicalConfigPath(projectRoot, path)
	}
	return canonicalStrings(out)
}

func canonicalConfigPath(projectRoot, path string) string {
	if path == "" {
		return ""
	}
	if filepath.IsAbs(path) || path[0] == '~' {
		return filepath.Clean(path)
	}
	return filepath.Clean(filepath.Join(projectRoot, path))
}

func canonicalStrings(values []string) []string {
	out := append([]string{}, values...)
	slices.Sort(out)
	return slices.Compact(out)
}

func latestConfigDigest(logger *logging.Logger) (*configDigestRecord, error) {
	eventType := logging.EventConfigDigest
	events, err := logger.Query(logging.QueryOptions{EventType: &eventType, Descending: true, ByID: true, Limit: 1})
	if err != nil {
		return nil, fmt.Errorf("read previous config.digest audit row: %w", err)
	}
	if len(events) == 0 {
		return nil, nil
	}
	var record configDigestRecord
	if err := json.Unmarshal([]byte(events[0].Detail), &record); err != nil {
		return nil, fmt.Errorf("decode previous config.digest audit row: %w", err)
	}
	if record.Digest == "" {
		return nil, fmt.Errorf("decode previous config.digest audit row: digest is empty")
	}
	return &record, nil
}

type configDigestHistory struct {
	Rows            int
	Changes         int
	LastChange      *time.Time
	MissingSessions []string
}

func inspectConfigDigestHistory(logger *logging.Logger) (configDigestHistory, error) {
	events, err := allAuditEvents(logger)
	if err != nil {
		return configDigestHistory{}, err
	}

	history := configDigestHistory{}
	nonDigestEvents := make(map[string]int)
	digestEvents := make(map[string]int)
	var previousDigest string
	for _, event := range events {
		if event.EventType != logging.EventConfigDigest {
			// Administrative audit rows have no session ID. They are part of
			// the chain, but cannot be missing a per-wrap config.digest row.
			if event.SessionID != "" {
				nonDigestEvents[event.SessionID]++
			}
			continue
		}

		var record configDigestRecord
		if err := json.Unmarshal([]byte(event.Detail), &record); err != nil {
			return configDigestHistory{}, fmt.Errorf("decode config.digest audit row %d: %w", event.ID, err)
		}
		if record.Digest == "" {
			return configDigestHistory{}, fmt.Errorf("decode config.digest audit row %d: digest is empty", event.ID)
		}
		if event.SessionID != "" {
			digestEvents[event.SessionID]++
		}
		history.Rows++
		if previousDigest != "" && previousDigest != record.Digest {
			history.Changes++
			changedAt := event.Timestamp
			history.LastChange = &changedAt
		}
		previousDigest = record.Digest
	}
	for sessionID := range nonDigestEvents {
		if digestEvents[sessionID] == 0 {
			history.MissingSessions = append(history.MissingSessions, sessionID)
		}
	}
	sort.Strings(history.MissingSessions)
	return history, nil
}

func allAuditEvents(logger *logging.Logger) ([]logging.Event, error) {
	const pageSize = 10000
	var events []logging.Event
	for offset := 0; ; offset += pageSize {
		page, err := logger.Query(logging.QueryOptions{Limit: pageSize, Offset: offset, ByID: true})
		if err != nil {
			return nil, fmt.Errorf("read audit events: %w", err)
		}
		events = append(events, page...)
		if len(page) < pageSize {
			return events, nil
		}
	}
}

func writeConfigDigestVerifyResult(w io.Writer, history configDigestHistory) error {
	lastChange := "none"
	if history.LastChange != nil {
		lastChange = history.LastChange.UTC().Format(time.RFC3339)
	}
	fmt.Fprintf(w, "Config digest history: %d row(s), %d change(s), last change: %s\n", history.Rows, history.Changes, lastChange)
	if len(history.MissingSessions) == 0 {
		return nil
	}
	fmt.Fprintf(w, "CONFIG DIGEST: INCOMPLETE — %d session(s) with audit rows are missing config.digest: %s\n",
		len(history.MissingSessions), strings.Join(history.MissingSessions, ", "))
	return &exitCodeError{code: 1}
}

func changedConfigPolicyFields(previous, current json.RawMessage) []string {
	return changedJSONFields("", previous, current)
}

func changedJSONFields(prefix string, previous, current json.RawMessage) []string {
	if bytes.Equal(previous, current) {
		return nil
	}
	var oldFields, newFields map[string]json.RawMessage
	if json.Unmarshal(previous, &oldFields) != nil || json.Unmarshal(current, &newFields) != nil {
		return []string{prefix}
	}
	keys := make(map[string]bool, len(oldFields)+len(newFields))
	for key := range oldFields {
		keys[key] = true
	}
	for key := range newFields {
		keys[key] = true
	}
	names := make([]string, 0, len(keys))
	for key := range keys {
		names = append(names, key)
	}
	sort.Strings(names)

	var changes []string
	for _, name := range names {
		field := name
		if prefix != "" {
			field = prefix + "." + name
		}
		changes = append(changes, changedJSONFields(field, oldFields[name], newFields[name])...)
	}
	return changes
}
