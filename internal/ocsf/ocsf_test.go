package ocsf

import (
	"encoding/base64"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

func row(et logging.EventType, detail string, blocked bool) logging.ChainRow {
	r := logging.ChainRow{
		ID: 1, Timestamp: "2026-09-27T00:15:40.961281573Z", EventType: string(et),
		Category: "test", Detail: detail, SessionID: "s",
	}
	if blocked {
		r.Blocked = 1
	}
	return r
}

func mustMap(t *testing.T, r logging.ChainRow) Event {
	t.Helper()
	e, err := FromRow(r, "test")
	if err != nil {
		t.Fatal(err)
	}
	return e
}

// The golden export covers the forms wrap writes today; these are the
// documented fallbacks for forms it does not, each beside the parsed case.
func TestFromRowFallbacks(t *testing.T) {
	if f := mustMap(t, row(logging.EventFileBlocked, "op=open path=/a b/c reason=denied", true)).File; f.Path != "/a b/c" || f.Name != "c" {
		t.Fatalf("path= form: got %+v", f)
	}
	if f := mustMap(t, row(logging.EventFileBlocked, "op=open reason=denied", true)).File; f.Name != "unknown" || f.Path != "" {
		t.Fatalf("a row naming no path must map to file name unknown and no path, got %+v", f)
	}

	if p := mustMap(t, row(logging.EventSessionStart, `command="/usr/bin/node" lifecycle=1`, false)).Process; p.CmdLine != "/usr/bin/node" || p.Name != "node" {
		t.Fatalf("command= form: got %+v", p)
	}
	if p := mustMap(t, row(logging.EventSessionStart, "/usr/bin/make test", false)).Process; p.CmdLine != "/usr/bin/make test" || p.Name != "make" {
		t.Fatalf("bare session_start form must keep the whole detail as cmd_line, got %+v", p)
	}
	// A slash in an argument must not rename the process to the argument's
	// base name; the name is always the executable's.
	if p := mustMap(t, row(logging.EventSessionStart, "/usr/bin/node scripts/run.js --out=/tmp/x", false)).Process; p.Name != "node" || p.CmdLine != "/usr/bin/node scripts/run.js --out=/tmp/x" {
		t.Fatalf("process.name must be the executable's base name, got %+v", p)
	}
	if p := mustMap(t, row(logging.EventSessionStart, "claude --add-dir ../shared/lib", false)).Process; p.Name != "claude" {
		t.Fatalf("a bare executable name with path arguments: got %+v", p)
	}
	// The quoted command= value is the executable alone, so a space in its
	// path is part of the name, not a word break.
	if p := mustMap(t, row(logging.EventSessionStart, `command="/opt/My Tools/claude" lifecycle=1`, false)).Process; p.Name != "claude" || p.CmdLine != "/opt/My Tools/claude" {
		t.Fatalf("a quoted executable path with a space: got %+v", p)
	}

	state := logging.EventFilesystemFenceState
	if d := mustMap(t, row(state, "macOS filesystem-fence ENGAGED: profile applied", false)).StatusDetail; d != "ENGAGED" {
		t.Fatalf("fence state form: status_detail = %q", d)
	}
	if d := mustMap(t, row(state, "some other form", false)).StatusDetail; d != string(state) {
		t.Fatalf("an unrecognized fence state form must fall back to the row type, got %q", d)
	}

	if e := mustMap(t, row(logging.EventSessionEnd, "exit_code=3", false)); e.ExitCode == nil || *e.ExitCode != 3 {
		t.Fatalf("exit_code= form: got %v", e.ExitCode)
	}
	if e := mustMap(t, row(logging.EventSessionEnd, "ended", false)); e.ExitCode != nil {
		t.Fatalf("a session_end without exit_code= must leave exit_code out, got %d", *e.ExitCode)
	}

	if e := mustMap(t, row(logging.EventType("future_type"), "x", false)); e.ClassUID != ClassApplicationLifecycle || e.StatusDetail != "future_type" {
		t.Fatalf("an unnamed type must map to Application Lifecycle with its type in status_detail, got class %d %q", e.ClassUID, e.StatusDetail)
	}
}

func TestFromRowRejectsBadRows(t *testing.T) {
	r := row(logging.EventSessionEnd, "exit_code=0", false)
	r.Timestamp = "yesterday"
	if _, err := FromRow(r, "test"); err == nil {
		t.Fatal("a non-RFC 3339 timestamp mapped")
	}
	r = row(logging.EventSessionEnd, "exit_code=0", false)
	r.SessionID = "s\xff"
	if _, err := FromRow(r, "test"); err == nil {
		t.Fatal("a non-UTF-8 session_id mapped; it cannot be exported verbatim")
	}
}

// The reader rule in audit-log.md: detail is the stored bytes with each
// maximal run of invalid bytes replaced by one U+FFFD, and detail_base64 is
// set only then.
func TestFromRowInvalidDetail(t *testing.T) {
	for _, tc := range []struct{ stored, detail string }{
		{"a\xffb", "a\uFFFDb"},
		{"a\xff\xfeb", "a\uFFFDb"},
		{"a\xff\xfe\xfdb\xc0\xafc", "a\uFFFDb\uFFFDc"},
		{"\xe2\x82\xff", "\uFFFD"}, // a truncated sequence and a stray byte are one run
		{"caf\u00e9 \xff\xff", "caf\u00e9 \uFFFD"},
	} {
		e := mustMap(t, row(logging.EventFileBlocked, tc.stored, true))
		if e.Message != tc.detail {
			t.Errorf("stored %q: message = %q, want %q (the same rendering as detail)", tc.stored, e.Message, tc.detail)
		}
		r := e.Unmapped.NockLock
		if r.Detail != tc.detail {
			t.Errorf("stored %q: detail = %q, want %q", tc.stored, r.Detail, tc.detail)
		}
		if raw, err := base64.StdEncoding.DecodeString(r.DetailBase64); err != nil || string(raw) != tc.stored {
			t.Errorf("stored %q: detail_base64 does not decode to the stored bytes: %q %v", tc.stored, raw, err)
		}
	}
	if r := mustMap(t, row(logging.EventFileBlocked, "caf\u00e9", true)).Unmapped.NockLock; r.DetailBase64 != "" || r.Detail != "caf\u00e9" {
		t.Fatalf("a valid UTF-8 detail travels as is, without detail_base64: got %+v", r)
	}
}

func TestFromRowNetworkAndOutcome(t *testing.T) {
	e := mustMap(t, row(logging.EventNetworkPassed, "method=tcp host=api.example.com:443 rule=allowlist", false))
	if e.ClassUID != ClassNetworkActivity || e.DstEndpoint == nil || *e.DstEndpoint != (Endpoint{Hostname: "api.example.com", Port: 443}) {
		t.Fatalf("host:port must split into hostname and port, got class %d %+v", e.ClassUID, e.DstEndpoint)
	}
	if e := mustMap(t, row(logging.EventNetworkPassed, "method=tcp host=[::1]:8443", false)); *e.DstEndpoint != (Endpoint{Hostname: "::1", Port: 8443}) {
		t.Fatalf("bracketed IPv6 host:port: got %+v", e.DstEndpoint)
	}
	if e := mustMap(t, row(logging.EventNetworkPassed, "method=CONNECT host=example.com", false)); *e.DstEndpoint != (Endpoint{Hostname: "example.com"}) {
		t.Fatalf("a bare host keeps no port, got %+v", e.DstEndpoint)
	}
	if e := mustMap(t, row(logging.EventNetworkPassed, "egress level=OFF allow_all=true", false)); e.ClassUID != ClassApplicationLifecycle || e.DstEndpoint != nil || e.ActionID != 0 {
		t.Fatalf("a network_passed row naming no host is fence setup, not a connection: got class %d action %d", e.ClassUID, e.ActionID)
	}
	if e := mustMap(t, row(logging.EventNetworkBlocked, "rule=lookback:x trigger=y", true)); e.ClassUID != ClassNetworkActivity || e.Action != "Denied" {
		t.Fatalf("every network_blocked row is a denied network event, got class %d %q", e.ClassUID, e.Action)
	}

	if e := mustMap(t, row(logging.EventSessionEnd, "exit_code=1 secret_preflight=refused", true)); e.Status != "Failure" {
		t.Fatalf("a blocked session_end must report Failure, got %q", e.Status)
	}
	if e := mustMap(t, row(logging.EventSessionEnd, "exit_code=0", false)); e.Status != "Success" {
		t.Fatalf("an unblocked session_end must report Success, got %q", e.Status)
	}

	if e := mustMap(t, row(logging.EventSecretBlocked, `preflight {"findings":[]}`, true)); e.Resources != nil || e.FindingInfo.Title != "Secret preflight scan refused the run" {
		t.Fatalf("a preflight report is not an environment variable: got %+v %+v", e.Resources, e.FindingInfo)
	}
	if e := mustMap(t, row(logging.EventSecretBlocked, "DEPLOY_API_TOKEN", true)); len(e.Resources) != 1 || e.Resources[0] != (Resource{Name: "DEPLOY_API_TOKEN", Type: "Environment variable"}) {
		t.Fatalf("a withheld variable names its resource, got %+v", e.Resources)
	}
}
