package ocsf

import (
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
	if p := mustMap(t, row(logging.EventSessionStart, "/usr/bin/make test", false)).Process; p.CmdLine != "/usr/bin/make test" {
		t.Fatalf("bare session_start form must keep the whole detail as cmd_line, got %+v", p)
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
