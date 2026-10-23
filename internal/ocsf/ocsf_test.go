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
