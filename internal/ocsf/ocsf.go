// Package ocsf maps NockLock audit rows to Open Cybersecurity Schema Framework
// (OCSF) events, one event per row, for `nocklock verify --export ocsf`.
//
// Every event carries its source row verbatim in unmapped.nocklock, so the
// hash chain and the row signatures can be recomputed from the export alone
// (see docs/how-it-works/audit-log.md). The mapped OCSF fields are a reading
// aid for ingesting tools: they are derived from the row, never added to it,
// and where a row does not record a value the field is left out rather than
// guessed.
package ocsf

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"path"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

// Version is the one OCSF schema version every exported event declares in
// metadata.version. CI validates the golden export against this version's
// class schemas; bump both together.
const Version = "1.9.0"

// OCSF class UIDs the exporter emits. The category UID is the class UID's
// thousands digit.
const (
	ClassFileActivity         = 1001
	ClassProcessActivity      = 1007
	ClassDetectionFinding     = 2004
	ClassNetworkActivity      = 4001
	ClassApplicationLifecycle = 6002
)

// Event is one OCSF event. Field names and enum values follow the OCSF
// schema named by Version.
type Event struct {
	ClassUID      int          `json:"class_uid"`
	CategoryUID   int          `json:"category_uid"`
	ActivityID    int          `json:"activity_id"`
	ActivityName  string       `json:"activity_name"`
	TypeUID       int          `json:"type_uid"`
	SeverityID    int          `json:"severity_id"`
	Time          int64        `json:"time"`
	Message       string       `json:"message,omitempty"`
	StatusID      int          `json:"status_id,omitempty"`
	Status        string       `json:"status,omitempty"`
	StatusDetail  string       `json:"status_detail,omitempty"`
	ActionID      int          `json:"action_id,omitempty"`
	Action        string       `json:"action,omitempty"`
	DispositionID int          `json:"disposition_id,omitempty"`
	Disposition   string       `json:"disposition,omitempty"`
	Metadata      Metadata     `json:"metadata"`
	Device        Device       `json:"device"`
	Actor         Actor        `json:"actor"`
	Process       *Process     `json:"process,omitempty"`
	ExitCode      *int         `json:"exit_code,omitempty"`
	File          *File        `json:"file,omitempty"`
	DstEndpoint   *Endpoint    `json:"dst_endpoint,omitempty"`
	FindingInfo   *FindingInfo `json:"finding_info,omitempty"`
	Resources     []Resource   `json:"resources,omitempty"`
	App           *Product     `json:"app,omitempty"`
	Unmapped      Unmapped     `json:"unmapped"`
}

// Metadata is the OCSF metadata object.
type Metadata struct {
	Version      string  `json:"version"`
	Product      Product `json:"product"`
	UID          string  `json:"uid"`
	LogName      string  `json:"log_name"`
	Sequence     int64   `json:"sequence,omitempty"`
	OriginalTime string  `json:"original_time,omitempty"`
}

// Product is the OCSF product object, used for metadata.product and app.
type Product struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
	Version    string `json:"version"`
}

// Device is the OCSF device object. The audit log does not record a host, so
// every event carries the same Unknown device (see unrecordedDevice).
type Device struct {
	TypeID int    `json:"type_id"`
	Name   string `json:"name"`
}

// Actor is the OCSF actor object: the nocklock wrap run that recorded the row.
type Actor struct {
	Process Process `json:"process"`
}

// Process is the OCSF process object.
type Process struct {
	Name    string `json:"name,omitempty"`
	CmdLine string `json:"cmd_line,omitempty"`
	UID     string `json:"uid"`
}

// File is the OCSF file object.
type File struct {
	Name   string `json:"name"`
	Path   string `json:"path,omitempty"`
	TypeID int    `json:"type_id"`
}

// Endpoint is the OCSF network endpoint object.
type Endpoint struct {
	Hostname string `json:"hostname"`
	Port     int    `json:"port,omitempty"`
}

// FindingInfo is the OCSF finding_info object.
type FindingInfo struct {
	UID   string `json:"uid"`
	Title string `json:"title"`
}

// Resource is the OCSF resource details object.
type Resource struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Unmapped holds the NockLock data the OCSF classes have no field for: the
// source row on every row event, and the chain evidence on the trailer.
type Unmapped struct {
	NockLock *Row     `json:"nocklock,omitempty"`
	Export   *Trailer `json:"nocklock_export,omitempty"`
}

// Row is an events row verbatim, under the stored column names. DetailBase64
// is set only when the stored detail is not valid UTF-8, which JSON cannot
// carry byte for byte; the hash then covers the decoded bytes, not Detail.
type Row struct {
	logging.ChainRow
	DetailBase64 string `json:"detail_base64,omitempty"`
}

// Trailer is the chain evidence the export ends with: the signed chain head
// and the public key, so a reader can recompute every entry_hash, check every
// entry_sig, and check the head signature over HeadSignedBytes, all from the
// export alone.
type Trailer struct {
	Verdict     string `json:"verdict"` // AUTHENTIC or CONSISTENT, as nocklock verify --audit reported
	RowCount    int    `json:"row_count"`
	GenesisHash string `json:"genesis_hash"`
	ChainHead   string `json:"chain_head"`
	// UnsignedThroughID is the highest row id that predates signing adoption:
	// those rows carry no entry_sig and are covered by the hash chain and the
	// signed head only. The head signature commits to it (see audit-log.md).
	UnsignedThroughID int64  `json:"unsigned_through_id,omitempty"`
	HeadSig           string `json:"head_sig,omitempty"`
	HeadSignedBytes   string `json:"head_signed_bytes,omitempty"` // base64 of the bytes HeadSig covers
	PublicKey         string `json:"public_key,omitempty"`        // base64 Ed25519
	KeyFingerprint    string `json:"public_key_fingerprint,omitempty"`
}

const (
	logName       = "nocklock events"
	vendorName    = "Nock Technologies"
	productName   = "NockLock"
	severityInfo  = 1
	severityMed   = 3
	statusSuccess = 1
	statusFailure = 2
	activityOther = 99
)

// unrecordedDevice is the device every event carries: OCSF requires one on
// several classes, and the audit log does not record the host, so the export
// says so instead of asserting the exporting host.
var unrecordedDevice = Device{TypeID: 0, Name: "unrecorded"}

// FromRow maps one audit row to its OCSF event. productVersion is the
// NockLock version writing the export. Every event type maps: one the table
// below does not name becomes an Application Lifecycle event, so no row is
// ever dropped from the chain. It errors only when the stored timestamp is
// not RFC 3339 or a column other than detail is not valid UTF-8.
func FromRow(r logging.ChainRow, productVersion string) (Event, error) {
	ts, err := time.Parse(time.RFC3339Nano, r.Timestamp)
	if err != nil {
		return Event{}, fmt.Errorf("entry %d: timestamp %q is not RFC 3339: %w", r.ID, r.Timestamp, err)
	}
	row, err := verbatimRow(r)
	if err != nil {
		return Event{}, err
	}
	blocked := r.Blocked != 0
	// The mapped fields follow the same one-U+FFFD-per-run rendering as
	// unmapped.nocklock.detail, not encoding/json's one per invalid byte.
	detail := strings.ToValidUTF8(logging.DecodeEventDetail(r.EventType, r.Detail), "\uFFFD")
	e := baseEvent(productVersion, r.EntryHash, r.SessionID, ts)
	e.Message = detail
	e.Metadata.Sequence = r.ID
	e.Metadata.OriginalTime = r.Timestamp
	e.Unmapped.NockLock = &row
	if blocked {
		e.SeverityID = severityMed
	}
	child := r.SessionID + ":child"

	switch logging.EventType(r.EventType) {
	case logging.EventSessionStart:
		e.setClass(ClassProcessActivity, 1, "Launch")
		cmd, name := sessionCommand(detail)
		e.Process = &Process{Name: name, CmdLine: cmd, UID: child}
		e.setStatus(true)
	case logging.EventSessionEnd:
		e.setClass(ClassProcessActivity, 2, "Terminate")
		e.Process = &Process{UID: child}
		if code, err := strconv.Atoi(token(detail, "exit_code")); err == nil {
			e.ExitCode = &code
		}
		e.setStatus(!blocked)
	case logging.EventNetworkBlocked:
		e.setClass(ClassNetworkActivity, 5, "Refuse")
		e.DstEndpoint = endpoint(detail)
		e.setDecision(true)
	case logging.EventNetworkPassed:
		// A network_passed row naming no host= records fence setup (the egress
		// level, staged socket rules), not a connection: it falls through to
		// Application Lifecycle like the other state rows.
		if e.DstEndpoint = endpoint(detail); e.DstEndpoint != nil {
			e.setClass(ClassNetworkActivity, 1, "Open")
			e.setDecision(false)
			break
		}
		e.lifecycle(r.EventType, blocked)
	case logging.EventFileBlocked:
		e.setClass(ClassFileActivity, activityOther, "Other")
		e.File = blockedFile(detail)
		e.setDecision(true)
	case logging.EventSecretBlocked:
		e.setClass(ClassDetectionFinding, 1, "Create")
		if strings.HasPrefix(detail, "preflight ") {
			// The secret preflight scan's JSON report; message carries it.
			e.FindingInfo = &FindingInfo{UID: r.EntryHash, Title: "Secret preflight scan refused the run"}
		} else if service, ok := strings.CutPrefix(detail, "mach-lookup "); ok {
			e.FindingInfo = &FindingInfo{UID: r.EntryHash, Title: "Keychain service access denied"}
			e.Resources = []Resource{{Name: service, Type: "Mach service"}}
		} else {
			e.FindingInfo = &FindingInfo{UID: r.EntryHash, Title: "Secret withheld from the wrapped agent"}
			e.Resources = []Resource{{Name: detail, Type: "Environment variable"}}
		}
		e.setDecision(true)
	default:
		// Fence state, config_loaded, proxy start/stop, *_passed rows and
		// every other type.
		e.lifecycle(r.EventType, blocked)
		if logging.EventType(r.EventType) == logging.EventFilesystemFenceState {
			if state := fenceState(detail); state != "" {
				e.StatusDetail = state
			}
		}
	}
	return e, nil
}

// lifecycle makes e an Application Lifecycle event with the row type in
// status_detail.
func (e *Event) lifecycle(eventType string, blocked bool) {
	e.setClass(ClassApplicationLifecycle, activityOther, "Other")
	app := e.Metadata.Product
	e.App = &app
	e.StatusDetail = eventType
	e.setStatus(!blocked)
}

// TrailerEvent wraps the chain evidence in an Application Lifecycle event, so
// every line of the export is an OCSF event an ingesting tool accepts.
func TrailerEvent(t Trailer, productVersion string, now time.Time) Event {
	e := baseEvent(productVersion, "nocklock-export:"+t.ChainHead, "nocklock-export", now)
	e.Message = fmt.Sprintf("NockLock audit export: %d rows, chain head %s, %s", t.RowCount, t.ChainHead, t.Verdict)
	e.lifecycle("audit_export_trailer", false)
	e.Unmapped.Export = &t
	return e
}

// baseEvent returns the fields every exported event shares: informational
// severity, the pinned metadata, the unrecorded device, and the nocklock run
// as actor.
func baseEvent(productVersion, uid, actorUID string, t time.Time) Event {
	return Event{
		SeverityID: severityInfo,
		Time:       t.UnixMilli(),
		Metadata: Metadata{
			Version: Version,
			Product: Product{Name: productName, VendorName: vendorName, Version: productVersion},
			UID:     uid,
			LogName: logName,
		},
		Device: unrecordedDevice,
		Actor:  Actor{Process: Process{Name: "nocklock", UID: actorUID}},
	}
}

func (e *Event) setClass(class, activity int, name string) {
	e.ClassUID, e.CategoryUID = class, class/1000
	e.ActivityID, e.ActivityName = activity, name
	e.TypeUID = class*100 + activity
}

func (e *Event) setStatus(ok bool) {
	if ok {
		e.StatusID, e.Status = statusSuccess, "Success"
	} else {
		e.StatusID, e.Status = statusFailure, "Failure"
	}
}

// setDecision records a fence decision: OCSF action Allowed (1) or Denied (2)
// and disposition Allowed (1) or Blocked (2).
func (e *Event) setDecision(blocked bool) {
	e.setStatus(!blocked)
	if blocked {
		e.ActionID, e.Action = 2, "Denied"
		e.DispositionID, e.Disposition = 2, "Blocked"
	} else {
		e.ActionID, e.Action = 1, "Allowed"
		e.DispositionID, e.Disposition = 1, "Allowed"
	}
}

func verbatimRow(r logging.ChainRow) (Row, error) {
	for _, f := range [...]struct{ name, v string }{
		{"event_type", r.EventType}, {"category", r.Category}, {"session_id", r.SessionID}, {"entry_sig", r.EntrySig},
	} {
		if !utf8.ValidString(f.v) {
			return Row{}, fmt.Errorf("entry %d: %s is not valid UTF-8 and cannot be exported verbatim", r.ID, f.name)
		}
	}
	row := Row{ChainRow: r}
	if !utf8.ValidString(r.Detail) {
		// Each maximal run of invalid bytes becomes one U+FFFD; the reader
		// rule in audit-log.md checks detail against exactly this rendering.
		row.Detail = strings.ToValidUTF8(r.Detail, "\uFFFD")
		row.DetailBase64 = base64.StdEncoding.EncodeToString([]byte(r.Detail))
	}
	return row, nil
}

// token returns the value of a space-separated key=value token in detail, or
// "" when absent.
func token(detail, key string) string {
	for _, f := range strings.Fields(detail) {
		if v, ok := strings.CutPrefix(f, key+"="); ok {
			return v
		}
	}
	return ""
}

// endpoint returns the destination a network row's host= token names, split
// into hostname and port when it is host:port, or nil when the row names none.
func endpoint(detail string) *Endpoint {
	host := token(detail, "host")
	if host == "" {
		return nil
	}
	if h, p, err := net.SplitHostPort(host); err == nil {
		if port, err := strconv.Atoi(p); err == nil && h != "" {
			return &Endpoint{Hostname: h, Port: port}
		}
	}
	return &Endpoint{Hostname: host}
}

// sessionCommand returns the wrapped command of a session_start detail and
// the base name of its executable ("" when there is none). The quoted
// command= value is the executable alone (wrap records argv[0], which may
// contain spaces), so it is both. The older bare form is the whole command
// line, whose first word is the executable, so a slash in an argument cannot
// rename the process.
func sessionCommand(detail string) (cmd, name string) {
	if rest, ok := strings.CutPrefix(detail, "command="); ok {
		if q, err := strconv.QuotedPrefix(rest); err == nil {
			if c, err := strconv.Unquote(q); err == nil {
				return c, baseName(c)
			}
		}
	}
	exe, _, _ := strings.Cut(strings.TrimSpace(detail), " ")
	return detail, baseName(exe)
}

// baseName is path.Base, except that an empty path has no name.
func baseName(p string) string {
	if p == "" {
		return ""
	}
	return path.Base(p)
}

// blockedFile returns the file a file_blocked row names: the path= value of
// the interposer form (which may contain spaces, so it runs to " reason="),
// or report.path of its JSON form. A row naming no path gets name "unknown".
func blockedFile(detail string) *File {
	var p string
	if strings.HasPrefix(detail, "{") {
		var env struct {
			Report struct {
				Path string `json:"path"`
			} `json:"report"`
		}
		if json.Unmarshal([]byte(detail), &env) == nil {
			p = env.Report.Path
		}
	} else if _, rest, ok := strings.Cut(detail, "path="); ok {
		p, _, _ = strings.Cut(rest, " reason=")
	}
	if p == "" {
		return &File{Name: "unknown", TypeID: 0}
	}
	return &File{Name: path.Base(p), Path: p, TypeID: 0}
}

// fenceState returns the state word of a filesystem_fence_state detail
// ("macOS filesystem-fence ENGAGED: ..."), or "" when the form differs.
func fenceState(detail string) string {
	_, rest, ok := strings.Cut(detail, "filesystem-fence ")
	if !ok {
		return ""
	}
	state, _, ok := strings.Cut(rest, ":")
	if !ok {
		return ""
	}
	return state
}
