package cli

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/nocktechnologies/nocklock/internal/ocsf"
)

var updateOCSFGolden = flag.Bool("update-ocsf-golden", false, "rewrite testdata/ocsf/export.golden.jsonl")

const ocsfGoldenPath = "testdata/ocsf/export.golden.jsonl"

// ocsfFixtureRows are audit rows taken from real wrap runs, with host paths,
// socket names and config names replaced by neutral placeholders. Between them
// they reach every OCSF class the exporter emits, the session_start envelope,
// both file_blocked detail forms, a type the mapping table does not name, and a
// detail that is not valid UTF-8.
var ocsfFixtureRows = []struct {
	et       logging.EventType
	category string
	detail   string
	blocked  bool
	egress   string
}{
	{logging.EventSessionStart, "session", `command="/usr/bin/node" lifecycle=1`, false, "proxy"},
	{logging.EventConfigLoaded, "session", "claude-code", false, ""},
	{logging.EventSecretBlocked, "secret", "DEPLOY_API_TOKEN", true, ""},
	{logging.EventSecretPassed, "secret", "HOME, LANG, TERM, PATH", false, ""},
	{logging.EventSecretBlocked, "secret", `preflight {"findings":[{"path":"<project>/deploy.cfg","rule":"private-key"}]}`, true, ""},
	{logging.EventFilePassed, "filesystem", "landlock abi=5 paths=4", false, ""},
	{logging.EventFilePassed, "filesystem", "root=<home>/project mode=read-write", false, ""},
	{logging.EventFilesystemFenceState, "filesystem", "macOS filesystem-fence ENGAGED: seatbelt profile applied", false, ""},
	{logging.EventProxyStart, "network", "addr=127.0.0.1:43451 unix_socket=<tmp>/proxy.sock", false, ""},
	{logging.EventNetworkPassed, "network", "egress level=proxy proxy=127.0.0.1:43451 domains=3", false, ""},
	{logging.EventNetworkPassed, "network", "method=CONNECT host=api.example.com", false, ""},
	{logging.EventNetworkPassed, "network", "method=tcp host=api.example.com:443 rule=allowlist", false, ""},
	{logging.EventNetworkBlocked, "network", "method=CONNECT host=example.com", true, ""},
	{logging.EventFileBlocked, "filesystem", "op=open path=/proc/sys/crypto/fips_enabled reason=path resolution failed", true, ""},
	{logging.EventFileBlocked, "filesystem", `{"version":1,"report":{"operation":"connect","path":"<tmp>/agent.sock","reason":"unix socket outside grant"},"connection_peer":{"credentials_status":"unavailable","executable":{"status":"unavailable"}}}`, true, ""},
	{logging.EventFileBlocked, "filesystem", "op=open path=<home>/caf\xe9 reason=denied", true, ""},
	{logging.EventNetworkError, "network", "proxy watchdog: proxy died, killing child", true, ""},
	{logging.EventRuntimeChanged, "session", "runtime=claude-code previous=codex", false, ""},
	{logging.EventSessionEnd, "session", "exit_code=0", false, ""},
	{logging.EventProxyStop, "network", "proxy stopped", false, ""},
}

const ocsfFixtureSession = "6f52bc9c-6f77-4f4a-b32b-5073e4e5101f"

// seedOCSFFixture writes the fixture rows to the project's audit log, signed
// with a key from a fixed seed at the managed key path, so the export is
// reproducible byte for byte apart from the trailer's head signature.
func seedOCSFFixture(t *testing.T, dbPath, keyPath string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
		t.Fatal(err)
	}
	seed := sha256.Sum256([]byte("nocklock ocsf export fixture key"))
	if err := os.WriteFile(keyPath, seed[:], 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := logging.NewLogger(dbPath, "", logging.WithSigning(keyPath))
	if err != nil {
		t.Fatal(err)
	}
	base := time.Date(2026, 9, 27, 0, 15, 40, 961281573, time.UTC)
	for i, r := range ocsfFixtureRows {
		if err := l.Log(logging.Event{
			Timestamp: base.Add(time.Duration(i) * 1500 * time.Microsecond), EventType: r.et, Category: r.category,
			Detail: r.detail, Blocked: r.blocked, EgressLevel: r.egress, SessionID: ocsfFixtureSession,
		}); err != nil {
			t.Fatalf("log fixture row %d: %v", i+1, err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
}

func exportOCSF(t *testing.T) (lines []string, stderr string) {
	t.Helper()
	out := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")
	var stdout, errOut bytes.Buffer
	if err := runAuditExport(context.Background(), &stdout, &errOut, "ocsf", out, "", false); err != nil {
		t.Fatalf("export: %v\n%s", err, errOut.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("--out export wrote to stdout: %q", stdout.String())
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n"), errOut.String()
}

// trailerFields decodes the trailer line, returning the event and its
// unmapped.nocklock_export object.
func trailerFields(t *testing.T, line string) (ev, trailer map[string]any) {
	t.Helper()
	if err := json.Unmarshal([]byte(line), &ev); err != nil {
		t.Fatal(err)
	}
	return ev, ev["unmapped"].(map[string]any)["nocklock_export"].(map[string]any)
}

// normalizeTrailer blanks the trailer fields that differ on every run: its
// time and the head signature, whose signed bytes include the moment signing
// was adopted. TestOCSFExportVerifiesFromExportAlone checks them.
func normalizeTrailer(t *testing.T, line string) string {
	t.Helper()
	ev, tr := trailerFields(t, line)
	ev["time"] = 0
	tr["head_sig"], tr["head_signed_bytes"] = "<varies>", "<varies>"
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(ev); err != nil {
		t.Fatal(err)
	}
	return strings.TrimSuffix(buf.String(), "\n")
}

func TestOCSFExportGolden(t *testing.T) {
	// Resolve before setupAnchorProject changes into the temporary project.
	golden, err := filepath.Abs(ocsfGoldenPath)
	if err != nil {
		t.Fatal(err)
	}
	db, key := setupAnchorProject(t)
	seedOCSFFixture(t, db, key)
	lines, stderr := exportOCSF(t)
	if !strings.Contains(stderr, "AUDIT: AUTHENTIC") || !strings.Contains(stderr, "EXPORT: OCSF "+ocsf.Version) {
		t.Fatalf("export report missing the verdict or the export line:\n%s", stderr)
	}
	if len(lines) != len(ocsfFixtureRows)+1 {
		t.Fatalf("want %d rows + 1 trailer, got %d lines", len(ocsfFixtureRows), len(lines))
	}
	lines[len(lines)-1] = normalizeTrailer(t, lines[len(lines)-1])
	got := strings.Join(lines, "\n") + "\n"

	if *updateOCSFGolden {
		if err := os.MkdirAll(filepath.Dir(golden), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatalf("read golden (run with -update-ocsf-golden to create it): %v", err)
	}
	if got != string(want) {
		t.Fatalf("export differs from %s (run with -update-ocsf-golden after checking the diff):\n%s", ocsfGoldenPath, got)
	}

	classes := map[float64]bool{}
	for _, l := range lines {
		var ev map[string]any
		if err := json.Unmarshal([]byte(l), &ev); err != nil {
			t.Fatal(err)
		}
		classes[ev["class_uid"].(float64)] = true
		if v := ev["metadata"].(map[string]any)["version"]; v != ocsf.Version {
			t.Fatalf("metadata.version = %v, want %s", v, ocsf.Version)
		}
	}
	for _, c := range []float64{ocsf.ClassFileActivity, ocsf.ClassProcessActivity, ocsf.ClassDetectionFinding, ocsf.ClassNetworkActivity, ocsf.ClassApplicationLifecycle} {
		if !classes[c] {
			t.Errorf("fixture export never reached class %v", c)
		}
	}
}

// rowCanonical re-implements the documented canonical row encoding from the
// exported fields alone, without the logging package, as an outside verifier
// would: 0x01 || u64be(id) || lp(timestamp) || lp(event_type) || lp(category)
// || lp(detail) || blocked byte || lp(session_id), lp = u32be length + bytes.
func rowCanonical(r ocsf.Row) ([]byte, error) {
	detail := []byte(r.Detail)
	if r.DetailBase64 != "" {
		var err error
		if detail, err = base64.StdEncoding.DecodeString(r.DetailBase64); err != nil {
			return nil, err
		}
		// detail_base64 stands in for detail only when the bytes cannot travel
		// as JSON, and detail must then be their lossy rendering; otherwise
		// detail could be rewritten under an unchanged hash.
		if utf8.Valid(detail) || r.Detail != strings.ToValidUTF8(string(detail), "\uFFFD") {
			return nil, errors.New("detail_base64 does not match detail")
		}
	}
	lp := func(b []byte, s []byte) []byte {
		b = binary.BigEndian.AppendUint32(b, uint32(len(s)))
		return append(b, s...)
	}
	b := binary.BigEndian.AppendUint64([]byte{0x01}, uint64(r.ID))
	b = lp(b, []byte(r.Timestamp))
	b = lp(b, []byte(r.EventType))
	b = lp(b, []byte(r.Category))
	b = lp(b, detail)
	if r.Blocked != 0 {
		b = append(b, 1)
	} else {
		b = append(b, 0)
	}
	return lp(b, []byte(r.SessionID)), nil
}

// headUnsignedThroughID reads unsigned_through_id out of the head signed bytes
// and checks they end with the fingerprint of pub. After the version byte,
// chain_head and row_count come pruned_at, pruned_count, signed_genesis_at and
// unsigned_through_id, each a presence byte then (when 1) a u32be-length string
// or a u64be, and last the 32-byte SHA-256 of the public key.
func headUnsignedThroughID(signed []byte, pub ed25519.PublicKey) (int64, error) {
	rest := signed[41:]
	take := func(n int) ([]byte, error) {
		if len(rest) < n {
			return nil, errors.New("head signed bytes truncated")
		}
		b := rest[:n]
		rest = rest[n:]
		return b, nil
	}
	var unsigned int64
	for i, isString := range []bool{true, false, true, false} {
		flag, err := take(1)
		if err != nil {
			return 0, err
		}
		if flag[0] == 0 {
			continue
		}
		n := 8
		if isString {
			l, err := take(4)
			if err != nil {
				return 0, err
			}
			n = int(binary.BigEndian.Uint32(l))
		}
		v, err := take(n)
		if err != nil {
			return 0, err
		}
		if i == 3 {
			unsigned = int64(binary.BigEndian.Uint64(v))
		}
	}
	fp := sha256.Sum256(pub)
	if !bytes.Equal(rest, fp[:]) {
		return 0, errors.New("head signed bytes do not end with the public key fingerprint")
	}
	return unsigned, nil
}

// verifyExport checks an export the way a downstream reader can, from its
// lines alone: every entry_hash recomputes from unmapped.nocklock, the links
// run from the genesis hash to the trailer's chain_head, every entry_sig and
// the head signature verify under the trailer's key, and the signed head bytes
// commit to that chain_head, row count, unsigned_through_id and key. Rows up to
// unsigned_through_id predate signing and must carry no signature.
func verifyExport(t *testing.T, lines []string) error {
	t.Helper()
	var tev struct {
		Unmapped struct {
			Export *ocsf.Trailer `json:"nocklock_export"`
		} `json:"unmapped"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &tev); err != nil || tev.Unmapped.Export == nil {
		return errors.New("last line is not the export trailer")
	}
	trailer := *tev.Unmapped.Export
	pubBytes, err := base64.StdEncoding.DecodeString(trailer.PublicKey)
	if err != nil || len(pubBytes) != ed25519.PublicKeySize {
		return errors.New("trailer public key is not an Ed25519 key")
	}
	pub := ed25519.PublicKey(pubBytes)

	prev := trailer.GenesisHash
	rows := lines[:len(lines)-1]
	for _, l := range rows {
		var ev struct {
			Unmapped struct {
				NockLock ocsf.Row `json:"nocklock"`
			} `json:"unmapped"`
		}
		if err := json.Unmarshal([]byte(l), &ev); err != nil {
			return err
		}
		r := ev.Unmapped.NockLock
		cb, err := rowCanonical(r)
		if err != nil {
			return err
		}
		prevBytes, err := hex.DecodeString(r.PrevHash)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(append(append([]byte{}, cb...), prevBytes...))
		if r.PrevHash != prev || hex.EncodeToString(sum[:]) != r.EntryHash {
			return errors.New("entry " + r.EntryHash + " does not recompute from unmapped")
		}
		if r.ID <= trailer.UnsignedThroughID {
			if r.EntrySig != "" {
				return errors.New("a row before signing adoption carries a signature")
			}
		} else if sig, err := base64.StdEncoding.DecodeString(r.EntrySig); err != nil || !ed25519.Verify(pub, cb, sig) {
			return errors.New("entry signature does not verify")
		}
		prev = r.EntryHash
	}
	if prev != trailer.ChainHead || len(rows) != trailer.RowCount {
		return errors.New("rows do not end at the trailer chain_head")
	}
	signed, err := base64.StdEncoding.DecodeString(trailer.HeadSignedBytes)
	if err != nil || len(signed) < 41 {
		return errors.New("head signed bytes malformed")
	}
	if hex.EncodeToString(signed[1:33]) != trailer.ChainHead || binary.BigEndian.Uint64(signed[33:41]) != uint64(trailer.RowCount) {
		return errors.New("head signed bytes do not commit to chain_head and row_count")
	}
	unsigned, err := headUnsignedThroughID(signed, pub)
	if err != nil {
		return err
	}
	if unsigned != trailer.UnsignedThroughID {
		return errors.New("trailer unsigned_through_id differs from the signed head")
	}
	headSig, err := base64.StdEncoding.DecodeString(trailer.HeadSig)
	if err != nil || !ed25519.Verify(pub, signed, headSig) {
		return errors.New("head signature does not verify")
	}
	return nil
}

func TestOCSFExportVerifiesFromExportAlone(t *testing.T) {
	db, key := setupAnchorProject(t)
	seedOCSFFixture(t, db, key)
	lines, _ := exportOCSF(t)
	if err := verifyExport(t, lines); err != nil {
		t.Fatalf("intact export: %v", err)
	}

	// Negative controls: a changed field of a row, a detail rewritten behind
	// a detail_base64 of the original, a dropped row, a stripped row
	// signature excused by a claimed unsigned prefix, and a forged head
	// signature must each fail the same check.
	edit := func(i int, from, to string) []string {
		c := append([]string{}, lines...)
		if !strings.Contains(c[i], from) {
			t.Fatalf("line %d has no %q", i, from)
		}
		c[i] = strings.Replace(c[i], from, to, 1)
		return c
	}
	if err := verifyExport(t, edit(2, `"detail":"DEPLOY_API_TOKEN"`, `"detail":"DEPLOY_API_TOKEX"`)); err == nil {
		t.Fatal("an edited detail still verified")
	}
	original := base64.StdEncoding.EncodeToString([]byte("DEPLOY_API_TOKEN"))
	if err := verifyExport(t, edit(2, `"detail":"DEPLOY_API_TOKEN"`, `"detail":"harmless","detail_base64":"`+original+`"`)); err == nil {
		t.Fatal("a detail rewritten behind detail_base64 still verified")
	}
	var row struct {
		Unmapped struct {
			NockLock ocsf.Row `json:"nocklock"`
		} `json:"unmapped"`
	}
	if err := json.Unmarshal([]byte(lines[2]), &row); err != nil {
		t.Fatal(err)
	}
	stripped := edit(2, `"entry_sig":"`+row.Unmapped.NockLock.EntrySig+`"`, `"entry_sig":""`)
	if err := verifyExport(t, stripped); err == nil {
		t.Fatal("a stripped row signature still verified")
	}
	last := len(lines) - 1
	stripped[last] = strings.Replace(stripped[last], `"chain_head":`, `"unsigned_through_id":3,"chain_head":`, 1)
	if err := verifyExport(t, stripped); err == nil {
		t.Fatal("a stripped row signature excused by a claimed unsigned prefix still verified")
	}
	if err := verifyExport(t, append(append([]string{}, lines[:3]...), lines[4:]...)); err == nil {
		t.Fatal("an export missing a row still verified")
	}
	_, tr := trailerFields(t, lines[len(lines)-1])
	headSig := tr["head_sig"].(string)
	forged := base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))
	if err := verifyExport(t, edit(len(lines)-1, headSig, forged)); err == nil {
		t.Fatal("a forged head signature still verified")
	}
}

func TestOCSFExportStdout(t *testing.T) {
	db, key := setupAnchorProject(t)
	seedOCSFFixture(t, db, key)
	var stdout, stderr bytes.Buffer
	if err := runAuditExport(context.Background(), &stdout, &stderr, "ocsf", "", "", false); err != nil {
		t.Fatalf("export: %v\n%s", err, stderr.String())
	}
	if strings.Contains(stdout.String(), "AUDIT:") {
		t.Fatal("the verification report must go to stderr, not into the export")
	}
	var n int
	sc := bufio.NewScanner(&stdout)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		if !json.Valid(sc.Bytes()) {
			t.Fatalf("line %d is not JSON: %s", n+1, sc.Text())
		}
		n++
	}
	if n != len(ocsfFixtureRows)+1 {
		t.Fatalf("want %d lines on stdout, got %d", len(ocsfFixtureRows)+1, n)
	}
}

func TestOCSFExportRefusesBadChain(t *testing.T) {
	for _, mode := range []string{"file", "stdout"} {
		t.Run(mode, func(t *testing.T) {
			db, key := setupAnchorProject(t)
			seedOCSFFixture(t, db, key)
			raw, err := sql.Open("sqlite", db)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := raw.Exec("UPDATE events SET detail='altered' WHERE id=3"); err != nil {
				t.Fatal(err)
			}
			raw.Close()

			dir := t.TempDir()
			out := ""
			if mode == "file" {
				out = filepath.Join(dir, "audit.ocsf.jsonl")
			}
			var stdout, stderr bytes.Buffer
			err = runAuditExport(context.Background(), &stdout, &stderr, "ocsf", out, "", false)
			var exit *exitCodeError
			if !errors.As(err, &exit) || exit.code != 1 {
				t.Fatalf("want exit 1 on a tampered chain, got %v\n%s", err, stderr.String())
			}
			if !strings.Contains(stderr.String(), "AUDIT: TAMPERED") || !strings.Contains(stderr.String(), "EXPORT: REFUSED") {
				t.Fatalf("refusal not reported:\n%s", stderr.String())
			}
			if stdout.Len() != 0 {
				t.Fatalf("refused export wrote to stdout: %q", stdout.String())
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("refused export left files behind: %v", entries)
			}
		})
	}
}

func TestOCSFExportRejectsUnknownFormat(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := runAuditExport(context.Background(), &stdout, &stderr, "csv", "", "", false)
	if err == nil || !strings.Contains(err.Error(), "supported format is ocsf") {
		t.Fatalf("want an unsupported-format error, got %v", err)
	}
}

func TestOCSFExportRefusesLogChangedAfterChecks(t *testing.T) {
	db, key := setupAnchorProject(t)
	seedOCSFFixture(t, db, key)
	exportAfterChecks = func() {
		l, err := logging.NewLogger(db, "", logging.WithSigning(key))
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		if err := l.Log(logging.Event{Timestamp: time.Now(), EventType: logging.EventSessionStart, Category: "session", Detail: "late run", SessionID: "late"}); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() { exportAfterChecks = nil })

	out := filepath.Join(t.TempDir(), "audit.ocsf.jsonl")
	var stdout, stderr bytes.Buffer
	err := runAuditExport(context.Background(), &stdout, &stderr, "ocsf", out, "", false)
	if err == nil || !strings.Contains(err.Error(), "changed after the checks") {
		t.Fatalf("want a refusal for rows the checks did not cover, got %v\n%s", err, stderr.String())
	}
	if !strings.Contains(stderr.String(), "EXPORT: REFUSED") {
		t.Fatalf("refusal not reported:\n%s", stderr.String())
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatalf("refused export left %s behind: %v", out, err)
	}
}
