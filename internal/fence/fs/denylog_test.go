package fs

import (
	"bufio"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

const fixturePath = "testdata/seatbelt_log_stream.ndjson"

// The fixture holds records captured with `log stream --style ndjson
// --predicate 'sender == "Sandbox"'` on a macos-latest runner (macOS 26.6.2):
// the stream header, an unrelated system denial, an untagged denial of `cat`
// (profile without a message), and a tagged denial of `cat` (session SESS1).
// The last three lines are hand-made variants: a truncated record, a tagged
// write denial on a path with spaces, and a tagged non-file operation.
func fixtureLines(t *testing.T) []string {
	t.Helper()
	f, err := os.Open(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var lines []string
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		lines = append(lines, sc.Text())
	}
	if err := sc.Err(); err != nil {
		t.Fatal(err)
	}
	return lines
}

func TestParseDenial_Fixtures(t *testing.T) {
	lines := fixtureLines(t)
	if len(lines) != 7 {
		t.Fatalf("fixture changed: want 7 lines, got %d", len(lines))
	}

	var got []Denial
	for _, l := range lines {
		if d, ok := ParseDenial([]byte(l), DenialTag("SESS1")); ok {
			got = append(got, d)
		}
	}
	if len(got) != 2 {
		t.Fatalf("want exactly 2 denials for session SESS1, got %d: %+v", len(got), got)
	}
	if got[0].Operation != "file-read-data" || !strings.HasSuffix(got[0].Path, "/tmp.JjekWtTptd/s.txt") {
		t.Errorf("recorded denial parsed wrong: %+v", got[0])
	}
	if want := "file-write-create /Users/runner/My Projects/.ssh/id_ed25519"; got[1].Detail() != want {
		t.Errorf("path with spaces: got %q, want %q", got[1].Detail(), want)
	}
}

func TestParseDenial_NegativeControls(t *testing.T) {
	lines := fixtureLines(t)

	// Same recorded stream, different session: nothing is attributed.
	for i, l := range lines {
		if d, ok := ParseDenial([]byte(l), DenialTag("SESS2")); ok {
			t.Errorf("line %d logged for the wrong session: %+v", i, d)
		}
	}
	// Individually: header, other process, untagged denial, truncated JSON and
	// a tagged non-file operation are all skipped for the right session.
	for _, i := range []int{0, 1, 2, 4, 6} {
		if d, ok := ParseDenial([]byte(lines[i]), DenialTag("SESS1")); ok {
			t.Errorf("line %d must be skipped, parsed %+v", i, d)
		}
	}
	if _, ok := ParseDenial([]byte(`{"eventMessage":"Sandbox: x(1) deny(1) file-read-data /p\nnocklock:SESS1extra"}`), DenialTag("SESS1")); ok {
		t.Error("a tag that merely has the session id as a prefix must not match")
	}
}

func skipWithoutShell(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
}

type tailerRecorder struct {
	mu         sync.Mutex
	denials    []Denial
	suppressed []int
	warnings   []string
}

func (r *tailerRecorder) config(argv []string, tag string, max int) DenialTailerConfig {
	return DenialTailerConfig{
		Argv: argv, Tag: tag, Max: max,
		Drain: 200 * time.Millisecond, ReadyWait: 2 * time.Second,
		OnDenial:     func(d Denial) { r.mu.Lock(); r.denials = append(r.denials, d); r.mu.Unlock() },
		OnSuppressed: func(n int) { r.mu.Lock(); r.suppressed = append(r.suppressed, n); r.mu.Unlock() },
		OnWarning:    func(m string) { r.mu.Lock(); r.warnings = append(r.warnings, m); r.mu.Unlock() },
	}
}

func TestDenialTailer_ReportsOnlyThisSession(t *testing.T) {
	skipWithoutShell(t)
	var r tailerRecorder
	tl := StartDenialTailer(r.config([]string{"/bin/sh", "-c", `cat "$1"; exec sleep 30`, "sh", fixturePath}, DenialTag("SESS1"), 0))
	tl.Stop()
	if len(r.denials) != 2 || len(r.warnings) != 0 || len(r.suppressed) != 0 {
		t.Fatalf("denials=%+v warnings=%q suppressed=%v", r.denials, r.warnings, r.suppressed)
	}

	var other tailerRecorder
	tl = StartDenialTailer(other.config([]string{"/bin/sh", "-c", `cat "$1"; exec sleep 30`, "sh", fixturePath}, DenialTag("SESS2"), 0))
	tl.Stop()
	if len(other.denials) != 0 {
		t.Fatalf("session SESS2 must see no denials, got %+v", other.denials)
	}
}

func TestDenialTailer_CapsAndReportsSuppressedOnce(t *testing.T) {
	skipWithoutShell(t)
	rec := `{"eventMessage":"Sandbox: x(1) deny(1) file-read-data /p/%d\nnocklock:S"}`
	var b strings.Builder
	for i := 0; i < 5; i++ {
		b.WriteString(strings.Replace(rec, "%d", string(rune('a'+i)), 1) + "\n")
	}
	stream := filepath.Join(t.TempDir(), "burst.ndjson")
	if err := os.WriteFile(stream, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}

	var r tailerRecorder
	tl := StartDenialTailer(r.config([]string{"/bin/sh", "-c", `cat "$1"; exec sleep 30`, "sh", stream}, DenialTag("S"), 2))
	tl.Stop()
	if len(r.denials) != 2 {
		t.Errorf("want 2 reported denials, got %d", len(r.denials))
	}
	if len(r.suppressed) != 1 || r.suppressed[0] != 3 {
		t.Errorf("want one suppressed notice of 3, got %v", r.suppressed)
	}
}

func TestDenialTailer_UnstartableStreamWarnsOnce(t *testing.T) {
	var r tailerRecorder
	start := time.Now()
	tl := StartDenialTailer(r.config([]string{filepath.Join(t.TempDir(), "no-such-log")}, DenialTag("S"), 0))
	tl.Stop()
	tl.Stop()
	if len(r.warnings) != 1 || !strings.Contains(r.warnings[0], "denial log unavailable") {
		t.Fatalf("want exactly one unavailable warning, got %q", r.warnings)
	}
	if time.Since(start) > time.Second {
		t.Errorf("an unstartable tailer must not delay the run: %v", time.Since(start))
	}
}

func TestDenialTailer_EarlyExitWarnsOnceWithStderr(t *testing.T) {
	skipWithoutShell(t)
	var r tailerRecorder
	tl := StartDenialTailer(r.config([]string{"/bin/sh", "-c", "echo log: permission denied >&2; exit 3"}, DenialTag("S"), 0))
	tl.Stop()
	if len(r.warnings) != 1 || !strings.Contains(r.warnings[0], "permission denied") {
		t.Fatalf("want one early-exit warning quoting stderr, got %q", r.warnings)
	}
}
