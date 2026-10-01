package fs

import (
	"bufio"
	"fmt"
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
// The next three lines are hand-made variants: a truncated record, a tagged
// write denial on a path with spaces, and a tagged non-file operation. The last
// is a forgery: a userland os_log record under sender "Sandbox" with the right
// tag. Real kernel records carry processID 0, processImagePath "/kernel" and a
// senderImagePath under /System/Library/Extensions/Sandbox.kext/; those are the
// fields ParseDenial requires, and the forgery carries its own pid and paths.
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
	if len(lines) != 8 {
		t.Fatalf("fixture changed: want 8 lines, got %d", len(lines))
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
	// Individually: header, other process, untagged denial, truncated JSON, a
	// tagged non-file operation and a tagged userland forgery are all skipped
	// for the right session.
	for _, i := range []int{0, 1, 2, 4, 6, 7} {
		if d, ok := ParseDenial([]byte(lines[i]), DenialTag("SESS1")); ok {
			t.Errorf("line %d must be skipped, parsed %+v", i, d)
		}
	}
	if _, ok := ParseDenial([]byte(`{"eventMessage":"Sandbox: x(1) deny(1) file-read-data /p\nnocklock:SESS1extra"}`), DenialTag("SESS1")); ok {
		t.Error("a tag that merely has the session id as a prefix must not match")
	}
}

func TestParseDenial_RequiresEachKernelProvenanceField(t *testing.T) {
	real := fixtureLines(t)[3]
	if _, ok := ParseDenial([]byte(real), DenialTag("SESS1")); !ok {
		t.Fatal("the recorded kernel denial must parse before it is mutated")
	}
	for name, mut := range map[string][2]string{
		"processID":        {`"processID":0`, `"processID":4242`},
		"processImagePath": {`"processImagePath":"\/kernel"`, `"processImagePath":"\/tmp\/Sandbox"`},
		"senderImagePath":  {`"senderImagePath":"\/System\/Library\/Extensions\/Sandbox.kext`, `"senderImagePath":"\/tmp\/Sandbox.kext`},
	} {
		forged := strings.Replace(real, mut[0], mut[1], 1)
		if forged == real {
			t.Fatalf("%s: mutation did not apply; fixture changed", name)
		}
		if d, ok := ParseDenial([]byte(forged), DenialTag("SESS1")); ok {
			t.Errorf("a record with a forged %s must not be logged, parsed %+v", name, d)
		}
	}
}

func skipWithoutShell(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("needs /bin/sh")
	}
}

// streamArgv replays a file as a never-ending stream: cat it, then idle.
func streamArgv(t *testing.T, body string) []string {
	t.Helper()
	stream := filepath.Join(t.TempDir(), "stream.ndjson")
	if err := os.WriteFile(stream, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return []string{"/bin/sh", "-c", `cat "$1"; exec sleep 30`, "sh", stream}
}

type tailerRecorder struct {
	mu         sync.Mutex
	denials    []Denial
	suppressed [][2]int
	warnings   []string
}

func (r *tailerRecorder) config(argv []string, tag string, max int) DenialTailerConfig {
	return DenialTailerConfig{
		Argv: argv, Tag: tag, Max: max,
		Drain: 200 * time.Millisecond, ReadyWait: 2 * time.Second,
		OnDenial:     func(d Denial) { r.mu.Lock(); r.denials = append(r.denials, d); r.mu.Unlock() },
		OnSuppressed: func(o, d int) { r.mu.Lock(); r.suppressed = append(r.suppressed, [2]int{o, d}); r.mu.Unlock() },
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
	rec := kernelRecord("/p/%d")
	var b strings.Builder
	for i := 0; i < 5; i++ {
		b.WriteString(strings.Replace(rec, "%d", string(rune('a'+i)), 1) + "\n")
	}
	var r tailerRecorder
	tl := StartDenialTailer(r.config(streamArgv(t, b.String()), DenialTag("S"), 2))
	tl.Stop()
	if len(r.denials) != 2 {
		t.Errorf("want 2 reported denials, got %d", len(r.denials))
	}
	if len(r.suppressed) != 1 || r.suppressed[0] != [2]int{3, 0} {
		t.Errorf("want one suppressed notice of 3 over the cap, got %v", r.suppressed)
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

func TestDenialTailer_RepeatedDenialsReportOnceAndDoNotUseCap(t *testing.T) {
	skipWithoutShell(t)
	rec := kernelRecord("/dev/dtracehelper")
	real := kernelRecord("/home/u/.ssh/id")
	var r tailerRecorder
	tl := StartDenialTailer(r.config(streamArgv(t, strings.Repeat(rec+"\n", 4)+real+"\n"), DenialTag("S"), 2))
	tl.Stop()
	if len(r.denials) != 2 || len(r.suppressed) != 1 || r.suppressed[0] != [2]int{0, 3} {
		t.Fatalf("denials=%+v suppressed=%v", r.denials, r.suppressed)
	}
}

func kernelRecord(path string) string {
	return `{"processID":0,"processImagePath":"/kernel","senderImagePath":"/System/Library/Extensions/Sandbox.kext/Contents/MacOS/Sandbox","eventMessage":"Sandbox: x(1) deny(1) file-read-data ` + path + `\nnocklock:S"}`
}

func TestDenialTailer_StopKeepsEveryBufferedRecordFromASlowConsumer(t *testing.T) {
	skipWithoutShell(t)
	const n = 1000
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString(kernelRecord(fmt.Sprintf("/p/%04d", i)) + "\n")
	}
	if b.Len() <= 64*1024 {
		t.Fatalf("burst of %d bytes does not exceed the pipe buffer", b.Len())
	}
	var r tailerRecorder
	cfg := r.config(streamArgv(t, b.String()), DenialTag("S"), 2*n)
	onDenial := cfg.OnDenial
	cfg.OnDenial = func(d Denial) { time.Sleep(time.Millisecond); onDenial(d) }
	tl := StartDenialTailer(cfg)
	tl.Stop()
	if len(r.denials) != n || len(r.warnings) != 0 {
		t.Fatalf("want all %d denials and no warning, got %d denials, warnings=%q", n, len(r.denials), r.warnings)
	}
}

func TestDenialTailer_StopWarnsOnceWhenTheReaderStalls(t *testing.T) {
	skipWithoutShell(t)
	var r tailerRecorder
	release := make(chan struct{})
	cfg := r.config(streamArgv(t, kernelRecord("/p/a")+"\n"+kernelRecord("/p/b")+"\n"), DenialTag("S"), 0)
	cfg.OnDenial = func(Denial) { <-release }
	tl := StartDenialTailer(cfg)

	stopped := make(chan struct{})
	go func() { tl.Stop(); close(stopped) }()
	deadline := time.Now().Add(5 * time.Second)
	for {
		r.mu.Lock()
		n := len(r.warnings)
		r.mu.Unlock()
		if n > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("a stalled reader produced no truncation warning")
		}
		time.Sleep(10 * time.Millisecond)
	}
	close(release)
	<-stopped
	if len(r.warnings) != 1 || !strings.Contains(r.warnings[0], "dropped") {
		t.Fatalf("want exactly one truncation warning, got %q", r.warnings)
	}
}
