package fs

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Best-effort capture of Seatbelt file denials from the macOS unified log.
//
// Seatbelt has no callback like the Linux interposer socket; the kernel writes
// each denial to the unified log (sender "Sandbox"). The generated profile tags
// its deny rules with `(with message "nocklock:<session-id>")` and the kernel
// appends that tag to the log line, so a denial is attributed to a session by
// its tag alone, covering every descendant of the wrapped process with no PID
// bookkeeping. The unified log can drop lines under load, so the audit rows this
// produces are evidence of denials, never proof that none occurred.

// DenialTag is the message tag a session's deny rules carry.
func DenialTag(sessionID string) string { return "nocklock:" + sessionID }

// Denial is one file access the Seatbelt fence refused.
type Denial struct {
	Operation string // e.g. "file-read-data"
	Path      string
}

// Detail renders the audit-row detail, e.g. "file-read-data /Users/x/.ssh/id_ed25519".
func (d Denial) Detail() string { return d.Operation + " " + d.Path }

// ParseDenial extracts a file denial from one `log stream --style ndjson` line.
// It reports false for anything that is not a file denial carrying tag: the
// stream's non-JSON header, malformed or truncated JSON, denials of other
// processes or sessions (no tag, or a different one), and non-file operations.
func ParseDenial(line []byte, tag string) (Denial, bool) {
	var rec struct {
		EventMessage string `json:"eventMessage"`
	}
	if err := json.Unmarshal(line, &rec); err != nil {
		return Denial{}, false
	}
	// eventMessage is "Sandbox: <proc>(<pid>) deny(<n>) <op> <path>" with the
	// profile's message tag on a following line.
	first, rest, tagged := strings.Cut(rec.EventMessage, "\n")
	if !tagged || !hasLine(rest, tag) {
		return Denial{}, false
	}
	_, afterDeny, ok := strings.Cut(first, ") deny(")
	if !ok {
		return Denial{}, false
	}
	_, opAndPath, ok := strings.Cut(afterDeny, ") ")
	if !ok {
		return Denial{}, false
	}
	op, path, ok := strings.Cut(opAndPath, " ")
	if !ok || !strings.HasPrefix(op, "file-") || path == "" {
		return Denial{}, false
	}
	return Denial{Operation: op, Path: path}, true
}

func hasLine(s, want string) bool {
	for _, l := range strings.Split(s, "\n") {
		if l == want {
			return true
		}
	}
	return false
}

// LogStreamArgv is the command that streams Seatbelt denials as ndjson.
func LogStreamArgv() []string {
	return []string{"/usr/bin/log", "stream", "--style", "ndjson", "--predicate", `sender == "Sandbox"`}
}

const (
	// DefaultMaxDenialEvents caps denial rows per session so a denial storm
	// cannot flood the audit chain.
	DefaultMaxDenialEvents = 500
	// DefaultDenialDrain is how long the tailer keeps reading after the child
	// exits, so late log lines still land.
	DefaultDenialDrain = time.Second
	// DefaultDenialReadyWait bounds how long Start waits for the stream to
	// attach before the child launches.
	DefaultDenialReadyWait = 750 * time.Millisecond
)

// DenialTailerConfig configures StartDenialTailer. Zero values select defaults.
type DenialTailerConfig struct {
	Argv      []string      // defaults to LogStreamArgv()
	Tag       string        // only denials carrying this tag are reported
	Max       int           // denial events reported before suppression
	Drain     time.Duration // post-exit read window
	ReadyWait time.Duration // bound on waiting for the stream to attach

	OnDenial     func(Denial)
	OnSuppressed func(n int) // called at most once, with the count over Max
	OnWarning    func(msg string)
}

// DenialTailer reads Seatbelt denials in the background. It never blocks or
// fails the wrapped process: every problem becomes one OnWarning call.
type DenialTailer struct {
	cfg      DenialTailerConfig
	cmd      *exec.Cmd
	done     chan struct{} // closed when the reader goroutine exits
	stopping atomic.Bool
	stopOnce sync.Once
	warnOnce sync.Once
	waitOnce sync.Once
	stderr   cappedBuffer
}

// StartDenialTailer starts the stream and waits briefly for it to attach. A
// tailer that cannot start is returned already finished, after one warning.
func StartDenialTailer(cfg DenialTailerConfig) *DenialTailer {
	if len(cfg.Argv) == 0 {
		cfg.Argv = LogStreamArgv()
	}
	if cfg.Max <= 0 {
		cfg.Max = DefaultMaxDenialEvents
	}
	if cfg.Drain <= 0 {
		cfg.Drain = DefaultDenialDrain
	}
	if cfg.ReadyWait <= 0 {
		cfg.ReadyWait = DefaultDenialReadyWait
	}
	t := &DenialTailer{cfg: cfg, done: make(chan struct{})}

	t.cmd = exec.Command(cfg.Argv[0], cfg.Argv[1:]...)
	t.cmd.Stderr = &t.stderr
	t.cmd.WaitDelay = time.Second
	out, err := t.cmd.StdoutPipe()
	if err == nil {
		err = t.cmd.Start()
	}
	if err != nil {
		t.warn(fmt.Sprintf("denial log unavailable: cannot start %s: %v", cfg.Argv[0], err))
		close(t.done)
		return t
	}

	ready := make(chan struct{})
	go t.read(out, ready)
	select {
	case <-ready:
	case <-t.done:
	case <-time.After(cfg.ReadyWait):
	}
	return t
}

func (t *DenialTailer) warn(msg string) {
	t.warnOnce.Do(func() {
		if t.cfg.OnWarning != nil {
			t.cfg.OnWarning(msg)
		}
	})
}

func (t *DenialTailer) read(out io.Reader, ready chan<- struct{}) {
	defer close(t.done)
	sc := bufio.NewScanner(out)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	signalled := false
	reported, suppressed := 0, 0
	for sc.Scan() {
		if !signalled {
			signalled = true
			close(ready)
		}
		d, ok := ParseDenial(sc.Bytes(), t.cfg.Tag)
		if !ok {
			continue
		}
		if reported >= t.cfg.Max {
			suppressed++
			continue
		}
		reported++
		if t.cfg.OnDenial != nil {
			t.cfg.OnDenial(d)
		}
	}
	if suppressed > 0 && t.cfg.OnSuppressed != nil {
		t.cfg.OnSuppressed(suppressed)
	}
	if !t.stopping.Load() {
		t.wait() // stderr is complete only once the process has been reaped
		detail := strings.TrimSpace(t.stderr.String())
		if err := sc.Err(); err != nil {
			detail = err.Error()
		}
		t.warn("denial log stopped early; later denials may be missing: " + detail)
	}
}

// Stop lets the stream drain briefly, then ends it and waits for the reader.
// It is safe to call more than once.
func (t *DenialTailer) Stop() {
	t.stopOnce.Do(func() {
		select {
		case <-t.done:
		case <-time.After(t.cfg.Drain):
		}
		t.stopping.Store(true)
		if t.cmd.Process != nil {
			_ = t.cmd.Process.Kill()
		}
		select {
		case <-t.done:
		case <-time.After(2 * time.Second):
		}
		t.wait()
	})
}

func (t *DenialTailer) wait() {
	t.waitOnce.Do(func() { _ = t.cmd.Wait() })
}

// cappedBuffer keeps the first 2 KiB written to it; a failing stream's stderr
// is only ever quoted in one warning.
type cappedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if room := 2048 - c.buf.Len(); room > 0 {
		c.buf.Write(p[:min(room, len(p))])
	}
	return len(p), nil
}

func (c *cappedBuffer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}
