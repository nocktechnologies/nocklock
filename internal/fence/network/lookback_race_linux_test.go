//go:build linux

package network

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
	"github.com/nocktechnologies/nocklock/internal/logging"
)

// tripper stands in for the interposer's side of a denied open: it sends one
// report to a real fs.Fence whose handler commits the trigger and closes
// everything, then waits for the ack, as the interposer does.
type tripper struct {
	fence    *fsfence.Fence
	tripDone atomic.Int64 // unix nanos at which LookbackTrip returned
}

func (e *lbEnv) attachFence(t *testing.T, cfg *fsfence.FenceConfig, lib string) *tripper {
	t.Helper()
	fence, err := fsfence.NewFence(cfg, lib)
	if err != nil {
		t.Fatalf("NewFence: %v", err)
	}
	tr := &tripper{fence: fence}
	ctx, cancel := context.WithCancel(context.Background())
	_ = fence.Listen(ctx) // the handler below takes every report; the channel stays empty
	fence.SetReportHandler(func(ev fsfence.FenceEvent) {
		e.p.LookbackTrip(func() error {
			return e.commitTrigger(fmt.Sprintf("op=%s path=%s reason=%s", ev.Operation, ev.Path, ev.Reason))
		})
		tr.tripDone.Store(time.Now().UnixNano())
	})
	t.Cleanup(func() { cancel(); fence.Close() })
	return tr
}

func newTripEnv(t *testing.T, rules []config.LookbackRule) (*lbEnv, *tripper) {
	t.Helper()
	e := newLBEnv(t, rules)
	return e, e.attachFence(t, &fsfence.FenceConfig{WaitForAck: true}, "")
}

// report sends one denied-open report and returns once the ack arrives.
func (tr *tripper) report() error {
	c, err := net.Dial("unix", tr.fence.SocketPath)
	if err != nil {
		return err
	}
	defer c.Close()
	line, _ := json.Marshal(fsfence.FenceEvent{Type: "file", Action: "blocked", Path: "/etc/shadow", Operation: "open", Reason: "denied"})
	if _, err := c.Write(append(line, '\n')); err != nil {
		return err
	}
	_ = c.SetReadDeadline(time.Now().Add(15 * time.Second))
	_, err = io.ReadFull(c, make([]byte, 1))
	return err
}

// connectRaw is dialCONNECT for goroutines: it returns errors instead of failing.
func connectRaw(addr, target string) (net.Conn, int, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, 0, err
	}
	req, _ := http.NewRequest(http.MethodConnect, "http://"+addr, nil)
	req.Host = target
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, 0, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		conn.Close()
		return nil, 0, err
	}
	return conn, resp.StatusCode, nil
}

// slowPost streams a POST body through the proxy in chunks until a write fails
// or the body is complete. It reports bytes written and the final status line.
const gateAfter = 8

type slowPost struct {
	conn    net.Conn
	chunks  int
	chunk   int
	wrote   atomic.Int64
	werr    atomic.Value // error that ended the writer, if any
	done    chan struct{}
	started chan struct{}
}

// A non-nil gate holds the writer after gateAfter chunks until it is closed,
// so a stalled host cannot let the body finish before the trip under test.
func startSlowPost(t *testing.T, proxyAddr, host string, chunks, chunkSize int, every time.Duration, gate <-chan struct{}) *slowPost {
	t.Helper()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	sp := &slowPost{conn: conn, chunks: chunks, chunk: chunkSize, done: make(chan struct{}), started: make(chan struct{})}
	t.Cleanup(func() { conn.Close() })
	go func() {
		defer close(sp.done)
		_, err := fmt.Fprintf(conn, "POST http://%s/ HTTP/1.1\r\nHost: %s\r\nContent-Length: %d\r\n\r\n", host, host, chunks*chunkSize)
		if err != nil {
			sp.werr.Store(err)
			return
		}
		close(sp.started)
		buf := []byte(strings.Repeat("x", chunkSize))
		for i := 0; i < chunks; i++ {
			if gate != nil && i == gateAfter {
				select {
				case <-gate:
				case <-time.After(10 * time.Second):
				}
			}
			n, err := conn.Write(buf)
			sp.wrote.Add(int64(n))
			if err != nil {
				sp.werr.Store(err)
				return
			}
			time.Sleep(every)
		}
	}()
	return sp
}

func (sp *slowPost) writeError() error {
	if v := sp.werr.Load(); v != nil {
		return v.(error)
	}
	return nil
}

// Test 9, CONNECT half: a denied open races a CONNECT, 200 times. No new
// connection survives past the ack: the CONNECT is denied, or its tunnel is
// closed by the time the ack returns.
func TestLookbackRaceConnect(t *testing.T) {
	target := holdTarget(t)
	for i := 0; i < 200; i++ {
		t.Run(fmt.Sprintf("iter%03d", i), func(t *testing.T) {
			e, tr := newTripEnv(t, denyRule("r", ""))
			type result struct {
				conn   net.Conn
				status int
				err    error
			}
			res := make(chan result, 1)
			go func() {
				time.Sleep(time.Duration(i%7) * 120 * time.Microsecond)
				c, s, err := connectRaw(e.addr, target)
				res <- result{c, s, err}
			}()
			if err := tr.report(); err != nil {
				t.Fatalf("report: %v", err)
			}

			conn, status := connectStatus(t, e.addr, target)
			conn.Close()
			if status != http.StatusForbidden {
				t.Fatalf("CONNECT started after the ack = %d, want 403", status)
			}
			r := <-res
			switch {
			case r.err != nil, r.status == http.StatusForbidden:
			case r.status == http.StatusOK:
				defer r.conn.Close()
				assertClosed(t, r.conn, 2*time.Second, "tunnel that was registered before the trip")
			default:
				t.Fatalf("racing CONNECT status = %d", r.status)
			}
			if r.conn != nil {
				r.conn.Close()
			}
		})
	}
}

// Control for test 9: with no denied open, every tunnel stays open.
func TestLookbackRaceConnectControl(t *testing.T) {
	target := holdTarget(t)
	for i := 0; i < 20; i++ {
		e := newLBEnv(t, denyRule("r", ""))
		conn, status := connectStatus(t, e.addr, target)
		if status != http.StatusOK {
			t.Fatalf("CONNECT = %d, want 200", status)
		}
		assertOpen(t, conn, 20*time.Millisecond, "tunnel with no trigger")
		conn.Close()
	}
}

// Test 9, POST half: a denied open races a streaming POST, 200 times. No
// request survives past the ack: it is denied, or reset with an incomplete
// body, and once teardown settles no further body bytes reach the target. The
// bytes accepted before the trip are bounded by teardown, not prevented.
func TestLookbackRaceStreamingPost(t *testing.T) {
	for i := 0; i < 200; i++ {
		t.Run(fmt.Sprintf("iter%03d", i), func(t *testing.T) {
			t.Parallel() // each iteration owns its proxy, logger and target; most of the time is teardown
			e, tr := newTripEnv(t, denyRule("r", ""))
			pt := newPostTarget(t)
			const chunks, size = 96, 4096
			gate := make(chan struct{})
			sp := startSlowPost(t, e.addr, pt.host, chunks, size, time.Millisecond, gate)
			time.Sleep(time.Duration(i%7) * time.Millisecond)
			err := tr.report()
			close(gate)
			if err != nil {
				t.Fatalf("report: %v", err)
			}

			conn, status := connectStatus(t, e.addr, pt.host)
			conn.Close()
			if status != http.StatusForbidden {
				t.Fatalf("CONNECT started after the ack = %d, want 403", status)
			}

			time.Sleep(100 * time.Millisecond)
			settled := pt.received.Load()
			select {
			case <-sp.done:
			case <-time.After(5 * time.Second):
				t.Fatal("client writer still running 5 s after the ack")
			}
			// A POST the proxy denied outright gets a 403 and its body is drained
			// and discarded, so the client's writes may all succeed and the reset
			// that follows can swallow the 403; it must still never reach the
			// target. An accepted POST must be cut: a failed write, or a reset
			// or EOF on read. A live connection with no answer is a failure.
			_ = sp.conn.SetReadDeadline(time.Now().Add(time.Second))
			resp, rerr := http.ReadResponse(bufio.NewReader(sp.conn), nil)
			denied := rerr == nil && resp.StatusCode == http.StatusForbidden
			var ne net.Error
			cut := sp.writeError() != nil || (rerr != nil && !(errors.As(rerr, &ne) && ne.Timeout()))
			if !denied && !cut {
				t.Fatalf("client wrote the whole %d-byte body and the connection was not cut (read: %v)", chunks*size, rerr)
			}
			if denied && settled != 0 {
				t.Fatalf("denied POST delivered %d body bytes to the target", settled)
			}
			time.Sleep(100 * time.Millisecond)
			if after := pt.received.Load(); after != settled {
				t.Fatalf("target received %d more body bytes after teardown settled (%d -> %d)", after-settled, settled, after)
			}
			if pt.finished.Load() != 0 || settled >= chunks*size {
				t.Fatalf("target received a complete body (%d bytes)", settled)
			}
		})
	}
}

// Control for test 9: with no denied open every POST body arrives complete.
func TestLookbackRaceStreamingPostControl(t *testing.T) {
	for i := 0; i < 20; i++ {
		e := newLBEnv(t, denyRule("r", ""))
		pt := newPostTarget(t)
		const chunks, size = 64, 4096
		sp := startSlowPost(t, e.addr, pt.host, chunks, size, 200*time.Microsecond, nil)
		<-sp.done
		if err := sp.writeError(); err != nil {
			t.Fatalf("writer error with no trigger: %v", err)
		}
		resp, err := http.ReadResponse(bufio.NewReader(sp.conn), nil)
		if err != nil || resp.StatusCode != http.StatusOK {
			t.Fatalf("response = %v, %v", resp, err)
		}
		if pt.finished.Load() != 1 || pt.received.Load() != chunks*size {
			t.Fatalf("target got %d bytes, finished=%d; want the complete %d-byte body", pt.received.Load(), pt.finished.Load(), chunks*size)
		}
	}
}

// Test 10: an open tunnel and a slow POST are cut by a trigger before the ack,
// and a network_blocked row records each closure. The control has no trigger.
func TestLookbackTriggerClosesOpenConnections(t *testing.T) {
	target := holdTarget(t)
	e, tr := newTripEnv(t, denyRule("r", ""))
	pt := newPostTarget(t)

	tunnel, status := connectStatus(t, e.addr, target)
	defer tunnel.Close()
	if status != http.StatusOK {
		t.Fatalf("CONNECT = %d", status)
	}
	const chunks, size = 400, 1024
	gate := make(chan struct{})
	sp := startSlowPost(t, e.addr, pt.host, chunks, size, 2*time.Millisecond, gate)
	<-sp.started
	waitFor(t, 5*time.Second, "POST body to start arriving", func() bool { return pt.received.Load() > 0 && e.liveCount() == 2 })

	err := tr.report()
	close(gate)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	assertClosed(t, tunnel, time.Second, "tunnel after the ack")
	select {
	case <-sp.done:
	case <-time.After(5 * time.Second):
		t.Fatal("POST writer was not reset")
	}
	if sp.writeError() == nil {
		t.Fatal("POST completed its body despite the trigger")
	}
	time.Sleep(100 * time.Millisecond)
	if pt.finished.Load() != 0 || pt.received.Load() >= chunks*size {
		t.Fatalf("target received a complete POST body (%d bytes)", pt.received.Load())
	}

	trig, _ := e.l.LatestBlockedEvent(lbSession, logging.EventFileBlocked)
	var connectRow, postRow bool
	for _, r := range e.rows(t, logging.EventNetworkBlocked) {
		if !strings.Contains(r.Detail, fmt.Sprintf("rule=lookback:r trigger=%d", trig.ID)) {
			continue
		}
		connectRow = connectRow || strings.HasPrefix(r.Detail, "method=CONNECT host=localhost ")
		postRow = postRow || strings.HasPrefix(r.Detail, "method=POST host="+pt.host+" ")
	}
	if !connectRow || !postRow {
		t.Fatalf("closure rows: CONNECT=%v POST=%v, want both", connectRow, postRow)
	}
	if n := e.liveCount(); n != 0 {
		t.Fatalf("live set has %d entries after close-all", n)
	}

	c := newLBEnv(t, denyRule("r", ""))
	cpt := newPostTarget(t)
	ctunnel, cstatus := connectStatus(t, c.addr, target)
	defer ctunnel.Close()
	csp := startSlowPost(t, c.addr, cpt.host, 20, size, time.Millisecond, nil)
	<-csp.done
	if cstatus != http.StatusOK || csp.writeError() != nil {
		t.Fatalf("control: status %d, POST error %v", cstatus, csp.writeError())
	}
	assertOpen(t, ctunnel, 50*time.Millisecond, "control tunnel")
	waitFor(t, 3*time.Second, "control POST to complete", func() bool { return cpt.finished.Load() == 1 })
	if n := len(c.rows(t, logging.EventNetworkBlocked)); n != 0 {
		t.Fatalf("control wrote %d network_blocked rows", n)
	}
}

// Test 12, first case: a CONNECT paused after Hijack and before the mutex while
// the trigger commits and close-all finishes is denied on resume.
func TestLookbackSeamPausedBeforeEvaluateIsDenied(t *testing.T) {
	target := holdTarget(t)
	e, tr := newTripEnv(t, denyRule("r", ""))
	entered, resume := make(chan struct{}), make(chan struct{})
	var once sync.Once
	e.p.lookbackPause = func(stage string) {
		if stage == "before-evaluate" {
			once.Do(func() { close(entered); <-resume })
		}
	}
	type result struct {
		conn   net.Conn
		status int
		err    error
	}
	res := make(chan result, 1)
	go func() {
		c, s, err := connectRaw(e.addr, target)
		res <- result{c, s, err}
	}()
	<-entered
	if err := tr.report(); err != nil {
		t.Fatalf("report: %v", err)
	}
	close(resume)
	r := <-res
	if r.err != nil || r.status != http.StatusForbidden {
		t.Fatalf("paused CONNECT = %d, %v; want 403 on resume", r.status, r.err)
	}
	r.conn.Close()
	if n := e.liveCount(); n != 0 {
		t.Fatalf("live set has %d entries", n)
	}
}

// Test 12, second case: a request paused inside the critical section, after
// evaluate allows and before it registers, holds the mutex, so the report
// handler blocks until it registers, and the connection is closed before the
// ack. The control cuts the mutex out and the connection survives.
func TestLookbackSeamPausedInsideCriticalSection(t *testing.T) {
	target := holdTarget(t)
	pt := newPostTarget(t)

	open := func(t *testing.T, e *lbEnv, kind string) net.Conn {
		t.Helper()
		if kind == "connect" {
			c, _, err := connectRaw(e.addr, target)
			if err != nil {
				t.Logf("connect: %v", err)
			}
			return c
		}
		c, err := net.Dial("tcp", e.addr)
		if err != nil {
			t.Errorf("dial: %v", err)
			return nil
		}
		fmt.Fprintf(c, "POST http://%s/ HTTP/1.1\r\nHost: %s\r\nContent-Length: 1000\r\n\r\npartial", pt.host, pt.host)
		return c
	}
	pausedEnv := func(t *testing.T) (*lbEnv, *tripper, chan struct{}, chan struct{}) {
		e, tr := newTripEnv(t, denyRule("r", ""))
		entered, resume := make(chan struct{}), make(chan struct{})
		var once sync.Once
		e.p.lookbackPause = func(stage string) {
			if stage == "after-evaluate" {
				once.Do(func() { close(entered); <-resume })
			}
		}
		return e, tr, entered, resume
	}

	for _, kind := range []string{"connect", "plain-http"} {
		t.Run(kind, func(t *testing.T) {
			e, tr, entered, resume := pausedEnv(t)
			connCh := make(chan net.Conn, 1)
			go func() { connCh <- open(t, e, kind) }()
			<-entered

			acked := make(chan error, 1)
			go func() { acked <- tr.report() }()
			select {
			case err := <-acked:
				t.Fatalf("ack arrived (%v) while a request sat inside the critical section", err)
			case <-time.After(150 * time.Millisecond):
			}
			close(resume)
			if err := <-acked; err != nil {
				t.Fatalf("report: %v", err)
			}
			conn := <-connCh
			if conn == nil {
				// The trip cut the request before the client read its 200 line.
				// The cut must still have happened by the ack.
				if n := e.liveCount(); n != 0 {
					t.Fatalf("%s request was cut before the 200 line but the live set has %d entries at the ack", kind, n)
				}
				trig, err := e.l.LatestBlockedEvent(lbSession, logging.EventFileBlocked)
				if err != nil || trig == nil {
					t.Fatalf("trigger not committed: %v %v", trig, err)
				}
				rows := e.rows(t, logging.EventNetworkBlocked)
				if len(rows) != 1 || !strings.HasSuffix(rows[0].Detail, fmt.Sprintf("rule=lookback:r trigger=%d", trig.ID)) {
					t.Fatalf("closure rows at the ack = %+v, want one citing trigger %d", rows, trig.ID)
				}
				return
			}
			defer conn.Close()
			assertClosed(t, conn, time.Second, kind+" connection at the ack")
		})

		t.Run(kind+" control: no mutex", func(t *testing.T) {
			e, _, entered, resume := pausedEnv(t)
			connCh := make(chan net.Conn, 1)
			go func() { connCh <- open(t, e, kind) }()
			<-entered
			// Commit and close-all without taking the mutex, as a broken
			// implementation would: the request has not registered yet, so
			// nothing is closed.
			e.logTrigger(t, lbSession, time.Now())
			e.p.lookback.closeAllLocked()
			close(resume)
			conn := <-connCh
			if conn == nil {
				t.Fatal("no connection")
			}
			defer conn.Close()
			waitFor(t, 3*time.Second, "request to register", func() bool { return e.liveCount() == 1 })
			assertOpen(t, conn, 300*time.Millisecond, kind+" connection with the mutex removed")
		})
	}
}

// Test 14(a): another connection holds the write lock for 300 ms and stalls the
// trigger commit. A CONNECT that arrives meanwhile waits on the mutex and is
// then denied, citing the new trigger row.
func TestLookbackCommitStallThenConnectDenied(t *testing.T) {
	target := holdTarget(t)
	e := newLBEnv(t, denyRule("r", ""))
	if err := e.l.Log(logging.Event{Timestamp: time.Now(), EventType: logging.EventSessionStart, Category: "session", Detail: "x", SessionID: lbSession}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	committing := make(chan struct{})
	wait := holdWriteLock(t, e.dbPath, 300*time.Millisecond)
	start := time.Now()
	go e.p.LookbackTrip(func() error {
		close(committing)
		return e.commitTrigger("d")
	})
	<-committing

	conn, status := connectStatus(t, e.addr, target)
	conn.Close()
	if status != http.StatusForbidden {
		t.Fatalf("CONNECT during the commit stall = %d, want 403", status)
	}
	if took := time.Since(start); took < 250*time.Millisecond {
		t.Fatalf("CONNECT returned after %v, before the write lock cleared; it should wait for the mutex", took)
	}
	wait()
	trig, err := e.l.LatestBlockedEvent(lbSession, logging.EventFileBlocked)
	if err != nil || trig == nil {
		t.Fatalf("trigger not committed: %v %v", trig, err)
	}
	rows := e.rows(t, logging.EventNetworkBlocked)
	if len(rows) != 1 || !strings.HasSuffix(rows[0].Detail, fmt.Sprintf("rule=lookback:r trigger=%d", trig.ID)) {
		t.Fatalf("denial rows = %+v, want one citing trigger %d", rows, trig.ID)
	}
}

// Test 14(b): the lock outlasts busy_timeout, so the commit fails. Close-all
// still runs and denials say trigger=uncommitted, including a CONNECT that
// arrived during the stall. The control has no lock and cites the new row id.
func TestLookbackCommitFailureStaysDenied(t *testing.T) {
	if testing.Short() {
		t.Skip("holds a write lock past the 5 s busy timeout")
	}
	target := holdTarget(t)
	e := newLBEnv(t, denyRule("r", ""))
	if err := e.l.Log(logging.Event{Timestamp: time.Now(), EventType: logging.EventSessionStart, Category: "session", Detail: "x", SessionID: lbSession}); err != nil {
		t.Fatalf("seed: %v", err)
	}
	tunnel, status := connectStatus(t, e.addr, target)
	defer tunnel.Close()
	if status != http.StatusOK {
		t.Fatalf("CONNECT = %d", status)
	}

	stop := captureStderr(t)
	committing := make(chan struct{})
	wait := holdWriteLock(t, e.dbPath, 6*time.Second)
	tripped := make(chan struct{})
	go func() {
		defer close(tripped)
		e.p.LookbackTrip(func() error {
			close(committing)
			return e.commitTrigger("d")
		})
	}()
	<-committing
	conn, status := connectStatus(t, e.addr, target)
	conn.Close()
	<-tripped
	wait()
	stderr := stop()

	if status != http.StatusForbidden {
		t.Fatalf("CONNECT during the stall = %d, want 403", status)
	}
	if !strings.Contains(stderr, "trigger could not be committed") {
		t.Fatalf("stderr does not report the failed commit:\n%s", stderr)
	}
	assertClosed(t, tunnel, time.Second, "tunnel after a failed commit")
	conn, status = connectStatus(t, e.addr, target)
	conn.Close()
	if status != http.StatusForbidden {
		t.Fatalf("CONNECT after the failed commit = %d, want 403", status)
	}
	rows := e.rows(t, logging.EventNetworkBlocked)
	if len(rows) < 2 {
		t.Fatalf("denial rows = %+v", rows)
	}
	for _, r := range rows {
		if !strings.HasSuffix(r.Detail, "rule=lookback:r trigger=uncommitted") {
			t.Fatalf("row %q does not cite trigger=uncommitted", r.Detail)
		}
	}

	c, ctr := newTripEnv(t, denyRule("r", ""))
	ctunnel, _ := connectStatus(t, c.addr, target)
	defer ctunnel.Close()
	if err := ctr.report(); err != nil {
		t.Fatalf("control report: %v", err)
	}
	cconn, cstatus := connectStatus(t, c.addr, target)
	cconn.Close()
	ctrig, _ := c.l.LatestBlockedEvent(lbSession, logging.EventFileBlocked)
	crows := c.rows(t, logging.EventNetworkBlocked)
	if cstatus != http.StatusForbidden || ctrig == nil || len(crows) == 0 {
		t.Fatalf("control: status %d trigger %v rows %d", cstatus, ctrig, len(crows))
	}
	for _, r := range crows {
		if !strings.HasSuffix(r.Detail, fmt.Sprintf("trigger=%d", ctrig.ID)) {
			t.Fatalf("control row %q does not cite trigger %d", r.Detail, ctrig.ID)
		}
	}
}

const interposerChildSource = `
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    int fd;
    if (argc > 2 && argv[2][0] == 'r') {
        fd = (int)syscall(SYS_openat, AT_FDCWD, argv[1], O_RDONLY);
    } else {
        fd = open(argv[1], O_RDONLY);
    }
    printf("fd=%d errno=%d\n", fd, fd < 0 ? errno : 0);
    return 0;
}
`

// Test 11: a denied open from a raw syscall is invisible to the libc
// interposer, so it writes no row and egress stays allowed; the same open
// through libc writes a row, closes the open tunnel and denies the next
// CONNECT. When a sensor for raw syscalls lands, the first subtest fails and
// this pinned limit is updated.
func TestLookbackPinnedLimitRawSyscallBypassesInterposer(t *testing.T) {
	if _, err := exec.LookPath("gcc"); err != nil {
		t.Skipf("gcc unavailable: %v", err)
	}
	dir, err := os.MkdirTemp("/tmp", "nllb-test-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	so := filepath.Join(dir, "libfence_fs.so")
	if out, err := exec.Command("gcc", "-shared", "-fPIC", "-O2", "-Wall", "-Wextra", "-Werror", "-o", so, "../fs/interposer/libfence_fs.c", "-ldl", "-lpthread").CombinedOutput(); err != nil {
		t.Fatalf("build interposer: %v\n%s", err, out)
	}
	src, child := filepath.Join(dir, "child.c"), filepath.Join(dir, "child")
	if err := os.WriteFile(src, []byte(interposerChildSource), 0o600); err != nil {
		t.Fatalf("write child: %v", err)
	}
	if out, err := exec.Command("gcc", "-O2", "-Wall", "-Wextra", "-Werror", "-o", child, src).CombinedOutput(); err != nil {
		t.Fatalf("build child: %v\n%s", err, out)
	}
	target := holdTarget(t)

	run := func(t *testing.T, mode string) (*lbEnv, net.Conn, string) {
		e := newLBEnv(t, denyRule("r", ""))
		cfg := &fsfence.FenceConfig{Root: dir, Mode: "read-write", AllowPaths: []string{"/"}, DenyPaths: []string{"/etc/hostname"}, WaitForAck: true}
		tr := e.attachFence(t, cfg, so)
		tunnel, status := connectStatus(t, e.addr, target)
		if status != http.StatusOK {
			t.Fatalf("CONNECT = %d", status)
		}
		t.Cleanup(func() { tunnel.Close() })
		cmd := exec.Command(child, "/etc/hostname", mode)
		cmd.Env = append(os.Environ(), tr.fence.EnvVars()...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("child: %v\n%s", err, out)
		}
		return e, tunnel, strings.TrimSpace(string(out))
	}

	t.Run("raw syscall writes no row and egress stays allowed", func(t *testing.T) {
		e, tunnel, out := run(t, "raw")
		if !strings.HasPrefix(out, "fd=") || strings.Contains(out, "fd=-1") {
			t.Fatalf("raw open output %q: the open should bypass the libc fence in this harness", out)
		}
		if n := len(e.rows(t, logging.EventFileBlocked)); n != 0 {
			t.Fatalf("raw syscall open wrote %d file_blocked rows", n)
		}
		assertOpen(t, tunnel, 100*time.Millisecond, "tunnel after a raw-syscall open")
		conn, status := connectStatus(t, e.addr, target)
		conn.Close()
		if status != http.StatusOK {
			t.Fatalf("CONNECT after a raw-syscall open = %d, want 200", status)
		}
	})

	t.Run("control: libc open writes a row and denies egress", func(t *testing.T) {
		e, tunnel, out := run(t, "libc")
		if !strings.Contains(out, "fd=-1 errno=13") {
			t.Fatalf("libc open output %q, want EACCES", out)
		}
		if n := len(e.rows(t, logging.EventFileBlocked)); n != 1 {
			t.Fatalf("libc open wrote %d file_blocked rows, want 1", n)
		}
		assertClosed(t, tunnel, time.Second, "tunnel after a libc denied open")
		conn, status := connectStatus(t, e.addr, target)
		conn.Close()
		if status != http.StatusForbidden {
			t.Fatalf("CONNECT after a libc denied open = %d, want 403", status)
		}
	})
}
