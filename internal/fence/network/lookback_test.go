package network

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/nocktechnologies/nocklock/pkg/receipt"
)

const lbSession = "lb-session"

func denyRule(name, within string) []config.LookbackRule {
	return []config.LookbackRule{{Name: name, On: config.LookbackTriggerFileBlocked, Within: within, Then: config.LookbackActionDenyEgress}}
}

// lbEnv is a signed logger plus a started proxy with look-back rules enabled.
type lbEnv struct {
	p      *ProxyServer
	l      *logging.Logger
	addr   string
	dbPath string
	pub    ed25519.PublicKey
}

func newLBEnv(t *testing.T, rules []config.LookbackRule) *lbEnv {
	t.Helper()
	return newLBEnvCfg(t, config.NetworkConfig{Allow: []string{"localhost"}}, rules)
}

func newLBEnvCfg(t *testing.T, cfg config.NetworkConfig, rules []config.LookbackRule) *lbEnv {
	t.Helper()
	dir := t.TempDir()
	e := &lbEnv{dbPath: filepath.Join(dir, "events.db")}
	keyPath := filepath.Join(dir, "keys", "audit.key")
	l, err := logging.NewLogger(e.dbPath, "", logging.WithSigning(keyPath))
	if err != nil {
		t.Fatalf("NewLogger: %v", err)
	}
	t.Cleanup(func() { l.Close() })
	e.l = l
	e.pub, err = logging.LoadPublicKeyFile(keyPath)
	if err != nil {
		t.Fatalf("load public key: %v", err)
	}
	e.p = NewProxyServer(cfg, l, lbSession)
	e.p.dialFunc = unsafeDial
	e.p.EnableLookback(rules)
	e.addr, err = e.p.Start()
	if err != nil {
		t.Fatalf("proxy Start: %v", err)
	}
	t.Cleanup(func() { e.p.Stop() })
	return e
}

func (e *lbEnv) logTrigger(t *testing.T, session string, ts time.Time) {
	t.Helper()
	err := e.l.Log(logging.Event{
		Timestamp: ts, EventType: logging.EventFileBlocked, Category: "filesystem",
		Detail: "op=open path=/etc/shadow reason=denied", Blocked: true, SessionID: session,
	})
	if err != nil {
		t.Fatalf("log trigger: %v", err)
	}
}

// commitTrigger writes a file_blocked row the way the wrap report handler does.
func (e *lbEnv) commitTrigger(detail string) error {
	return e.l.LogImmediate(logging.Event{Timestamp: time.Now(), EventType: logging.EventFileBlocked, Category: "filesystem", Detail: detail, Blocked: true, SessionID: lbSession})
}

func (e *lbEnv) rows(t *testing.T, et logging.EventType) []logging.Event {
	t.Helper()
	sid := lbSession
	evs, err := e.l.Query(logging.QueryOptions{EventType: &et, SessionID: &sid, Limit: 100000, ByID: true})
	if err != nil {
		t.Fatalf("query %s: %v", et, err)
	}
	return evs
}

func (e *lbEnv) liveCount() int {
	g := e.p.lookback
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.live)
}

// holdTarget accepts TCP connections and holds them open, discarding input.
func holdTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(io.Discard, c) //nolint:errcheck
			}()
		}
	}()
	_, port, _ := net.SplitHostPort(ln.Addr().String())
	return "localhost:" + port
}

// postTarget records the bytes of every POST body it receives.
type postTarget struct {
	host     string
	received atomic.Int64
	finished atomic.Int64 // requests whose body arrived complete
}

func newPostTarget(t *testing.T) *postTarget {
	t.Helper()
	pt := &postTarget{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		buf := make([]byte, 4096)
		for {
			n, err := r.Body.Read(buf)
			pt.received.Add(int64(n))
			if err == io.EOF {
				pt.finished.Add(1)
				break
			}
			if err != nil {
				return
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	pt.host = "localhost:" + port
	return pt
}

// dialAlways dials target whatever address the proxy asks for, so a test can
// send CONNECTs to many distinct hostnames.
func dialAlways(target string) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, target)
	}
}

// connectStatus issues a CONNECT and returns the status; the caller closes conn.
func connectStatus(t *testing.T, addr, target string) (net.Conn, int) {
	t.Helper()
	conn, resp := dialCONNECT(t, addr, target)
	return conn, resp.StatusCode
}

// assertClosed fails unless the connection reports EOF or a reset within wait.
func assertClosed(t *testing.T, c net.Conn, wait time.Duration, what string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(wait))
	_, err := c.Read(make([]byte, 1))
	if err == nil {
		t.Fatalf("%s: connection delivered data, want it closed", what)
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatalf("%s: connection still open after %v", what, wait)
	}
}

// assertOpen fails unless the connection stays silent and open for wait.
func assertOpen(t *testing.T, c net.Conn, wait time.Duration, what string) {
	t.Helper()
	_ = c.SetReadDeadline(time.Now().Add(wait))
	_, err := c.Read(make([]byte, 1))
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("%s: connection closed (read err %v), want it open", what, err)
	}
}

// captureStderr redirects os.Stderr until the returned func is called, which
// restores it and returns what was written.
func captureStderr(t *testing.T) func() string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := os.Stderr
	os.Stderr = w
	done := make(chan string)
	go func() {
		b, _ := io.ReadAll(r)
		done <- string(b)
	}()
	return func() string {
		os.Stderr = orig
		w.Close()
		return <-done
	}
}

// Test 1: a trigger row denies CONNECT and the row cites rule and trigger.
func TestLookbackTriggerDeniesConnect(t *testing.T) {
	e := newLBEnv(t, denyRule("probe-then-exfil", ""))
	target := holdTarget(t)

	conn, status := connectStatus(t, e.addr, target)
	conn.Close()
	if status != http.StatusOK {
		t.Fatalf("control: CONNECT without a trigger = %d, want 200", status)
	}
	if n := len(e.rows(t, logging.EventNetworkBlocked)); n != 0 {
		t.Fatalf("control: %d network_blocked rows without a trigger", n)
	}

	e.logTrigger(t, lbSession, time.Now())
	trig, err := e.l.LatestBlockedEvent(lbSession, logging.EventFileBlocked)
	if err != nil || trig == nil {
		t.Fatalf("LatestBlockedEvent = %v, %v", trig, err)
	}

	conn, status = connectStatus(t, e.addr, target)
	conn.Close()
	if status != http.StatusForbidden {
		t.Fatalf("CONNECT after trigger = %d, want 403", status)
	}
	rows := e.rows(t, logging.EventNetworkBlocked)
	if len(rows) != 1 {
		t.Fatalf("network_blocked rows = %d, want 1", len(rows))
	}
	want := fmt.Sprintf("method=CONNECT host=localhost rule=lookback:probe-then-exfil trigger=%d", trig.ID)
	if rows[0].Detail != want || !rows[0].Blocked {
		t.Fatalf("denial row = %q blocked=%v, want %q blocked", rows[0].Detail, rows[0].Blocked, want)
	}
}

// Plain HTTP is denied by the same rule, with the same row.
func TestLookbackTriggerDeniesPlainHTTP(t *testing.T) {
	e := newLBEnv(t, denyRule("r", ""))
	pt := newPostTarget(t)
	client := &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(&url.URL{Scheme: "http", Host: e.addr}),
		DisableKeepAlives: true,
	}}

	resp, err := client.Get("http://" + pt.host + "/")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("control: GET without a trigger = %v, %v", resp, err)
	}
	resp.Body.Close()

	e.logTrigger(t, lbSession, time.Now())
	resp, err = client.Get("http://" + pt.host + "/")
	if err != nil {
		t.Fatalf("GET after trigger: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("GET after trigger = %d, want 403", resp.StatusCode)
	}
	rows := e.rows(t, logging.EventNetworkBlocked)
	if len(rows) != 1 || !strings.Contains(rows[0].Detail, "method=GET host="+pt.host+" rule=lookback:r trigger=") {
		t.Fatalf("denial rows = %+v", rows)
	}
}

// Test 2: the denial row and trigger verify INTACT; editing the trigger id in
// the denial breaks the chain.
func TestLookbackDenialVerifiesUnderReceipt(t *testing.T) {
	e := newLBEnv(t, denyRule("r", ""))
	target := holdTarget(t)
	e.logTrigger(t, lbSession, time.Now())
	conn, status := connectStatus(t, e.addr, target)
	conn.Close()
	if status != http.StatusForbidden {
		t.Fatalf("CONNECT = %d, want 403", status)
	}

	res, err := receipt.VerifySession(e.dbPath, e.pub, lbSession)
	if err != nil || res.Verdict != receipt.VerdictIntact {
		t.Fatalf("verdict = %s (%v) reason %q, want INTACT", res.Verdict, err, res.Reason)
	}
	trig, _ := e.l.LatestBlockedEvent(lbSession, logging.EventFileBlocked)
	_, err = rawUpdate(e.dbPath, "UPDATE events SET detail = replace(detail, ?, ?) WHERE event_type = 'network_blocked'",
		"trigger="+strconv.FormatInt(trig.ID, 10), "trigger=999")
	if err != nil {
		t.Fatalf("tamper: %v", err)
	}
	res, err = receipt.VerifySession(e.dbPath, e.pub, lbSession)
	if err != nil || res.Verdict != receipt.VerdictTampered {
		t.Fatalf("after editing the trigger id: verdict = %s (%v), want TAMPERED", res.Verdict, err)
	}
}

func rawUpdate(dbPath, stmt string, args ...any) (int64, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return 0, err
	}
	defer db.Close()
	res, err := db.Exec(stmt, args...)
	if err != nil {
		return 0, err
	}
	return res.RowsAffected()
}

// Test 3: a trigger in another session does not trip the rule.
func TestLookbackOtherSessionTriggerDoesNotTrip(t *testing.T) {
	e := newLBEnv(t, denyRule("r", ""))
	target := holdTarget(t)
	e.logTrigger(t, "some-other-session", time.Now())
	conn, status := connectStatus(t, e.addr, target)
	conn.Close()
	if status != http.StatusOK {
		t.Fatalf("CONNECT with only another session's trigger = %d, want 200", status)
	}

	e.logTrigger(t, lbSession, time.Now())
	conn, status = connectStatus(t, e.addr, target)
	conn.Close()
	if status != http.StatusForbidden {
		t.Fatalf("control: the same trigger in this session = %d, want 403", status)
	}
}

// Test 4: a trigger older than within allows; a future-dated one denies.
func TestLookbackWithinWindow(t *testing.T) {
	cases := []struct {
		name string
		age  time.Duration
		want int
	}{
		{"older than within allows", -2 * time.Hour, http.StatusOK},
		{"inside within denies", -time.Minute, http.StatusForbidden},
		{"future-dated denies", time.Hour, http.StatusForbidden},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := newLBEnv(t, denyRule("r", "1h"))
			target := holdTarget(t)
			e.logTrigger(t, lbSession, time.Now().Add(tc.age))
			conn, status := connectStatus(t, e.addr, target)
			conn.Close()
			if status != tc.want {
				t.Fatalf("CONNECT = %d, want %d", status, tc.want)
			}
		})
	}
}

func TestEvaluateLookback(t *testing.T) {
	now := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	rules := []config.LookbackRule{
		{Name: "short", On: "file_blocked", Within: "1m", Then: "deny_egress"},
		{Name: "forever", On: "file_blocked", Then: "deny_egress"},
	}
	trig := func(age time.Duration) *logging.Event {
		return &logging.Event{ID: 7, Timestamp: now.Add(-age)}
	}
	cases := []struct {
		name     string
		rules    []config.LookbackRule
		trigger  *logging.Event
		wantDeny bool
		wantRule string
	}{
		{"no trigger", rules, nil, false, ""},
		{"inside first rule's window", rules, trig(10 * time.Second), true, "short"},
		{"outside first, second has no window", rules, trig(time.Hour), true, "forever"},
		{"future-dated", rules[:1], trig(-time.Hour), true, "short"},
		{"outside the only window", rules[:1], trig(time.Hour), false, ""},
		{"exactly on the boundary", rules[:1], trig(time.Minute), true, "short"},
		{"no rules", nil, trig(time.Second), false, ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			deny, rule, id := evaluateLookback(tc.rules, tc.trigger, now)
			if deny != tc.wantDeny || rule != tc.wantRule {
				t.Fatalf("evaluateLookback = %v %q, want %v %q", deny, rule, tc.wantDeny, tc.wantRule)
			}
			if deny && id != 7 {
				t.Fatalf("trigger id = %d, want 7", id)
			}
		})
	}
}

// Test 5: 10,000 network_passed rows after the trigger do not push it out.
func TestLookbackSurvivesManyLaterRows(t *testing.T) {
	e := newLBEnv(t, denyRule("r", ""))
	target := holdTarget(t)
	e.logTrigger(t, lbSession, time.Now())
	batch := make([]logging.Event, 10000)
	for i := range batch {
		batch[i] = logging.Event{
			Timestamp: time.Now(), EventType: logging.EventNetworkPassed, Category: "network",
			Detail: "method=CONNECT host=x", SessionID: lbSession,
		}
	}
	if err := e.l.LogBatch(batch); err != nil {
		t.Fatalf("LogBatch: %v", err)
	}
	conn, status := connectStatus(t, e.addr, target)
	conn.Close()
	if status != http.StatusForbidden {
		t.Fatalf("CONNECT after 10,000 later rows = %d, want 403", status)
	}

	c := newLBEnv(t, denyRule("r", ""))
	for i := range batch {
		batch[i].SessionID = lbSession
	}
	if err := c.l.LogBatch(batch); err != nil {
		t.Fatalf("control LogBatch: %v", err)
	}
	conn, status = connectStatus(t, c.addr, holdTarget(t))
	conn.Close()
	if status != http.StatusOK {
		t.Fatalf("control: CONNECT with no trigger = %d, want 200", status)
	}
}

// Test 6: an unreadable history denies egress and says so once on stderr. The
// control is the same failure with no rules: egress is unaffected.
func TestLookbackUnreadableHistoryDenies(t *testing.T) {
	e := newLBEnv(t, denyRule("r", ""))
	target := holdTarget(t)
	if err := e.l.Close(); err != nil {
		t.Fatalf("close logger: %v", err)
	}
	stop := captureStderr(t)
	var statuses []int
	for i := 0; i < 3; i++ {
		conn, status := connectStatus(t, e.addr, target)
		conn.Close()
		statuses = append(statuses, status)
	}
	stderr := stop()
	for _, s := range statuses {
		if s != http.StatusForbidden {
			t.Fatalf("CONNECT with unreadable history = %v, want all 403", statuses)
		}
	}
	if n := strings.Count(stderr, "cannot read the event history"); n != 1 {
		t.Fatalf("stderr mentions the unreadable history %d times, want once:\n%s", n, stderr)
	}

	c := newLBEnv(t, nil)
	ctarget := holdTarget(t)
	if err := c.l.Close(); err != nil {
		t.Fatalf("close control logger: %v", err)
	}
	conn, status := connectStatus(t, c.addr, ctarget)
	conn.Close()
	if status != http.StatusOK {
		t.Fatalf("control: no rules, closed logger: CONNECT = %d, want 200", status)
	}
}

// A trip whose commit succeeds but whose read-back is empty keeps egress denied
// for the session. The control is the same empty query with no trip: egress is
// allowed, so the denial comes from the trip.
func TestLookbackEmptyReadBackAfterCommitStaysDenied(t *testing.T) {
	empty := func() (*logging.Event, error) { return nil, nil }

	e := newLBEnv(t, denyRule("r", ""))
	target := holdTarget(t)
	e.p.lookback.query = empty
	e.p.LookbackTrip(func() error { return e.commitTrigger("op=open path=/etc/shadow reason=denied") })
	conn, status := connectStatus(t, e.addr, target)
	conn.Close()
	if status != http.StatusForbidden {
		t.Fatalf("CONNECT after a committed trip with an empty read-back = %d, want 403", status)
	}

	c := newLBEnv(t, denyRule("r", ""))
	ctarget := holdTarget(t)
	c.p.lookback.query = empty
	conn, status = connectStatus(t, c.addr, ctarget)
	conn.Close()
	if status != http.StatusOK {
		t.Fatalf("control: empty read-back with no trip: CONNECT = %d, want 200", status)
	}
}

// Test 8: denied requests to distinct hosts write at most the cap plus one
// summary row. The control stays under the cap and writes one row each.
func TestLookbackDenialRowCap(t *testing.T) {
	if testing.Short() {
		t.Skip("writes ~500 signed rows")
	}
	e := newLBEnvCfg(t, config.NetworkConfig{AllowAll: true}, denyRule("r", ""))
	e.p.dialFunc = dialAlways(holdTarget(t))
	e.logTrigger(t, lbSession, time.Now())
	for i := 0; i < 1000; i++ {
		conn, status := connectStatus(t, e.addr, fmt.Sprintf("host-%d.example.com:443", i))
		conn.Close()
		if status != http.StatusForbidden {
			t.Fatalf("request %d = %d, want 403", i, status)
		}
	}
	rows := e.rows(t, logging.EventNetworkBlocked)
	if len(rows) != lookbackMaxDenialRows+1 {
		t.Fatalf("1,000 denials wrote %d rows, want %d", len(rows), lookbackMaxDenialRows+1)
	}
	if last := rows[len(rows)-1].Detail; !strings.Contains(last, "summary=") || !strings.Contains(last, "rule=lookback:r") {
		t.Fatalf("last row = %q, want the cap summary", last)
	}

	c := newLBEnvCfg(t, config.NetworkConfig{AllowAll: true}, denyRule("r", ""))
	c.p.dialFunc = dialAlways(holdTarget(t))
	c.logTrigger(t, lbSession, time.Now())
	for i := 0; i < 100; i++ {
		conn, _ := connectStatus(t, c.addr, fmt.Sprintf("host-%d.example.com:443", i))
		conn.Close()
	}
	crows := c.rows(t, logging.EventNetworkBlocked)
	if len(crows) != 100 {
		t.Fatalf("control: 100 denials wrote %d rows, want 100", len(crows))
	}
	for _, r := range crows {
		if strings.Contains(r.Detail, "summary=") {
			t.Fatalf("control: unexpected summary row %q", r.Detail)
		}
	}
}

// Test 15: the registered set empties as requests finish. The control holds
// 200 open and the set has 200 entries.
func TestLookbackLiveSetCleanup(t *testing.T) {
	e := newLBEnv(t, denyRule("r", ""))
	connectTarget := holdTarget(t)
	pt := newPostTarget(t)

	var held []net.Conn
	t.Cleanup(func() {
		for _, c := range held {
			c.Close()
		}
	})
	for i := 0; i < 100; i++ {
		conn, status := connectStatus(t, e.addr, connectTarget)
		if status != http.StatusOK {
			t.Fatalf("CONNECT %d = %d", i, status)
		}
		held = append(held, conn)

		// An unfinished POST body keeps the plain-HTTP request in flight.
		c, err := net.Dial("tcp", e.addr)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		held = append(held, c)
		fmt.Fprintf(c, "POST http://%s/ HTTP/1.1\r\nHost: %s\r\nContent-Length: 10\r\n\r\nab", pt.host, pt.host)
	}
	waitFor(t, 5*time.Second, "200 live entries while held open", func() bool { return e.liveCount() == 200 })

	for _, c := range held {
		c.Close()
	}
	waitFor(t, 5*time.Second, "an empty live set after everything finished", func() bool { return e.liveCount() == 0 })

	client := &http.Client{Transport: &http.Transport{
		Proxy:             http.ProxyURL(&url.URL{Scheme: "http", Host: e.addr}),
		DisableKeepAlives: true,
	}}
	for i := 0; i < 100; i++ {
		conn, status := connectStatus(t, e.addr, connectTarget)
		conn.Close()
		resp, err := client.Get("http://" + pt.host + "/")
		if err != nil || status != http.StatusOK {
			t.Fatalf("finishing request %d: %v status %d", i, err, status)
		}
		resp.Body.Close()
	}
	waitFor(t, 5*time.Second, "an empty live set after 100 CONNECT + 100 GET finished", func() bool { return e.liveCount() == 0 })
}

func waitFor(t *testing.T, d time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// Test 14(c): an unrelated writer holds the database write lock and no trigger
// commit is in progress. Evaluation is a WAL read and does not wait, and the
// CONNECT is allowed once the lock clears. The control has no writer.
func TestLookbackUnrelatedWriterDoesNotDelayEvaluation(t *testing.T) {
	run := func(t *testing.T, withWriter bool) {
		e := newLBEnv(t, denyRule("r", ""))
		target := holdTarget(t)
		if err := e.l.Log(logging.Event{Timestamp: time.Now(), EventType: logging.EventSessionStart, Category: "session", Detail: "x", SessionID: lbSession}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		var unlock func()
		if withWriter {
			unlock = holdWriteLock(t, e.dbPath, 300*time.Millisecond)
		}
		start := time.Now()
		release, denial := e.p.admitLookback("method=CONNECT host=x", func() {})
		took := time.Since(start)
		if denial != nil {
			t.Fatalf("trigger-free admit denied: %+v", denial)
		}
		release()
		if took > 150*time.Millisecond {
			t.Fatalf("admit took %v with writer=%v; evaluation must not wait for the write lock", took, withWriter)
		}

		conn, status := connectStatus(t, e.addr, target)
		conn.Close()
		if status != http.StatusOK {
			t.Fatalf("CONNECT = %d, want 200", status)
		}
		if unlock != nil {
			unlock()
		}
	}
	t.Run("with unrelated writer", func(t *testing.T) { run(t, true) })
	t.Run("control: no writer", func(t *testing.T) { run(t, false) })
}

// holdWriteLock takes the SQLite write lock on a separate connection for d,
// without writing. The returned func waits for it to be released.
func holdWriteLock(t *testing.T, dbPath string, d time.Duration) (wait func()) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open lock holder: %v", err)
	}
	db.SetMaxOpenConns(1)
	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatalf("lock holder conn: %v", err)
	}
	if _, err := conn.ExecContext(t.Context(), "BEGIN IMMEDIATE"); err != nil {
		t.Fatalf("take write lock: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		time.Sleep(d)
		_, _ = conn.ExecContext(t.Context(), "COMMIT")
		conn.Close()
		db.Close()
	}()
	return func() { <-done }
}
