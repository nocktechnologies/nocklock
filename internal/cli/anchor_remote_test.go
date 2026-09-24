package cli

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/anchorclient"
	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/spf13/cobra"

	_ "modernc.org/sqlite"
)

const remoteTestToken = "tok-SENTINEL-cli-4a9e"

// seedSignedChain writes n signed rows with the managed key the CLI resolves.
func seedSignedChain(t *testing.T, dbPath, keyPath string, n int) {
	t.Helper()
	l, err := logging.NewLogger(dbPath, "", logging.WithSigning(keyPath))
	if err != nil {
		t.Fatalf("seed logger: %v", err)
	}
	for i := 0; i < n; i++ {
		if err := l.Log(logging.Event{EventType: logging.EventFileBlocked, Category: "filesystem", Detail: "/etc/shadow", Blocked: true, SessionID: "s"}); err != nil {
			t.Fatalf("seed Log: %v", err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatalf("seed close: %v", err)
	}
}

// emitAnchorNow emits a signed anchor of the current chain head.
func emitAnchorNow(t *testing.T, dbPath, keyPath string) *logging.Anchor {
	t.Helper()
	l, err := logging.NewLogger(dbPath, "", logging.WithSigning(keyPath))
	if err != nil {
		t.Fatalf("anchor logger: %v", err)
	}
	defer l.Close()
	a, err := l.EmitAnchor()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	return a
}

// truncateTo deletes every row past keep and rewrites chain_head in lockstep:
// the rollback an attacker with file access performs.
func truncateTo(t *testing.T, dbPath string, keep int) {
	t.Helper()
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("open raw: %v", err)
	}
	defer db.Close()
	var h string
	if err := db.QueryRow("SELECT entry_hash FROM events WHERE id = ?", keep).Scan(&h); err != nil {
		t.Fatalf("read hash@%d: %v", keep, err)
	}
	if _, err := db.Exec("DELETE FROM events WHERE id > ?", keep); err != nil {
		t.Fatalf("truncate: %v", err)
	}
	if _, err := db.Exec("UPDATE chain_head SET entry_hash = ?, row_count = ? WHERE id = 1", h, keep); err != nil {
		t.Fatalf("rewrite head: %v", err)
	}
}

// anchorStore is a fake off-box store serving one anchor for GET latest.
func anchorStore(t *testing.T, a *logging.Anchor) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/nocklock/anchors/"+a.AgentID+"/latest/" {
			http.NotFound(w, r)
			return
		}
		data, _ := logging.MarshalAnchor(a)
		w.Write(data)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func wantExit1(t *testing.T, err error) {
	t.Helper()
	var ece *exitCodeError
	if !asExitCodeError(err, &ece) || ece.code != 1 {
		t.Fatalf("want exit 1, got %v", err)
	}
}

// ---------- verify --against-remote-anchor ----------

func TestVerifyRemoteAnchor_OK(t *testing.T) {
	dbPath, keyPath := setupAnchorProject(t)
	seedSignedChain(t, dbPath, keyPath, 5)
	srv := anchorStore(t, emitAnchorNow(t, dbPath, keyPath))
	t.Setenv(anchorclient.EnvURL, srv.URL)
	t.Setenv(anchorclient.EnvToken, remoteTestToken)

	var out bytes.Buffer
	if err := runVerifyAgainstRemoteAnchor(context.Background(), &out, ""); err != nil {
		t.Fatalf("intact chain vs remote anchor should pass, got %v\n%s", err, out.String())
	}
	if !strings.Contains(out.String(), "ANCHOR: OK") {
		t.Errorf("missing ANCHOR: OK:\n%s", out.String())
	}
}

// The remote store attests MORE rows than the local chain now holds: a local
// rollback that the local signed head alone cannot see.
func TestVerifyRemoteAnchor_Truncation(t *testing.T) {
	dbPath, keyPath := setupAnchorProject(t)
	seedSignedChain(t, dbPath, keyPath, 5)
	remote := emitAnchorNow(t, dbPath, keyPath) // row_count 5, pinned off-box
	truncateTo(t, dbPath, 3)                    // local rolled back to 3
	srv := anchorStore(t, remote)
	t.Setenv(anchorclient.EnvURL, srv.URL)
	t.Setenv(anchorclient.EnvToken, remoteTestToken)

	var out bytes.Buffer
	err := runVerifyAgainstRemoteAnchor(context.Background(), &out, "")
	wantExit1(t, err)
	if !strings.Contains(out.String(), "ANCHOR: TRUNCATION") {
		t.Errorf("missing ANCHOR: TRUNCATION:\n%s", out.String())
	}
}

func TestVerifyRemoteAnchor_UnavailableExitsNonZero(t *testing.T) {
	dbPath, keyPath := setupAnchorProject(t)
	seedSignedChain(t, dbPath, keyPath, 2)

	notFound := httptest.NewServer(http.NotFoundHandler())
	defer notFound.Close()
	down := httptest.NewServer(http.NotFoundHandler())
	downURL := down.URL
	down.Close() // connection refused

	cases := map[string]string{
		"unset URL":         "",
		"no stored anchor":  notFound.URL,
		"unreachable":       downURL,
		"non-loopback http": "http://ncc.example.com",
	}
	for name, u := range cases {
		t.Run(name, func(t *testing.T) {
			t.Setenv(anchorclient.EnvURL, u)
			t.Setenv(anchorclient.EnvToken, remoteTestToken)
			var out bytes.Buffer
			err := runVerifyAgainstRemoteAnchor(context.Background(), &out, "")
			wantExit1(t, err)
			if !strings.Contains(out.String(), "anchor_unavailable") || !strings.Contains(out.String(), "ANCHOR: UNAVAILABLE") {
				t.Errorf("absence must be reported as anchor_unavailable:\n%s", out.String())
			}
			if strings.Contains(out.String(), remoteTestToken) {
				t.Error("verify output leaks the bearer token")
			}
		})
	}
}

func TestVerifyRemoteAnchor_NoKeyFailsClosed(t *testing.T) {
	dbPath, _ := setupAnchorProject(t)
	// An unsigned log, and no managed key on disk.
	l, err := logging.NewLogger(dbPath, "")
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()
	t.Setenv(anchorclient.EnvURL, srv.URL)

	var out bytes.Buffer
	wantExit1(t, runVerifyAgainstRemoteAnchor(context.Background(), &out, ""))
	if !strings.Contains(out.String(), "ANCHOR: FAILED") {
		t.Errorf("missing FAILED verdict:\n%s", out.String())
	}
	if hits.Load() != 0 {
		t.Error("fetched from the store without a key to authenticate the result")
	}
}

func TestVerifyAnchorFlagsMutuallyExclusive(t *testing.T) {
	t.Cleanup(func() {
		_ = verifyCmd.Flags().Set("against-anchor", "")
		_ = verifyCmd.Flags().Set("against-remote-anchor", "false")
	})
	if err := verifyCmd.Flags().Set("against-anchor", "x.json"); err != nil {
		t.Fatal(err)
	}
	if err := verifyCmd.Flags().Set("against-remote-anchor", "true"); err != nil {
		t.Fatal(err)
	}
	err := verifyCmd.RunE(verifyCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("want mutual-exclusion error, got %v", err)
	}
}

// ---------- anchor push (CLI) ----------

func TestAnchorPushCLI(t *testing.T) {
	dbPath, keyPath := setupAnchorProject(t)
	seedSignedChain(t, dbPath, keyPath, 3)
	a := emitAnchorNow(t, dbPath, keyPath)
	if err := logging.WriteAnchor(logging.DefaultAnchorPath(dbPath), a); err != nil {
		t.Fatal(err)
	}

	var got struct {
		Anchor *logging.Anchor `json:"anchor"`
		Pubkey string          `json:"pubkey"`
	}
	var auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	t.Setenv(anchorclient.EnvURL, "")
	if err := runAnchorPush(context.Background(), io.Discard, ""); err == nil || err.Error() != "no anchor URL configured (NOCKLOCK_ANCHOR_URL)" {
		t.Fatalf("unset URL: got %v", err)
	}

	t.Setenv(anchorclient.EnvURL, srv.URL)
	t.Setenv(anchorclient.EnvToken, remoteTestToken)
	var out bytes.Buffer
	if err := runAnchorPush(context.Background(), &out, ""); err != nil {
		t.Fatalf("push: %v", err)
	}
	if got.Anchor == nil || *got.Anchor != *a || auth != "Bearer "+remoteTestToken || got.Pubkey == "" {
		t.Errorf("server did not receive the default anchor file with key and bearer")
	}
	pub, err := logging.LoadPublicKeyFile(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	if got.Pubkey != logging.EncodePublicKey(pub) {
		t.Errorf("pushed pubkey is not the managed key")
	}
	if strings.Contains(out.String(), remoteTestToken) {
		t.Error("push output leaks the token")
	}
}

func TestAnchorPushCLIRegressionIsError(t *testing.T) {
	dbPath, keyPath := setupAnchorProject(t)
	seedSignedChain(t, dbPath, keyPath, 1)
	anchorFile := filepath.Join(t.TempDir(), "a.json")
	if err := logging.WriteAnchor(anchorFile, emitAnchorNow(t, dbPath, keyPath)); err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "row_count regression", http.StatusConflict)
	}))
	defer srv.Close()
	t.Setenv(anchorclient.EnvURL, srv.URL)
	t.Setenv(anchorclient.EnvToken, remoteTestToken)
	err := runAnchorPush(context.Background(), io.Discard, anchorFile)
	if err == nil || !strings.Contains(err.Error(), "regression") || strings.Contains(err.Error(), remoteTestToken) {
		t.Fatalf("409 must surface as a regression error without the token, got %v", err)
	}
}

// ---------- wrap teardown push + child env ----------

func TestStripAnchorEnvRemovesURLAndToken(t *testing.T) {
	env := []string{
		"PATH=/bin",
		anchorclient.EnvURL + "=https://ncc.example.com",
		anchorclient.EnvToken + "=" + remoteTestToken,
		"NOCKLOCK_ANCHOR_TOKEN_EXTRA=keep",
	}
	got := stripAnchorEnv(env)
	joined := strings.Join(got, "\n")
	if strings.Contains(joined, anchorclient.EnvURL+"=") || strings.Contains(joined, remoteTestToken) {
		t.Fatalf("anchor URL/token survived the strip: %q", got)
	}
	if !strings.Contains(joined, "PATH=/bin") || !strings.Contains(joined, "NOCKLOCK_ANCHOR_TOKEN_EXTRA=keep") {
		t.Fatalf("strip removed unrelated vars: %q", got)
	}
}

func TestPushAnchorOffBox_UnsetURLIsSilent(t *testing.T) {
	t.Setenv(anchorclient.EnvURL, "")
	var buf bytes.Buffer
	pushAnchorOffBox(&buf, &logging.Anchor{}, nil)
	if buf.Len() != 0 {
		t.Fatalf("unset URL must print nothing, got %q", buf.String())
	}
}

func TestPushAnchorOffBox_FailureWarnsLoudly(t *testing.T) {
	dbPath, keyPath := setupAnchorProject(t)
	seedSignedChain(t, dbPath, keyPath, 1)
	a := emitAnchorNow(t, dbPath, keyPath)
	pub, _ := logging.LoadPublicKeyFile(keyPath)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	t.Setenv(anchorclient.EnvURL, srv.URL)
	t.Setenv(anchorclient.EnvToken, remoteTestToken)

	var buf bytes.Buffer
	pushAnchorOffBox(&buf, a, pub)
	if !strings.Contains(buf.String(), "NockLock: warning: chain anchor NOT pushed off-box:") || !strings.Contains(buf.String(), "500") {
		t.Fatalf("missing loud warning: %q", buf.String())
	}
	if strings.Contains(buf.String(), remoteTestToken) {
		t.Fatal("warning leaks the token")
	}
}

func TestPushAnchorOffBox_HonorsTimeout(t *testing.T) {
	dbPath, keyPath := setupAnchorProject(t)
	seedSignedChain(t, dbPath, keyPath, 1)
	a := emitAnchorNow(t, dbPath, keyPath)
	pub, _ := logging.LoadPublicKeyFile(keyPath)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-release:
		case <-time.After(10 * time.Second):
		}
	}))
	defer srv.Close()
	defer close(release)
	t.Setenv(anchorclient.EnvURL, srv.URL)

	orig := anchorPushTimeout
	anchorPushTimeout = 150 * time.Millisecond
	t.Cleanup(func() { anchorPushTimeout = orig })

	var buf bytes.Buffer
	start := time.Now()
	pushAnchorOffBox(&buf, a, pub)
	if el := time.Since(start); el > 3*time.Second {
		t.Fatalf("teardown push ignored its timeout (%v)", el)
	}
	if !strings.Contains(buf.String(), "NOT pushed off-box") || !strings.Contains(buf.String(), "deadline exceeded") {
		t.Fatalf("timeout must warn: %q", buf.String())
	}
}

// End-to-end through wrap's RunE (no root needed: fs/syscall fences and the
// proxy are off so the child runs directly). A failing off-box push must leave
// the wrapped command's exit code untouched and warn on stderr, and the child
// must never see the anchor URL or token even when the secret fence would pass
// them.
func TestWrapTeardownPushFailOpenAndChildEnvStripped(t *testing.T) {
	project := t.TempDir()
	nockDir := filepath.Join(project, config.Dir)
	if err := os.MkdirAll(nockDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := config.DefaultConfig()
	cfg.Logging.DB = filepath.Join(config.Dir, "events.db")
	cfg.Filesystem.Root = ""
	cfg.Network.AllowAll = true
	cfg.Syscall.Enforcement = "off"
	// Explicit (non-empty) lists so no default fills in: every var passes and the
	// block pattern matches nothing, so ONLY the anchor-env strip keeps the token
	// (which the default "*_TOKEN*" block would otherwise catch) from the child.
	cfg.Secrets.Pass = []string{"*"}
	cfg.Secrets.Block = []string{"NOCKLOCK_TEST_MATCHES_NOTHING"}
	if err := writeConfigTOML(filepath.Join(nockDir, config.File), &cfg); err != nil {
		t.Fatal(err)
	}
	t.Chdir(project)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "xdg"))

	var pushes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pushes.Add(1)
		http.Error(w, "store down", http.StatusServiceUnavailable)
	}))
	defer srv.Close()
	t.Setenv(anchorclient.EnvURL, srv.URL)
	t.Setenv(anchorclient.EnvToken, remoteTestToken)
	t.Setenv("NOCKLOCK_E2E_CONTROL", "visible")

	envOut := filepath.Join(t.TempDir(), "child-env.txt")
	var runErr error
	wc := &cobra.Command{}
	wc.SetContext(context.Background())
	stderr := captureStderr(t, func() {
		runErr = wrapCmd.RunE(wc, []string{"--", "/bin/sh", "-c", `env > "$0"; exit 3`, envOut})
	})

	var ece *exitCodeError
	if !asExitCodeError(runErr, &ece) || ece.code != 3 {
		t.Fatalf("wrapped exit code must survive a failed push: want exit 3, got %v", runErr)
	}
	if pushes.Load() != 1 {
		t.Fatalf("teardown should attempt exactly one push, got %d", pushes.Load())
	}
	if !strings.Contains(stderr, "NockLock: warning: chain anchor NOT pushed off-box:") {
		t.Fatalf("missing push warning on stderr:\n%s", stderr)
	}
	if strings.Contains(stderr, remoteTestToken) {
		t.Fatal("stderr leaks the token")
	}
	childEnv, err := os.ReadFile(envOut)
	if err != nil {
		t.Fatalf("child env dump: %v", err)
	}
	if !strings.Contains(string(childEnv), "NOCKLOCK_E2E_CONTROL=visible") {
		t.Fatal("control var missing: the child env dump is not trustworthy")
	}
	if strings.Contains(string(childEnv), anchorclient.EnvToken) || strings.Contains(string(childEnv), remoteTestToken) {
		t.Fatal("the wrapped child can see NOCKLOCK_ANCHOR_TOKEN")
	}
	if strings.Contains(string(childEnv), anchorclient.EnvURL) {
		t.Fatal("the wrapped child can see NOCKLOCK_ANCHOR_URL")
	}
	// The local anchor is still written before the (failed) push.
	if _, err := logging.ReadAnchor(filepath.Join(nockDir, "chain-anchor.json")); err != nil {
		t.Fatalf("teardown anchor file: %v", err)
	}
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr pipe: %v", err)
	}
	os.Stderr = w
	done := make(chan []byte)
	go func() {
		b, _ := io.ReadAll(r)
		done <- b
	}()
	func() {
		defer func() { os.Stderr = orig }()
		fn()
	}()
	w.Close()
	out := <-done
	r.Close()
	return string(out)
}
