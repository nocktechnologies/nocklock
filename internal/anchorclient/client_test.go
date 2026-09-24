package anchorclient

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

const testToken = "tok-SENTINEL-do-not-leak-4f1c"

// signedAnchor returns a genuine signed anchor and the key it was signed with.
func signedAnchor(t *testing.T) (*logging.Anchor, ed25519.PublicKey) {
	t.Helper()
	dir := t.TempDir()
	l, err := logging.NewLogger(filepath.Join(dir, "events.db"), "", logging.WithSigning(filepath.Join(dir, "state", "signing")))
	if err != nil {
		t.Fatalf("logger: %v", err)
	}
	defer l.Close()
	if err := l.Log(logging.Event{EventType: logging.EventFileBlocked, Category: "filesystem", Detail: "/etc/shadow", Blocked: true, SessionID: "s"}); err != nil {
		t.Fatalf("log: %v", err)
	}
	a, err := l.EmitAnchor()
	if err != nil {
		t.Fatalf("emit: %v", err)
	}
	return a, l.SigningPublicKey()
}

func assertNoToken(t *testing.T, err error) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), testToken) {
		t.Fatalf("error string leaks the bearer token: %v", err)
	}
}

func TestPushSuccessSendsContractBody(t *testing.T) {
	a, pub := signedAnchor(t)
	var gotAuth, gotCT, gotPath, gotMethod string
	var gotBody map[string]json.RawMessage
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotCT = r.Header.Get("Content-Type")
		gotPath = r.URL.Path
		gotMethod = r.Method
		data, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(data, &gotBody); err != nil {
			t.Errorf("body is not JSON: %v", err)
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	if err := Push(context.Background(), srv.URL+"/", testToken, a, pub); err != nil {
		t.Fatalf("push: %v", err)
	}
	if gotMethod != http.MethodPost || gotPath != "/api/nocklock/anchors/" {
		t.Errorf("got %s %s, want POST /api/nocklock/anchors/", gotMethod, gotPath)
	}
	if gotAuth != "Bearer "+testToken {
		t.Errorf("Authorization header not the bearer token")
	}
	if gotCT != "application/json" {
		t.Errorf("Content-Type = %q", gotCT)
	}
	if len(gotBody) != 2 {
		t.Errorf("body must carry exactly anchor+pubkey, got keys %v", keys(gotBody))
	}
	var pk string
	if err := json.Unmarshal(gotBody["pubkey"], &pk); err != nil {
		t.Fatalf("pubkey field: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(pk)
	if err != nil || !ed25519.PublicKey(raw).Equal(pub) {
		t.Errorf("pubkey is not the std-base64 of the signing key")
	}
	want, _ := logging.MarshalAnchor(a)
	if string(gotBody["anchor"]) != string(want) {
		t.Errorf("anchor object altered in transit:\n got %s\nwant %s", gotBody["anchor"], want)
	}
}

func TestPushOmitsAuthHeaderWithoutToken(t *testing.T) {
	a, pub := signedAnchor(t)
	var sawAuth bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, sawAuth = r.Header["Authorization"]
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if err := Push(context.Background(), srv.URL, "", a, pub); err != nil {
		t.Fatalf("push: %v", err)
	}
	if sawAuth {
		t.Error("Authorization header sent with an empty token")
	}
}

func TestPush409IsRegression(t *testing.T) {
	a, pub := signedAnchor(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		// A server that echoes the token must not leak it through our error.
		io.WriteString(w, "row_count 1 regresses below stored 9 "+testToken+" "+strings.Repeat("x", 2000))
	}))
	defer srv.Close()
	err := Push(context.Background(), srv.URL, testToken, a, pub)
	if !errors.Is(err, ErrAnchorRegression) {
		t.Fatalf("409 must wrap ErrAnchorRegression, got %v", err)
	}
	if !strings.Contains(err.Error(), "regresses below stored 9") {
		t.Errorf("server body text missing: %v", err)
	}
	if len(err.Error()) > 700 {
		t.Errorf("server body not truncated to 512 bytes (error is %d bytes)", len(err.Error()))
	}
	assertNoToken(t, err)
}

func TestPush409RedactsTokenStraddlingTruncation(t *testing.T) {
	a, pub := signedAnchor(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		io.WriteString(w, strings.Repeat("x", maxErrorBodyBytes-len(testToken)+1)+testToken+strings.Repeat("x", 2000))
	}))
	defer srv.Close()
	err := Push(context.Background(), srv.URL, testToken, a, pub)
	if !errors.Is(err, ErrAnchorRegression) {
		t.Fatalf("409 must wrap ErrAnchorRegression, got %v", err)
	}
	if !strings.HasSuffix(err.Error(), "...(truncated)") {
		t.Errorf("server body must remain truncated, got %v", err)
	}
	if strings.Contains(err.Error(), testToken[:len(testToken)-1]) {
		t.Fatalf("error string leaks a truncated bearer token: %v", err)
	}
	assertNoToken(t, err)
}

func TestPush500IsError(t *testing.T) {
	a, pub := signedAnchor(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()
	err := Push(context.Background(), srv.URL, testToken, a, pub)
	if err == nil || errors.Is(err, ErrAnchorRegression) || !strings.Contains(err.Error(), "500") {
		t.Fatalf("500 must be a plain error carrying the status, got %v", err)
	}
	assertNoToken(t, err)
}

func TestPushHonorsContextTimeout(t *testing.T) {
	a, pub := signedAnchor(t)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		select {
		case <-r.Context().Done():
		case <-release:
		case <-time.After(5 * time.Second):
		}
	}))
	defer srv.Close()
	defer close(release)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err := Push(ctx, srv.URL, testToken, a, pub)
	if err == nil || !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("want deadline exceeded, got %v", err)
	}
	if time.Since(start) > 2*time.Second {
		t.Errorf("push did not honor the context deadline")
	}
	assertNoToken(t, err)
}

func TestPushDoesNotFollowRedirects(t *testing.T) {
	a, pub := signedAnchor(t)
	var followed bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { followed = true }))
	defer target.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	err := Push(context.Background(), srv.URL, testToken, a, pub)
	if err == nil || followed {
		t.Fatalf("redirect must be an error and never followed (err=%v followed=%v)", err, followed)
	}
}

func TestValidateBaseURL(t *testing.T) {
	ok := []string{
		"https://ncc.example.com",
		"https://ncc.example.com/prefix/",
		"http://127.0.0.1:8080",
		"http://localhost:9",
		"http://[::1]:9",
	}
	for _, u := range ok {
		if _, err := ValidateBaseURL(u); err != nil {
			t.Errorf("%q should be accepted: %v", u, err)
		}
	}
	bad := []string{
		"",
		"http://ncc.example.com",
		"http://10.0.0.5",
		"http://127.0.0.1.example.com",
		"ftp://ncc.example.com",
		"ncc.example.com",
		"https://user:pw@ncc.example.com",
		"https://ncc.example.com/?x=1",
		"https:///nohost",
	}
	for _, u := range bad {
		if _, err := ValidateBaseURL(u); err == nil {
			t.Errorf("%q should be rejected", u)
		}
	}
}

func TestPushRejectsNonLoopbackHTTP(t *testing.T) {
	a, pub := signedAnchor(t)
	err := Push(context.Background(), "http://ncc.example.com", testToken, a, pub)
	if err == nil || !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("non-loopback http must be rejected before any request, got %v", err)
	}
}

func TestFetchLatest(t *testing.T) {
	a, _ := signedAnchor(t)
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath, gotAuth = r.URL.Path, r.Header.Get("Authorization")
		data, _ := logging.MarshalAnchor(a)
		w.Write(data)
	}))
	defer srv.Close()
	got, err := FetchLatest(context.Background(), srv.URL, testToken, a.AgentID)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if gotPath != "/api/nocklock/anchors/"+a.AgentID+"/latest/" {
		t.Errorf("path = %s", gotPath)
	}
	if gotAuth != "Bearer "+testToken {
		t.Error("fetch did not send the bearer token")
	}
	if *got != *a {
		t.Errorf("fetched anchor differs:\n got %+v\nwant %+v", got, a)
	}
}

func TestFetchLatest404IsNoRemoteAnchor(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	_, err := FetchLatest(context.Background(), srv.URL, testToken, "abc")
	if !errors.Is(err, ErrNoRemoteAnchor) {
		t.Fatalf("404 must wrap ErrNoRemoteAnchor, got %v", err)
	}
	assertNoToken(t, err)
}

func TestFetchLatestCapsOversizedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"version":1,"agent_id":"`+strings.Repeat("a", 200<<10)+`"}`)
	}))
	defer srv.Close()
	_, err := FetchLatest(context.Background(), srv.URL, testToken, "abc")
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized body must be refused, got %v", err)
	}
}

func TestFetchLatestInvalidJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "not json")
	}))
	defer srv.Close()
	if _, err := FetchLatest(context.Background(), srv.URL, testToken, "abc"); err == nil {
		t.Fatal("invalid JSON must be an error")
	}
}

func keys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
