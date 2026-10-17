package cli

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/anchorclient"
	"github.com/nocktechnologies/nocklock/internal/logging"
)

func requireHistoryCoverage(t *testing.T, output, prefix string, err error, code int) {
	t.Helper()
	if strings.Count(output, "COVERAGE: LIMITED\n") != 1 {
		t.Fatalf("history verification must append exactly one limited-coverage block:\n%s", output)
	}
	if !strings.HasPrefix(output, prefix) {
		t.Fatalf("verification verdict changed: want prefix %q, got:\n%s", prefix, output)
	}
	for _, limit := range []string{"does not prove that every action was logged", "allowed file accesses", "file denials", "kernel-dropped packets", "proxy bypasses", "Linux CONFINED Unix-socket connections"} {
		if !strings.Contains(output, limit) {
			t.Errorf("missing recording limit %q:\n%s", limit, output)
		}
	}
	if !strings.HasSuffix(output, "This check does not establish past enforcement or recording coverage.\n") {
		t.Fatalf("coverage notice must finish the helper output:\n%s", output)
	}
	if code == 0 {
		if err != nil {
			t.Fatalf("success exit changed: %v", err)
		}
	} else {
		var exit *exitCodeError
		if !errors.As(err, &exit) || exit.code != code {
			t.Fatalf("want original exit %d, got %v", code, err)
		}
	}
}

func TestAuditVerificationCoveragePreservesVerdicts(t *testing.T) {
	for _, state := range []string{"authentic", "consistent", "tampered"} {
		t.Run(state, func(t *testing.T) {
			db, key := setupAnchorProject(t)
			if state == "consistent" {
				l, err := logging.NewLogger(db, "")
				if err != nil {
					t.Fatal(err)
				}
				if err := l.Log(logging.Event{EventType: logging.EventFileBlocked, Detail: "fixture"}); err != nil {
					t.Fatal(err)
				}
				l.Close()
			} else {
				seedSignedChain(t, db, key, 3)
			}
			code := 0
			if state == "tampered" {
				raw, err := sql.Open("sqlite", db)
				if err != nil {
					t.Fatal(err)
				}
				defer raw.Close()
				if _, err := raw.Exec("UPDATE events SET detail='altered' WHERE id=1"); err != nil {
					t.Fatal(err)
				}
				code = 1
			}
			var out bytes.Buffer
			err := runAuditVerify(context.Background(), &out, "", false)
			requireHistoryCoverage(t, out.String(), "AUDIT: "+strings.ToUpper(state), err, code)
		})
	}
}

func TestLocalAnchorVerificationCoverageV1AndV2(t *testing.T) {
	for _, version := range []string{"v1", "v2"} {
		for _, state := range []string{"ok", "forged", "truncation"} {
			t.Run(version+"/"+state, func(t *testing.T) {
				db, key := setupAnchorProject(t)
				seedSignedChain(t, db, key, 3)
				path := filepath.Join(t.TempDir(), "anchor.json")
				var err error
				if version == "v1" {
					a := emitAnchorNow(t, db, key)
					if state == "forged" {
						a.Sig = base64.StdEncoding.EncodeToString(make([]byte, 64))
					}
					err = logging.WriteAnchor(path, a)
				} else {
					a := emitRemoteAnchorNow(t, db, key)
					if state == "forged" {
						a.Sig = base64.StdEncoding.EncodeToString(make([]byte, 64))
					}
					err = logging.WriteAnchorV2(path, a)
				}
				if err != nil {
					t.Fatal(err)
				}
				if state == "truncation" {
					truncateTo(t, db, 1)
				}
				code := 0
				if state != "ok" {
					code = 1
				}
				var out bytes.Buffer
				err = runVerifyAgainstAnchor(context.Background(), &out, path, "")
				requireHistoryCoverage(t, out.String(), "ANCHOR: "+strings.ToUpper(state), err, code)
			})
		}
	}
}

func TestRemoteAnchorVerificationCoveragePreservesVerdicts(t *testing.T) {
	for _, state := range []string{"ok", "forged", "missing", "truncation", "no_url", "no_key"} {
		t.Run(state, func(t *testing.T) {
			db, key := setupAnchorProject(t)
			seedSignedChain(t, db, key, 3)
			a := emitRemoteAnchorNow(t, db, key)
			if state == "forged" {
				a.Sig = base64.StdEncoding.EncodeToString(make([]byte, 64))
			}
			if state == "truncation" {
				truncateTo(t, db, 1)
			}
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != "/api/nocklock/anchors/v2/"+a.AgentID+"/"+a.ChainID+"/latest/" {
					t.Errorf("unexpected remote verification request: %s %s", r.Method, r.URL.Path)
				}
				if state == "missing" {
					http.NotFound(w, r)
					return
				}
				_ = json.NewEncoder(w).Encode(a)
			}))
			defer srv.Close()
			t.Setenv(anchorclient.EnvURL, srv.URL)
			t.Setenv(anchorclient.EnvToken, remoteTestToken)
			if state == "no_url" {
				t.Setenv(anchorclient.EnvURL, "")
			}
			if state == "no_key" {
				if err := os.Remove(key); err != nil {
					t.Fatal(err)
				}
			}
			prefix, code := "ANCHOR: UNAVAILABLE", 1
			switch state {
			case "ok":
				prefix, code = "ANCHOR: OK", 0
			case "truncation":
				prefix = "ANCHOR: TRUNCATION"
			case "no_key":
				prefix = "ANCHOR: FAILED"
			}
			var out bytes.Buffer
			err := runVerifyAgainstRemoteAnchor(context.Background(), &out, "")
			requireHistoryCoverage(t, out.String(), prefix, err, code)
			wantHits := int32(1)
			if state == "no_url" || state == "no_key" {
				wantHits = 0
			}
			if hits.Load() != wantHits {
				t.Fatalf("remote requests=%d, want %d", hits.Load(), wantHits)
			}
		})
	}
}

func TestHistoryVerificationCoverageOnEarlyErrors(t *testing.T) {
	for _, mode := range []string{"audit", "local", "remote"} {
		for _, failure := range []string{"missing_db", "invalid_key"} {
			t.Run(mode+"/"+failure, func(t *testing.T) {
				db, key := setupAnchorProject(t)
				path := filepath.Join(t.TempDir(), "anchor.json")
				pub := ""
				want := "event log not found"
				if failure == "invalid_key" {
					seedSignedChain(t, db, key, 1)
					if err := logging.WriteAnchor(path, emitAnchorNow(t, db, key)); err != nil {
						t.Fatal(err)
					}
					pub, want = "invalid-public-key", "invalid --ed25519-pub"
				}
				var out bytes.Buffer
				var err error
				switch mode {
				case "audit":
					err = runAuditVerify(context.Background(), &out, pub, false)
				case "local":
					err = runVerifyAgainstAnchor(context.Background(), &out, path, pub)
				case "remote":
					err = runVerifyAgainstRemoteAnchor(context.Background(), &out, pub)
				}
				var exit *exitCodeError
				if err == nil || !strings.Contains(err.Error(), want) || errors.As(err, &exit) {
					t.Fatalf("original operational error changed: %v", err)
				}
				// Operational failures still return their original error to Cobra;
				// they do not gain a fabricated audit/anchor verdict.
				requireHistoryCoverage(t, out.String(), "COVERAGE: LIMITED\n", nil, 0)
			})
		}
	}
}

func TestCoverageNoticeDoesNotChangeOtherOutput(t *testing.T) {
	db, key := setupAnchorProject(t)
	seedSignedChain(t, db, key, 1)
	var out bytes.Buffer
	if err := runExportPubkey(&out); err != nil {
		t.Fatal(err)
	}
	if _, err := logging.ParsePublicKey(strings.TrimSpace(out.String())); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := runAnchorEmit(context.Background(), &out, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := logging.UnmarshalAnchor(out.Bytes()); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	// Enrollment shares this renderer; it must not acquire the public verify notice.
	if err := writeAnchorV2VerifyResult(&out, &logging.AnchorV2VerifyResult{OK: true, Classification: "ok"}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "COVERAGE:") {
		t.Fatal("enrollment result renderer gained verification coverage output")
	}
	out.Reset()
	renderVerifyHuman(&out, verifyReport{})
	if strings.Contains(out.String(), "COVERAGE:") {
		t.Fatal("live-probe output gained history coverage output")
	}
	out.Reset()
	if err := renderVerifyJSON(&out, verifyReport{}); err != nil {
		t.Fatal(err)
	}
	if !json.Valid(out.Bytes()) || strings.Contains(out.String(), "COVERAGE:") {
		t.Fatal("live-probe JSON contract changed")
	}
}
