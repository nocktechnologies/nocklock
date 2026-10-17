package anchorclient

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/logging"
)

func v2Fixture(t *testing.T) (*logging.AnchorV2, ed25519.PublicKey) {
	t.Helper()
	return v2FixtureLegacy(t, strings.Repeat("0", 64))
}

func v2FixtureLegacy(t *testing.T, legacy string) (*logging.AnchorV2, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	a := &logging.AnchorV2{Version: 2, AgentID: logging.PublicKeyFingerprint(pub), ChainID: strings.Repeat("a", 64),
		HeadHash: strings.Repeat("b", 64), RowCount: 3, CreatedAt: "2026-10-14T00:00:00Z", LegacyAnchorDigest: legacy}
	cb, err := logging.AnchorV2CanonicalBytes(a)
	if err != nil {
		t.Fatal(err)
	}
	a.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, cb))
	return a, pub
}

func v2Reply(t *testing.T, a *logging.AnchorV2, pub ed25519.PublicKey, code string) map[string]any {
	t.Helper()
	digest, err := logging.AnchorV2SnapshotDigest(a, pub, a.AgentID, a.ChainID)
	if err != nil {
		t.Fatal(err)
	}
	return map[string]any{"success": code != "already_exists", "data": map[string]any{"code": code, "anchor": a,
		"agent_id": a.AgentID, "chain_id": a.ChainID, "legacy_anchor_digest": a.LegacyAnchorDigest,
		"snapshot_digest": digest, "registration_digest": digest}}
}

func TestV2FetchAuthenticatesExpectedPairWithoutDowngrade(t *testing.T) {
	a, pub := v2Fixture(t)
	for _, tc := range []struct {
		name   string
		status int
		alter  bool
	}{
		{"valid", 200, false}, {"swapped", 200, true}, {"missing", 404, false}, {"unsupported", 405, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/api/nocklock/anchors/v2/"+a.AgentID+"/"+a.ChainID+"/latest/" {
					t.Errorf("unexpected route %s", r.URL.Path)
				}
				if r.Header.Get("Authorization") != "Bearer private-token" {
					t.Error("missing auth")
				}
				w.WriteHeader(tc.status)
				copy := *a
				if tc.alter {
					copy.ChainID = strings.Repeat("c", 64)
				}
				_ = json.NewEncoder(w).Encode(copy)
			}))
			defer s.Close()
			got, err := FetchLatestV2(context.Background(), s.URL, "private-token", a.AgentID, a.ChainID, pub)
			if tc.name == "valid" {
				if err != nil || got.ChainID != a.ChainID {
					t.Fatalf("fetch: %v %v", got, err)
				}
			} else if err == nil {
				t.Fatal("invalid remote accepted")
			}
			if calls != 1 {
				t.Fatalf("requests=%d; no fallback permitted", calls)
			}
		})
	}
}

func TestV2RegisterRequiresAuthenticatedExactRetry(t *testing.T) {
	a, pub := v2Fixture(t)
	for _, tc := range []struct {
		name    string
		status  int
		code    string
		corrupt bool
	}{
		{"created", 201, "registered", false}, {"exact_retry", 409, "already_exists", false},
		{"other_claim", 409, "registration_conflict", false}, {"lying_digest", 409, "already_exists", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reply := v2Reply(t, a, pub, tc.code)
			if tc.corrupt {
				reply["data"].(map[string]any)["registration_digest"] = strings.Repeat("d", 64)
			}
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/nocklock/anchors/v2/register/" {
					t.Errorf("route %s", r.URL.Path)
				}
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				if body["mode"] != "fresh" || len(body) != 3 {
					t.Errorf("body: %v", body)
				}
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(reply)
			}))
			defer s.Close()
			_, err := RegisterV2(context.Background(), s.URL, "", a, pub, false)
			if (tc.name == "created" || tc.name == "exact_retry") != (err == nil) {
				t.Fatalf("register: %v", err)
			}
		})
	}
}

func TestV2PushChecksInputAndAuthenticatedResponse(t *testing.T) {
	a, pub := v2Fixture(t)
	for _, tc := range []struct {
		name     string
		previous string
		status   int
		forged   bool
	}{
		{"stored", strings.Repeat("c", 64), 201, false}, {"conflict", strings.Repeat("c", 64), 409, false},
		{"invalid_precondition", "", 201, false}, {"forged_reply", strings.Repeat("c", 64), 201, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			reply := v2Reply(t, a, pub, "stored")
			if tc.forged {
				copy := *a
				copy.HeadHash = strings.Repeat("d", 64)
				reply["data"].(map[string]any)["anchor"] = &copy
			}
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/api/nocklock/anchors/v2/" {
					t.Errorf("route %s", r.URL.Path)
				}
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				if body["expected_previous"] != tc.previous || len(body) != 3 {
					t.Errorf("body %v", body)
				}
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(reply)
			}))
			defer s.Close()
			_, err := PushV2(context.Background(), s.URL, "private-token", a, pub, tc.previous)
			if (tc.name == "stored") != (err == nil) {
				t.Fatalf("push: %v", err)
			}
			if tc.name == "invalid_precondition" && calls != 0 {
				t.Fatal("invalid CAS reached server")
			}
			if tc.name == "conflict" && !errors.Is(err, ErrAnchorConflict) {
				t.Fatalf("missing conflict classification: %v", err)
			}
		})
	}
}

func TestV2LegacyAbsenceRequiresUpgradedStoreResponse(t *testing.T) {
	a, pub := v2Fixture(t)
	for _, tc := range []struct {
		body   string
		absent bool
	}{
		{`{"success":false,"data":{"code":"legacy_missing"}}`, true},
		{"404 page not found", false},
		{`{"success":false,"data":{"code":"not_registered"}}`, false},
	} {
		s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/api/nocklock/anchors/v2/"+a.AgentID+"/legacy/" {
				t.Errorf("wrong legacy route: %s", r.URL.Path)
			}
			w.WriteHeader(404)
			_, _ = w.Write([]byte(tc.body))
		}))
		_, err := FetchLegacyForMigration(context.Background(), s.URL, "", a.AgentID, pub)
		s.Close()
		if err == nil || errors.Is(err, ErrNoLegacyHistory) != tc.absent {
			t.Fatalf("body %q: %v", tc.body, err)
		}
	}
}

func TestV2NeverReplaysBearerOnRedirect(t *testing.T) {
	a, pub := v2Fixture(t)
	reached := false
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true; t.Error("followed redirect") }))
	defer target.Close()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, target.URL, 307) }))
	defer s.Close()
	_, err := FetchLatestV2(context.Background(), s.URL, "private-token", a.AgentID, a.ChainID, pub)
	if err == nil || reached || strings.Contains(err.Error(), "private-token") {
		t.Fatalf("redirect result: %v reached=%v", err, reached)
	}
}

func TestV2ConflictRedactsEchoedToken(t *testing.T) {
	a, pub := v2Fixture(t)
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(409)
		_, _ = w.Write([]byte("echo private-token"))
	}))
	defer s.Close()
	_, err := PushV2(context.Background(), s.URL, "private-token", a, pub, strings.Repeat("c", 64))
	if err == nil || strings.Contains(err.Error(), "private-token") || !errors.Is(err, ErrAnchorConflict) {
		t.Fatalf("conflict result: %v", err)
	}
}

func TestV2MigrationAuthenticatesOriginalWitnessAndRetry(t *testing.T) {
	legacy := strings.Repeat("e", 64)
	a, pub := v2FixtureLegacy(t, legacy)
	for _, tc := range []struct {
		name, expected, code string
		status               int
		ok                   bool
	}{
		{"created", legacy, "registered", 201, true},
		{"exact_retry", legacy, "already_migrated", 200, true},
		{"legacy_changed", legacy, "legacy_changed", 409, false},
		{"wrong_witness", strings.Repeat("f", 64), "registered", 201, false},
		{"zero_witness", strings.Repeat("0", 64), "registered", 201, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			reply := v2Reply(t, a, pub, tc.code)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				if r.URL.Path != "/api/nocklock/anchors/v2/migrate/" {
					t.Errorf("route %s", r.URL.Path)
				}
				var body map[string]any
				_ = json.NewDecoder(r.Body).Decode(&body)
				if body["expected_legacy"] != legacy || len(body) != 3 {
					t.Errorf("body %v", body)
				}
				w.WriteHeader(tc.status)
				_ = json.NewEncoder(w).Encode(reply)
			}))
			defer server.Close()
			_, err := MigrateV2(context.Background(), server.URL, "private-token", a, pub, tc.expected)
			if (err == nil) != tc.ok {
				t.Fatalf("migration: %v", err)
			}
			if tc.expected != legacy && calls != 0 {
				t.Fatal("mismatched witness reached server")
			}
		})
	}
}

func TestV2RegisterAcknowledgmentIsExplicit(t *testing.T) {
	a, pub := v2Fixture(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["mode"] != "acknowledge_no_legacy_history" {
			t.Errorf("mode %v", body["mode"])
		}
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(v2Reply(t, a, pub, "registered"))
	}))
	defer server.Close()
	if _, err := RegisterV2(context.Background(), server.URL, "", a, pub, true); err != nil {
		t.Fatal(err)
	}
}

func TestV2RegistrationConfirmationCannotRollBackOriginal(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sign := func(a *logging.AnchorV2) {
		cb, err := logging.AnchorV2CanonicalBytes(a)
		if err != nil {
			t.Fatal(err)
		}
		a.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, cb))
	}
	original, _ := v2Fixture(t)
	original.AgentID = logging.PublicKeyFingerprint(pub)
	sign(original)
	originalDigest, err := logging.AnchorV2SnapshotDigest(original, pub, original.AgentID, original.ChainID)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		count uint64
		head  string
		ok    bool
	}{
		{"older_signed_latest", 2, original.HeadHash, false},
		{"same_height_other_head", 3, strings.Repeat("d", 64), false},
		{"advanced_signed_latest", 4, strings.Repeat("e", 64), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			stored := *original
			stored.RowCount = tc.count
			stored.HeadHash = tc.head
			sign(&stored)
			reply := v2Reply(t, &stored, pub, "already_exists")
			reply["data"].(map[string]any)["registration_digest"] = originalDigest
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(409)
				_ = json.NewEncoder(w).Encode(reply)
			}))
			defer server.Close()
			_, err := RegisterV2(context.Background(), server.URL, "", original, pub, false)
			if (err == nil) != tc.ok {
				t.Fatalf("confirmation: %v", err)
			}
		})
	}
}

func TestV2MalformedSuccessRedactsBearer(t *testing.T) {
	// Migrate first: a shared fixture would leave a nonzero legacy digest and
	// make fresh registration fail locally without testing response redaction.
	for _, operation := range []string{"migrate", "fetch", "register", "push"} {
		t.Run(operation, func(t *testing.T) {
			legacy := strings.Repeat("0", 64)
			if operation == "migrate" {
				legacy = strings.Repeat("e", 64)
			}
			a, pub := v2FixtureLegacy(t, legacy)
			token := "review-secret-token"
			method, path, status := http.MethodPost, "/api/nocklock/anchors/v2/", http.StatusCreated
			code := "stored"
			if operation == "register" || operation == "migrate" {
				path += operation + "/"
				code = "registered"
			}
			reply := v2Reply(t, a, pub, code)
			reply["data"].(map[string]any)["anchor"] = map[string]any{token: "echo"}
			if operation == "fetch" {
				method, path, status = http.MethodGet, path+a.AgentID+"/"+a.ChainID+"/latest/", http.StatusOK
				reply = map[string]any{token: "echo"}
			}
			var calls atomic.Int32
			s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if r.Method != method || r.URL.Path != path {
					t.Errorf("malformed-response request = %s %s, want %s %s", r.Method, r.URL.Path, method, path)
				}
				if r.Header.Get("Authorization") != "Bearer "+token {
					t.Error("malformed-response request missing bearer authentication")
				}
				w.WriteHeader(status)
				_ = json.NewEncoder(w).Encode(reply)
			}))
			defer s.Close()
			var err error
			switch operation {
			case "fetch":
				_, err = FetchLatestV2(context.Background(), s.URL, token, a.AgentID, a.ChainID, pub)
			case "register":
				_, err = RegisterV2(context.Background(), s.URL, token, a, pub, false)
			case "push":
				_, err = PushV2(context.Background(), s.URL, token, a, pub, strings.Repeat("c", 64))
			case "migrate":
				_, err = MigrateV2(context.Background(), s.URL, token, a, pub, a.LegacyAnchorDigest)
			}
			if calls.Load() != 1 {
				t.Fatalf("malformed-response case did not reach its HTTP handler exactly once: requests=%d error=%v", calls.Load(), err)
			}
			prefix := "anchor v2: invalid stored anchor: "
			if operation == "fetch" {
				prefix = "invalid remote v2 anchor: "
			}
			if err == nil || !strings.HasPrefix(err.Error(), prefix) {
				t.Fatalf("expected malformed response error from HTTP, got %v", err)
			}
			if strings.Contains(err.Error(), token) {
				t.Fatalf("bearer leaked in error: %v", err)
			}
		})
	}
}
