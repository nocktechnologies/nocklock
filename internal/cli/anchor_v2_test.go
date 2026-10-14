//go:build linux || darwin

package cli

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/anchorclient"
)

func TestAnchorEnrollmentDoesNotReadoptDatabaseStrippedDuringLegacyFetch(t *testing.T) {
	dbPath, key := setupAnchorProject(t)
	seedSignedChain(t, dbPath, key, 2)
	var posts atomic.Int32
	mutation := make(chan error, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/legacy/") {
			db, err := sql.Open("sqlite", dbPath)
			if err == nil {
				_, err = db.Exec("DELETE FROM events; UPDATE chain_head SET entry_hash=?, row_count=0, head_sig='', signed_genesis_at=NULL, unsigned_through_id=NULL, signing_pubkey_fingerprint=''", fmt.Sprintf("%x", sha256.Sum256(nil)))
				db.Close()
			}
			select {
			case mutation <- err:
			default:
				t.Error("legacy-fetch mutation result already queued: unexpected repeated fetch")
				http.Error(w, "duplicate legacy fetch", http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusNotFound)
			io.WriteString(w, `{"success":false,"data":{"code":"legacy_missing"}}`)
			return
		}
		posts.Add(1)
		http.Error(w, "unexpected registration", http.StatusBadRequest)
	}))
	defer srv.Close()
	t.Setenv(anchorclient.EnvURL, srv.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := runAnchorEnrollment(ctx, io.Discard, "fresh")
	select {
	case mutationErr := <-mutation:
		if mutationErr != nil {
			t.Fatalf("legacy-fetch database mutation failed: %v", mutationErr)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("legacy-fetch database mutation was not observed within 2s; enrollment returned: %v", err)
	}
	if err == nil || posts.Load() != 0 {
		t.Fatalf("stripped DB was adopted/sent: posts=%d error=%v", posts.Load(), err)
	}
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var genesis sql.NullString
	var sig string
	if err := db.QueryRow("SELECT signed_genesis_at, head_sig FROM chain_head WHERE id=1").Scan(&genesis, &sig); err != nil {
		t.Fatal(err)
	}
	if genesis.Valid || sig != "" {
		t.Fatal("enrollment re-signed the stripped database")
	}
}
