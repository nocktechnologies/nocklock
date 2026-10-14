//go:build linux || darwin

package logging

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRetainedRegistrationRequestBlocksPruneAndRetries(t *testing.T) {
	for _, failure := range []string{"request_directory_sync", "pending_file_sync"} {
		t.Run(failure, func(t *testing.T) {
			f := newIdentityFixture(t)
			identityOldEvent(t, f.logger)
			initial := *initIdentity(t, f)
			injected := errors.New("registration durability fault")
			fileSyncs := 0
			failed := false
			f.logger.identitySync = func(file *os.File) error {
				info, err := file.Stat()
				if err != nil {
					return err
				}
				if !info.IsDir() {
					fileSyncs++
				}
				if !failed && ((failure == "request_directory_sync" && info.IsDir()) || (failure == "pending_file_sync" && !info.IsDir() && fileSyncs == 2)) {
					failed = true
					return injected
				}
				return file.Sync()
			}
			sends := 0
			send := func(req AnchorRegistrationRequest) (*AnchorV2, error) { sends++; return req.Anchor, nil }
			_, err := f.logger.RegisterAnchorV2("fresh", nil, send)
			if !errors.Is(err, injected) || !failed || sends != 0 {
				t.Fatalf("wrong fault: %v failed=%v sends=%d", err, failed, sends)
			}
			f.logger.identitySync = nil
			path := filepath.Join(filepath.Dir(f.record), AnchorRegistrationFileName)
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			id, err := f.logger.ReadChainIdentity()
			if err != nil || *id != initial {
				t.Fatalf("not retained request+none: %+v %v", id, err)
			}
			assertIdentityPruneRefused(t, f.logger, "retained original anchor registration request")
			current, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(original, current) {
				t.Fatalf("prune changed request: %v", err)
			}
			id, err = f.logger.ReadChainIdentity()
			if err != nil || *id != initial {
				t.Fatalf("prune changed identity: %+v %v", id, err)
			}
			id, err = f.logger.RegisterAnchorV2("fresh", nil, func(req AnchorRegistrationRequest) (*AnchorV2, error) {
				current, e := os.ReadFile(path)
				if e != nil || !bytes.Equal(original, current) || req.Anchor.RowCount != 1 {
					t.Fatalf("retry changed original: %v %+v", e, req)
				}
				return send(req)
			})
			if err != nil || id.RegistrationState != ChainRegistrationEnrolled || sends != 1 {
				t.Fatalf("exact retry failed: %+v %v sends=%d", id, err, sends)
			}
		})
	}
}

func TestPruneRefusesUnusableRetainedRequest(t *testing.T) {
	for _, kind := range []string{"empty", "malformed", "oversized", "symlink", "directory"} {
		t.Run(kind, func(t *testing.T) {
			f := newIdentityFixture(t)
			identityOldEvent(t, f.logger)
			initIdentity(t, f)
			path := filepath.Join(filepath.Dir(f.record), AnchorRegistrationFileName)
			var err error
			switch kind {
			case "empty":
				err = os.WriteFile(path, nil, 0600)
			case "malformed":
				err = os.WriteFile(path, []byte("not JSON"), 0600)
			case "oversized":
				err = os.WriteFile(path, bytes.Repeat([]byte("x"), 16385), 0600)
			case "symlink":
				err = os.Symlink(filepath.Join(t.TempDir(), "absent"), path)
			case "directory":
				err = os.Mkdir(path, 0700)
			}
			if err != nil {
				t.Fatal(err)
			}
			before, err := f.logger.Stats("")
			if err != nil {
				t.Fatal(err)
			}
			if n, err := f.logger.Prune(24 * time.Hour); err == nil || n != 0 {
				t.Fatalf("unusable request allowed prune: %d %v", n, err)
			}
			after, err := f.logger.Stats("")
			if err != nil || after.TotalEvents != before.TotalEvents {
				t.Fatalf("refusal changed rows: %+v %v", after, err)
			}
		})
	}
}

func TestRegisterChainIdentityRequiresSigner(t *testing.T) {
	f := newIdentityFixture(t)
	initial := *initIdentity(t, f)
	reader, err := NewLogger(f.db, f.project)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	calls := 0
	confirm := func(id ChainIdentity) (*ChainRegistrationConfirmation, error) {
		calls++
		return &ChainRegistrationConfirmation{AgentID: id.AgentID, ChainID: id.ChainID}, nil
	}
	if _, err := reader.RegisterChainIdentity(confirm); err == nil || !strings.Contains(err.Error(), "existing signing key") || calls != 0 {
		t.Fatalf("unsigned registration: %v calls=%d", err, calls)
	}
	id, err := f.logger.ReadChainIdentity()
	if err != nil || *id != initial {
		t.Fatalf("unsigned registration changed state: %+v %v", id, err)
	}
	id, err = f.logger.RegisterChainIdentity(confirm)
	if err != nil || id.RegistrationState != ChainRegistrationEnrolled || calls != 1 {
		t.Fatalf("signed control: %+v %v calls=%d", id, err, calls)
	}
}

func TestAnchorV2MissingKeyIsNotForgery(t *testing.T) {
	f := newIdentityFixture(t)
	identityOldEvent(t, f.logger)
	initIdentity(t, f)
	a, err := f.logger.EmitAnchorV2()
	if err != nil {
		t.Fatal(err)
	}
	result, err := f.logger.VerifyAgainstAnchorV2(a, nil)
	if err != nil || result.OK || result.Classification != "no_key" || !strings.Contains(result.Reason, "--ed25519-pub") {
		t.Fatalf("missing key: %+v %v", result, err)
	}
	result, err = f.logger.VerifyAgainstAnchorV2(a, f.logger.SigningPublicKey())
	if err != nil || !result.OK {
		t.Fatalf("valid key: %+v %v", result, err)
	}
}

func TestExistingSigningRejectsWrongKeyBeforeMutation(t *testing.T) {
	f := newIdentityFixture(t)
	identityOldEvent(t, f.logger)
	f.logger.Close()
	wrong := filepath.Join(t.TempDir(), "keys", "wrong.key")
	if _, err := loadOrCreateSigner(wrong); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(f.db)
	if err != nil {
		t.Fatal(err)
	}
	if l, err := NewLogger(f.db, f.project, WithExistingSigning(wrong)); err == nil {
		l.Close()
		t.Fatal("existing-only open accepted mismatched key")
	} else if !strings.Contains(err.Error(), "does not match the adopted public key fingerprint") {
		t.Fatal(err)
	}
	after, err := os.ReadFile(f.db)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("wrong-key refusal changed DB: %v", err)
	}
	l, err := NewLogger(f.db, f.project, WithExistingSigning(f.key))
	if err != nil {
		t.Fatal(err)
	}
	l.Close()
}

func TestExistingSigningRefusalDoesNotCreateOrMigrate(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		f := newIdentityFixture(t)
		path := filepath.Join(f.project, "absent", "events.db")
		if l, err := NewLogger(path, f.project, WithExistingSigning(f.key)); err == nil {
			l.Close()
			t.Fatal("absent DB accepted")
		}
		if _, err := os.Stat(filepath.Dir(path)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("existing-only open created missing directory/DB: %v", err)
		}
	})
	t.Run("stripped", func(t *testing.T) {
		f := newIdentityFixture(t)
		identityOldEvent(t, f.logger)
		if _, err := f.logger.db.Exec("DROP TABLE chain_identity; UPDATE events SET entry_sig=''; UPDATE chain_head SET signed_genesis_at=NULL, unsigned_through_id=NULL, signing_pubkey_fingerprint='', head_sig=''"); err != nil {
			t.Fatal(err)
		}
		f.logger.Close()
		if err := os.Chmod(f.db, 0640); err != nil {
			t.Fatal(err)
		}
		before, err := os.ReadFile(f.db)
		if err != nil {
			t.Fatal(err)
		}
		if l, err := NewLogger(f.db, f.project, WithExistingSigning(f.key)); err == nil {
			l.Close()
			t.Fatal("stripped DB accepted")
		}
		after, err := os.ReadFile(f.db)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatalf("refusal migrated or wrote stripped DB: %v", err)
		}
		info, err := os.Stat(f.db)
		if err != nil || info.Mode().Perm() != 0640 {
			t.Fatalf("refusal changed permissions: %v %v", info, err)
		}
		// Normal wrap adoption is intentionally still supported.
		normal, err := NewLogger(f.db, f.project, WithSigning(f.key))
		if err != nil {
			t.Fatal(err)
		}
		defer normal.Close()
		adopted, err := signingAlreadyAdopted(normal.db)
		if err != nil || !adopted {
			t.Fatalf("normal adoption failed: %v %v", adopted, err)
		}
	})
}

func TestExistingSigningReadsLiveWALAndOlderSignedDB(t *testing.T) {
	f := newIdentityFixture(t)
	if _, err := f.logger.db.Exec("DROP TABLE chain_identity; PRAGMA wal_autocheckpoint=0; PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
		t.Fatal(err)
	}
	base, err := os.ReadFile(f.db)
	if err != nil {
		t.Fatal(err)
	}
	identityOldEvent(t, f.logger)
	current, err := os.ReadFile(f.db)
	if err != nil || !bytes.Equal(base, current) {
		t.Fatalf("fixture checkpointed instead of retaining live WAL: %v", err)
	}
	wal, err := os.Stat(f.db + "-wal")
	if err != nil || wal.Size() == 0 {
		t.Fatalf("live WAL absent: %v %v", wal, err)
	}
	strict, err := NewLogger(f.db, f.project, WithExistingSigning(f.key))
	if err != nil {
		t.Fatal(err)
	}
	result, err := strict.VerifyChainSigned(strict.SigningPublicKey(), true)
	if err != nil || !result.Intact || result.SigState != "authentic" || result.EntriesVerified != 1 {
		t.Fatalf("live WAL row ignored: %+v %v", result, err)
	}
	if _, err := strict.readChainIdentityMirror(); err != nil {
		t.Fatalf("valid pre-v2 signed DB was not supported: %v", err)
	}
	strict.Close()
	if _, err := f.logger.db.Exec("UPDATE events SET entry_sig=''; UPDATE chain_head SET signed_genesis_at=NULL, unsigned_through_id=NULL, signing_pubkey_fingerprint='', head_sig=''"); err != nil {
		t.Fatal(err)
	}
	if l, err := NewLogger(f.db, f.project, WithExistingSigning(f.key)); err == nil {
		l.Close()
		t.Fatal("existing-only open ignored stripped live WAL")
	}
}

func TestLegacyPruneUnsupportedPlatformRequestCheck(t *testing.T) {
	f := newIdentityFixture(t)
	if err := f.logger.allowLegacyPruneWithoutIdentity(); err != nil {
		t.Fatalf("no-request legacy control: %v", err)
	}
	path := filepath.Join(filepath.Dir(f.record), AnchorRegistrationFileName)
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("retained request"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := f.logger.allowLegacyPruneWithoutIdentity(); err == nil || !strings.Contains(err.Error(), "retained original anchor registration request") {
		t.Fatalf("unsupported-platform branch accepted request: %v", err)
	}
}
