//go:build linux || darwin

package logging

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func signV2Fixture(t *testing.T, l *Logger, a *AnchorV2) {
	t.Helper()
	data, err := AnchorV2CanonicalBytes(a)
	if err != nil {
		t.Fatal(err)
	}
	a.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(l.signer.priv, data))
}

func TestAnchorV2LifecycleEmissionAndUnsignedCounts(t *testing.T) {
	f := newIdentityFixture(t)
	identityOldEvent(t, f.logger)
	if _, err := f.logger.EmitAnchorV2(); !errors.Is(err, ErrChainIdentityMissing) {
		t.Fatalf("emission minted identity: %v", err)
	}
	id := initIdentity(t, f)
	a, err := f.logger.EmitAnchorV2()
	if err != nil {
		t.Fatal(err)
	}
	if a.RowCount != 1 || a.ChainID != id.ChainID {
		t.Fatalf("incorrect snapshot: %+v", a)
	}
	if legacy, err := f.logger.EmitAnchor(); err != nil || legacy.Version != 1 {
		t.Fatalf("library v1 emitter changed: %+v %v", legacy, err)
	}
	identityOldEvent(t, f.logger)
	result, err := f.logger.VerifyAgainstAnchorV2(a, f.logger.SigningPublicKey())
	if err != nil || !result.OK || result.LocalRowCount != 2 {
		t.Fatalf("allowed grown prefix: %+v %v", result, err)
	}
	for _, tc := range []struct {
		name   string
		change func(*AnchorV2)
		resign bool
		want   string
	}{
		{"forged_chain_id", func(a *AnchorV2) { a.ChainID = strings.Repeat("1", 64) }, false, "forged"},
		{"signed_wrong_pair", func(a *AnchorV2) { a.ChainID = strings.Repeat("1", 64); a.RowCount = 50 }, true, "identity_mismatch"},
		{"changed_witness", func(a *AnchorV2) { a.LegacyAnchorDigest = strings.Repeat("2", 64) }, true, "identity_mismatch"},
		{"full_uint64", func(a *AnchorV2) { a.RowCount = math.MaxUint64 }, true, "truncation"},
		{"wrong_prefix", func(a *AnchorV2) { a.HeadHash = strings.Repeat("3", 64) }, true, "tampered"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := *a
			tc.change(&bad)
			if tc.resign {
				signV2Fixture(t, f.logger, &bad)
			}
			result, err := f.logger.VerifyAgainstAnchorV2(&bad, f.logger.SigningPublicKey())
			if err != nil || result.OK || result.Classification != tc.want || result.AnchorRowCount != bad.RowCount {
				t.Fatalf("wrong verdict: %+v %v", result, err)
			}
		})
	}
	if _, err := f.logger.db.Exec("UPDATE events SET entry_sig='' WHERE id=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.logger.EmitAnchorV2(); err == nil {
		t.Fatal("emitted an anchor over stripped row signature")
	}
	result, err = f.logger.VerifyAgainstAnchorV2(a, f.logger.SigningPublicKey())
	if err != nil || result.OK || result.Classification != "tampered" {
		t.Fatalf("stripped local chain accepted: %+v %v", result, err)
	}
}

func TestAnchorEmitNeverSignsUnverifiedDatabaseHead(t *testing.T) {
	f := newIdentityFixture(t)
	identityOldEvent(t, f.logger)
	initIdentity(t, f)
	if _, err := f.logger.EmitAnchor(); err != nil {
		t.Fatalf("allowed signed legacy control: %v", err)
	}
	if _, err := f.logger.db.Exec("UPDATE chain_head SET entry_hash=?", strings.Repeat("6", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.logger.EmitAnchor(); err == nil {
		t.Fatal("legacy emission signed an unverified head")
	}
	if _, err := f.logger.EmitAnchorV2(); err == nil {
		t.Fatal("v2 emission signed an unverified head")
	}
}

func TestAnchorV2RegistrationRetainsOriginalAfterLostResponse(t *testing.T) {
	f := newIdentityFixture(t)
	identityOldEvent(t, f.logger)
	initIdentity(t, f)
	path := filepath.Join(filepath.Dir(f.record), AnchorRegistrationFileName)
	var original []byte
	var err error
	_, err = f.logger.RegisterAnchorV2("fresh", nil, func(req AnchorRegistrationRequest) (*AnchorV2, error) {
		original, err = os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		record, err := os.ReadFile(f.record)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(record), `"registration_state":"pending"`) {
			t.Fatal("request sent before pending persisted")
		}
		var disk AnchorRegistrationRequest
		if err := json.Unmarshal(original, &disk); err != nil || *disk.Anchor != *req.Anchor || disk.Mode != req.Mode {
			t.Fatalf("request not durably exact: %v", err)
		}
		return nil, errors.New("response lost after server committed")
	})
	if err == nil {
		t.Fatal("lost response accepted")
	}
	assertIdentityPruneRefused(t, f.logger)
	identityOldEvent(t, f.logger)
	id, err := f.logger.RegisterAnchorV2("fresh", nil, func(req AnchorRegistrationRequest) (*AnchorV2, error) {
		var disk AnchorRegistrationRequest
		json.Unmarshal(original, &disk)
		if *disk.Anchor != *req.Anchor || req.Anchor.RowCount != 1 {
			t.Fatal("retry regenerated original signed request after local append")
		}
		return req.Anchor, nil
	})
	if err != nil || id.RegistrationState != ChainRegistrationEnrolled {
		t.Fatalf("exact retry: %+v %v", id, err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(original) {
		t.Fatal("retry rewrote original request")
	}
	assertIdentityPruneRefused(t, f.logger)
}

func TestAnchorV2RegistrationRejectsDamagedOriginalAndChangedMode(t *testing.T) {
	for _, name := range []string{"missing", "unknown_field", "bad_signature", "symlink", "hardlink", "changed_mode"} {
		t.Run(name, func(t *testing.T) {
			f := newIdentityFixture(t)
			identityOldEvent(t, f.logger)
			initIdentity(t, f)
			f.logger.RegisterAnchorV2("fresh", nil, func(AnchorRegistrationRequest) (*AnchorV2, error) { return nil, errors.New("lost") })
			path := filepath.Join(filepath.Dir(f.record), AnchorRegistrationFileName)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			mode := "fresh"
			switch name {
			case "missing":
				err = os.Remove(path)
			case "unknown_field":
				err = os.WriteFile(path, append([]byte(`{"unknown":true,`), data[1:]...), 0600)
			case "bad_signature":
				var req AnchorRegistrationRequest
				json.Unmarshal(data, &req)
				req.Anchor.Sig = base64.StdEncoding.EncodeToString(make([]byte, 64))
				data, _ = json.Marshal(req)
				err = os.WriteFile(path, data, 0600)
			case "symlink", "hardlink":
				target := filepath.Join(t.TempDir(), "request")
				if err = os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
				if name == "symlink" {
					err = os.Symlink(target, path)
				} else {
					err = os.Link(target, path)
				}
			case "changed_mode":
				mode = "acknowledge_no_legacy_history"
			}
			if err != nil {
				t.Fatal(err)
			}
			sent := false
			_, err = f.logger.RegisterAnchorV2(mode, nil, func(req AnchorRegistrationRequest) (*AnchorV2, error) { sent = true; return req.Anchor, nil })
			if err == nil || sent {
				t.Fatalf("damaged request sent: %v", err)
			}
			assertIdentityPruneRefused(t, f.logger)
		})
	}
}

func TestAnchorV2RegistrationChecksPrefixesAndConfirmation(t *testing.T) {
	for _, name := range []string{"local_tamper", "wrong_pair", "wrong_head", "older", "nil"} {
		t.Run(name, func(t *testing.T) {
			f := newIdentityFixture(t)
			identityOldEvent(t, f.logger)
			initIdentity(t, f)
			if name == "local_tamper" {
				if _, err := f.logger.db.Exec("UPDATE events SET detail='changed'"); err != nil {
					t.Fatal(err)
				}
			}
			sent := false
			_, err := f.logger.RegisterAnchorV2("fresh", nil, func(req AnchorRegistrationRequest) (*AnchorV2, error) {
				sent = true
				bad := *req.Anchor
				switch name {
				case "wrong_pair":
					bad.ChainID = strings.Repeat("4", 64)
				case "wrong_head":
					bad.HeadHash = strings.Repeat("5", 64)
				case "older":
					bad.RowCount = 0
					bad.HeadHash = chainGenesisHashHex
				case "nil":
					return nil, nil
				}
				signV2Fixture(t, f.logger, &bad)
				return &bad, nil
			})
			if err == nil {
				t.Fatal("invalid state accepted")
			}
			id, readErr := f.logger.ReadChainIdentity()
			if readErr != nil {
				t.Fatal(readErr)
			}
			if name == "local_tamper" {
				if sent || id.RegistrationState != ChainRegistrationNone {
					t.Fatal("tampered preflight sent registration")
				}
			} else {
				if !sent || id.RegistrationState != ChainRegistrationPending {
					t.Fatal("invalid confirmation cleared pending")
				}
			}
		})
	}
}

func TestAnchorV2MigrationChecksImmutableLegacyWitness(t *testing.T) {
	f := newIdentityFixture(t)
	identityOldEvent(t, f.logger)
	legacy, err := f.logger.EmitAnchor()
	if err != nil {
		t.Fatal(err)
	}
	digest, err := LegacyAnchorSnapshotDigest(legacy, f.logger.SigningPublicKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.logger.InitializeChainIdentity(digest); err != nil {
		t.Fatal(err)
	}
	identityOldEvent(t, f.logger)
	id, err := f.logger.RegisterAnchorV2("migrate", legacy, func(req AnchorRegistrationRequest) (*AnchorV2, error) {
		if req.Legacy == nil || req.Anchor.LegacyAnchorDigest != digest || req.Anchor.RowCount != 2 {
			t.Fatal("migration lost its exact witness")
		}
		return req.Anchor, nil
	})
	if err != nil || id.RegistrationState != ChainRegistrationEnrolled {
		t.Fatalf("migration: %+v %v", id, err)
	}
	if _, err := f.logger.RegisterAnchorV2("fresh", nil, func(AnchorRegistrationRequest) (*AnchorV2, error) {
		t.Fatal("changed migration mode sent")
		return nil, nil
	}); err == nil {
		t.Fatal("migration changed to fresh")
	}
}

func TestExistingSigningNeverAdoptsOrGeneratesKey(t *testing.T) {
	f := newIdentityFixture(t)
	identityOldEvent(t, f.logger)
	f.logger.Close()
	strict, err := NewLogger(f.db, f.project, WithExistingSigning(f.key))
	if err != nil {
		t.Fatal(err)
	}
	result, err := strict.VerifyChainSigned(strict.SigningPublicKey(), true)
	if err != nil || !result.Intact || result.SigState != "authentic" {
		t.Fatalf("allowed signed control: %+v %v", result, err)
	}
	if _, err := strict.db.Exec("UPDATE events SET entry_sig=''; UPDATE chain_head SET head_sig='', signed_genesis_at=NULL, unsigned_through_id=NULL, signing_pubkey_fingerprint=''"); err != nil {
		t.Fatal(err)
	}
	strict.Close()
	if logger, err := NewLogger(f.db, f.project, WithExistingSigning(f.key)); err == nil {
		logger.Close()
		t.Fatal("strict open adopted stripped chain")
	}
	missing := filepath.Join(t.TempDir(), "missing.key")
	if logger, err := NewLogger(f.db, f.project, WithExistingSigning(missing)); err == nil {
		logger.Close()
		t.Fatal("strict open accepted missing key")
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("strict open generated a replacement key")
	}
}

func TestAnchorV2PruneCannotInterleaveRegistration(t *testing.T) {
	f := newIdentityFixture(t)
	identityOldEvent(t, f.logger)
	initIdentity(t, f)
	entered, release := make(chan struct{}), make(chan struct{})
	registered := make(chan error, 1)
	go func() {
		_, err := f.logger.RegisterAnchorV2("fresh", nil, func(req AnchorRegistrationRequest) (*AnchorV2, error) {
			close(entered)
			<-release
			return req.Anchor, nil
		})
		registered <- err
	}()
	<-entered
	other, err := NewLogger(f.db, f.project, WithExistingSigning(f.key))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	pruned := make(chan error, 1)
	go func() { _, err := other.Prune(time.Hour); pruned <- err }()
	select {
	case err := <-pruned:
		close(release)
		t.Fatalf("prune bypassed held registration lock: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := <-registered; err != nil {
		t.Fatal(err)
	}
	if err := <-pruned; err == nil {
		t.Fatal("enrolled chain pruned")
	}
}
