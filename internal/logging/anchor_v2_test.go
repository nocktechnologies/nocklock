package logging

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"reflect"
	"strings"
	"testing"
)

type anchorV2Fixture struct {
	Format    string `json:"format"`
	PublicKey string `json:"public_key"`
	Legacy    struct {
		Anchor    Anchor `json:"anchor"`
		Canonical string `json:"canonical_hex"`
		Digest    string `json:"snapshot_digest"`
	} `json:"legacy"`
	Cases []struct {
		Name          string   `json:"name"`
		Anchor        AnchorV2 `json:"anchor"`
		ExpectedAgent string   `json:"expected_agent_id"`
		ExpectedChain string   `json:"expected_chain_id"`
		Canonical     string   `json:"canonical_hex"`
		Digest        string   `json:"snapshot_digest"`
		Result        string   `json:"expected_result"`
	} `json:"cases"`
}

func readAnchorV2Fixture(t *testing.T) (anchorV2Fixture, ed25519.PublicKey) {
	t.Helper()
	data, err := os.ReadFile("testdata/anchor-v2/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture anchorV2Fixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	pub, err := base64.StdEncoding.DecodeString(fixture.PublicKey)
	if err != nil || len(pub) != ed25519.PublicKeySize {
		t.Fatalf("fixture public key: %v", err)
	}
	return fixture, pub
}

func TestAnchorV2PublicVectors(t *testing.T) {
	fixture, pub := readAnchorV2Fixture(t)
	if fixture.Format != "nocklock-anchor-v2-test-vectors-1" || len(fixture.Cases) != 5 {
		t.Fatal("unexpected public fixture format or case count")
	}
	for _, tc := range fixture.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			cb, err := AnchorV2CanonicalBytes(&tc.Anchor)
			if err != nil || hex.EncodeToString(cb) != tc.Canonical {
				t.Fatalf("canonical bytes differ from independent public vector: %x, %v", cb, err)
			}
			err = VerifyAnchorV2(&tc.Anchor, pub, tc.ExpectedAgent, tc.ExpectedChain)
			digest, digestErr := AnchorV2SnapshotDigest(&tc.Anchor, pub, tc.ExpectedAgent, tc.ExpectedChain)
			switch tc.Result {
			case "valid":
				if err != nil || digestErr != nil || digest != tc.Digest {
					t.Fatalf("valid vector: verify=%v digest=%q err=%v", err, digest, digestErr)
				}
			case "invalid_signature":
				if err == nil || !strings.Contains(err.Error(), "signature does not verify") || digestErr == nil || digest != "" {
					t.Fatalf("forged vector accepted or misclassified: %v, %q, %v", err, digest, digestErr)
				}
			case "identity_mismatch":
				if !errors.Is(err, ErrAnchorIdentityMismatch) || !errors.Is(digestErr, ErrAnchorIdentityMismatch) || digest != "" {
					t.Fatalf("swapped pair accepted or misclassified: %v, %q, %v", err, digest, digestErr)
				}
			default:
				t.Fatalf("unknown expected result %q", tc.Result)
			}
			data, err := MarshalAnchorV2(&tc.Anchor)
			if err != nil {
				t.Fatal(err)
			}
			roundtrip, err := UnmarshalAnchorV2(data)
			if err != nil || !reflect.DeepEqual(roundtrip, &tc.Anchor) {
				t.Fatalf("record round trip: %v, %v", roundtrip, err)
			}
		})
	}
	cb, err := anchorCanonicalBytes(&fixture.Legacy.Anchor)
	if err != nil || hex.EncodeToString(cb) != fixture.Legacy.Canonical || cb[0] != 0x05 {
		t.Fatalf("legacy canonical bytes changed: %x, %v", cb, err)
	}
	digest, err := LegacyAnchorSnapshotDigest(&fixture.Legacy.Anchor, pub)
	if err != nil || digest != fixture.Legacy.Digest {
		t.Fatalf("legacy migration digest: %q, %v", digest, err)
	}
	migration := fixture.Cases[4].Anchor
	if migration.LegacyAnchorDigest != digest || migration.AgentID != fixture.Legacy.Anchor.AgentID || migration.HeadHash != fixture.Legacy.Anchor.HeadHash || migration.RowCount != uint64(fixture.Legacy.Anchor.RowCount) {
		t.Fatal("migration fixture must bind the exact legacy snapshot and retain its head")
	}
}

func TestAnchorV2CanonicalByteLiteral(t *testing.T) {
	a := AnchorV2{Version: 2, AgentID: strings.Repeat("a", 64), ChainID: strings.Repeat("b", 64), HeadHash: strings.Repeat("c", 64), RowCount: 0x0102030405060708, CreatedAt: "2026-10-13T12:34:56.123456789Z", LegacyAnchorDigest: strings.Repeat("d", 64)}
	// Literal framing is independent of the production encoder: 0x06 domain,
	// 64-byte ASCII identity, decoded hashes, big-endian count, 30-byte time.
	want := []byte{0x06, 0, 0, 0, 64}
	want = append(want, []byte(a.AgentID)...)
	want = append(want, bytes.Repeat([]byte{0xbb}, 32)...)
	want = append(want, bytes.Repeat([]byte{0xcc}, 32)...)
	want = append(want, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 30)
	want = append(want, []byte(a.CreatedAt)...)
	want = append(want, bytes.Repeat([]byte{0xdd}, 32)...)
	got, err := AnchorV2CanonicalBytes(&a)
	if err != nil || !bytes.Equal(got, want) {
		t.Fatalf("canonical bytes: got %x (%v), want %x", got, err, want)
	}
}

func TestAnchorV2EverySignedFieldBound(t *testing.T) {
	fixture, pub := readAnchorV2Fixture(t)
	original := fixture.Cases[0].Anchor
	cases := map[string]func(*AnchorV2){
		"version":              func(a *AnchorV2) { a.Version = 1 },
		"agent_id":             func(a *AnchorV2) { a.AgentID = strings.Repeat("1", 64) },
		"chain_id":             func(a *AnchorV2) { a.ChainID = strings.Repeat("1", 64) },
		"head_hash":            func(a *AnchorV2) { a.HeadHash = strings.Repeat("1", 64) },
		"row_count":            func(a *AnchorV2) { a.RowCount++ },
		"created_at":           func(a *AnchorV2) { a.CreatedAt = "2026-10-13T12:34:57.123456789Z" },
		"legacy_anchor_digest": func(a *AnchorV2) { a.LegacyAnchorDigest = strings.Repeat("1", 64) },
		"signature":            func(a *AnchorV2) { a.Sig = base64.StdEncoding.EncodeToString(make([]byte, 64)) },
		"v1_signature_replay":  func(a *AnchorV2) { a.Sig = fixture.Legacy.Anchor.Sig },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := original
			mutate(&a)
			// Even a caller trusting the altered IDs must reject the signature.
			if err := VerifyAnchorV2(&a, pub, a.AgentID, a.ChainID); err == nil {
				t.Fatal("modified signed record accepted")
			}
		})
	}
	if err := VerifyAnchorV2(&original, pub, original.AgentID, original.ChainID); err != nil {
		t.Fatalf("unaltered positive control: %v", err)
	}
}

func TestAnchorV2RejectMalformedRecords(t *testing.T) {
	fixture, pub := readAnchorV2Fixture(t)
	original := fixture.Cases[0].Anchor
	cases := map[string]func(*AnchorV2){
		"unknown_version":   func(a *AnchorV2) { a.Version = 3 },
		"uppercase_agent":   func(a *AnchorV2) { a.AgentID = strings.ToUpper(a.AgentID) },
		"uppercase_chain":   func(a *AnchorV2) { a.ChainID = strings.ToUpper(a.ChainID) },
		"short_chain":       func(a *AnchorV2) { a.ChainID = "ab" },
		"invalid_hex":       func(a *AnchorV2) { a.ChainID = strings.Repeat("x", 64) },
		"uppercase_head":    func(a *AnchorV2) { a.HeadHash = strings.ToUpper(a.HeadHash) },
		"missing_legacy":    func(a *AnchorV2) { a.LegacyAnchorDigest = "" },
		"uppercase_legacy":  func(a *AnchorV2) { a.LegacyAnchorDigest = strings.Repeat("AB", 32) },
		"short_signature":   func(a *AnchorV2) { a.Sig = "AA==" },
		"missing_timestamp": func(a *AnchorV2) { a.CreatedAt = "" },
		"invalid_date":      func(a *AnchorV2) { a.CreatedAt = "2026-02-30T12:34:56Z" },
		"non_utc":           func(a *AnchorV2) { a.CreatedAt = "2026-10-13T12:34:56+00:00" },
		"empty_fraction":    func(a *AnchorV2) { a.CreatedAt = "2026-10-13T12:34:56.Z" },
		"extra_precision":   func(a *AnchorV2) { a.CreatedAt = "2026-10-13T12:34:56.1234567890Z" },
		"comma_fraction":    func(a *AnchorV2) { a.CreatedAt = "2026-10-13T12:34:56,123Z" },
		"short_hour":        func(a *AnchorV2) { a.CreatedAt = "2026-10-13T1:34:56.123Z" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := original
			mutate(&a)
			if _, err := MarshalAnchorV2(&a); err == nil {
				t.Fatal("malformed record marshaled")
			}
			if err := VerifyAnchorV2(&a, pub, original.AgentID, original.ChainID); err == nil {
				t.Fatal("malformed record verified")
			}
		})
	}
	if _, err := AnchorV2CanonicalBytes(nil); err == nil {
		t.Fatal("nil record accepted")
	}
	for _, badPub := range []ed25519.PublicKey{nil, make([]byte, 31), make([]byte, 33), make([]byte, 32)} {
		if err := VerifyAnchorV2(&original, badPub, original.AgentID, original.ChainID); err == nil {
			t.Fatal("invalid/wrong public key accepted")
		}
	}
	for _, pair := range [][2]string{{"", original.ChainID}, {original.AgentID, ""}, {strings.Repeat("e", 64), original.ChainID}} {
		if err := VerifyAnchorV2(&original, pub, pair[0], pair[1]); err == nil {
			t.Fatal("absent or wrong trusted pair accepted")
		}
	}
}

func TestAnchorV2StrictJSON(t *testing.T) {
	fixture, _ := readAnchorV2Fixture(t)
	data, err := MarshalAnchorV2(&fixture.Cases[0].Anchor)
	if err != nil {
		t.Fatal(err)
	}
	valid := string(data)
	cases := map[string]string{
		"duplicate":         strings.Replace(valid, `"version":2`, `"version":2,"version":2`, 1),
		"escaped_duplicate": strings.Replace(valid, `"version":2`, `"version":2,"\u0076ersion":2`, 1),
		"case_fold":         strings.Replace(valid, `"version"`, `"Version"`, 1),
		"unknown":           strings.Replace(valid, `"version":2`, `"version":2,"extra":0`, 1),
		"missing_version":   strings.Replace(valid, `"version":2,`, "", 1),
		"missing_count":     strings.Replace(valid, `"row_count":5,`, "", 1),
		"null_count":        strings.Replace(valid, `"row_count":5`, `"row_count":null`, 1),
		"negative_count":    strings.Replace(valid, `"row_count":5`, `"row_count":-1`, 1),
		"fraction_count":    strings.Replace(valid, `"row_count":5`, `"row_count":5.0`, 1),
		"exponent_count":    strings.Replace(valid, `"row_count":5`, `"row_count":5e0`, 1),
		"overflow_count":    strings.Replace(valid, `"row_count":5`, `"row_count":18446744073709551616`, 1),
		"quoted_count":      strings.Replace(valid, `"row_count":5`, `"row_count":"5"`, 1),
		"multiple_objects":  valid + valid,
		"trailing_data":     valid + " garbage",
		"truncated":         valid[:len(valid)-1],
		"null":              "null", "array": "[]", "empty": "",
		"invalid_utf8": strings.Replace(valid, "created_at", "created_\xffat", 1),
	}
	for name, raw := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := UnmarshalAnchorV2([]byte(raw)); err == nil {
				t.Fatal("invalid JSON accepted")
			}
		})
	}
	if _, err := UnmarshalAnchorV2(data); err != nil {
		t.Fatalf("valid JSON positive control: %v", err)
	}
}

func TestAnchorV2TransportInvariantDigest(t *testing.T) {
	fixture, pub := readAnchorV2Fixture(t)
	original := fixture.Cases[0].Anchor
	data, _ := MarshalAnchorV2(&original)
	var unordered map[string]any
	if err := json.Unmarshal(data, &unordered); err != nil {
		t.Fatal(err)
	}
	// Padding and CR/LF differ; bytes, canonical output, and digest must not.
	unordered["sig"] = strings.TrimRight(original.Sig[:40]+"\r\n"+original.Sig[40:], "=")
	spaced, _ := json.MarshalIndent(unordered, "", "  ")
	a, err := UnmarshalAnchorV2(spaced)
	if err != nil {
		t.Fatal(err)
	}
	canonicalJSON, err := MarshalAnchorV2(a)
	if err != nil || !bytes.Equal(canonicalJSON, data) {
		t.Fatalf("canonical JSON drifted: %s, %v", canonicalJSON, err)
	}
	digest, err := AnchorV2SnapshotDigest(a, pub, a.AgentID, a.ChainID)
	if err != nil || digest != fixture.Cases[0].Digest {
		t.Fatalf("transport changed digest: %q, %v", digest, err)
	}
	legacy := fixture.Legacy.Anchor
	legacy.Sig = strings.TrimRight(legacy.Sig, "=")
	if digest, err := LegacyAnchorSnapshotDigest(&legacy, pub); err != nil || digest != fixture.Legacy.Digest {
		t.Fatalf("legacy signature spelling changed digest: %q, %v", digest, err)
	}
	// Nonzero unused padding bits decode under permissive base64, but are not
	// an accepted spelling of the record signature.
	a.Sig = original.Sig[:85] + "B=="
	if _, err := MarshalAnchorV2(a); err == nil {
		t.Fatal("noncanonical base64 padding bits accepted")
	}
}

func TestAnchorV2Uint64AndTimestampControls(t *testing.T) {
	fixture, _ := readAnchorV2Fixture(t)
	a := fixture.Cases[0].Anchor
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	a.AgentID = publicKeyFingerprint(pub)
	for _, count := range []uint64{0, 1 << 53, math.MaxUint64} {
		for _, timestamp := range []string{"2026-10-13T12:34:56Z", "2026-10-13T12:34:56.0Z", "2026-10-13T12:34:56.123456789Z"} {
			a.RowCount, a.CreatedAt = count, timestamp
			cb, err := AnchorV2CanonicalBytes(&a)
			if err != nil {
				t.Fatal(err)
			}
			a.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(priv, cb))
			data, err := MarshalAnchorV2(&a)
			if err != nil {
				t.Fatal(err)
			}
			decoded, err := UnmarshalAnchorV2(data)
			if err != nil || decoded.RowCount != count || decoded.CreatedAt != timestamp {
				t.Fatalf("integer/timestamp round trip failed: %v, %v", decoded, err)
			}
			if err := VerifyAnchorV2(decoded, pub, a.AgentID, a.ChainID); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func TestAnchorV2LeavesV1Default(t *testing.T) {
	l, _, pub := newSigningLogger(t)
	defer l.Close()
	a := emitN(t, l, 1)
	if AnchorVersion != 1 || a.Version != 1 {
		t.Fatal("default anchor emission changed")
	}
	data, err := MarshalAnchor(a)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte("chain_id")) || bytes.Contains(data, []byte("legacy_anchor_digest")) {
		t.Fatal("v2 fields leaked into legacy output")
	}
	if _, err := UnmarshalAnchorV2(data); err == nil {
		t.Fatal("v1 record accepted as v2")
	}
	if _, err := LegacyAnchorSnapshotDigest(a, pub); err != nil {
		t.Fatalf("default v1 emission cannot be a migration witness: %v", err)
	}
	result, err := l.VerifyAgainstAnchor(a, pub)
	if err != nil || !result.OK {
		t.Fatalf("v1 default verification regressed: %v, %v", result, err)
	}
	fixture, fixturePub := readAnchorV2Fixture(t)
	v2, _ := MarshalAnchorV2(&fixture.Cases[0].Anchor)
	legacyView, err := UnmarshalAnchor(v2)
	if err != nil {
		t.Fatal(err)
	}
	result, err = l.VerifyAgainstAnchor(legacyView, fixturePub)
	if err != nil || result.OK || result.Classification != "forged" {
		t.Fatalf("v1 verifier must reject v2: %v, %v", result, err)
	}
}

func TestLegacyAnchorSnapshotRejectsInvalidWitness(t *testing.T) {
	fixture, pub := readAnchorV2Fixture(t)
	original := fixture.Legacy.Anchor
	cases := map[string]func(*Anchor){
		"version":        func(a *Anchor) { a.Version = 2 },
		"agent":          func(a *Anchor) { a.AgentID = strings.Repeat("1", 64) },
		"uppercase_hash": func(a *Anchor) { a.HeadHash = strings.ToUpper(a.HeadHash) },
		"negative_count": func(a *Anchor) { a.RowCount = -1 },
		"changed_count":  func(a *Anchor) { a.RowCount++ },
		"invalid_time":   func(a *Anchor) { a.CreatedAt = "not-a-time" },
		"bad_signature":  func(a *Anchor) { a.Sig = base64.StdEncoding.EncodeToString(make([]byte, 64)) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := original
			mutate(&a)
			if digest, err := LegacyAnchorSnapshotDigest(&a, pub); err == nil || digest != "" {
				t.Fatalf("invalid witness produced a digest: %q, %v", digest, err)
			}
		})
	}
	if digest, err := LegacyAnchorSnapshotDigest(nil, pub); err == nil || digest != "" {
		t.Fatal("nil witness accepted")
	}
	if _, err := LegacyAnchorSnapshotDigest(&original, nil); err == nil {
		t.Fatal("witness authenticated without key")
	}
	if digest, err := LegacyAnchorSnapshotDigest(&original, pub); err != nil || digest != fixture.Legacy.Digest {
		t.Fatalf("valid witness control: %q, %v", digest, err)
	}
}

func FuzzUnmarshalAnchorV2(f *testing.F) {
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	data, err := os.ReadFile("testdata/anchor-v2/vectors.json")
	if err != nil {
		f.Fatal(err)
	}
	var fixture anchorV2Fixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		f.Fatal(err)
	}
	for _, tc := range fixture.Cases {
		data, err := MarshalAnchorV2(&tc.Anchor)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(data)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		a, err := UnmarshalAnchorV2(data)
		if err != nil {
			return
		}
		cb, err := AnchorV2CanonicalBytes(a)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := MarshalAnchorV2(a)
		if err != nil {
			t.Fatal(err)
		}
		roundtrip, err := UnmarshalAnchorV2(encoded)
		if err != nil {
			t.Fatal(err)
		}
		again, err := AnchorV2CanonicalBytes(roundtrip)
		if err != nil || !bytes.Equal(cb, again) {
			t.Fatal("canonical bytes changed after JSON round trip")
		}
	})
}
