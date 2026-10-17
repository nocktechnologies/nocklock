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
	"sort"
	"strings"
	"testing"
)

type rotationExpected struct {
	Root      string        `json:"lineage_root"`
	Old       ChainIdentity `json:"old_identity"`
	Next      ChainIdentity `json:"new_identity"`
	Head      string        `json:"head_hash"`
	Count     uint64        `json:"row_count"`
	Successor string        `json:"successor_public_key"`
}
type rotationVector struct {
	Name            string               `json:"name"`
	Bundle          *RotationEndorsement `json:"bundle"`
	TransportHex    string               `json:"transport_hex,omitempty"`
	Expected        rotationExpected     `json:"expected"`
	Canonical       string               `json:"canonical_hex,omitempty"`
	Digest          string               `json:"endorsement_digest,omitempty"`
	AcceptanceBytes string               `json:"acceptance_canonical_hex,omitempty"`
	Result          string               `json:"expected_result"`
	Control         string               `json:"positive_control,omitempty"`
}
type rotationFixture struct {
	Format string           `json:"format"`
	Cases  []rotationVector `json:"cases"`
}

var rotationErrors = map[string]error{
	"valid": nil, "root_mismatch": ErrRotationRootMismatch, "identity_mismatch": ErrRotationIdentityMismatch,
	"tail_mismatch": ErrRotationTailMismatch, "replay": ErrRotationReplay, "missing": ErrRotationMissing,
	"unused": ErrRotationUnused, "bad_signature": ErrRotationBadSignature, "malformed": ErrRotationMalformed,
}

func verifyRotationVector(v rotationVector) error {
	raw, err := json.Marshal(v.Bundle)
	if v.TransportHex != "" {
		raw, err = hex.DecodeString(v.TransportHex)
	}
	if err != nil {
		return err
	}
	var r *RotationEndorsement
	if v.Bundle != nil || v.TransportHex != "" {
		r, err = UnmarshalRotationEndorsement(raw)
		if err != nil {
			return err
		}
	}
	key, err := hex.DecodeString(v.Expected.Successor)
	if err != nil {
		return err
	}
	return VerifyRotationEndorsement(r, v.Expected.Root, &v.Expected.Old, &v.Expected.Next, v.Expected.Head, v.Expected.Count, key)
}
func TestRotationPublicVectors(t *testing.T) {
	if os.Getenv("NOCKLOCK_GENERATE_ROTATION_VECTORS") == "1" {
		t.Skip("generation run; verify frozen vectors without the opt-in next")
	}
	data, err := os.ReadFile("testdata/rotation-endorsement/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var f rotationFixture
	if err = json.Unmarshal(data, &f); err != nil {
		t.Fatal(err)
	}
	if f.Format != "nocklock-rotation-endorsement-test-vectors-1" || len(f.Cases) < 40 {
		t.Fatal("unexpected vector envelope")
	}
	cases := map[string]rotationVector{}
	seen := map[string]bool{}
	for _, v := range f.Cases {
		if _, ok := cases[v.Name]; ok {
			t.Fatal("duplicate vector")
		}
		cases[v.Name] = v
	}
	for _, v := range f.Cases {
		t.Run(v.Name, func(t *testing.T) {
			want, ok := rotationErrors[v.Result]
			if !ok {
				t.Fatal("unknown result")
			}
			seen[v.Result] = true
			got := verifyRotationVector(v)
			if !errors.Is(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
			if want != nil {
				control, ok := cases[v.Control]
				if !ok || control.Result != "valid" {
					t.Fatal("missing positive control")
				}
				if e := verifyRotationVector(control); e != nil {
					t.Fatal(e)
				}
			}
			if v.Canonical != "" {
				cb, e := RotationEndorsementCanonicalBytes(v.Bundle)
				if e != nil || hex.EncodeToString(cb) != v.Canonical {
					t.Fatal("canonical bytes drift", e)
				}
				sig, e := anchorSignature(v.Bundle.Sig)
				if e != nil {
					t.Fatal(e)
				}
				digest := rotationDigest(cb, sig)
				if digest != v.Digest || hex.EncodeToString(rotationAcceptanceBytes(digest)) != v.AcceptanceBytes {
					t.Fatal("digest or acceptance encoding drift")
				}
			}
			if v.Bundle != nil && v.TransportHex == "" {
				raw, e := MarshalRotationEndorsement(v.Bundle)
				if e == nil {
					r, e := UnmarshalRotationEndorsement(raw)
					if e != nil || !reflect.DeepEqual(r, v.Bundle) {
						t.Fatal("round trip drift", e)
					}
				}
			}
		})
	}
	for result := range rotationErrors {
		if !seen[result] {
			t.Fatalf("missing failure class %s", result)
		}
	}
}

// signRotation is deliberately test-only: key switching is not implemented.
// Ephemeral private keys never leave memory, including during vector generation.
func signRotation(t *testing.T, r *RotationEndorsement, old, next ed25519.PrivateKey) {
	t.Helper()
	cb, e := RotationEndorsementCanonicalBytes(r)
	if e != nil {
		t.Fatal(e)
	}
	sig := ed25519.Sign(old, cb)
	r.Sig = base64.StdEncoding.EncodeToString(sig)
	r.Acceptance = base64.StdEncoding.EncodeToString(ed25519.Sign(next, rotationAcceptanceBytes(rotationDigest(cb, sig))))
}
func rotationTestKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	p, k, e := ed25519.GenerateKey(rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	return p, k
}
func rotationTestIdentity(pub ed25519.PublicKey, chain string) ChainIdentity {
	return ChainIdentity{Version: 1, AgentID: publicKeyFingerprint(pub), ChainID: chain, LegacyAnchorDigest: strings.Repeat("0", 64), RegistrationState: ChainRegistrationNone}
}
func rotationBase(t *testing.T) (rotationVector, ed25519.PrivateKey, ed25519.PrivateKey) {
	root, _ := rotationTestKey(t)
	old, oldPriv := rotationTestKey(t)
	next, nextPriv := rotationTestKey(t)
	r := RotationEndorsement{Version: 1, LineageRoot: publicKeyFingerprint(root), OldChainID: strings.Repeat("1", 64), NewChainID: strings.Repeat("2", 64), HeadHash: strings.Repeat("3", 64), RowCount: 7, SuccessorPublicKey: hex.EncodeToString(next), OldPublicKey: hex.EncodeToString(old)}
	signRotation(t, &r, oldPriv, nextPriv)
	v := rotationVector{Name: "valid_independent_root", Bundle: &r, Expected: rotationExpected{r.LineageRoot, rotationTestIdentity(old, r.OldChainID), rotationTestIdentity(next, r.NewChainID), r.HeadHash, r.RowCount, r.SuccessorPublicKey}, Result: "valid"}
	return v, oldPriv, nextPriv
}

// TestGenerateRotationVectors runs only with an explicit opt-in. It writes public
// material only and never modifies the anchor-v2 compatibility fixtures.
func TestGenerateRotationVectors(t *testing.T) {
	if os.Getenv("NOCKLOCK_GENERATE_ROTATION_VECTORS") != "1" {
		t.Skip("explicit public-vector generation opt-in required")
	}
	base, old, next := rotationBase(t)
	f := rotationFixture{Format: "nocklock-rotation-endorsement-test-vectors-1"}
	add := func(v rotationVector) {
		if v.Bundle != nil {
			if cb, e := RotationEndorsementCanonicalBytes(v.Bundle); e == nil {
				if sig, e := anchorSignature(v.Bundle.Sig); e == nil {
					v.Canonical = hex.EncodeToString(cb)
					v.Digest = rotationDigest(cb, sig)
					v.AcceptanceBytes = hex.EncodeToString(rotationAcceptanceBytes(v.Digest))
				}
			}
		}
		f.Cases = append(f.Cases, v)
	}
	clone := func() rotationVector { v := base; r := *base.Bundle; v.Bundle = &r; v.Control = base.Name; return v }
	add(base)
	for _, count := range []uint64{0, 1 << 53, math.MaxUint64} {
		v := clone()
		v.Name = map[uint64]string{0: "valid_zero", 1 << 53: "valid_above_json_exact_integer", math.MaxUint64: "valid_max_uint64"}[count]
		v.Bundle.RowCount = count
		v.Expected.Count = count
		v.Control = ""
		signRotation(t, v.Bundle, old, next)
		add(v)
	}
	mutations := []struct {
		name, result string
		mutate       func(*rotationVector)
	}{
		{"substituted_root", "root_mismatch", func(v *rotationVector) { v.Expected.Root = strings.Repeat("4", 64) }},
		{"wrong_old_chain", "identity_mismatch", func(v *rotationVector) { v.Expected.Old.ChainID = strings.Repeat("4", 64) }},
		{"wrong_retiring_identity", "identity_mismatch", func(v *rotationVector) { v.Expected.Old.AgentID = strings.Repeat("4", 64) }},
		{"replay_new_chain", "replay", func(v *rotationVector) { v.Expected.Next.ChainID = strings.Repeat("4", 64) }},
		{"replay_successor", "replay", func(v *rotationVector) { v.Expected.Successor = strings.Repeat("4", 64) }},
		{"wrong_successor_identity", "replay", func(v *rotationVector) { v.Expected.Next.AgentID = strings.Repeat("4", 64) }},
		{"truncated_old_count", "tail_mismatch", func(v *rotationVector) { v.Expected.Count-- }},
		{"extended_old_count", "tail_mismatch", func(v *rotationVector) { v.Expected.Count++ }},
		{"wrong_old_tail", "tail_mismatch", func(v *rotationVector) { v.Expected.Head = strings.Repeat("4", 64) }},
		{"missing_endorsement", "missing", func(v *rotationVector) { v.Bundle = nil }},
		{"unused_endorsement", "unused", func(v *rotationVector) { v.Bundle.Acceptance = "" }},
		{"bad_retiring_signature", "bad_signature", func(v *rotationVector) { v.Bundle.Sig = base64.StdEncoding.EncodeToString(make([]byte, 64)) }},
		{"bad_acceptance_signature", "bad_signature", func(v *rotationVector) { v.Bundle.Acceptance = base64.StdEncoding.EncodeToString(make([]byte, 64)) }},
	}
	for _, m := range mutations {
		v := clone()
		v.Name = m.name
		v.Result = m.result
		m.mutate(&v)
		add(v)
	}

	// A valid successor signature for another endorsement is not acceptance here.
	alternate := clone()
	alternate.Name = "valid_alternate_tail_count"
	alternate.Control = ""
	alternate.Bundle.RowCount++
	alternate.Expected.Count++
	signRotation(t, alternate.Bundle, old, next)
	add(alternate)
	swapped := alternate
	swappedRecord := *alternate.Bundle
	swapped.Bundle = &swappedRecord
	swapped.Name = "replayed_acceptance"
	swapped.Result = "bad_signature"
	swapped.Bundle.Acceptance = base.Bundle.Acceptance
	swapped.Control = alternate.Name
	add(swapped)

	// The first rotation's lineage root is the retiring key's own fingerprint.
	oldPub, e := hex.DecodeString(base.Bundle.OldPublicKey)
	if e != nil {
		t.Fatal(e)
	}
	first := clone()
	first.Name = "valid_first_rotation"
	first.Control = ""
	first.Bundle.LineageRoot = publicKeyFingerprint(oldPub)
	first.Expected.Root = first.Bundle.LineageRoot
	signRotation(t, first.Bundle, old, next)
	add(first)

	// A correctly signed transition into the chain it retires is rejected.
	same := clone()
	same.Name = "same_old_and_new_chain"
	same.Result = "identity_mismatch"
	same.Bundle.NewChainID = same.Bundle.OldChainID
	same.Expected.Next.ChainID = same.Bundle.OldChainID
	signRotation(t, same.Bundle, old, next)
	add(same)

	// Whitespace-only transport is an absent endorsement, not a malformed one.
	empty := clone()
	empty.Name = "missing_empty_transport"
	empty.Result = "missing"
	empty.TransportHex = hex.EncodeToString([]byte(" \n"))
	add(empty)
	// Each signed field gets an independent one-field tamper and restored control.
	for _, field := range []string{"lineage_root", "old_chain_id", "new_chain_id", "head_hash", "row_count", "successor_public_key", "old_public_key"} {
		v := clone()
		v.Name = "unsigned_change_" + field
		v.Result = "bad_signature"
		switch field {
		case "lineage_root":
			v.Bundle.LineageRoot = strings.Repeat("4", 64)
		case "old_chain_id":
			v.Bundle.OldChainID = strings.Repeat("4", 64)
		case "new_chain_id":
			v.Bundle.NewChainID = strings.Repeat("4", 64)
		case "head_hash":
			v.Bundle.HeadHash = strings.Repeat("4", 64)
		case "row_count":
			v.Bundle.RowCount++
		case "successor_public_key":
			v.Bundle.SuccessorPublicKey = strings.Repeat("4", 64)
		case "old_public_key":
			v.Bundle.OldPublicKey = strings.Repeat("4", 64)
		}
		add(v)
	}
	raw, e := MarshalRotationEndorsement(base.Bundle)
	if e != nil {
		t.Fatal(e)
	}
	s := string(raw)
	malformed := map[string]string{
		"duplicate":         strings.Replace(s, `"version":1`, `"version":1,"version":1`, 1),
		"escaped_duplicate": strings.Replace(s, `"version":1`, `"version":1,"\u0076ersion":1`, 1),
		"case_folded":       strings.Replace(s, `"version"`, `"Version"`, 1),
		"unknown":           strings.Replace(s, `"version":1`, `"version":1,"extra":0`, 1),
		"missing_field":     strings.Replace(s, `"row_count":7,`, "", 1),
		"null_field":        strings.Replace(s, `"row_count":7`, `"row_count":null`, 1),
		"negative_count":    strings.Replace(s, `"row_count":7`, `"row_count":-1`, 1),
		"fractional_count":  strings.Replace(s, `"row_count":7`, `"row_count":7.0`, 1),
		"exponent_count":    strings.Replace(s, `"row_count":7`, `"row_count":7e0`, 1),
		"overflow_count":    strings.Replace(s, `"row_count":7`, `"row_count":18446744073709551616`, 1),
		"quoted_count":      strings.Replace(s, `"row_count":7`, `"row_count":"7"`, 1),
		"unknown_version":   strings.Replace(s, `"version":1`, `"version":2`, 1),
		"uppercase_hex":     strings.Replace(s, base.Bundle.LineageRoot, strings.ToUpper(base.Bundle.LineageRoot), 1),
		"short_hex":         strings.Replace(s, base.Bundle.HeadHash, "00", 1),
		"invalid_hex":       strings.Replace(s, base.Bundle.HeadHash, strings.Repeat("g", 64), 1),
		"short_signature":   strings.Replace(s, base.Bundle.Sig, "AA==", 1),
		"padding_bits":      strings.Replace(s, base.Bundle.Sig, base.Bundle.Sig[:85]+"B==", 1),
		"null_object":       "null", "array": "[]", "trailing_object": s + s, "trailing_data": s + " garbage", "truncated_object": s[:len(s)-1],
		"invalid_utf8": strings.Replace(s, "lineage_root", "lineage_\xffroot", 1),
	}
	for name, transport := range malformed {
		v := clone()
		v.Name = "malformed_" + name
		v.Result = "malformed"
		v.TransportHex = hex.EncodeToString([]byte(transport))
		add(v)
	}
	sort.Slice(f.Cases, func(i, j int) bool { return f.Cases[i].Name < f.Cases[j].Name })
	// Stable entry order despite the map above, without altering canonical records.
	// The envelope is a fixture, not a protocol message.
	data, e := json.MarshalIndent(f, "", "  ")
	if e != nil {
		t.Fatal(e)
	}
	if e = os.MkdirAll("testdata/rotation-endorsement", 0755); e != nil {
		t.Fatal(e)
	}
	if e = os.WriteFile("testdata/rotation-endorsement/vectors.json", append(data, '\n'), 0644); e != nil {
		t.Fatal(e)
	}
}

func TestRotationVerificationOrderAndAcceptanceBinding(t *testing.T) {
	v, old, next := rotationBase(t)
	// Old key can sign a new endorsement, but cannot reuse successor acceptance.
	prior := v.Bundle.Acceptance
	v.Bundle.RowCount++
	cb, _ := RotationEndorsementCanonicalBytes(v.Bundle)
	v.Bundle.Sig = base64.StdEncoding.EncodeToString(ed25519.Sign(old, cb))
	v.Bundle.Acceptance = prior
	v.Expected.Count = 0
	if e := verifyRotationVector(v); !errors.Is(e, ErrRotationBadSignature) {
		t.Fatalf("acceptance/count order: %v", e)
	}
	signRotation(t, v.Bundle, old, next)
	if e := verifyRotationVector(v); !errors.Is(e, ErrRotationTailMismatch) {
		t.Fatalf("restored acceptance: %v", e)
	}
	v.Expected.Count = v.Bundle.RowCount
	if e := verifyRotationVector(v); e != nil {
		t.Fatal(e)
	}
	raw, _ := MarshalRotationEndorsement(v.Bundle)
	// Accepted base64 transport variants normalize without changing signed bytes.
	wrapped := strings.Replace(string(raw), v.Bundle.Sig, strings.TrimRight(v.Bundle.Sig, "="), 1)
	r, e := UnmarshalRotationEndorsement([]byte(wrapped))
	if e != nil {
		t.Fatal(e)
	}
	normalized, e := MarshalRotationEndorsement(r)
	if e != nil || !bytes.Equal(raw, normalized) {
		t.Fatal("signature normalization drift", e)
	}
}

func TestRotationCanonicalLiteralAndDomains(t *testing.T) {
	r := RotationEndorsement{Version: 1, LineageRoot: strings.Repeat("1", 64), OldChainID: strings.Repeat("2", 64), NewChainID: strings.Repeat("3", 64), HeadHash: strings.Repeat("4", 64), RowCount: 0x0102030405060708, SuccessorPublicKey: strings.Repeat("5", 64), OldPublicKey: strings.Repeat("6", 64)}
	want := append([]byte("nocklock-rotation-endorsement-v1\x00"), 1)
	for _, value := range []byte{0x11, 0x22, 0x33, 0x44} {
		want = append(want, bytes.Repeat([]byte{value}, 32)...)
	}
	want = append(want, 1, 2, 3, 4, 5, 6, 7, 8)
	for _, value := range []byte{0x55, 0x66} {
		want = append(want, bytes.Repeat([]byte{value}, 32)...)
	}
	got, e := RotationEndorsementCanonicalBytes(&r)
	if e != nil || !bytes.Equal(want, got) {
		t.Fatalf("literal layout drift: %x, %v", got, e)
	}
	v, _, _ := rotationBase(t)
	cb, _ := RotationEndorsementCanonicalBytes(v.Bundle)
	pub, _ := hex.DecodeString(v.Bundle.OldPublicKey)
	sig, _ := anchorSignature(v.Bundle.Sig)
	if !ed25519.Verify(pub, cb, sig) {
		t.Fatal("signature control")
	}
	for _, offset := range []int{0, len(rotationDomain) - 1, len(rotationDomain)} {
		changed := bytes.Clone(cb)
		changed[offset] ^= 1
		if ed25519.Verify(pub, changed, sig) {
			t.Fatal("domain/version not bound")
		}
	}
}
