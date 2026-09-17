// Ed25519 signing for the audit log (v1.1). The unkeyed SHA-256 hash chain in
// logger.go proves only internal CONSISTENCY: a writer with access to the
// SQLite file can recompute every hash and the in-database head. A keyed
// signature over the same canonical bytes proves AUTHENTICITY — that NockLock,
// holder of the private key, wrote the row — which an active file writer
// without the key cannot forge. The key lives OUTSIDE .nock/events.db so a
// db-only attacker cannot sign.
package logging

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// signingKeyVersion is the encoding version of the key file. The file stores
// the raw 32-byte Ed25519 seed (crypto/ed25519 derives the private key from it).
const signingSeedLen = ed25519.SeedSize // 32

// signingRand is the entropy source for key generation. It is a package
// variable so a test can substitute a failing reader and exercise the
// create-path cleanup contract; production always uses crypto/rand.
var signingRand io.Reader = rand.Reader

// headSigVersion is the leading domain-separation tag for chain_head canonical
// bytes. Row canonical bytes lead with 0x01 (see canonicalBytes); the head
// leads with 0x03 so a row signature can never be replayed as a head signature.
// Version 0x03 also binds the signing, pruning, and public-key metadata.
const headSigVersion byte = 0x03

// signer holds a loaded Ed25519 keypair. A nil *signer means signing is off.
type signer struct {
	priv ed25519.PrivateKey
	pub  ed25519.PublicKey
}

// headSignatureMetadata is the security-relevant chain_head metadata covered
// by its signature. The database stores optional values as NULL; the canonical
// encoding preserves that distinction from an empty or zero value.
type headSignatureMetadata struct {
	prunedAt                *string
	prunedCount             *int
	signedGenesisAt         *string
	unsignedThroughID       *int64
	publicKeyFingerprintHex string
}

// DefaultSigningKeyPath returns the NockLock-managed signing key path,
// $XDG_CONFIG_HOME/nocklock/signing-ed25519.key or ~/.config/nocklock/signing-ed25519.key.
func DefaultSigningKeyPath() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "nocklock", "signing-ed25519.key"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot resolve home directory for signing key: %w", err)
	}
	return filepath.Join(home, ".config", "nocklock", "signing-ed25519.key"), nil
}

// loadOrCreateSigner loads the Ed25519 key at path, generating it on first use
// if absent. The key file is created 0600 in a 0700 directory, holding the raw
// 32-byte seed. A world/group-readable, non-regular, or symlinked key file is
// rejected (fail closed). The private key is never printed.
func loadOrCreateSigner(path string) (*signer, error) {
	dir, err := validateSigningKeyDirectory(filepath.Dir(path), true)
	if err != nil {
		return nil, err
	}
	path = filepath.Join(dir, filepath.Base(path))

	// O_EXCL closes the create race: exactly one process creates the key, the
	// rest fall through to load. O_NOFOLLOW refuses to create through a symlink.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY|oNoFollow, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return loadSigner(path)
		}
		return nil, fmt.Errorf("failed to create signing key at %s: %w", path, err)
	}
	// The file now exists on disk. A silent Close error persisting a truncated
	// key — or any failed Write/Chmod leaving a partial key — is exactly the
	// No-Silent-Success failure NockLock exists to prevent, here on our own
	// signing key. So the Close error is checked, not discarded, and on ANY
	// failure the partial key is removed before returning.
	fail := func(werr error) (*signer, error) {
		closeErr := f.Close()
		removeErr := os.Remove(path) // never leave a corrupt/partial key behind
		return nil, errors.Join(werr, closeErr, removeErr)
	}

	pub, priv, err := ed25519.GenerateKey(signingRand)
	if err != nil {
		return fail(fmt.Errorf("failed to generate Ed25519 signing key: %w", err))
	}
	seed := priv.Seed()
	if _, err := f.Write(seed); err != nil {
		return fail(fmt.Errorf("failed to write signing key seed: %w", err))
	}
	if err := f.Chmod(0o600); err != nil {
		return fail(fmt.Errorf("failed to set signing key permissions: %w", err))
	}
	// Close explicitly and surface its error (a discarded deferred Close could
	// hide a flush failure that truncated the key).
	if err := f.Close(); err != nil {
		if removeErr := os.Remove(path); removeErr != nil {
			return nil, fmt.Errorf("failed to close signing key file at %s: %w", path, errors.Join(err, removeErr))
		}
		return nil, fmt.Errorf("failed to close signing key file at %s: %w", path, err)
	}
	return &signer{priv: priv, pub: pub}, nil
}

// validateSigningKeyDirectory creates and validates the managed key directory.
// Every existing path component must be real (not symlinked), aside from a
// trusted platform alias, and the final directory must be private to the
// current owner before a key is created or loaded from it.
func validateSigningKeyDirectory(dir string, create bool) (string, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve signing key directory %s: %w", dir, err)
	}
	absDir = filepath.Clean(absDir)
	if create {
		if err := os.MkdirAll(absDir, 0o700); err != nil {
			return "", fmt.Errorf("failed to create signing key directory %s: %w", absDir, err)
		}
	} else if _, err := os.Lstat(absDir); err != nil {
		return "", err
	}
	resolvedDir, err := filepath.EvalSymlinks(absDir)
	if err != nil {
		return "", fmt.Errorf("failed to resolve signing key directory %s: %w", absDir, err)
	}
	resolvedDir = filepath.Clean(resolvedDir)
	if resolvedDir != absDir && !isTrustedSigningKeyDirectoryAlias(absDir, resolvedDir) {
		return "", fmt.Errorf("refusing to use signing key directory %s: path contains a symlink", absDir)
	}
	info, err := os.Lstat(resolvedDir)
	if err != nil {
		return "", fmt.Errorf("failed to stat signing key directory %s: %w", resolvedDir, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return "", fmt.Errorf("refusing to use signing key directory %s: not a real directory", resolvedDir)
	}
	if info.Mode().Perm() != 0o700 {
		return "", fmt.Errorf("refusing to use signing key directory %s: permissions %o, want 0700", resolvedDir, info.Mode().Perm())
	}
	if err := validateSigningKeyDirectoryOwner(info); err != nil {
		return "", fmt.Errorf("refusing to use signing key directory %s: %w", resolvedDir, err)
	}
	return resolvedDir, nil
}

// loadSigner reads and validates an existing signing key file. It rejects a
// symlink, a non-regular file, or one that is group/world accessible, then
// reconstructs the private key from its 32-byte seed. Errors from a missing
// file are returned unwrapped enough for errors.Is(err, os.ErrNotExist).
func loadSigner(path string) (*signer, error) {
	dir, err := validateSigningKeyDirectory(filepath.Dir(path), false)
	if err != nil {
		return nil, err
	}
	path = filepath.Join(dir, filepath.Base(path))

	// Reject a symlink before opening; O_NOFOLLOW below is the authoritative
	// guard that also closes the lstat->open TOCTOU window.
	if fi, err := os.Lstat(path); err != nil {
		return nil, err // preserves os.ErrNotExist for the caller
	} else if fi.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("refusing to use signing key at %s: path is a symlink", path)
	}

	f, err := os.OpenFile(path, os.O_RDONLY|oNoFollow, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("failed to stat signing key at %s: %w", path, err)
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("refusing to use signing key at %s: not a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return nil, fmt.Errorf("refusing to use signing key at %s: permissions %o are group/world accessible, want 0600", path, perm)
	}

	seed, err := io.ReadAll(io.LimitReader(f, signingSeedLen+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read signing key at %s: %w", path, err)
	}
	if len(seed) != signingSeedLen {
		return nil, fmt.Errorf("refusing to use signing key at %s: seed is %d bytes, want %d", path, len(seed), signingSeedLen)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	return &signer{priv: priv, pub: pub}, nil
}

// loadPublicKey returns just the public key from an existing key file, without
// creating one. A missing file surfaces os.ErrNotExist so verify can fall back
// to a hash-only (unsigned) check rather than failing.
func loadPublicKey(path string) (ed25519.PublicKey, error) {
	s, err := loadSigner(path)
	if err != nil {
		return nil, err
	}
	return s.pub, nil
}

// LoadPublicKeyFile returns the public key from the managed signing key file
// without creating one. A missing file surfaces os.ErrNotExist so callers can
// fall back to a hash-only (unsigned) verification.
func LoadPublicKeyFile(path string) (ed25519.PublicKey, error) {
	return loadPublicKey(path)
}

// EnsurePublicKeyFile returns the public key from the managed signing key file,
// generating the key on first use if absent (for `verify --export-pubkey`). The
// private key is never returned or printed.
func EnsurePublicKeyFile(path string) (ed25519.PublicKey, error) {
	s, err := loadOrCreateSigner(path)
	if err != nil {
		return nil, err
	}
	return s.pub, nil
}

// signRow returns the base64 signature over a row's canonical bytes — the exact
// bytes the hash chain already covers (canonicalBytes), reused, not re-encoded.
func (s *signer) signRow(canonical []byte) string {
	return base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, canonical))
}

// headCanonicalBytes returns the domain-separated canonical bytes for the
// chain_head record. In addition to the hash and row count, it authenticates
// pruning, signing-adoption, and public-key metadata so database-only changes
// to those fields cannot still verify as authentic.
func headCanonicalBytes(headHashHex string, rowCount int, meta headSignatureMetadata) ([]byte, error) {
	hb, err := hex.DecodeString(headHashHex)
	if err != nil {
		return nil, fmt.Errorf("invalid head hash hex: %w", err)
	}
	if len(hb) != 32 {
		return nil, fmt.Errorf("head hash must be 32 bytes, got %d", len(hb))
	}
	fingerprint, err := hex.DecodeString(meta.publicKeyFingerprintHex)
	if err != nil || len(fingerprint) != sha256.Size {
		return nil, fmt.Errorf("signing public key fingerprint must be %d bytes of hex", sha256.Size)
	}
	buf := make([]byte, 0, 1+32+8+2*(1+4)+2*(1+8)+sha256.Size)
	buf = append(buf, headSigVersion)
	buf = append(buf, hb...)
	var cnt [8]byte
	binary.BigEndian.PutUint64(cnt[:], uint64(rowCount))
	buf = append(buf, cnt[:]...)
	buf = appendHeadOptionalString(buf, meta.prunedAt)
	buf = appendHeadOptionalInt(buf, meta.prunedCount)
	buf = appendHeadOptionalString(buf, meta.signedGenesisAt)
	buf = appendHeadOptionalInt64(buf, meta.unsignedThroughID)
	buf = append(buf, fingerprint...)
	return buf, nil
}

func appendHeadOptionalString(buf []byte, value *string) []byte {
	if value == nil {
		return append(buf, 0)
	}
	buf = append(buf, 1)
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(*value)))
	buf = append(buf, length[:]...)
	return append(buf, (*value)...)
}

func appendHeadOptionalInt(buf []byte, value *int) []byte {
	if value == nil {
		return append(buf, 0)
	}
	buf = append(buf, 1)
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(*value))
	return append(buf, encoded[:]...)
}

func appendHeadOptionalInt64(buf []byte, value *int64) []byte {
	if value == nil {
		return append(buf, 0)
	}
	buf = append(buf, 1)
	var encoded [8]byte
	binary.BigEndian.PutUint64(encoded[:], uint64(*value))
	return append(buf, encoded[:]...)
}

// signHead returns the base64 head signature, or "" when signing is off.
func signHead(s *signer, headHashHex string, rowCount int, meta headSignatureMetadata) (string, error) {
	if s == nil {
		return "", nil
	}
	hb, err := headCanonicalBytes(headHashHex, rowCount, meta)
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(ed25519.Sign(s.priv, hb)), nil
}

// verifyRowSig checks a base64 row signature against the row's canonical bytes.
func verifyRowSig(pub ed25519.PublicKey, canonical []byte, sigB64 string) bool {
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, canonical, sig)
}

// verifyHeadSig checks a base64 head signature against the head canonical bytes.
func verifyHeadSig(pub ed25519.PublicKey, headHashHex string, rowCount int, meta headSignatureMetadata, sigB64 string) bool {
	hb, err := headCanonicalBytes(headHashHex, rowCount, meta)
	if err != nil {
		return false
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, hb, sig)
}

func publicKeyFingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:])
}

// ParsePublicKey decodes a public key supplied out-of-band (--ed25519-pub / env)
// in standard base64 or hex.
func ParsePublicKey(s string) (ed25519.PublicKey, error) {
	if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}
	if b, err := hex.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
		return ed25519.PublicKey(b), nil
	}
	return nil, fmt.Errorf("public key must be %d bytes encoded as base64 or hex", ed25519.PublicKeySize)
}

// EncodePublicKey renders a public key as standard base64 for out-of-band use.
func EncodePublicKey(pub ed25519.PublicKey) string {
	return base64.StdEncoding.EncodeToString(pub)
}
