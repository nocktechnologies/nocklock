package logging

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/nocktechnologies/nocklock/internal/config"
)

// ChainIdentityFileName names the trusted record in the project's external
// audit state directory. It is never selected by logging.db or stored in the DB.
const ChainIdentityFileName = "chain-identity.json"

const chainIdentityLockName = "chain-identity.lock"

// ChainRegistrationState records whether the remote store might hold a pin.
// Transitions are monotonic: none -> pending -> enrolled. Pending is persisted
// before sending registration and is never cleared on errors or rejection.
type ChainRegistrationState string

const (
	// ChainRegistrationNone means no registration has ever been sent.
	ChainRegistrationNone ChainRegistrationState = "none"
	// ChainRegistrationPending means registration may have reached the store.
	ChainRegistrationPending ChainRegistrationState = "pending"
	// ChainRegistrationEnrolled means the store confirmed the exact pair.
	ChainRegistrationEnrolled ChainRegistrationState = "enrolled"
)

// ErrChainIdentityMissing means both trusted record and DB identity are absent.
// It is a legacy chain, not permission to create an ID during push or verify.
var ErrChainIdentityMissing = errors.New("chain identity is not initialized; explicit operator enrollment is required")

// ChainIdentity binds one audit chain to its trusted expected identity. The
// immutable fields are mirrored in SQLite; RegistrationState exists only in
// this external record so a database rollback cannot undo a pending remote pin.
// The record's schema Version is independent of the anchor record version.
type ChainIdentity struct {
	Version            int                    `json:"version"`
	AgentID            string                 `json:"agent_id"`
	ChainID            string                 `json:"chain_id"`
	LegacyAnchorDigest string                 `json:"legacy_anchor_digest"`
	RegistrationState  ChainRegistrationState `json:"registration_state"`
}

// ChainRegistrationConfirmation identifies the pair the store confirmed.
// The registration callback may return it only after verifying a successful
// registration, or an existing remote pin for exactly this pair and snapshot.
// HTTP status alone (including an unverified 409) is not confirmation.
type ChainRegistrationConfirmation struct {
	AgentID string
	ChainID string
}

// InitializeChainIdentity explicitly creates a random identity for a selected
// chain. It requires a signing logger and a canonical legacy witness digest
// (64 zeroes for a fresh chain). Callers must first verify the selected chain
// and obtain operator authorization for enrollment/migration. It does not send
// a registration, mint an ID on read, or infer ownership of a legacy anchor.
// Repeating with an existing matching identity returns it unchanged; partial
// creation or mismatched state fails closed and requires operator recovery.
func (l *Logger) InitializeChainIdentity(legacyAnchorDigest string) (*ChainIdentity, error) {
	if l.signer == nil {
		return nil, errors.New("initializing chain identity requires the audit signing key")
	}
	if _, err := anchorHex32("legacy_anchor_digest", legacyAnchorDigest); err != nil {
		return nil, err
	}
	store, err := l.lockChainIdentityStore()
	if err != nil {
		return nil, err
	}
	defer store.close()
	identity, err := l.readChainIdentityLocked(store)
	if err != nil {
		return nil, err
	}
	if identity != nil {
		if identity.LegacyAnchorDigest != legacyAnchorDigest {
			return nil, errors.New("chain identity already has a different legacy witness; archive the old chain before explicit enrollment of a fresh chain")
		}
		return identity, nil
	}
	var randomID [32]byte
	if _, err := rand.Read(randomID[:]); err != nil {
		return nil, fmt.Errorf("cannot generate chain identity: %w", err)
	}
	identity = &ChainIdentity{Version: 1, AgentID: publicKeyFingerprint(l.signer.pub), ChainID: hex.EncodeToString(randomID[:]), LegacyAnchorDigest: legacyAnchorDigest, RegistrationState: ChainRegistrationNone}
	// Commit the mirror first. If writing the trusted record fails or the
	// process dies between stores, the mirror refuses future prune/creation.
	// Never repair that partial state by silently minting another identity.
	if _, err := l.db.Exec("INSERT INTO chain_identity (id, version, agent_id, chain_id, legacy_anchor_digest) VALUES (1, ?, ?, ?, ?)", identity.Version, identity.AgentID, identity.ChainID, identity.LegacyAnchorDigest); err != nil {
		return nil, fmt.Errorf("cannot persist chain identity mirror: %w", err)
	}
	if err := store.write(identity); err != nil {
		return nil, err
	}
	return identity, nil
}

// ReadChainIdentity reads under the shared identity lock and requires the
// trusted record and DB mirror to agree. A missing, malformed, or mismatched
// record never falls back to the DB's identity. Both absent returns
// ErrChainIdentityMissing. V2 emit/push/verify callers must use this check.
func (l *Logger) ReadChainIdentity() (*ChainIdentity, error) {
	if l.projectRoot == "" {
		mirror, err := l.readChainIdentityMirror()
		if err != nil {
			return nil, err
		}
		if mirror == nil {
			return nil, ErrChainIdentityMissing
		}
		return nil, errors.New("chain identity requires the project root; follow docs/runbooks/chain-identity-move.md")
	}
	store, err := l.lockChainIdentityStore()
	if err != nil {
		return nil, err
	}
	defer store.close()
	identity, err := l.readChainIdentityLocked(store)
	if err != nil {
		return nil, err
	}
	if identity == nil {
		return nil, ErrChainIdentityMissing
	}
	return identity, nil
}

// ChainIdentityDirectory returns the validated external directory to deny to a
// fenced child when this chain has a trusted identity. An entirely legacy chain
// returns an empty path without creating state. logging.db cannot select or
// bypass this directory; incomplete or mismatched identity state is an error.
func (l *Logger) ChainIdentityDirectory() (string, error) {
	mirror, err := l.readChainIdentityMirror()
	if err != nil {
		return "", err
	}
	if l.projectRoot == "" {
		if mirror == nil {
			return "", nil
		}
		return "", errors.New("chain identity requires the project root; follow docs/runbooks/chain-identity-move.md")
	}
	dir, err := config.AuditStateDir(l.projectRoot)
	if err != nil {
		return "", err
	}
	_, err = os.Lstat(filepath.Join(dir, ChainIdentityFileName))
	if mirror == nil && errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("cannot inspect trusted chain identity: %w", err)
	}
	if _, err := l.ReadChainIdentity(); err != nil {
		return "", err
	}
	return config.EnsureAuditStateDir(l.projectRoot)
}

// RegisterChainIdentity serializes registration with prune and persists pending
// durably before invoking register. The callback must use a bounded deadline
// and affirm the exact trusted pair only after authenticating the store's
// response. Every error, panic, timeout or interrupted process leaves pending;
// there is no transition back to none. Already enrolled is an idempotent no-op.
// No network behavior is implemented here. The callback must not call identity
// lifecycle methods or Prune on this chain (the shared lock is already held).
func (l *Logger) RegisterChainIdentity(register func(ChainIdentity) (*ChainRegistrationConfirmation, error)) (*ChainIdentity, error) {
	if register == nil {
		return nil, errors.New("chain registration requires a confirmation callback")
	}
	store, err := l.lockChainIdentityStore()
	if err != nil {
		return nil, err
	}
	defer store.close()
	identity, err := l.readChainIdentityLocked(store)
	if err != nil {
		return nil, err
	}
	if identity == nil {
		return nil, ErrChainIdentityMissing
	}
	return l.registerChainIdentityLocked(store, identity, register)
}

func (l *Logger) registerChainIdentityLocked(store *chainIdentityStore, identity *ChainIdentity, register func(ChainIdentity) (*ChainRegistrationConfirmation, error)) (*ChainIdentity, error) {
	if identity.RegistrationState == ChainRegistrationEnrolled {
		return identity, nil
	}
	if identity.RegistrationState == ChainRegistrationNone {
		identity.RegistrationState = ChainRegistrationPending
		if err := store.write(identity); err != nil {
			return nil, err
		}
	}
	confirmation, err := register(*identity)
	if err != nil {
		return nil, fmt.Errorf("registration remains pending; the remote pin may exist: %w; archive the old DB and enroll a fresh chain if recovery is impossible", err)
	}
	if confirmation == nil || confirmation.AgentID != identity.AgentID || confirmation.ChainID != identity.ChainID {
		return nil, errors.New("registration remains pending: store confirmation does not affirm the exact trusted pair; do not clear the remote pin")
	}
	identity.RegistrationState = ChainRegistrationEnrolled
	if err := store.write(identity); err != nil {
		return nil, err
	}
	return identity, nil
}

func (l *Logger) lockPruneIdentity() (func(), error) {
	if !identityLockSupported {
		// These platforms cannot initialize/register an identity, so there is
		// no competing enrollment operation to lock against. Preserve legacy
		// pruning only when neither trusted state nor a DB mirror exists.
		if err := l.allowLegacyPruneWithoutIdentity(); err != nil {
			return nil, err
		}
		return func() {}, nil
	}
	if l.projectRoot == "" {
		_, err := l.ReadChainIdentity()
		if errors.Is(err, ErrChainIdentityMissing) {
			return func() {}, nil // Legacy library callers without project context.
		}
		return nil, err
	}
	store, err := l.lockChainIdentityStore()
	if err != nil {
		return nil, err
	}
	identity, err := l.readChainIdentityLocked(store)
	if err == nil && identity != nil && identity.RegistrationState != ChainRegistrationNone {
		err = fmt.Errorf("refusing prune: remote pin for (%s, %s) is %s; archive the old DB and enroll a fresh chain to bound growth; for moved state follow docs/runbooks/chain-identity-move.md", identity.AgentID, identity.ChainID, identity.RegistrationState)
	}
	if err != nil {
		store.close()
		return nil, err
	}
	return store.close, nil
}

func (l *Logger) allowLegacyPruneWithoutIdentity() error {
	dir, err := l.ChainIdentityDirectory()
	if err != nil {
		return err
	}
	if dir != "" {
		return errors.New("trusted chain identity prune checks require Linux or macOS; remote pin preserved")
	}
	return nil
}

func (l *Logger) readChainIdentityMirror() (*ChainIdentity, error) {
	var identity ChainIdentity
	rows, err := l.db.Query("SELECT id, version, agent_id, chain_id, legacy_anchor_digest FROM chain_identity")
	if err != nil {
		return nil, fmt.Errorf("cannot read chain identity mirror: %w", err)
	}
	defer rows.Close()
	if !rows.Next() {
		return nil, rows.Err()
	}
	var id int
	if err := rows.Scan(&id, &identity.Version, &identity.AgentID, &identity.ChainID, &identity.LegacyAnchorDigest); err != nil {
		return nil, fmt.Errorf("cannot decode chain identity mirror: %w", err)
	}
	if id != 1 || rows.Next() {
		return nil, errors.New("chain identity mirror must contain exactly one row with id 1")
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	identity.RegistrationState = ChainRegistrationNone // State is trusted-file-only.
	if err := validateChainIdentity(&identity); err != nil {
		return nil, fmt.Errorf("invalid chain identity mirror: %w", err)
	}
	return &identity, nil
}

func (l *Logger) readChainIdentityLocked(store *chainIdentityStore) (*ChainIdentity, error) {
	mirror, err := l.readChainIdentityMirror()
	if err != nil {
		return nil, err
	}
	identity, err := store.read()
	if err != nil {
		return nil, err
	}
	if mirror == nil && identity == nil {
		return nil, nil
	}
	if mirror == nil || identity == nil {
		return nil, errors.New("refusing chain operation: trusted identity record and DB mirror are incomplete; remote pin may exist; follow docs/runbooks/chain-identity-move.md, never mint a replacement ID")
	}
	if mirror.Version != identity.Version || mirror.AgentID != identity.AgentID || mirror.ChainID != identity.ChainID || mirror.LegacyAnchorDigest != identity.LegacyAnchorDigest {
		return nil, errors.New("refusing chain operation: trusted identity and DB mirror disagree; preserve the remote pin and follow docs/runbooks/chain-identity-move.md")
	}
	if l.signer != nil && publicKeyFingerprint(l.signer.pub) != identity.AgentID {
		return nil, errors.New("chain identity does not match the loaded signing key; restore the original key before enrollment")
	}
	return identity, nil
}

func validateChainIdentity(identity *ChainIdentity) error {
	if identity.Version != 1 {
		return errors.New("unsupported chain identity schema: require version 1")
	}
	for _, field := range []struct{ name, value string }{{"agent_id", identity.AgentID}, {"chain_id", identity.ChainID}, {"legacy_anchor_digest", identity.LegacyAnchorDigest}} {
		if _, err := anchorHex32(field.name, field.value); err != nil {
			return err
		}
	}
	switch identity.RegistrationState {
	case ChainRegistrationNone, ChainRegistrationPending, ChainRegistrationEnrolled:
		return nil
	default:
		return errors.New("invalid chain registration state; preserve the remote pin and recover the trusted record")
	}
}

type chainIdentityStore struct {
	root *os.Root
	lock *os.File
}

func (s *chainIdentityStore) close() {
	// Closing the persistent lock descriptor releases its OS lock. Never unlink
	// or rename the lock file: other processes must keep locking the same inode.
	s.lock.Close()
	s.root.Close()
}

func (l *Logger) lockChainIdentityStore() (*chainIdentityStore, error) {
	if l.projectRoot == "" {
		return nil, errors.New("chain identity requires an explicit project root")
	}
	dir, err := config.EnsureAuditStateDir(l.projectRoot)
	if err != nil {
		return nil, fmt.Errorf("cannot protect trusted chain identity directory: %w", err)
	}
	if pathContains(l.projectRoot, dir) {
		return nil, errors.New("trusted chain identity directory must be outside the fenced project; move XDG_STATE_HOME outside the project")
	}
	before, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	opened, err := root.Stat(".")
	if err != nil || !os.SameFile(before, opened) {
		root.Close()
		return nil, errors.New("trusted chain identity directory changed while opening; refusing operation")
	}
	lock, err := openChainIdentityLock(root)
	if err != nil {
		root.Close()
		return nil, fmt.Errorf("cannot open trusted chain identity lock: %w", err)
	}
	store := &chainIdentityStore{root: root, lock: lock}
	if err := store.checkFile(chainIdentityLockName, lock); err != nil {
		store.close()
		return nil, err
	}
	if err := lockIdentityFile(lock); err != nil {
		store.close()
		return nil, fmt.Errorf("cannot lock trusted chain identity: %w", err)
	}
	// Catch a replacement while we were waiting on another process's lock.
	if err := store.checkFile(chainIdentityLockName, lock); err != nil {
		store.close()
		return nil, err
	}
	return store, nil
}

func openChainIdentityLock(root *os.Root) (*os.File, error) {
	// Distinguish first creation from opening the winner's inode. Concurrent
	// non-exclusive Root.OpenFile(O_CREATE) calls can return ENOENT on macOS.
	// O_EXCL makes creation atomic; only EEXIST permits opening the existing
	// file, still relative to the same anchored root and without symlink follow.
	flags := os.O_RDWR | oNoFollow | identityNonBlock
	f, err := root.OpenFile(chainIdentityLockName, flags|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return root.OpenFile(chainIdentityLockName, flags, 0)
	}
	return f, err
}

func (s *chainIdentityStore) checkFile(name string, f *os.File) error {
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("trusted chain identity file %s must be regular and not group/world-writable", name)
	}
	if err := validateIdentityFileOwner(info); err != nil {
		return err
	}
	entry, err := s.root.Lstat(name)
	if err != nil || entry.Mode()&os.ModeSymlink != 0 || !os.SameFile(info, entry) {
		return fmt.Errorf("trusted chain identity file %s changed or is a symlink; refusing operation", name)
	}
	return nil
}

func (s *chainIdentityStore) read() (*ChainIdentity, error) {
	data, err := s.readData(ChainIdentityFileName, 4096)
	if err != nil || data == nil {
		return nil, err
	}
	var identity ChainIdentity
	if err := json.Unmarshal(data, &identity); err != nil {
		return nil, fmt.Errorf("invalid trusted chain identity JSON: %w", err)
	}
	if err := validateChainIdentity(&identity); err != nil {
		return nil, err
	}
	// This operator-owned machine record has one encoding. Comparing it also
	// rejects duplicate, unknown, missing, null and case-folded JSON fields.
	canonical, _ := json.Marshal(&identity)
	if !bytes.Equal(bytes.TrimSpace(data), canonical) {
		return nil, errors.New("trusted chain identity record is not canonical; recover the original record without editing its identity or registration state")
	}
	return &identity, nil
}

func (s *chainIdentityStore) readData(name string, limit int64) ([]byte, error) {
	f, err := s.root.OpenFile(name, os.O_RDONLY|oNoFollow|identityNonBlock, 0)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("cannot read trusted chain identity: %w", err)
	}
	defer f.Close()
	if err := s.checkFile(name, f); err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil || int64(len(data)) > limit {
		return nil, errors.New("cannot read trusted chain identity: invalid or oversized record")
	}
	return data, nil
}

func (s *chainIdentityStore) write(identity *ChainIdentity) error {
	if err := validateChainIdentity(identity); err != nil {
		return err
	}
	data, err := json.Marshal(identity)
	if err != nil {
		return err
	}
	return s.writeData(ChainIdentityFileName, data)
}

func (s *chainIdentityStore) writeData(name string, data []byte) error {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	tmpName := ".chain-identity-" + hex.EncodeToString(nonce[:]) + ".tmp"
	f, err := s.root.OpenFile(tmpName, os.O_CREATE|os.O_EXCL|os.O_WRONLY|oNoFollow, 0o600)
	if err != nil {
		return fmt.Errorf("cannot create trusted chain identity update: %w", err)
	}
	defer s.root.Remove(tmpName)
	_, writeErr := f.Write(append(data, '\n'))
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return fmt.Errorf("cannot persist trusted chain identity update: %w", err)
	}
	if err := s.root.Rename(tmpName, name); err != nil {
		return fmt.Errorf("cannot replace trusted chain identity: %w", err)
	}
	dir, err := s.root.Open(".")
	if err != nil {
		return fmt.Errorf("cannot sync trusted chain identity directory: %w", err)
	}
	err = errors.Join(dir.Sync(), dir.Close())
	if err != nil {
		return fmt.Errorf("cannot sync trusted chain identity directory: %w", err)
	}
	// EnsureAuditStateDir may have just created several ancestors. Persist
	// their directory entries too: losing the whole new state directory after
	// a power failure must not erase a pending remote registration.
	for parent := filepath.Dir(s.root.Name()); ; parent = filepath.Dir(parent) {
		dir, err := os.Open(parent)
		if err != nil {
			return fmt.Errorf("cannot sync trusted chain identity ancestor: %w", err)
		}
		if err := errors.Join(dir.Sync(), dir.Close()); err != nil {
			return fmt.Errorf("cannot sync trusted chain identity ancestor: %w", err)
		}
		if filepath.Dir(parent) == parent {
			break
		}
	}
	return nil
}
