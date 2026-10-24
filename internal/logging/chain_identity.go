package logging

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
)

// ChainIdentityFileName names the trusted record in the project's external
// audit state directory. It is never selected by logging.db or stored in the DB.
const ChainIdentityFileName = "chain-identity.json"

// ChainIdentityLockName is the lock file beside ChainIdentityFileName that
// serializes identity reads and writes; it is never unlinked or replaced.
const ChainIdentityLockName = "chain-identity.lock"

const pruneIdentityLockTimeout = 5 * time.Second

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
	return l.InitializeChainIdentityContext(context.Background(), legacyAnchorDigest)
}

// InitializeChainIdentityContext is InitializeChainIdentity with cancellable identity-lock acquisition.
// Once a durable write starts, it completes synchronously before returning.
func (l *Logger) InitializeChainIdentityContext(ctx context.Context, legacyAnchorDigest string) (*ChainIdentity, error) {
	if l.signer == nil {
		return nil, errors.New("initializing chain identity requires the audit signing key")
	}
	if _, err := anchorHex32("legacy_anchor_digest", legacyAnchorDigest); err != nil {
		return nil, err
	}
	store, err := l.lockChainIdentityStoreContext(ctx)
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
	// Establish previously legacy-created ancestry before even the DB mirror
	// changes. Unsupported directory durability must not poison a legacy chain.
	if err := store.prepareWrite(); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
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
	return l.ReadChainIdentityContext(context.Background())
}

// ReadChainIdentityContext is ReadChainIdentity with cancellable identity-lock acquisition.
func (l *Logger) ReadChainIdentityContext(ctx context.Context) (*ChainIdentity, error) {
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
	store, err := l.lockChainIdentityStoreContext(ctx)
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
	return l.ChainIdentityDirectoryContext(context.Background())
}

// ChainIdentityDirectoryContext is ChainIdentityDirectory with cancellable identity-lock acquisition.
func (l *Logger) ChainIdentityDirectoryContext(ctx context.Context) (string, error) {
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
	if _, err := l.ReadChainIdentityContext(ctx); err != nil {
		return "", err
	}
	return config.EnsureAuditStateDir(l.projectRoot)
}

// RegisterChainIdentity serializes registration with prune and persists pending
// durably before invoking register. The callback must use a bounded deadline
// and affirm the exact trusted pair only after authenticating the store's
// response. Request errors, panics, timeouts or interruptions leave pending;
// there is no transition back to none. A post-rename durability error preserves
// the visible replacement. Already enrolled is an idempotent no-op.
// No network behavior is implemented here. The callback must not call identity
// lifecycle methods or Prune on this chain (the shared lock is already held).
func (l *Logger) RegisterChainIdentity(register func(ChainIdentity) (*ChainRegistrationConfirmation, error)) (*ChainIdentity, error) {
	return l.RegisterChainIdentityContext(context.Background(), register)
}

// RegisterChainIdentityContext is RegisterChainIdentity with cancellable identity-lock acquisition.
// Once a durable write starts, it completes synchronously before returning.
func (l *Logger) RegisterChainIdentityContext(ctx context.Context, register func(ChainIdentity) (*ChainRegistrationConfirmation, error)) (*ChainIdentity, error) {
	if l.signer == nil {
		return nil, errors.New("chain registration requires the existing signing key")
	}
	if register == nil {
		return nil, errors.New("chain registration requires a confirmation callback")
	}
	store, err := l.lockChainIdentityStoreContext(ctx)
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
	return l.registerChainIdentityLocked(ctx, store, identity, register)
}

func (l *Logger) registerChainIdentityLocked(ctx context.Context, store *chainIdentityStore, identity *ChainIdentity, register func(ChainIdentity) (*ChainRegistrationConfirmation, error)) (*ChainIdentity, error) {
	if identity.RegistrationState == ChainRegistrationEnrolled {
		return identity, nil
	}
	// A prior rename may have succeeded while its directory fsync failed.
	// Never infer durability from finding pending: every retry re-establishes
	// the complete file and directory barrier before any remote side effect.
	identity.RegistrationState = ChainRegistrationPending
	if err := store.write(identity); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err // pending is durable; cancellation never resets it
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
	if l.projectRoot == "" {
		return nil, errors.New("refusing prune without an explicit project root: a rolled-back DB cannot prove absence of a remote pin; reopen with project context and follow docs/runbooks/chain-identity-move.md")
	}
	if !identityLockSupported {
		// These platforms cannot initialize/register an identity, so there is
		// no competing enrollment operation to lock against. Preserve legacy
		// pruning only when neither trusted state nor a DB mirror exists.
		if err := l.allowLegacyPruneWithoutIdentity(); err != nil {
			return nil, err
		}
		return func() {}, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), pruneIdentityLockTimeout)
	defer cancel()
	store, err := l.lockChainIdentityStoreContext(ctx)
	if err != nil {
		return nil, err
	}
	identity, err := l.readChainIdentityLocked(store)
	if err == nil && identity != nil && identity.RegistrationState != ChainRegistrationNone {
		err = fmt.Errorf("refusing prune: remote pin for (%s, %s) is %s; archive the old DB and enroll a fresh chain to bound growth; for moved state follow docs/runbooks/chain-identity-move.md", identity.AgentID, identity.ChainID, identity.RegistrationState)
	}
	if err == nil {
		var request []byte
		request, err = store.readData(AnchorRegistrationFileName, 16384)
		if err == nil && request != nil {
			err = errors.New("refusing prune: retained original anchor registration request requires this signed history; retry the original anchor enroll or anchor migrate before archiving the chain")
		}
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
	stateDir, err := config.AuditStateDir(l.projectRoot)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(stateDir, AnchorRegistrationFileName)); err == nil {
		return errors.New("refusing prune: retained original anchor registration request requires Linux or macOS to validate; signed history preserved")
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("cannot inspect retained anchor registration request: %w", err)
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
	root         *os.Root
	lock         *os.File
	syncRoot     string
	syncFile     func(*os.File) error
	syncRootFile func(*os.File) error
	rootDurable  bool
}

// ChainIdentityDurabilityError means the replacement record is visible, but a
// directory barrier failed. It must not be treated as an uncommitted write or
// permission to send registration. Retrying pending registration redoes all barriers.
type ChainIdentityDurabilityError struct{ Err error }

// Error describes the committed replacement and required retry.
func (e *ChainIdentityDurabilityError) Error() string {
	return "trusted chain identity replacement committed, but durability is uncertain; preserve its visible state and retry the operation: " + e.Err.Error()
}

// Unwrap returns the directory synchronization failure.
func (e *ChainIdentityDurabilityError) Unwrap() error { return e.Err }

// TrustedChainStateDirectory returns the canonical external audit-state
// directory to protect even before an identity is created. It does not mint an
// identity. A configured logging.db cannot change this trusted location.
func (l *Logger) TrustedChainStateDirectory() (string, error) {
	dir, _, err := l.trustedChainStateLocation()
	return dir, err
}

func (l *Logger) trustedChainStateLocation() (string, string, error) {
	if l.projectRoot == "" {
		return "", "", errors.New("chain identity requires an explicit project root")
	}
	dir, root, err := config.EnsureAuditStateLocation(l.projectRoot)
	if err != nil {
		return "", "", fmt.Errorf("cannot protect trusted chain identity directory: %w", err)
	}
	if pathContains(l.projectRoot, dir) {
		return "", "", errors.New("trusted chain identity directory must be outside the fenced project; move XDG_STATE_HOME outside the project")
	}
	if dir == root || !pathContains(root, dir) {
		return "", "", errors.New("trusted chain identity directory must be strictly below its state root; refusing operation")
	}
	return dir, root, nil
}

func (s *chainIdentityStore) close() {
	// Closing the persistent lock descriptor releases its OS lock. Never unlink
	// or rename the lock file: other processes must keep locking the same inode.
	s.lock.Close()
	s.root.Close()
}

func (l *Logger) lockChainIdentityStore() (*chainIdentityStore, error) {
	return l.lockChainIdentityStoreContext(context.Background())
}

func (l *Logger) lockChainIdentityStoreContext(ctx context.Context) (*chainIdentityStore, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	dir, syncRoot, err := l.trustedChainStateLocation()
	if err != nil {
		return nil, err
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
	syncFile := l.identitySync
	if syncFile == nil {
		syncFile = (*os.File).Sync
	}
	syncRootFile := l.identityRootSync
	if syncRootFile == nil {
		syncRootFile = (*os.File).Sync
	}
	store := &chainIdentityStore{root: root, lock: lock, syncRoot: syncRoot, syncFile: syncFile, syncRootFile: syncRootFile}
	if err := store.checkFile(ChainIdentityLockName, lock); err != nil {
		store.close()
		return nil, err
	}
	if err := lockIdentityFileContext(ctx, lock); err != nil {
		store.close()
		return nil, fmt.Errorf("cannot lock trusted chain identity: %w", err)
	}
	// Catch a replacement while we were waiting on another process's lock.
	if err := store.checkFile(ChainIdentityLockName, lock); err != nil {
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
	f, err := root.OpenFile(ChainIdentityLockName, flags|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return root.OpenFile(ChainIdentityLockName, flags, 0)
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

// prepareWrite establishes the configured root's complete existing lineage
// before changing trusted state. Legacy path resolution may have created any
// number of ancestors without directory fsync; existence is not proof of their
// durability. Only identity mutation pays this stricter requirement. Reads,
// legacy logging and prune do not call it. The post-rename barrier remains
// bounded by syncRoot, and every new locked mutation performs its own preflight.
func (s *chainIdentityStore) prepareWrite() error {
	if s.rootDurable {
		return nil
	}
	for path := s.syncRoot; ; path = filepath.Dir(path) {
		dir, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("cannot establish trusted identity storage durability before writing: %w", err)
		}
		if err := errors.Join(s.syncRootFile(dir), dir.Close()); err != nil {
			return fmt.Errorf("cannot establish trusted identity storage durability before writing: %w", err)
		}
		if filepath.Dir(path) == path {
			break
		}
	}
	s.rootDurable = true
	return nil
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
	if err := s.prepareWrite(); err != nil {
		return err
	}
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
	syncErr := s.syncFile(f)
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return fmt.Errorf("cannot persist trusted chain identity update: %w", err)
	}
	if err := s.root.Rename(tmpName, name); err != nil {
		return fmt.Errorf("cannot replace trusted chain identity: %w", err)
	}
	// Rename committed the replacement. Subsequent errors mean visible but
	// uncertain durability, not that the old record is still present.
	dir, err := s.root.Open(".")
	if err != nil {
		return &ChainIdentityDurabilityError{Err: err}
	}
	if err := errors.Join(s.syncFile(dir), dir.Close()); err != nil {
		return &ChainIdentityDurabilityError{Err: err}
	}
	// Persist NockLock-owned directory entries through the configured state
	// root only. prepareWrite already established the root's ancestry before
	// mutation; post-rename uncertainty is bounded to this owned subtree.
	for parent := filepath.Dir(s.root.Name()); ; parent = filepath.Dir(parent) {
		dir, err := os.Open(parent)
		if err != nil {
			return &ChainIdentityDurabilityError{Err: err}
		}
		if err := errors.Join(s.syncFile(dir), dir.Close()); err != nil {
			return &ChainIdentityDurabilityError{Err: err}
		}
		if parent == s.syncRoot {
			break
		}
		if filepath.Dir(parent) == parent {
			return &ChainIdentityDurabilityError{Err: errors.New("cannot reach the configured state root while syncing; preserve the record and correct the state path")}
		}
	}
	return nil
}
