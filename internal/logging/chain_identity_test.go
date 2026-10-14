//go:build linux || darwin

package logging

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
)

type identityFixture struct {
	logger                   *Logger
	project, db, key, record string
}

func newIdentityFixture(t *testing.T) identityFixture {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	project := t.TempDir()
	db := filepath.Join(project, ".nock", "events.db")
	key := filepath.Join(t.TempDir(), "keys", "signing.key")
	l, err := NewLogger(db, project, WithSigning(key))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	dir, err := config.AuditStateDir(project)
	if err != nil {
		t.Fatal(err)
	}
	return identityFixture{l, project, db, key, filepath.Join(dir, ChainIdentityFileName)}
}

func initIdentity(t *testing.T, f identityFixture) *ChainIdentity {
	t.Helper()
	identity, err := f.logger.InitializeChainIdentity(strings.Repeat("0", 64))
	if err != nil {
		t.Fatal(err)
	}
	return identity
}

func identityOldEvent(t *testing.T, l *Logger) {
	t.Helper()
	event := sampleEvent(EventFilePassed, "filesystem", "disposable old event", false, "identity-test")
	event.Timestamp = time.Now().Add(-48 * time.Hour)
	if err := l.Log(event); err != nil {
		t.Fatal(err)
	}
}

func assertIdentityPruneRefused(t *testing.T, l *Logger, wantError string) {
	t.Helper()
	before, err := l.Stats("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Prune(24 * time.Hour); err == nil || !strings.Contains(err.Error(), wantError) {
		t.Fatalf("prune refusal: got %v; want error containing %q", err, wantError)
	}
	after, err := l.Stats("")
	if err != nil || after.TotalEvents != before.TotalEvents {
		t.Fatalf("refused prune changed events: %v, %v", after, err)
	}
}

func TestChainIdentityExplicitCreationAndLegacyPrune(t *testing.T) {
	f := newIdentityFixture(t)
	if _, err := f.logger.ReadChainIdentity(); !errors.Is(err, ErrChainIdentityMissing) {
		t.Fatalf("missing identity: %v", err)
	}
	if _, err := os.Stat(f.record); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("read created identity: %v", err)
	}
	identityOldEvent(t, f.logger)
	if n, err := f.logger.Prune(24 * time.Hour); err != nil || n != 1 {
		t.Fatalf("legacy prune: %d, %v", n, err)
	}
	first := initIdentity(t, f)
	if first.RegistrationState != ChainRegistrationNone || len(first.ChainID) != 64 {
		t.Fatalf("bad fresh identity: %+v", first)
	}
	second := initIdentity(t, f)
	if *first != *second {
		t.Fatal("repeat initialization changed identity")
	}
	first.ChainID = strings.Repeat("a", 64)
	read, err := f.logger.ReadChainIdentity()
	if err != nil || *read != *second {
		t.Fatalf("returned value mutated persisted record: %+v, %v", read, err)
	}
	identityOldEvent(t, f.logger)
	if n, err := f.logger.Prune(24 * time.Hour); err != nil || n != 1 {
		t.Fatalf("none state prune: %d, %v", n, err)
	}
	if _, err := f.logger.InitializeChainIdentity(strings.Repeat("1", 64)); err == nil {
		t.Fatal("immutable migration witness changed")
	}
	if info, err := os.Stat(f.record); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("record permissions: %v, %v", info, err)
	}
	result, err := f.logger.VerifyChain()
	if err != nil || !result.Intact {
		t.Fatalf("chain corrupted: %+v, %v", result, err)
	}
}

func TestChainIdentityRegistrationTransitions(t *testing.T) {
	f := newIdentityFixture(t)
	identityOldEvent(t, f.logger)
	identity := initIdentity(t, f)
	calls := 0
	register := func(seen ChainIdentity) (*ChainRegistrationConfirmation, error) {
		calls++
		data, err := os.ReadFile(f.record)
		if err != nil {
			t.Fatal(err)
		}
		var durable ChainIdentity
		if err := json.Unmarshal(data, &durable); err != nil {
			t.Fatal(err)
		}
		if durable.RegistrationState != ChainRegistrationPending || seen != durable {
			t.Fatalf("callback preceded pending write: %+v / %+v", seen, durable)
		}
		return &ChainRegistrationConfirmation{identity.AgentID, identity.ChainID}, nil
	}
	enrolled, err := f.logger.RegisterChainIdentity(register)
	if err != nil || enrolled.RegistrationState != ChainRegistrationEnrolled {
		t.Fatalf("registration: %+v, %v", enrolled, err)
	}
	assertIdentityPruneRefused(t, f.logger, "remote pin")
	again, err := f.logger.RegisterChainIdentity(register)
	if err != nil || *again != *enrolled || calls != 1 {
		t.Fatalf("repeat enrolled registration changed state/called store: %v, %d", err, calls)
	}
	if got := initIdentity(t, f); *got != *enrolled {
		t.Fatal("initialize reset enrollment")
	}
}

func TestChainIdentityRegistrationFailuresRemainPending(t *testing.T) {
	for _, outcome := range []string{"timeout", "rejection", "wrong_agent", "wrong_chain", "missing_confirmation", "panic"} {
		t.Run(outcome, func(t *testing.T) {
			f := newIdentityFixture(t)
			identityOldEvent(t, f.logger)
			id := initIdentity(t, f)
			func() {
				defer func() {
					if recovered := recover(); recovered != nil && outcome != "panic" {
						t.Fatalf("unexpected panic: %v", recovered)
					}
				}()
				_, err := f.logger.RegisterChainIdentity(func(ChainIdentity) (*ChainRegistrationConfirmation, error) {
					switch outcome {
					case "timeout", "rejection":
						return nil, errors.New(outcome)
					case "wrong_agent":
						return &ChainRegistrationConfirmation{strings.Repeat("f", 64), id.ChainID}, nil
					case "wrong_chain":
						return &ChainRegistrationConfirmation{id.AgentID, strings.Repeat("f", 64)}, nil
					case "missing_confirmation":
						return nil, nil
					default:
						panic("simulated request interruption")
					}
				})
				if err == nil {
					t.Fatal("failed registration succeeded")
				}
			}()
			pending, err := f.logger.ReadChainIdentity()
			if err != nil || pending.RegistrationState != ChainRegistrationPending {
				t.Fatalf("failure cleared pending: %+v,%v", pending, err)
			}
			assertIdentityPruneRefused(t, f.logger, "remote pin")
			// An authenticated already-exists confirmation for this pair may
			// complete a lost-response retry; no retry ever resets to none.
			got, err := f.logger.RegisterChainIdentity(func(ChainIdentity) (*ChainRegistrationConfirmation, error) {
				return &ChainRegistrationConfirmation{id.AgentID, id.ChainID}, nil
			})
			if err != nil || got.RegistrationState != ChainRegistrationEnrolled {
				t.Fatalf("confirmed retry: %+v,%v", got, err)
			}
		})
	}
}

func TestChainIdentityRejectsPartialCorruptAndMismatchedState(t *testing.T) {
	for _, tc := range []struct{ corruption, wantError string }{
		{"missing_record", "incomplete"},
		{"missing_mirror", "incomplete"},
		{"wrong_chain", "disagree"},
		{"wrong_agent", "disagree"},
		{"wrong_witness", "disagree"},
		{"bad_state", "invalid chain registration state"},
		{"unknown_field", "not canonical"},
		{"duplicate_field", "not canonical"},
		{"truncated", "invalid trusted chain identity JSON"},
		{"oversized", "invalid or oversized record"},
		{"record_symlink", "path escapes from parent"},
		{"lock_symlink", "path escapes from parent"},
		{"record_hardlink", "exactly one hard link"},
		{"record_writable", "not group/world-writable"},
		{"lock_writable", "not group/world-writable"},
		{"owned_dir_symlink", "path is a symlink"},
	} {
		t.Run(tc.corruption, func(t *testing.T) {
			corruption := tc.corruption
			f := newIdentityFixture(t)
			identityOldEvent(t, f.logger)
			id := initIdentity(t, f)
			data, err := os.ReadFile(f.record)
			if err != nil {
				t.Fatal(err)
			}
			lock := filepath.Join(filepath.Dir(f.record), chainIdentityLockName)
			switch corruption {
			case "missing_record":
				err = os.Remove(f.record)
			case "missing_mirror":
				_, err = f.logger.db.Exec("DELETE FROM chain_identity")
			case "wrong_chain":
				_, err = f.logger.db.Exec("UPDATE chain_identity SET chain_id=?", strings.Repeat("1", 64))
			case "wrong_agent":
				_, err = f.logger.db.Exec("UPDATE chain_identity SET agent_id=?", strings.Repeat("1", 64))
			case "wrong_witness":
				_, err = f.logger.db.Exec("UPDATE chain_identity SET legacy_anchor_digest=?", strings.Repeat("1", 64))
			case "bad_state":
				err = os.WriteFile(f.record, []byte(strings.Replace(string(data), `"none"`, `"unknown"`, 1)), 0600)
			case "unknown_field":
				err = os.WriteFile(f.record, []byte(strings.Replace(string(data), `{"version":1`, `{"extra":0,"version":1`, 1)), 0600)
			case "duplicate_field":
				err = os.WriteFile(f.record, []byte(strings.Replace(string(data), `{"version":1`, `{"version":1,"version":1`, 1)), 0600)
			case "truncated":
				err = os.WriteFile(f.record, data[:len(data)/2], 0600)
			case "oversized":
				err = os.WriteFile(f.record, []byte(strings.Repeat(" ", 4097)), 0600)
			case "record_symlink", "lock_symlink":
				path := f.record
				if corruption == "lock_symlink" {
					path = lock
				}
				target := filepath.Join(t.TempDir(), "target")
				if e := os.WriteFile(target, data, 0600); e != nil {
					t.Fatal(e)
				}
				if e := os.Remove(path); e != nil {
					t.Fatal(e)
				}
				err = os.Symlink(target, path)
			case "record_hardlink":
				err = os.Link(f.record, filepath.Join(t.TempDir(), "alias"))
			case "record_writable":
				err = os.Chmod(f.record, 0666)
			case "lock_writable":
				err = os.Chmod(lock, 0666)
			case "owned_dir_symlink":
				dir := filepath.Dir(f.record)
				target := dir + "-moved"
				if e := os.Rename(dir, target); e != nil {
					t.Fatal(e)
				}
				err = os.Symlink(target, dir)
			}
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.logger.ReadChainIdentity(); err == nil {
				t.Fatal("corruption accepted")
			}
			assertIdentityPruneRefused(t, f.logger, tc.wantError)
			if _, err := f.logger.InitializeChainIdentity(id.LegacyAnchorDigest); err == nil {
				t.Fatal("incomplete identity silently reinitialized")
			}
			called := false
			if _, err := f.logger.RegisterChainIdentity(func(ChainIdentity) (*ChainRegistrationConfirmation, error) { called = true; return nil, nil }); err == nil || called {
				t.Fatalf("corrupt registration reached callback: %v, %v", called, err)
			}
		})
	}
}

func TestChainIdentityRegistrationAndPruneShareLock(t *testing.T) {
	f := newIdentityFixture(t)
	identityOldEvent(t, f.logger)
	id := initIdentity(t, f)
	other, err := NewLogger(f.db, f.project, WithSigning(f.key))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	entered, release := make(chan struct{}), make(chan struct{})
	releaseRegistration := sync.OnceFunc(func() { close(release) })
	defer releaseRegistration()
	registered := make(chan error, 1)
	go func() {
		_, err := f.logger.RegisterChainIdentity(func(ChainIdentity) (*ChainRegistrationConfirmation, error) {
			close(entered)
			<-release
			return &ChainRegistrationConfirmation{id.AgentID, id.ChainID}, nil
		})
		registered <- err
	}()
	select {
	case <-entered:
	case err := <-registered:
		t.Fatalf("registration returned before entering callback: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("registration did not enter callback within 5s")
	}
	pruned := make(chan error, 1)
	go func() { _, err := other.Prune(24 * time.Hour); pruned <- err }()
	select {
	case err := <-pruned:
		t.Fatalf("prune escaped held registration lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	releaseRegistration()
	select {
	case err := <-registered:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("registration did not complete after callback release")
	}
	select {
	case err := <-pruned:
		if err == nil || !strings.Contains(err.Error(), "remote pin") {
			t.Fatalf("prune after enrollment: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("prune did not complete after registration released its lock")
	}
	stats, err := f.logger.Stats("")
	if err != nil || stats.TotalEvents != 1 {
		t.Fatalf("racing prune deleted event: %+v,%v", stats, err)
	}
}

func TestChainIdentityCrashAfterPending(t *testing.T) {
	f := newIdentityFixture(t)
	identityOldEvent(t, f.logger)
	initIdentity(t, f)
	cmd := exec.Command(os.Args[0], "-test.run=^TestChainIdentityCrashHelper$")
	cmd.Env = append(os.Environ(), "NOCKLOCK_IDENTITY_CRASH_DB="+f.db, "NOCKLOCK_IDENTITY_CRASH_PROJECT="+f.project, "NOCKLOCK_IDENTITY_CRASH_KEY="+f.key)
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 23 {
		t.Fatalf("crash helper: %v", err)
	}
	id, err := f.logger.ReadChainIdentity()
	if err != nil || id.RegistrationState != ChainRegistrationPending {
		t.Fatalf("crash lost pending: %+v,%v", id, err)
	}
	assertIdentityPruneRefused(t, f.logger, "remote pin")
}

func TestChainIdentityCrashHelper(t *testing.T) {
	db := os.Getenv("NOCKLOCK_IDENTITY_CRASH_DB")
	if db == "" {
		return
	}
	l, err := NewLogger(db, os.Getenv("NOCKLOCK_IDENTITY_CRASH_PROJECT"), WithSigning(os.Getenv("NOCKLOCK_IDENTITY_CRASH_KEY")))
	if err != nil {
		t.Fatal(err)
	}
	_, err = l.RegisterChainIdentity(func(ChainIdentity) (*ChainRegistrationConfirmation, error) { os.Exit(23); return nil, nil })
	t.Fatalf("crash callback did not run: %v", err)
}

func TestChainIdentityRejectsInProjectStateRoot(t *testing.T) {
	f := newIdentityFixture(t)
	t.Setenv("XDG_STATE_HOME", filepath.Join(f.project, "writable-state"))
	if _, err := f.logger.InitializeChainIdentity(strings.Repeat("0", 64)); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("in-project trusted state accepted: %v", err)
	}
	mirror, err := f.logger.readChainIdentityMirror()
	if err != nil || mirror != nil {
		t.Fatalf("failed creation wrote mirror: %+v,%v", mirror, err)
	}
}

// offlineMoveState mirrors the runbook's preflight + no-clobber move while all
// chain users are stopped. It is intentionally test-only, not an automatic
// production migration or path-repair API.
func offlineMoveState(source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("source state is not a real directory")
	}
	if _, err := os.Lstat(destination); !errors.Is(err, os.ErrNotExist) {
		return errors.New("destination state already exists; refusing overwrite")
	}
	return os.Rename(source, destination)
}

func TestChainIdentityOfflineMoveProcedure(t *testing.T) {
	for _, scenario := range []string{"preserve_agreement", "missing_record", "destination_conflict"} {
		t.Run(scenario, func(t *testing.T) {
			f := newIdentityFixture(t)
			identityOldEvent(t, f.logger)
			before := initIdentity(t, f)
			before, err := f.logger.RegisterChainIdentity(func(ChainIdentity) (*ChainRegistrationConfirmation, error) {
				return &ChainRegistrationConfirmation{before.AgentID, before.ChainID}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			// Resolve and retain old mapping before renaming the project.
			oldState := filepath.Dir(f.record)
			newProject := filepath.Join(t.TempDir(), "moved-project")
			if err := f.logger.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(f.project, newProject); err != nil {
				t.Fatal(err)
			}
			newState, err := config.AuditStateDir(newProject)
			if err != nil {
				t.Fatal(err)
			}
			newDB := filepath.Join(newProject, ".nock", "events.db")
			t.Logf("move mapping: old_project=%s new_project=%s old_state=%s new_state=%s db=%s chain_id=%s state=%s", f.project, newProject, oldState, newState, newDB, before.ChainID, before.RegistrationState)
			switch scenario {
			case "destination_conflict":
				if err := os.Mkdir(newState, 0700); err != nil {
					t.Fatal(err)
				}
				sentinel := filepath.Join(newState, "operator-owned-conflict")
				if err := os.WriteFile(sentinel, []byte("preserve me"), 0600); err != nil {
					t.Fatal(err)
				}
				if err := offlineMoveState(oldState, newState); err == nil {
					t.Fatal("destination conflict overwritten")
				}
				if data, err := os.ReadFile(sentinel); err != nil || string(data) != "preserve me" {
					t.Fatal("destination changed")
				}
				if _, err := os.Stat(filepath.Join(oldState, ChainIdentityFileName)); err != nil {
					t.Fatal("source changed on conflict")
				}
				return
			case "preserve_agreement":
				if err := offlineMoveState(oldState, newState); err != nil {
					t.Fatal(err)
				}
				if _, err := os.Lstat(oldState); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("source state still present")
				}
			}
			moved, err := NewLogger(newDB, newProject, WithSigning(f.key))
			if err != nil {
				t.Fatal(err)
			}
			defer moved.Close()
			if scenario == "missing_record" {
				if _, err := moved.ReadChainIdentity(); err == nil || !strings.Contains(err.Error(), "chain-identity-move.md") {
					t.Fatalf("moved DB silently adopted: %v", err)
				}
				if _, err := moved.InitializeChainIdentity(strings.Repeat("0", 64)); err == nil {
					t.Fatal("moved DB minted replacement ID")
				}
				assertIdentityPruneRefused(t, moved, "incomplete")
				return
			}
			after, err := moved.ReadChainIdentity()
			if err != nil || *after != *before {
				t.Fatalf("move changed trusted pair/state: %+v,%v", after, err)
			}
			verified, err := moved.VerifyChain()
			if err != nil || !verified.Intact {
				t.Fatalf("moved chain invalid: %+v,%v", verified, err)
			}
			assertIdentityPruneRefused(t, moved, "remote pin")
		})
	}
}

func TestChainIdentityPendingWriteFailureDoesNotSend(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory write permissions")
	}
	f := newIdentityFixture(t)
	initIdentity(t, f)
	dir := filepath.Dir(f.record)
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700) })
	called := false
	_, err := f.logger.RegisterChainIdentity(func(ChainIdentity) (*ChainRegistrationConfirmation, error) { called = true; return nil, nil })
	if err == nil || called {
		t.Fatalf("failed durable pending write invoked request: called=%v err=%v", called, err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	identity, err := f.logger.ReadChainIdentity()
	if err != nil || identity.RegistrationState != ChainRegistrationNone {
		t.Fatalf("pre-request failure changed none: %+v,%v", identity, err)
	}
	identityOldEvent(t, f.logger)
	if n, err := f.logger.Prune(24 * time.Hour); err != nil || n != 1 {
		t.Fatalf("no request sent, prune must remain allowed: %d,%v", n, err)
	}
}

func TestChainIdentityCreationGuards(t *testing.T) {
	f := newIdentityFixture(t)
	if _, err := f.logger.RegisterChainIdentity(func(ChainIdentity) (*ChainRegistrationConfirmation, error) {
		t.Fatal("uninitialized callback ran")
		return nil, nil
	}); !errors.Is(err, ErrChainIdentityMissing) {
		t.Fatalf("registration invented identity: %v", err)
	}
	if _, err := f.logger.RegisterChainIdentity(nil); err == nil {
		t.Fatal("nil callback accepted")
	}
	if _, err := f.logger.InitializeChainIdentity("invalid"); err == nil {
		t.Fatal("invalid legacy digest accepted")
	}
	unsigned, err := NewLogger(f.db, f.project)
	if err != nil {
		t.Fatal(err)
	}
	defer unsigned.Close()
	if _, err := unsigned.InitializeChainIdentity(strings.Repeat("0", 64)); err == nil {
		t.Fatal("identity initialized without signing key")
	}
	initIdentity(t, f)
	withoutRoot, err := NewLogger(f.db, "")
	if err != nil {
		t.Fatal(err)
	}
	defer withoutRoot.Close()
	assertIdentityPruneRefused(t, withoutRoot, "explicit project root")
	if _, err := withoutRoot.ChainIdentityDirectory(); err == nil {
		t.Fatal("missing root bypassed trusted identity protection")
	}
}

func TestChainIdentityUnsupportedPlatformLegacyGuard(t *testing.T) {
	f := newIdentityFixture(t)
	if err := f.logger.allowLegacyPruneWithoutIdentity(); err != nil {
		t.Fatalf("legacy platform fallback refused: %v", err)
	}
	initIdentity(t, f)
	if err := f.logger.allowLegacyPruneWithoutIdentity(); err == nil {
		t.Fatal("unsupported platform fallback accepted v2 identity")
	}
	if err := os.Remove(f.record); err != nil {
		t.Fatal(err)
	}
	if err := f.logger.allowLegacyPruneWithoutIdentity(); err == nil {
		t.Fatal("unsupported platform fallback accepted DB-only identity")
	}
}

func TestChainIdentitySharedKeyAndConcurrentInitialization(t *testing.T) {
	f := newIdentityFixture(t)
	other, err := NewLogger(f.db, f.project, WithSigning(f.key))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	type outcome struct {
		id  *ChainIdentity
		err error
	}
	results := make(chan outcome, 2)
	for _, l := range []*Logger{f.logger, other} {
		go func(l *Logger) {
			id, err := l.InitializeChainIdentity(strings.Repeat("0", 64))
			results <- outcome{id, err}
		}(l)
	}
	first, second := <-results, <-results
	if first.err != nil || second.err != nil || *first.id != *second.id {
		t.Fatalf("concurrent initialization diverged: id=%+v error=%v / id=%+v error=%v", first.id, first.err, second.id, second.err)
	}
	projectB := t.TempDir()
	chainB, err := NewLogger(filepath.Join(projectB, ".nock", "events.db"), projectB, WithSigning(f.key))
	if err != nil {
		t.Fatal(err)
	}
	defer chainB.Close()
	idB, err := chainB.InitializeChainIdentity(strings.Repeat("0", 64))
	if err != nil {
		t.Fatal(err)
	}
	if idB.AgentID != first.id.AgentID || idB.ChainID == first.id.ChainID {
		t.Fatal("shared signing key conflated independent chains")
	}
	if _, err := f.logger.RegisterChainIdentity(func(ChainIdentity) (*ChainRegistrationConfirmation, error) { return nil, errors.New("timeout") }); err == nil {
		t.Fatal("registration failure expected")
	}
	identityOldEvent(t, chainB)
	if n, err := chainB.Prune(24 * time.Hour); err != nil || n != 1 {
		t.Fatalf("A enrollment blocked B prune: %d,%v", n, err)
	}
	assertIdentityPruneRefused(t, f.logger, "remote pin")
}

func TestChainIdentityPendingRetryReestablishesDurability(t *testing.T) {
	f := newIdentityFixture(t)
	initial := initIdentity(t, f)
	recordDir, err := filepath.EvalSymlinks(filepath.Dir(f.record))
	if err != nil {
		t.Fatal(err)
	}
	_, root, err := config.EnsureAuditStateLocation(f.project)
	if err != nil {
		t.Fatal(err)
	}
	var syncs []string
	failed := false
	injected := errors.New("injected first directory fsync failure")
	f.logger.identitySync = func(file *os.File) error {
		info, err := file.Stat()
		if err != nil {
			return err
		}
		syncs = append(syncs, filepath.Clean(file.Name()))
		if info.IsDir() && !failed {
			failed = true
			return injected
		}
		return file.Sync()
	}
	calls := 0
	callback := func(id ChainIdentity) (*ChainRegistrationConfirmation, error) {
		calls++
		if len(syncs) != 4 || !strings.HasPrefix(filepath.Base(syncs[0]), ".chain-identity-") || syncs[1] != recordDir || syncs[2] != filepath.Dir(recordDir) || syncs[3] != root {
			t.Fatalf("callback before complete bounded durability barrier: %v", syncs)
		}
		return &ChainRegistrationConfirmation{AgentID: id.AgentID, ChainID: id.ChainID}, nil
	}
	_, err = f.logger.RegisterChainIdentity(callback)
	var durability *ChainIdentityDurabilityError
	if !errors.As(err, &durability) || !errors.Is(err, injected) || calls != 0 {
		t.Fatalf("post-rename failure: err=%v callback=%d", err, calls)
	}
	pending, err := f.logger.ReadChainIdentity()
	if err != nil || pending.ChainID != initial.ChainID || pending.RegistrationState != ChainRegistrationPending {
		t.Fatalf("committed pending record lost: %+v, %v", pending, err)
	}
	syncs = nil
	enrolled, err := f.logger.RegisterChainIdentity(callback)
	if err != nil || calls != 1 || enrolled.RegistrationState != ChainRegistrationEnrolled {
		t.Fatalf("durable retry: %+v, %v, calls=%d", enrolled, err, calls)
	}
	// Both pending and enrolled updates sync no ancestor above the state root.
	for _, path := range syncs {
		if !pathContains(root, path) {
			t.Fatalf("synced unrelated ancestor %q above %q", path, root)
		}
	}
}

func TestChainIdentityPruneRefusesRootlessAfterDatabaseRollback(t *testing.T) {
	for _, enrolled := range []bool{false, true} {
		t.Run(fmt.Sprintf("enrolled=%t", enrolled), func(t *testing.T) {
			f := newIdentityFixture(t)
			identityOldEvent(t, f.logger)
			backup := filepath.Join(t.TempDir(), "before-identity.db")
			if _, err := f.logger.db.Exec("VACUUM INTO ?", backup); err != nil {
				t.Fatal(err)
			}
			initIdentity(t, f)
			_, err := f.logger.RegisterChainIdentity(func(id ChainIdentity) (*ChainRegistrationConfirmation, error) {
				if !enrolled {
					return nil, errors.New("lost registration response")
				}
				return &ChainRegistrationConfirmation{AgentID: id.AgentID, ChainID: id.ChainID}, nil
			})
			if enrolled && err != nil {
				t.Fatal(err)
			}
			f.logger.Close()
			originalRecord, err := os.ReadFile(f.record)
			if err != nil {
				t.Fatal(err)
			}
			snapshot, err := os.ReadFile(backup)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(f.db, snapshot, 0600); err != nil {
				t.Fatal(err)
			}
			for _, project := range []string{"", f.project} {
				l, err := NewLogger(f.db, project, WithSigning(f.key))
				if err != nil {
					t.Fatal(err)
				}
				mirror, err := l.readChainIdentityMirror()
				if err != nil || mirror != nil {
					t.Fatalf("rollback fixture retained mirror: %+v, %v", mirror, err)
				}
				wantError := "incomplete"
				if project == "" {
					wantError = "explicit project root"
				}
				assertIdentityPruneRefused(t, l, wantError)
				l.Close()
			}
			actual, err := os.ReadFile(f.record)
			if err != nil || string(actual) != string(originalRecord) {
				t.Fatalf("prune changed trusted record: %v", err)
			}
		})
	}
	// Allowed control: explicit project context still permits a legacy prune.
	f := newIdentityFixture(t)
	identityOldEvent(t, f.logger)
	if n, err := f.logger.Prune(24 * time.Hour); err != nil || n != 1 {
		t.Fatalf("legacy control: %d, %v", n, err)
	}
}

func TestChainIdentityPruneLockWaitIsBounded(t *testing.T) {
	f := newIdentityFixture(t)
	identityOldEvent(t, f.logger)
	holder, err := f.logger.lockChainIdentityStore()
	if err != nil {
		t.Fatal(err)
	}
	releaseHolder := sync.OnceFunc(holder.close)
	defer releaseHolder()
	start := time.Now()
	_, err = f.logger.Prune(24 * time.Hour)
	elapsed := time.Since(start)
	if !errors.Is(err, context.DeadlineExceeded) || elapsed < pruneIdentityLockTimeout || elapsed > pruneIdentityLockTimeout+2*time.Second {
		t.Fatalf("prune lock wait: %v after %s", err, elapsed)
	}
	stats, err := f.logger.Stats("")
	if err != nil || stats.TotalEvents != 1 {
		t.Fatalf("timed-out prune changed rows: %+v, %v", stats, err)
	}
	releaseHolder()
	if n, err := f.logger.Prune(24 * time.Hour); err != nil || n != 1 {
		t.Fatalf("released lock control: %d, %v", n, err)
	}
}

func TestChainIdentityRootDurabilityIsOnlyRequiredForMutation(t *testing.T) {
	f := newIdentityFixture(t)
	// Legacy code could have created several nested components without syncing
	// any of them. A mutation must establish all of that existing lineage.
	t.Setenv("XDG_STATE_HOME", filepath.Join(t.TempDir(), "legacy", "nested", "state"))
	dir, root, err := config.EnsureAuditStateLocation(f.project)
	if err != nil {
		t.Fatal(err)
	}
	f.record = filepath.Join(dir, ChainIdentityFileName)
	injected := syscall.EINVAL
	var synced []string
	f.logger.identityRootSync = func(file *os.File) error {
		synced = append(synced, filepath.Clean(file.Name()))
		if filepath.Clean(file.Name()) == filepath.Dir(root) {
			return injected
		}
		return file.Sync()
	}
	if _, err := f.logger.InitializeChainIdentity(strings.Repeat("0", 64)); !errors.Is(err, injected) {
		t.Fatalf("identity accepted unsupported root durability: %v", err)
	}
	mirror, err := f.logger.readChainIdentityMirror()
	if err != nil || mirror != nil {
		t.Fatalf("failed preflight changed DB mirror: %+v, %v", mirror, err)
	}
	if _, err := os.Stat(f.record); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed preflight wrote identity: %v", err)
	}
	calls := len(synced)
	identityOldEvent(t, f.logger)
	if _, err := f.logger.Stats(""); err != nil {
		t.Fatal(err)
	}
	verified, err := f.logger.VerifyChainSigned(f.logger.SigningPublicKey(), true)
	if err != nil || !verified.Intact || verified.SigState != "authentic" {
		t.Fatalf("legacy verification: %+v, %v", verified, err)
	}
	if _, err := f.logger.ReadChainIdentity(); !errors.Is(err, ErrChainIdentityMissing) {
		t.Fatalf("legacy read: %v", err)
	}
	if _, err := f.logger.TrustedChainStateDirectory(); err != nil {
		t.Fatalf("future fence directory: %v", err)
	}
	if n, err := f.logger.Prune(24 * time.Hour); err != nil || n != 1 {
		t.Fatalf("legacy prune: %d, %v", n, err)
	}
	if len(synced) != calls {
		t.Fatal("legacy operation invoked trusted-write durability")
	}
	synced = nil
	f.logger.identityRootSync = func(file *os.File) error { synced = append(synced, filepath.Clean(file.Name())); return file.Sync() }
	id := initIdentity(t, f)
	assertRootLineageSynced(t, root, synced)
	// Existing records can still be read and an unregistered chain pruned on
	// a filesystem that rejects directory sync. Registration cannot proceed.
	f.logger.identityRootSync = func(*os.File) error { return injected }
	if got, err := f.logger.ReadChainIdentity(); err != nil || *got != *id {
		t.Fatalf("existing identity read: %+v, %v", got, err)
	}
	identityOldEvent(t, f.logger)
	if n, err := f.logger.Prune(24 * time.Hour); err != nil || n != 1 {
		t.Fatalf("unregistered identity prune: %d, %v", n, err)
	}
	if _, err := f.logger.RegisterChainIdentity(func(ChainIdentity) (*ChainRegistrationConfirmation, error) {
		t.Fatal("registration sent before root preflight succeeded")
		return nil, nil
	}); !errors.Is(err, injected) {
		t.Fatalf("registration ignored unsupported durability: %v", err)
	}
	f.logger.identityRootSync = func(file *os.File) error { synced = append(synced, filepath.Clean(file.Name())); return file.Sync() }
	synced = nil
	if _, err := f.logger.RegisterChainIdentity(func(ChainIdentity) (*ChainRegistrationConfirmation, error) {
		assertRootLineageSynced(t, root, synced)
		return &ChainRegistrationConfirmation{AgentID: id.AgentID, ChainID: id.ChainID}, nil
	}); err != nil {
		t.Fatalf("allowed registration: %v", err)
	}
}

func assertRootLineageSynced(t *testing.T, root string, actual []string) {
	t.Helper()
	var expected []string
	for path := root; ; path = filepath.Dir(path) {
		expected = append(expected, path)
		if filepath.Dir(path) == path {
			break
		}
	}
	if !slices.Equal(actual, expected) {
		t.Fatalf("root lineage barrier: got %v; want %v", actual, expected)
	}
}

func TestChainIdentityRootPreflightCannotBeBorrowedFromFailedInitializer(t *testing.T) {
	f := newIdentityFixture(t)
	t.Setenv("XDG_STATE_HOME", filepath.Join(t.TempDir(), "new", "nested", "root"))
	dir, root, err := config.EnsureAuditStateLocation(f.project) // prior legacy mkdir without barriers
	if err != nil {
		t.Fatal(err)
	}
	f.record = filepath.Join(dir, ChainIdentityFileName)
	other, err := NewLogger(f.db, f.project, WithSigning(f.key))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	atBarrier, release := make(chan struct{}), make(chan struct{})
	injected := errors.New("initializer A root sync failed")
	f.logger.identityRootSync = func(*os.File) error { close(atBarrier); <-release; return injected }
	var synced []string
	other.identityRootSync = func(file *os.File) error { synced = append(synced, filepath.Clean(file.Name())); return file.Sync() }
	first := make(chan error, 1)
	second := make(chan error, 1)
	go func() { _, err := f.logger.InitializeChainIdentity(strings.Repeat("0", 64)); first <- err }()
	<-atBarrier
	go func() { _, err := other.InitializeChainIdentity(strings.Repeat("0", 64)); second <- err }()
	close(release)
	if err := <-first; !errors.Is(err, injected) {
		t.Fatalf("A error: %v", err)
	}
	if err := <-second; err != nil {
		t.Fatalf("B initialization: %v", err)
	}
	assertRootLineageSynced(t, root, synced)
}

func TestChainIdentityExecuteOnlyParentPreservesLegacyOperations(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
	f := newIdentityFixture(t)
	parent := filepath.Join(t.TempDir(), "search-only")
	t.Setenv("XDG_STATE_HOME", filepath.Join(parent, "state"))
	if _, err := config.EnsureAuditStateDir(f.project); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(parent, 0111); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(parent, 0700) })
	identityOldEvent(t, f.logger)
	if _, err := f.logger.ReadChainIdentity(); !errors.Is(err, ErrChainIdentityMissing) {
		t.Fatalf("legacy read: %v", err)
	}
	if n, err := f.logger.Prune(24 * time.Hour); err != nil || n != 1 {
		t.Fatalf("legacy prune: %d, %v", n, err)
	}
	if _, err := f.logger.InitializeChainIdentity(strings.Repeat("0", 64)); !errors.Is(err, os.ErrPermission) {
		t.Fatalf("identity ignored unreadable ancestor: %v", err)
	}
	mirror, err := f.logger.readChainIdentityMirror()
	if err != nil || mirror != nil {
		t.Fatalf("failed mutation changed mirror: %+v, %v", mirror, err)
	}
	if err := os.Chmod(parent, 0700); err != nil {
		t.Fatal(err)
	}
	initIdentity(t, f)
}

func TestChainIdentitySyncRootGuardTerminatesOnUnreachableRoot(t *testing.T) {
	f := newIdentityFixture(t)
	id := initIdentity(t, f)
	store, err := f.logger.lockChainIdentityStore()
	if err != nil {
		t.Fatal(err)
	}
	defer store.close()
	store.rootDurable = true           // exercise only the post-rename defensive guard
	store.syncRoot = store.root.Name() // cannot be reached by a loop starting at its parent
	var synced []string
	store.syncFile = func(file *os.File) error {
		synced = append(synced, filepath.Clean(file.Name()))
		// Keep the negative control bounded if the production root guard is
		// removed: a repeated root must produce the wrong error, not hang.
		if len(synced) > 1 && synced[len(synced)-1] == synced[len(synced)-2] {
			return errors.New("repeated filesystem root without terminating")
		}
		return nil
	}
	err = store.write(id)
	var durability *ChainIdentityDurabilityError
	if !errors.As(err, &durability) || !strings.Contains(err.Error(), "cannot reach the configured state root") {
		t.Fatalf("missing root termination: %v", err)
	}
	if len(synced) == 0 {
		t.Fatal("root termination returned without syncing any path")
	}
	last := synced[len(synced)-1]
	if filepath.Dir(last) != last {
		t.Fatalf("did not stop at filesystem root: %v", synced)
	}
}
