//go:build linux || darwin

package logging

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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

func assertIdentityPruneRefused(t *testing.T, l *Logger) {
	t.Helper()
	before, err := l.Stats("")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := l.Prune(24 * time.Hour); err == nil {
		t.Fatal("prune accepted")
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
	assertIdentityPruneRefused(t, f.logger)
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
			assertIdentityPruneRefused(t, f.logger)
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
	for _, corruption := range []string{"missing_record", "missing_mirror", "wrong_chain", "wrong_agent", "wrong_witness", "bad_state", "unknown_field", "duplicate_field", "truncated", "oversized", "record_symlink", "lock_symlink", "record_hardlink", "record_writable", "lock_writable", "owned_dir_symlink"} {
		t.Run(corruption, func(t *testing.T) {
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
			assertIdentityPruneRefused(t, f.logger)
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
	registered := make(chan error, 1)
	go func() {
		_, err := f.logger.RegisterChainIdentity(func(ChainIdentity) (*ChainRegistrationConfirmation, error) {
			close(entered)
			<-release
			return &ChainRegistrationConfirmation{id.AgentID, id.ChainID}, nil
		})
		registered <- err
	}()
	<-entered
	pruned := make(chan error, 1)
	go func() { _, err := other.Prune(24 * time.Hour); pruned <- err }()
	select {
	case err := <-pruned:
		close(release)
		t.Fatalf("prune escaped held registration lock: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	close(release)
	if err := <-registered; err != nil {
		t.Fatal(err)
	}
	if err := <-pruned; err == nil || !strings.Contains(err.Error(), "remote pin") {
		t.Fatalf("prune after enrollment: %v", err)
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
	assertIdentityPruneRefused(t, f.logger)
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
				assertIdentityPruneRefused(t, moved)
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
			assertIdentityPruneRefused(t, moved)
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
	assertIdentityPruneRefused(t, withoutRoot)
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
		t.Fatalf("concurrent initialization diverged: %+v/%+v", first, second)
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
	assertIdentityPruneRefused(t, f.logger)
}
