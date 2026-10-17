//go:build linux || darwin

package cli

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/anchorclient"
	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
)

func holdAnchorIdentityLock(t *testing.T, logger *logging.Logger) func() {
	t.Helper()
	dir, err := logger.ChainIdentityDirectory()
	if err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(dir, "chain-identity.lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		f.Close()
		t.Fatal(err)
	}
	var once sync.Once
	release := func() { once.Do(func() { f.Close() }) }
	t.Cleanup(release)
	return release
}

func TestFinishAnchorSessionIncludesIdentityWaitInBudget(t *testing.T) {
	dbPath, keyPath := setupAnchorProject(t)
	seedSignedChain(t, dbPath, keyPath, 1)
	emitRemoteAnchorNow(t, dbPath, keyPath)
	logger := remoteTestLogger(t, dbPath, keyPath)
	t.Setenv(anchorclient.EnvURL, "")
	original := anchorPushTimeout
	anchorPushTimeout = 50 * time.Millisecond
	t.Cleanup(func() { anchorPushTimeout = original })
	release := holdAnchorIdentityLock(t, logger)
	fallback := time.AfterFunc(2*time.Second, release)
	defer fallback.Stop()
	var out bytes.Buffer
	start := time.Now()
	finishAnchorSession(&out, logger, dbPath)
	if elapsed := time.Since(start); elapsed > time.Second || !strings.Contains(out.String(), "context deadline exceeded") {
		t.Fatalf("teardown identity wait exceeded budget: %s, %q", elapsed, out.String())
	}
	if _, err := os.Stat(logging.DefaultAnchorPath(dbPath)); !os.IsNotExist(err) {
		t.Fatalf("timed-out teardown wrote anchor: %v", err)
	}
	release()
	out.Reset()
	finishAnchorSession(&out, logger, dbPath)
	if out.Len() != 0 {
		t.Fatalf("released lock control warned: %s", out.String())
	}
	if _, err := logging.ReadAnchorV2(logging.DefaultAnchorPath(dbPath)); err != nil {
		t.Fatalf("released lock control failed to emit: %v", err)
	}
}

func TestAnchorCLIIdentityWaitHonorsCallerContext(t *testing.T) {
	for _, operation := range []string{"emit", "local verify", "remote verify", "push", "enroll", "migrate", "wrap startup"} {
		t.Run(operation, func(t *testing.T) {
			dbPath, keyPath := setupAnchorProject(t)
			seedSignedChain(t, dbPath, keyPath, 1)
			anchor := emitRemoteAnchorNow(t, dbPath, keyPath)
			legacy := emitAnchorNow(t, dbPath, keyPath)
			path := logging.DefaultAnchorPath(dbPath)
			if err := logging.WriteAnchorV2(path, anchor); err != nil {
				t.Fatal(err)
			}
			logger := remoteTestLogger(t, dbPath, keyPath)
			var posts atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					posts.Add(1)
					http.Error(w, "unexpected mutation", 500)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/legacy/") {
					if operation == "migrate" {
						data, _ := logging.MarshalAnchor(legacy)
						w.Write(data)
						return
					}
					w.WriteHeader(http.StatusNotFound)
					io.WriteString(w, `{"data":{"code":"legacy_missing"}}`)
					return
				}
				data, _ := logging.MarshalAnchorV2(anchor)
				w.Write(data)
			}))
			defer srv.Close()
			t.Setenv(anchorclient.EnvURL, srv.URL)
			release := holdAnchorIdentityLock(t, logger)
			fallback := time.AfterFunc(2*time.Second, release)
			defer fallback.Stop()
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			var out bytes.Buffer
			var err error
			start := time.Now()
			switch operation {
			case "emit":
				err = runAnchorEmit(ctx, &out, "")
			case "local verify":
				err = runVerifyAgainstAnchor(ctx, &out, path, "")
			case "remote verify":
				err = runVerifyAgainstRemoteAnchor(ctx, &out, "")
			case "push":
				err = runAnchorPush(ctx, &out, path)
			case "enroll":
				err = runAnchorEnrollment(ctx, &out, "fresh")
			case "migrate":
				err = runAnchorEnrollment(ctx, &out, "migrate")
			case "wrap startup":
				project, _ := os.Getwd()
				cfg := config.Config{Filesystem: config.FilesystemConfig{Root: project}}
				err = protectChainIdentity(ctx, &cfg, logger)
			}
			if elapsed := time.Since(start); err == nil || elapsed > time.Second || !strings.Contains(out.String()+err.Error(), "context deadline exceeded") {
				t.Fatalf("CLI ignored identity deadline: err=%v elapsed=%s out=%q", err, elapsed, out.String())
			}
			if posts.Load() != 0 {
				t.Fatal("cancelled operation sent a mutation")
			}
			release()
		})
	}
}
