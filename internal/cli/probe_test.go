package cli

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProbeSecretDetectsBlockedAndEscaped(t *testing.T) {
	t.Setenv(verifySecretControlName, "control")
	t.Setenv(verifySecretName, "")
	got := probeSecret()
	if got.Blocked {
		t.Fatalf("probeSecret with env present blocked=true, want escape: %+v", got)
	}

	os.Unsetenv(verifySecretName)
	got = probeSecret()
	if !got.Blocked || !got.Attempted {
		t.Fatalf("probeSecret with env absent = %+v, want attempted blocked", got)
	}
}

func TestProbeSecretRequiresControlEnv(t *testing.T) {
	t.Setenv(verifySecretName, "")

	got := probeSecret()
	if got.Attempted || got.Blocked {
		t.Fatalf("probeSecret without control env = %+v, want inconclusive", got)
	}
}

func TestProbeFilesystemDetectsReadableCanaryAsEscape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "canary")
	if err := os.WriteFile(path, []byte("canary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(verifyCanaryPathEnv, path)
	t.Setenv(verifyCanaryTokenEnv, "canary")

	got := probeFilesystem()
	if got.Blocked || !got.Attempted {
		t.Fatalf("probeFilesystem readable canary = %+v, want attempted escape", got)
	}
}

func TestProbeFilesystemTreatsMissingCanaryAsInconclusive(t *testing.T) {
	t.Setenv(verifyCanaryPathEnv, filepath.Join(t.TempDir(), "missing"))
	t.Setenv(verifyCanaryTokenEnv, "canary")

	got := probeFilesystem()
	if got.Blocked || got.Attempted {
		t.Fatalf("probeFilesystem missing canary = %+v, want inconclusive", got)
	}
}

func TestProbeFilesystemTreatsKnownMissingCanaryAsHiddenByFence(t *testing.T) {
	t.Setenv(verifyCanaryPathEnv, filepath.Join(t.TempDir(), "missing"))
	t.Setenv(verifyCanaryTokenEnv, "canary")
	t.Setenv(verifyCanaryKnownEnv, "1")

	got := probeFilesystem()
	if !got.Blocked || !got.Attempted {
		t.Fatalf("probeFilesystem known missing canary = %+v, want attempted blocked", got)
	}
}

func TestProbeNetworkRequiresProxyGeneratedBlock(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "NockLock: domain not in allowlist", http.StatusForbidden)
	}))
	defer proxy.Close()
	stubVerifyProxy(t, proxy.URL)
	t.Setenv(verifyNetworkURLEnv, "http://verify.nocklock.invalid")

	got := probeNetwork()
	if !got.Attempted || !got.Blocked {
		t.Fatalf("probeNetwork proxy block = %+v, want attempted blocked", got)
	}
}

func TestProbeNetworkTransportErrorIsInconclusive(t *testing.T) {
	stubVerifyProxy(t, "")
	t.Setenv(verifyNetworkURLEnv, "http://127.0.0.1:1")

	got := probeNetwork()
	if got.Attempted || got.Blocked {
		t.Fatalf("probeNetwork transport error = %+v, want inconclusive", got)
	}
}

func TestProbeNetworkUnexpectedResponseIsEscape(t *testing.T) {
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "not a fence block")
	}))
	defer proxy.Close()
	stubVerifyProxy(t, proxy.URL)
	t.Setenv(verifyNetworkURLEnv, "http://verify.nocklock.invalid")

	got := probeNetwork()
	if !got.Attempted || got.Blocked || !strings.Contains(got.Detail, "status 200") {
		t.Fatalf("probeNetwork unexpected response = %+v, want attempted escape", got)
	}
}

func stubVerifyProxy(t *testing.T, rawURL string) {
	t.Helper()
	orig := verifyProxyFromEnvironment
	verifyProxyFromEnvironment = func(*http.Request) (*url.URL, error) {
		if rawURL == "" {
			return nil, nil
		}
		return url.Parse(rawURL)
	}
	t.Cleanup(func() { verifyProxyFromEnvironment = orig })
}
