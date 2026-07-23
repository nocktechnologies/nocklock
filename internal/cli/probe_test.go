package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProbeSecretDetectsBlockedAndEscaped(t *testing.T) {
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

func TestProbeFilesystemDetectsReadableCanaryAsEscape(t *testing.T) {
	path := filepath.Join(t.TempDir(), "canary")
	if err := os.WriteFile(path, []byte("canary"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(verifyCanaryPathEnv, path)

	got := probeFilesystem()
	if got.Blocked || !got.Attempted {
		t.Fatalf("probeFilesystem readable canary = %+v, want attempted escape", got)
	}
}

func TestProbeFilesystemTreatsMissingCanaryAsBlocked(t *testing.T) {
	t.Setenv(verifyCanaryPathEnv, filepath.Join(t.TempDir(), "missing"))

	got := probeFilesystem()
	if !got.Blocked || !got.Attempted {
		t.Fatalf("probeFilesystem missing canary = %+v, want attempted blocked", got)
	}
}
