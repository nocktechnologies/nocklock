//go:build linux

package landlock

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
)

// TestDefaultConfigEtcSecretDenied checks real kernel reads against a synthetic
// /etc tree. It never opens host secrets, and fails with the old /etc/ grant.
func TestDefaultConfigEtcSecretDenied(t *testing.T) {
	const probeEnv = "NOCKLOCK_DEFAULT_ETC_PROBE"
	if root := os.Getenv(probeEnv); root != "" {
		// Retire this permanently restricted thread when the test goroutine exits.
		runtime.LockOSThread()
		abi, err := DetectABI()
		if err != nil || abi == 0 {
			t.Fatalf("detect Landlock: abi=%d err=%v", abi, err)
		}
		cfg := config.DefaultConfig().Filesystem
		fc := &fsfence.FenceConfig{Root: filepath.Join(root, "project"), Mode: cfg.Mode}
		// Relocate every default grant, including /tmp, under the fake host root.
		// This prevents the real /tmp grant from covering the fixture itself.
		for _, p := range cfg.Allow {
			fc.AllowPaths = append(fc.AllowPaths, filepath.Join(root, p))
		}
		spec, err := RulesFromConfig(fc, nil, abi)
		if err != nil {
			t.Fatal(err)
		}
		if err := Apply(spec); err != nil {
			t.Fatal(err)
		}
		if _, err := os.ReadFile(filepath.Join(root, "etc/ld.so.cache")); err != nil {
			t.Fatalf("loader cache read denied: %v", err)
		}
		for _, name := range []string{"etc/environment", "etc/ssl/private/server.key", "etc/ld.so.cache.backup"} {
			_, err := os.ReadFile(filepath.Join(root, name))
			if !errors.Is(err, syscall.EACCES) {
				t.Fatalf("secret %s read error = %v, want EACCES", name, err)
			}
		}
		return
	}
	if abi, err := DetectABI(); err != nil {
		t.Fatal(err)
	} else if abi == 0 {
		t.Skip("Landlock unavailable")
	}
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "project"), 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"etc/ld.so.cache", "etc/environment", "etc/ssl/private/server.key", "etc/ld.so.cache.backup"} {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("synthetic fixture\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := os.ReadFile(path); err != nil {
			t.Fatalf("unfenced read control: %v", err)
		}
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestDefaultConfigEtcSecretDenied$")
	cmd.Env = append(os.Environ(), probeEnv+"="+root)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("default policy probe: %v\n%s", err, strings.TrimSpace(string(output)))
	}
}
