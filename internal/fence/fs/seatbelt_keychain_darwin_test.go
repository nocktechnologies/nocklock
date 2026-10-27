//go:build darwin

package fs

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The private keychain lives outside the sensitive-path denylist so a denied
// query proves service isolation independently of file rules. It is never the
// default keychain or in the user's search list. Both APIs use an explicit ref.
func TestSeatbeltKeychainServiceIsolation_RealSandboxExec(t *testing.T) {
	requireSandboxExec(t)
	clang, err := exec.LookPath("clang")
	if err != nil {
		if os.Getenv("NOCKLOCK_SANDBOX_REQUIRE") == "1" {
			t.Fatal("clang is required for the Keychain enforcement proof")
		}
		t.Skip("clang unavailable: Keychain enforcement not proved")
	}
	run := func(t *testing.T, argv ...string) (string, error) {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
		cmd.WaitDelay = 5 * time.Second
		out, err := cmd.CombinedOutput()
		if ctx.Err() != nil {
			t.Fatalf("Keychain proof command timed out: %s", argv[0])
		}
		return string(out), err
	}
	mustRun := func(t *testing.T, argv ...string) string {
		t.Helper()
		out, err := run(t, argv...)
		if err != nil {
			t.Fatalf("%s failed: %v\n%s", argv[0], err, out)
		}
		return out
	}
	base := t.TempDir()
	probe := filepath.Join(base, "keychain-probe")
	mustRun(t, clang, "-Werror", "-Wno-deprecated-declarations", "-framework", "Security",
		"-framework", "CoreFoundation", "testdata/keychain_probe.c", "-o", probe)
	root := filepath.Join(base, "project")
	sensitive := filepath.Join(base, "sensitive")
	for _, dir := range []string{root, sensitive} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	allowed := filepath.Join(root, "allowed.txt")
	if err := os.WriteFile(allowed, []byte("ordinary-file"), 0600); err != nil {
		t.Fatal(err)
	}
	keychain := filepath.Join(root, "synthetic.keychain")
	// Inspect metadata only; never read an item from a pre-existing keychain.
	searchList := mustRun(t, "/usr/bin/security", "list-keychains", "-d", "user")
	defaultKeychain := mustRun(t, "/usr/bin/security", "default-keychain", "-d", "user")
	t.Cleanup(func() {
		if got := mustRun(t, "/usr/bin/security", "list-keychains", "-d", "user"); got != searchList {
			t.Error("Keychain proof changed the user's search list")
		}
		if got := mustRun(t, "/usr/bin/security", "default-keychain", "-d", "user"); got != defaultKeychain {
			t.Error("Keychain proof changed the user's default keychain")
		}
	})
	t.Cleanup(func() { mustRun(t, probe, "delete", keychain) })
	mustRun(t, probe, "create", keychain)
	const canary = "SYNTHETIC-CANARY-ONLY"
	for _, api := range []string{"legacy", "item"} {
		if out := mustRun(t, probe, api, keychain); !strings.Contains(out, canary) {
			t.Fatalf("unfenced %s control did not read the synthetic credential: %q", api, out)
		}
	}

	for _, tc := range []struct {
		name     string
		root     bool
		hardened bool
		port     int
	}{
		{"baseline", false, false, 0},
		{"hardened", false, true, 0},
		{"root-without-proxy", true, false, 0},
		{"root-with-proxy", true, false, 54321},
		{"root-hardened-with-proxy", true, true, 54321},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var profile string
			var err error
			if tc.root {
				profile, _, err = GenerateTaggedWriteConfinementProfile([]string{sensitive}, root,
					"read-write", tc.hardened, DenialTag("keychain-proof"), tc.port)
			} else {
				profile, _, err = GenerateProfileAndCount([]string{sensitive}, tc.hardened)
			}
			if err != nil {
				t.Fatal(err)
			}
			pf := filepath.Join(t.TempDir(), "profile.sb")
			if err := os.WriteFile(pf, []byte(profile), 0600); err != nil {
				t.Fatal(err)
			}
			if out := mustRun(t, SandboxExecPath, "-f", pf, "/bin/cat", allowed); out != "ordinary-file" {
				t.Fatalf("ordinary file control: %q", out)
			}
			for _, api := range []string{"legacy", "item"} {
				out, err := run(t, SandboxExecPath, "-f", pf, probe, api, keychain)
				var exit *exec.ExitError
				if !errors.As(err, &exit) || exit.ExitCode() != 1 ||
					!strings.Contains(out, "keychain-status=") || strings.Contains(out, canary) {
					t.Errorf("%s must start normally but fail its Keychain query: err=%v out=%q", api, err, out)
				}
			}
			// Remove only the Keychain Mach rule. The identical process, database,
			// path denies and network floor must then allow both credential reads.
			start := strings.Index(profile, "(deny mach-lookup")
			if start < 0 {
				t.Fatal("Keychain Mach rule missing")
			}
			end := strings.Index(profile[start:], "\n)\n")
			if end < 0 {
				t.Fatal("Keychain Mach rule terminator missing")
			}
			end += start + len("\n)\n")
			for _, service := range []string{"com.apple.SecurityServer"} {
				if !strings.Contains(profile[start:end], `(global-name "`+service+`")`) {
					t.Fatalf("Keychain Mach rule does not cover %s", service)
				}
			}
			mutant := profile[:start] + profile[end:]
			if err := os.WriteFile(pf, []byte(mutant), 0600); err != nil {
				t.Fatal(err)
			}
			for _, api := range []string{"legacy", "item"} {
				out := mustRun(t, SandboxExecPath, "-f", pf, probe, api, keychain)
				if !strings.Contains(out, canary) {
					t.Fatalf("%s policy-removal control failed to read the canary: %q", api, out)
				}
			}
		})
	}
}
