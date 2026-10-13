//go:build darwin

package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
	"github.com/spf13/cobra"
)

func TestWrapMacOSDeniesManagedSigningKey(t *testing.T) {
	requireSandboxExecForWrap(t)
	for _, placement := range []string{"default", "xdg", "symlinked-xdg", "project-xdg"} {
		t.Run(placement, func(t *testing.T) {
			base := t.TempDir()
			home := filepath.Join(base, "home")
			project := filepath.Join(base, "project")
			for _, dir := range []string{home, project} {
				if err := os.Mkdir(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("HOME", home)
			t.Setenv("LANG", "C")
			t.Setenv("XDG_STATE_HOME", filepath.Join(base, "state"))
			t.Setenv("XDG_CONFIG_HOME", "")
			switch placement {
			case "xdg":
				t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "config"))
			case "symlinked-xdg":
				target := filepath.Join(base, "real-config")
				if err := os.Mkdir(target, 0700); err != nil {
					t.Fatal(err)
				}
				link := filepath.Join(base, "config-link")
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
				t.Setenv("XDG_CONFIG_HOME", link)
			case "project-xdg":
				t.Setenv("XDG_CONFIG_HOME", filepath.Join(project, "config"))
			}
			writeTestConfig(t, project, config.DefaultTOML())
			withWorkingDir(t, project)
			key, err := logging.DefaultSigningKeyPath()
			if err != nil {
				t.Fatal(err)
			}
			pub, err := logging.EnsurePublicKeyFile(key)
			if err != nil {
				t.Fatal(err)
			}
			// The host can read the fresh fixture key; no user key is used or printed.
			if seed, err := os.ReadFile(key); err != nil || len(seed) != 32 {
				t.Fatalf("host key control: length=%d error=%v", len(seed), err)
			}
			ordinary := filepath.Join(project, "ordinary")
			if err := os.WriteFile(ordinary, []byte("allowed"), 0600); err != nil {
				t.Fatal(err)
			}
			cmd := &cobra.Command{}
			cmd.SetContext(context.Background())
			// Reading project data and creating/renaming/removing ordinary files
			// remains allowed; reading or unlinking the key must be kernel-denied.
			script := `cat "$1" >/dev/null || exit 10; if error=$(cat "$2" 2>&1 >/dev/null); then exit 42; fi; case "$error" in *"Operation not permitted"*|*"Permission denied"*) ;; *) exit 41 ;; esac; if rm "$2" 2>/dev/null; then exit 44; fi; printf allowed > "$3"; mv "$1" "$1.moved" && rm "$1.moved" || exit 11`
			if placement == "project-xdg" {
				script += `; parent="$(dirname "$(dirname "$2")")"; if mv "$parent" "$parent-moved" 2>/dev/null; then if cat "$parent-moved/nocklock/signing-ed25519.key" >/dev/null 2>&1; then exit 43; fi; fi`
			}
			err = wrapCmd.RunE(cmd, []string{"--", "/bin/sh", "-c", script, "sh", ordinary, key, filepath.Join(project, "written")})
			if err != nil {
				t.Fatalf("wrapped key denial / project allow control: %v", err)
			}
			if _, err := os.Stat(filepath.Join(project, "written")); err != nil {
				t.Fatal(err)
			}
			logger, err := logging.NewLogger(resolvedAuditDB(t, project), project)
			if err != nil {
				t.Fatal(err)
			}
			defer logger.Close()
			chain, err := logger.VerifyChainSigned(pub, true)
			if err != nil || chain.SigState != "authentic" {
				t.Fatalf("parent signing must still work: %+v, %v", chain, err)
			}
		})
	}
}
