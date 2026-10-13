package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nocktechnologies/nocklock/internal/config"
	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
	"github.com/nocktechnologies/nocklock/internal/fence/fs/landlock"
	"github.com/nocktechnologies/nocklock/internal/logging"
)

func TestManagedSigningKeyDirectoryLandlockDeny(t *testing.T) {
	base := t.TempDir()
	project := filepath.Join(base, "project")
	keyRoot := filepath.Join(base, "config")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_CONFIG_HOME", keyRoot)
	key, err := logging.DefaultSigningKeyPath()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := logging.EnsurePublicKeyFile(key); err != nil {
		t.Fatal(err)
	}
	_, denied, err := withManagedSigningKeyDeny(nil)
	if err != nil {
		t.Fatal(err)
	}
	realKey, err := filepath.EvalSymlinks(key)
	if err != nil {
		t.Fatal(err)
	}
	if denied != filepath.Dir(realKey) {
		t.Fatalf("deny = %q; want canonical key directory", denied)
	}
	for _, grant := range []string{"none", "read", "write", "root"} {
		t.Run(grant, func(t *testing.T) {
			cfg := config.FilesystemConfig{Root: project, Mode: "read-write", Deny: []string{denied}}
			switch grant {
			case "read":
				cfg.Allow = []string{keyRoot}
			case "write":
				cfg.AllowRW = []string{keyRoot}
			case "root":
				cfg.Root = base
			}
			resolved, err := fsfence.ProcessConfig(cfg)
			if err != nil {
				t.Fatal(err)
			}
			_, err = landlock.RulesFromConfig(resolved, nil, 3)
			if grant == "none" {
				if err != nil {
					t.Fatalf("outside-grants key must permit the project: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), "cannot be enforced by Landlock") {
				t.Fatalf("overlapping %s grant must refuse: %v", grant, err)
			}
		})
	}
}

func TestManagedSigningKeyDirectoryResolution(t *testing.T) {
	base := resolvedTempDir(t)
	t.Run("not yet created resolves under the existing ancestor", func(t *testing.T) {
		t.Setenv("XDG_CONFIG_HOME", filepath.Join(base, "missing"))
		_, dir, err := withManagedSigningKeyDeny(nil)
		if want := filepath.Join(base, "missing", "nocklock"); err != nil || dir != want {
			t.Fatalf("dir = %q, err = %v; want %q", dir, err, want)
		}
	})
	t.Run("broken symlink fails closed", func(t *testing.T) {
		link := filepath.Join(base, "dangling")
		if err := os.Symlink(filepath.Join(base, "nowhere"), link); err != nil {
			t.Fatal(err)
		}
		t.Setenv("XDG_CONFIG_HOME", link)
		if _, _, err := withManagedSigningKeyDeny(nil); err == nil {
			t.Fatal("unresolvable signer directory must fail closed")
		}
	})
}
