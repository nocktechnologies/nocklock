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
	denied, err := managedSigningKeyDirectory()
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

func TestManagedSigningKeyDirectoryFailsOnUnresolvablePath(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(t.TempDir(), "missing"))
	if _, err := managedSigningKeyDirectory(); err == nil {
		t.Fatal("missing signer directory must fail closed")
	}
}
