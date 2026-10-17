//go:build unix

package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// trustTestInfo is a crafted FileInfo with a chosen mode and owning uid, so the
// trust walk can be driven over writable, foreign-owned and safe layouts with no
// chmod, no chown and no root.
type trustTestInfo struct {
	mode os.FileMode
	uid  uint32
}

func (i trustTestInfo) Name() string       { return "fixture" }
func (i trustTestInfo) Size() int64        { return 0 }
func (i trustTestInfo) Mode() os.FileMode  { return i.mode }
func (i trustTestInfo) ModTime() time.Time { return time.Time{} }
func (i trustTestInfo) IsDir() bool        { return i.mode.IsDir() }
func (i trustTestInfo) Sys() any           { s := syscall.Stat_t{Uid: i.uid}; return &s }

// trustFixture is a fake filesystem for the config trust walk. Every path
// component defaults to a safe, invoker-owned directory; a test overrides only
// the components it cares about.
type trustFixture struct {
	nodes map[string]trustTestInfo
}

const trustTestUID = 1000

// configLeaf is the path the fixture walks: root -> home -> project -> .nock ->
// config.toml. The ancestors start safe (0755, owned by the invoking uid).
const configLeaf = "/home/user/project/.nock/config.toml"

func newTrustFixture() *trustFixture {
	f := &trustFixture{nodes: map[string]trustTestInfo{}}
	for _, dir := range []string{"/", "/home", "/home/user", "/home/user/project", "/home/user/project/.nock"} {
		f.nodes[dir] = trustTestInfo{mode: os.ModeDir | 0o755, uid: trustTestUID}
	}
	f.nodes[configLeaf] = trustTestInfo{mode: 0o644, uid: trustTestUID}
	return f
}

// install points the lstat seam at the fixture and restores the permissive
// defaults (set in TestMain) afterwards.
func (f *trustFixture) install(t *testing.T) {
	t.Helper()
	prevLstat := configTrustLstat
	configTrustLstat = func(path string) (os.FileInfo, error) {
		info, ok := f.nodes[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return info, nil
	}
	t.Cleanup(func() { configTrustLstat = prevLstat })
}

func TestResolveTrustedConfigPath(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*trustFixture)
		errSub string
	}{
		{"accepted safe layout", func(*trustFixture) {}, ""},
		{"root-owned ancestor accepted", func(f *trustFixture) {
			f.nodes["/home"] = trustTestInfo{mode: os.ModeDir | 0o755, uid: 0}
		}, ""},
		{"writable file refused", func(f *trustFixture) {
			f.nodes[configLeaf] = trustTestInfo{mode: 0o666, uid: trustTestUID}
		}, "group- or world-writable"},
		{"group-writable file refused", func(f *trustFixture) {
			f.nodes[configLeaf] = trustTestInfo{mode: 0o664, uid: trustTestUID}
		}, "group- or world-writable"},
		{"writable ancestor refused", func(f *trustFixture) {
			f.nodes["/home/user/project"] = trustTestInfo{mode: os.ModeDir | 0o777, uid: trustTestUID}
		}, "group- or world-writable"},
		{"sticky world-writable ancestor still refused", func(f *trustFixture) {
			f.nodes["/home/user/project"] = trustTestInfo{mode: os.ModeDir | os.ModeSticky | 0o777, uid: trustTestUID}
		}, "group- or world-writable"},
		{"other-owner file refused", func(f *trustFixture) {
			f.nodes[configLeaf] = trustTestInfo{mode: 0o644, uid: 1001}
		}, "owned by uid 1001"},
		{"other-owner ancestor refused", func(f *trustFixture) {
			f.nodes["/home/user"] = trustTestInfo{mode: os.ModeDir | 0o755, uid: 1001}
		}, "owned by uid 1001"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newTrustFixture()
			tc.change(f)
			f.install(t)
			_, _, err := resolveTrustedConfigPath(configLeaf, trustTestUID)
			if tc.errSub == "" {
				if err != nil {
					t.Fatalf("expected the layout to be accepted, got: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.errSub) {
				t.Fatalf("expected a refusal containing %q, got: %v", tc.errSub, err)
			}
			var refusal configTrustError
			if !errors.As(err, &refusal) {
				t.Fatalf("expected a trust refusal, got an I/O error: %v", err)
			}
		})
	}
}

// scopedTrustLstat makes the real trust walk see only the tree under root: real
// Lstat inside it, a trusted directory for every ancestor above it. The host's
// temp directory is often under a world-writable /tmp, which the walk would
// refuse before reaching the layout a test builds.
func scopedTrustLstat(t *testing.T, root string) {
	t.Helper()
	prev := configTrustLstat
	configTrustLstat = func(path string) (os.FileInfo, error) {
		if withinDirLexical(root, path) {
			return os.Lstat(path)
		}
		return permissiveTrustInfo{}, nil
	}
	t.Cleanup(func() { configTrustLstat = prev })
}

// trustTree is a real directory tree for the end-to-end trust tests. Every
// directory is created 0755 and every config 0600, with explicit chmods so the
// host umask does not decide the outcome.
type trustTree struct {
	t    *testing.T
	root string
}

func newTrustTree(t *testing.T) *trustTree {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	scopedTrustLstat(t, root)
	return &trustTree{t: t, root: root}
}

func (tr *trustTree) path(rel string) string { return filepath.Join(tr.root, rel) }

func (tr *trustTree) dir(rel string, mode os.FileMode) {
	tr.t.Helper()
	if err := os.MkdirAll(tr.path(rel), 0o755); err != nil {
		tr.t.Fatal(err)
	}
	if err := os.Chmod(tr.path(rel), mode); err != nil {
		tr.t.Fatal(err)
	}
}

func (tr *trustTree) config(rel, name string) {
	tr.t.Helper()
	if err := os.WriteFile(tr.path(rel), []byte("[project]\nname = \""+name+"\"\n"), 0o600); err != nil {
		tr.t.Fatal(err)
	}
}

func (tr *trustTree) symlink(target, rel string) {
	tr.t.Helper()
	if err := os.Symlink(tr.path(target), tr.path(rel)); err != nil {
		tr.t.Fatal(err)
	}
}

// TestLoadThroughTrustedSymlinkedParent is the macOS /var -> /private/var shape:
// a config whose path runs through a symlink to a trusted directory loads, and
// the read follows the same resolved path the walk checked.
func TestLoadThroughTrustedSymlinkedParent(t *testing.T) {
	t.Setenv(AllowUntrustedConfigEnv, "")
	tr := newTrustTree(t)
	tr.dir("private/var/project/.nock", 0o755)
	tr.config("private/var/project/.nock/config.toml", "via-symlink")
	tr.symlink("private/var", "var")

	cfg, err := Load(tr.path("var/project/.nock/config.toml"))
	if err != nil {
		t.Fatalf("a config behind a trusted symlinked parent should load, got: %v", err)
	}
	if cfg.Project.Name != "via-symlink" {
		t.Fatalf("loaded project %q, want via-symlink", cfg.Project.Name)
	}
}

// TestLoadRefusesSymlinkIntoWritableDir proves the walk checks the symlink's
// target: a project directory that links into a world- or group-writable
// directory is refused on that directory, and the same layout with the write
// bits cleared loads (the negative control).
func TestLoadRefusesSymlinkIntoWritableDir(t *testing.T) {
	t.Setenv(AllowUntrustedConfigEnv, "")
	for _, mode := range []os.FileMode{0o777, 0o775} {
		t.Run(fmt.Sprintf("%04o", mode), func(t *testing.T) {
			tr := newTrustTree(t)
			tr.dir("shared/.nock", 0o755)
			tr.config("shared/.nock/config.toml", "shared")
			tr.dir("shared", mode)
			tr.dir("home", 0o755)
			tr.symlink("shared", "home/project")
			path := tr.path("home/project/.nock/config.toml")

			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tr.path("shared")+" is group- or world-writable") {
				t.Fatalf("expected a refusal naming %s, got: %v", tr.path("shared"), err)
			}

			tr.dir("shared", 0o755)
			if _, err := Load(path); err != nil {
				t.Fatalf("the same layout without the write bits should load, got: %v", err)
			}
		})
	}
}

// TestLoadRefusesSymlinkPlantedInWritableDir is the planted /tmp/.nock case
// with a symlink: another user drops .nock in a writable directory, pointing at
// a config that passes the trust rule on its own. The directory holding the link
// is refused, sticky bit or not; with the write bits cleared the same link loads
// (the negative control).
func TestLoadRefusesSymlinkPlantedInWritableDir(t *testing.T) {
	t.Setenv(AllowUntrustedConfigEnv, "")
	for _, mode := range []os.FileMode{0o777, os.ModeSticky | 0o777} {
		t.Run(mode.String(), func(t *testing.T) {
			tr := newTrustTree(t)
			tr.dir("victim/.nock", 0o755)
			tr.config("victim/.nock/config.toml", "victim")
			tr.dir("tmp", 0o755)
			tr.symlink("victim/.nock", "tmp/.nock")
			if err := os.Chmod(tr.path("tmp"), mode); err != nil {
				t.Fatal(err)
			}
			path := tr.path("tmp/.nock/config.toml")

			_, err := Load(path)
			if err == nil || !strings.Contains(err.Error(), tr.path("tmp")+" is group- or world-writable") {
				t.Fatalf("expected a refusal naming %s, got: %v", tr.path("tmp"), err)
			}

			tr.dir("tmp", 0o755)
			if _, err := Load(path); err != nil {
				t.Fatalf("the same link in a trusted directory should load, got: %v", err)
			}
		})
	}
}

// TestLoadDotDotChecksTheFileItReads pins check and read to the same file. With
// safe/link -> wild/deep, the path safe/link/../config.toml lexically names
// safe/config.toml, but the kernel reads wild/config.toml. The walk must judge
// wild/config.toml: refused while wild is world-writable, loaded (and its
// contents, not safe's, returned) once it is not.
func TestLoadDotDotChecksTheFileItReads(t *testing.T) {
	t.Setenv(AllowUntrustedConfigEnv, "")
	tr := newTrustTree(t)
	tr.dir("safe", 0o755)
	tr.config("safe/config.toml", "lexical")
	tr.dir("wild/deep", 0o755)
	tr.config("wild/config.toml", "resolved")
	tr.dir("wild", 0o777)
	tr.symlink("wild/deep", "safe/link")
	path := tr.path("safe/link") + "/../config.toml"

	_, err := Load(path)
	if err == nil || !strings.Contains(err.Error(), tr.path("wild")+" is group- or world-writable") {
		t.Fatalf("expected a refusal naming %s, got: %v", tr.path("wild"), err)
	}

	tr.dir("wild", 0o755)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("expected the resolved config to load once its directory is trusted, got: %v", err)
	}
	if cfg.Project.Name != "resolved" {
		t.Fatalf("loaded project %q, want the file the kernel reads (resolved)", cfg.Project.Name)
	}
}

// TestLoadRefusesNonRegularConfig refuses a directory standing where the config
// file should be, rather than reading or blocking on it.
func TestLoadRefusesNonRegularConfig(t *testing.T) {
	t.Setenv(AllowUntrustedConfigEnv, "")
	tr := newTrustTree(t)
	tr.dir(".nock/config.toml", 0o755)
	if _, err := Load(tr.path(".nock/config.toml")); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("expected a not-a-regular-file refusal, got: %v", err)
	}
}

// TestLoadMissingConfigKeepsNotExist keeps the missing-config error matchable
// with errors.Is now that the path is resolved before it is read.
func TestLoadMissingConfigKeepsNotExist(t *testing.T) {
	t.Setenv(AllowUntrustedConfigEnv, "")
	tr := newTrustTree(t)
	_, err := Load(tr.path(".nock/config.toml"))
	if !errors.Is(err, os.ErrNotExist) || !strings.Contains(err.Error(), "failed to read config at") {
		t.Fatalf("expected a wrapped not-exist read error, got: %v", err)
	}
}

// TestReadTrustedConfigEscapeHatch proves the operator escape hatch disables the
// walk, and that only a truthy value does so: an empty value leaves it on. This
// is the negative control for the hatch -- the untrusted layout loads only when
// the hatch is truthy.
func TestReadTrustedConfigEscapeHatch(t *testing.T) {
	tr := newTrustTree(t)
	tr.dir("project/.nock", 0o755)
	tr.config("project/.nock/config.toml", "hatch")
	tr.dir("project", 0o777)
	path := tr.path("project/.nock/config.toml")

	t.Setenv(AllowUntrustedConfigEnv, "1")
	if _, err := Load(path); err != nil {
		t.Fatalf("hatch=1 should accept the layout, got: %v", err)
	}

	t.Setenv(AllowUntrustedConfigEnv, "")
	if _, err := Load(path); err == nil {
		t.Fatal("empty hatch must leave the trust walk on, but the layout was accepted")
	}
}
