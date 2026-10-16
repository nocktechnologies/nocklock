//go:build unix

package config

import (
	"os"
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

// install points the package seams at the fixture and restores the permissive
// defaults (set in TestMain) afterwards.
func (f *trustFixture) install(t *testing.T) {
	t.Helper()
	prevLstat, prevUID := configTrustLstat, configTrustUID
	configTrustLstat = func(path string) (os.FileInfo, error) {
		info, ok := f.nodes[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return info, nil
	}
	configTrustUID = func() uint32 { return trustTestUID }
	t.Cleanup(func() { configTrustLstat, configTrustUID = prevLstat, prevUID })
}

func TestCheckConfigTrust(t *testing.T) {
	for _, tc := range []struct {
		name   string
		change func(*trustFixture)
		errSub string
	}{
		{"accepted safe layout", func(*trustFixture) {}, ""},
		{"root-owned ancestor accepted", func(f *trustFixture) {
			f.nodes["/home"] = trustTestInfo{mode: os.ModeDir | 0o755, uid: 0}
		}, ""},
		{"symlinked config refused", func(f *trustFixture) {
			f.nodes[configLeaf] = trustTestInfo{mode: os.ModeSymlink | 0o777, uid: trustTestUID}
		}, "is a symlink"},
		{"symlinked ancestor refused", func(f *trustFixture) {
			f.nodes["/home/user/project"] = trustTestInfo{mode: os.ModeSymlink | 0o777, uid: trustTestUID}
		}, "is a symlink"},
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
			err := checkConfigTrust(configLeaf)
			if tc.errSub == "" {
				if err != nil {
					t.Fatalf("expected the layout to be accepted, got: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.errSub) {
				t.Fatalf("expected a refusal containing %q, got: %v", tc.errSub, err)
			}
			if !strings.Contains(err.Error(), configLeaf) {
				t.Fatalf("refusal should name the config file %q, got: %v", configLeaf, err)
			}
		})
	}
}

// TestCheckConfigTrustEscapeHatch proves the operator escape hatch disables the
// walk, and that only a truthy value does so: an empty value leaves it on. This
// is the negative control for the hatch -- the untrusted layout loads only when
// the hatch is truthy.
func TestCheckConfigTrustEscapeHatch(t *testing.T) {
	f := newTrustFixture()
	f.nodes["/home/user/project"] = trustTestInfo{mode: os.ModeDir | 0o777, uid: trustTestUID}
	f.install(t)

	t.Setenv(AllowUntrustedConfigEnv, "1")
	if err := checkConfigTrust(configLeaf); err != nil {
		t.Fatalf("hatch=1 should accept the layout, got: %v", err)
	}

	t.Setenv(AllowUntrustedConfigEnv, "")
	if err := checkConfigTrust(configLeaf); err == nil {
		t.Fatal("empty hatch must leave the trust walk on, but the layout was accepted")
	}
}
