//go:build linux || darwin

package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
)

type interposerTestInfo struct {
	mode os.FileMode
	stat syscall.Stat_t
}

func (i interposerTestInfo) Name() string       { return "fixture" }
func (i interposerTestInfo) Size() int64        { return 0 }
func (i interposerTestInfo) Mode() os.FileMode  { return i.mode }
func (i interposerTestInfo) ModTime() time.Time { return time.Time{} }
func (i interposerTestInfo) IsDir() bool        { return i.mode.IsDir() }
func (i interposerTestInfo) Sys() any           { return &i.stat }

type interposerFixture struct {
	nodes map[string]interposerTestInfo
	links map[string]string
	fs    interposerFilesystem
}

func newInterposerFixture() *interposerFixture {
	f := &interposerFixture{nodes: map[string]interposerTestInfo{}, links: map[string]string{}}
	f.fs = interposerFilesystem{uid: 1000}
	f.fs.lstat = func(path string) (os.FileInfo, error) {
		info, ok := f.nodes[path]
		if !ok {
			return nil, os.ErrNotExist
		}
		return info, nil
	}
	f.fs.readlink = func(path string) (string, error) {
		link, ok := f.links[path]
		if !ok {
			return "", fmt.Errorf("not a symlink: %s", path)
		}
		return link, nil
	}
	for _, dir := range []string{"/", "/safe", "/safe/bin", "/safe/cellar", "/safe/cellar/nocklock", "/safe/cellar/nocklock/1.0", "/safe/cellar/nocklock/1.0/lib"} {
		f.add(dir, os.ModeDir|0o755, 0)
	}
	f.add("/safe/bin/libfence_fs.so", 0o644, 1000)
	f.add("/safe/cellar/nocklock/1.0/lib/libfence_fs.so", 0o644, 1000)
	return f
}

func (f *interposerFixture) add(path string, mode os.FileMode, uid uint32) {
	f.nodes[path] = interposerTestInfo{mode: mode, stat: syscall.Stat_t{Dev: 1, Ino: uint64(len(f.nodes) + 1), Uid: uid}}
}

func TestInterposerTrustLayoutsAndPermissions(t *testing.T) {
	const candidate = "/safe/bin/libfence_fs.so"
	for _, tc := range []struct {
		name   string
		change func(*interposerFixture)
		want   string
		err    string
	}{
		{"source adjacent", func(f *interposerFixture) {}, candidate, ""},
		{"root owned", func(f *interposerFixture) { f.add(candidate, 0o755, 0) }, candidate, ""},
		{"homebrew link", func(f *interposerFixture) {
			f.add(candidate, os.ModeSymlink|0o777, 1000)
			f.links[candidate] = "../cellar/nocklock/1.0/lib/libfence_fs.so"
		}, "/safe/cellar/nocklock/1.0/lib/libfence_fs.so", ""},
		{"symlink ancestor", func(f *interposerFixture) {
			f.add("/safe/bin", os.ModeSymlink|0o777, 0)
			f.links["/safe/bin"] = "/safe/cellar/nocklock/1.0/lib"
			// Lstat of the full original spelling follows its parent symlink.
			f.nodes[candidate] = f.nodes["/safe/cellar/nocklock/1.0/lib/libfence_fs.so"]
		}, "/safe/cellar/nocklock/1.0/lib/libfence_fs.so", ""},
		{"group writable file", func(f *interposerFixture) { f.add(candidate, 0o664, 1000) }, "", "group/world-writable"},
		{"world writable file", func(f *interposerFixture) { f.add(candidate, 0o646, 0) }, "", "group/world-writable"},
		{"foreign file owner", func(f *interposerFixture) { f.add(candidate, 0o644, 1001) }, "", "owned by uid 1001"},
		{"writable original ancestor", func(f *interposerFixture) { f.add("/safe", os.ModeDir|0o775, 1000) }, "", "group/world-writable"},
		{"sticky ancestor", func(f *interposerFixture) { f.add("/safe", os.ModeDir|os.ModeSticky|0o777, 0) }, "", "group/world-writable"},
		{"foreign ancestor owner", func(f *interposerFixture) { f.add("/safe", os.ModeDir|0o755, 1001) }, "", "owned by uid 1001"},
		{"writable target ancestor", func(f *interposerFixture) {
			f.add(candidate, os.ModeSymlink|0o777, 1000)
			f.links[candidate] = "/safe/cellar/nocklock/1.0/lib/libfence_fs.so"
			f.add("/safe/cellar", os.ModeDir|0o777, 0)
		}, "", "group/world-writable"},
		{"foreign symlink owner", func(f *interposerFixture) {
			f.add(candidate, os.ModeSymlink|0o777, 1001)
			f.links[candidate] = "/safe/cellar/nocklock/1.0/lib/libfence_fs.so"
		}, "", "owned by uid 1001"},
		{"dotdot does not hide unsafe ancestor", func(f *interposerFixture) {
			f.add(candidate, os.ModeSymlink|0o777, 1000)
			f.links[candidate] = "/safe/unsafe/../cellar/nocklock/1.0/lib/libfence_fs.so"
			f.add("/safe/unsafe", os.ModeDir|0o777, 0)
		}, "", "group/world-writable"},
		{"directory", func(f *interposerFixture) { f.add(candidate, os.ModeDir|0o755, 0) }, "", "not a regular file"},
		{"fifo", func(f *interposerFixture) { f.add(candidate, os.ModeNamedPipe|0o600, 1000) }, "", "not a regular file"},
		{"broken link", func(f *interposerFixture) {
			f.add(candidate, os.ModeSymlink|0o777, 1000)
			f.links[candidate] = "/safe/missing"
		}, "", "disappeared or became unreadable"},
		{"loop", func(f *interposerFixture) {
			f.add(candidate, os.ModeSymlink|0o777, 1000)
			f.links[candidate] = candidate
		}, "", "too many symlinks"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInterposerFixture()
			tc.change(f)
			got, err := inspectInterposerPath(candidate, f.fs)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) || got != "" {
					t.Fatalf("got path=%q err=%v, want refusal containing %q", got, err, tc.err)
				}
			} else if err != nil || got != tc.want {
				t.Fatalf("got path=%q err=%v, want %q", got, err, tc.want)
			}
		})
	}
}

func TestInterposerTrustRejectsObservedReplacement(t *testing.T) {
	const candidate = "/safe/bin/libfence_fs.so"
	for _, tc := range []struct {
		name   string
		path   string
		mutate func(*interposerFixture)
	}{
		{"library inode", candidate, func(f *interposerFixture) {
			n := f.nodes[candidate]
			n.stat.Ino += 100
			f.nodes[candidate] = n
		}},
		{"ancestor inode", "/safe/bin", func(f *interposerFixture) {
			n := f.nodes["/safe/bin"]
			n.stat.Ino += 100
			f.nodes["/safe/bin"] = n
		}},
		{"symlink target", candidate, func(f *interposerFixture) { f.links[candidate] = "/safe/cellar/nocklock/1.0/lib/other.so" }},
		{"target inode after target read", "/safe/cellar/nocklock/1.0/lib/libfence_fs.so", func(f *interposerFixture) {
			path := "/safe/cellar/nocklock/1.0/lib/libfence_fs.so"
			n := f.nodes[path]
			n.stat.Ino += 100
			f.nodes[path] = n
		}},
		{"candidate disappears", candidate, func(f *interposerFixture) { delete(f.nodes, candidate) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newInterposerFixture()
			if tc.name == "symlink target" || tc.name == "target inode after target read" {
				f.add(candidate, os.ModeSymlink|0o777, 1000)
				f.links[candidate] = "/safe/cellar/nocklock/1.0/lib/libfence_fs.so"
			}
			original := f.fs.lstat
			reads := 0
			f.fs.lstat = func(path string) (os.FileInfo, error) {
				if path == tc.path {
					reads++
					if reads == 2 {
						tc.mutate(f)
					}
				}
				return original(path)
			}
			got, err := inspectInterposerPath(candidate, f.fs)
			if err == nil || got != "" || !(strings.Contains(err.Error(), "changed during validation") || strings.Contains(err.Error(), "disappeared")) {
				t.Fatalf("replacement accepted: path=%q err=%v", got, err)
			}
		})
	}
}

func TestInterposerResolverDoesNotFallBackAfterUnsafeCandidate(t *testing.T) {
	f := newInterposerFixture()
	f.add("/safe/bin/libfence_fs.so", 0o666, 1000)
	got, err := findTrustedLibFenceFS("/safe/bin/nocklock", "/project", []string{"/safe/cellar/nocklock/1.0/lib/libfence_fs.so"}, func(path string) (string, error) {
		return inspectInterposerPath(path, f.fs)
	})
	if err == nil || got != "" || !strings.Contains(err.Error(), "refusing to launch") {
		t.Fatalf("unsafe candidate bypassed: path=%q err=%v", got, err)
	}
}

func TestInterposerTrustRealWritableFileAndLegacyNegativeControl(t *testing.T) {
	candidate := filepath.Join(t.TempDir(), "libfence_fs.so")
	if err := os.WriteFile(candidate, []byte("inert fixture; never loaded"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(candidate, 0o777); err != nil {
		t.Fatal(err)
	}
	// Released resolver's acceptance predicate: os.Stat succeeds and the file
	// is outside the project. This is deliberately insufficient and is the red
	// control; neither resolver executes this inert file.
	project := t.TempDir()
	if _, err := os.Stat(candidate); err != nil || pathIsWithinDir(candidate, project) {
		t.Fatalf("legacy negative control did not accept its unsafe fixture: %v", err)
	}
	if got, err := trustedInterposerPath(candidate); err == nil || got != "" || !strings.Contains(err.Error(), "group/world-writable") {
		t.Fatalf("strict resolver accepted writable real file: path=%q err=%v", got, err)
	}
}

func TestDoctorRealInterposerProbe(t *testing.T) {
	if os.Getenv("NOCKLOCK_INTERPOSER_DOCTOR_CHILD") == "1" {
		caps := currentDoctorCapabilities
		caps.goos = "linux" // Exercise the real library probe on either Unix test host.
		check := filesystemDoctorCheck(&config.Config{Filesystem: config.FilesystemConfig{Root: "/project"}}, caps)
		if check.Severity != doctorCritical || check.Status != "configured-but-backend-missing" || !strings.Contains(check.Message, "group/world-writable") {
			t.Fatalf("unsafe interposer was not reported: %+v", check)
		}
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(executable)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	child := filepath.Join(dir, "doctor-test")
	if err := os.WriteFile(child, binary, 0o700); err != nil {
		t.Fatal(err)
	}
	candidate := filepath.Join(dir, "libfence_fs.so")
	if err := os.WriteFile(candidate, []byte("inert fixture; never loaded"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(candidate, 0o777); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, child, "-test.run=^TestDoctorRealInterposerProbe$", "-test.v")
	cmd.Dir = t.TempDir()
	cmd.Env = append(os.Environ(), "NOCKLOCK_INTERPOSER_DOCTOR_CHILD=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("real doctor probe: %v\n%s", err, output)
	}
}

func TestInterposerResolverOnlyInitialAbsencePermitsFallback(t *testing.T) {
	for _, broken := range []bool{false, true} {
		t.Run(fmt.Sprintf("broken=%t", broken), func(t *testing.T) {
			f := newInterposerFixture()
			const candidate = "/safe/bin/libfence_fs.so"
			const fallback = "/safe/cellar/nocklock/1.0/lib/libfence_fs.so"
			delete(f.nodes, candidate)
			if broken {
				f.add(candidate, os.ModeSymlink|0o777, 1000)
				f.links[candidate] = "/safe/missing"
			}
			got, err := findTrustedLibFenceFS("/safe/bin/nocklock", "/project", []string{fallback}, func(path string) (string, error) {
				return inspectInterposerPath(path, f.fs)
			})
			if broken {
				if err == nil || got != "" || !strings.Contains(err.Error(), "refusing to launch") {
					t.Fatalf("broken existing candidate silently fell back: %q, %v", got, err)
				}
			} else if err != nil || got != fallback {
				t.Fatalf("missing candidate did not permit safe fallback: %q, %v", got, err)
			}
		})
	}
}

func TestTrustedVerificationScratchFallsBack(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	fixture, err := os.MkdirTemp(home, ".nocklock-scratch-test-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(fixture) })
	unsafe, safe := filepath.Join(fixture, "unsafe"), filepath.Join(fixture, "safe")
	for _, dir := range []string{unsafe, safe} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(unsafe, 0o777); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		bases []string
		roots []string
		want  bool
	}{
		{"unsafe home safe state", []string{unsafe, safe}, nil, true},
		{"all unsafe", []string{unsafe}, nil, false},
		{"safe state inside policy", []string{unsafe, safe}, []string{safe}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, cleanup, ok := createTrustedScratchOutsideBases(tc.roots, tc.bases)
			if cleanup != nil {
				defer cleanup()
			}
			if ok != tc.want {
				t.Fatalf("scratch = %q, ok = %t; want %t", dir, ok, tc.want)
			}
			if ok {
				if !pathWithinAny(dir, []string{safe}) {
					t.Fatalf("scratch %q did not use the safe fallback %q", dir, safe)
				}
				probe := filepath.Join(dir, "probe")
				if err := os.WriteFile(probe, []byte("inert; never executed"), 0o700); err != nil {
					t.Fatal(err)
				}
				if _, err := trustedInterposerPath(probe); err != nil {
					t.Fatalf("selected scratch is not trusted: %v", err)
				}
			} else if dir != "" || cleanup != nil {
				t.Fatalf("refusal returned scratch %q or cleanup", dir)
			}
			entries, err := os.ReadDir(unsafe)
			if err != nil || len(entries) != 0 {
				t.Fatalf("unsafe base contains scratch: entries=%v err=%v", entries, err)
			}
		})
	}
}
