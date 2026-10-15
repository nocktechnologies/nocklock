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
	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
	"github.com/nocktechnologies/nocklock/internal/fence/fs/landlock"
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

func TestInterposerResolverSkipsLibraryInsideSymlinkedWorkingDirectory(t *testing.T) {
	base := t.TempDir()
	real := filepath.Join(base, "real")
	other := filepath.Join(base, "other")
	for _, dir := range []string{real, other} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{real, other} {
		if err := os.WriteFile(filepath.Join(dir, "libfence_fs.so"), []byte("inert; never loaded"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Report only the fixture libraries as present so host /usr/lib paths do not
	// influence the result; canonicalization matches the production resolver.
	inspect := func(path string) (string, error) {
		if !strings.HasPrefix(path, base) {
			return "", os.ErrNotExist
		}
		return filepath.EvalSymlinks(path)
	}
	for _, tc := range []struct {
		name, workingDir, candidate string
		want                        string
	}{
		{"cwd spelled through symlink", link, filepath.Join(real, "libfence_fs.so"), ""},
		{"candidate spelled through symlink", real, filepath.Join(link, "libfence_fs.so"), ""},
		{"negative control: library outside cwd", link, filepath.Join(other, "libfence_fs.so"), filepath.Join(other, "libfence_fs.so")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := findTrustedLibFenceFS("", tc.workingDir, []string{tc.candidate}, inspect)
			if tc.want == "" {
				if err == nil || got != "" {
					t.Fatalf("library inside the working directory was accepted: %q", got)
				}
				return
			}
			want, _ := filepath.EvalSymlinks(tc.want)
			if err != nil || got != want {
				t.Fatalf("safe library outside cwd rejected: got %q err %v; want %q", got, err, want)
			}
		})
	}
}

// TestQueueProjectLibrarySymlinkCannotChooseOutsideTarget covers the Gander
// MAJOR: a project-owned pointer (project/libfence_fs.so) that is itself a
// symlink to a trusted library outside the project must be refused, because the
// pointer the resolver found sits inside the project — whatever it targets. The
// earlier symlinked-cwd test only exercised an in-project pointer to an
// in-project target; it never covered a pointer that escapes outward, which the
// resolve-both exclusion lets through because it canonicalizes the candidate
// before the containment check.
//
// It also covers the ancestor-symlink shape (Gander round 5): a candidate
// spelled OUTSIDE the project whose PARENT directory is a symlink INTO the
// project, with the project file itself a symlink escaping outward. The lexical
// arm sees an outside spelling and the resolved exclusions canonicalize the
// candidate outward, so only the parent-directory resolution refuses it.
//
// The positive controls prove a trusted installed or Homebrew-style link that
// lives outside the project still resolves.
func TestQueueProjectLibrarySymlinkCannotChooseOutsideTarget(t *testing.T) {
	base := resolvedTempDir(t)
	proj := filepath.Join(base, "proj") // the project (working directory)
	installed := filepath.Join(base, "installed")
	cellar := filepath.Join(base, "cellar")
	opt := filepath.Join(base, "opt")
	for _, dir := range []string{proj, installed, cellar, opt} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// A symlinked spelling of the project root, so raw and canonical cwd differ.
	projLink := filepath.Join(base, "projlink")
	if err := os.Symlink(proj, projLink); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	// Real trusted libraries, all OUTSIDE the project.
	for _, dir := range []string{installed, cellar} {
		if err := os.WriteFile(filepath.Join(dir, "libfence_fs.so"), []byte("inert; never loaded"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// Project-owned pointer that escapes outward: proj/libfence_fs.so -> installed.
	projPointer := filepath.Join(proj, "libfence_fs.so")
	if err := os.Symlink(filepath.Join(installed, "libfence_fs.so"), projPointer); err != nil {
		t.Fatal(err)
	}
	// Trusted links that live outside the project and target outside it: a safe
	// installed-style link and a Homebrew-style link into a Cellar.
	installedLink := filepath.Join(base, "usr-local-libfence_fs.so")
	if err := os.Symlink(filepath.Join(installed, "libfence_fs.so"), installedLink); err != nil {
		t.Fatal(err)
	}
	brewLink := filepath.Join(opt, "libfence_fs.so")
	if err := os.Symlink(filepath.Join(cellar, "libfence_fs.so"), brewLink); err != nil {
		t.Fatal(err)
	}

	// Ancestor-symlink shape: a directory inside the project holds an
	// outward-escaping pointer, reached through a symlink that is spelled
	// OUTSIDE the project but points INTO it. The candidate's own spelling is
	// outside the project (the lexical arm misses it) and its final link
	// resolves outward (the resolved exclusions miss it); only resolving the
	// parent directory catches that the pointer physically lives in the project.
	projLibDir := filepath.Join(proj, "libdir")
	if err := os.Mkdir(projLibDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(installed, "libfence_fs.so"), filepath.Join(projLibDir, "libfence_fs.so")); err != nil {
		t.Fatal(err)
	}
	ancestorLink := filepath.Join(base, "ancestor-into-proj")
	if err := os.Symlink(projLibDir, ancestorLink); err != nil {
		t.Fatal(err)
	}

	// In-project spelling whose parent directory itself escapes outward: the
	// candidate proj/vendor/libfence_fs.so is spelled inside the project, but
	// proj/vendor is a symlink to a directory OUTSIDE it. The parent resolves out
	// (the parent-resolved rule misses it) and the file resolves out (the
	// resolved exclusions miss it), so only the lexical arm, reading the spelling
	// before resolution, refuses it. This is the distinguishing negative control
	// for the lexical arm now that the parent-resolved rule precedes it.
	vendorTarget := filepath.Join(base, "vendor-outside")
	if err := os.Mkdir(vendorTarget, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(installed, "libfence_fs.so"), filepath.Join(vendorTarget, "libfence_fs.so")); err != nil {
		t.Fatal(err)
	}
	vendorLink := filepath.Join(proj, "vendor")
	if err := os.Symlink(vendorTarget, vendorLink); err != nil {
		t.Fatal(err)
	}

	// Positive control for the parent-resolved rule's allow side: a real install
	// reached through a parent directory that is a symlink pointing OUTSIDE the
	// project must still resolve. The parent resolves out, so the rule must
	// resolve the parent (not compare it lexically) to let this through.
	outerInstall := filepath.Join(base, "outer-install")
	if err := os.Mkdir(outerInstall, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outerInstall, "libfence_fs.so"), []byte("inert; never loaded"), 0o644); err != nil {
		t.Fatal(err)
	}
	outerAlias := filepath.Join(base, "outer-alias")
	if err := os.Symlink(outerInstall, outerAlias); err != nil {
		t.Fatal(err)
	}

	// Report only the fixture libraries as present so host /usr/lib paths do not
	// influence the result; canonicalization matches the production resolver.
	inspect := func(path string) (string, error) {
		if !strings.HasPrefix(path, base) {
			return "", os.ErrNotExist
		}
		return filepath.EvalSymlinks(path)
	}

	for _, tc := range []struct {
		name, workingDir, candidate string
		want                        string
	}{
		// The reviewer's reproduction: project-owned pointer inside a symlinked
		// cwd, spelled through the cwd symlink, escaping outward.
		{"regression: symlinked cwd, project pointer escapes outward", projLink, filepath.Join(projLink, "libfence_fs.so"), ""},
		// Project-owned outward pointer, raw cwd spelling, raw candidate.
		{"negative: raw cwd, project pointer escapes outward", proj, projPointer, ""},
		// Project-owned outward pointer, symlinked cwd, candidate spelled
		// canonically through the raw project path. The parent-resolved rule
		// refuses it (proj resolves to itself, inside the symlinked cwd); the
		// lexical arm's canonical-cwd clause is the backstop.
		{"negative: canonical cwd, project pointer escapes outward", projLink, projPointer, ""},
		// Ancestor symlink: candidate spelled OUTSIDE the project, but its parent
		// directory is a symlink into the project and the project file escapes
		// outward. Only the parent-resolved rule catches it; this case is
		// accepted on 305843d (the lexical and resolved arms both miss it).
		{"negative: ancestor dir symlinked into project, pointer escapes outward", proj, filepath.Join(ancestorLink, "libfence_fs.so"), ""},
		// In-project spelling whose parent symlinks outward: only the lexical arm
		// catches it (parent and full path both resolve out). Distinguishing
		// negative control for the lexical arm — removing that arm accepts this.
		{"negative: in-project spelling, parent dir symlinks outward", proj, filepath.Join(vendorLink, "libfence_fs.so"), ""},
		// Positive controls: trusted links that live outside the project resolve.
		{"positive: safe installed link outside project", proj, installedLink, filepath.Join(installed, "libfence_fs.so")},
		{"positive: Homebrew-style link outside project", proj, brewLink, filepath.Join(cellar, "libfence_fs.so")},
		// Positive control for the parent-resolved rule's allow side: a real
		// install whose parent directory is a symlink pointing OUTSIDE the project
		// still resolves (the rule resolves the parent, it does not compare it
		// lexically).
		{"positive: install via parent dir symlinked outside project", proj, filepath.Join(outerAlias, "libfence_fs.so"), filepath.Join(outerInstall, "libfence_fs.so")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := findTrustedLibFenceFS("", tc.workingDir, []string{tc.candidate}, inspect)
			if tc.want == "" {
				if err == nil || got != "" {
					t.Fatalf("project-owned pointer that escapes outward was accepted: %q", got)
				}
				return
			}
			want, _ := filepath.EvalSymlinks(tc.want)
			if err != nil || got != want {
				t.Fatalf("trusted library outside cwd rejected: got %q err %v; want %q", got, err, want)
			}
		})
	}
}

func TestVerificationScratchStateFallbackKeepsLandlockRulesValid(t *testing.T) {
	fixture, err := os.MkdirTemp(mustHome(t), ".nocklock-state-fallback-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(fixture) })
	project := filepath.Join(fixture, "project")
	unsafeHome := filepath.Join(fixture, "home")
	stateHome := filepath.Join(fixture, "state")
	for _, dir := range []string{project, unsafeHome, stateHome} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(unsafeHome, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Setenv("XDG_STATE_HOME", stateHome)
	state, err := config.AuditStateDir(project)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	// The same exclusion set runProbeUnderWrap builds: the original project's
	// audit-state directory, in canonical form, kept out of staging scratch.
	forbidden := []string{resolveExistingPrefix(state)}
	if canonical, _ := filepath.EvalSymlinks(state); forbidden[0] != canonical {
		t.Fatalf("audit state exclusion %q is not canonical %q", forbidden[0], canonical)
	}
	stateRoot := filepath.Dir(filepath.Dir(state))

	probeBin, cleanup, ok := createTrustedScratchOutsideBases(forbidden, []string{unsafeHome, stateRoot})
	if !ok {
		t.Fatal("state fallback was not chosen")
	}
	defer cleanup()
	if pathWithinAny(probeBin, forbidden) || !pathWithinAny(probeBin, []string{stateRoot}) {
		t.Fatalf("scratch %q is not under the state root and outside the denied audit directory", probeBin)
	}
	cfg := &fsfence.FenceConfig{Root: project, AllowPaths: []string{probeBin}, DenyPaths: []string{state}}
	if _, err := landlock.RulesFromConfig(cfg, nil, 7); err != nil {
		t.Fatalf("Landlock rule generation failed for the chosen fallback: %v", err)
	}

	// Negative control: the audit directory itself is never a usable base, and
	// a grant inside it is the overlap Landlock cannot enforce.
	if dir, cleanup, ok := createTrustedScratchOutsideBases(forbidden, []string{state}); ok {
		cleanup()
		t.Fatalf("scratch %q was created inside the denied audit directory", dir)
	}
	bad := &fsfence.FenceConfig{Root: project, AllowPaths: []string{filepath.Join(state, "bin")}, DenyPaths: []string{state}}
	if err := os.Mkdir(filepath.Join(state, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := landlock.RulesFromConfig(bad, nil, 7); err == nil {
		t.Fatal("Landlock accepted a grant inside the denied audit directory")
	}
}

func mustHome(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	return home
}
