//go:build linux || darwin

package cli

import (
	"context"
	"errors"
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
	got, err := findTrustedLibFenceFS("/safe/bin/nocklock", "/project", []string{"/safe/cellar/nocklock/1.0/lib/libfence_fs.so"}, func(path string, projectDirs []string) (string, error) {
		return inspectTrustedPath(path, f.fs, 0, projectDirs)
	})
	if err == nil || got != "" || !strings.Contains(err.Error(), "refusing to launch") {
		t.Fatalf("unsafe candidate bypassed: path=%q err=%v", got, err)
	}
}

// The fixture lives in a private root under $HOME, not t.TempDir(): under /tmp
// (mode 1777) the sticky world-writable ancestor refuses the candidate before
// its own 0777 mode matters, so the row would pass with the per-file check
// deleted. A 0644 sibling in the same root resolves, which proves no ancestor
// is the refuser, and the refusal must name the candidate file itself.
func TestInterposerTrustRealWritableFileAndLegacyNegativeControl(t *testing.T) {
	root := homeResolvedTempDir(t)
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	control := filepath.Join(root, "trusted", "libfence_fs.so")
	if err := os.Mkdir(filepath.Dir(control), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(control, []byte("inert fixture; never loaded"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Explicit chmod: os.WriteFile and os.Mkdir modes are masked by umask.
	if err := os.Chmod(control, 0o644); err != nil {
		t.Fatal(err)
	}
	if got, err := trustedInterposerPath(control); err != nil || got != control {
		t.Fatalf("positive control in the same root was refused, so an ancestor is untrusted: path=%q err=%v", got, err)
	}

	candidate := filepath.Join(root, "libfence_fs.so")
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
	want := fmt.Sprintf("%q is group/world-writable (mode 0777)", candidate)
	if got, err := trustedInterposerPath(candidate); err == nil || got != "" || !strings.Contains(err.Error(), want) {
		t.Fatalf("strict resolver did not refuse the writable file for its own mode: path=%q err=%v, want refusal containing %s", got, err, want)
	}
}

func TestDoctorRealInterposerProbe(t *testing.T) {
	if os.Getenv("NOCKLOCK_INTERPOSER_DOCTOR_CHILD") == "1" {
		caps := currentDoctorCapabilities
		caps.goos = "linux" // Exercise the real library probe on either Unix test host.
		check := filesystemDoctorCheck(&config.Config{Filesystem: config.FilesystemConfig{Root: "."}}, caps)
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
			got, err := findTrustedLibFenceFS("/safe/bin/nocklock", "/project", []string{fallback}, func(path string, projectDirs []string) (string, error) {
				return inspectTrustedPath(path, f.fs, 0, projectDirs)
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

// TestResolverRefusesProjectOwnedLibraryPaths pins the one rule that guards the
// trust walk: during the walk, every path it visits — the original spelling,
// every ancestor, every symlink and every symlink-target hop — is compared
// against the project by its raw and canonical spelling against both working
// directory spellings, and any in-project hit refuses that candidate. The table
// covers every shape found so far, each refused for the project reason and not a
// permission one — proven per row by the recorded refusal being the project
// sentinel and the resolver reporting "not found" rather than a hard-fail, and by
// the positive controls in the same tree resolving.
//
// It drives the real production walk (inspectTrustedPath on real files) so a
// middle hop through a project-owned symlink is actually visited; a stub that
// only returns the final canonical path never sees the hop. The fixture lives
// under $HOME, whose ancestors are not group/world-writable, so the ownership
// checks pass; t.TempDir() sits under world-writable /tmp and would refuse every
// row for the wrong reason.
//
// Fail-before was measured by two behavioral reconstructions of this table (the
// new table cannot compile against the historical SHAs, whose inspectTrustedPath
// had no projectDirs parameter):
//   - ee90e6b0's logic (the three per-candidate arms restored, this walk rule
//     off): only the middle-hop row is accepted — that is the round-6 gap.
//   - both the arms and this rule removed: every negative row is accepted, and
//     the group-writable row hard-fails the launch (the permission error fires
//     with no project check to skip the candidate first) — proving the rule is
//     load-bearing for every shape and that the project check must precede the
//     permission check (confirmed by moving it after fsys.inspect: the
//     group-writable row then hard-fails).
//
// Read from git history, not measured here: the in-project-spelling,
// project-file-outward and symlinked-cwd shapes were first refused in 305843d and
// the ancestor-symlink shape in ee90e6b0. All rows pass on this change.
func TestResolverRefusesProjectOwnedLibraryPaths(t *testing.T) {
	base := homeResolvedTempDir(t)
	proj := filepath.Join(base, "proj") // the project (working directory)
	installed := filepath.Join(base, "installed")
	cellar := filepath.Join(base, "cellar")
	opt := filepath.Join(base, "opt")
	outerInstall := filepath.Join(base, "outer-install")
	projInside := filepath.Join(proj, "inside") // holds an in-project regular file
	projGW := filepath.Join(proj, "gw")         // holds a group-writable in-project file
	projLibDir := filepath.Join(proj, "libdir") // reached through an ancestor symlink
	for _, dir := range []string{proj, installed, cellar, opt, outerInstall, projInside, projGW, projLibDir} {
		if err := os.Mkdir(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	// Real trusted libraries, all OUTSIDE the project.
	for _, dir := range []string{installed, cellar, outerInstall} {
		if err := os.WriteFile(filepath.Join(dir, "libfence_fs.so"), []byte("inert; never loaded"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	installedLib := filepath.Join(installed, "libfence_fs.so")

	// A symlinked spelling of the project root, so raw and canonical cwd differ.
	projLink := filepath.Join(base, "projlink")
	if err := os.Symlink(proj, projLink); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	// Shape: a plain regular library spelled inside the project.
	insideLib := filepath.Join(projInside, "libfence_fs.so")
	if err := os.WriteFile(insideLib, []byte("inert; never loaded"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Shape: a group-writable regular library inside the project. The project
	// check must refuse it BEFORE the permission check, so the resolver falls back
	// to the next (trusted) candidate instead of hard-failing the launch.
	gwLib := filepath.Join(projGW, "libfence_fs.so")
	if err := os.WriteFile(gwLib, []byte("inert; never loaded"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Chmod after creation: os.WriteFile's mode is masked by umask, so an explicit
	// chmod is what actually makes the file group-writable (the permission the
	// ordering control depends on).
	if err := os.Chmod(gwLib, 0o664); err != nil {
		t.Fatal(err)
	}
	// Shape: a project file linking outward: proj/libfence_fs.so -> installed.
	projPointer := filepath.Join(proj, "libfence_fs.so")
	if err := os.Symlink(installedLib, projPointer); err != nil {
		t.Fatal(err)
	}
	// Shape: ancestor dir symlinked into the project. The candidate is spelled
	// OUTSIDE the project, its parent is a symlink INTO it, and the project file
	// it finds escapes outward — only a visited middle path lands in the project.
	if err := os.Symlink(installedLib, filepath.Join(projLibDir, "libfence_fs.so")); err != nil {
		t.Fatal(err)
	}
	ancestorLink := filepath.Join(base, "ancestor-into-proj")
	if err := os.Symlink(projLibDir, ancestorLink); err != nil {
		t.Fatal(err)
	}
	// Shape: a middle hop through a project-owned symlink. The candidate is
	// spelled OUTSIDE the project and resolves to a library OUTSIDE it, but the
	// walk passes through proj/mid.so on the way — the hop ee90e6b0 never checked.
	projMid := filepath.Join(proj, "mid.so")
	if err := os.Symlink(installedLib, projMid); err != nil {
		t.Fatal(err)
	}
	middleEntry := filepath.Join(base, "entry.so")
	if err := os.Symlink(projMid, middleEntry); err != nil {
		t.Fatal(err)
	}
	// Trusted links that live outside the project: an installed-style link, a
	// Homebrew-style link into a Cellar, and an install reached through a parent
	// directory that is a symlink pointing OUTSIDE the project.
	installedLink := filepath.Join(base, "usr-local-libfence_fs.so")
	if err := os.Symlink(installedLib, installedLink); err != nil {
		t.Fatal(err)
	}
	brewLink := filepath.Join(opt, "libfence_fs.so")
	if err := os.Symlink(filepath.Join(cellar, "libfence_fs.so"), brewLink); err != nil {
		t.Fatal(err)
	}
	outerAlias := filepath.Join(base, "outer-alias")
	if err := os.Symlink(outerInstall, outerAlias); err != nil {
		t.Fatal(err)
	}

	// Gate candidates to the fixture so the host /usr/local install does not
	// resolve, but run the REAL production entry point for those that are: that is
	// what visits the middle hop and applies the one rule to every visited path.
	inspect := func(path string, projectDirs []string) (string, error) {
		if !strings.HasPrefix(path, base+string(os.PathSeparator)) {
			return "", os.ErrNotExist
		}
		return trustedInterposerPathInProject(path, projectDirs)
	}

	for _, tc := range []struct {
		name       string
		workingDir string
		candidates []string
		want       string // "" means refuse (no candidate selected)
	}{
		// Negatives — every shape found so far, each refused for the project reason.
		{"candidate spelled inside the project", proj, []string{insideLib}, ""},
		{"project file linking outward", proj, []string{projPointer}, ""},
		{"parent dir symlinked into the project", proj, []string{filepath.Join(ancestorLink, "libfence_fs.so")}, ""},
		{"middle hop through a project-owned symlink", proj, []string{middleEntry}, ""},
		{"symlinked cwd, project pointer escapes outward", projLink, []string{filepath.Join(projLink, "libfence_fs.so")}, ""},
		// Ordering control: the in-project candidate is also group-writable. The
		// project check must precede the permission check, so this is SKIPPED and
		// the next (trusted) candidate is selected rather than failing the launch.
		{"group-writable in-project candidate is skipped, next selected", proj, []string{gwLib, installedLib}, installedLib},
		// Positive controls in the same tree: trusted links outside the project
		// resolve, proving permissions are not what refuses the negatives.
		{"installed link outside project resolves", proj, []string{installedLink}, installedLib},
		{"Homebrew-style link outside project resolves", proj, []string{brewLink}, filepath.Join(cellar, "libfence_fs.so")},
		{"install via parent dir symlinked outside project resolves", proj, []string{filepath.Join(outerAlias, "libfence_fs.so")}, filepath.Join(outerInstall, "libfence_fs.so")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Record each candidate's own refusal so a row can only pass for the
			// project reason. A permission refusal would also leave err != nil and
			// got == "", but it hard-fails the launch instead of skipping.
			refusals := map[string]error{}
			recording := func(path string, projectDirs []string) (string, error) {
				got, err := inspect(path, projectDirs)
				if err != nil {
					refusals[path] = err
				}
				return got, err
			}
			got, err := findTrustedLibFenceFS("", tc.workingDir, tc.candidates, recording)
			// Every fixture candidate the resolver refused before selecting one (all
			// of them, for a negative row) must carry the project sentinel.
			for _, candidate := range tc.candidates {
				refusal, refused := refusals[candidate]
				if !refused {
					if tc.want == "" {
						t.Fatalf("candidate %q was not refused by the trust walk: got %q err %v", candidate, got, err)
					}
					break // the selected candidate; later ones are never inspected
				}
				if !errors.Is(refusal, errTrustedPathWithinProject) {
					t.Fatalf("candidate %q was refused for the wrong reason (want the project rule, not a permission hard-fail): %v", candidate, refusal)
				}
			}
			if tc.want == "" {
				if err == nil || got != "" {
					t.Fatalf("project-owned library path was accepted: got %q err %v", got, err)
				}
				// A project skip falls through to "not found"; a hard-fail reports
				// "cannot inspect ... candidate" and stops at that candidate.
				if !strings.Contains(err.Error(), "trusted filesystem fence library not found") {
					t.Fatalf("resolver did not skip the project-owned candidate: %v", err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("trusted library outside the project rejected: got %q err %v; want %q", got, err, tc.want)
			}
		})
	}
}

// homeResolvedTempDir returns a canonical temp directory under $HOME. The real
// trust walk checks that no ancestor is group/world-writable, which /tmp (mode
// 1777) is; $HOME and its ancestors are not, so fixtures placed here let the
// production walk run without a stubbed inspector.
func homeResolvedTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp(mustHome(t), ".nocklock-interposer-trust-*")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	resolved, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return resolved
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
