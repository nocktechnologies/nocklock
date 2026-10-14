package cli

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

func writeLaunchFixture(t *testing.T, dir, name string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), mode); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestResolveChildArgvPreservesArgumentsAndPrefixes(t *testing.T) {
	project, first, second := t.TempDir(), t.TempDir(), t.TempDir()
	t.Chdir(project)
	wantPath := writeLaunchFixture(t, first, "agent", 0o700)
	writeLaunchFixture(t, second, "agent", 0o700)
	writeLaunchFixture(t, project, "agent", 0o700) // Must not shadow PATH.
	t.Setenv("PATH", first+string(os.PathListSeparator)+second)
	args := []string{"agent", "argument with spaces", "", "--literal=$HOME;$(id)", "line\nbreak"}
	before := append([]string(nil), args...)
	inner := []string{"/nocklock", "__landlock-exec", "--"}
	outer := []string{"/sandbox-exec", "-f", "profile.sb"}
	got, err := resolveChildArgv(args, inner, nil, outer)
	if err != nil {
		t.Fatal(err)
	}
	want := append([]string{"/sandbox-exec", "-f", "profile.sb", "/nocklock", "__landlock-exec", "--", wantPath}, args[1:]...)
	if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(args, before) {
		t.Fatalf("resolved argv=%q input=%q; want argv=%q and unchanged input=%q", got, args, want, before)
	}
	got[0], got[3], got[6], got[7] = "changed", "changed", "changed", "changed"
	if outer[0] != "/sandbox-exec" || inner[0] != "/nocklock" || !reflect.DeepEqual(args, before) {
		t.Fatal("resolved argv aliases caller-owned arguments or prefixes")
	}
}

func TestResolveChildArgvExplicitPathsPreserveSymlinkTraversal(t *testing.T) {
	project, target := t.TempDir(), t.TempDir()
	t.Chdir(project)
	t.Setenv("PATH", "") // Explicit paths do not depend on PATH.
	local := writeLaunchFixture(t, project, "agent", 0o700)
	realTarget := writeLaunchFixture(t, target, "agent", 0o700)
	if err := os.Mkdir(filepath.Join(target, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(target, "bin"), filepath.Join(project, "link")); err != nil {
		t.Fatal(err)
	}
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, command, want, target string }{
		{"absolute", local, local, local},
		{"explicit_relative", "./agent", wd + "/./agent", local},
		{"relative_symlink_parent", "./link/../agent", wd + "/./link/../agent", realTarget},
		{"absolute_symlink_parent", wd + "/link/../agent", wd + "/link/../agent", realTarget},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := resolveChildArgv([]string{tc.command, "--flag"})
			if err != nil || !reflect.DeepEqual(got, []string{tc.want, "--flag"}) {
				t.Fatalf("got %q err=%v; want %q", got, err, tc.want)
			}
			real, err := filepath.EvalSymlinks(got[0])
			wantReal, wantErr := filepath.EvalSymlinks(tc.target)
			if err != nil || wantErr != nil || real != wantReal {
				t.Fatalf("selected %q (%v), want %q (%v)", real, err, wantReal, wantErr)
			}
		})
	}
}

func TestResolveChildArgvRefusesImplicitCWDAndUnavailableCommands(t *testing.T) {
	project, empty, nonExec := t.TempDir(), t.TempDir(), t.TempDir()
	t.Chdir(project)
	writeLaunchFixture(t, project, "agent", 0o700)
	nonExecPath := writeLaunchFixture(t, nonExec, "agent", 0o600)
	if err := os.Mkdir("relative-bin", 0o700); err != nil {
		t.Fatal(err)
	}
	writeLaunchFixture(t, "relative-bin", "agent", 0o700)
	for _, tc := range []struct {
		name, command, path, godebug string
		wantErr                      error
	}{
		{"missing", "agent", empty, "", exec.ErrNotFound},
		{"non_executable_on_path", "agent", nonExec, "", exec.ErrNotFound},
		{"non_executable_explicit", nonExecPath, empty, "", os.ErrPermission},
		{"directory", project, empty, "", syscall.EISDIR},
		{"dot_default", "agent", ".", "execerrdot=1", exec.ErrDot},
		{"dot_override", "agent", ".", "execerrdot=0", exec.ErrDot},
		{"relative_entry_override", "agent", "relative-bin", "execerrdot=0", exec.ErrDot},
		{"empty_entry_override", "agent", ":" + empty, "execerrdot=0", exec.ErrDot},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("PATH", tc.path)
			t.Setenv("GODEBUG", tc.godebug)
			got, err := resolveChildArgv([]string{tc.command}, []string{"shim", "--"})
			if got != nil || !errors.Is(err, tc.wantErr) || !strings.Contains(err.Error(), "resolve command") {
				t.Fatalf("got argv=%q err=%v; want no argv and %v", got, err, tc.wantErr)
			}
		})
	}
	if got, err := resolveChildArgv(nil); got != nil || err == nil {
		t.Fatalf("empty arguments: got %q err=%v", got, err)
	}
}
