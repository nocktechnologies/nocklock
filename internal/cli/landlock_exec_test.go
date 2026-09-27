package cli

import (
	"fmt"
	"os"
	"strings"
	"testing"

	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
)

// TestAllowSelfProcFS_GrantsFilesNotDirectory is the unit-level regression test
// for #10757's round-2 MAJOR finding: the interposer allow-list injection must
// add the wrapped process's own /proc/<pid>/{stat,status,statm} FILES, never
// the /proc/<pid> DIRECTORY (which would also match environ, cmdline, mem, maps
// and fd in the interposer's allow check — the same-UID leak #115 removed).
func TestAllowSelfProcFS_GrantsFilesNotDirectory(t *testing.T) {
	base := "/root\x1frw\x1f/tmp/sock"
	env := []string{fsfence.EnvFSAllowed + "=" + base}

	got := allowSelfProcFS(env)
	if len(got) != 1 {
		t.Fatalf("allowSelfProcFS changed env length: got %d entries, want 1", len(got))
	}
	_, val, _ := strings.Cut(got[0], "=")

	pid := os.Getpid()
	for _, f := range fsfence.SelfProcFiles {
		want := "+" + fmt.Sprintf("/proc/%d/%s", pid, f)
		if !strings.Contains(val, want) {
			t.Errorf("allowSelfProcFS: serialized value missing %q; got %q", want, val)
		}
	}

	// The bare directory entry (with no file suffix) must never appear — that
	// is the whole-subtree grant this fix removes.
	dirEntry := fmt.Sprintf("+/proc/%d", pid)
	for _, field := range strings.Split(val, "\x1f") {
		if field == dirEntry {
			t.Errorf("allowSelfProcFS must not grant the bare /proc/<pid> directory, got field %q in %q", field, val)
		}
	}
}

// TestAllowSelfProcFS_NoopWithoutFSAllowedEnv confirms allowSelfProcFS leaves
// env untouched when NOCKLOCK_FS_ALLOWED is absent (the filesystem fence is
// off), rather than injecting a self-proc grant into an unrelated variable.
func TestAllowSelfProcFS_NoopWithoutFSAllowedEnv(t *testing.T) {
	env := []string{"PATH=/usr/bin", "HOME=/home/x"}
	got := allowSelfProcFS(append([]string{}, env...))
	if len(got) != len(env) {
		t.Fatalf("allowSelfProcFS changed env length: got %v, want %v", got, env)
	}
	for i := range env {
		if got[i] != env[i] {
			t.Errorf("allowSelfProcFS modified env[%d]: got %q, want %q", i, got[i], env[i])
		}
	}
}
