//go:build linux

package netns

import (
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
)

// installScriptSandbox is a throwaway root that scripts/install-egress-helper.sh
// is re-pointed into, with stub tools on PATH, so the script can be driven
// unprivileged and a signal can be delivered at a chosen point.
type installScriptSandbox struct {
	root   string
	script string
}

// newInstallScriptSandbox copies the real install script into a temp root with
// its absolute install paths rewritten under that root, then edits the copy with
// mutate (which may be nil). Stubs shadow id/mktemp/install/chown/visudo/su.
// mktemp delegates to the real binary, then delivers $SIG to the script the
// $SIGNAL_AT-th time it is called; install records that it ran.
func newInstallScriptSandbox(t *testing.T, mutate func(string) string) *installScriptSandbox {
	t.Helper()
	realMktemp, err := exec.LookPath("mktemp")
	if err != nil {
		t.Skipf("mktemp not available: %v", err)
	}
	src, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "scripts", "install-egress-helper.sh"))
	if err != nil {
		t.Fatalf("read install script: %v", err)
	}

	root := t.TempDir()
	body := string(src)
	for old, repl := range map[string]string{
		"/usr/libexec":            filepath.Join(root, "libexec"),
		"/etc/sudoers.d":          filepath.Join(root, "sudoers.d"),
		"/usr/local/bin/nocklock": filepath.Join(root, "nocklock"),
	} {
		body = strings.ReplaceAll(body, old, repl)
	}
	if mutate != nil {
		body = mutate(body)
	}
	script := filepath.Join(root, "install-egress-helper.sh")
	writeExec(t, script, body)
	writeExec(t, filepath.Join(root, "nocklock"), "#!/bin/sh\n")
	for _, d := range []string{"tmp", "bin"} {
		if err := os.Mkdir(filepath.Join(root, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}

	stubs := map[string]string{
		"id": "#!/bin/sh\n[ \"$1\" = -u ] && echo 0\nexit 0\n",
		"mktemp": "#!/bin/sh\n" +
			"n=$(cat \"$SANDBOX/count\" 2>/dev/null || echo 0); n=$((n+1)); echo \"$n\" >\"$SANDBOX/count\"\n" +
			"out=$(" + realMktemp + " \"$@\") || exit 1\n" +
			"[ \"$n\" != \"$SIGNAL_AT\" ] || kill -s \"$SIG\" \"$(cat \"$SANDBOX/pid\")\"\n" +
			"echo \"$out\"\n",
		"install": "#!/bin/sh\n: >\"$SANDBOX/install-ran\"\n",
	}
	for _, name := range []string{"chown", "visudo", "su"} {
		stubs[name] = "#!/bin/sh\nexit 0\n"
	}
	for name, content := range stubs {
		writeExec(t, filepath.Join(root, "bin", name), content)
	}
	return &installScriptSandbox{root: root, script: script}
}

func writeExec(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

// run executes the script and returns its exit code (-1 if killed by a signal
// instead of exiting through a handler). signalAt is the mktemp call after which
// sig is delivered; 0 delivers nothing.
func (s *installScriptSandbox) run(t *testing.T, sig string, signalAt int) int {
	t.Helper()
	cmd := exec.Command("sh", "-c", `echo $$ >"$SANDBOX/pid"; exec sh "$1" --user tester`, "sh", s.script)
	cmd.Env = append(os.Environ(),
		"PATH="+filepath.Join(s.root, "bin")+":"+os.Getenv("PATH"),
		"TMPDIR="+filepath.Join(s.root, "tmp"),
		"SANDBOX="+s.root,
		"SIG="+sig,
		"SIGNAL_AT="+strconv.Itoa(signalAt),
	)
	err := cmd.Run()
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	if err != nil {
		t.Fatalf("run install script: %v", err)
	}
	return 0
}

func (s *installScriptSandbox) installRan() bool {
	_, err := os.Stat(filepath.Join(s.root, "install-ran"))
	return err == nil
}

// leftovers lists temp files the script created and did not remove: anything in
// TMPDIR, and any staged (dotted) file next to the sudoers drop-in.
func (s *installScriptSandbox) leftovers(t *testing.T) []string {
	t.Helper()
	var out []string
	for _, pattern := range []string{
		filepath.Join(s.root, "tmp", "*"),
		filepath.Join(s.root, "sudoers.d", "nocklock-egress.*"),
	} {
		m, err := filepath.Glob(pattern)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, m...)
	}
	return out
}

// TestInstallEgressHelperSignalTerminates pins that a signal delivered after a
// temp file is created stops the script: no privileged install step runs after
// it, the process exits through the handler (130 INT / 143 TERM), and every temp
// file is removed. Covers a signal after each of the two mktemp calls.
func TestInstallEgressHelperSignalTerminates(t *testing.T) {
	for _, tc := range []struct {
		sig  string
		want int
	}{{"TERM", 143}, {"INT", 130}} {
		for _, after := range []int{1, 2} {
			t.Run(tc.sig+"_after_mktemp_"+strconv.Itoa(after), func(t *testing.T) {
				// A shell cannot trap a signal that was ignored on entry, so the INT
				// case is only meaningful when this process did not inherit SIG_IGN.
				if tc.sig == "INT" && signal.Ignored(syscall.SIGINT) {
					t.Skip("SIGINT is ignored in this process and is inherited by the script's shell")
				}
				s := newInstallScriptSandbox(t, nil)
				if got := s.run(t, tc.sig, after); got != tc.want {
					t.Errorf("exit code = %d, want %d", got, tc.want)
				}
				if s.installRan() {
					t.Error("install step executed after the signal; the handler must terminate, not resume")
				}
				if l := s.leftovers(t); len(l) != 0 {
					t.Errorf("temp files leaked after the signal: %v", l)
				}
			})
		}
	}
}

// TestInstallEgressHelperSignalTerminatesNegativeControl proves the harness can
// see the bug: with the TERM handler reverted to cleanup-only (returns
// and resumes), the install step DOES run after the signal.
func TestInstallEgressHelperSignalTerminatesNegativeControl(t *testing.T) {
	const fixed = "trap 'exit 143' TERM"
	s := newInstallScriptSandbox(t, func(body string) string {
		if !strings.Contains(body, fixed) {
			t.Fatalf("install script no longer contains %q; update this control", fixed)
		}
		return strings.Replace(body, fixed, "trap cleanup TERM", 1)
	})
	s.run(t, "TERM", 2)
	if !s.installRan() {
		t.Fatal("negative control did not reproduce the resume bug: install never ran with a returning TERM handler, so the test above proves nothing")
	}
}

// TestInstallEgressHelperCompletesAndCleansUp is the no-signal baseline: the
// stubs let the script run end to end, both install steps run, and the EXIT trap
// still removes the temp files (the sudoers stage is renamed away by then).
func TestInstallEgressHelperCompletesAndCleansUp(t *testing.T) {
	s := newInstallScriptSandbox(t, nil)
	if got := s.run(t, "TERM", 0); got != 0 {
		t.Fatalf("exit code = %d, want 0", got)
	}
	if !s.installRan() {
		t.Error("baseline run never reached the install step; the stubs are not exercising the script")
	}
	if l := s.leftovers(t); len(l) != 0 {
		t.Errorf("temp files leaked on a clean run: %v", l)
	}
}
