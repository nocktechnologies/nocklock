//go:build linux

package cli

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestWrapOwnConfigPresetReadsOnlyItsOwnConfig proves that --profile opencode
// and --profile goose start on Linux and read their own directory beneath
// ~/.config, while ~/.config/gh, the other agent's directory, and writes to the
// own directory and a sibling sharing its name as a prefix stay denied, through the interposer and through Landlock alone
// (env -u LD_PRELOAD). Controls: without --profile, a project config granting
// the same directory, or ~/.config itself, refuses startup.
func TestWrapOwnConfigPresetReadsOnlyItsOwnConfig(t *testing.T) {
	requirePresetUnprivileged(t)
	bin := nocklockBinary(t)
	requireInterposerBeside(t, bin)

	for _, tc := range []struct{ profile, own, other, stage string }{
		// stage is a directory the preset grants, so the LD_PRELOAD library
		// beside the staged binary stays readable after exec.
		{"opencode", "opencode", "goose", ".cache/opencode"},
		{"goose", "goose", "opencode", ".local/share/goose"},
	} {
		t.Run(tc.profile, func(t *testing.T) {
			// Outside /tmp: the presets grant /tmp, which would cover the fixture.
			base, err := os.MkdirTemp(mustGetwd(t), "preset-own-config-")
			if err != nil {
				t.Fatalf("mkdir fixture: %v", err)
			}
			t.Cleanup(func() { _ = os.RemoveAll(base) })
			home, repo := filepath.Join(base, "home"), filepath.Join(base, "project")
			stage := filepath.Join(home, tc.stage)
			for _, dir := range []string{repo, stage, filepath.Join(home, ".local", "state")} {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatalf("mkdir %s: %v", dir, err)
				}
			}
			own, other, sibling := tc.own+"/config", tc.other+"/config", tc.own+"-extra/config"
			files := map[string]string{}
			for _, rel := range []string{own, other, sibling, "gh/hosts.yml"} {
				p := filepath.Join(home, ".config", rel)
				if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
					t.Fatalf("mkdir %s: %v", p, err)
				}
				if err := os.WriteFile(p, []byte("canary-"+rel+"\n"), 0o600); err != nil {
					t.Fatalf("write %s: %v", p, err)
				}
				files[rel] = p
			}
			staged := filepath.Join(stage, "nocklock")
			copyExecutable(t, bin, staged)
			copyExecutable(t, filepath.Join(filepath.Dir(bin), "libfence_fs.so"), filepath.Join(stage, "libfence_fs.so"))
			t.Setenv("HOME", home)
			t.Setenv("XDG_STATE_HOME", filepath.Join(home, ".local", "state"))

			const proof = `cat "$1" || exit 10
if cat "$2"; then exit 11; fi
if cat "$3"; then exit 12; fi
env -u LD_PRELOAD cat "$1" || exit 13
if env -u LD_PRELOAD cat "$2"; then exit 14; fi
if env -u LD_PRELOAD cat "$3"; then exit 15; fi
if cat "$4"; then exit 17; fi
if env -u LD_PRELOAD cat "$4"; then exit 18; fi
if (printf x >> "$1"); then exit 16; fi
echo OWN_CONFIG_PROOF_OK`
			cmd := exec.Command(staged, "wrap", "--profile", tc.profile, "--",
				"/bin/sh", "-c", proof, "own-config-proof", files[own], files[other], files["gh/hosts.yml"], files[sibling])
			cmd.Dir = repo
			cmd.Env = os.Environ()
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("--profile %s own-config proof failed: %v\n%s", tc.profile, err, out)
			}
			for _, want := range []string{"OWN_CONFIG_PROOF_OK", "canary-" + own} {
				if !strings.Contains(string(out), want) {
					t.Fatalf("wrapped proof output missing %q:\n%s", want, out)
				}
			}
			for _, leak := range []string{"canary-" + tc.other, "canary-gh", "canary-" + sibling, "cannot be preloaded"} {
				if strings.Contains(string(out), leak) {
					t.Fatalf("wrapped proof output contains %q:\n%s", leak, out)
				}
			}
			if got, err := os.ReadFile(files[own]); err != nil || string(got) != "canary-"+own+"\n" {
				t.Fatalf("own config changed to %q: %v", got, err)
			}

			for _, grant := range []string{"~/.config/" + tc.own + "/", "~/.config/"} {
				writeTestConfig(t, repo, `[project]
runtime = "`+tc.profile+`"
[filesystem]
root = "."
linux_enforcement = "required"
allow = ["`+grant+`"]
`)
				cmd := exec.Command(staged, "wrap", "--", "/bin/echo", "CHILD_STARTED")
				cmd.Dir = repo
				cmd.Env = os.Environ()
				out, err := cmd.CombinedOutput()
				if err == nil || strings.Contains(string(out), "CHILD_STARTED") || !strings.Contains(string(out), "built-in credential deny") {
					t.Fatalf("grant %q without --profile: want startup refusal, got %v\n%s", grant, err, out)
				}
			}
		})
	}
}

func copyExecutable(t *testing.T, src, dst string) {
	t.Helper()
	in, err := os.Open(src)
	if err != nil {
		t.Fatalf("open %s: %v", src, err)
	}
	defer in.Close()
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o755)
	if err != nil {
		t.Fatalf("create %s: %v", dst, err)
	}
	if _, err := io.Copy(out, in); err != nil {
		t.Fatalf("copy %s: %v", src, err)
	}
	if err := out.Close(); err != nil {
		t.Fatalf("close %s: %v", dst, err)
	}
}
