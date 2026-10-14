//go:build linux

package cli

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestWrapChildCredentialsAfterExec checks the final child through the installed
// helper, Landlock shim and seccomp path, under the invoking user's credential.
func TestWrapChildCredentialsAfterExec(t *testing.T) {
	if os.Getenv("NOCKLOCK_CHILD_CREDENTIALS_REQUIRE") != "1" {
		t.Skip("post-exec wrap proof requires dedicated hosted CI")
	}
	if os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Fatal("post-exec wrap proof is restricted to a disposable hosted CI runner")
	}
	requireNetnsHelperSudo(t)
	bin := nocklockBinary(t)
	// Keep this proof's signing identity outside its project grant and separate
	// from any other test or runner identity. TestMain isolates audit state.
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	project := t.TempDir()
	if err := os.Mkdir(filepath.Join(project, ".nock"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := fmt.Sprintf(`[project]
name = "post-exec-credentials"
[filesystem]
root = %q
mode = "read-write"
linux_enforcement = "required"
allow = ["/usr/", "/lib/", "/lib64/", "/bin/", "/etc/", "/dev/", "/proc/"]
deny = []
[network]
allow = ["example.com"]
allow_all = false
[syscall]
enforcement = "required"
`, project)
	if err := os.WriteFile(filepath.Join(project, ".nock", "config.toml"), []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}
	groups, err := os.Getgroups()
	if err != nil {
		t.Fatal(err)
	}
	var groupText []string
	for _, group := range groups {
		groupText = append(groupText, strconv.Itoa(group))
	}
	const probe = `import json, pathlib, sys
s = dict(line.split(':', 1) for line in pathlib.Path('/proc/self/status').read_text().splitlines())
for name, expected in [('Uid', sys.argv[1]), ('Gid', sys.argv[2])]:
    assert s[name].split() == [expected] * 4, (name, s[name])
assert sorted(map(int, s['Groups'].split())) == sorted(map(int, filter(None, sys.argv[3].split(',')))), s['Groups']
assert s['NoNewPrivs'].strip() == '1', s['NoNewPrivs']
for name in ('CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'):
    value = int(s[name], 16)
    mask = (1 << 12) | (1 << 21) | (1 << 8) if name == 'CapBnd' else (1 << 64) - 1
    assert value & mask == 0, (name, s[name])
print('CREDENTIALS_OK ' + json.dumps({k: s[k].strip() for k in ('Uid', 'Gid', 'Groups', 'CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb', 'NoNewPrivs')}))
`
	for iteration := 0; iteration < 6; iteration++ {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		cmd := exec.CommandContext(ctx, bin, "wrap", "--net-fence=netns", "--", "/usr/bin/python3", "-I", "-c", probe,
			strconv.Itoa(os.Getuid()), strconv.Itoa(os.Getgid()), strings.Join(groupText, ","))
		cmd.Dir = project
		cmd.Env = append(os.Environ(), "GOMAXPROCS=8")
		out, err := runCredentialCommand(ctx, cmd, 2*time.Second)
		cancel()
		if err != nil || !strings.Contains(string(out), "CREDENTIALS_OK ") {
			t.Fatalf("wrapped post-exec credential iteration %d: %v\n%s", iteration, err, out)
		}
		for line := range strings.SplitSeq(string(out), "\n") {
			if strings.HasPrefix(line, "CREDENTIALS_OK ") {
				t.Logf("wrapped post-exec credential iteration %d: %s", iteration, line)
			}
		}
	}
}
