//go:build linux

package netns

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

const childCredentialRequire = "NOCKLOCK_CHILD_CREDENTIALS_REQUIRE"
const childCredentialProbe = "NOCKLOCK_CHILD_CREDENTIALS_PROBE"

// TestChildCredentialsAfterExecStress checks the final process image, not the
// dropping thread's pre-exec assertion. It changes credentials only in fresh
// subprocesses, and requires explicit opt-in on a disposable hosted CI runner.
func TestChildCredentialsAfterExecStress(t *testing.T) {
	if os.Getenv(childCredentialRequire) != "1" {
		t.Skip("post-exec credential proof requires dedicated hosted root CI")
	}
	if os.Geteuid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		t.Fatal("credential proof requires root on a disposable GitHub-hosted runner")
	}
	u, err := user.Lookup("nobody")
	if err != nil {
		t.Fatal(err)
	}
	for _, procs := range []int{2, 8, 32} {
		for iteration := 0; iteration < 12; iteration++ {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^$")
			cmd.Env = append(os.Environ(), childCredentialProbe+"=1", "GOMAXPROCS="+strconv.Itoa(procs), "SUDO_UID="+u.Uid, "SUDO_GID="+u.Gid)
			out, err := cmd.CombinedOutput()
			cancel()
			if err != nil {
				t.Fatalf("GOMAXPROCS=%d iteration=%d: %v\n%s", procs, iteration, err, out)
			}
			assertFinalChildCredential(t, string(out), u.Uid, u.Gid)
		}
		t.Logf("GOMAXPROCS=%d: 12 execs; five capability sets, Groups, Uid/Gid and NoNewPrivs verified", procs)
	}
}

func runChildCredentialProbe() error {
	if os.Geteuid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" || os.Getenv("RUNNER_ENVIRONMENT") != "github-hosted" {
		return fmt.Errorf("credential subprocess is restricted to hosted root CI")
	}
	uid, err := strconv.Atoi(os.Getenv("SUDO_UID"))
	if err != nil {
		return err
	}
	gid, err := strconv.Atoi(os.Getenv("SUDO_GID"))
	if err != nil {
		return err
	}
	// Give every existing thread a visibly wrong group; the exec'd child must
	// instead report the explicitly requested unprivileged group.
	if err := syscall.Setgroups([]int{12345}); err != nil {
		return err
	}
	ready := make(chan struct{}, 32)
	for range 32 {
		go func() {
			runtime.LockOSThread()
			ready <- struct{}{}
			for {
				runtime.Gosched()
			}
		}()
	}
	for range 32 {
		<-ready
	}
	return DropAndExecChild(Request{UID: uid, GID: gid, Groups: []int{gid},
		Argv: []string{"/bin/cat", "/proc/self/status"}, Env: []string{"PATH=/usr/bin:/bin"}})
}

func assertFinalChildCredential(t *testing.T, status, uid, gid string) {
	t.Helper()
	fields := map[string]string{}
	for line := range strings.SplitSeq(status, "\n") {
		key, value, ok := strings.Cut(line, ":")
		if ok {
			fields[key] = strings.Join(strings.Fields(value), " ")
		}
	}
	for name, want := range map[string]string{
		"Uid":    strings.TrimSpace(strings.Repeat(uid+" ", 4)),
		"Gid":    strings.TrimSpace(strings.Repeat(gid+" ", 4)),
		"Groups": gid, "NoNewPrivs": "1",
	} {
		if fields[name] != want {
			t.Errorf("post-exec %s=%q, want %q", name, fields[name], want)
		}
	}
	for _, name := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		value, err := strconv.ParseUint(fields[name], 16, 64)
		if err != nil {
			t.Errorf("post-exec missing/malformed %s: %q", name, fields[name])
			continue
		}
		// Bounding retains capabilities outside the three setup-only bits;
		// all other sets are empty for this ordinary unprivileged executable.
		mask := ^uint64(0)
		if name == "CapBnd" {
			mask = 1<<unix.CAP_NET_ADMIN | 1<<unix.CAP_SYS_ADMIN | 1<<unix.CAP_SETPCAP
		}
		if value&mask != 0 {
			t.Errorf("post-exec %s=%016x retains forbidden bits %016x", name, value, value&mask)
		}
	}
	t.Logf("post-exec receipt: Uid=%s Gid=%s Groups=%s NoNewPrivs=%s CapInh=%s CapPrm=%s CapEff=%s CapBnd=%s CapAmb=%s",
		fields["Uid"], fields["Gid"], fields["Groups"], fields["NoNewPrivs"], fields["CapInh"], fields["CapPrm"], fields["CapEff"], fields["CapBnd"], fields["CapAmb"])
}

// credentialExecOnOtherThread is only a mutation-test target. The CI script
// redirects the production final exec here to model per-thread drops followed
// by execution on a different runtime thread. The dropping thread stays locked
// and blocked, guaranteeing that the new goroutine cannot borrow its credential.
func credentialExecOnOtherThread(req Request) error {
	done := make(chan error, 1)
	go func() { done <- unix.Exec(req.Argv[0], req.Argv, req.Env) }()
	return fmt.Errorf("mutated exec returned: %w", <-done)
}
