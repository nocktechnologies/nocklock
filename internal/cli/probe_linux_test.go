//go:build linux

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func stubCloneNewUser(t *testing.T, err error) {
	t.Helper()
	orig := probeCloneNewUserRaw
	t.Cleanup(func() { probeCloneNewUserRaw = orig })
	probeCloneNewUserRaw = func() error { return err }
}

func TestProbeSyscallUnfencedSuccessIsAttempted(t *testing.T) {
	stubCloneNewUser(t, nil)
	result := probeSyscall()
	if !result.Attempted || result.Blocked {
		t.Fatalf("probeSyscall() = %+v, want attempted and not blocked", result)
	}
}

func TestProbeSyscallEPERMIsBlocked(t *testing.T) {
	stubCloneNewUser(t, unix.EPERM)
	result := probeSyscall()
	if !result.Attempted || !result.Blocked {
		t.Fatalf("probeSyscall() = %+v, want attempted and blocked", result)
	}
}

func TestProbeSyscallEINVALIsInconclusiveNotDenial(t *testing.T) {
	stubCloneNewUser(t, unix.EINVAL)
	result := probeSyscall()
	if result.Attempted || result.Blocked {
		t.Fatalf("probeSyscall() = %+v, want not attempted and not blocked", result)
	}
	if !strings.Contains(result.Detail, "EINVAL") || !strings.Contains(result.Detail, "inconclusive") {
		t.Fatalf("detail = %q, want it to name EINVAL and say inconclusive", result.Detail)
	}
}

func TestProbeSyscallOtherErrorIsInconclusive(t *testing.T) {
	stubCloneNewUser(t, errors.New("waiting for clone child: no child"))
	result := probeSyscall()
	if result.Attempted || result.Blocked {
		t.Fatalf("probeSyscall() = %+v, want not attempted and not blocked", result)
	}
}

func TestProbeSyscallRealUnfencedClone(t *testing.T) {
	if !userNamespacesEnabled() {
		t.Skip("unprivileged user namespaces are disabled on this kernel")
	}
	result := probeSyscall()
	switch classifyUnfencedClone(result) {
	case unfencedCloneSkip:
		// The kernel sysctls can report user namespaces as enabled while host
		// policy (container seccomp, AppArmor) still denies the clone with EPERM:
		// a missing host capability, not a missing fence. When this skips, the
		// unfenced control for the syscall fence is not proven on this host; that
		// coverage gates in CI, where the clone can run unfenced.
		t.Skipf("host policy denies the unfenced clone (%s); cannot prove the unfenced case here", result.Detail)
	case unfencedCloneFail:
		t.Fatalf("unfenced clone(CLONE_NEWUSER) probe = %+v, want attempted and not blocked", result)
	}
}

// unfencedCloneOutcome is how the real-clone test should treat an unfenced
// clone(CLONE_NEWUSER) probe result.
type unfencedCloneOutcome int

const (
	// unfencedCloneOK means the probe ran unfenced and was not blocked.
	unfencedCloneOK unfencedCloneOutcome = iota
	// unfencedCloneSkip means host policy denied the clone with EPERM, which is a
	// missing host capability rather than a missing fence. Skipping here leaves the
	// unfenced control for the syscall fence unproven on that host, by design: the
	// control gates in CI, where the clone can run unfenced.
	unfencedCloneSkip
	// unfencedCloneFail means the probe could not prove the unfenced case: it was
	// inconclusive (never attempted).
	unfencedCloneFail
)

func (o unfencedCloneOutcome) String() string {
	switch o {
	case unfencedCloneOK:
		return "ok"
	case unfencedCloneSkip:
		return "skip"
	case unfencedCloneFail:
		return "fail"
	default:
		return "unknown"
	}
}

// classifyUnfencedClone decides how the real-clone test treats a probe result.
// probeSyscall sets Blocked only for an EPERM denial, so an attempted-and-blocked
// result is exactly the host-policy EPERM class that must skip. An unattempted
// probe is inconclusive and must fail; anything else ran unfenced and is OK.
func classifyUnfencedClone(result probeResult) unfencedCloneOutcome {
	switch {
	case result.Attempted && result.Blocked:
		return unfencedCloneSkip
	case !result.Attempted:
		return unfencedCloneFail
	default:
		return unfencedCloneOK
	}
}

func TestClassifyUnfencedClone(t *testing.T) {
	tests := []struct {
		name    string
		stubErr error
		want    unfencedCloneOutcome
	}{
		// EPERM outside any fence is host policy denying the namespace, not a
		// missing fence: skip, do not fail.
		{"EPERM is a host-policy skip", unix.EPERM, unfencedCloneSkip},
		// A non-EPERM, inconclusive outcome is a genuine failure of the probe.
		{"inconclusive error fails", errors.New("waiting for clone child: no child"), unfencedCloneFail},
		// Negative control: an unfenced clone that succeeds is OK.
		{"unfenced success is ok", nil, unfencedCloneOK},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stubCloneNewUser(t, tt.stubErr)
			if got := classifyUnfencedClone(probeSyscall()); got != tt.want {
				t.Fatalf("classifyUnfencedClone() = %s, want %s", got, tt.want)
			}
		})
	}
}

// userNamespacesEnabled reports false only when the kernel reports user
// namespaces as disabled. A missing sysctl is treated as enabled.
func userNamespacesEnabled() bool {
	for _, name := range []string{"max_user_namespaces", "unprivileged_userns_clone"} {
		data, err := os.ReadFile(filepath.Join("/proc/sys/user", name))
		if err != nil {
			data, err = os.ReadFile(filepath.Join("/proc/sys/kernel", name))
		}
		if err == nil && strings.TrimSpace(string(data)) == "0" {
			return false
		}
	}
	return true
}
