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
	if !result.Attempted || result.Blocked {
		t.Fatalf("unfenced clone(CLONE_NEWUSER) probe = %+v, want attempted and not blocked", result)
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
