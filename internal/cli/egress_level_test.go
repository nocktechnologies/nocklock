package cli

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestEffectiveEgressLevelTruthTable(t *testing.T) {
	gooses := []string{"linux", "darwin", "windows"}
	modes := []string{"proxy", "netns"}
	for _, goos := range gooses {
		for _, mode := range modes {
			for _, allowAll := range []bool{false, true} {
				for _, syscallEnforced := range []bool{false, true} {
					for _, fsInterposer := range []bool{false, true} {
						want := egressLevelAdvisory
						switch {
						case allowAll:
							want = egressLevelOff
						case mode == "netns" && goos == "linux":
							want = egressLevelKernel
						case mode == "netns":
							want = egressLevelUnreachable
						case goos == "linux" && syscallEnforced && fsInterposer:
							want = egressLevelConfined
						case goos == "linux" && syscallEnforced:
							want = egressLevelUnreachable
						}
						got := effectiveEgressLevel(goos, mode, allowAll, syscallEnforced, fsInterposer)
						if got != want {
							t.Errorf("effectiveEgressLevel(%s, %s, %t, %t, %t) = %s, want %s", goos, mode, allowAll, syscallEnforced, fsInterposer, got, want)
						}
					}
				}
			}
		}
	}

}

func TestEgressBannersNameEveryLevel(t *testing.T) {
	tests := []struct {
		level egressLevel
		want  []string
	}{
		{egressLevelKernel, []string{"KERNEL-enforced (netns)", "3 domain(s)"}},
		{egressLevelConfined, []string{"CONFINED (syscall fence; proxy bridge only)", "3 domain(s)"}},
		{egressLevelAdvisory, []string{"WARNING", "ADVISORY", "userspace proxy only", "ignores HTTP_PROXY", "any host"}},
		{egressLevelOff, []string{"WARNING", "OFF", "allow_all = true", "any host"}},
		{egressLevelUnreachable, []string{"fatal", "UNREACHABLE", "proxy bridge is disabled"}},
	}
	for _, tt := range tests {
		var stderr bytes.Buffer
		fmt.Fprintln(&stderr, egressBanner(tt.level, 3))
		for _, part := range tt.want {
			if !strings.Contains(stderr.String(), part) {
				t.Errorf("%s banner did not contain %q: %s", tt.level, part, stderr.String())
			}
		}
	}
}

func TestRequireEnforcedEgressAcceptsOnlyEnforcedLevels(t *testing.T) {
	for _, tt := range []struct {
		level egressLevel
		want  bool
	}{
		{egressLevelKernel, true},
		{egressLevelConfined, true},
		{egressLevelAdvisory, false},
		{egressLevelOff, false},
		{egressLevelUnreachable, false},
	} {
		if got := egressLevelMeetsRequirement(tt.level); got != tt.want {
			t.Errorf("egressLevelMeetsRequirement(%s) = %t, want %t", tt.level, got, tt.want)
		}
	}
	if got := egressRequirementMessage(egressLevelAdvisory, "darwin"); !strings.Contains(got, "macOS cannot provide enforced egress") {
		t.Fatalf("macOS advisory fix is not actionable: %q", got)
	}
	if got := egressRequirementMessage(egressLevelAdvisory, "linux"); !strings.Contains(got, "--net-fence=netns") {
		t.Fatalf("Linux advisory fix does not name --net-fence=netns: %q", got)
	}
	if got := egressRequirementMessage(egressLevelOff, "darwin"); !strings.Contains(got, "macOS cannot provide enforced egress today") {
		t.Fatalf("macOS OFF fix must say enforced egress is unavailable: %q", got)
	}
}
