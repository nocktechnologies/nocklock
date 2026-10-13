package cli

import (
	"errors"
	"strings"
	"testing"
)

func TestConfinedUnixSocketPolicy(t *testing.T) {
	tests := []struct {
		name          string
		abi           int
		detectErr     error
		require       bool
		wantIsolated  bool
		wantWarning   bool
		wantErrorText string
		wantReason    string
	}{
		{name: "supported ABI isolates", abi: 9, wantIsolated: true},
		{name: "older ABI runs with reachable warning", abi: 8, wantWarning: true, wantReason: "landlock_abi_8_below_9"},
		{name: "strict opt-in refuses older ABI", abi: 8, require: true, wantErrorText: "CONFINED egress cannot block pathname and abstract Unix sockets"},
		{name: "unknown capability runs with reachable warning", detectErr: errors.New("probe failed"), wantWarning: true, wantReason: "landlock_abi_unavailable"},
		{name: "strict opt-in refuses unknown capability", detectErr: errors.New("probe failed"), require: true, wantErrorText: "network.require_unix_socket_isolation is true"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolated, warning, err := confinedUnixSocketPolicy(tt.abi, tt.detectErr, tt.require)
			if isolated != tt.wantIsolated {
				t.Fatalf("isolated = %t, want %t", isolated, tt.wantIsolated)
			}
			if (warning != "") != tt.wantWarning {
				t.Fatalf("warning = %q, want warning=%t", warning, tt.wantWarning)
			}
			if tt.wantReason != "" && !strings.Contains(warning, tt.wantReason) {
				t.Fatalf("warning = %q, want reason %q", warning, tt.wantReason)
			}
			if tt.wantErrorText == "" {
				if err != nil {
					t.Fatalf("unexpected error: %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.wantErrorText) {
				t.Fatalf("error = %v, want it to contain %q", err, tt.wantErrorText)
			}
		})
	}
}

func TestUnixSocketBoundaryStatus(t *testing.T) {
	tests := []struct {
		name       string
		abi        int
		detectErr  error
		wantStatus string
		wantReason string
	}{
		{name: "ABI 8 unavailable", abi: 8, wantStatus: "unavailable", wantReason: "landlock_abi_8_below_9"},
		{name: "ABI 9 enforceable", abi: 9, wantStatus: "enforceable"},
		{name: "detection failed", detectErr: errors.New("probe failed"), wantStatus: "unavailable", wantReason: "landlock_abi_unavailable"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, reason := unixSocketBoundaryStatus(tt.abi, tt.detectErr)
			if status != tt.wantStatus || reason != tt.wantReason {
				t.Fatalf("unixSocketBoundaryStatus() = (%q, %q), want (%q, %q)", status, reason, tt.wantStatus, tt.wantReason)
			}
		})
	}
}

func TestStrictUnixSocketIsolationRequiresLinuxConfinedEgress(t *testing.T) {
	tests := []struct {
		name    string
		goos    string
		level   egressLevel
		req     bool
		wantErr bool
	}{
		{name: "strict Linux confined is supported", goos: "linux", level: egressLevelConfined, req: true},
		{name: "strict Linux advisory is rejected", goos: "linux", level: egressLevelAdvisory, req: true, wantErr: true},
		{name: "strict Linux kernel is rejected", goos: "linux", level: egressLevelKernel, req: true, wantErr: true},
		{name: "strict Linux off is rejected", goos: "linux", level: egressLevelOff, req: true, wantErr: true},
		{name: "strict non-Linux is rejected", goos: "darwin", level: egressLevelSeatbelt, req: true, wantErr: true},
		{name: "non-strict modes are unchanged", goos: "linux", level: egressLevelAdvisory},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := strictUnixSocketIsolationModeError(tt.goos, tt.level, tt.req)
			if (err != nil) != tt.wantErr {
				t.Fatalf("strictUnixSocketIsolationModeError() = %v, want error=%t", err, tt.wantErr)
			}
			if tt.wantErr && !strings.Contains(err.Error(), "network.require_unix_socket_isolation requires Linux CONFINED egress") {
				t.Fatalf("strict mode error = %q, want actionable mode requirement", err)
			}
		})
	}
}
