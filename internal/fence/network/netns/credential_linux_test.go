//go:build linux

package netns

import "testing"

// TestValidateChildCredential is the automated coverage for the security
// boundary of the stdin setup request (helper_linux.go): the helper must refuse
// any credential that is root or that does not match the sudo-invoking user. It
// is pure (reads only SUDO_UID/SUDO_GID env) and runs non-root, so it exercises
// the HIGH-severity escalation fix on the default `go test` path — unlike the
// root-gated SetupAndExec path itself.
func TestValidateChildCredential(t *testing.T) {
	const (
		user  = "1000"
		group = "1000"
	)
	for _, tc := range []struct {
		name        string
		req         Request
		sudoUID     string
		sudoGID     string
		wantRefused bool
	}{
		{
			name:    "happy path — matches the sudo-invoking user",
			req:     Request{UID: 1000, GID: 1000, Groups: []int{1000}},
			sudoUID: user, sudoGID: group,
			wantRefused: false,
		},
		{
			name:    "uid 0 refused (the escalation this guard closes)",
			req:     Request{UID: 0, GID: 0, Groups: nil},
			sudoUID: "0", sudoGID: "0",
			wantRefused: true,
		},
		{
			name:    "gid 0 refused",
			req:     Request{UID: 1000, GID: 0, Groups: nil},
			sudoUID: user, sudoGID: group,
			wantRefused: true,
		},
		{
			name:    "group 0 refused",
			req:     Request{UID: 1000, GID: 1000, Groups: []int{1000, 0}},
			sudoUID: user, sudoGID: group,
			wantRefused: true,
		},
		{
			name:    "uid not matching SUDO_UID refused",
			req:     Request{UID: 1234, GID: 1000, Groups: []int{1000}},
			sudoUID: user, sudoGID: group,
			wantRefused: true,
		},
		{
			name:    "gid not matching SUDO_GID refused",
			req:     Request{UID: 1000, GID: 1234, Groups: []int{1000}},
			sudoUID: user, sudoGID: group,
			wantRefused: true,
		},
		{
			name:    "SUDO_UID absent refused (not under sudo)",
			req:     Request{UID: 1000, GID: 1000, Groups: []int{1000}},
			sudoUID: "", sudoGID: group,
			wantRefused: true,
		},
		{
			name:    "SUDO_UID unparseable refused",
			req:     Request{UID: 1000, GID: 1000, Groups: []int{1000}},
			sudoUID: "notanint", sudoGID: group,
			wantRefused: true,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SUDO_UID", tc.sudoUID)
			t.Setenv("SUDO_GID", tc.sudoGID)
			err := validateChildCredential(tc.req)
			if tc.wantRefused && err == nil {
				t.Fatalf("expected refusal, got nil")
			}
			if !tc.wantRefused && err != nil {
				t.Fatalf("expected acceptance, got %v", err)
			}
		})
	}
}
