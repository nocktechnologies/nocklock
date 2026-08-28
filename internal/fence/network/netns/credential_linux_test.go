//go:build linux

package netns

import (
	"os/user"
	"strconv"
	"testing"
)

// TestValidateChildCredential is the automated coverage for the security
// boundary of the stdin setup request (helper_linux.go): the helper must refuse
// any credential that is root or that does not match the sudo-invoking user. It
// is pure (reads only SUDO_UID/SUDO_GID env) and runs non-root, so it exercises
// the HIGH-severity escalation fix on the default `go test` path — unlike the
// root-gated SetupAndExec path itself.
func TestValidateChildCredential(t *testing.T) {
	invokingUser, err := user.Current()
	if err != nil {
		t.Fatalf("resolve current user: %v", err)
	}
	if invokingUser.Uid == "0" {
		invokingUser, err = user.Lookup("nobody")
		if err != nil {
			t.Fatalf("resolve an unprivileged test user: %v", err)
		}
	}
	uid, err := strconv.Atoi(invokingUser.Uid)
	if err != nil {
		t.Fatalf("parse test uid %q: %v", invokingUser.Uid, err)
	}
	gid, err := strconv.Atoi(invokingUser.Gid)
	if err != nil {
		t.Fatalf("parse test gid %q: %v", invokingUser.Gid, err)
	}
	groupIDs, err := invokingUser.GroupIds()
	if err != nil {
		t.Fatalf("resolve test user's groups: %v", err)
	}
	groups := make([]int, 0, len(groupIDs))
	ownedGroups := make(map[int]struct{}, len(groupIDs))
	for _, groupID := range groupIDs {
		groupIDInt, parseErr := strconv.Atoi(groupID)
		if parseErr != nil {
			t.Fatalf("parse test group %q: %v", groupID, parseErr)
		}
		groups = append(groups, groupIDInt)
		ownedGroups[groupIDInt] = struct{}{}
	}
	unauthorizedGroup := 1
	for {
		if _, owned := ownedGroups[unauthorizedGroup]; !owned {
			break
		}
		unauthorizedGroup++
	}
	sudoUID, sudoGID := invokingUser.Uid, invokingUser.Gid

	for _, tc := range []struct {
		name        string
		req         Request
		sudoUID     string
		sudoGID     string
		wantRefused bool
	}{
		{
			name:    "happy path — matches the sudo-invoking user",
			req:     Request{UID: uid, GID: gid, Groups: groups},
			sudoUID: sudoUID, sudoGID: sudoGID,
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
			req:     Request{UID: uid, GID: 0, Groups: nil},
			sudoUID: sudoUID, sudoGID: sudoGID,
			wantRefused: true,
		},
		{
			name:    "group 0 refused",
			req:     Request{UID: uid, GID: gid, Groups: []int{gid, 0}},
			sudoUID: sudoUID, sudoGID: sudoGID,
			wantRefused: true,
		},
		{
			name:    "supplementary group not owned by invoking user refused",
			req:     Request{UID: uid, GID: gid, Groups: []int{gid, unauthorizedGroup}},
			sudoUID: sudoUID, sudoGID: sudoGID,
			wantRefused: true,
		},
		{
			name:    "uid not matching SUDO_UID refused",
			req:     Request{UID: uid + 1, GID: gid, Groups: []int{gid}},
			sudoUID: sudoUID, sudoGID: sudoGID,
			wantRefused: true,
		},
		{
			name:    "gid not matching SUDO_GID refused",
			req:     Request{UID: uid, GID: gid + 1, Groups: []int{gid}},
			sudoUID: sudoUID, sudoGID: sudoGID,
			wantRefused: true,
		},
		{
			name:    "SUDO_UID absent refused (not under sudo)",
			req:     Request{UID: uid, GID: gid, Groups: []int{gid}},
			sudoUID: "", sudoGID: sudoGID,
			wantRefused: true,
		},
		{
			name:    "SUDO_UID unparseable refused",
			req:     Request{UID: uid, GID: gid, Groups: []int{gid}},
			sudoUID: "notanint", sudoGID: sudoGID,
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
