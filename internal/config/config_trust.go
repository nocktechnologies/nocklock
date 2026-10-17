package config

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// AllowUntrustedConfigEnv is the operator escape hatch for a config file that
// lives in a layout the trust walk would otherwise refuse -- a shared build
// directory owned by a trusted service account, for instance. Set it to a truthy
// value ("1", "true", "yes", "on") to skip the ownership and permission walk. It
// is read from the operator environment, never from the config file, so a fenced
// child cannot turn it on for the next run.
//
// The constant lives here, untagged, because every platform's build (and
// callers such as the CLI test harness) references it, while the walk it gates
// is a POSIX-ownership concept and lives in the unix-tagged file.
const AllowUntrustedConfigEnv = "NOCKLOCK_ALLOW_UNTRUSTED_CONFIG"

// configTrustLstat is a seam for deterministic, unprivileged tests. Production
// uses the real filesystem; tests swap in a fake view so crafted ownership and
// permission cases need no chmod, no chown and no root.
var configTrustLstat = os.Lstat

// readConfigFile reads path with no trust walk, wrapping a failure in the
// loader's error message.
func readConfigFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, configReadError(path, err)
	}
	return data, nil
}

// configReadError wraps an I/O failure reading the config at path, keeping the
// cause matchable with errors.Is.
func configReadError(path string, err error) error {
	return fmt.Errorf("failed to read config at %s: %w", path, err)
}

// accountLookups are the user and group database reads behind
// isUserPrivateGroup. configTrustAccounts is a seam so tests can describe any
// account layout without depending on the host's account files.
type accountLookups struct {
	user    func(uid uint32) (name string, primaryGID uint32, err error)
	group   func(gid uint32) (name string, err error)
	members func(gid uint32) ([]string, error)
}

var configTrustAccounts = accountLookups{
	user:    lookupUserAccount,
	group:   lookupGroupName,
	members: localGroupMembers,
}

// isUserPrivateGroup reports whether gid is the invoking user's private group:
// the per-user group Debian and Ubuntu create by default (USERGROUPS_ENAB),
// which also gives that user a umask of 002. It holds only when gid is uid's
// primary group, the group's name is the user's login name, and no account
// other than the user is in the group, either as a listed member or through
// its own primary group. Any lookup failure reports false, so a group whose
// members cannot be read is treated as shared.
func isUserPrivateGroup(uid, gid uint32) bool {
	name, primary, err := configTrustAccounts.user(uid)
	if err != nil || name == "" || primary != gid {
		return false
	}
	if group, err := configTrustAccounts.group(gid); err != nil || group != name {
		return false
	}
	members, err := configTrustAccounts.members(gid)
	if err != nil {
		return false
	}
	for _, member := range members {
		if member != name {
			return false
		}
	}
	return true
}

func lookupUserAccount(uid uint32) (string, uint32, error) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return "", 0, err
	}
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	if err != nil {
		return "", 0, err
	}
	return u.Username, uint32(gid), nil
}

func lookupGroupName(gid uint32) (string, error) {
	g, err := user.LookupGroupId(strconv.FormatUint(uint64(gid), 10))
	if err != nil {
		return "", err
	}
	return g.Name, nil
}

// The local account files localGroupMembers reads. They are variables so a
// test can point them at fixtures.
var (
	groupFilePath  = "/etc/group"
	passwdFilePath = "/etc/passwd"
)

// localGroupMembers returns every account the local account files place in
// gid: the members the group file lists for it and every user whose primary
// group it is. os/user does not expose group members. A gid with no entry in
// the group file is an error, because its members (from a directory service,
// say) cannot be read here.
func localGroupMembers(gid uint32) ([]string, error) {
	id := strconv.FormatUint(uint64(gid), 10)
	groups, err := colonRecords(groupFilePath)
	if err != nil {
		return nil, err
	}
	found := false
	var members []string
	for _, f := range groups {
		if len(f) < 4 || f[2] != id {
			continue
		}
		found = true
		for _, member := range strings.Split(f[3], ",") {
			if member = strings.TrimSpace(member); member != "" {
				members = append(members, member)
			}
		}
	}
	if !found {
		return nil, fmt.Errorf("no %s entry for gid %s", groupFilePath, id)
	}
	users, err := colonRecords(passwdFilePath)
	if err != nil {
		return nil, err
	}
	for _, f := range users {
		if len(f) >= 4 && f[3] == id {
			members = append(members, f[0])
		}
	}
	return members, nil
}

// colonRecords splits a colon-separated account file into fields, skipping
// blank and comment lines.
func colonRecords(path string) ([][]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var records [][]string
	for _, line := range strings.Split(string(data), "\n") {
		if line = strings.TrimSpace(line); line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		records = append(records, strings.Split(line, ":"))
	}
	return records, nil
}
