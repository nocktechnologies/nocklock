package config

import (
	"errors"
	"os"
	"testing"
	"time"
)

// permissiveTrustInfo is a trusted directory as far as the config trust walk is
// concerned: a non-world-writable directory whose owner cannot be read (Sys is
// nil), so the ownership comparison is skipped. It stands in for every path
// component under the permissive default seam.
type permissiveTrustInfo struct{}

func (permissiveTrustInfo) Name() string       { return "trusted" }
func (permissiveTrustInfo) Size() int64        { return 0 }
func (permissiveTrustInfo) Mode() os.FileMode  { return os.ModeDir | 0o755 }
func (permissiveTrustInfo) ModTime() time.Time { return time.Time{} }
func (permissiveTrustInfo) IsDir() bool        { return true }
func (permissiveTrustInfo) Sys() any           { return nil }

// TestMain installs a permissive config trust seam for the whole package test
// binary. Existing tests load configs from t.TempDir() under a world-writable
// /tmp, which the real trust walk refuses; the seam reports every real directory
// as trusted so those tests exercise parsing and validation instead of the walk.
// Files and symlinks keep their real Lstat info, and the config file itself is
// still checked on its open handle, so a fixture written group- or
// world-writable is refused. The dedicated trust tests (config_trust_test.go)
// swap in their own seams and restore this default.
//
// The account seam defaults to failing every lookup, so no group counts as the
// invoker's private group and a group-writable fixture is refused whatever the
// host's account files say. Tests that need a private group install one.
func TestMain(m *testing.M) {
	noAccounts := errors.New("account lookups are disabled in tests")
	configTrustAccounts = accountLookups{
		user:    func(uint32) (string, uint32, error) { return "", 0, noAccounts },
		group:   func(uint32) (string, error) { return "", noAccounts },
		members: func(uint32) ([]string, error) { return nil, noAccounts },
	}
	configTrustLstat = func(path string) (os.FileInfo, error) {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() {
			return info, err
		}
		return permissiveTrustInfo{}, nil
	}
	os.Exit(m.Run())
}
