package config

import (
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
// /tmp, which the real trust walk refuses; the fake lets those tests exercise
// parsing and validation instead of the walk. The dedicated trust tests
// (config_trust_test.go) swap in crafted fakes and restore this default.
func TestMain(m *testing.M) {
	configTrustLstat = func(string) (os.FileInfo, error) { return permissiveTrustInfo{}, nil }
	os.Exit(m.Run())
}
