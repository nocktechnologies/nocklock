//go:build darwin

package logging

import (
	"path/filepath"
	"testing"
)

func TestSigningKey_AcceptsMacOSTemporaryDirectory(t *testing.T) {
	keyPath := filepath.Join(t.TempDir(), "keys", "audit.key")
	if _, err := loadOrCreateSigner(keyPath); err != nil {
		t.Fatalf("loadOrCreateSigner(%q): %v", keyPath, err)
	}
}
