//go:build !linux && !darwin

package logging

import (
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestChainIdentityUnsupportedPlatformPreservesLegacyPrune(t *testing.T) {
	project := t.TempDir()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	l, err := NewLogger(filepath.Join(project, "events.db"), project)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	event := sampleEvent(EventFilePassed, "filesystem", "legacy control", false, "legacy")
	event.Timestamp = time.Now().Add(-48 * time.Hour)
	if err := l.Log(event); err != nil {
		t.Fatal(err)
	}
	if n, err := l.Prune(24 * time.Hour); err != nil || n != 1 {
		t.Fatalf("legacy prune regressed: %d,%v", n, err)
	}
	if _, err := l.db.Exec("INSERT INTO chain_identity (id,version,agent_id,chain_id,legacy_anchor_digest) VALUES(1,1,?,?,?)", strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("0", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err := l.Prune(24 * time.Hour); err == nil {
		t.Fatal("unsupported platform pruned v2 identity")
	}
}
