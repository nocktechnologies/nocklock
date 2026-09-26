package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
	"github.com/nocktechnologies/nocklock/internal/fence/fs/landlock"
)

// TestEgressDecisionDirIsLandlockEnforceable pins the N10710 fix for bug (a):
// the egress decision dir must live under the audit state root (.nock), never
// the system temp dir. The default filesystem preset GRANTs /tmp, and Landlock
// is allow-only, so a decision dir UNDER a granted tree — the old
// os.MkdirTemp("", "nocklock-egress-decisions-") behaviour — makes
// RulesFromConfig fail closed on the default composition. This is the
// regression proof: it runs unprivileged on every PR (no root, literal ABI) and
// FAILS on the old /tmp-based path while passing on the new .nock path.
func TestEgressDecisionDirIsLandlockEnforceable(t *testing.T) {
	const abi = 5

	root := t.TempDir()
	// Stand-in for the Landlock-granted system temp root (the default preset
	// GRANTs /tmp). It is a SIBLING of root, so granting it does not also grant
	// root/.nock — this isolates the egress-dir concern from the audit-dir deny,
	// which is enforceable for its own reason (landlock.rootPathRules skips the
	// literal ".nock" child of the root).
	grantedTemp := t.TempDir()

	dbPath := filepath.Join(root, ".nock", "events.db")
	const sessionID = "test-session"

	// The new dir must sit under the audit root, not the granted temp tree.
	newDir := egressDecisionDir(dbPath, sessionID)
	if !strings.HasPrefix(newDir, filepath.Join(root, ".nock")+string(os.PathSeparator)) {
		t.Fatalf("egress decision dir %q must live under the audit root %q", newDir, filepath.Join(root, ".nock"))
	}

	// The OLD behaviour placed the dir under the system temp root; model that as
	// a dir under the granted temp tree.
	oldDir := filepath.Join(grantedTemp, "nocklock-egress-decisions-abc123")

	build := func(decisionDir string) (landlock.Spec, error) {
		return landlock.RulesFromConfig(&fsfence.FenceConfig{
			Root:       root,
			Mode:       "read-write",
			AllowPaths: []string{grantedTemp},
			DenyPaths:  egressChildDenyPaths(dbPath, root, decisionDir),
		}, nil, abi)
	}

	// New path: the deny sits outside every granted tree -> rules generate.
	if _, err := build(newDir); err != nil {
		t.Fatalf("egress decision dir under the audit root must generate Landlock rules cleanly, got: %v", err)
	}

	// Old /tmp-style path: the deny overlaps the granted temp tree -> rejected.
	_, err := build(oldDir)
	if err == nil {
		t.Fatal("egress decision dir under a Landlock-granted tree must be rejected (the old os.MkdirTemp path); got no error")
	}
	if !strings.Contains(err.Error(), "cannot be enforced by Landlock") {
		t.Fatalf("expected Landlock deny-enforcement rejection for the /tmp-style path, got: %v", err)
	}
}
