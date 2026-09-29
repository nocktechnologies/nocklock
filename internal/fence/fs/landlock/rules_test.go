package landlock

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
)

func TestRightsForABIMasksUnknownBits(t *testing.T) {
	v1 := RightsForABI(1)
	v3 := RightsForABI(3)

	if v1 == 0 {
		t.Fatal("ABI v1 rights should not be empty")
	}
	if v3&v1 != v1 {
		t.Fatalf("ABI v3 should include all v1 rights: v1=%#x v3=%#x", v1, v3)
	}
	if v1&RightTruncate != 0 {
		t.Fatalf("ABI v1 must not include truncate, got %#x", v1)
	}
	if v3&RightTruncate == 0 {
		t.Fatalf("ABI v3 should include truncate, got %#x", v3)
	}
}

// resolvedTempDir returns a t.TempDir() with symlinks resolved. RulesFromConfig
// canonicalizes the Landlock root (filepath.EvalSymlinks) for security, so the
// emitted root-child rule paths are always the resolved form. On macOS
// t.TempDir() sits under /var/folders, a symlink to /private/var/folders, so a
// test comparing against the raw temp path would mismatch; resolving up front
// keeps the test and the ruleset in the same frame (a no-op on Linux).
func resolvedTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("resolve temp dir: %v", err)
	}
	return dir
}

func TestRulesFromConfigMapsReadOnlyAndReadWriteRights(t *testing.T) {
	root := resolvedTempDir(t)
	readOnly := filepath.Join(root, "readonly")
	if err := os.Mkdir(readOnly, 0o755); err != nil {
		t.Fatalf("mkdir readonly: %v", err)
	}
	readWrite := filepath.Join(root, "readwrite")

	spec, err := RulesFromConfig(&fsfence.FenceConfig{
		Root:       root,
		Mode:       "read-only",
		AllowPaths: []string{readOnly},
	}, []AllowPath{{Path: readWrite, Access: AccessReadWrite}}, 3)
	if err != nil {
		t.Fatalf("RulesFromConfig failed: %v", err)
	}

	if spec.ABI != 3 {
		t.Fatalf("ABI = %d, want 3", spec.ABI)
	}
	if spec.HandledAccessFS&RightTruncate == 0 {
		t.Fatalf("ABI v3 handled rights should include truncate: %#x", spec.HandledAccessFS)
	}
	// Root, allow, and extra rules are appended first, so indices 0-2 stay
	// stable. Baseline device grants follow and vary by host, so filter them out
	// and keep the exact-count assertion on everything else — an unintended
	// extra grant from RulesFromConfig must still fail this test.
	var configured []PathRule
	for _, r := range spec.Paths {
		if !IsBaselineDeviceNode(r.Path) {
			configured = append(configured, r)
		}
	}
	if len(configured) != 3 {
		t.Fatalf("expected exactly root + allow + extra paths, got %d: %+v", len(configured), configured)
	}
	if spec.Paths[0].Path != root || spec.Paths[0].Access != AccessReadOnly {
		t.Fatalf("root rule = %+v, want read-only %s", spec.Paths[0], root)
	}
	if spec.Paths[1].Path != readOnly || spec.Paths[1].Access != AccessReadOnly {
		t.Fatalf("allow rule = %+v, want read-only %s", spec.Paths[1], readOnly)
	}
	if spec.Paths[2].Path != readWrite || spec.Paths[2].Access != AccessReadWrite {
		t.Fatalf("extra rule = %+v, want read-write %s", spec.Paths[2], readWrite)
	}
}

func TestRulesFromConfigOmitsMissingReadOnlyPath(t *testing.T) {
	parent := t.TempDir()
	root := filepath.Join(parent, "project")
	existing := filepath.Join(parent, "existing")
	missing := filepath.Join(parent, "missing")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(existing, 0o755); err != nil {
		t.Fatal(err)
	}
	spec, err := RulesFromConfig(&fsfence.FenceConfig{
		Root: root, Mode: "read-write", AllowPaths: []string{existing, missing},
	}, nil, 5)
	if err != nil {
		t.Fatalf("build rules with absent read path: %v", err)
	}
	foundExisting := false
	for _, rule := range spec.Paths {
		if rule.Path == missing {
			t.Fatal("missing path received a Landlock grant")
		}
		if rule.Path == existing {
			foundExisting = true
			if rule.Rights&RightExecute == 0 || rule.Rights&RightWriteFile != 0 {
				t.Fatalf("existing path must be executable but read-only: %+v", rule)
			}
		}
	}
	if !foundExisting {
		t.Fatal("existing read-only path received no Landlock grant")
	}
}

// TestRulesFromConfigGrantsBaselineDeviceWrites asserts on the RIGHTS BITMASK,
// not path presence: /dev/null and /dev/tty must carry write, and /dev/zero must
// be read-only. A path-presence check would pass under the pre-fix behavior
// where these devices were reachable via an allow entry but only granted read —
// the exact reason git and echo failed in the field.
func TestRulesFromConfigGrantsBaselineDeviceWrites(t *testing.T) {
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skipf("/dev/null unavailable: %v", err)
	}
	root := t.TempDir()
	// ABI 5 handles RightIOCTLDev, which the writable devices request.
	spec, err := RulesFromConfig(&fsfence.FenceConfig{Root: root, Mode: "read-write"}, nil, 5)
	if err != nil {
		t.Fatalf("RulesFromConfig failed: %v", err)
	}

	byPath := make(map[string]PathRule)
	for _, r := range spec.Paths {
		byPath[r.Path] = r
	}

	null, ok := byPath["/dev/null"]
	if !ok {
		t.Fatalf("/dev/null not granted; rules=%+v", spec.Paths)
	}
	if null.Rights&RightWriteFile == 0 || null.Rights&RightReadFile == 0 {
		t.Fatalf("/dev/null must be read+write, got rights %#x", null.Rights)
	}

	if _, err := os.Stat("/dev/tty"); err == nil {
		tty, ok := byPath["/dev/tty"]
		if !ok {
			t.Fatalf("/dev/tty present on host but not granted; rules=%+v", spec.Paths)
		}
		if tty.Rights&RightWriteFile == 0 || tty.Rights&RightReadFile == 0 {
			t.Fatalf("/dev/tty must be read+write, got rights %#x", tty.Rights)
		}
	}

	if _, err := os.Stat("/dev/zero"); err == nil {
		zero, ok := byPath["/dev/zero"]
		if !ok {
			t.Fatalf("/dev/zero present on host but not granted; rules=%+v", spec.Paths)
		}
		if zero.Rights&RightWriteFile != 0 {
			t.Fatalf("/dev/zero must be read-only, got write bit in rights %#x", zero.Rights)
		}
		if zero.Rights&RightReadFile == 0 {
			t.Fatalf("/dev/zero must be readable, got rights %#x", zero.Rights)
		}
	}
}

// TestRulesFromConfigDenySuppressesBaselineDevice verifies an explicit deny of a
// baseline device node wins: the node is not re-granted (which would also make
// the ruleset unenforceable, since Landlock cannot carve a deny out of a grant).
func TestRulesFromConfigDenySuppressesBaselineDevice(t *testing.T) {
	if _, err := os.Stat("/dev/null"); err != nil {
		t.Skipf("/dev/null unavailable: %v", err)
	}
	root := t.TempDir()
	spec, err := RulesFromConfig(&fsfence.FenceConfig{
		Root:      root,
		Mode:      "read-write",
		DenyPaths: []string{"/dev/null"},
	}, nil, 5)
	if err != nil {
		t.Fatalf("RulesFromConfig failed: %v", err)
	}
	for _, r := range spec.Paths {
		if r.Path == "/dev/null" {
			t.Fatalf("/dev/null denied but still granted: %+v", r)
		}
	}
}

func TestRulesFromConfigKeepsAllowPathsReadOnlyWhenRootIsReadWrite(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	allowPath := filepath.Join(t.TempDir(), "external-cache")
	if err := os.Mkdir(allowPath, 0o755); err != nil {
		t.Fatalf("mkdir allow path: %v", err)
	}

	spec, err := RulesFromConfig(&fsfence.FenceConfig{
		Root:       root,
		Mode:       "read-write",
		AllowPaths: []string{allowPath},
	}, nil, 5)
	if err != nil {
		t.Fatalf("RulesFromConfig failed: %v", err)
	}

	var allowRule *PathRule
	for i := range spec.Paths {
		if spec.Paths[i].Path == allowPath {
			allowRule = &spec.Paths[i]
			break
		}
	}
	if allowRule == nil {
		t.Fatalf("missing allow path rule %q in %+v", allowPath, spec.Paths)
	}
	if allowRule.Access != AccessReadOnly {
		t.Fatalf("allow path access = %q, want %q", allowRule.Access, AccessReadOnly)
	}
	if allowRule.Rights&writeRights != 0 {
		t.Fatalf("allow path must not include write/create/remove rights: %#x", allowRule.Rights)
	}
	if allowRule.Rights&RightTruncate != 0 {
		t.Fatalf("allow path must not include truncate: %#x", allowRule.Rights)
	}
}

func TestRulesFromConfigMapsAllowRWPathsReadWrite(t *testing.T) {
	root := t.TempDir()
	readOnly := filepath.Join(t.TempDir(), "readonly")
	readWrite := filepath.Join(t.TempDir(), "readwrite")
	for _, path := range []string{readOnly, readWrite} {
		if err := os.Mkdir(path, 0o755); err != nil {
			t.Fatalf("mkdir %q: %v", path, err)
		}
	}

	spec, err := RulesFromConfig(&fsfence.FenceConfig{
		Root:         root,
		Mode:         "read-only",
		AllowPaths:   []string{readOnly},
		AllowRWPaths: []string{readWrite},
	}, nil, 5)
	if err != nil {
		t.Fatalf("RulesFromConfig failed: %v", err)
	}

	rules := make(map[string]PathRule, len(spec.Paths))
	for _, rule := range spec.Paths {
		rules[rule.Path] = rule
	}
	if rule := rules[readOnly]; rule.Access != AccessReadOnly || rule.Rights&writeRights != 0 {
		t.Fatalf("read-only allow rule = %+v, want no write rights", rule)
	}
	if rule := rules[readWrite]; rule.Access != AccessReadWrite || rule.Rights&writeRights == 0 {
		t.Fatalf("read-write allow rule = %+v, want write rights", rule)
	}
}

// TestRulesFromConfigLimitsRegularFileRights asserts a rule naming a REGULAR
// FILE carries only file rights: directory-entry rights (MAKE_DIR, REMOVE_DIR,
// REFER) are meaningless on a file and must not be set. The rule comes from an
// allow_rw entry, since the root is granted as one directory hierarchy and no
// longer produces a per-file rule for each of its children.
func TestRulesFromConfigLimitsRegularFileRights(t *testing.T) {
	root := resolvedTempDir(t)
	allowedPath := filepath.Join(root, "allowed.txt")
	if err := os.WriteFile(allowedPath, []byte("allowed"), 0o600); err != nil {
		t.Fatalf("write allowed placeholder: %v", err)
	}

	spec, err := RulesFromConfig(&fsfence.FenceConfig{
		Root:         root,
		Mode:         "read-write",
		AllowRWPaths: []string{allowedPath},
	}, nil, 5)
	if err != nil {
		t.Fatalf("RulesFromConfig failed: %v", err)
	}

	fileRule, ok := findPathRule(spec.Paths, allowedPath)
	if !ok {
		t.Fatalf("missing regular-file rule %q in %+v", allowedPath, spec.Paths)
	}
	if fileRule.Rights&RightMakeDir != 0 || fileRule.Rights&RightRemoveDir != 0 || fileRule.Rights&RightRefer != 0 {
		t.Fatalf("regular file rule should not include directory-only rights: %#x", fileRule.Rights)
	}
	if fileRule.Rights&RightWriteFile == 0 || fileRule.Rights&RightTruncate == 0 {
		t.Fatalf("regular read-write file rule should include write/truncate: %#x", fileRule.Rights)
	}
}

// TestRulesFromConfigGrantsFenceRootAsOneHierarchy is the acceptance test for
// "the agent can create entries directly in the fence root", on a FRESH root -
// one with no audit state inside it, which is the default. See
// TestRulesFromConfigProtectedSubdirWithholdsRootGrant for the legacy shape.
//
// Landlock checks
// MAKE_REG/MAKE_DIR/REMOVE_FILE/REMOVE_DIR against the DIRECTORY that holds the
// entry, so a ruleset that granted only the root's existing children (what
// earlier rounds did, to keep the in-root audit directory ungranted) denied
// `touch <root>/newfile` even in read-write mode.
func TestRulesFromConfigGrantsFenceRootAsOneHierarchy(t *testing.T) {
	root := resolvedTempDir(t)
	src := filepath.Join(root, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}

	spec, err := RulesFromConfig(&fsfence.FenceConfig{
		Root: root,
		Mode: "read-write",
	}, nil, 5)
	if err != nil {
		t.Fatalf("RulesFromConfig failed: %v", err)
	}

	rootRule, ok := findPathRule(spec.Paths, root)
	if !ok {
		t.Fatalf("fence root %q is not granted: %+v", root, spec.Paths)
	}
	for _, right := range []struct {
		name string
		bit  uint64
	}{
		{"MAKE_REG", RightMakeReg},
		{"MAKE_DIR", RightMakeDir},
		{"REMOVE_FILE", RightRemoveFile},
		{"REMOVE_DIR", RightRemoveDir},
	} {
		if rootRule.Rights&right.bit == 0 {
			t.Fatalf("root rule is missing %s, so the child cannot create/remove entries in the root: %#x", right.name, rootRule.Rights)
		}
	}

	// The root is granted as ONE rule, not re-enumerated per child. A stray
	// per-child rule would be redundant at best and, for a symlinked child,
	// would grant a path outside the root.
	for _, rule := range spec.Paths {
		if rule.Path == src {
			t.Fatalf("root child %q got its own rule; the root grant already covers it: %+v", src, spec.Paths)
		}
	}
}

// TestRulesFromConfigRootGrantCoversNockConfigDir codifies an ACCEPTED
// CONSEQUENCE of granting the fence root on a FRESH root, so it is a decision on
// the record rather than a surprise.
//
// <root>/.nock/config.toml is the fence's own config, and it falls inside the
// root grant. No Landlock ruleset can exclude it: the kernel walks upward from
// the accessed file and allows as soon as an ancestor rule grants the access
// (security/landlock/fs.c, is_access_to_paths_allowed), so a narrower rule on
// .nock cannot revoke the root's grant, and stacking layers does not help
// because every layer would have to grant MAKE_REG on the root for a create in
// the root to succeed.
//
// What keeps this sound: the config is read by the UNFENCED parent before the
// child starts, so in-session tampering cannot widen the fence the child is
// already under; a rewritten config only takes effect on the NEXT wrap, and it
// is a tracked file in the project, so the edit is visible in git. The audit
// trail — which must survive a hostile child — is what moved out of the root
// (config.AuditStateDir); see TestLandlockChildCanMutateRootButNotRelocatedAudit
// for the enforced negative control.
func TestRulesFromConfigRootGrantCoversNockConfigDir(t *testing.T) {
	root := resolvedTempDir(t)
	nockDir := filepath.Join(root, ".nock")
	if err := os.Mkdir(nockDir, 0o700); err != nil {
		t.Fatalf("mkdir .nock: %v", err)
	}

	spec, err := RulesFromConfig(&fsfence.FenceConfig{
		Root: root,
		Mode: "read-write",
	}, nil, 5)
	if err != nil {
		t.Fatalf("RulesFromConfig failed: %v", err)
	}
	if _, ok := findPathRule(spec.Paths, nockDir); ok {
		t.Fatalf("expected no rule naming %q; it is covered by the root grant, not granted separately", nockDir)
	}
	if _, ok := findPathRule(spec.Paths, root); !ok {
		t.Fatalf("fence root %q is not granted, so .nock would not be reachable: %+v", root, spec.Paths)
	}
}

// TestRulesFromConfigRejectsDenyInsideGrantedRoot codifies the second accepted
// consequence, again for a FRESH root: with the root granted as one hierarchy,
// a filesystem.deny path
// INSIDE the root can no longer be enforced by Landlock, and rule generation
// fails closed rather than shipping a fence that ignores the deny. Before the
// root was granted, such a deny worked only when the path did not yet exist.
// Deny paths outside the root (the default set: ~/.ssh, ~/.aws, ~/.gnupg) are
// unaffected.
func TestRulesFromConfigRejectsDenyInsideGrantedRoot(t *testing.T) {
	root := resolvedTempDir(t)
	secret := filepath.Join(root, "secrets")

	_, err := RulesFromConfig(&fsfence.FenceConfig{
		Root:      root,
		Mode:      "read-write",
		DenyPaths: []string{secret},
	}, nil, 5)
	if err == nil {
		t.Fatal("expected a deny path inside the granted root to be rejected")
	}
	if !strings.Contains(err.Error(), "cannot be enforced by Landlock") {
		t.Fatalf("expected an unenforceable-deny error, got: %v", err)
	}
}

func findPathRule(rules []PathRule, path string) (PathRule, bool) {
	for _, rule := range rules {
		if rule.Path == path {
			return rule, true
		}
	}
	return PathRule{}, false
}

// TestRulesFromConfigRootChildSymlinkGrantsNothingOutsideRoot replaces the
// earlier "reject a root child that symlinks outside the root" guard. That
// check existed because the ruleset enumerated and resolved each root child, so
// a symlink to /etc would have produced a real rule on /etc. Granting the root
// as one hierarchy removes the hazard at the source: Landlock binds the rule to
// the root's inode, and the symlink TARGET has no rule on any of its ancestors,
// so it is granted nothing. The guard is kept as an assertion on that outcome
// rather than deleted.
func TestRulesFromConfigRootChildSymlinkGrantsNothingOutsideRoot(t *testing.T) {
	root := resolvedTempDir(t)
	outside := resolvedTempDir(t)
	if err := os.Symlink(outside, filepath.Join(root, "loot")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	spec, err := RulesFromConfig(&fsfence.FenceConfig{
		Root: root,
		Mode: "read-write",
	}, nil, 5)
	if err != nil {
		t.Fatalf("RulesFromConfig failed: %v", err)
	}
	for _, rule := range spec.Paths {
		if IsBaselineDeviceNode(rule.Path) {
			continue
		}
		if !pathInsideRoot(root, rule.Path) {
			t.Fatalf("rule %q lies outside the fence root %q: %+v", rule.Path, root, spec.Paths)
		}
	}
}

// TestRulesFromConfigProtectedSubdirWithholdsRootGrant is the LEGACY shape: a
// root that still holds its audit trail. The protected directory gets no grant,
// AND the root itself gets none either - asserted as the ABSENCE of a root rule,
// because a root rule is exactly what would reach the protected directory by
// ancestor walk. The root's other children stay granted, so the agent keeps
// working everywhere it worked before.
func TestRulesFromConfigProtectedSubdirWithholdsRootGrant(t *testing.T) {
	root := resolvedTempDir(t)
	audit := filepath.Join(root, ".nock")
	if err := os.Mkdir(audit, 0o700); err != nil {
		t.Fatalf("mkdir audit dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(audit, "events.db"), []byte("chain"), 0o600); err != nil {
		t.Fatalf("write audit db: %v", err)
	}
	src := filepath.Join(root, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}

	spec, err := RulesFromConfig(&fsfence.FenceConfig{
		Root:                root,
		Mode:                "read-write",
		ProtectedRootSubdir: audit,
	}, nil, 5)
	if err != nil {
		t.Fatalf("RulesFromConfig failed: %v", err)
	}

	if rule, ok := findPathRule(spec.Paths, root); ok {
		t.Fatalf("root %q was granted while the audit trail is inside it; MAKE_REG on the root would reach %q: %+v", root, audit, rule)
	}
	for _, rule := range spec.Paths {
		if rule.Path == audit || strings.HasPrefix(rule.Path, audit+string(os.PathSeparator)) {
			t.Fatalf("protected audit path %q was granted: %+v", rule.Path, spec.Paths)
		}
	}
	if _, ok := findPathRule(spec.Paths, src); !ok {
		t.Fatalf("root child %q lost its grant: %+v", src, spec.Paths)
	}
}

// TestRulesFromConfigProtectedSubdirRejectsChildSymlinkOutsideRoot keeps the
// escape check the per-child enumeration needs. Child rules resolve symlinks, so
// a child pointing outside the root would otherwise produce a real grant on the
// target. The single-rule fresh-root path cannot hit this, which is why the
// guard lives with the legacy shape.
func TestRulesFromConfigProtectedSubdirRejectsChildSymlinkOutsideRoot(t *testing.T) {
	root := resolvedTempDir(t)
	audit := filepath.Join(root, ".nock")
	if err := os.Mkdir(audit, 0o700); err != nil {
		t.Fatalf("mkdir audit dir: %v", err)
	}
	if err := os.Symlink(resolvedTempDir(t), filepath.Join(root, "loot")); err != nil {
		t.Skipf("symlinks unsupported: %v", err)
	}

	_, err := RulesFromConfig(&fsfence.FenceConfig{
		Root:                root,
		Mode:                "read-write",
		ProtectedRootSubdir: audit,
	}, nil, 5)
	if err == nil {
		t.Fatal("expected a root child symlinked outside the root to be rejected")
	}
	if !strings.Contains(err.Error(), "resolves outside Landlock root") {
		t.Fatalf("expected an outside-root symlink error, got: %v", err)
	}
}

// TestRulesFromConfigProtectedSubdirRefusesWhenUnresolvable: if the protected
// directory cannot be resolved, refuse rather than fall through to granting the
// whole root, which would expose the very directory being protected.
func TestRulesFromConfigProtectedSubdirRefusesWhenUnresolvable(t *testing.T) {
	root := resolvedTempDir(t)
	_, err := RulesFromConfig(&fsfence.FenceConfig{
		Root:                root,
		Mode:                "read-write",
		ProtectedRootSubdir: filepath.Join(root, "does-not-resolve"),
	}, nil, 5)
	if err == nil {
		t.Fatal("expected an unresolvable protected subdirectory to be rejected, not silently ignored")
	}
	if !strings.Contains(err.Error(), "protected root subdirectory") {
		t.Fatalf("expected a protected-subdirectory error, got: %v", err)
	}
}

// TestRulesFromConfigRefusesProtectedSubdirBelowDirectChild closes a hole that
// would fail SILENTLY. Skipping one entry protects only that entry, so if the
// protected directory sits deeper than a direct child, the child above it gets
// granted and Landlock's ancestor walk reaches the protected directory anyway.
// It comes up when filesystem.root is an ancestor of the project holding the
// audit trail. Refusing is the only honest answer: a ruleset that looks like it
// protects the audit log but does not is worse than one that will not build.
func TestRulesFromConfigRefusesProtectedSubdirBelowDirectChild(t *testing.T) {
	root := resolvedTempDir(t)
	audit := filepath.Join(root, "project", ".nock")
	if err := os.MkdirAll(audit, 0o700); err != nil {
		t.Fatalf("mkdir nested audit dir: %v", err)
	}

	_, err := RulesFromConfig(&fsfence.FenceConfig{
		Root:                root,
		Mode:                "read-write",
		ProtectedRootSubdir: audit,
	}, nil, 5)
	if err == nil {
		t.Fatal("expected a protected directory below a direct child to be refused, not silently exposed")
	}
	if !strings.Contains(err.Error(), "not a direct child") {
		t.Fatalf("expected a direct-child error, got: %v", err)
	}
}

func TestRulesFromConfigRejectsEmptyABI(t *testing.T) {
	_, err := RulesFromConfig(&fsfence.FenceConfig{Root: t.TempDir(), Mode: "read-write"}, nil, 0)
	if err == nil {
		t.Fatal("expected ABI 0 to be rejected")
	}
	if !strings.Contains(err.Error(), "Landlock ABI") {
		t.Fatalf("expected ABI error, got: %v", err)
	}
}

func TestSpecRoundTrip(t *testing.T) {
	spec := Spec{
		ABI:             3,
		HandledAccessFS: RightsForABI(3),
		Paths: []PathRule{
			{Path: "/tmp/project", Access: AccessReadWrite, Rights: RightsForABI(3)},
			{Path: "/tmp/events.db", Access: AccessReadWrite, Rights: RightsForABI(3)},
		},
	}

	encoded, err := MarshalSpec(spec)
	if err != nil {
		t.Fatalf("MarshalSpec failed: %v", err)
	}
	decoded, err := UnmarshalSpec(encoded)
	if err != nil {
		t.Fatalf("UnmarshalSpec failed: %v", err)
	}
	if decoded.ABI != spec.ABI || decoded.HandledAccessFS != spec.HandledAccessFS {
		t.Fatalf("decoded header = ABI %d rights %#x, want ABI %d rights %#x", decoded.ABI, decoded.HandledAccessFS, spec.ABI, spec.HandledAccessFS)
	}
	if len(decoded.Paths) != len(spec.Paths) {
		t.Fatalf("decoded %d paths, want %d", len(decoded.Paths), len(spec.Paths))
	}
	for i := range spec.Paths {
		if decoded.Paths[i] != spec.Paths[i] {
			t.Fatalf("decoded path %d = %+v, want %+v", i, decoded.Paths[i], spec.Paths[i])
		}
	}
}

// N8441: a deny path that overlaps a Landlock-granted tree cannot be enforced
// by the allow-only Landlock layer (a static binary or a child that clears
// LD_PRELOAD would reach it). RulesFromConfig must fail closed instead of
// silently emitting a ruleset that grants the denied path.
func TestRulesFromConfigRejectsDenyPathInsideRoot(t *testing.T) {
	root := resolvedTempDir(t)
	src := filepath.Join(root, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	deny := filepath.Join(src, "secret") // under the granted root child "src"

	_, err := RulesFromConfig(&fsfence.FenceConfig{
		Root:      root,
		Mode:      "read-write",
		DenyPaths: []string{deny},
	}, nil, 5)
	if err == nil {
		t.Fatal("expected deny path inside the granted root to be rejected")
	}
	if !strings.Contains(err.Error(), "cannot be enforced by Landlock") {
		t.Fatalf("expected Landlock deny-enforcement error, got: %v", err)
	}
}

func TestRulesFromConfigRejectsDenyPathInsideAllow(t *testing.T) {
	root := t.TempDir()
	allow := t.TempDir()
	deny := filepath.Join(allow, ".ssh") // under an explicitly allowed tree

	_, err := RulesFromConfig(&fsfence.FenceConfig{
		Root:       root,
		Mode:       "read-only",
		AllowPaths: []string{allow},
		DenyPaths:  []string{deny},
	}, nil, 5)
	if err == nil {
		t.Fatal("expected deny path inside an allow path to be rejected")
	}
	if !strings.Contains(err.Error(), "cannot be enforced by Landlock") {
		t.Fatalf("expected Landlock deny-enforcement error, got: %v", err)
	}
}

func TestRulesFromConfigRejectsDenyPathInsideAllowRW(t *testing.T) {
	root := t.TempDir()
	allowRW := t.TempDir()
	deny := filepath.Join(allowRW, "protected")

	_, err := RulesFromConfig(&fsfence.FenceConfig{
		Root:         root,
		Mode:         "read-only",
		AllowRWPaths: []string{allowRW},
		DenyPaths:    []string{deny},
	}, nil, 5)
	if err == nil || !strings.Contains(err.Error(), "cannot be enforced by Landlock") {
		t.Fatalf("deny path inside allow_rw error = %v, want Landlock enforcement rejection", err)
	}
}

// A deny path that does not overlap any granted tree needs no Landlock rule:
// Landlock denies everything not explicitly allowed, so the config is valid.
func TestRulesFromConfigAllowsNonOverlappingDenyPath(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}

	spec, err := RulesFromConfig(&fsfence.FenceConfig{
		Root:      root,
		Mode:      "read-write",
		DenyPaths: []string{"/home/someone-else/.ssh", "/etc/shadow"},
	}, nil, 5)
	if err != nil {
		t.Fatalf("non-overlapping deny path should be accepted: %v", err)
	}
	for _, rule := range spec.Paths {
		if pathsOverlap("/etc/shadow", rule.Path) || pathsOverlap("/home/someone-else/.ssh", rule.Path) {
			t.Fatalf("did not expect a deny path to overlap a granted rule %q", rule.Path)
		}
	}
}

func TestPathsOverlapComponentBoundary(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
	}{
		{"/a/b", "/a/b", true},   // identical
		{"/a/b", "/a/b/c", true}, // ancestor
		{"/a/b/c", "/a/b", true}, // descendant
		{"/a/b", "/a/bc", false}, // not a component boundary
		{"/a/b", "/a/c", false},  // siblings
		{"/", "/a/b", true},      // root is an ancestor of everything
		{"/a", "/", true},        // descendant of root
	}
	for _, c := range cases {
		if got := pathsOverlap(c.a, c.b); got != c.want {
			t.Errorf("pathsOverlap(%q, %q) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
