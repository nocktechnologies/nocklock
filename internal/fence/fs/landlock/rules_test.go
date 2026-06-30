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

func TestRulesFromConfigMapsReadOnlyAndReadWriteRights(t *testing.T) {
	root := t.TempDir()
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
	if len(spec.Paths) != 3 {
		t.Fatalf("expected enumerated root child + allow + extra paths, got %d: %+v", len(spec.Paths), spec.Paths)
	}
	if spec.Paths[0].Path != readOnly || spec.Paths[0].Access != AccessReadOnly {
		t.Fatalf("root child rule = %+v, want read-only %s", spec.Paths[0], readOnly)
	}
	if spec.Paths[1].Path != readOnly || spec.Paths[1].Access != AccessReadOnly {
		t.Fatalf("allow rule = %+v, want read-only %s", spec.Paths[1], readOnly)
	}
	if spec.Paths[2].Path != readWrite || spec.Paths[2].Access != AccessReadWrite {
		t.Fatalf("extra rule = %+v, want read-write %s", spec.Paths[2], readWrite)
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

func TestRulesFromConfigLimitsRegularFileRights(t *testing.T) {
	root := t.TempDir()
	allowedPath := filepath.Join(root, "allowed.txt")
	if err := os.WriteFile(allowedPath, []byte("allowed"), 0o600); err != nil {
		t.Fatalf("write allowed placeholder: %v", err)
	}
	dbPath := filepath.Join(root, "events.db")
	if err := os.WriteFile(dbPath, []byte(""), 0o600); err != nil {
		t.Fatalf("write db placeholder: %v", err)
	}

	spec, err := RulesFromConfig(&fsfence.FenceConfig{
		Root: root,
		Mode: "read-write",
	}, []AllowPath{{Path: dbPath, Access: AccessReadWrite}}, 5)
	if err != nil {
		t.Fatalf("RulesFromConfig failed: %v", err)
	}

	fileRule := spec.Paths[0]
	if fileRule.Rights&RightMakeDir != 0 || fileRule.Rights&RightRemoveDir != 0 || fileRule.Rights&RightRefer != 0 {
		t.Fatalf("regular file rule should not include directory-only rights: %#x", fileRule.Rights)
	}
	if fileRule.Rights&RightWriteFile == 0 || fileRule.Rights&RightTruncate == 0 {
		t.Fatalf("regular read-write file rule should include write/truncate: %#x", fileRule.Rights)
	}
}

func TestRulesFromConfigEnumeratesRootButSkipsNockAuditDir(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".nock"), 0o700); err != nil {
		t.Fatalf("mkdir .nock: %v", err)
	}
	src := filepath.Join(root, "src")
	if err := os.Mkdir(src, 0o755); err != nil {
		t.Fatalf("mkdir src: %v", err)
	}
	readme := filepath.Join(root, "README.md")
	if err := os.WriteFile(readme, []byte("readme"), 0o644); err != nil {
		t.Fatalf("write readme: %v", err)
	}

	spec, err := RulesFromConfig(&fsfence.FenceConfig{
		Root: root,
		Mode: "read-write",
	}, nil, 5)
	if err != nil {
		t.Fatalf("RulesFromConfig failed: %v", err)
	}

	got := map[string]bool{}
	for _, rule := range spec.Paths {
		got[rule.Path] = true
		if rule.Path == root || rule.Path == filepath.Join(root, ".nock") || strings.HasPrefix(rule.Path, filepath.Join(root, ".nock")+string(os.PathSeparator)) {
			t.Fatalf("ruleset granted audit path %q in %+v", rule.Path, spec.Paths)
		}
	}
	for _, want := range []string{readme, src} {
		if !got[want] {
			t.Fatalf("missing root child rule %q in %+v", want, spec.Paths)
		}
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
	root := t.TempDir()
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
