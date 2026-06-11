package landlock

import (
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
		t.Fatalf("expected root + allow + extra paths, got %d: %+v", len(spec.Paths), spec.Paths)
	}
	if spec.Paths[0].Path != root || spec.Paths[0].Access != AccessReadOnly {
		t.Fatalf("root rule = %+v, want read-only root %s", spec.Paths[0], root)
	}
	if spec.Paths[1].Path != readOnly || spec.Paths[1].Access != AccessReadOnly {
		t.Fatalf("allow rule = %+v, want read-only %s", spec.Paths[1], readOnly)
	}
	if spec.Paths[2].Path != readWrite || spec.Paths[2].Access != AccessReadWrite {
		t.Fatalf("extra rule = %+v, want read-write %s", spec.Paths[2], readWrite)
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
