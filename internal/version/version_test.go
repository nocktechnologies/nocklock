package version

import (
	"strings"
	"testing"
)

func TestBuildInfo_dev(t *testing.T) {
	orig := Version
	Version = "dev"
	defer func() { Version = orig }()

	got := BuildInfo()
	if got != "NockLock (dev)" {
		t.Fatalf("BuildInfo() with Version=dev: got %q, want %q", got, "NockLock (dev)")
	}
	if strings.Contains(got, " v") {
		t.Fatalf("dev build must not include a version number: got %q", got)
	}
}

func TestBuildInfo_tagged(t *testing.T) {
	orig := Version
	Version = "0.2.0"
	defer func() { Version = orig }()

	got := BuildInfo()
	want := "NockLock v0.2.0"
	if got != want {
		t.Fatalf("BuildInfo() with Version=0.2.0: got %q, want %q", got, want)
	}
	if strings.Contains(got, "(dev)") {
		t.Fatalf("tagged build must not include (dev): got %q", got)
	}
}
