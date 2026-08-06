//go:build linux

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAttemptUnshareUnexpectedExitIsUnproven(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unshare")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho unexpected failure >&2\nexit 42\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	result := attemptUnshare("--user", "true")
	if result.Status != "unproven" {
		t.Fatalf("status = %q, want unproven", result.Status)
	}
}

func TestAttemptUnsharePermissionDeniedIsBlocked(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "unshare")
	if err := os.WriteFile(path, []byte("#!/bin/sh\necho 'unshare failed: Operation not permitted' >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	result := attemptUnshare("--user", "true")
	if result.Status != nsBlocked {
		t.Fatalf("status = %q, want %q", result.Status, nsBlocked)
	}
}

func TestDetectNftVersionFailureIsUnproven(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nft")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 42\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)

	_, status := detectNftVersion()
	if status != nftUnproven {
		t.Fatalf("status = %q, want %q", status, nftUnproven)
	}
}
