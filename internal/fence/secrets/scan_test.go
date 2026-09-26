package secrets

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func syntheticToken() string { return "ghp_" + strings.Repeat("aB3x", 9) }

func TestScanDetectsWithoutRetainingValues(t *testing.T) {
	root := t.TempDir()
	value := syntheticToken()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("# config\nTOKEN="+value+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	report := Scan(context.Background(), root, []string{"."}, []string{"CUSTOM=" + value})
	if !report.Complete || report.Safe() || len(report.Findings) != 2 || report.FilesScanned != 1 || report.EnvScanned != 1 {
		t.Fatalf("unexpected report: %+v", report)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), value) {
		t.Fatal("report retained a secret value")
	}
	for _, f := range report.Findings {
		if f.Source == "file" && (f.Location != ".env" || f.Line != 2) {
			t.Fatalf("wrong location: %+v", f)
		}
	}
}

func TestScanDetectors(t *testing.T) {
	for _, tc := range []struct{ value, rule string }{
		{"AKIA" + strings.Repeat("A", 16), "aws-access-key-id"},
		{"ASIA" + strings.Repeat("B", 16), "aws-access-key-id"},
		{syntheticToken(), "github-token"},
		{"github_pat_" + strings.Repeat("a", 82), "github-token"},
		{"-----BEGIN " + "OPENSSH PRIVATE KEY-----", "private-key"},
		{"-----BEGIN " + "PRIVATE KEY-----", "private-key"},
	} {
		t.Run(tc.rule+tc.value[:4], func(t *testing.T) {
			r := Scan(context.Background(), "", nil, []string{"TEST=" + tc.value})
			if len(r.Findings) != 1 || r.Findings[0].Rule != tc.rule {
				t.Fatalf("missing detector: %+v", r)
			}
		})
	}
	r := Scan(context.Background(), "", nil, []string{"TEST=ghp_example", "TEXT=ordinary prose"})
	if !r.Safe() {
		t.Fatalf("benign inputs flagged: %+v", r)
	}
}

func TestScanPrivateKeyFileReportsLineAndRedactsMetadata(t *testing.T) {
	root := t.TempDir()
	header := "-----BEGIN " + "PRIVATE KEY-----"
	if err := os.WriteFile(filepath.Join(root, header), []byte("comment\n"+header+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	r := Scan(context.Background(), root, []string{header}, nil)
	if !r.Complete || len(r.Findings) != 1 || r.Findings[0].Rule != "private-key" || r.Findings[0].Line != 2 || r.Findings[0].Location != "[redacted]" {
		t.Fatalf("unexpected private-key finding: %+v", r)
	}
}

func TestScanFailsClosedOnIncompleteInputs(t *testing.T) {
	for _, kind := range []string{"missing", "symlink", "oversize", "traversal", "cancelled"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			path := "input"
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			switch kind {
			case "symlink":
				if err := os.Symlink(t.TempDir(), filepath.Join(root, path)); err != nil {
					t.Fatal(err)
				}
			case "oversize":
				if err := os.WriteFile(filepath.Join(root, path), []byte(strings.Repeat("x", MaxFileBytes+1)), 0600); err != nil {
					t.Fatal(err)
				}
			case "traversal":
				path = "../escape"
			case "cancelled":
				cancel()
			}
			r := Scan(ctx, root, []string{path}, nil)
			if r.Complete || r.Safe() || len(r.Issues) == 0 {
				t.Fatalf("incomplete scan accepted: %+v", r)
			}
		})
	}
}

func TestScanIncludesBinaryAndHiddenFiles(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".hidden.bin"), []byte("\x00\x01"+syntheticToken()+"\x00"), 0600); err != nil {
		t.Fatal(err)
	}
	r := Scan(context.Background(), root, []string{"."}, nil)
	if len(r.Findings) != 1 || r.FilesScanned != 1 {
		t.Fatalf("binary/hidden input skipped: %+v", r)
	}
}

func TestScanRejectsSymlinkInExplicitParent(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "real"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "real", "file"), []byte("clean"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("real", filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	r := Scan(context.Background(), root, []string{"link/file"}, nil)
	if r.Complete || r.Safe() {
		t.Fatalf("symlink parent accepted: %+v", r)
	}
}

func TestScanLimitsTotalBytesAndEntries(t *testing.T) {
	value := "VAR=" + strings.Repeat("x", MaxFileBytes)
	r := Scan(context.Background(), "", nil, strings.Split(strings.Repeat(value+"\n", MaxScanBytes/MaxFileBytes+1), "\n"))
	if r.Complete || r.BytesScanned > MaxScanBytes {
		t.Fatalf("total limit failed: %+v", r)
	}
	env := make([]string, MaxScanEntries+1)
	for i := range env {
		env[i] = "VAR="
	}
	r = Scan(context.Background(), "", nil, env)
	if r.Complete || r.EnvScanned != MaxScanEntries {
		t.Fatalf("entry limit failed: %+v", r)
	}
}

func TestScanEmptyFileIsCleanAndDuplicatePathsAreNotRepeated(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "empty"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	r := Scan(context.Background(), root, []string{".", "empty"}, nil)
	if !r.Safe() || r.FilesScanned != 1 {
		t.Fatalf("unexpected report: %+v", r)
	}
}

func TestScanRedactsRecognizedCredentialsInMetadata(t *testing.T) {
	root := t.TempDir()
	value := syntheticToken()
	name := value + "," + value
	if err := os.WriteFile(filepath.Join(root, name), []byte(value), 0600); err != nil {
		t.Fatal(err)
	}
	r := Scan(context.Background(), root, []string{name, name + "-missing"}, []string{value + "=" + value})
	raw, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), value) {
		t.Fatal("metadata exposed a recognized credential")
	}
	if len(r.Findings) != 2 || len(r.Issues) != 1 {
		t.Fatalf("unexpected report: %+v", r)
	}
}
