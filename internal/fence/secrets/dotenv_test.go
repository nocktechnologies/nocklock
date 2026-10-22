package secrets

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScanDotEnvOnlyReportsMetadata(t *testing.T) {
	root := t.TempDir()
	nested := filepath.Join(root, "nested")
	if err := os.Mkdir(nested, 0700); err != nil {
		t.Fatal(err)
	}
	canary := "fake-canary-only-12345"
	for name, body := range map[string]string{".env": "API_TOKEN=" + canary, "nested/.env.local": "PASSWORD=" + canary, "ordinary.txt": "PASSWORD=" + canary} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
	}
	r := ScanDotEnv(context.Background(), root)
	if !r.Complete || len(r.Findings) != 2 || r.FilesScanned != 2 {
		t.Fatalf("unexpected report %+v", r)
	}
	out, _ := json.Marshal(r)
	if strings.Contains(string(out), canary) {
		t.Fatal("value leaked into report")
	}
}

func TestScanDotEnvSafeControlAndSymlink(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".env"), []byte("PORT=3000\nAPI_KEY=\nTOKEN=${DEV_TOKEN}\n# PASSWORD=example\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if r := ScanDotEnv(context.Background(), root); !r.Safe() {
		t.Fatalf("safe control %+v", r)
	}
	outside := filepath.Join(t.TempDir(), "fake")
	if err := os.WriteFile(outside, []byte("TOKEN=fake"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, ".env.link")); err != nil {
		t.Fatal(err)
	}
	if r := ScanDotEnv(context.Background(), root); r.Complete {
		t.Fatal("symlink .env must report incomplete without following it")
	}
}

func TestScanDotEnvShallowScopeExcludesDependencyAndBuildDirectories(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{
		".git/.env", "node_modules/.env", "vendor/.env", ".venv/.env",
		"build/.env", "dist/.env", "target/.env", ".next/.env",
		"app/deeper/.env", ".environment", "app/.envrc",
	} {
		full := filepath.Join(root, path)
		if err := os.MkdirAll(filepath.Dir(full), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte("TOKEN=fake-outside-scope"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if report := ScanDotEnv(context.Background(), root); !report.Safe() || report.FilesScanned != 0 {
		t.Fatalf("out-of-scope files were inspected: %+v", report)
	}
	if err := os.WriteFile(filepath.Join(root, "app", ".env.local"), []byte("TOKEN=fake-in-scope"), 0600); err != nil {
		t.Fatal(err)
	}
	if report := ScanDotEnv(context.Background(), root); !report.Complete || len(report.Findings) != 1 || report.FilesScanned != 1 {
		t.Fatalf("immediate child dotenv was not inspected: %+v", report)
	}
}

func TestScanDotEnvCancellationReportsIncomplete(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if report := ScanDotEnv(ctx, t.TempDir()); report.Complete || len(report.Findings) != 0 {
		t.Fatalf("cancelled inspection must be incomplete without inventing findings: %+v", report)
	}
}
