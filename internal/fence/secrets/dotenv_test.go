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
