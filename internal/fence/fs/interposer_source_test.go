package fs

import (
	"os"
	"strings"
	"testing"
)

func TestInterposerSourceCoversStatFamily(t *testing.T) {
	source, err := os.ReadFile("interposer/libfence_fs.c")
	if err != nil {
		t.Fatalf("read interposer source: %v", err)
	}
	text := string(source)

	for _, snippet := range []string{
		"typedef int    (*real_fstat_t)(int, struct stat *);",
		"static real_fstat_t",
		"real_fstat",
		"int fstat(int fd, struct stat *buf)",
		"resolve_fd_path(fd, resolved)",
		"typedef int    (*real_stat64_t)(const char *, struct stat64 *);",
		"int stat64(const char *pathname, struct stat64 *buf)",
		"int lstat64(const char *pathname, struct stat64 *buf)",
		"int fstat64(int fd, struct stat64 *buf)",
	} {
		if !strings.Contains(text, snippet) {
			t.Fatalf("libfence_fs.c missing stat-family coverage snippet %q", snippet)
		}
	}
}
