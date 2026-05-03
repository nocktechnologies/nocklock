package fs

import (
	"os"
	"regexp"
	"testing"
)

func TestInterposerSourceCoversStatFamily(t *testing.T) {
	source, err := os.ReadFile("interposer/libfence_fs.c")
	if err != nil {
		t.Fatalf("read interposer source: %v", err)
	}
	text := string(source)

	for _, pattern := range []string{
		`typedef\s+int\s+\(\*real_fstat_t\)\s*\(\s*int\s*,\s*struct\s+stat\s*\*\s*\)\s*;`,
		`static\s+real_fstat_t\s+real_fstat\s*;`,
		`int\s+fstat\s*\(\s*int\s+fd\s*,\s*struct\s+stat\s*\*\s*buf\s*\)`,
		`resolve_fd_path\s*\(\s*fd\s*,\s*resolved\s*\)`,
		`typedef\s+int\s+\(\*real_stat64_t\)\s*\(\s*const\s+char\s*\*\s*,\s*struct\s+stat64\s*\*\s*\)\s*;`,
		`int\s+stat64\s*\(\s*const\s+char\s*\*\s*pathname\s*,\s*struct\s+stat64\s*\*\s*buf\s*\)`,
		`int\s+lstat64\s*\(\s*const\s+char\s*\*\s*pathname\s*,\s*struct\s+stat64\s*\*\s*buf\s*\)`,
		`int\s+fstat64\s*\(\s*int\s+fd\s*,\s*struct\s+stat64\s*\*\s*buf\s*\)`,
	} {
		if !regexp.MustCompile(pattern).MatchString(text) {
			t.Fatalf("libfence_fs.c missing stat-family coverage pattern %q", pattern)
		}
	}
}

func TestInterposerSourceAvoidsUnsafeStat64FallbackCasts(t *testing.T) {
	source, err := os.ReadFile("interposer/libfence_fs.c")
	if err != nil {
		t.Fatalf("read interposer source: %v", err)
	}

	unsafeFallback := regexp.MustCompile(`real_(stat|lstat|fstat)\s*\([^;]*\(\s*struct\s+stat\s*\*\s*\)\s*buf`)
	if match := unsafeFallback.FindString(string(source)); match != "" {
		t.Fatalf("libfence_fs.c has unsafe stat64 fallback cast %q", match)
	}
}

func TestInterposerSourceBypassesNonPathFileDescriptors(t *testing.T) {
	source, err := os.ReadFile("interposer/libfence_fs.c")
	if err != nil {
		t.Fatalf("read interposer source: %v", err)
	}
	text := string(source)

	for _, pattern := range []string{
		`static\s+int\s+fd_target_is_path\s*\(\s*const\s+char\s*\*\s*resolved\s*\)`,
		`if\s*\(\s*!\s*fd_target_is_path\s*\(\s*resolved\s*\)\s*\)`,
		`if\s*\(\s*real_fstat\s*\)\s*return\s+real_fstat\s*\(\s*fd\s*,\s*buf\s*\)\s*;`,
		`if\s*\(\s*real_fstat64\s*\)\s*return\s+real_fstat64\s*\(\s*fd\s*,\s*buf\s*\)\s*;`,
	} {
		if !regexp.MustCompile(pattern).MatchString(text) {
			t.Fatalf("libfence_fs.c missing non-path fd bypass pattern %q", pattern)
		}
	}
}

func TestInterposerSourceTreatsProcFSMagicTargetsAsNonPaths(t *testing.T) {
	source, err := os.ReadFile("interposer/libfence_fs.c")
	if err != nil {
		t.Fatalf("read interposer source: %v", err)
	}
	text := string(source)

	for _, pattern := range []string{
		`strncmp\s*\(\s*resolved\s*,\s*"socket:\["\s*,\s*8\s*\)`,
		`strncmp\s*\(\s*resolved\s*,\s*"pipe:\["\s*,\s*6\s*\)`,
		`strncmp\s*\(\s*resolved\s*,\s*"anon_inode:\["\s*,\s*12\s*\)`,
		`strncmp\s*\(\s*resolved\s*,\s*"/memfd:"\s*,\s*7\s*\)`,
	} {
		if !regexp.MustCompile(pattern).MatchString(text) {
			t.Fatalf("libfence_fs.c missing procfs magic fd target guard pattern %q", pattern)
		}
	}
}

func TestInterposerSourceBypassesATEmptyPathForNonPathFileDescriptors(t *testing.T) {
	source, err := os.ReadFile("interposer/libfence_fs.c")
	if err != nil {
		t.Fatalf("read interposer source: %v", err)
	}
	text := string(source)

	for _, pattern := range []string{
		`(?s)int\s+fstatat\s*\(.*?if\s*\(\s*!\s*fd_target_is_path\s*\(\s*resolved\s*\)\s*\)\s*\{.*?return\s+real_fstatat\s*\(\s*dirfd\s*,\s*pathname\s*,\s*buf\s*,\s*flags\s*\)\s*;`,
		`(?s)int\s+__fxstatat\s*\(.*?if\s*\(\s*!\s*fd_target_is_path\s*\(\s*resolved\s*\)\s*\)\s*\{.*?return\s+real___fxstatat\s*\(\s*vers\s*,\s*dirfd\s*,\s*pathname\s*,\s*buf\s*,\s*flags\s*\)\s*;`,
		`(?s)int\s+statx\s*\(.*?if\s*\(\s*!\s*fd_target_is_path\s*\(\s*resolved\s*\)\s*\)\s*\{.*?return\s+real_statx\s*\(\s*dirfd\s*,\s*pathname\s*,\s*flags\s*,\s*mask\s*,\s*statxbuf\s*\)\s*;`,
	} {
		if !regexp.MustCompile(pattern).MatchString(text) {
			t.Fatalf("libfence_fs.c missing AT_EMPTY_PATH non-path fd bypass pattern %q", pattern)
		}
	}
}
