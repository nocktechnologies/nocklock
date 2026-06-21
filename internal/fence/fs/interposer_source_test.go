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

func TestInterposerSourceCoversMetadataMutatorFamily(t *testing.T) {
	source, err := os.ReadFile("interposer/libfence_fs.c")
	if err != nil {
		t.Fatalf("read interposer source: %v", err)
	}
	text := string(source)

	for _, pattern := range []string{
		`typedef\s+int\s+\(\*real_fchmod_t\)\s*\(\s*int\s*,\s*mode_t\s*\)\s*;`,
		`typedef\s+int\s+\(\*real_fchmodat_t\)\s*\(\s*int\s*,\s*const\s+char\s*\*\s*,\s*mode_t\s*,\s*int\s*\)\s*;`,
		`typedef\s+int\s+\(\*real_fchown_t\)\s*\(\s*int\s*,\s*uid_t\s*,\s*gid_t\s*\)\s*;`,
		`typedef\s+int\s+\(\*real_fchownat_t\)\s*\(\s*int\s*,\s*const\s+char\s*\*\s*,\s*uid_t\s*,\s*gid_t\s*,\s*int\s*\)\s*;`,
		`typedef\s+int\s+\(\*real_futimens_t\)\s*\(\s*int\s*,\s*const\s+struct\s+timespec\s+\*\s*\)\s*;`,
		`typedef\s+int\s+\(\*real_utimensat_t\)\s*\(\s*int\s*,\s*const\s+char\s*\*\s*,\s*const\s+struct\s+timespec\s+\*\s*,\s*int\s*\)\s*;`,
		`static\s+real_fchmod_t\s+real_fchmod\s*;`,
		`static\s+real_fchmodat_t\s+real_fchmodat\s*;`,
		`static\s+real_fchown_t\s+real_fchown\s*;`,
		`static\s+real_fchownat_t\s+real_fchownat\s*;`,
		`static\s+real_futimens_t\s+real_futimens\s*;`,
		`static\s+real_utimensat_t\s+real_utimensat\s*;`,
		`real_fchmod\s*=\s*\(real_fchmod_t\)dlsym\s*\(\s*RTLD_NEXT\s*,\s*"fchmod"\s*\)\s*;`,
		`real_fchmodat\s*=\s*\(real_fchmodat_t\)dlsym\s*\(\s*RTLD_NEXT\s*,\s*"fchmodat"\s*\)\s*;`,
		`real_fchown\s*=\s*\(real_fchown_t\)dlsym\s*\(\s*RTLD_NEXT\s*,\s*"fchown"\s*\)\s*;`,
		`real_fchownat\s*=\s*\(real_fchownat_t\)dlsym\s*\(\s*RTLD_NEXT\s*,\s*"fchownat"\s*\)\s*;`,
		`real_futimens\s*=\s*\(real_futimens_t\)dlsym\s*\(\s*RTLD_NEXT\s*,\s*"futimens"\s*\)\s*;`,
		`real_utimensat\s*=\s*\(real_utimensat_t\)dlsym\s*\(\s*RTLD_NEXT\s*,\s*"utimensat"\s*\)\s*;`,
		`int\s+fchmod\s*\(\s*int\s+fd\s*,\s*mode_t\s+mode\s*\)`,
		`int\s+fchmodat\s*\(\s*int\s+dirfd\s*,\s*const\s+char\s*\*\s*pathname\s*,\s*mode_t\s+mode\s*,\s*int\s+flags\s*\)`,
		`int\s+fchown\s*\(\s*int\s+fd\s*,\s*uid_t\s+owner\s*,\s*gid_t\s+group\s*\)`,
		`int\s+fchownat\s*\(\s*int\s+dirfd\s*,\s*const\s+char\s*\*\s*pathname\s*,\s*uid_t\s+owner\s*,\s*gid_t\s+group\s*,\s*int\s+flags\s*\)`,
		`int\s+futimens\s*\(\s*int\s+fd\s*,\s*const\s+struct\s+timespec\s+times\s*\[\s*2\s*\]\s*\)`,
		`int\s+utimensat\s*\(\s*int\s+dirfd\s*,\s*const\s+char\s*\*\s*pathname\s*,\s*const\s+struct\s+timespec\s+times\s*\[\s*2\s*\]\s*,\s*int\s+flags\s*\)`,
		`(?s)int\s+fchmod\s*\(.*?resolve_fd_path\s*\(\s*fd\s*,\s*resolved\s*\).*?check_path\s*\(\s*resolved\s*,\s*1\s*/\*\s*always write\s*\*/`,
		`(?s)int\s+fchown\s*\(.*?resolve_fd_path\s*\(\s*fd\s*,\s*resolved\s*\).*?check_path\s*\(\s*resolved\s*,\s*1\s*/\*\s*always write\s*\*/`,
		`(?s)int\s+futimens\s*\(.*?resolve_fd_path\s*\(\s*fd\s*,\s*resolved\s*\).*?check_path\s*\(\s*resolved\s*,\s*1\s*/\*\s*always write\s*\*/`,
		`(?s)int\s+fchmodat\s*\(.*?resolve_openat_path\s*\(\s*dirfd\s*,\s*pathname\s*,\s*resolved\s*\).*?check_path\s*\(\s*resolved\s*,\s*1\s*/\*\s*always write\s*\*/`,
		`(?s)int\s+fchownat\s*\(.*?resolve_openat_lstat_path\s*\(\s*dirfd\s*,\s*pathname\s*,\s*resolved\s*\).*?check_path\s*\(\s*resolved\s*,\s*1\s*/\*\s*always write\s*\*/`,
		`(?s)int\s+utimensat\s*\(.*?resolve_openat_lstat_path\s*\(\s*dirfd\s*,\s*pathname\s*,\s*resolved\s*\).*?check_path\s*\(\s*resolved\s*,\s*1\s*/\*\s*always write\s*\*/`,
	} {
		if !regexp.MustCompile(pattern).MatchString(text) {
			t.Fatalf("libfence_fs.c missing metadata-mutator coverage pattern %q", pattern)
		}
	}
}

func TestInterposerSourceHandlesMetadataMutatorReviewRegressions(t *testing.T) {
	source, err := os.ReadFile("interposer/libfence_fs.c")
	if err != nil {
		t.Fatalf("read interposer source: %v", err)
	}
	text := string(source)

	for _, pattern := range []string{
		`(?s)int\s+fchmod\s*\(.*?resolve_fd_path\s*\(\s*fd\s*,\s*resolved\s*\)\s*!=\s*0.*?fcntl\s*\(\s*fd\s*,\s*F_GETFD\s*\)\s*==\s*-1\s*&&\s*errno\s*==\s*EBADF`,
		`(?s)int\s+fchown\s*\(.*?resolve_fd_path\s*\(\s*fd\s*,\s*resolved\s*\)\s*!=\s*0.*?fcntl\s*\(\s*fd\s*,\s*F_GETFD\s*\)\s*==\s*-1\s*&&\s*errno\s*==\s*EBADF`,
		`(?s)int\s+futimens\s*\(.*?resolve_fd_path\s*\(\s*fd\s*,\s*resolved\s*\)\s*!=\s*0.*?fcntl\s*\(\s*fd\s*,\s*F_GETFD\s*\)\s*==\s*-1\s*&&\s*errno\s*==\s*EBADF`,
		`(?s)int\s+fchmodat\s*\(.*?if\s*\(\s*is_null_pathname\s*\(\s*pathname\s*\)\s*\).*?return\s+real_fchmodat\s*\(\s*dirfd\s*,\s*pathname\s*,\s*mode\s*,\s*flags\s*\)`,
		`(?s)int\s+fchownat\s*\(.*?if\s*\(\s*is_null_pathname\s*\(\s*pathname\s*\)\s*\).*?return\s+real_fchownat\s*\(\s*dirfd\s*,\s*pathname\s*,\s*owner\s*,\s*group\s*,\s*flags\s*\)`,
		`(?s)int\s+utimensat\s*\(.*?if\s*\(\s*is_null_pathname\s*\(\s*pathname\s*\)\s*\).*?return\s+real_utimensat\s*\(\s*dirfd\s*,\s*pathname\s*,\s*times\s*,\s*flags\s*\)`,
		`(?s)int\s+fchmodat\s*\(.*?resolve_fd_path\s*\(\s*dirfd\s*,\s*resolved\s*\)\s*!=\s*0.*?fcntl\s*\(\s*dirfd\s*,\s*F_GETFD\s*\)\s*==\s*-1\s*&&\s*errno\s*==\s*EBADF`,
		`(?s)int\s+fchownat\s*\(.*?resolve_fd_path\s*\(\s*dirfd\s*,\s*resolved\s*\)\s*!=\s*0.*?fcntl\s*\(\s*dirfd\s*,\s*F_GETFD\s*\)\s*==\s*-1\s*&&\s*errno\s*==\s*EBADF`,
		`(?s)int\s+utimensat\s*\(.*?resolve_fd_path\s*\(\s*dirfd\s*,\s*resolved\s*\)\s*!=\s*0.*?fcntl\s*\(\s*dirfd\s*,\s*F_GETFD\s*\)\s*==\s*-1\s*&&\s*errno\s*==\s*EBADF`,
		`(?s)int\s+fchmodat\s*\(.*?if\s*\(\s*pathname\[0\]\s*==\s*'\\0'\s*&&\s*\(\s*flags\s*&\s*AT_EMPTY_PATH\s*\)\s*\)\s*return\s+real_fchmodat\s*\(\s*dirfd\s*,\s*pathname\s*,\s*mode\s*,\s*flags\s*\)\s*;`,
		`(?s)int\s+fchownat\s*\(.*?if\s*\(\s*pathname\[0\]\s*==\s*'\\0'\s*&&\s*\(\s*flags\s*&\s*AT_EMPTY_PATH\s*\)\s*\)\s*return\s+real_fchownat\s*\(\s*dirfd\s*,\s*pathname\s*,\s*owner\s*,\s*group\s*,\s*flags\s*\)\s*;`,
		`(?s)int\s+utimensat\s*\(.*?if\s*\(\s*pathname\[0\]\s*==\s*'\\0'\s*&&\s*\(\s*flags\s*&\s*AT_EMPTY_PATH\s*\)\s*\)\s*return\s+real_utimensat\s*\(\s*dirfd\s*,\s*pathname\s*,\s*times\s*,\s*flags\s*\)\s*;`,
	} {
		if !regexp.MustCompile(pattern).MatchString(text) {
			t.Fatalf("libfence_fs.c missing metadata-mutator review regression pattern %q", pattern)
		}
	}
}

func TestInterposerSourceHandlesStatAtNullAndATEmptyPathReporting(t *testing.T) {
	source, err := os.ReadFile("interposer/libfence_fs.c")
	if err != nil {
		t.Fatalf("read interposer source: %v", err)
	}
	text := string(source)

	for _, pattern := range []string{
		`(?s)int\s+fstatat\s*\(.*?if\s*\(\s*is_null_pathname\s*\(\s*pathname\s*\)\s*\).*?return\s+real_fstatat\s*\(\s*dirfd\s*,\s*pathname\s*,\s*buf\s*,\s*flags\s*\)`,
		`(?s)int\s+__fxstatat\s*\(.*?if\s*\(\s*is_null_pathname\s*\(\s*pathname\s*\)\s*\).*?return\s+real___fxstatat\s*\(\s*vers\s*,\s*dirfd\s*,\s*pathname\s*,\s*buf\s*,\s*flags\s*\)`,
		`(?s)int\s+statx\s*\(.*?if\s*\(\s*is_null_pathname\s*\(\s*pathname\s*\)\s*\).*?return\s+real_statx\s*\(\s*dirfd\s*,\s*pathname\s*,\s*flags\s*,\s*mask\s*,\s*statxbuf\s*\)`,
		`(?s)int\s+__fxstatat\s*\(.*?report_blocked\s*\(\s*\(\s*pathname\[0\]\s*==\s*'\\0'\s*&&\s*\(\s*flags\s*&\s*AT_EMPTY_PATH\s*\)\s*\)\s*\?\s*"\(fd\)"\s*:\s*pathname\s*,\s*"__fxstatat"`,
	} {
		if !regexp.MustCompile(pattern).MatchString(text) {
			t.Fatalf("libfence_fs.c missing stat-at review regression pattern %q", pattern)
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

// TestInterposerSourceUsesResolvedPathForWriteFamily guards the #32 TOCTOU fix.
// Every write/mutate hook must hand the real syscall the canonical *resolved*
// path that check_path() authorized — never the caller's original pathname — so
// a symlink swap between the check and the real call cannot redirect the
// operation outside the fence. If any hook regresses to passing the original
// pathname, the matching `resolved` pattern below stops matching and this fails.
func TestInterposerSourceUsesResolvedPathForWriteFamily(t *testing.T) {
	source, err := os.ReadFile("interposer/libfence_fs.c")
	if err != nil {
		t.Fatalf("read interposer source: %v", err)
	}
	text := string(source)

	for _, pattern := range []string{
		`return\s+real_open\s*\(\s*resolved\s*,\s*flags\s*,\s*mode\s*\)\s*;`,
		`return\s+real_openat\s*\(\s*dirfd\s*,\s*resolved\s*,\s*flags\s*,\s*mode\s*\)\s*;`,
		`return\s+real_fopen\s*\(\s*resolved\s*,\s*mode\s*\)\s*;`,
		`return\s+real_unlink\s*\(\s*resolved\s*\)\s*;`,
		`return\s+real_rename\s*\(\s*resolved_old\s*,\s*resolved_new\s*\)\s*;`,
		`return\s+real_mkdir\s*\(\s*resolved\s*,\s*mode\s*\)\s*;`,
		`return\s+real_rmdir\s*\(\s*resolved\s*\)\s*;`,
		`return\s+real_open64\s*\(\s*resolved\s*,\s*flags\s*,\s*mode\s*\)\s*;`,
		`return\s+real_openat64\s*\(\s*dirfd\s*,\s*resolved\s*,\s*flags\s*,\s*mode\s*\)\s*;`,
		`return\s+real_fopen64\s*\(\s*resolved\s*,\s*mode\s*\)\s*;`,
		`return\s+real_unlinkat\s*\(\s*dirfd\s*,\s*resolved\s*,\s*flags\s*\)\s*;`,
		`return\s+real_renameat\s*\(\s*olddirfd\s*,\s*resolved_old\s*,\s*newdirfd\s*,\s*resolved_new\s*\)\s*;`,
		`return\s+real_renameat2\s*\(\s*olddirfd\s*,\s*resolved_old\s*,\s*newdirfd\s*,\s*resolved_new\s*,\s*flags\s*\)\s*;`,
		`return\s+real_mkdirat\s*\(\s*dirfd\s*,\s*resolved\s*,\s*mode\s*\)\s*;`,
		// symlinkat: target is the link's CONTENTS (passed through unchanged); the
		// linkpath being created is the resolved one.
		`return\s+real_symlinkat\s*\(\s*target\s*,\s*newdirfd\s*,\s*resolved\s*\)\s*;`,
		`return\s+real_linkat\s*\(\s*olddirfd\s*,\s*resolved_old\s*,\s*newdirfd\s*,\s*resolved_new\s*,\s*flags\s*\)\s*;`,
	} {
		if !regexp.MustCompile(pattern).MatchString(text) {
			t.Fatalf("libfence_fs.c missing TOCTOU-safe resolved-path call (regression of #32?): %q", pattern)
		}
	}
}
