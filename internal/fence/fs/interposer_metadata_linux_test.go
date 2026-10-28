//go:build linux

package fs

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestInterposerProjectAncestorMetadata(t *testing.T) {
	h := newAckHarness(t, time.Duration(0))
	parent := filepath.Join(h.dir, "parent")
	root := filepath.Join(parent, "project")
	sibling := filepath.Join(parent, "sibling")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{filepath.Join(root, "allowed"), sibling} {
		if err := os.WriteFile(p, []byte("control"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	source := `
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "line=%d errno=%d\n", __LINE__, errno); return 1; } } while (0)
int main(int argc, char **argv) {
 REQUIRE(argc == 5);
 struct stat st;
 struct stat64 st64;
 struct statx sx;
 if (argv[4][0] == 'd') {
  REQUIRE(stat(argv[1], &st) == -1 && errno == ENOENT);
  REQUIRE(lstat(argv[1], &st) == -1 && errno == ENOENT);
  return 0;
 }
 REQUIRE(stat(argv[1], &st) == 0 && S_ISDIR(st.st_mode));
 REQUIRE(lstat(argv[1], &st) == 0 && S_ISDIR(st.st_mode));
 REQUIRE(fstatat(AT_FDCWD, argv[1], &st, 0) == 0);
 REQUIRE(stat64(argv[1], &st64) == 0);
 REQUIRE(lstat64(argv[1], &st64) == 0);
 REQUIRE(statx(AT_FDCWD, argv[1], 0, STATX_TYPE, &sx) == 0);
 int fd = (int)syscall(SYS_openat, AT_FDCWD, argv[1], O_PATH | O_DIRECTORY);
 REQUIRE(fd >= 0);
 REQUIRE(fstat(fd, &st) == 0);
 REQUIRE(fstat64(fd, &st64) == 0);
 close(fd);
 REQUIRE(open(argv[1], O_RDONLY | O_DIRECTORY) == -1 && errno == EACCES);
 REQUIRE(stat(argv[2], &st) == -1 && errno == ENOENT);
 REQUIRE(lstat(argv[2], &st) == -1 && errno == ENOENT);
 REQUIRE(open(argv[2], O_RDONLY) == -1 && errno == EACCES);
 fd = open(argv[3], O_RDONLY);
 REQUIRE(fd >= 0);
 close(fd);
 return 0;
}
`
	src := filepath.Join(h.dir, "metadata.c")
	bin := filepath.Join(h.dir, "metadata")
	if err := os.WriteFile(src, []byte(source), 0600); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command("gcc", "-Wall", "-Wextra", "-Werror", "-o", bin, src).CombinedOutput(); err != nil {
		t.Fatalf("build probe: %v\n%s", err, out)
	}
	for _, denied := range []bool{false, true} {
		name := "ancestor-only"
		mode := "allowed"
		cfg := &FenceConfig{Root: root, Mode: "read-write"}
		if denied {
			name, mode = "explicit-deny-wins", "denied"
			cfg.DenyPaths = []string{parent}
		}
		t.Run(name, func(t *testing.T) {
			cmd := exec.Command(bin, parent, sibling, filepath.Join(root, "allowed"), mode)
			cmd.Env = append(os.Environ(), EnvLDPreload+"="+h.so, EnvFSAllowed+"="+cfg.Serialize(h.sock))
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("metadata boundary: %v\n%s", err, out)
			}
		})
	}
}
