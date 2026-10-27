package linuxinstall

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixture(t *testing.T, tag string, mutate func(*tar.Header, *[]byte)) ([]byte, []byte) {
	t.Helper()
	elf := make([]byte, 64)
	copy(elf, []byte{0x7f, 'E', 'L', 'F', 2, 1, 1})
	elf[16], elf[18] = 3, 62
	files := map[string][]byte{"nocklock": elf, "libfence_fs.so": elf, "INSTALL.md": []byte("instructions"), "LICENSE": []byte("license")}
	info := BuildInfo{Schema: 1, Kind: "release", Tag: tag, Version: tag[1:], Commit: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", OS: "linux", Arch: "amd64", Distribution: "ubuntu-24.04", Libc: "glibc-2.39", Lifecycle: 1, Files: map[string]string{}}
	for n, d := range files {
		info.Files[n] = hash(d)
	}
	files["build-info.json"], _ = json.Marshal(info)
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	root := "nocklock-" + tag + "-linux-amd64"
	directory := &tar.Header{Name: root, Typeflag: tar.TypeDir, Mode: 0o755}
	if mutate != nil {
		empty := []byte{}
		mutate(directory, &empty)
	}
	if err := tw.WriteHeader(directory); err != nil {
		t.Fatal(err)
	}
	for n, d := range files {
		h := &tar.Header{Name: root + "/" + n, Typeflag: tar.TypeReg, Mode: payloadModes[n], Size: int64(len(d))}
		if mutate != nil {
			mutate(h, &d)
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			if _, err := tw.Write(d); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	name, _ := ArchiveName(tag)
	return buf.Bytes(), []byte(hash(buf.Bytes()) + "  " + name + "\n")
}

func TestValidateRelease(t *testing.T) {
	a, m := fixture(t, "v1.2.3", nil)
	f, err := Validate(a, m, "v1.2.3")
	if err != nil || len(f) != 5 {
		t.Fatalf("valid: %v", err)
	}
	for _, tag := range []string{"../escape", "v01.2.3", "v1.2.3-rc1", "v1.2.4"} {
		if _, err := Validate(a, m, tag); err == nil {
			t.Fatalf("accepted %s", tag)
		}
	}
	if _, err := Validate(append(a, 1), m, "v1.2.3"); err == nil {
		t.Fatal("changed archive accepted")
	}
	if _, err := Validate(a, append(m, m...), "v1.2.3"); err == nil {
		t.Fatal("duplicate manifest accepted")
	}
}

func TestPOSIXDirectoryHeader(t *testing.T) {
	a, m := fixture(t, "v1.2.3", func(h *tar.Header, _ *[]byte) {
		if h.Typeflag == tar.TypeDir {
			h.Name += "/"
		}
	})
	if _, err := Validate(a, m, "v1.2.3"); err != nil {
		t.Fatal("native builder directory header refused", err)
	}
}

// The tagged native builder runs this against its real Python-produced archive,
// before signing. Ordinary package tests use the bounded synthetic fixtures.
func TestBuiltReleaseArchive(t *testing.T) {
	dir := os.Getenv("NOCKLOCK_TEST_RELEASE_DIR")
	if dir == "" {
		t.Skip("native tagged builder supplies its output directory")
	}
	tag := os.Getenv("NOCKLOCK_TEST_RELEASE_TAG")
	name, err := ArchiveName(tag)
	if err != nil {
		t.Fatal(err)
	}
	archive, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Validate(archive, manifest, tag); err != nil {
		t.Fatal(err)
	}
}

func TestRejectUnsafeReleaseMembers(t *testing.T) {
	for c, want := range map[string]string{
		"traversal": "unexpected path, type, mode or size",
		"absolute":  "unexpected path, type, mode or size",
		"symlink":   "unexpected ownership, extension or link",
		"hardlink":  "unexpected ownership, extension or link",
		"device":    "unexpected path, type, mode or size",
		"mode":      "unexpected path, type, mode or size",
		"owner":     "unexpected ownership, extension or link",
		"hash":      "payload hash mismatch: nocklock",
		"platform":  "build-info does not describe",
		"protocol":  "build-info does not describe",
	} {
		t.Run(c, func(t *testing.T) {
			a, m := fixture(t, "v1.2.3", func(h *tar.Header, d *[]byte) {
				if c == "platform" || c == "protocol" {
					if h.Name == "nocklock-v1.2.3-linux-amd64/build-info.json" {
						var info BuildInfo
						json.Unmarshal(*d, &info)
						if c == "platform" {
							info.Arch = "arm64"
						} else {
							info.Lifecycle = 0
						}
						*d, _ = json.Marshal(info)
						h.Size = int64(len(*d))
					}
					return
				}
				if h.Name != "nocklock-v1.2.3-linux-amd64/nocklock" {
					return
				}
				switch c {
				case "traversal":
					h.Name = "nocklock-v1.2.3-linux-amd64/../escape"
				case "absolute":
					h.Name = "/escape"
				case "symlink":
					h.Typeflag = tar.TypeSymlink
					h.Linkname = "/escape"
					h.Size = 0
				case "hardlink":
					h.Typeflag = tar.TypeLink
					h.Linkname = "/escape"
					h.Size = 0
				case "device":
					h.Typeflag = tar.TypeChar
					h.Size = 0
				case "mode":
					h.Mode = 0o777
				case "owner":
					h.Uid = 1000
				case "hash":
					*d = append([]byte(nil), (*d)...)
					(*d)[10] = 99
				}
			})
			if _, err := Validate(a, m, "v1.2.3"); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("unsafe archive: got %v, want refusal containing %q", err, want)
			}
		})
	}
}
