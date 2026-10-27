package linuxinstall

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
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

func TestRejectUnsafeReleaseMembers(t *testing.T) {
	for _, c := range []string{"traversal", "absolute", "symlink", "hardlink", "device", "mode", "owner", "hash", "platform", "protocol"} {
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
			if _, err := Validate(a, m, "v1.2.3"); err == nil {
				t.Fatal("unsafe archive accepted")
			}
		})
	}
}
