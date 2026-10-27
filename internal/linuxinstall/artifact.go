// Package linuxinstall installs authenticated, immutable Linux release pairs.
package linuxinstall

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
)

const maxArchive = 128 << 20

var tagPattern = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
var commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
var payloadModes = map[string]int64{
	"nocklock": 0o755, "libfence_fs.so": 0o755,
	"INSTALL.md": 0o644, "LICENSE": 0o644, "build-info.json": 0o644,
}

// BuildInfo binds the release pair to one tag, source commit and platform.
type BuildInfo struct {
	Schema       int               `json:"schema"`
	Kind         string            `json:"kind"`
	Tag          string            `json:"tag"`
	Version      string            `json:"version"`
	Commit       string            `json:"commit"`
	OS           string            `json:"os"`
	Arch         string            `json:"arch"`
	Distribution string            `json:"distribution"`
	Libc         string            `json:"libc_baseline"`
	Files        map[string]string `json:"files"`
	Lifecycle    int               `json:"install_protocol"`
}

// ArchiveName validates a stable tag and returns its exact release asset name.
func ArchiveName(tag string) (string, error) {
	if !tagPattern.MatchString(tag) {
		return "", fmt.Errorf("expected stable release tag vX.Y.Z, got %q", tag)
	}
	return "nocklock_" + tag + "_linux_amd64.tar.gz", nil
}

func hash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }

// Validate checks the signed manifest, bounded tar members and paired provenance.
// It returns bytes, never extracts an archive-supplied path or executes payloads.
func Validate(archive, manifest []byte, tag string) (map[string][]byte, error) {
	name, err := ArchiveName(tag)
	if err != nil {
		return nil, err
	}
	if len(archive) > maxArchive || string(manifest) != hash(archive)+"  "+name+"\n" {
		return nil, fmt.Errorf("archive exceeds limit or does not match the single signed manifest entry")
	}
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	root := "nocklock-" + tag + "-linux-amd64"
	files := map[string][]byte{}
	seen := map[string]bool{}
	var total int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if seen[h.Name] {
			return nil, fmt.Errorf("duplicate archive member %q", h.Name)
		}
		seen[h.Name] = true
		if h.Uid != 0 || h.Gid != 0 || len(h.PAXRecords) != 0 || h.Linkname != "" {
			return nil, fmt.Errorf("unexpected ownership, extension or link in %q", h.Name)
		}
		if h.Name == root && h.Typeflag == tar.TypeDir && h.Mode == 0o755 {
			continue
		}
		var file string
		for n, mode := range payloadModes {
			if h.Name == root+"/"+n && h.Mode == mode && h.Typeflag == tar.TypeReg {
				file = n
				break
			}
		}
		if file == "" || h.Size < 0 || h.Size > maxArchive-total {
			return nil, fmt.Errorf("unexpected path, type, mode or size: %q", h.Name)
		}
		total += h.Size
		data, err := io.ReadAll(io.LimitReader(tr, h.Size+1))
		if err != nil || int64(len(data)) != h.Size {
			return nil, fmt.Errorf("truncated archive member %q", h.Name)
		}
		files[file] = data
	}
	if len(files) != len(payloadModes) || !seen[root] {
		return nil, fmt.Errorf("release archive is missing required files")
	}
	// Consume the bounded remainder to authenticate the gzip checksum as well.
	rest, err := io.ReadAll(io.LimitReader(gz, 1<<20))
	if err != nil || len(rest) == 1<<20 || len(bytes.Trim(rest, "\x00")) != 0 {
		return nil, fmt.Errorf("invalid trailing archive data")
	}
	var info BuildInfo
	if err := json.Unmarshal(files["build-info.json"], &info); err != nil {
		return nil, err
	}
	if info.Schema != 1 || info.Kind != "release" || info.Tag != tag || info.Version != tag[1:] ||
		!commitPattern.MatchString(info.Commit) || info.OS != "linux" || info.Arch != "amd64" ||
		info.Distribution != "ubuntu-24.04" || info.Libc != "glibc-2.39" || info.Lifecycle != 1 || len(info.Files) != len(payloadModes)-1 {
		return nil, fmt.Errorf("build-info does not describe the selected Linux release and install protocol")
	}
	for n, data := range files {
		if n != "build-info.json" && info.Files[n] != hash(data) {
			return nil, fmt.Errorf("payload hash mismatch: %s", n)
		}
	}
	for _, n := range []string{"nocklock", "libfence_fs.so"} {
		d := files[n]
		if len(d) < 64 || !bytes.Equal(d[:7], []byte{0x7f, 'E', 'L', 'F', 2, 1, 1}) ||
			(d[16] != 2 && d[16] != 3) || d[17] != 0 || d[18] != 62 || d[19] != 0 {
			return nil, fmt.Errorf("%s is not an amd64 ELF64 executable/library", n)
		}
	}
	return files, nil
}
