package secrets

import (
	"bytes"
	"context"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	// MaxFileBytes bounds each file or environment value inspected by Scan.
	MaxFileBytes = 1 << 20
	// MaxScanBytes bounds all content inspected in one Scan call.
	MaxScanBytes = 32 << 20
	// MaxScanEntries bounds traversal and environment work in one Scan call.
	MaxScanEntries = 10000
	maxScanDepth   = 64
)

// Finding identifies a detected credential format without retaining its value.
type Finding struct {
	Rule     string `json:"rule"`
	Source   string `json:"source"`
	Location string `json:"location"`
	Line     int    `json:"line,omitempty"`
}

// ScanIssue identifies an input that could not be completely inspected.
type ScanIssue struct {
	Location string `json:"location"`
	Reason   string `json:"reason"`
}

// ScanReport contains only metadata, never matched bytes or source lines.
type ScanReport struct {
	Complete     bool        `json:"complete"`
	Findings     []Finding   `json:"findings"`
	Issues       []ScanIssue `json:"issues"`
	FilesScanned int         `json:"files_scanned"`
	EnvScanned   int         `json:"env_scanned"`
	BytesScanned int64       `json:"bytes_scanned"`
}

// Safe reports whether the selected inputs were completely scanned without findings.
// It does not establish that unrecognized secrets are absent or that files stay safe.
func (r ScanReport) Safe() bool { return r.Complete && len(r.Issues) == 0 && len(r.Findings) == 0 }

var scanDetectors = []struct {
	id string
	re *regexp.Regexp
}{
	{"aws-access-key-id", regexp.MustCompile(`(?:^|[^A-Za-z0-9])((?:AKIA|ASIA)[A-Z0-9]{16})(?:$|[^A-Za-z0-9])`)},
	{"github-token", regexp.MustCompile(`(?:^|[^A-Za-z0-9_])((?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}))(?:$|[^A-Za-z0-9_])`)},
	{"private-key", regexp.MustCompile(`(-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----)`)},
}

type scanner struct {
	ctx     context.Context
	report  ScanReport
	entries int
	stopped bool
	seen    map[string]bool
}

// Scan inspects relative paths beneath root and the supplied environment values.
// It never follows encountered symlinks, skips hidden/binary files, or uses ignore
// files. Unsupported or incomplete inputs make the report non-safe. This is a
// bounded preflight check, not a filesystem snapshot or a runtime security fence.
func Scan(ctx context.Context, root string, paths, environ []string) ScanReport {
	s := scanner{ctx: ctx, report: ScanReport{Complete: true, Findings: []Finding{}, Issues: []ScanIssue{}}, seen: make(map[string]bool)}
	for _, entry := range environ {
		if !s.next("environment") {
			break
		}
		name, value, ok := strings.Cut(entry, "=")
		if !ok || name == "" {
			s.issue("environment", "malformed entry; supply NAME=VALUE entries")
			continue
		}
		if !s.withinSize(name, int64(len(value))) {
			continue
		}
		s.inspect([]byte(value), "env", name)
		s.report.EnvScanned++
	}
	if len(paths) > 0 && !s.stopped {
		r, err := os.OpenRoot(root)
		if err != nil {
			s.issue(".", "cannot open scan root; check that it exists and is readable")
		} else {
			defer r.Close()
			for _, path := range paths {
				if !s.next("scan paths") {
					break
				}
				if !fs.ValidPath(filepath.ToSlash(path)) || filepath.IsAbs(path) {
					s.issue(path, "scan paths must be relative without '..' or empty components")
					continue
				}
				// Validate explicit parents too: selecting link/file must not bypass
				// the symlink rejection applied during ordinary tree traversal.
				parentOK := true
				for parent := filepath.Dir(path); parent != "."; parent = filepath.Dir(parent) {
					info, err := r.Lstat(parent)
					if err != nil || !info.IsDir() {
						s.issue(path, "parent is unreadable or not a real directory; choose a non-symlink path")
						parentOK = false
						break
					}
				}
				if parentOK {
					s.walk(r, path, 0)
				}
			}
		}
	}
	if s.ctx.Err() != nil && !s.stopped {
		s.issue("scan", "scan cancelled; rerun before launching")
	}
	sort.Slice(s.report.Findings, func(i, j int) bool {
		a, b := s.report.Findings[i], s.report.Findings[j]
		if a.Source != b.Source {
			return a.Source < b.Source
		}
		if a.Location != b.Location {
			return a.Location < b.Location
		}
		return a.Rule < b.Rule
	})
	return s.report
}

func (s *scanner) issue(location, reason string) {
	s.report.Complete = false
	s.report.Issues = append(s.report.Issues, ScanIssue{scanLocation(location), reason})
}

// Metadata can itself contain credential material (for example a token used as
// a filename). Scrub recognized formats there as well as omitting matched values.
func scanLocation(location string) string {
	for _, detector := range scanDetectors {
		var out strings.Builder
		for len(location) > 0 {
			match := detector.re.FindStringSubmatchIndex(location)
			if match == nil {
				out.WriteString(location)
				break
			}
			out.WriteString(location[:match[2]])
			out.WriteString("[redacted]")
			// Leave the trailing delimiter for the next search, so adjacent
			// credentials sharing a delimiter are both removed.
			location = location[match[3]:]
		}
		location = out.String()
	}
	return location
}

func (s *scanner) next(location string) bool {
	if s.stopped {
		return false
	}
	if s.ctx.Err() != nil {
		s.issue(location, "scan cancelled; rerun before launching")
		s.stopped = true
		return false
	}
	s.entries++
	if s.entries > MaxScanEntries {
		s.issue(location, "scan exceeds 10000 entries; select a smaller explicit scope")
		s.stopped = true
		return false
	}
	return true
}

func (s *scanner) withinSize(location string, size int64) bool {
	if size > MaxFileBytes {
		s.issue(location, "input exceeds 1 MiB; select smaller inputs or inspect it separately")
		return false
	}
	if size > MaxScanBytes-s.report.BytesScanned {
		s.issue(location, "scan exceeds 32 MiB; select a smaller explicit scope")
		s.stopped = true
		return false
	}
	return true
}

func (s *scanner) inspect(data []byte, source, location string) {
	s.report.BytesScanned += int64(len(data))
	for _, detector := range scanDetectors {
		if match := detector.re.FindSubmatchIndex(data); match != nil {
			line := 0
			if source == "file" {
				line = bytes.Count(data[:match[2]], []byte{'\n'}) + 1
			}
			s.report.Findings = append(s.report.Findings, Finding{detector.id, source, scanLocation(location), line})
		}
	}
}

func (s *scanner) walk(root *os.Root, path string, depth int) {
	if s.seen[path] {
		return
	}
	s.seen[path] = true
	if !s.next(path) {
		return
	}
	if depth > maxScanDepth {
		s.issue(path, "directory depth exceeds 64; select a shallower explicit scope")
		return
	}
	before, err := root.Lstat(path)
	if err != nil {
		s.issue(path, "cannot inspect input; check existence and permissions")
		return
	}
	if !before.IsDir() && !before.Mode().IsRegular() {
		s.issue(path, "symlink or special file is unsupported; select regular files/directories")
		return
	}
	f, err := openScanFile(root, path)
	if err != nil {
		s.issue(path, "cannot open input safely; check permissions, platform support and concurrent changes")
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !os.SameFile(before, info) || before.Mode().Type() != info.Mode().Type() {
		s.issue(path, "input changed while opening; stop concurrent changes and retry")
		return
	}
	if info.IsDir() {
		for !s.stopped {
			entries, err := f.ReadDir(128)
			for _, entry := range entries {
				s.walk(root, filepath.Join(path, entry.Name()), depth+1)
				if s.stopped {
					break
				}
			}
			if err == io.EOF {
				break
			}
			if err != nil {
				s.issue(path, "cannot finish reading directory; check permissions and retry")
				break
			}
		}
	} else {
		if !s.withinSize(path, info.Size()) {
			return
		}
		limit := min(int64(MaxFileBytes), MaxScanBytes-s.report.BytesScanned)
		data, err := io.ReadAll(io.LimitReader(f, limit+1))
		if err != nil {
			s.issue(path, "cannot finish reading file; check permissions and retry")
			return
		}
		if !s.withinSize(path, int64(len(data))) {
			return
		}
		s.inspect(data, "file", path)
		s.report.FilesScanned++
	}
	after, err := f.Stat()
	if err != nil || info.Size() != after.Size() || !info.ModTime().Equal(after.ModTime()) {
		s.issue(path, "input changed during scan; stop concurrent changes and retry")
	}
}
