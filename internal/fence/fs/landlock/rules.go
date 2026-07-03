package landlock

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	fsfence "github.com/nocktechnologies/nocklock/internal/fence/fs"
)

const (
	AccessReadOnly  = "read-only"
	AccessReadWrite = "read-write"
)

// Landlock filesystem access bits. They intentionally mirror Linux UAPI values
// so tests can verify ABI masking on every platform without importing unix.
const (
	RightExecute    uint64 = 1 << 0
	RightWriteFile  uint64 = 1 << 1
	RightReadFile   uint64 = 1 << 2
	RightReadDir    uint64 = 1 << 3
	RightRemoveDir  uint64 = 1 << 4
	RightRemoveFile uint64 = 1 << 5
	RightMakeChar   uint64 = 1 << 6
	RightMakeDir    uint64 = 1 << 7
	RightMakeReg    uint64 = 1 << 8
	RightMakeSock   uint64 = 1 << 9
	RightMakeFifo   uint64 = 1 << 10
	RightMakeBlock  uint64 = 1 << 11
	RightMakeSym    uint64 = 1 << 12
	RightRefer      uint64 = 1 << 13
	RightTruncate   uint64 = 1 << 14
	RightIOCTLDev   uint64 = 1 << 15
)

const maxSupportedABI = 5

const readRights = RightExecute | RightReadFile | RightReadDir

const writeRights = RightWriteFile |
	RightRemoveDir |
	RightRemoveFile |
	RightMakeChar |
	RightMakeDir |
	RightMakeReg |
	RightMakeSock |
	RightMakeFifo |
	RightMakeBlock |
	RightMakeSym |
	RightRefer |
	RightTruncate

// AllowPath is an extra path rule to add beyond the resolved filesystem config.
type AllowPath struct {
	Path   string
	Access string
}

// PathRule is the serialized Landlock allow rule for one path.
type PathRule struct {
	Path   string `json:"path"`
	Access string `json:"access"`
	Rights uint64 `json:"rights"`
}

// Spec is the ruleset description passed to the hidden __landlock-exec shim.
type Spec struct {
	ABI             int        `json:"abi"`
	HandledAccessFS uint64     `json:"handled_access_fs"`
	Paths           []PathRule `json:"paths"`
}

// RightsForABI returns only the Landlock filesystem bits known by the detected
// ABI. Passing unknown bits makes the kernel reject the entire ruleset.
func RightsForABI(abi int) uint64 {
	if abi <= 0 {
		return 0
	}
	rights := readRights |
		RightWriteFile |
		RightRemoveDir |
		RightRemoveFile |
		RightMakeChar |
		RightMakeDir |
		RightMakeReg |
		RightMakeSock |
		RightMakeFifo |
		RightMakeBlock |
		RightMakeSym
	if abi >= 2 {
		rights |= RightRefer
	}
	if abi >= 3 {
		rights |= RightTruncate
	}
	if abi >= 5 {
		rights |= RightIOCTLDev
	}
	return rights
}

func clampABI(abi int) int {
	if abi > maxSupportedABI {
		return maxSupportedABI
	}
	return abi
}

// RulesFromConfig maps NockLock's resolved allowlist to Landlock fd rules.
func RulesFromConfig(cfg *fsfence.FenceConfig, extra []AllowPath, abi int) (Spec, error) {
	if cfg == nil {
		return Spec{}, fmt.Errorf("filesystem config is required")
	}
	if abi <= 0 {
		return Spec{}, fmt.Errorf("Landlock ABI must be positive")
	}
	abi = clampABI(abi)
	handled := RightsForABI(abi)
	if handled == 0 {
		return Spec{}, fmt.Errorf("Landlock ABI %d has no supported rights", abi)
	}

	spec := Spec{
		ABI:             abi,
		HandledAccessFS: handled,
		Paths:           make([]PathRule, 0, len(cfg.AllowPaths)+len(extra)),
	}
	rootAccess := AccessReadWrite
	if cfg.Mode == "read-only" {
		rootAccess = AccessReadOnly
	}
	rootRules, err := rootPathRules(cfg.Root, rootAccess, abi)
	if err != nil {
		return Spec{}, err
	}
	spec.Paths = append(spec.Paths, rootRules...)
	for _, p := range cfg.AllowPaths {
		spec.Paths = append(spec.Paths, pathRule(p, AccessReadOnly, abi))
	}
	for _, p := range extra {
		spec.Paths = append(spec.Paths, pathRule(filepath.Clean(p.Path), p.Access, abi))
	}
	if err := assertDenyPathsEnforceable(cfg.DenyPaths, spec.Paths); err != nil {
		return Spec{}, err
	}
	return spec, nil
}

// assertDenyPathsEnforceable fails closed when a configured deny path cannot be
// honored by Landlock.
//
// Landlock is allow-only: every rule GRANTS access to a path subtree and the
// kernel rejects a zero-access rule, so there is no way to express a deny that
// carves a hole out of a granted tree (see Apply in landlock_linux.go). The
// LD_PRELOAD interposer does enforce DenyPaths, but a static binary or a child
// that clears LD_PRELOAD relies solely on Landlock. If a deny path overlaps a
// Landlock-granted tree (a root child, an allow path, or an extra rule),
// Landlock would silently grant access to the very path the operator asked to
// deny. Refuse to build such a ruleset rather than ship a fence that ignores
// the deny. Deny paths that do not overlap any grant need no rule: Landlock
// denies everything that is not explicitly allowed.
func assertDenyPathsEnforceable(denyPaths []string, granted []PathRule) error {
	for _, deny := range denyPaths {
		d := filepath.Clean(deny)
		if d == "" || d == "." {
			continue
		}
		for _, rule := range granted {
			if pathsOverlap(d, rule.Path) {
				return fmt.Errorf(
					"deny path %q overlaps Landlock-granted tree %q and cannot be enforced by Landlock (allow-only); "+
						"narrow the root/allow grant so it does not include the deny path", d, rule.Path)
			}
		}
	}
	return nil
}

// pathsOverlap reports whether two cleaned paths refer to the same location or
// one is an ancestor directory of the other. Comparison is component-boundary
// aware so "/a/bc" does not overlap "/a/b".
func pathsOverlap(a, b string) bool {
	return a == b || isAncestor(a, b) || isAncestor(b, a)
}

// isAncestor reports whether ancestor is a strict parent directory of
// descendant (both cleaned).
func isAncestor(ancestor, descendant string) bool {
	if ancestor == descendant {
		return false
	}
	sep := string(os.PathSeparator)
	if ancestor == sep {
		return strings.HasPrefix(descendant, sep)
	}
	return strings.HasPrefix(descendant, ancestor+sep)
}

func rootPathRules(root, access string, abi int) ([]PathRule, error) {
	cleanRoot, err := filepath.EvalSymlinks(filepath.Clean(root))
	if err != nil {
		return nil, fmt.Errorf("resolve Landlock root %q: %w", root, err)
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, fmt.Errorf("read Landlock root %q: %w", root, err)
	}

	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		if entry.Name() == ".nock" {
			continue
		}
		child := filepath.Join(cleanRoot, entry.Name())
		if entry.Type()&os.ModeSymlink != 0 {
			resolved, err := filepath.EvalSymlinks(child)
			if err != nil {
				return nil, fmt.Errorf("resolve Landlock root child %q: %w", child, err)
			}
			if !pathInsideRoot(cleanRoot, resolved) {
				return nil, fmt.Errorf("Landlock root child %q resolves outside Landlock root %q to %q", child, cleanRoot, resolved)
			}
			child = resolved
		}
		paths = append(paths, child)
	}
	sort.Strings(paths)

	rules := make([]PathRule, 0, len(paths))
	for _, path := range paths {
		rules = append(rules, pathRule(path, access, abi))
	}
	return rules, nil
}

func pathInsideRoot(root, path string) bool {
	root = filepath.Clean(root)
	path = filepath.Clean(path)
	if path == root {
		return true
	}
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
}

func pathRule(path, access string, abi int) PathRule {
	rights := rightsForPath(path, access)
	rights &= RightsForABI(abi)
	return PathRule{Path: filepath.Clean(path), Access: access, Rights: rights}
}

func rightsForPath(path, access string) uint64 {
	rights := readRights
	info, err := os.Stat(path)
	if err == nil && !info.IsDir() {
		rights = RightExecute | RightReadFile
		if access == AccessReadWrite {
			rights |= RightWriteFile | RightTruncate
		}
		return rights
	}
	if access == AccessReadWrite {
		rights |= writeRights
	}
	return rights
}

func MarshalSpec(spec Spec) (string, error) {
	data, err := json.Marshal(spec)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func UnmarshalSpec(raw string) (Spec, error) {
	var spec Spec
	if err := json.Unmarshal([]byte(raw), &spec); err != nil {
		return Spec{}, err
	}
	if spec.ABI <= 0 || spec.HandledAccessFS == 0 {
		return Spec{}, fmt.Errorf("invalid Landlock ruleset header")
	}
	return spec, nil
}
