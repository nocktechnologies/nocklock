package landlock

import (
	"encoding/json"
	"errors"
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
		Paths:           make([]PathRule, 0, len(cfg.AllowPaths)+len(cfg.AllowRWPaths)+len(extra)),
	}
	rootAccess := AccessReadWrite
	if cfg.Mode == "read-only" {
		rootAccess = AccessReadOnly
	}
	rootRuleset, err := rootRules(cfg.Root, cfg.ProtectedRootSubdir, rootAccess, abi)
	if err != nil {
		return Spec{}, err
	}
	spec.Paths = append(spec.Paths, rootRuleset...)
	for _, p := range cfg.AllowPaths {
		// An absent optional read path grants nothing. A fresh HOME need not
		// already contain ~/.claude for the default policy to start.
		if _, err := os.Stat(p); errors.Is(err, os.ErrNotExist) {
			continue
		} else if err != nil {
			return Spec{}, fmt.Errorf("inspect allow path %q: %w", p, err)
		}
		spec.Paths = append(spec.Paths, pathRule(p, AccessReadOnly, abi))
	}
	for _, p := range cfg.AllowRWPaths {
		spec.Paths = append(spec.Paths, pathRule(p, AccessReadWrite, abi))
	}
	for _, p := range extra {
		spec.Paths = append(spec.Paths, pathRule(filepath.Clean(p.Path), p.Access, abi))
	}
	spec.Paths = append(spec.Paths, baselineDeviceRules(abi, cfg.DenyPaths)...)
	if err := assertDenyPathsEnforceable(cfg.DenyPaths, spec.Paths); err != nil {
		return Spec{}, err
	}
	return spec, nil
}

// baselineDeviceRules grants the standard character devices that ordinary
// programs cannot run without: /dev/null and /dev/tty are writable and
// /dev/zero is readable. The fence otherwise grants a non-directory file only
// read+execute, so a program that writes to /dev/null (git, shells, echo) is
// denied outright — the exact breakage reported in the field. These devices are
// world read/write and carry no data worth fencing, so they are granted
// unconditionally, independent of the configured allow list, and the LD_PRELOAD
// interposer applies the identical baseline (see check_path in
// internal/fence/fs/interposer/libfence_fs.c).
//
// An explicit deny still wins: a node covered by a configured deny path is
// skipped rather than silently re-granted (which would also make the ruleset
// unenforceable via assertDenyPathsEnforceable). Absent nodes are skipped so
// the rules stay valid on minimal containers.
//
// These are the only grants RulesFromConfig emits OUTSIDE the configured root;
// the containment invariant (FuzzRulesFromConfigContainment) exempts exactly
// this set via IsBaselineDeviceNode.
func baselineDeviceRules(abi int, denyPaths []string) []PathRule {
	handled := RightsForABI(abi)
	rules := make([]PathRule, 0, len(baselineDeviceNodes))
	for _, n := range baselineDeviceNodes {
		if _, err := os.Stat(n.path); err != nil {
			continue
		}
		if deniedByConfig(n.path, denyPaths) {
			continue
		}
		rules = append(rules, PathRule{Path: n.path, Access: n.access, Rights: n.rights & handled})
	}
	return rules
}

// baselineDeviceNode is a standard character device granted unconditionally.
type baselineDeviceNode struct {
	path   string
	access string
	rights uint64
}

// baselineDeviceNodes is the curated set of world-accessible character devices
// every program needs: /dev/null and /dev/tty writable, and /dev/zero,
// /dev/urandom and /dev/random readable (the entropy sources musl and older
// TLS stacks read directly when getrandom(2) is unavailable). The interposer
// (check_path in libfence_fs.c) applies the identical set.
var baselineDeviceNodes = []baselineDeviceNode{
	{"/dev/null", AccessReadWrite, RightReadFile | RightWriteFile | RightIOCTLDev},
	{"/dev/tty", AccessReadWrite, RightReadFile | RightWriteFile | RightIOCTLDev},
	{"/dev/zero", AccessReadOnly, RightReadFile},
	{"/dev/urandom", AccessReadOnly, RightReadFile},
	{"/dev/random", AccessReadOnly, RightReadFile},
}

// IsBaselineDeviceNode reports whether path is one of the curated device nodes
// granted unconditionally outside the root. Used by the containment fuzz test to
// exempt exactly these paths from the "every grant lies inside the root" check.
func IsBaselineDeviceNode(path string) bool {
	for _, n := range baselineDeviceNodes {
		if n.path == path {
			return true
		}
	}
	return false
}

// deniedByConfig reports whether path is covered by any configured deny path
// (the deny path is the node itself or an ancestor directory of it).
func deniedByConfig(path string, denyPaths []string) bool {
	for _, d := range denyPaths {
		dc := filepath.Clean(d)
		if dc == "" || dc == "." {
			continue
		}
		if pathsOverlap(dc, path) {
			return true
		}
	}
	return false
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

// rootRules grants the fence root. It has two shapes, and which one applies is
// decided entirely by whether the audit state sits inside the root.
//
// DEFAULT (protectedSubdir empty): ONE rule on the root, so the fenced child can
// create and remove entries DIRECTLY IN the root and not merely inside
// subdirectories that already exist. Landlock checks
// MAKE_REG/MAKE_DIR/REMOVE_FILE/REMOVE_DIR against the directory holding the
// entry, so without a rule on the root itself `touch <root>/newfile` is denied
// even in read-write mode. Granting the root alone is also strictly safer for
// symlinks: Landlock binds the rule to the root's inode, so a symlink inside the
// root pointing outside it grants nothing.
//
// LEGACY (protectedSubdir set): grant each EXISTING CHILD of the root and skip
// the protected directory, leaving the root itself ungranted. The child keeps
// the access it has today but cannot create or remove entries directly in the
// root. This is the shape every release before the audit state moved out used,
// and it is required whenever a directory inside the root must stay unwritable:
// the kernel walks upward from the accessed file and allows as soon as an
// ancestor rule grants the access, so a rule on the root cannot be narrowed
// underneath, and stacking layers does not help because every layer would need
// MAKE_REG on the root for a create in the root to succeed.
//
// The per-child grants resolve symlinks, so this shape needs the escape check
// the single root rule does not: a child symlinked outside the root would
// otherwise produce a real rule on the target.
func rootRules(root, protectedSubdir, access string, abi int) ([]PathRule, error) {
	cleanRoot, err := filepath.EvalSymlinks(filepath.Clean(root))
	if err != nil {
		return nil, fmt.Errorf("resolve Landlock root %q: %w", root, err)
	}
	if protectedSubdir == "" {
		return []PathRule{pathRule(cleanRoot, access, abi)}, nil
	}

	protected, err := filepath.EvalSymlinks(filepath.Clean(protectedSubdir))
	if err != nil {
		// A protected directory that cannot be resolved must not silently
		// downgrade to granting the whole root, which would expose it.
		return nil, fmt.Errorf("resolve protected root subdirectory %q: %w", protectedSubdir, err)
	}
	// Skipping one entry only protects a DIRECT child. If the protected
	// directory sits deeper, the child on the path to it gets granted and the
	// ancestor walk reaches the protected directory anyway — silently, which is
	// the worst outcome. Refuse instead of pretending to protect it. This
	// happens when filesystem.root is an ancestor of the project directory
	// holding the audit trail.
	if filepath.Dir(protected) != cleanRoot {
		return nil, fmt.Errorf(
			"cannot protect %q inside Landlock root %q: it is not a direct child, and Landlock grants a whole hierarchy, so granting %q would grant it too; "+
				"set filesystem.root to the directory that holds the audit trail, or move the audit trail out of the root",
			protected, cleanRoot, filepath.Dir(protected))
	}
	entries, err := os.ReadDir(cleanRoot)
	if err != nil {
		return nil, fmt.Errorf("read Landlock root %q: %w", cleanRoot, err)
	}

	paths := make([]string, 0, len(entries))
	for _, entry := range entries {
		child := filepath.Join(cleanRoot, entry.Name())
		if child == protected {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			resolved, err := filepath.EvalSymlinks(child)
			if err != nil {
				return nil, fmt.Errorf("resolve Landlock root child %q: %w", child, err)
			}
			if !pathInsideRoot(cleanRoot, resolved) {
				return nil, fmt.Errorf("Landlock root child %q resolves outside Landlock root %q to %q", child, cleanRoot, resolved)
			}
			if resolved == protected {
				continue
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
