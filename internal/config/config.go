// Package config handles TOML configuration parsing and defaults for NockLock.
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/BurntSushi/toml"
)

// ResolveDBPath returns the absolute path to the event log database and the
// project root directory, given a config and the path it was loaded from.
//
// There are two outcomes, and which one applies depends on what is already on
// disk. NockLock never moves an audit chain to change the answer.
//
// LEGACY ROOT — a log already exists at <projectRoot>/.nock/<name>. That file
// stays exactly where it is and keeps being used. An existing audit chain is the
// one thing here that must not be touched by an upgrade: relocating it means
// moving a live SQLite database, its WAL sidecars and its chain anchor
// together, and a half-finished move produces a chain that verifies while
// missing its tail. The cost is that the fence cannot grant the project root for
// creates while the log sits inside it (see fs.FenceConfig.ProtectedRootSubdir),
// which wrap reports on stderr.
//
// NEW ROOT — no legacy log. The log lives in the project's audit state directory
// OUTSIDE the project (AuditStateDir), keeping only the configured filename.
// Nothing NockLock owns is then inside the fence root, which is what lets the
// root be granted so the agent can create and remove files in its own project.
//
// An ABSOLUTE logging.db is returned as written, once it does not conflict
// with a legacy chain sitting in the conventional spot or the state dir --
// it joins the SAME scan as those, rather than short-circuiting before they
// are even looked at. Validate rejects an absolute path that points outside
// the project and its audit state directory, so that check happens at config
// load with a clear error rather than here.
//
// Note that projectRoot (the directory holding .nock/config.toml) and
// filesystem.root need not be the same directory. The choice above is keyed on
// projectRoot because that is what identifies the project; whether the root may
// be granted is decided separately, by asking whether the audit directory
// actually falls inside filesystem.root.
func ResolveDBPath(cfg *Config, configPath string) (dbPath string, projectRoot string, err error) {
	configured := cfg.Logging.DB
	defaultDB := DefaultConfig().Logging.DB
	if configured == "" {
		configured = defaultDB
	}
	defaultBase := filepath.Base(defaultDB)
	// Absolutize the project root before anything is derived from it. With
	// `wrap --profile X` and no config file, loadWrapConfig hands us the
	// sentinel "embedded profile X", and plain relative config paths reach here
	// too; either way filepath.Dir twice yields ".". Hashing "." would give
	// EVERY such project the same audit state directory and interleave their
	// chains, and EvalSymlinks does not absolutize, so it would not catch it.
	projectRoot = filepath.Dir(filepath.Dir(configPath))
	if abs, absErr := filepath.Abs(projectRoot); absErr == nil {
		projectRoot = abs
	}
	stateBase, stateOwned, checkStateBase := auditStateLayout(projectRoot)
	resolvedStateBase := resolveExisting(stateBase)
	stateBaseAvailable := false
	if info, statErr := os.Stat(stateBase); statErr == nil && info.IsDir() {
		if resolved, resolveErr := evalAuditStateRoot(stateBase); resolveErr == nil {
			resolvedStateBase = resolved
			stateBaseAvailable = true
		}
	}
	stateDir := filepath.Join(resolvedStateBase, filepath.Join(stateOwned...))

	isAbs := filepath.IsAbs(configured)

	// Only the conventional <projectRoot>/.nock location counts as a legacy log.
	// The default logging.db is now the bare name "events.db", so treating the
	// configured relative path as a candidate would make <projectRoot>/events.db
	// -- plausibly a file the project owns -- look like NockLock's own state.
	// This candidate is built the same way whether configured is absolute or
	// relative: an older NockLock could have written it to the conventional spot
	// regardless of what the CURRENT config says.
	conventional := filepath.Join(projectRoot, Dir, filepath.Base(configured))
	defaultConventional := filepath.Join(projectRoot, Dir, defaultBase)
	candidates := []string{conventional, defaultConventional}
	// A relative logging.db that contains a separator is a PATH the operator
	// wrote by hand, and before the relocation it named a real in-project log,
	// so honor it. A bare filename is deliberately NOT probed: it is what this
	// version's own default carries, so no NockLock ever wrote a chain to
	// <root>/<bare name>, and a file sitting there belongs to the project. This
	// only applies when configured is itself relative: an absolute path is
	// handled as its own candidate below, not folded into this one.
	relativeConfigured := ""
	if !isAbs {
		if cleaned := filepath.Clean(configured); cleaned != filepath.Base(cleaned) {
			joined := filepath.Join(projectRoot, cleaned)
			// filepath.Join cleans ".." components away silently, so a hand-written
			// "../audit/events.db" would otherwise join to a path outside the
			// project and get adopted, below, as the AUTHORITATIVE log -- handing a
			// file the fenced agent's own project never owned the same trust as a
			// real audit chain. Refuse the config outright instead of just skipping
			// the candidate: a config that names a path outside the project is
			// invalid, not merely one with nothing to find there.
			if !withinDir(projectRoot, joined) {
				return "", projectRoot, fmt.Errorf("logging.db %q escapes the project root %s; use a path inside the project or a bare filename", configured, projectRoot)
			}
			if joined != conventional {
				candidates = append(candidates, joined)
			}
			relativeConfigured = joined
		}
	}

	// The relocated (state-dir) path only competes with an in-project
	// candidate; with none present, that path is the DESTINATION for a fresh
	// chain below, not a second chain to reconcile. The state root is inspected
	// read-only here: an absent or unusable root means its candidates cannot be
	// inspected, so they are omitted rather than blocking an in-project chain.
	// Creation and trust validation happen only if this destination is selected.
	stateDB := filepath.Join(stateDir, filepath.Base(configured))
	defaultStateDB := filepath.Join(stateDir, defaultBase)
	if stateBaseAvailable {
		candidates = append(candidates, stateDB, defaultStateDB)
	}

	// An absolute logging.db joins the SAME scan as everything above it,
	// instead of being returned before any of it is even looked at: unlike the
	// other candidates, it is always treated as "existing" below, because an
	// explicit absolute path IS the operator's chosen destination whether or
	// not a file has been written there yet, so it conflicts -- and is refused
	// -- whenever a real chain also sits at one of the other candidates.
	absoluteConfigured := ""
	if isAbs {
		absoluteConfigured = configured
		candidates = append(candidates, configured)
	}

	// Every candidate is Lstat'd on its ORIGINAL, uncanonicalized spelling: a
	// symlink planted directly at a candidate path must be caught regardless
	// of where it points, even when its target happens to canonicalize to the
	// same file another candidate already reaches directly. De-duplicating
	// candidates before this scan -- by their canonical form -- would let a
	// planted symlink whose target coincides with an earlier real candidate
	// skip the Lstat/symlink check entirely, silently defeating both the
	// symlink refusal and the multi-chain refusal below. So dedup happens
	// AFTER each candidate has individually passed the symlink check, keyed by
	// the canonical form each one resolves to -- which is also what goes into
	// the error message, so a symlinked ancestor (macOS routes TMPDIR and /var
	// through /private, for instance) cannot make the same file look like two
	// chains or get named inconsistently with another candidate that reached
	// it a different way.
	canonOf := make(map[string]string, len(candidates))
	rawSeen := make(map[string]bool, len(candidates))
	var existing []string
	seenCanon := make(map[string]bool, len(candidates))
	for _, raw := range candidates {
		if rawSeen[raw] {
			continue
		}
		rawSeen[raw] = true
		canon := resolveExisting(raw)
		canonOf[raw] = canon

		info, statErr := os.Lstat(raw)
		if statErr != nil {
			// Only "not there" means not there. A permission error, an I/O
			// error or a symlink loop would otherwise read as absence, and wrap
			// would start a FRESH chain while the real audit trail sat in the
			// now-writable project root. Fail closed instead.
			if errors.Is(statErr, os.ErrNotExist) {
				continue
			}
			return "", projectRoot, fmt.Errorf("cannot determine whether an event log exists at %s: %w", raw, statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", projectRoot, fmt.Errorf("refusing to use the event log at %s: path is a symlink", raw)
		}
		if !seenCanon[canon] {
			seenCanon[canon] = true
			existing = append(existing, canon)
		}
	}
	if stateDB != "" {
		if canon, ok := canonOf[stateDB]; ok {
			stateDB = canon
		}
	}
	if absoluteConfigured != "" {
		absoluteConfigured = canonOf[absoluteConfigured]
	}
	if relativeConfigured != "" {
		relativeConfigured = canonOf[relativeConfigured]
	}

	// The explicit absolute destination always counts, even when nothing has
	// been written there yet: see the comment above candidates' construction.
	if absoluteConfigured != "" && !slices.Contains(existing, absoluteConfigured) {
		existing = append(existing, absoluteConfigured)
	}
	// A renamed relative logging.db selects a new state-dir destination even
	// when it does not exist yet. If the default-name chain still exists, count
	// both paths and refuse instead of silently abandoning the old chain.
	if !isAbs && stateBaseAvailable && stateDB != "" && filepath.Base(configured) != defaultBase &&
		!slices.Contains(existing, relativeConfigured) && !slices.Contains(existing, stateDB) {
		existing = append(existing, stateDB)
	}

	// Exactly one authoritative log per root. More than one is an
	// operator-visible state, not a race, so name every candidate instead of
	// picking a side: choosing silently could run against a stale or tampered
	// chain while the real one sits right next to it.
	if len(existing) > 1 {
		return "", projectRoot, fmt.Errorf(
			"%d event logs found: %s. NockLock will not guess which audit chain is authoritative. "+
				"Verify each one, then move the ones you are discarding aside "+
				"(their -wal/-shm sidecars and chain anchors travel with them)",
			len(existing), strings.Join(existing, ", "))
	}
	ensureSelectedStateDir := func() (string, error) {
		createdBase, createErr := resolveAuditStateRoot(stateBase)
		if createErr != nil {
			return "", createErr
		}
		if createdBase != resolvedStateBase {
			return "", fmt.Errorf("audit state root changed while resolving: scanned %s, now %s", resolvedStateBase, createdBase)
		}
		return ensureAuditStateDirAt(createdBase, stateOwned, checkStateBase)
	}
	// An absolute logging.db is used as written once nothing else conflicts.
	// When its canonical path is inside the canonical audit state directory,
	// apply the same state-root trust checks as the relative/default route.
	if absoluteConfigured != "" {
		if stateDB != "" && withinDir(filepath.Dir(stateDB), absoluteConfigured) {
			if _, err := ensureSelectedStateDir(); err != nil {
				return "", projectRoot, err
			}
		}
		return configured, projectRoot, nil
	}
	// The state-dir candidate, existing or not, is the one case that still
	// needs EnsureAuditStateDir: unlike an in-project log, it carries the
	// ownership/permission/symlink trust checks a directory NockLock itself
	// manages requires, and AuditStateDir above deliberately skipped them.
	if len(existing) == 1 && existing[0] != stateDB {
		return existing[0], projectRoot, nil
	}

	stateDir, err = ensureSelectedStateDir()
	if err != nil {
		return "", projectRoot, err
	}
	return filepath.Join(stateDir, filepath.Base(configured)), projectRoot, nil
}

// Config is the top-level NockLock configuration.
type Config struct {
	ProfileName string           `toml:"-"`
	Project     ProjectConfig    `toml:"project"`
	Filesystem  FilesystemConfig `toml:"filesystem"`
	Network     NetworkConfig    `toml:"network"`
	Secrets     SecretsConfig    `toml:"secrets"`
	Syscall     SyscallConfig    `toml:"syscall"`
	Logging     LoggingConfig    `toml:"logging"`
	Cloud       CloudConfig      `toml:"cloud"`
}

// ProjectConfig identifies the project being fenced.
type ProjectConfig struct {
	Name string `toml:"name"`
	Root string `toml:"root"`
}

// FilesystemConfig defines filesystem access boundaries.
type FilesystemConfig struct {
	Root             string   `toml:"root"`
	Mode             string   `toml:"mode"`
	LinuxEnforcement string   `toml:"linux_enforcement"`
	Allow            []string `toml:"allow"`
	AllowRW          []string `toml:"allow_rw"`
	Deny             []string `toml:"deny"`
	// MacOSAllowUnfenced is a temporary macOS-only escape hatch. When true,
	// wrap records a DEGRADED fence state and starts the child only if Seatbelt
	// cannot be applied. It is scheduled for removal in v0.6; false is the
	// secure, fail-closed default.
	MacOSAllowUnfenced bool `toml:"macos_allow_unfenced"`
	// Hardened opts in to the stricter macOS Seatbelt rules (deny
	// mach-priv-host-port, iokit-open, system-socket; tightened /dev). It is a
	// no-op on Linux. Absent/false = no behaviour change.
	Hardened bool `toml:"hardened"`
}

// SyscallConfig defines the syscall-surface fence (Linux seccomp-BPF). It is
// nil-safe: an absent [syscall] table leaves Enforcement empty, which defaults
// to "required" so Linux launches fail closed when seccomp-BPF is unavailable.
type SyscallConfig struct {
	// Enforcement is one of "required", "preferred", or "off". Empty defaults to
	// "required". On non-Linux platforms the syscall fence is always a no-op.
	Enforcement string `toml:"enforcement"`
	// AllowNamespaces, when true, leaves unshare/setns and namespace-creating
	// clone() flags permitted (the rest of the baseline still applies). Default
	// false denies namespace creation.
	AllowNamespaces bool `toml:"allow_namespaces"`
	// SocketFamilies is the allowlist of socket(2) address families the child may
	// create (e.g. "unix", "inet", "inet6"). Empty means no socket restriction.
	SocketFamilies []string `toml:"socket_families"`
	// ExtraDeny appends additional syscall NAMES to deny beyond the baseline.
	// Unknown names are skipped (forward-compat).
	ExtraDeny []string `toml:"extra_deny"`
}

// NetworkConfig defines network egress boundaries.
type NetworkConfig struct {
	Allow              []string `toml:"allow"`
	AllowAll           bool     `toml:"allow_all"`
	AllowPrivateRanges bool     `toml:"allow_private_ranges"`
}

// SecretsConfig defines environment filtering and optional secret preflight checks.
type SecretsConfig struct {
	Pass  []string `toml:"pass"`
	Block []string `toml:"block"`
	// ScanEnv checks values remaining after filtering before the child starts.
	ScanEnv bool `toml:"scan_env"`
	// ScanPaths selects project-relative files/directories for required preflight.
	ScanPaths []string `toml:"scan_paths"`
	// ScanEnvAllow exempts exact environment names from value scanning, never filtering.
	ScanEnvAllow []string `toml:"scan_env_allow"`
}

// LoggingConfig configures local event logging.
type LoggingConfig struct {
	DB    string `toml:"db"`
	Level string `toml:"level"`
}

// CloudConfig configures optional NockCC dashboard sync.
type CloudConfig struct {
	Enabled  bool   `toml:"enabled"`
	APIKey   string `toml:"api_key"`
	Endpoint string `toml:"endpoint"`
}

const (
	// Dir is the NockLock config directory name relative to the project root.
	Dir = ".nock"
	// File is the config file name within Dir.
	File = "config.toml"
)

// FindConfig walks up from the current working directory looking for a
// .nock/config.toml file and returns the first path it finds.
// Returns an error wrapping os.ErrNotExist if no config is found.
func FindConfig() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("failed to get working directory: %w", err)
	}
	for {
		candidate := filepath.Join(dir, Dir, File)
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			// Reached filesystem root without finding config.
			return "", fmt.Errorf("no %s/%s found in %s or any parent directory: %w", Dir, File, dir, os.ErrNotExist)
		}
		dir = parent
	}
}

// Load reads and parses a TOML config file at the given path.
func Load(path string) (*Config, error) {
	cfg := DefaultConfig()
	if err := loadInto(&cfg, path); err != nil {
		return nil, err
	}

	return &cfg, nil
}

// LoadOverlay reads a TOML config file over base, keeping only changes that do
// not widen the fence relative to base.
func LoadOverlay(base Config, path string) (*Config, error) {
	baseCopy := cloneConfig(base)
	overlay := cloneConfig(base)
	fields, err := overlayDefinedFields(path)
	if err != nil {
		return nil, err
	}
	md, err := loadIntoWithMetadata(&overlay, path)
	if err != nil {
		return nil, err
	}
	addMetadataFields(fields, md)
	cfg := restrictOverlay(baseCopy, overlay, fields)
	return &cfg, nil
}

func loadInto(cfg *Config, path string) error {
	_, err := loadIntoWithMetadata(cfg, path)
	return err
}

func loadIntoWithMetadata(cfg *Config, path string) (toml.MetaData, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return toml.MetaData{}, fmt.Errorf("failed to read config at %s: %w", path, err)
	}

	md, err := toml.Decode(string(data), cfg)
	if err != nil {
		return toml.MetaData{}, fmt.Errorf("failed to parse config at %s: %w", path, err)
	}
	if undecoded := md.Undecoded(); len(undecoded) > 0 {
		return toml.MetaData{}, fmt.Errorf("unknown config keys at %s: %v", path, undecoded)
	}

	if errs := Validate(cfg); len(errs) > 0 {
		for _, e := range errs {
			if e.Severity == "error" {
				return toml.MetaData{}, fmt.Errorf("invalid config at %s: %s", path, e.Error())
			}
		}
	}
	if err := validateAuditDBLocation(cfg, path); err != nil {
		return toml.MetaData{}, fmt.Errorf("invalid config at %s: %w", path, err)
	}

	return md, nil
}

// validateAuditDBLocation rejects an absolute logging.db that points outside
// both the project and its audit state directory.
//
// logging.db comes from a file a repository can ship, so an unrestricted
// absolute path would let a hostile checkout aim a SQLite database at any path
// the invoking user can write. Something has always refused those paths; the
// point of doing it HERE is that the operator gets one clear error at config
// load naming the setting, instead of a failure from deep inside the event
// logger at the moment the fence starts.
//
// Relative paths need no check here: a hand-written relative path containing
// a separator is confined to the project root by ResolveDBPath itself, which
// rejects one that would traverse outside it before ever probing or returning
// it. Every other relative path resolves into the audit state directory or
// the project's own .nock, never anywhere else.
func validateAuditDBLocation(cfg *Config, configPath string) error {
	db := strings.TrimSpace(cfg.Logging.DB)
	if db == "" || !filepath.IsAbs(db) {
		return nil
	}
	projectRoot := filepath.Dir(filepath.Dir(configPath))
	absRoot, err := filepath.Abs(projectRoot)
	if err != nil {
		// Fences fail closed: an unresolvable project root means the check
		// cannot be made, not that the path is fine.
		return fmt.Errorf("logging.db %q cannot be checked: the project root %q could not be resolved: %w", db, projectRoot, err)
	}
	if withinDir(absRoot, db) {
		// Inside the project is allowed, but NOT directly in its top level. The
		// fence protects an in-project audit trail by withholding the grant on
		// the root and granting each child except the audit directory, which
		// only works when the audit directory IS a child. With the log sitting
		// in the root itself there is nothing to skip: Landlock grants whole
		// hierarchies, so any rule that let the agent work would also expose the
		// log. Say so here rather than failing later while building the ruleset.
		dbDir := resolveExisting(filepath.Dir(db))
		tops := []string{absRoot}
		// filesystem.root need not be the project root, and it is the one the
		// fence actually grants, so check both.
		if fenceRoot := strings.TrimSpace(cfg.Filesystem.Root); fenceRoot != "" {
			if expanded, expErr := expandHome(fenceRoot); expErr == nil {
				if abs, absErr := filepath.Abs(expanded); absErr == nil {
					tops = append(tops, abs)
				}
			}
		}
		for _, top := range tops {
			if dbDir == resolveExisting(top) {
				return fmt.Errorf(
					"logging.db %q sits directly in %s. Put it in a subdirectory (for example %q) "+
						"or leave logging.db as a bare filename so the event log goes to NockLock's audit "+
						"state directory outside the project, which is the recommended setting",
					db, top, filepath.Join(Dir, filepath.Base(db)))
			}
		}
		return nil
	}
	stateDir, err := AuditStateDir(absRoot)
	if err == nil && withinDir(stateDir, db) {
		return nil
	}
	return fmt.Errorf(
		"logging.db %q is an absolute path outside both the project (%s) and NockLock's audit state directory. "+
			"Use a relative name such as \"events.db\" to keep the event log in the audit state directory, "+
			"which is where it belongs and where the fenced agent cannot reach it",
		db, absRoot)
}

// expandHome replaces a leading ~ with the user's home directory. internal/fence/fs
// exports the shared version, but it imports this package, so this leaf cannot
// call it.
func expandHome(path string) (string, error) {
	if path != "~" && !strings.HasPrefix(path, "~/") {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	if path == "~" {
		return home, nil
	}
	return filepath.Join(home, path[2:]), nil
}

// withinDir reports whether path is dir or lies beneath it, comparing at
// component boundaries so a sibling named like dir plus a suffix does not match.
func withinDir(dir, path string) bool {
	rel, err := filepath.Rel(resolveExisting(dir), resolveExisting(path))
	if err != nil {
		return false
	}
	return rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)))
}

// resolveExisting canonicalizes path by resolving symlinks in its deepest
// EXISTING ancestor and re-appending the components that do not exist yet.
//
// Resolving only whole existing paths is not enough, and getting this wrong is a
// macOS-only bug: /tmp, /var and the default TMPDIR are system symlinks into
// /private, so a project directory resolves to /private/var/... while a
// logging.db underneath it that has not been created yet does not resolve at
// all. Comparing one against the other then says the path is outside the project
// when it is plainly inside it.
func resolveExisting(path string) string {
	cleaned := filepath.Clean(path)
	if resolved, err := filepath.EvalSymlinks(cleaned); err == nil {
		return resolved
	}
	tail := []string{filepath.Base(cleaned)}
	for dir := filepath.Dir(cleaned); ; {
		if resolved, err := filepath.EvalSymlinks(dir); err == nil {
			parts := append([]string{resolved}, reverseTail(tail)...)
			return filepath.Join(parts...)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return cleaned
		}
		tail = append(tail, filepath.Base(dir))
		dir = parent
	}
}

func reverseTail(in []string) []string {
	out := make([]string, len(in))
	for i, v := range in {
		out[len(in)-1-i] = v
	}
	return out
}
