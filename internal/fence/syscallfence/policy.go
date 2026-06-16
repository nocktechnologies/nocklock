// Package syscallfence fences the SYSTEM-CALL surface of a fenced child.
//
// NockLock already fences filesystem paths (Landlock on Linux, Seatbelt/SBPL on
// macOS), network egress (HTTP proxy), and the environment (secret fence). It did
// NOT, before this package, constrain which syscalls the child may invoke. A
// path-fenced agent can still load a kernel module, create a user namespace,
// ptrace a sibling, or open a raw packet socket — none of which the filesystem or
// network fences see. This package closes that surface.
//
// The model is adapted from Omnigent's seccomp/bwrap hardening (and from the
// Kubernetes RuntimeDefault seccomp profile), translated to pure Go with NO cgo:
// a default-ALLOW seccomp-BPF filter that returns EPERM for a curated denylist of
// dangerous subsystems. "Default allow, deny the dangerous" — not "default deny",
// which would require enumerating the thousands of benign syscalls a modern
// toolchain makes and is impractical to maintain (the same reason the macOS
// Seatbelt fence is allow-default; see internal/fence/fs/sbpl.go).
//
// Everything here is opt-in and nil-safe: an absent or zero Policy results in
// ZERO behaviour change. Apply is only reached on Linux when the operator sets
// [syscall] enforcement to "required" or "preferred".
package syscallfence

// Mode selects how hard a failure to install the syscall fence is treated.
//
//   - ModeRequired:  refusing to install the filter is fatal; the child does not
//     run. This is the fail-closed posture for high-assurance deployments.
//   - ModePreferred: if the kernel does not support seccomp-BPF the child still
//     runs (with a warning), but if seccomp IS supported the filter MUST install
//     cleanly or it is fatal — a partial apply is never tolerated.
//   - ModeOff:       the fence is disabled; Apply is a no-op.
type Mode string

const (
	ModeRequired  Mode = "required"
	ModePreferred Mode = "preferred"
	ModeOff       Mode = "off"
)

// Policy is the resolved, runtime-independent description of the syscall fence to
// install. It is produced from config and serialized across the re-exec shim. The
// zero value is a valid "do nothing" policy.
type Policy struct {
	// AllowedSocketFamilies is the allowlist of socket(2) address families the
	// child may create (e.g. "unix", "inet", "inet6"). socket() calls for any
	// family NOT in this list are denied with EPERM (deny-the-complement). An
	// empty list means the socket() filter is not installed at all (no socket
	// restriction) — it does NOT mean "deny all sockets", so an unset policy is
	// permissive, matching the opt-in discipline.
	AllowedSocketFamilies []string `json:"allowed_socket_families,omitempty"`

	// AllowNamespaces, when false (the default), denies the namespace-creating
	// syscalls (unshare/setns and clone with any CLONE_NEW* bit). When true, the
	// namespace primitives are left allowed (the rest of the baseline denylist
	// still applies). Container-launching workloads that legitimately need user
	// namespaces set this true.
	AllowNamespaces bool `json:"allow_namespaces"`

	// ExtraDenySyscalls is an operator-supplied list of additional syscall NAMES
	// to deny with EPERM, beyond the BaselineDenylist. Unknown names are skipped
	// (forward-compat), exactly like the baseline.
	ExtraDenySyscalls []string `json:"extra_deny_syscalls,omitempty"`

	// Mode controls fail-closed vs fail-open behaviour on an install failure.
	// An empty Mode is treated as ModeOff (do nothing) by Apply.
	Mode Mode `json:"mode"`
}

// IsZero reports whether the policy would cause any behaviour change. A zero
// policy (Mode off/empty, namespaces allowed implicitly via the baseline only,
// no socket allowlist, no extras) still installs the baseline when Mode is set;
// IsZero is true only when Mode disables the fence entirely.
func (p Policy) IsZero() bool {
	return p.Mode == ModeOff || p.Mode == ""
}
