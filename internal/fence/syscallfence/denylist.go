package syscallfence

import "runtime"

// This file is pure Go with NO build tag so the denylist and the name->number
// resolution it drives are unit-testable on every platform (including the macOS
// dev/CI host, which cannot run a Linux kernel). The actual seccomp install lives
// in seccomp_linux.go; everything that decides WHAT to deny lives here.

// BaselineDenylist is the curated set of syscalls denied with EPERM by default.
//
// It is the Kubernetes RuntimeDefault profile INVERTED: instead of "default deny,
// allow a large list", this is "default ALLOW, deny these dangerous subsystems".
// Default-allow is required because a from-scratch allowlist would have to
// enumerate the thousands of benign syscalls a modern language runtime/toolchain
// makes, and would break on the next libc/runtime that adds one — the same
// fail-open hazard the macOS Seatbelt fence documents. Denying the dangerous
// complement is maintainable and forward-compatible.
//
// Entries are syscall NAMES, resolved to per-arch numbers at apply time. A name
// with no number on the target ABI is SKIPPED (forward-compat: a kernel/arch that
// lacks a syscall cannot have it called, so there is nothing to deny).
//
// Grouped by the privilege-escalation / sandbox-escape primitive each represents:
var BaselineDenylist = []string{
	// --- Kernel module loading: load arbitrary code into ring 0. ---
	"init_module",
	"finit_module",
	"delete_module",

	// --- Mount / namespace filesystem primitives: re-pivot the rootfs, bind over
	// fenced paths, escape via a new mount namespace. unshare/setns are also
	// gated by AllowNamespaces below, but the FS-mount primitives are denied
	// unconditionally in the baseline. ---
	"mount",
	"umount2",
	"pivot_root",
	"mount_setattr",
	"move_mount",
	"fsopen",
	"fsconfig",
	"fsmount",
	"open_tree",

	// --- open_by_handle_at: bypasses path-based fencing entirely by opening an
	// inode by its file handle (the classic Landlock/AppArmor bypass). Its
	// companion name_to_handle_at is denied too so a handle cannot be minted. ---
	"open_by_handle_at",
	"name_to_handle_at",

	// --- Kernel keyring: a credential store outside the env/secret fence. ---
	"add_key",
	"request_key",
	"keyctl",

	// --- Programmable-kernel / speculative attack surface. ---
	"bpf",             // load eBPF programs into the kernel
	"perf_event_open", // perf subsystem; repeated LPE source
	"userfaultfd",     // userspace page-fault handling; heap-grooming / KASLR aid

	// --- Namespace creation (also gated by AllowNamespaces; listed here so that
	// even with the legacy-clone arg filter, the dedicated syscalls are denied
	// when namespaces are not permitted). ---
	"unshare",
	"setns",

	// --- Time setters: moving the wall clock can defeat cert/expiry checks and
	// confuse the audit log. ---
	"settimeofday",
	"stime",
	"clock_settime",
	"clock_adjtime",
	"adjtimex",

	// --- Catastrophic host control. ---
	"reboot",
	"kexec_load",
	"kexec_file_load",

	// --- Raw hardware I/O ports (x86). ---
	"ioperm",
	"iopl",

	// --- Cross-process inspection / injection: ptrace and the process_vm_*
	// pair let a fenced process read or WRITE a sibling's memory, defeating the
	// per-process boundary. Added on top of the inverted-RuntimeDefault set
	// because RuntimeDefault leaves ptrace allowed for debuggers; a fenced agent
	// has no such need and it is a direct sandbox-escape primitive. ---
	"ptrace",
	"process_vm_readv",
	"process_vm_writev",

	// --- i386 socket multiplexer: defense-in-depth for the secondary ABI path.
	// On i386, socket-family syscalls are multiplexed through socketcall(2), so
	// deny the multiplexer when the compat ABI is reachable from a 64-bit child.
	"socketcall",
}

// namespaceDenylist is the subset of the baseline that is suppressed when the
// policy sets AllowNamespaces=true. (The FS-mount primitives stay denied even
// then; only the namespace-entering/creating syscalls are released.)
var namespaceDenylist = map[string]struct{}{
	"unshare": {},
	"setns":   {},
}

// syscallTable maps Go's runtime.GOARCH to a syscall-name -> number table for
// that architecture's NATIVE ABI. Built from the kernel UAPI (verified against
// golang.org/x/sys/unix zsysnum tables). A name absent from a table means that
// arch has no such syscall; resolution skips it (forward-compat).
//
// Numbers are kept here, in pure Go, rather than read from unix.SYS_* so that:
//   - the denylist resolves and is testable on darwin (no Linux build tag), and
//   - the SECONDARY ABI numbers (i386/x32 on amd64, arm on arm64) are available
//     from a 64-bit binary, where unix.SYS_* only exposes the native ABI.
var syscallTable = map[string]map[string]uint32{
	"amd64": {
		"init_module": 175, "finit_module": 313, "delete_module": 176,
		"mount": 165, "umount2": 166, "pivot_root": 155, "mount_setattr": 442,
		"move_mount": 429, "fsopen": 430, "fsconfig": 431, "fsmount": 432, "open_tree": 428,
		"open_by_handle_at": 304, "name_to_handle_at": 303,
		"add_key": 248, "request_key": 249, "keyctl": 250,
		"bpf": 321, "perf_event_open": 298, "userfaultfd": 323,
		"unshare": 272, "setns": 308,
		"settimeofday": 164, "clock_settime": 227, "clock_adjtime": 305, "adjtimex": 159,
		"reboot": 169, "kexec_load": 246, "kexec_file_load": 320,
		"ioperm": 173, "iopl": 172,
		"ptrace": 101, "process_vm_readv": 310, "process_vm_writev": 311,
		"clone": 56, "clone3": 435, "socket": 41,
	},
	"arm64": {
		"init_module": 105, "finit_module": 273, "delete_module": 106,
		"mount": 40, "umount2": 39, "pivot_root": 41, "mount_setattr": 442,
		"move_mount": 429, "fsopen": 430, "fsconfig": 431, "fsmount": 432, "open_tree": 428,
		"open_by_handle_at": 265, "name_to_handle_at": 264,
		"add_key": 217, "request_key": 218, "keyctl": 219,
		"bpf": 280, "perf_event_open": 241, "userfaultfd": 282,
		"unshare": 97, "setns": 268,
		"settimeofday": 170, "clock_settime": 112, "clock_adjtime": 266, "adjtimex": 171,
		"reboot": 142, "kexec_load": 104, "kexec_file_load": 294,
		// ioperm/iopl: arm64 has no I/O-port syscalls — absent on purpose.
		"ptrace": 117, "process_vm_readv": 270, "process_vm_writev": 271,
		"clone": 220, "clone3": 435, "socket": 198,
	},
	// 386 is the secondary ABI on amd64. socket() goes through socketcall(2) on
	// i386, so a direct socket() filter is not meaningful there; socketcall is
	// left out of the family allowlist path (the native filter still applies to
	// the 64-bit entry, which is the one a 64-bit child actually uses).
	"386": {
		"init_module": 128, "finit_module": 350, "delete_module": 129,
		"mount": 21, "umount2": 52, "pivot_root": 217, "mount_setattr": 442,
		"move_mount": 429, "fsopen": 430, "fsconfig": 431, "fsmount": 432, "open_tree": 428,
		"open_by_handle_at": 342, "name_to_handle_at": 341,
		"add_key": 286, "request_key": 287, "keyctl": 288,
		"bpf": 357, "perf_event_open": 336, "userfaultfd": 374,
		"unshare": 310, "setns": 346,
		"settimeofday": 79, "stime": 25, "clock_settime": 264, "clock_adjtime": 343, "adjtimex": 124,
		"reboot": 88, "kexec_load": 283,
		"ioperm": 101, "iopl": 110,
		"ptrace": 26, "process_vm_readv": 347, "process_vm_writev": 348,
		"clone": 120, "clone3": 435, "socket": 359, "socketcall": 102,
	},
	// arm (32-bit) is the secondary ABI on arm64.
	"arm": {
		"init_module": 128, "finit_module": 379, "delete_module": 129,
		"mount": 21, "umount2": 52, "pivot_root": 218, "mount_setattr": 442,
		"move_mount": 429, "fsopen": 430, "fsconfig": 431, "fsmount": 432, "open_tree": 428,
		"open_by_handle_at": 371, "name_to_handle_at": 370,
		"add_key": 309, "request_key": 310, "keyctl": 311,
		"bpf": 386, "perf_event_open": 364, "userfaultfd": 388,
		"unshare": 337, "setns": 375,
		"settimeofday": 79, "clock_settime": 262, "clock_adjtime": 372, "adjtimex": 124,
		"reboot": 88, "kexec_load": 347, "kexec_file_load": 401,
		"ptrace": 26, "process_vm_readv": 376, "process_vm_writev": 377,
		"clone": 120, "clone3": 435, "socket": 281,
	},
}

// secondaryArch returns the 32-bit/secondary ABI arch name paired with a 64-bit
// native arch, or "" if there is no distinct secondary ABI to filter. Emitting a
// filter for the secondary ABI is REQUIRED: a 64-bit process can still enter the
// kernel through the 32-bit syscall ABI (int 0x80 / the compat entry), where the
// syscall NUMBERS differ, so a native-only filter is trivially bypassable.
func secondaryArch(nativeArch string) string {
	switch nativeArch {
	case "amd64":
		return "386"
	case "arm64":
		return "arm"
	default:
		return ""
	}
}

// resolvedSyscall is a baseline/extra entry resolved to its number on one ABI.
type resolvedSyscall struct {
	Name string
	Nr   uint32
}

// resolveNames maps syscall names to numbers for the given arch, dropping any
// name that has no number on that arch (forward-compat skip). Order is preserved.
// This is the function the darwin-runnable tests exercise.
func resolveNames(names []string, arch string) []resolvedSyscall {
	table := syscallTable[arch]
	if table == nil {
		return nil
	}
	out := make([]resolvedSyscall, 0, len(names))
	seen := make(map[uint32]struct{}, len(names))
	for _, name := range names {
		nr, ok := table[name]
		if !ok {
			continue // unknown on this arch — skip (forward-compat)
		}
		if _, dup := seen[nr]; dup {
			continue
		}
		seen[nr] = struct{}{}
		out = append(out, resolvedSyscall{Name: name, Nr: nr})
	}
	return out
}

// syscallNr resolves a single syscall name on an arch, reporting whether it
// exists there.
func syscallNr(name, arch string) (uint32, bool) {
	table := syscallTable[arch]
	if table == nil {
		return 0, false
	}
	nr, ok := table[name]
	return nr, ok
}

// effectiveDenylist returns the baseline plus operator extras, with the
// namespace syscalls removed when the policy allows namespaces. The FS-mount
// primitives always remain. Names are returned (not yet resolved to numbers) so
// the same list can be resolved per-ABI.
func (p Policy) effectiveDenylist() []string {
	out := make([]string, 0, len(BaselineDenylist)+len(p.ExtraDenySyscalls))
	for _, name := range BaselineDenylist {
		if p.AllowNamespaces {
			if _, isNS := namespaceDenylist[name]; isNS {
				continue
			}
		}
		out = append(out, name)
	}
	out = append(out, p.ExtraDenySyscalls...)
	return out
}

// nativeArch is the arch the running binary was built for. Indirected through a
// var so tests can document intent; production always uses runtime.GOARCH.
var nativeArch = runtime.GOARCH
