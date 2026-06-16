//go:build linux

package syscallfence

import (
	"fmt"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// seccomp-BPF assembly for the syscall fence. This is a hand-built classic-BPF
// program (the only program type seccomp(2) accepts) installed with
// SECCOMP_SET_MODE_FILTER. No cgo, no libseccomp — just x/sys/unix.
//
// The headline property is ALL-OR-NOTHING: PR_SET_NO_NEW_PRIVS is set first, the
// full program is assembled in memory, and only a single successful seccomp(2)
// call flips enforcement on. There is no point at which a partial filter is live.
// Apply either returns nil with the whole filter installed, or returns an error
// having installed nothing that weakens the process (NO_NEW_PRIVS only tightens).

// Classic-BPF opcodes. Defined locally so the assembler does not depend on
// whether x/sys exports them portably; values are the stable BPF UAPI.
const (
	bpfLD   = 0x00
	bpfW    = 0x00
	bpfABS  = 0x20
	bpfJMP  = 0x05
	bpfJEQ  = 0x10
	bpfJSET = 0x40
	bpfRET  = 0x06
	bpfK    = 0x00
)

// seccomp_data field offsets (struct seccomp_data: nr, arch, instruction_pointer,
// args[6]). All little-endian 32-bit loads via BPF_ABS.
const (
	offNr      = 0  // int  nr
	offArch    = 4  // __u32 arch
	offArgsLow = 16 // args[0] low 32 bits (args start at offset 16; each arg is 8 bytes)
)

// argLowOffset returns the BPF_ABS offset of the low 32 bits of arg n.
func argLowOffset(n uint32) uint32 { return offArgsLow + n*8 }

// seccomp return actions.
const (
	retAllow = uint32(0x7fff0000) // SECCOMP_RET_ALLOW
	retErrno = uint32(0x00050000) // SECCOMP_RET_ERRNO base; OR the errno into the low 16 bits
)

func retErrnoAction(errno uint32) uint32 { return retErrno | (errno & 0x0000ffff) }

// abiFilter is one architecture's view of the filter: the AUDIT_ARCH token that
// identifies it in seccomp_data.arch, and the resolved syscall numbers for that
// ABI. We emit one abiFilter for the native arch and one for the secondary
// (32-bit) ABI, because a 64-bit process can still enter the kernel through the
// compat ABI where the numbers differ — a native-only filter is bypassable.
type abiFilter struct {
	arch        string // Go GOARCH key into syscallTable
	auditArch   uint32 // AUDIT_ARCH_* token
	deny        []resolvedSyscall
	clone       cloneInfo
	socketAllow socketInfo
}

type cloneInfo struct {
	cloneNr   uint32
	clone3Nr  uint32
	hasClone  bool
	hasClone3 bool
}

type socketInfo struct {
	socketNr  uint32
	hasSocket bool
	families  []uint32 // allowed AF_* values; empty => no socket restriction
}

// auditArchFor maps a Go arch to its AUDIT_ARCH token.
func auditArchFor(arch string) (uint32, bool) {
	switch arch {
	case "amd64":
		return unix.AUDIT_ARCH_X86_64, true
	case "386":
		return unix.AUDIT_ARCH_I386, true
	case "arm64":
		return unix.AUDIT_ARCH_AARCH64, true
	case "arm":
		return unix.AUDIT_ARCH_ARM, true
	default:
		return 0, false
	}
}

// socketFamilyValue maps a config family name to its AF_* constant.
func socketFamilyValue(name string) (uint32, bool) {
	switch name {
	case "unix", "local":
		return uint32(unix.AF_UNIX), true
	case "inet", "ipv4":
		return uint32(unix.AF_INET), true
	case "inet6", "ipv6":
		return uint32(unix.AF_INET6), true
	case "netlink":
		return uint32(unix.AF_NETLINK), true
	default:
		return 0, false
	}
}

// cloneNamespaceMask is the OR of all CLONE_NEW* bits. clone(2) with any of these
// in arg0 creates a namespace; we deny exactly those calls (masked-equality on
// arg0) while leaving ordinary clone()/fork()/pthread_create() — which pass none
// of these bits — allowed.
const cloneNamespaceMask = uint32(unix.CLONE_NEWNS |
	unix.CLONE_NEWCGROUP |
	unix.CLONE_NEWUTS |
	unix.CLONE_NEWIPC |
	unix.CLONE_NEWUSER |
	unix.CLONE_NEWPID |
	unix.CLONE_NEWNET |
	unix.CLONE_NEWTIME)

// Supported reports whether seccomp-BPF can be enforced on this kernel. It does a
// cheap, side-effect-free probe (a strict-mode check via prctl is avoided since
// that would terminate the thread); instead we treat Linux as supported and let
// Apply surface a precise error if the seccomp(2) call is rejected.
func Supported() bool {
	// PR_GET_SECCOMP returns the current mode without side effects; ENOSYS means
	// the kernel lacks CONFIG_SECCOMP.
	_, _, errno := unix.Syscall(unix.SYS_PRCTL, unix.PR_GET_SECCOMP, 0, 0)
	return errno != unix.ENOSYS
}

// Apply installs the syscall fence described by p. It MUST be called from the
// re-exec shim, on the thread that will execve, after NO_NEW_PRIVS/Landlock and
// immediately before execve. It is fail-closed and all-or-nothing.
func Apply(p Policy) error {
	if p.IsZero() {
		return nil
	}

	// 1. NO_NEW_PRIVS FIRST. seccomp(2) without CAP_SYS_ADMIN requires it, and it
	//    is the property that makes the filter irrevocable across execve. Set it
	//    before assembling anything so the process can never gain privileges that
	//    would let a child shed the filter.
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return fmt.Errorf("syscallfence: PR_SET_NO_NEW_PRIVS: %w", err)
	}

	filters, err := p.buildABIFilters()
	if err != nil {
		return err
	}

	prog := assembleProgram(filters)
	if len(prog) == 0 {
		// Nothing to enforce (e.g. no resolvable syscalls AND no socket/ns
		// restriction). Treat as a no-op rather than installing an empty filter.
		return nil
	}

	if err := installFilter(prog); err != nil {
		return fmt.Errorf("syscallfence: install filter: %w", err)
	}
	return nil
}

// buildABIFilters resolves the policy into one abiFilter per ABI we must cover
// (native + secondary 32-bit). An ABI whose AUDIT_ARCH token is unknown is
// skipped (the native one is required; its absence is an error).
func (p Policy) buildABIFilters() ([]abiFilter, error) {
	denyNames := p.effectiveDenylist()

	var families []uint32
	for _, fam := range p.AllowedSocketFamilies {
		v, ok := socketFamilyValue(fam)
		if !ok {
			return nil, fmt.Errorf("syscallfence: unknown socket family %q", fam)
		}
		families = append(families, v)
	}

	arches := []string{nativeArch}
	if sec := secondaryArch(nativeArch); sec != "" {
		arches = append(arches, sec)
	}

	out := make([]abiFilter, 0, len(arches))
	for i, arch := range arches {
		auditArch, ok := auditArchFor(arch)
		if !ok {
			if i == 0 {
				return nil, fmt.Errorf("syscallfence: unsupported native arch %q", arch)
			}
			continue // secondary ABI we cannot name: skip rather than fail
		}

		f := abiFilter{
			arch:      arch,
			auditArch: auditArch,
			deny:      resolveNames(denyNames, arch),
		}
		if nr, ok := syscallNr("clone", arch); ok && !p.AllowNamespaces {
			f.clone.cloneNr = nr
			f.clone.hasClone = true
		}
		if nr, ok := syscallNr("clone3", arch); ok && !p.AllowNamespaces {
			f.clone.clone3Nr = nr
			f.clone.hasClone3 = true
		}
		if len(families) > 0 {
			// socket() on i386 is multiplexed through socketcall(2); a direct
			// socket() family filter is not reliable there, so only install the
			// family allowlist where socket() is a first-class syscall.
			if nr, ok := syscallNr("socket", arch); ok && arch != "386" {
				f.socketAllow.socketNr = nr
				f.socketAllow.hasSocket = true
				f.socketAllow.families = families
			}
		}
		out = append(out, f)
	}
	return out, nil
}

// assembleProgram lays out the full classic-BPF program:
//
//	load arch
//	for each ABI:
//	    if arch != this.auditArch: jump past this ABI's block
//	    load nr
//	    clone3 handling (ENOSYS, so glibc falls back to legacy clone)
//	    clone CLONE_NEW* masked-equality -> EPERM
//	    each denied nr -> EPERM
//	    socket family allowlist (deny-the-complement) -> EPERM
//	default: ALLOW
//
// Because seccomp programs are flat with relative forward jumps and a hard 4096
// instruction cap, we build the instruction slice in two passes: first compute
// each block's size to resolve the "skip this ABI" jump distance, then emit.
func assembleProgram(filters []abiFilter) []unix.SockFilter {
	if len(filters) == 0 {
		return nil
	}

	// Tail: a single ALLOW that every non-denied path falls through to.
	allow := stmt(bpfRET|bpfK, retAllow)

	// Build each ABI's body (everything after the arch-guard jump). We measure it
	// first so the arch-guard jump can skip exactly over it.
	bodies := make([][]unix.SockFilter, len(filters))
	for i, f := range filters {
		bodies[i] = abiBody(f)
	}

	prog := make([]unix.SockFilter, 0, 64)
	// load arch into A
	prog = append(prog, stmt(bpfLD|bpfW|bpfABS, offArch))

	for i, f := range filters {
		body := bodies[i]
		// if A != auditArch -> jump over (len(body)) instrs to the next ABI guard.
		// BPF jumps are relative to the NEXT instruction; jt taken when EQ.
		// We want: if arch == auditArch fall through into body; else skip body.
		// jeq auditArch, jt=0 (fall through), jf=len(body) (skip).
		prog = append(prog, jump(bpfJMP|bpfJEQ|bpfK, f.auditArch, 0, uint8(len(body))))
		prog = append(prog, body...)
	}

	prog = append(prog, allow)
	return prog
}

// abiBody emits the per-ABI instruction block. It assumes A still holds arch on
// entry is NOT true — each body re-loads nr first. (The arch-guard above only
// gates entry into the body.)
func abiBody(f abiFilter) []unix.SockFilter {
	body := make([]unix.SockFilter, 0, 16)
	// load nr into A
	body = append(body, stmt(bpfLD|bpfW|bpfABS, offNr))

	// clone3 -> ENOSYS (NOT EPERM). glibc>=2.34 probes clone3 and, on ENOSYS,
	// falls back to the legacy arg-filtered clone; returning EPERM here instead
	// would break pthread_create. We deny namespace creation on the legacy clone
	// path below.
	if f.clone.hasClone3 {
		body = append(body,
			jump(bpfJMP|bpfJEQ|bpfK, f.clone.clone3Nr, 0, 1),
			stmt(bpfRET|bpfK, retErrnoAction(uint32(unix.ENOSYS))),
		)
	}

	// clone with any CLONE_NEW* bit in arg0 -> EPERM (masked equality). Ordinary
	// clone()/fork()/pthread_create() pass none of these bits and fall through to
	// ALLOW.
	if f.clone.hasClone {
		// if nr == clone -> evaluate arg0 mask; else skip the 3 clone instrs.
		body = append(body,
			jump(bpfJMP|bpfJEQ|bpfK, f.clone.cloneNr, 0, 3),
			stmt(bpfLD|bpfW|bpfABS, argLowOffset(0)),
			// if (arg0 & mask) != 0 -> deny. BPF_JSET takes the jt branch when any
			// masked bit is set.
			jump(bpfJMP|bpfJSET|bpfK, cloneNamespaceMask, 0, 1),
			stmt(bpfRET|bpfK, retErrnoAction(uint32(unix.EPERM))),
			// reload nr for the subsequent equality checks (A was overwritten by
			// the arg0 load above).
			stmt(bpfLD|bpfW|bpfABS, offNr),
		)
	}

	// Flat denylist: each resolved number -> EPERM.
	deny := stmt(bpfRET|bpfK, retErrnoAction(uint32(unix.EPERM)))
	for _, rs := range f.deny {
		body = append(body,
			jump(bpfJMP|bpfJEQ|bpfK, rs.Nr, 0, 1),
			deny,
		)
	}

	// socket() family allowlist: deny the complement. We compare nr to socket;
	// if it matches, load arg0 (domain) and ALLOW only if it equals one of the
	// allowed families, else EPERM.
	if f.socketAllow.hasSocket && len(f.socketAllow.families) > 0 {
		fams := f.socketAllow.families
		// Layout (deny-the-complement):
		//   [0]            jeq socket, jf=blockLen   ; not socket -> skip block
		//   [1]            LD arg0 (domain)
		//   [2..2+N-1]     jeq fam_i, jt=skip_i, jf=0 ; match -> jump to ALLOW
		//   [2+N]          RET EPERM                  ; no family matched
		//   [2+N+1]        RET ALLOW                  ; an allowed family matched
		// blockLen counts every instruction AFTER the socket-guard jeq:
		// 1 (LD) + N (jeqs) + 1 (deny) + 1 (allow).
		blockLen := 1 + len(fams) + 2
		body = append(body, jump(bpfJMP|bpfJEQ|bpfK, f.socketAllow.socketNr, 0, uint8(blockLen)))
		body = append(body, stmt(bpfLD|bpfW|bpfABS, argLowOffset(0))) // domain
		// A matching jeq must skip the remaining jeqs AND the trailing deny to land
		// on the final ALLOW. For the i-th jeq (0-based), instructions between it
		// and ALLOW are: (N-1-i) remaining jeqs + 1 deny.
		for i, fam := range fams {
			skip := uint8(len(fams) - 1 - i + 1)
			body = append(body, jump(bpfJMP|bpfJEQ|bpfK, fam, skip, 0))
		}
		body = append(body, deny)                        // no allowed family matched -> EPERM
		body = append(body, stmt(bpfRET|bpfK, retAllow)) // allowed family matched
	}

	return body
}

// installFilter performs the seccomp(2) SET_MODE_FILTER call with TSYNC so the
// filter applies to every thread of the (single-threaded-at-execve) process.
func installFilter(prog []unix.SockFilter) error {
	if len(prog) == 0 {
		return fmt.Errorf("empty BPF program")
	}
	if len(prog) > 4096 {
		return fmt.Errorf("BPF program too long (%d > 4096 instructions)", len(prog))
	}
	fprog := &unix.SockFprog{
		Len:    uint16(len(prog)),
		Filter: &prog[0],
	}
	_, _, errno := unix.Syscall(
		unix.SYS_SECCOMP,
		uintptr(unix.SECCOMP_SET_MODE_FILTER),
		uintptr(unix.SECCOMP_FILTER_FLAG_TSYNC),
		uintptr(unsafe.Pointer(fprog)),
	)
	if errno != 0 {
		// Keep prog alive across the syscall.
		runtime.KeepAlive(prog)
		return fmt.Errorf("seccomp(SET_MODE_FILTER): %w", errno)
	}
	runtime.KeepAlive(prog)
	return nil
}

// stmt builds a non-jump BPF instruction.
func stmt(code uint16, k uint32) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: 0, Jf: 0, K: k}
}

// jump builds a conditional/absolute BPF jump instruction.
func jump(code uint16, k uint32, jt, jf uint8) unix.SockFilter {
	return unix.SockFilter{Code: code, Jt: jt, Jf: jf, K: k}
}
