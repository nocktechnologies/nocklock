//go:build linux

package syscallfence

import (
	"testing"

	"golang.org/x/sys/unix"
)

// Structural tests for the assembled BPF program. These are gated to linux only
// because they reference the assembler types/constants from seccomp_linux.go,
// but they do NOT call seccomp(2) — they validate program structure in memory,
// so they run on a Linux CI runner without special privileges.

// simulate runs the classic-BPF program against a synthetic seccomp_data and
// returns the action word the program would produce. It implements just the
// opcode subset the assembler emits (LD/ABS/W, JMP/JEQ/JSET/K, RET/K).
func simulate(prog []unix.SockFilter, data seccompData) (uint32, error) {
	var a uint32
	pc := 0
	for pc < len(prog) {
		ins := prog[pc]
		class := ins.Code & 0x07
		switch class {
		case bpfLD:
			a = data.load(ins.K)
			pc++
		case bpfJMP:
			op := ins.Code & 0xf0
			switch op {
			case bpfJEQ:
				if a == ins.K {
					pc += 1 + int(ins.Jt)
				} else {
					pc += 1 + int(ins.Jf)
				}
			case bpfJSET:
				if a&ins.K != 0 {
					pc += 1 + int(ins.Jt)
				} else {
					pc += 1 + int(ins.Jf)
				}
			default:
				return 0, errBadOp
			}
		case bpfRET:
			return ins.K, nil
		default:
			return 0, errBadOp
		}
	}
	return 0, errFellOff
}

var (
	errBadOp   = errStr("unsupported BPF opcode in simulator")
	errFellOff = errStr("program fell off the end without RET")
)

type errStr string

func (e errStr) Error() string { return string(e) }

// seccompData is a synthetic struct seccomp_data for the simulator.
type seccompData struct {
	nr   uint32
	arch uint32
	args [6]uint32 // low 32 bits of each arg (all the assembler ever reads)
}

func (d seccompData) load(off uint32) uint32 {
	switch {
	case off == offNr:
		return d.nr
	case off == offArch:
		return d.arch
	case off >= offArgsLow:
		idx := (off - offArgsLow) / 8
		if int(idx) < len(d.args) {
			return d.args[idx]
		}
	}
	return 0
}

func eperm() uint32  { return retErrnoAction(uint32(unix.EPERM)) }
func enosys() uint32 { return retErrnoAction(uint32(unix.ENOSYS)) }

func buildTestProgram(t *testing.T, p Policy) ([]unix.SockFilter, abiFilter) {
	t.Helper()
	filters, err := p.buildABIFilters()
	if err != nil {
		t.Fatalf("buildABIFilters: %v", err)
	}
	prog := assembleProgram(filters)
	if len(prog) == 0 {
		t.Fatal("assembled empty program")
	}
	// Return the native ABI filter for argument construction.
	return prog, filters[0]
}

func TestProgram_DeniedSyscallReturnsEPERM(t *testing.T) {
	p := Policy{Mode: ModeRequired}
	prog, native := buildTestProgram(t, p)

	nr, _ := syscallNr("init_module", native.arch)
	got, err := simulate(prog, seccompData{nr: nr, arch: native.auditArch})
	if err != nil {
		t.Fatal(err)
	}
	if got != eperm() {
		t.Errorf("init_module: got %#x, want EPERM %#x", got, eperm())
	}
}

func TestProgram_AllowedSyscallReturnsAllow(t *testing.T) {
	p := Policy{Mode: ModeRequired}
	prog, native := buildTestProgram(t, p)

	// read(2) is never denied; it should ALLOW. read=0 on amd64, 63 on arm64.
	readNr := uint32(0)
	if native.arch == "arm64" || native.arch == "arm" {
		readNr = 63
	}
	got, err := simulate(prog, seccompData{nr: readNr, arch: native.auditArch})
	if err != nil {
		t.Fatal(err)
	}
	if got != retAllow {
		t.Errorf("read: got %#x, want ALLOW %#x", got, retAllow)
	}
}

func TestProgram_Clone3ReturnsENOSYSNotEPERM(t *testing.T) {
	// HEADLINE: clone3 must be ENOSYS so glibc falls back to legacy clone;
	// EPERM here breaks pthread_create on glibc>=2.34.
	p := Policy{Mode: ModeRequired}
	prog, native := buildTestProgram(t, p)

	nr, _ := syscallNr("clone3", native.arch)
	got, err := simulate(prog, seccompData{nr: nr, arch: native.auditArch})
	if err != nil {
		t.Fatal(err)
	}
	if got == eperm() {
		t.Fatalf("clone3 returned EPERM — would break pthread_create; must be ENOSYS")
	}
	if got != enosys() {
		t.Errorf("clone3: got %#x, want ENOSYS %#x", got, enosys())
	}
}

func TestProgram_CloneNamespaceBitDeniedButPlainCloneAllowed(t *testing.T) {
	p := Policy{Mode: ModeRequired} // AllowNamespaces defaults false
	prog, native := buildTestProgram(t, p)
	cloneNr, _ := syscallNr("clone", native.arch)

	// Plain clone (pthread_create-style flags, no CLONE_NEW*) must ALLOW.
	plainFlags := uint32(unix.CLONE_VM | unix.CLONE_FS | unix.CLONE_FILES | unix.CLONE_THREAD)
	got, err := simulate(prog, seccompData{nr: cloneNr, arch: native.auditArch, args: [6]uint32{plainFlags}})
	if err != nil {
		t.Fatal(err)
	}
	if got != retAllow {
		t.Errorf("plain clone (no CLONE_NEW*): got %#x, want ALLOW (pthread_create must work)", got)
	}

	// clone with CLONE_NEWUSER must be denied EPERM.
	nsFlags := uint32(unix.CLONE_NEWUSER)
	got, err = simulate(prog, seccompData{nr: cloneNr, arch: native.auditArch, args: [6]uint32{nsFlags}})
	if err != nil {
		t.Fatal(err)
	}
	if got != eperm() {
		t.Errorf("clone(CLONE_NEWUSER): got %#x, want EPERM", got)
	}
}

func TestProgram_CloneNamespaceAllowedWhenPolicyPermits(t *testing.T) {
	p := Policy{Mode: ModeRequired, AllowNamespaces: true}
	prog, native := buildTestProgram(t, p)
	cloneNr, _ := syscallNr("clone", native.arch)

	got, err := simulate(prog, seccompData{nr: cloneNr, arch: native.auditArch, args: [6]uint32{uint32(unix.CLONE_NEWUSER)}})
	if err != nil {
		t.Fatal(err)
	}
	if got != retAllow {
		t.Errorf("with AllowNamespaces=true, clone(CLONE_NEWUSER) should ALLOW, got %#x", got)
	}
	// unshare must no longer be denied either.
	unshareNr, _ := syscallNr("unshare", native.arch)
	got, err = simulate(prog, seccompData{nr: unshareNr, arch: native.auditArch})
	if err != nil {
		t.Fatal(err)
	}
	if got != retAllow {
		t.Errorf("with AllowNamespaces=true, unshare should ALLOW, got %#x", got)
	}
}

func TestProgram_SocketFamilyAllowlistDeniesComplement(t *testing.T) {
	p := Policy{
		Mode:                  ModeRequired,
		AllowedSocketFamilies: []string{"unix", "inet", "inet6"},
	}
	prog, native := buildTestProgram(t, p)
	if native.arch == "386" {
		t.Skip("socket() is multiplexed via socketcall on i386")
	}
	socketNr, _ := syscallNr("socket", native.arch)

	// AF_INET allowed.
	got, err := simulate(prog, seccompData{nr: socketNr, arch: native.auditArch, args: [6]uint32{uint32(unix.AF_INET)}})
	if err != nil {
		t.Fatal(err)
	}
	if got != retAllow {
		t.Errorf("socket(AF_INET): got %#x, want ALLOW", got)
	}

	// AF_PACKET (raw) NOT in the allowlist -> EPERM.
	got, err = simulate(prog, seccompData{nr: socketNr, arch: native.auditArch, args: [6]uint32{uint32(unix.AF_PACKET)}})
	if err != nil {
		t.Fatal(err)
	}
	if got != eperm() {
		t.Errorf("socket(AF_PACKET): got %#x, want EPERM (deny-the-complement)", got)
	}

	// AF_NETLINK also not in the allowlist -> EPERM.
	got, err = simulate(prog, seccompData{nr: socketNr, arch: native.auditArch, args: [6]uint32{uint32(unix.AF_NETLINK)}})
	if err != nil {
		t.Fatal(err)
	}
	if got != eperm() {
		t.Errorf("socket(AF_NETLINK): got %#x, want EPERM", got)
	}
}

func TestProgram_ForeignArchDoesNotMatchNativeRules(t *testing.T) {
	// A syscall number that is denied on the native ABI must NOT be accidentally
	// denied/allowed by the native block when the arch token is the SECONDARY ABI
	// (the multi-arch guard must route it to the secondary block). We assert the
	// program still terminates with a valid action for the secondary arch token.
	p := Policy{Mode: ModeRequired}
	prog, _ := buildTestProgram(t, p)

	sec := secondaryArch(nativeArch)
	if sec == "" {
		t.Skip("no secondary ABI on this arch")
	}
	secAudit, _ := auditArchFor(sec)
	initNr, _ := syscallNr("init_module", sec)
	got, err := simulate(prog, seccompData{nr: initNr, arch: secAudit})
	if err != nil {
		t.Fatal(err)
	}
	if got != eperm() {
		t.Errorf("init_module on secondary ABI %q: got %#x, want EPERM (32-bit entry must be filtered too)", sec, got)
	}
}

func TestProgram_PtraceAndProcessVMDenied(t *testing.T) {
	p := Policy{Mode: ModeRequired}
	prog, native := buildTestProgram(t, p)
	for _, name := range []string{"ptrace", "process_vm_readv", "process_vm_writev"} {
		nr, ok := syscallNr(name, native.arch)
		if !ok {
			t.Fatalf("%s should resolve on %s", name, native.arch)
		}
		got, err := simulate(prog, seccompData{nr: nr, arch: native.auditArch})
		if err != nil {
			t.Fatal(err)
		}
		if got != eperm() {
			t.Errorf("%s: got %#x, want EPERM", name, got)
		}
	}
}

func TestProgram_WithinInstructionCap(t *testing.T) {
	// Worst case: every option on. The classic-BPF cap is 4096 instructions.
	p := Policy{
		Mode:                  ModeRequired,
		AllowedSocketFamilies: []string{"unix", "inet", "inet6", "netlink"},
		ExtraDenySyscalls:     []string{"chroot", "acct", "swapon", "swapoff"},
	}
	filters, err := p.buildABIFilters()
	if err != nil {
		t.Fatal(err)
	}
	prog := assembleProgram(filters)
	if len(prog) > 4096 {
		t.Errorf("program is %d instructions, exceeds 4096 cap", len(prog))
	}
}
