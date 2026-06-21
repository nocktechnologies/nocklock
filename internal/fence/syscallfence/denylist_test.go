package syscallfence

import (
	"testing"
)

// These tests are darwin-runnable: they exercise the pure-Go name->number
// resolution and policy shaping with NO Linux kernel dependency.

func TestResolveNames_KnownSyscallsResolveToCanonicalNumbers(t *testing.T) {
	// Spot-check a handful of well-known, stable syscall numbers per arch. These
	// are kernel UAPI constants and must never drift.
	cases := []struct {
		arch string
		name string
		want uint32
	}{
		{"amd64", "init_module", 175},
		{"amd64", "ptrace", 101},
		{"amd64", "bpf", 321},
		{"amd64", "socket", 41},
		{"amd64", "connect", 42},
		{"amd64", "unshare", 272},
		{"arm64", "init_module", 105},
		{"arm64", "ptrace", 117},
		{"arm64", "bpf", 280},
		{"arm64", "socket", 198},
		{"386", "init_module", 128},
		{"arm", "init_module", 128},
	}
	for _, c := range cases {
		nr, ok := syscallNr(c.name, c.arch)
		if !ok {
			t.Errorf("syscallNr(%q, %q): not found, want %d", c.name, c.arch, c.want)
			continue
		}
		if nr != c.want {
			t.Errorf("syscallNr(%q, %q) = %d, want %d", c.name, c.arch, nr, c.want)
		}
	}
}

func TestSyscallTable_NumbersMatchSupportedABIs(t *testing.T) {
	// Full-table assertions keep compat ABI constants reviewable on non-Linux CI.
	// These are stable Linux UAPI numbers; changes should be explicit.
	expected := map[string]map[string]uint32{
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
			"clone": 56, "clone3": 435, "socket": 41, "connect": 42,
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
			"ptrace": 117, "process_vm_readv": 270, "process_vm_writev": 271,
			"clone": 220, "clone3": 435, "socket": 198, "connect": 203,
		},
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
			"clone": 120, "clone3": 435, "socket": 359, "socketcall": 102, "connect": 362,
		},
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
			"clone": 120, "clone3": 435, "socket": 281, "connect": 283,
		},
	}

	if len(syscallTable) != len(expected) {
		t.Fatalf("syscallTable has %d arch tables, want %d", len(syscallTable), len(expected))
	}
	for arch, wantTable := range expected {
		gotTable, ok := syscallTable[arch]
		if !ok {
			t.Fatalf("syscallTable missing arch %q", arch)
		}
		if len(gotTable) != len(wantTable) {
			t.Errorf("syscallTable[%q] has %d entries, want %d", arch, len(gotTable), len(wantTable))
		}
		for name, want := range wantTable {
			got, ok := syscallNr(name, arch)
			if !ok {
				t.Errorf("syscallNr(%q, %q): not found, want %d", name, arch, want)
				continue
			}
			if got != want {
				t.Errorf("syscallNr(%q, %q) = %d, want %d", name, arch, got, want)
			}
		}
		for name := range gotTable {
			if _, ok := wantTable[name]; !ok {
				t.Errorf("syscallTable[%q] has unexpected syscall %q", arch, name)
			}
		}
	}
}

func TestResolveNames_UnknownNameIsSkipped_ForwardCompat(t *testing.T) {
	// A made-up syscall and a real syscall that does not exist on the target arch
	// must both be SKIPPED, not error. This is the forward-compat contract: a
	// kernel that lacks a syscall cannot have it called, so there is nothing to
	// deny.
	names := []string{"init_module", "totally_not_a_real_syscall_xyz", "ptrace"}
	got := resolveNames(names, "amd64")
	if len(got) != 2 {
		t.Fatalf("resolveNames skipped/kept wrong count: got %d entries %+v, want 2", len(got), got)
	}
	if got[0].Name != "init_module" || got[1].Name != "ptrace" {
		t.Errorf("resolveNames order/skip wrong: %+v", got)
	}
}

func TestResolveNames_ArchSpecificAbsence_IsSkipped(t *testing.T) {
	// ioperm/iopl are x86-only; arm64 has no I/O-port syscalls. They must resolve
	// on amd64 but be skipped on arm64 (forward-compat skip, not an error).
	if _, ok := syscallNr("ioperm", "amd64"); !ok {
		t.Errorf("ioperm should resolve on amd64")
	}
	if _, ok := syscallNr("ioperm", "arm64"); ok {
		t.Errorf("ioperm must NOT resolve on arm64 (no I/O-port syscalls)")
	}
	if _, ok := syscallNr("iopl", "arm64"); ok {
		t.Errorf("iopl must NOT resolve on arm64")
	}
}

func TestResolveNames_UnknownArchReturnsNil(t *testing.T) {
	if got := resolveNames(BaselineDenylist, "sparc64"); got != nil {
		t.Errorf("resolveNames on unknown arch should be nil, got %+v", got)
	}
}

func TestResolveNames_DeduplicatesByNumber(t *testing.T) {
	// Passing the same name twice must not emit two filter rules for one number.
	got := resolveNames([]string{"ptrace", "ptrace"}, "amd64")
	if len(got) != 1 {
		t.Errorf("resolveNames should dedupe by number, got %+v", got)
	}
}

func TestBaselineDenylist_FullyResolvesOnSupportedArches(t *testing.T) {
	// Every baseline entry must resolve on at least one supported arch (catches a
	// typo'd name that would silently never deny anything anywhere).
	arches := []string{"amd64", "arm64", "386", "arm"}
	for _, name := range BaselineDenylist {
		found := false
		for _, arch := range arches {
			if _, ok := syscallNr(name, arch); ok {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("baseline syscall %q resolves on NO supported arch — likely a typo (it would silently never deny)", name)
		}
	}
}

func TestBaselineDenylist_CoversRequiredSubsystems(t *testing.T) {
	// Guard the security contract: the headline dangerous primitives must be
	// present in the baseline.
	required := []string{
		"init_module", "finit_module", "delete_module",
		"mount", "umount2", "pivot_root", "open_tree", "move_mount",
		"open_by_handle_at", "name_to_handle_at",
		"add_key", "request_key", "keyctl",
		"bpf", "perf_event_open", "userfaultfd",
		"unshare", "setns",
		"settimeofday", "clock_settime", "adjtimex",
		"reboot", "kexec_load", "kexec_file_load",
		"ioperm", "iopl",
		"ptrace", "process_vm_readv", "process_vm_writev",
		"socketcall",
	}
	set := make(map[string]struct{}, len(BaselineDenylist))
	for _, n := range BaselineDenylist {
		set[n] = struct{}{}
	}
	for _, r := range required {
		if _, ok := set[r]; !ok {
			t.Errorf("BaselineDenylist is missing required syscall %q", r)
		}
	}
}

func TestConnectSyscallResolvesForExtraDeny(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64", "386", "arm"} {
		if _, ok := syscallNr("connect", arch); !ok {
			t.Errorf("connect must resolve on %s so wrap can deny direct sockets when network fence is active", arch)
		}
	}
}

func TestEffectiveDenylist_AllowNamespacesReleasesUnshareSetns(t *testing.T) {
	denied := Policy{AllowNamespaces: false}.effectiveDenylist()
	if !containsName(denied, "unshare") || !containsName(denied, "setns") {
		t.Fatalf("with AllowNamespaces=false, unshare+setns must be denied: %v", denied)
	}

	allowed := Policy{AllowNamespaces: true}.effectiveDenylist()
	if containsName(allowed, "unshare") || containsName(allowed, "setns") {
		t.Errorf("with AllowNamespaces=true, unshare+setns must NOT be in the denylist: %v", allowed)
	}
	// FS-mount primitives must remain denied even when namespaces are allowed.
	for _, mustStay := range []string{"mount", "pivot_root", "open_tree"} {
		if !containsName(allowed, mustStay) {
			t.Errorf("with AllowNamespaces=true, %q must STILL be denied (FS-mount primitive)", mustStay)
		}
	}
}

func TestEffectiveDenylist_AppendsExtras(t *testing.T) {
	denied := Policy{ExtraDenySyscalls: []string{"chroot", "acct"}}.effectiveDenylist()
	if !containsName(denied, "chroot") || !containsName(denied, "acct") {
		t.Errorf("extras not appended: %v", denied)
	}
}

func TestSecondaryArch(t *testing.T) {
	cases := map[string]string{
		"amd64":   "386",
		"arm64":   "arm",
		"riscv64": "",
		"386":     "", // already 32-bit; no further secondary ABI to emit
	}
	for native, want := range cases {
		if got := secondaryArch(native); got != want {
			t.Errorf("secondaryArch(%q) = %q, want %q", native, got, want)
		}
	}
}

func TestPolicy_IsZero(t *testing.T) {
	if !(Policy{}).IsZero() {
		t.Error("empty Policy should be zero (no behaviour change)")
	}
	if !(Policy{Mode: ModeOff}).IsZero() {
		t.Error("Mode=off Policy should be zero")
	}
	if (Policy{Mode: ModePreferred}).IsZero() {
		t.Error("Mode=preferred Policy should NOT be zero")
	}
	if (Policy{Mode: ModeRequired}).IsZero() {
		t.Error("Mode=required Policy should NOT be zero")
	}
}

func containsName(list []string, name string) bool {
	for _, n := range list {
		if n == name {
			return true
		}
	}
	return false
}
