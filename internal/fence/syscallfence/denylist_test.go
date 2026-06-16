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
