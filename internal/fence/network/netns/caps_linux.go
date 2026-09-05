//go:build linux

package netns

// The five-set fence capability drop.
//
// This is the receipted Q6 cap-drop harness, lifted verbatim out of
// netns_bypass_linux_test.go so the PRODUCTION privileged helper
// (SetupAndExec) and the acceptance tests drop capabilities with the exact same
// code — the spec's "reuse the receipted Q6 cap-drop harness; do not reinvent"
// (2026-08-24 amendment). The Q6 mutation-resistance test and the Phase-1
// foundation egress test both exercise this drop, so any regression here fails a
// receipted CI gate.

import (
	"fmt"

	"golang.org/x/sys/unix"
)

// caps is the exact setup-only set the child drops from every capability set.
// CAP_SETPCAP stays effective until last so the preceding bounding-set drops are
// permitted, then is itself removed before exec.
var caps = []uintptr{unix.CAP_NET_ADMIN, unix.CAP_SYS_ADMIN, unix.CAP_SETPCAP}

// dropCaps removes each capability in `caps` from every capability set of the
// calling thread: bounding, ambient, then effective/permitted/inheritable.
// Bounding is dropped first, while CAP_SETPCAP is still held.
func dropCaps() error {
	// Bounding set — one PR_CAPBSET_DROP per capability. This is what prevents the
	// exec'd root tool from regaining the capability across execve.
	for _, c := range caps {
		if err := unix.Prctl(unix.PR_CAPBSET_DROP, c, 0, 0, 0); err != nil {
			return fmt.Errorf("PR_CAPBSET_DROP %d: %w", c, err)
		}
	}

	// Ambient set — clear all. Ambient caps are a subset of the permitted+
	// inheritable pair we clear below, so clearing the whole ambient set is a
	// complete (and simplest) way to ensure neither target cap is ambient.
	if err := unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0); err != nil {
		return fmt.Errorf("PR_CAP_AMBIENT_CLEAR_ALL: %w", err)
	}

	// Effective, permitted, inheritable — read the current sets, clear exactly the
	// target bits, write them back. Clearing bits is always permitted.
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capget: %w", err)
	}
	for _, c := range caps {
		word := c >> 5 // 32 capabilities per CapUserData word
		bit := uint32(1) << (c & 31)
		data[word].Effective &^= bit
		data[word].Permitted &^= bit
		data[word].Inheritable &^= bit
	}
	if err := unix.Capset(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capset: %w", err)
	}
	return nil
}

// assertCapsDropped verifies the post-drop credential directly before exec.
func assertCapsDropped() error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return fmt.Errorf("capget: %w", err)
	}
	for _, c := range caps {
		word := c >> 5
		bit := uint32(1) << (c & 31)
		if data[word].Effective&bit != 0 || data[word].Permitted&bit != 0 || data[word].Inheritable&bit != 0 {
			return fmt.Errorf("capability %d remains in effective, permitted, or inheritable set", c)
		}
		ambient, err := unix.PrctlRetInt(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET, c, 0, 0)
		if err != nil {
			return fmt.Errorf("PR_CAP_AMBIENT_IS_SET %d: %w", c, err)
		}
		if ambient != 0 {
			return fmt.Errorf("capability %d remains in ambient set", c)
		}
		bounding, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, c, 0, 0, 0)
		if err != nil {
			return fmt.Errorf("PR_CAPBSET_READ %d: %w", c, err)
		}
		if bounding != 0 {
			return fmt.Errorf("capability %d remains in bounding set", c)
		}
	}
	return nil
}
