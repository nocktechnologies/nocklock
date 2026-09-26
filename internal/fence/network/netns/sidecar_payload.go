package netns

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
)

// sidecarPayloadFD is the fixed inherited descriptor on which every sidecar
// startSidecar spawns (the transparent proxy, the host-side proxy, and the fenced
// child) receives its JSON payload. Keeping the payload off stdin (fd 0) is what
// lets the __netns-child sidecar inherit the caller's REAL stdin unchanged, so an
// interactive or piped agent under `--net-fence=netns` keeps its input stream
// (N10711). startSidecar passes the read end as the first (and only) entry of
// exec.Cmd.ExtraFiles, which the Go runtime maps to fd 3.
//
// NOTE: the __netns-cleanup and __netns-child-kill-watchdog sidecars are spawned
// separately (not via startSidecar) and use fd 3 for a DIFFERENT purpose — the
// parent-exit EOF pipe — while carrying their own (small, fixed) payload on
// stdin. Those processes are never in the child's input path, so the two fd-3
// conventions do not collide; a new payload-bearing sidecar should go through
// startSidecar and read fd 3 here.
const sidecarPayloadFD = 3

// ReadSidecarPayload decodes the JSON payload handed to a sidecar on the
// dedicated inherited descriptor (fd 3) into v. It FAILS CLOSED when the
// descriptor was not provided or is not readable: a sidecar must never silently
// fall back to reading its configuration from the caller's stdin (that is exactly
// the bug this channel removes). It is the negative-control surface for
// acceptance #4 — the helper refuses to start when the setup fd is missing.
func ReadSidecarPayload(v any) error {
	f := os.NewFile(uintptr(sidecarPayloadFD), "nocklock-sidecar-payload")
	if f != nil {
		// Close fd 3 once decoded so the payload pipe never leaks into the child
		// the __netns-child sidecar execs.
		defer f.Close()
	}
	return readSidecarPayloadFrom(f, v)
}

// readSidecarPayloadFrom is the testable core of ReadSidecarPayload: it validates
// that the payload descriptor is present and open, then decodes it. Split out so
// the fail-closed behaviour can be exercised without juggling process fd 3.
func readSidecarPayloadFrom(f *os.File, v any) error {
	// The nil guard is defensive and test-facing: os.NewFile returns non-nil even
	// for a closed/absent fd 3, so in production a missing descriptor fails closed
	// at the Stat (EBADF) below, not here.
	if f == nil {
		return errors.New("netns sidecar payload descriptor (fd 3) not provided; refusing to start")
	}
	if _, err := f.Stat(); err != nil {
		return fmt.Errorf("netns sidecar payload descriptor (fd 3) is not open: %w", err)
	}
	if err := json.NewDecoder(f).Decode(v); err != nil {
		return fmt.Errorf("decode netns sidecar payload from fd 3: %w", err)
	}
	return nil
}
