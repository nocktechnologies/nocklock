//go:build !linux

package cli

import "runtime"

// defaultEgressProbeCapabilities on non-Linux platforms carries only host
// identity. runEgressProbe short-circuits to the "unsupported" track before any
// of the probe function fields are called, so they are left nil here — the
// Linux network-egress fence has no meaning off Linux.
func defaultEgressProbeCapabilities() egressProbeCapabilities {
	return egressProbeCapabilities{
		goos: runtime.GOOS,
		arch: goarch(),
	}
}
