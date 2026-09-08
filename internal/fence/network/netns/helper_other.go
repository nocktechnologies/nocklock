//go:build !linux

package netns

import (
	"errors"
	"fmt"
)

// ErrUnsupported is returned on non-Linux platforms: the netns egress fence is a
// Linux network-namespace mechanism and has no equivalent elsewhere. Callers must
// treat this as fail-closed (refuse to run), never as "no fence" (spec: no
// advisory/degraded fallback).
var ErrUnsupported = errors.New("netns egress fence is only supported on Linux")

// Request mirrors the Linux setup request so the CLI helper subcommand compiles
// on every platform. It is never acted upon off Linux.
type Request struct {
	Argv   []string      `json:"argv"`
	Env    []string      `json:"env"`
	UID    int           `json:"uid"`
	GID    int           `json:"gid"`
	Groups []int         `json:"groups"`
	Egress *EgressConfig `json:"egress,omitempty"`
}

// BridgeSpec mirrors the Linux-only private bridge description so callers keep
// compiling on platforms where the netns fence refuses to run.
type BridgeSpec struct {
	Namespace      string `json:"namespace"`
	HostInterface  string `json:"host_interface"`
	ChildInterface string `json:"child_interface"`
	HostAddress    string `json:"host_address"`
	ChildAddress   string `json:"child_address"`
}

// EgressConfig mirrors the Linux-only transparent-proxy setup request.
type EgressConfig struct {
	Allow              []string   `json:"allow"`
	AllowPrivateRanges bool       `json:"allow_private_ranges"`
	Bridge             BridgeSpec `json:"bridge"`
}

// ChildExitError mirrors the Linux helper's child-status transport.
type ChildExitError struct {
	Code   int
	Detail string
}

func (e *ChildExitError) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	return fmt.Sprintf("netns child exited %d", e.Code)
}

// Check refuses on non-Linux platforms.
func Check() error { return ErrUnsupported }

// SetupAndExec refuses on non-Linux platforms.
func SetupAndExec(Request) error { return ErrUnsupported }

// NewBridgeSpec refuses on non-Linux platforms.
func NewBridgeSpec() (BridgeSpec, error) { return BridgeSpec{}, ErrUnsupported }

// DropAndExecChild refuses on non-Linux platforms.
func DropAndExecChild(Request) error { return ErrUnsupported }

// RunTransparentProxy refuses on non-Linux platforms.
func RunTransparentProxy(EgressConfig) error { return ErrUnsupported }

// RunHostProxy refuses on non-Linux platforms.
func RunHostProxy(EgressConfig) error { return ErrUnsupported }

// RunDeferredBridgeCleanup refuses on non-Linux platforms.
func RunDeferredBridgeCleanup(BridgeSpec) error { return ErrUnsupported }
