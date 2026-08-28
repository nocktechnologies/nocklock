//go:build !linux

package netns

import "errors"

// ErrUnsupported is returned on non-Linux platforms: the netns egress fence is a
// Linux network-namespace mechanism and has no equivalent elsewhere. Callers must
// treat this as fail-closed (refuse to run), never as "no fence" (spec: no
// advisory/degraded fallback).
var ErrUnsupported = errors.New("netns egress fence is only supported on Linux")

// Request mirrors the Linux setup request so the CLI helper subcommand compiles
// on every platform. It is never acted upon off Linux.
type Request struct {
	Argv   []string `json:"argv"`
	Env    []string `json:"env"`
	UID    int      `json:"uid"`
	GID    int      `json:"gid"`
	Groups []int    `json:"groups"`
}

// Check refuses on non-Linux platforms.
func Check() error { return ErrUnsupported }

// SetupAndExec refuses on non-Linux platforms.
func SetupAndExec(Request) error { return ErrUnsupported }
