//go:build !linux

package network

import (
	"errors"
	"time"

	"github.com/nocktechnologies/nocklock/internal/config"
	"github.com/nocktechnologies/nocklock/internal/logging"
)

// TransparentBroker is unavailable outside Linux because it is only useful
// with the nftables tproxy netns fence.
type TransparentBroker struct{}

// NewTransparentBroker returns the platform stub used by code shared with
// Linux. Start always refuses rather than creating a userspace fallback.
func NewTransparentBroker(config.NetworkConfig, *logging.Logger, string) *TransparentBroker {
	return &TransparentBroker{}
}

// Start refuses transparent proxy setup on unsupported platforms.
func (*TransparentBroker) Start() (string, string, error) {
	return "", "", errors.New("transparent netns broker is only supported on Linux")
}

// Stop is a no-op for the unsupported-platform stub.
func (*TransparentBroker) Stop() error { return nil }

// ProxyHeartbeatSeen is always false on the unsupported-platform stub.
func (*TransparentBroker) ProxyHeartbeatSeen() bool { return false }

// StartWatchdog is a no-op for the unsupported-platform stub.
func (*TransparentBroker) StartWatchdog(<-chan struct{}, time.Duration, int, func()) {}
