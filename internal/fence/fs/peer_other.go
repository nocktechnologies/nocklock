//go:build !linux

package fs

import "net"

func captureConnectionPeer(net.Conn) connectionPeer {
	return unavailableConnectionPeer()
}
