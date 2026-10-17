//go:build linux

package fs

import (
	"net"
	"os"

	"golang.org/x/sys/unix"
)

func captureConnectionPeer(conn net.Conn) connectionPeer {
	peer := unavailableConnectionPeer()
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return peer
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return peer
	}
	var credentials *unix.Ucred
	var lookupErr error
	err = raw.Control(func(fd uintptr) {
		credentials, lookupErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	})
	if err != nil || lookupErr != nil || credentials == nil || credentials.Pid <= 0 {
		return peer
	}
	peer.credentialsStatus = "captured"
	peer.credentials = peerCredentials{PID: credentials.Pid, UID: credentials.Uid, GID: credentials.Gid}
	peer.executable = observePeerExecutable(credentials.Pid, os.Readlink)
	return peer
}
