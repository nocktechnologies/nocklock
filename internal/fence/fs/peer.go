package fs

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// connectionPeer is a value snapshot taken before parsing an accepted connection. None of
// its fields can be filled from a report or mutated through a delivered event.
type connectionPeer struct {
	credentialsStatus string
	credentials       peerCredentials
	executable        peerExecutable
}

type peerCredentials struct {
	PID int32  `json:"pid"`
	UID uint32 `json:"uid"`
	GID uint32 `json:"gid"`
}

type peerExecutable struct {
	Status string `json:"status"`
	Path   string `json:"path,omitempty"`
}

func unavailableConnectionPeer() connectionPeer {
	return connectionPeer{
		credentialsStatus: "unavailable",
		executable:        peerExecutable{Status: "credentials_unavailable"},
	}
}

// This read is intentionally separate from SO_PEERCRED: exec, exit, PID reuse
// and namespace visibility can change what /proc exposes after connect/accept.
func observePeerExecutable(pid int32, readlink func(string) (string, error)) peerExecutable {
	path, err := readlink("/proc/" + strconv.FormatInt(int64(pid), 10) + "/exe")
	if err != nil || path == "" {
		return peerExecutable{Status: "unavailable"}
	}
	return peerExecutable{Status: "observed", Path: path}
}

// Detail returns the signed-detail payload for an interposer report. Reports
// received by the collector use a versioned envelope separating child claims
// from the connection peer snapshot. A peer identifies the connector, not each
// action's writer; its executable path is only a later procfs observation.
// Events without a collector snapshot retain the legacy text representation.
func (e FenceEvent) Detail() string {
	if !e.hasPeer {
		return fmt.Sprintf("op=%s path=%s reason=%s", e.Operation, e.Path, e.Reason)
	}
	var credentials *peerCredentials
	if e.peer.credentialsStatus == "captured" {
		captured := e.peer.credentials
		credentials = &captured
	}
	detail := struct {
		Version int        `json:"version"`
		Report  FenceEvent `json:"report"`
		Peer    struct {
			CredentialsStatus string           `json:"credentials_status"`
			Credentials       *peerCredentials `json:"credentials,omitempty"`
			Executable        peerExecutable   `json:"executable"`
		} `json:"connection_peer"`
	}{Version: 1, Report: e}
	detail.Peer.CredentialsStatus = e.peer.credentialsStatus
	detail.Peer.Credentials = credentials
	detail.Peer.Executable = e.peer.executable
	// This closed set of strings, integers and structs has no failing JSON
	// marshal cases. No child-supplied raw JSON or custom marshaler is used.
	encoded, _ := json.Marshal(detail)
	return string(encoded)
}
