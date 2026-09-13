//go:build linux

package netns

import (
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

const (
	// TransparentProxyPort is the in-namespace TCP listener selected by the
	// tproxy rules. It is not exposed on a host interface.
	TransparentProxyPort = 15080
	// ProxyHealthPort is reachable only over the private veth so the helper can
	// terminate the fenced child if either policy proxy dies.
	ProxyHealthPort = 15081
	proxyUID        = 65534 // the standard, dedicated nobody account
)

// subnetReservationDir is the host-wide directory that holds reservation files
// to prevent concurrent bridge subnet collisions.
var subnetReservationDir = "/run/nocklock-subnets"

// BridgeSpec identifies one private point-to-point veth bridge. The bridge is
// intentionally link-local and the child receives no default route: its only
// non-loopback peer is the host-side allowlist proxy.
type BridgeSpec struct {
	Namespace        string `json:"namespace"`
	HostInterface    string `json:"host_interface"`
	ChildInterface   string `json:"child_interface"`
	HostAddress      string `json:"host_address"`
	ChildAddress     string `json:"child_address"`
	ReservationID    string `json:"reservation_id"`
	ReservationToken string `json:"reservation_token"`
}

// EgressConfig is the fixed Phase-1b setup supplied to the privileged helper.
// The host-side proxy re-applies Allow before it resolves and dials an upstream;
// the transparent proxy applies the same rules before it can reach that peer.
type EgressConfig struct {
	Allow              []string   `json:"allow"`
	AllowPrivateRanges bool       `json:"allow_private_ranges"`
	Bridge             BridgeSpec `json:"bridge"`
}

var subnetReservationMutex sync.Mutex

// SubnetCollisionError indicates that the attempted subnet reservation collided
// with an existing reservation. The caller (wrap.go) should retry with a fresh candidate.
type SubnetCollisionError struct{}

func (e *SubnetCollisionError) Error() string {
	return "subnet collision: candidate already reserved by another run"
}

// generateBridgeCandidate generates a candidate link-local /30 identity
// with random names and addresses, but does NOT attempt reservation.
// Used by both NewBridgeSpec (unprivileged candidate generator) and by
// SetupAndExec (privileged retry loop).
func GenerateBridgeCandidate() (BridgeSpec, error) {
	var raw [4]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return BridgeSpec{}, fmt.Errorf("generate private netns bridge id: %w", err)
	}
	id := binary.BigEndian.Uint32(raw[:])
	slot := id & 0x3fff // 16,384 non-overlapping /30s in 169.254.0.0/16.
	octet3 := slot >> 6
	octet4 := (slot & 0x3f) << 2
	nameID := fmt.Sprintf("%08x", id)
	reservationID := fmt.Sprintf("169.254.%d.%d", octet3, octet4+1)

	// Generate the candidate bridge specification. Actual reservation is performed
	// by the privileged helper (SetupAndExec) which has write access to /run/nocklock-subnets.
	bridge := BridgeSpec{
		Namespace:      "nln" + nameID,
		HostInterface:  "nlh" + nameID,
		ChildInterface: "nlc" + nameID,
		HostAddress:    fmt.Sprintf("169.254.%d.%d", octet3, octet4+1),
		ChildAddress:   fmt.Sprintf("169.254.%d.%d", octet3, octet4+2),
		ReservationID:  reservationID,
	}
	return bridge, nil
}

// NewBridgeSpec generates a candidate link-local /30 identity for one netns run.
// It generates candidate names and addresses only; actual reservation is performed
// by the privileged helper (SetupAndExec) which has write access to /run/nocklock-subnets.
// This ensures the fence is not silently disabled on normal hosts where unprivileged
// processes cannot write the reservation directory.
func NewBridgeSpec() (BridgeSpec, error) {
	return GenerateBridgeCandidate()
}

// isSubnetReserved checks if a subnet address is already reserved by another run.
// It acquires a lock and checks for the existence of a reservation file.
func isSubnetReserved(subnetAddr string) (bool, error) {
	subnetReservationMutex.Lock()
	defer subnetReservationMutex.Unlock()

	reservationFile := filepath.Join(subnetReservationDir, subnetAddr)
	_, err := os.Stat(reservationFile)
	if err == nil {
		return true, nil // File exists, subnet is reserved.
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil // File doesn't exist, subnet is free.
	}
	return false, err // Other error.
}

// reserveSubnet creates a reservation file for a subnet address. It should only
// reserveSubnet creates a reservation file for a subnet address with an ownership
// token and returns the token. Called by the privileged helper (SetupAndExec) which
// has write access to /run/nocklock-subnets. Returns SubnetCollisionError if another
// run already owns this subnet (O_EXCL failed).
func reserveSubnet(subnetAddr string) (string, error) {
	subnetReservationMutex.Lock()
	defer subnetReservationMutex.Unlock()

	// Ensure the directory exists before creating the reservation file.
	if err := os.MkdirAll(subnetReservationDir, 0700); err != nil {
		return "", fmt.Errorf("create subnet reservation directory: %w", err)
	}

	// Generate a random ownership token for this run (not just PID, as PIDs are reused).
	var tokenBytes [16]byte
	if _, err := rand.Read(tokenBytes[:]); err != nil {
		return "", fmt.Errorf("generate reservation token: %w", err)
	}
	token := hex.EncodeToString(tokenBytes[:])

	reservationFile := filepath.Join(subnetReservationDir, subnetAddr)
	f, err := os.OpenFile(reservationFile, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			// Collision: another run reserved this subnet.
			return "", &SubnetCollisionError{}
		}
		return "", fmt.Errorf("create subnet reservation file: %w", err)
	}
	// Write token on first line (the ownership marker), then PID for debugging.
	if _, err := fmt.Fprintf(f, "%s\n%d\n", token, os.Getpid()); err != nil {
		_ = f.Close()
		_ = os.Remove(reservationFile)
		return "", fmt.Errorf("write reservation file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(reservationFile)
		return "", fmt.Errorf("close reservation file: %w", err)
	}
	return token, nil
}

// ReleaseSubnetReservation removes the reservation for a subnet only if the
// provided token matches the owner. This prevents TOCTOU deletion of another
// run's reservation. If the token does not match or the file doesn't exist,
// it returns nil without error (idempotent).
func ReleaseSubnetReservation(reservationID, token string) error {
	if reservationID == "" {
		return nil // No reservation to release.
	}

	subnetReservationMutex.Lock()
	defer subnetReservationMutex.Unlock()

	reservationFile := filepath.Join(subnetReservationDir, reservationID)

	// Read the reservation file to check ownership.
	content, err := os.ReadFile(reservationFile)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // File already gone, idempotent.
		}
		return fmt.Errorf("read subnet reservation: %w", err)
	}

	// Parse the token (first line of the file).
	lines := strings.Split(strings.TrimSpace(string(content)), "\n")
	if len(lines) == 0 || lines[0] != token {
		// Token mismatch: another run owns this subnet now, do not delete.
		return nil
	}

	// Token matches, safe to delete.
	if err := os.Remove(reservationFile); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("release subnet reservation: %w", err)
	}
	return nil
}

func (b BridgeSpec) hostCIDR() string  { return b.HostAddress + "/30" }
func (b BridgeSpec) childCIDR() string { return b.ChildAddress + "/30" }
func (b BridgeSpec) hostProxyAddr() string {
	return b.HostAddress + ":" + strconv.Itoa(TransparentProxyPort)
}
func (b BridgeSpec) childHealthAddr() string {
	return b.ChildAddress + ":" + strconv.Itoa(ProxyHealthPort)
}

func validateEgressConfig(cfg *EgressConfig, childUID int) error {
	if cfg == nil {
		return fmt.Errorf("netns egress setup is missing transparent proxy configuration")
	}
	if childUID == proxyUID {
		return fmt.Errorf("netns egress fence cannot use uid %d because it is reserved for the policy proxy", childUID)
	}
	b := cfg.Bridge
	for _, pair := range []struct {
		value  string
		prefix string
	}{
		{b.Namespace, "nln"},
		{b.HostInterface, "nlh"},
		{b.ChildInterface, "nlc"},
	} {
		if len(pair.value) != 11 || !strings.HasPrefix(pair.value, pair.prefix) {
			return fmt.Errorf("invalid private bridge %s name %q", pair.prefix, pair.value)
		}
		for _, r := range pair.value[3:] {
			if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
				return fmt.Errorf("invalid private bridge name %q", pair.value)
			}
		}
	}
	host, err := netip.ParseAddr(b.HostAddress)
	if err != nil || !host.Is4() || !host.IsLinkLocalUnicast() {
		return fmt.Errorf("invalid private bridge host address %q", b.HostAddress)
	}
	child, err := netip.ParseAddr(b.ChildAddress)
	if err != nil || !child.Is4() || !child.IsLinkLocalUnicast() {
		return fmt.Errorf("invalid private bridge child address %q", b.ChildAddress)
	}
	hostBytes := host.As4()
	childBytes := child.As4()
	if hostBytes[0] != childBytes[0] || hostBytes[1] != childBytes[1] || hostBytes[2] != childBytes[2] ||
		hostBytes[3]&^byte(3) != childBytes[3]&^byte(3) || hostBytes[3]&3 != 1 || childBytes[3]&3 != 2 {
		return fmt.Errorf("private bridge addresses %s and %s are not a host/child /30 pair", host, child)
	}
	return nil
}

// EgressRuleset returns the complete Phase-1b nftables policy. The only child
// egress path is transparent TCP interception on ports 80/443; the policy
// proxy's dedicated uid can reach only the host-side allowlist proxy.
// TPROXY is valid only in prerouting: output marks locally generated packets,
// policy routing loops them back, and prerouting assigns the transparent socket.
func EgressRuleset(cfg EgressConfig) string {
	b := cfg.Bridge
	return fmt.Sprintf(`table inet nocklock {
  chain output_route {
    type route hook output priority mangle; policy accept;
    meta skuid %d ip daddr %s tcp dport %d accept
    meta skuid 0 ip daddr %s tcp dport %d accept
    tcp dport { 80, 443 } meta mark set 0x1 accept
  }
  chain prerouting {
    type filter hook prerouting priority mangle; policy accept;
    iifname "lo" meta mark 0x1 tcp dport { 80, 443 } tproxy to :%d accept
  }
  chain input {
    type filter hook input priority filter; policy drop;
    iifname "lo" accept
    ip saddr %s tcp dport %d accept
    ct state established,related accept
  }
  chain output {
    type filter hook output priority filter; policy drop;
    ct state established,related accept
    oifname "lo" accept
    meta skuid %d ip daddr %s tcp dport %d accept
    meta skuid 0 ip daddr %s tcp dport %d accept
  }
  chain forward { type filter hook forward priority filter; policy drop; }
}
`, proxyUID, b.HostAddress, TransparentProxyPort, b.HostAddress, TransparentProxyPort,
		TransparentProxyPort, b.HostAddress, ProxyHealthPort, proxyUID, b.HostAddress,
		TransparentProxyPort, b.HostAddress, TransparentProxyPort)
}
