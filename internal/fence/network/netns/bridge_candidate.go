package netns

import "fmt"

// bridgeCandidateForID maps a random identity into the available link-local
// /30 pool. Reserve 169.254.169.0/24 and 169.254.170.0/24, which contain cloud
// instance and container metadata endpoints. This does not reserve every
// provider-specific address or replace the host-wide subnet reservation.
func bridgeCandidateForID(id uint32) BridgeSpec {
	const (
		allSlots      = 1 << 14
		reservedStart = 169 << 6
		reservedSlots = 2 << 6
	)
	slot := id % (allSlots - reservedSlots)
	if slot >= reservedStart {
		slot += reservedSlots
	}
	octet3, octet4 := slot>>6, (slot&0x3f)<<2
	nameID := fmt.Sprintf("%08x", id)
	host := fmt.Sprintf("169.254.%d.%d", octet3, octet4+1)
	return BridgeSpec{
		Namespace:      "nln" + nameID,
		HostInterface:  "nlh" + nameID,
		ChildInterface: "nlc" + nameID,
		HostAddress:    host,
		ChildAddress:   fmt.Sprintf("169.254.%d.%d", octet3, octet4+2),
		ReservationID:  host,
	}
}
