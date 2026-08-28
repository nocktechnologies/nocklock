//go:build linux

package netns

// DefaultDropRuleset is the Phase-1 FOUNDATION nftables base: a fail-closed,
// default-drop egress floor with NO allowances yet.
//
// The `inet` family filters IPv4 AND IPv6 in a single table, and every base
// hook (input, output, forward) has `policy drop`. Because the drop is at the
// hook level — not per-protocol — this denies EVERY transport (TCP, UDP/QUIC,
// SCTP, and anything else) in both address families. That is exactly the
// spec's "default-drop egress across every transport and both IPv4 and IPv6"
// (2026-07-30 linux-network-egress-enforcement, Candidate B, §B and the
// 2026-08-24 amendment's Phase-1 foundation increment).
//
// Loopback policy (deliberate, per spec Q7-independent foundation): the helper
// brings the loopback INTERFACE up (link state) but this base installs NO
// `oif lo accept` allowance, so loopback traffic is dropped too — "no
// allowances yet." The later transparent-allowlist increment adds the loopback
// and SNI/Host/DNS allowances that turn this floor into a selective HTTP(S)+DNS
// allowlist; the interface is brought up now so those increments (proxy
// listener, in-namespace DNS stub on 127.0.0.1) have a working `lo` to build on.
//
// This is the SINGLE source of truth for the base RULESET STRING: both the
// production helper (SetupAndExec) and the receipted Q6 / foundation acceptance
// tests install exactly this constant, so the packet-filter policy they exercise
// is byte-identical to the shipped one. (Interface setup around it — e.g.
// bringing loopback up — lives in each caller and is asserted separately; this
// constant pins only the nftables policy.)
const DefaultDropRuleset = "table inet filter {\n" +
	"  chain input   { type filter hook input priority 0; policy drop; }\n" +
	"  chain output  { type filter hook output priority 0; policy drop; }\n" +
	"  chain forward { type filter hook forward priority 0; policy drop; }\n" +
	"}\n"
