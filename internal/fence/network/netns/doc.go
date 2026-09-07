// Package netns is the home of NockLock's Linux network-namespace egress fence
// (Candidate B of the linux-network-egress-enforcement spec) and its acceptance
// tests.
//
// The Phase-1b privileged helper lives here (SetupAndExec in helper_linux.go):
// acquired via passwordless sudo, it creates a fresh network namespace
// (CLONE_NEWNET), adds nftables tproxy local-delivery routes, and starts a
// dedicated transparent sidecar before it drops the child to the unprivileged
// invoking user. The sidecar parses HTTP Host headers or TLS SNI, while an
// authenticated host-network broker repeats the allowlist decision and resolves
// only allowed names. A fixed-answer DNS stub returns the intercept address for
// every name; UDP/443, SCTP, and all other child egress stay default-drop.
// CAP_NET_ADMIN+CAP_SYS_ADMIN are removed from all five child capability sets
// (the receipted Q6 cap-drop harness in caps_linux.go). The helper fails closed:
// it never execs a child without the complete tproxy, DNS, and broker boundary.
//
// Two root-gated acceptance proofs guard the foundation, both run in the
// network-egress CI workflow:
//   - Q6 (netns_bypass_linux_test.go): a child with CAP_NET_ADMIN and
//     CAP_SYS_ADMIN dropped from every set cannot REWRITE the fence (issue #73).
//   - Foundation (foundation_linux_test.go): the original default-drop base
//     remains receipted as the causal floor test (Nock #9916).
//   - Protocol matrix (protocol_matrix_linux_test.go): allowed HTTP(S) succeeds
//     through tproxy, denied Host/SNI fails at the proxy, DNS reaches only the
//     stub, UDP/443/SCTP stay denied, and curl/Node/Python use TCP successfully.
package netns
