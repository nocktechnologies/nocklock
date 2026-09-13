// Package netns is the home of NockLock's Linux network-namespace egress fence
// (Candidate B of the linux-network-egress-enforcement spec) and its acceptance
// tests.
//
// The Phase-1 FOUNDATION privileged helper lives here (SetupAndExec in
// helper_linux.go): acquired via passwordless sudo, it creates a fresh network
// namespace (CLONE_NEWNET), brings loopback up, installs the shared
// DefaultDropRuleset base (default-drop across all transports, IPv4+IPv6),
// drops CAP_NET_ADMIN+CAP_SYS_ADMIN from all five capability sets (the receipted
// Q6 cap-drop harness in caps_linux.go), drops to the unprivileged invoking user,
// and execve's the agent as a non-root child inside the namespace. It fails
// closed — it never execs a child it could not fully fence.
//
// Two root-gated acceptance proofs guard the foundation, both run in the
// network-egress CI workflow:
//   - Q6 (netns_bypass_linux_test.go): a child with CAP_NET_ADMIN and
//     CAP_SYS_ADMIN dropped from every set cannot REWRITE the fence (issue #73).
//   - Foundation (foundation_linux_test.go): with the default-drop base
//     installed, that same capped child cannot EGRESS at all (Nock #9916).
//
// Phase 1b layers the transparent HTTP(S)/DNS allowlist onto that floor. TCP/80
// and TCP/443 are intercepted with nftables tproxy; a namespace-local proxy
// checks HTTP Host or TLS SNI before it can open an allowlisted CONNECT tunnel to
// the host-resolver proxy. A fixed-answer DNS stub maps every A/AAAA name to the
// intercept address, so the child has no direct resolver or default route.
// UDP/QUIC, SCTP, raw IP, and every other transport remain denied.
package netns
