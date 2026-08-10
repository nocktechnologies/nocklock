// Package netns is the home of NockLock's Linux network-namespace egress fence
// (Candidate B of the linux-network-egress-enforcement spec) and its acceptance
// tests.
//
// The Phase-1 privileged helper — which creates a network namespace, applies a
// default-drop nftables base, and execs the agent as an unprivileged child in
// that namespace — will live here. Phase 0 lands its single load-bearing
// acceptance proof first: the root-gated Q6 mutation-resistance test in
// netns_bypass_linux_test.go. That test demonstrates the premise Candidate B
// rests on — a child with CAP_NET_ADMIN and CAP_SYS_ADMIN dropped from every
// capability set cannot rewrite the fence (issue #73) — before any real helper
// is built on top of it.
package netns
