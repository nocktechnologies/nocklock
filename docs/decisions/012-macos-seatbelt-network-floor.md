# 012: macOS network floor in the Seatbelt profile, new level `SEATBELT`

**Status:** Accepted, shipped v0.7.0 (`CHANGELOG.md:18`).

**Context.** On macOS the proxy was `ADVISORY`; a client that ignored `HTTP_PROXY` reached any host.

**Decision.** With the network fence active the profile denies `network-outbound` except TCP to `localhost:<proxy port>`, allows no Unix-socket connect, and denies Mach lookups of the two mDNSResponder services so `getaddrinfo` fails inside the fence. A new signed level `SEATBELT` is used rather than `CONFINED`, which is defined by the Linux syscall fence and interposer bridge. `--require-enforced-egress` passes on macOS when the floor is engaged.

**Consequences.** `sandbox-exec` is deprecated by Apple and reads outside the root remain unconfined; resolver services not on the deny list are not claimed closed. A rejected profile or unhealthy proxy refuses to start.
