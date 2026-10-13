# Linux CONFINED Unix-socket reachability

Status: reachability confirmed; mitigation design only. Nock #11650.

## Finding

In Linux proxy mode, the seccomp policy restricts new `socket()` calls to
`AF_UNIX`. It does not restrict `connect()`. The filesystem interposer rewrites
the configured loopback proxy connection to the proxy's pathname socket, but
other AF_UNIX connections pass through unchanged. This includes pathname
sockets such as a user's Docker or SSH-agent socket and abstract sockets.

The probe in [`docs/probes/n11650/`](../probes/n11650/) reproduced both paths
as a non-root user on this host. Its AF_INET datagram negative control failed with
`EPERM`, and NockLock reported `CONFINED`. It created only its own temporary
pathname and abstract listeners; it did not touch Docker or another system
socket.

This means `CONFINED` currently blocks direct IP socket syscalls that the
interposer does not remap, but does not confine local IPC destinations. A process
with access to a privileged local service can ask that service to perform actions
on its behalf. The network proxy's domain allowlist does not mediate those requests.

## Candidate designs

| Option | Proxy path and cost | What remains reachable |
| --- | --- | --- |
| Landlock `LANDLOCK_ACCESS_FS_MAKE_SOCK` | ABI 2 support; low cost to add to the filesystem rules. It controls creation, rename, or link of pathname socket entries. | It does not restrict connecting to existing sockets, so it does not close this finding. Existing Docker, SSH-agent, desktop, and database sockets remain reachable. |
| Landlock abstract scope and pathname resolution | `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` is available from ABI 6. `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` is available from ABI 9 and restricts pathname-socket `connect()` and explicit-recipient `sendmsg()`. The pathname right can be allow-listed with a `LANDLOCK_RULE_PATH_BENEATH` rule. The proxy uses a pathname socket, so NockLock must add a rule for that run's exact proxy socket after it has been created; allowing a containing directory would be broader. The current Landlock builder supports ABI 5 and creates the proxy after building the child's rules, so both capability detection and rule ordering need changes. | Older kernels cannot enforce pathname resolution through Landlock; ABI below 6 also cannot scope abstract sockets. Landlock allows socket servers created in the same or a nested domain, so services deliberately started inside the sandbox remain reachable. Inherited file descriptors are also outside pathname lookup checks. |
| Deny `connect()` with seccomp | A seccomp filter cannot dereference the userspace `sockaddr` pointer, so it cannot tell whether a `connect()` targets the proxy path or another path. Denying every `connect()` also breaks the current interposer, which opens a proxy Unix connection for each client connection. Preserving the proxy would require a pre-connected/brokered channel and careful mediation of descriptor transfer. | An fd-number exception is not a safe identity check: the process can close and reuse that number. A syscall-only design must also account for other address-bearing interfaces and `io_uring` when available. |
| Mount namespace with a private socket view | Build a child mount namespace and expose only the proxy socket in the child-visible filesystem. This needs namespace setup, a carefully constructed mount tree, and a policy for hosts where unprivileged namespaces are disabled. | Abstract sockets are not filesystem paths, so they need a separate restriction. Any host socket left visible or inherited as an fd remains reachable. |
| `doctor` warning for known sockets | Low implementation cost. Check known high-impact endpoints such as Docker sockets and an `SSH_AUTH_SOCK` path, and explain that they are reachable from CONFINED children. | A warning does not enforce anything. It misses unknown, custom, or dynamically created sockets, and the child can still connect to every other accessible AF_UNIX endpoint. |

The kernel's Landlock documentation describes `MAKE_SOCK`, abstract-socket
scope, and pathname-socket resolution in the [Landlock userspace API](https://docs.kernel.org/userspace-api/landlock.html).
Seccomp filters cannot dereference pointer arguments such as the `sockaddr`
path, as documented in [Seccomp BPF](https://docs.kernel.org/userspace-api/seccomp_filter.html).
This host's wrap output
reported Landlock ABI v5, so neither ABI 6 abstract-socket scope nor ABI 9
pathname-socket resolution was available here. Detect ABI support at runtime;
kernel release strings alone are not a capability check.

The captured run is in [`output.txt`](../probes/n11650/output.txt). It reported
`path=CONNECTED`, `abstract=CONNECTED`, and
`inet_datagram=DENIED errno=1 Operation not permitted`; the server accepted the
`probe` payload on both listeners.

## Recommendation

Use Landlock's abstract scope on ABI 6+ and pathname `RESOLVE_UNIX` on ABI 9+,
with a path rule for only the current proxy socket. Add negative controls proving
that the proxy remains usable and that unrelated pathname and abstract sockets
are denied. On kernels without the required capability, do not describe
`CONFINED` as isolating Unix-socket destinations. If the product must guarantee
that isolation on older kernels, use a complete private socket view or a
brokered proxy channel; a `MAKE_SOCK` rule or a known-socket warning is not a
substitute. The design needs an explicit compatibility decision about whether
unsupported kernels refuse this guarantee or report the weaker posture.

The design should also cover inherited descriptors and any enabled alternate
socket-address interfaces. Even after external Unix sockets are blocked, an
agent can use the configured network proxy for allowed domains and can reach
services created within its own Landlock domain.

## Red-team follow-up

Do not add the reachability attack to red-team bench #165 until an enforcement
fix exists. The fix PR should add the path and abstract probes as attacks, keep
the AF_INET `EPERM` negative control, and prove the configured proxy path still
works. Until then, the script here is evidence of current exposure, not a
passing security assertion.
