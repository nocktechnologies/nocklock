# Network fence

Citations are `file:line` at `origin/main` 8a65777. The boundary table and limits follow `README.md` ("What network fence active means").

## Default: local proxy with a domain allowlist
`wrap` starts a local HTTP/HTTPS proxy (`internal/cli/wrap.go:697`, `internal/fence/network/proxy.go:156`) and routes the child through it. Hostnames are checked against `network.allow`; blocked requests get a 403 and a `network_blocked` row. For HTTPS only the hostname is inspected (CONNECT, `internal/fence/network/connect.go`): no certificate injection and no decryption. Private ranges are blocked unless `--allow-private-ranges` (`proxy.go:49`). If the proxy is not healthy, the agent does not start.

## Egress levels
The level is computed once by `effectiveEgressLevel` (`internal/cli/egress_level.go:24`), printed in the `wrap` banner and signed into the audit chain.

| Level | Boundary |
|---|---|
| `KERNEL` | Linux `--net-fence=netns`: network namespace, nftables default-drop floor, transparent HTTP(S) and DNS allowlist |
| `CONFINED` | Linux proxy mode with syscall enforcement and the interposer bridge: the child's IP sockets are denied and only the proxy's Unix socket is reachable |
| `SEATBELT` | macOS proxy with a Seatbelt kernel floor (needs `filesystem.root`) |
| `ADVISORY` | Proxy only; a client that ignores `HTTP_PROXY` reaches any host |
| `OFF` | `network.allow_all = true` |
| `UNREACHABLE` | Syscall fence confines the child to Unix sockets but the interposer is off; `wrap` refuses to start (`wrap.go:587-594`) |

`network.require_enforced = true` or `--require-enforced-egress` refuses `ADVISORY`, `OFF` and `UNREACHABLE` (`wrap.go:605-610`, `egress_level.go:46`).

## Linux netns mode (`--net-fence=netns`)
Needs Linux (`wrap.go:74-76`) and the privileged helper (`docs/setup.md`), and fails closed without the helper (README). It also needs `network.allow` entries (`wrap.go:675`). The child runs in its own namespace, keeps its configured IP socket families, and reaches only `network.allow` hosts through a transparent proxy and a fixed-answer DNS stub. Direct DNS to other resolvers, non-DNS UDP, QUIC, SCTP and raw IP are dropped in the kernel. The setup request travels in a 0600 file, not stdin (`.claude/decisions/004-netns-setup-request-channel.md`). Code: `internal/fence/network/netns/`. Feasibility probe: `nocklock egress-probe`.

## macOS Seatbelt floor
With the network fence active the profile denies `network-outbound` except TCP to `localhost:<proxy port>`, allows no Unix-socket connect, and denies Mach lookups of `com.apple.mDNSResponder` and `com.apple.mDNSResponderHelper` (`CHANGELOG.md:18`). The proxy listener is bound once and handed over; `[::1]:<port>` is held or wrap refuses to start.

## Look-back rules (Linux, `CONFINED` only)
`[[network.lookback]]` with `on = "file_blocked"`, `then = "deny_egress"`, optional `within`. After the interposer reports a denied open, the proxy closes open tunnels and denies new requests, logged as signed `network_blocked` rows citing `rule=lookback:<name> trigger=<id>` (`internal/fence/network/lookback.go:32,111`). `wrap` refuses to start with a rule at any other level (`egress_level.go:53`). A rule only narrows egress; it never adds an allow. Design: `docs/design/look-back-rules.md`.

## Honest limits
- `ADVISORY` is advisory. Read the banner.
- Hostname checks only: a permitted host can still receive anything the agent sends it.
- `CONFINED` blocks IP sockets; the full set of remaining ways out on Linux is on the roadmap (`docs/ROADMAP.md`, N11660 Unix-socket reach, N11655 io_uring) and is not claimed closed here.
- macOS: `sandbox-exec` is deprecated; reads outside the root are unconfined; with `filesystem.root = ""` there is no profile and egress is `ADVISORY`; `/etc/hosts` lookups stay allowed; resolver services not on the Mach deny list are not claimed closed. Windows has no network fence.
- Look-back rules never see static binaries, raw syscalls, or a cleared `LD_PRELOAD`.

## Tests
`internal/fence/network/*_test.go`, `internal/fence/network/netns/*_linux_test.go` (bypass, protocol matrix, DNS escape), `internal/cli/egress_level_test.go`, `internal/cli/wrap_egress_*_test.go`, `internal/cli/seatbelt_floor_test.go`, `wrap_network_floor_darwin_test.go`. CI: `.github/workflows/network-egress.yml`.
