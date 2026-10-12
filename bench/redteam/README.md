# Red-team bench (N11623)

`bash bench/redteam/run.sh` runs every attack in `attacks.toml` inside its own `nocklock wrap
--net-fence=netns` session, pairs each with the signed row that stopped it, runs both verifiers, and
writes `REPORT.md` and `report.json`. The MCP attacks run on the host, outside the fence, directly
against `nockguard proxy`; the proof is NockGuard's signed policy deny.

Scoring rule: the bench never scores a block it did not observe, and any harness problem fails the
run. An attack is BLOCKED only when it exits with a code it declares as `blocked_exit` and nothing
planted a mark (a file, or a datagram at the host receiver). Any other exit is a HARNESS-FAULT.

The direct-DNS attack is scored by receipt: a host receiver on UDP port 53 (the runner lowers
`net.ipv4.ip_unprivileged_port_start`, or run as root) must log nothing. Whether the client got a
reply does not matter.

## Limits

Known limits of this slice, written down rather than fixed:

- An interrupt (Ctrl-C, SIGTERM to the driver) between `Popen` and `killpg` in `run()` leaves that
  attack's process group running.
- `check_setup` runs once, before the first attack. It does not re-check that evidence paths stay
  outside the fence grants while attacks run.
- The NockGuard trail path (`<agent>.audit.jsonl` beside the policy audit path) is a naming
  convention the driver reproduces; the bench does not ask NockGuard where it wrote the trail.
- The symlink test (`test_a_symlinked_log_path_is_refused_and_its_target_untouched`) is vacuous when the victim file is
  absent: it asserts the value it falls back to. The FIFO and dangling-symlink tests carry the
  real refusal check.
- Direct DNS egress is scored by receipt only for a query to the host's outbound address on port
  53; a query to another resolver address is not observed by the bench.
