# Security policy

## Report a vulnerability

Please email **security@nocktechnologies.com** for a suspected fence escape, secret exposure, privilege escalation, or other security vulnerability. Do not open a public issue with exploit details or credentials.

Include the NockLock version or commit, OS and kernel version, the relevant configuration with secrets removed, reproduction steps, and the expected and observed behavior. A minimal reproduction using throwaway files, sockets and credentials is most useful. Do not include real API keys, tokens, private keys or sensitive audit contents.

For ordinary bugs and questions, use [GitHub Issues](https://github.com/nocktechnologies/nocklock/issues).

## Understand the boundary

Use the latest release and read its [release notes](https://github.com/nocktechnologies/nocklock/releases), including breaking changes. Run `nocklock doctor` on the host and review the egress level printed by `wrap`.

The [README](README.md#what-network-fence-active-means) and [feature documentation](docs/README.md) describe platform and configuration limits. In particular, macOS does not confine all reads outside the project, Linux CONFINED below Landlock ABI 9 leaves other Unix sockets reachable, and a signed audit log does not establish complete observation of every action.
