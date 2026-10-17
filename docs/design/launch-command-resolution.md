# Requested command resolution

Status: N11777 implemented and shipped in v0.10.0.
The diagnostic-only head first reproduced the defect before production edits.

## Objective and contract

The documented `nocklock wrap -- claude` invocation must select the requested
program through the invoking user's PATH even when Linux inserts its
Landlock/seccomp shim. Previously the shim passed the bare name to `execve`, which
interprets it relative to the working directory instead of searching PATH.

The correction resolves the requested command in the unprivileged
parent before adding launch prefixes. Arguments after the command remain
byte-for-byte unchanged; only argv[0] becomes the selected absolute path. Relative explicit paths keep
their spelling after the working-directory prefix so symlink/.. traversal is
not changed by lexical cleaning.
Explicit absolute and relative paths remain supported. A bare name found
through a relative PATH entry is refused with `ErrDot`, including when
`GODEBUG=execerrdot=0` would otherwise disable Go's check. No implicit working
directory fallback is allowed. Missing and non-executable commands produce an
actionable error without starting a child.
The CLI error starts with `resolve command "<requested command>":` and exits 1.

The caller's PATH is used, consistent with the existing direct `os/exec` path;
secret filtering of the child's environment remains separate. Dry-run remains
configuration validation without executable lookup. Fence setup, privilege
drops and the network helper's execution boundary remain unchanged. Path
selection does not pin an inode or eliminate replacement between lookup and
exec, and it does not identify an interpreter, module or agent implementation.
Executable fingerprinting is separate N11763 work.

## Implementation and verification

1. Add a bounded hosted regression against the unchanged production binary.
   Exercise an absolute-path allowed control, a bare PATH command, a CWD shadow,
   missing/non-executable PATH candidates with executable CWD decoys, and a dot
   PATH entry. The real CLI must keep Landlock and seccomp required. If the bare
   smoke unexpectedly passes on the current production code, stop and reconcile
   the finding before editing production.
   Each case first requires an absolute `/bin/sh` allowed control under the
   identical PATH, GODEBUG, directory and fence configuration. Refusal means exit
   1 with the command-resolution diagnostic; timeouts, output-drain failures,
   crashes and unrelated startup errors do not satisfy the assertion.
2. Add one small command-resolution helper beside `wrap.go`, before prefix
   composition. Follow the existing Go style: return actionable wrapped errors,
   copy argument slices instead of mutating caller storage, and use standard
   library path and executable lookup facilities. No dependency is needed.
3. Add portable PATH/composition and refusal tests, with removed-resolution and
   removed-ErrDot controls. Exercise the bare command through the existing hosted
   composed netns proof as well. Preserve its allowed and denied egress evidence.
4. Update user documentation and the changelog for the implemented behavior.
   Obtain three independent security/simplifier reviews, the full exact-head
   maintainer review and applicable hosted checks.

Build: `go build ./cmd/nocklock`. Local checks: `go test ./... -v`,
`go vet ./...`, `go fmt ./...`, and `gofmt -l .`. Scoped race checks cover the CLI
helper. Linux cross-builds are compilation evidence only. Real launch proofs
run on disposable GitHub-hosted Linux runners, never on this resident host.

The diagnostic regression uses the existing `TestWrapClaudeCodePreset` hosted
job and its strict prerequisite flag; no workflow change or local privileged
probe is required. A failing diagnostic head is not a merge candidate. This
card stays separate from fingerprint metadata and from held packaging work.

## Observed baseline

Diagnostic head `ca2d7b0501d063867abf42e2dcea9daf4da8a4b2` changed no
production source from next `595062f5444ed53ef4d653ba0e3ec1170c915736`.
[Hosted run 38548510795, preset job](https://github.com/nocktechnologies/nocklock/actions/runs/38548510795/job/115800441717)
passed all six identical-environment absolute controls. Bare `sh` failed with
ENOENT in `__landlock-exec`; four CWD-decoy cases executed the decoy and failed
the expected assertions. Landlock ABI7 and required seccomp were active. The
baseline fixture did not grant the staged interposer directory, so that run
is not interposer enforcement evidence; the final fixture grants it explicitly.
