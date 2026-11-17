# Example: protect a folder

This example keeps an AI agent from changing anything in a `migrations/`
folder. The agent can still work everywhere else it is allowed to. On Linux it
can also read `migrations/`; on macOS the folder is closed to reads too.

The configs here are the generic `nocklock init` default with the changes
described below. If your agent has a runtime preset (see the
[project README](../../README.md#quick-start)), run
`nocklock init --runtime <agent>` instead and make the same changes in that
config (on macOS, both `deny` entries), so the agent keeps its login and
settings.

## Why a hook is not enough

Many agents let you add a hook that refuses an edit. Say you add one that stops
the agent's edit tool from touching `migrations/`. The agent sees the refusal,
then runs a shell command instead:

```sh
echo "DROP TABLE users;" >> migrations/0001.sql
```

The hook only watched the edit tool, so the shell command goes through.

NockLock works at the operating-system level. The kernel refuses the write no
matter which tool the agent uses: the edit tool, a shell append, a script, or a
program it starts. Each refusal NockLock sees is written to its signed audit
log.

## What is in this folder

| Path | Used on | What it does |
|---|---|---|
| `.nock/config.toml` | macOS | The default config with `migrations/` and `.nock/` added to the deny list (no reads or writes). |
| `migrations/0001.sql` | macOS | A sample migration to protect. |
| `linux/.nock/config.toml` | Linux | The agent may change `app/` only; `migrations/` is read-only. |
| `linux/app/notes.txt` | Linux | A sample file the agent may change. |
| `linux/migrations/0001.sql` | Linux | A sample migration to protect. |

## macOS

1. Install NockLock (see the [project README](../../README.md#quick-start)).
2. Copy this folder, without the `linux` folder, and put your project files in
   it. Put your migrations in `migrations/`.
3. From that folder, start your agent under NockLock, for example:

   ```sh
   nocklock wrap -- <agent>
   ```

Any write to `migrations/`, by the edit tool or by a shell command, is now
refused by the kernel. Your other project files stay writable.

To check what happened, run `nocklock log --blocked` in the same folder. Each
refused write shows up as a `file_blocked` row. macOS reports these refusals
through `log stream`, which needs an admin account. On a standard account you
get one warning row in place of the `file_blocked` rows; the kernel refuses
the write the same way.

By default, each `nocklock wrap` records the config it runs with as a signed
`config.digest` row and warns before the agent starts when the config changed
since the last run from the same folder (see
[Signed audit log](../../README.md#signed-audit-log-v11-ed25519)). On macOS the
config file sits inside the folder the agent may change, so this example also
denies `.nock/`: the agent cannot change its own fence during a run.

## Linux

On Linux, NockLock uses Landlock. Landlock cannot deny a path inside a folder
it has already granted (see the
[filesystem fence limits](../../docs/how-it-works/filesystem-fence.md#linux-landlock-root-allowlist)).
So the macOS layout, which grants the whole project and denies `migrations/`
inside it, is refused at startup on Linux. The Linux config grants a different
folder instead:

- `app/` is the filesystem root: the folder the agent may write. The agent can
  read and change files there.
- `migrations/` sits next to `app/` and is in the read-only `allow` list. The
  agent can read it but cannot change it.

Steps:

1. Install NockLock, including the Linux file library (see the
   [setup guide](../../docs/setup.md)).
2. Copy the `linux` folder. Put the files the agent may change in `app/` and
   your migrations in `migrations/`.
3. From the copied `linux` folder (the one with `.nock/`), start your agent
   inside `app/`, for example:

   ```sh
   nocklock wrap -- sh -c 'cd app && exec <agent>'
   ```

   NockLock reads the config's `app/` and `migrations/` relative to the folder
   you run `nocklock wrap` from, so run it from the `linux` folder. Run from
   inside `app/`, NockLock looks for `app/app` and refuses to start. The
   config file sits outside `app/`, so the agent cannot change it.

Real output from a Linux run, with a shell append standing in for the agent.
The project folder is shown as `<project>`, and four other startup lines
(secret fence, syscall fence, a Landlock ABI note and network fence) are left
out of each run:

```text
$ nocklock wrap -- sh -c 'echo "DROP TABLE users;" >> migrations/0001.sql'
NockLock: Linux Landlock filesystem fence active — ABI v8
NockLock: filesystem fence active — root <project>/app (read-write)
/usr/bin/sh: 1: cannot create migrations/0001.sql: Permission denied
exit code: 2
$ cat migrations/0001.sql
CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL);

$ nocklock wrap -- cat migrations/0001.sql
NockLock: Linux Landlock filesystem fence active — ABI v8
NockLock: filesystem fence active — root <project>/app (read-write)
CREATE TABLE users (id INTEGER PRIMARY KEY, email TEXT NOT NULL);
exit code: 0

$ nocklock wrap -- sh -c 'echo "edited by the agent" >> app/notes.txt'
NockLock: Linux Landlock filesystem fence active — ABI v8
NockLock: filesystem fence active — root <project>/app (read-write)
exit code: 0
$ cat app/notes.txt
Notes the agent may edit.
edited by the agent
```

The append was refused and the migration is unchanged. `nocklock wrap` exits
with the agent's own exit code; the 2 here is the shell's code for the failed
append. Reading the migration
and changing `app/notes.txt` both still work.

`nocklock log` shows the refusal as a signed `file_blocked` row in the append's
session (other rows left out):

```text
Session 3843c0d2  started 2026-11-17 22:12:43  ended 2026-11-17 22:12:43  (0s)
  file_blocked: {"version":1,"report":{"type":"fs","action":"blocked","path":"migrations/0001.sql","operation":"open64","reason":"write denied on allow-list path <project>/migrations","timestamp":"2026-11-17T22:12:43Z"},...}
```

Run `nocklock verify --audit` to check that the log has not been changed.
