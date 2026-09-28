# N10825 Windows probes: `run-probe.ps1`

`run-probe.ps1` runs Probes 1, 2 and 3 of
[`docs/design/windows-feasibility.md`](../../design/windows-feasibility.md#probes-to-run-on-a-real-windows-box)
on a real Windows desktop. Every probe line in it is copied verbatim from the doc's code
blocks; if you change one, change the doc in the same commit.

- Probe 1: zero-capability loopback, with the exemption step run through the limited-token task.
- Probe 2: exemption elevation, scored from Probe 1's `VERDICT(1-exempt)`.
- Probe 3: AppContainer launch under the limited token.

The script refuses everything else before it changes anything: Probes 4-11 are not
assembled yet, and on `-Mode Desktop` it refuses the DISPOSABLE-BOX ONLY probes (8, 9).

## Requirements

- **The operator must be logged on interactively at the console.** The limited-token
  scheduled task is `-LogonType Interactive`; without a console logon it never starts and
  the run aborts at the positive control (`LIMITED-TOKEN: FAIL ... started=False`).
- An **elevated** Windows PowerShell 5.1 session (`powershell.exe`). An OpenSSH logon by a
  member of Administrators is elevated (the doc's "Elevation on the desktop" section).
- `python` and `curl.exe` on `PATH` (Probe 1). Nothing is installed or downloaded in Desktop mode.
- Ports 8899, 9999 and 9998 free (else Probe 1 records SETUP-FAULT and is not run).
- Run it in the foreground and let it finish: the global teardown runs in a `finally`.

## Operator commands

1. Copy the file to the desktop (from the repo root on the Linux box):

   ```bash
   scp docs/probes/n10825/run-probe.ps1 <user>@<desktop-host>:run-probe.ps1
   sha256sum docs/probes/n10825/run-probe.ps1
   ```

2. On the desktop, in the elevated PowerShell session, in the directory holding the file.
   Check the bytes arrived intact. The hash must match `sha256sum` above, and the first
   three bytes must be `239,187,191` (the UTF-8 byte-order mark PS 5.1 needs to read the
   file's em-dashes correctly):

   ```powershell
   (Get-FileHash -Algorithm SHA256 run-probe.ps1).Hash
   (Get-Content -Encoding Byte -TotalCount 3 run-probe.ps1) -join ','
   ```

3. Parse-only pre-check. It prints nothing on success and executes nothing:

   ```powershell
   [scriptblock]::Create((Get-Content -Raw run-probe.ps1)) | Out-Null
   ```

4. Run:

   ```powershell
   powershell -NoProfile -ExecutionPolicy Bypass -File run-probe.ps1 -Mode Desktop -Probes 1,2,3 *> probe-<ts>.log
   ```

   Replace `<ts>` with a UTC timestamp, e.g. `probe-20260928T1200Z.log`. The run takes a
   few minutes and writes `output.txt` in the same directory.

5. Bring back both `probe-<ts>.log` (the full transcript) and `output.txt`.

## Reading the result

`output.txt` holds the environment stamps (date, script SHA-256, run id, OS version, build,
edition, architecture, PowerShell version, user, `elevated=`), then the BEFORE and AFTER
state listings: loopback exemptions, listeners on 8899/9999/9998, `nocklock-probe-*`
scheduled tasks, `nocklock-*` / `agent-escape-*` AppContainer profiles (registry
mappings and package folders) and whether `$probeRoot` exists. Then one `AFTER==BEFORE`
or `AFTER!=BEFORE` line per category, and the final `RUN:` line.

The transcript carries the verdicts: `LAUNCHER-ENV:`, `LIMITED-TOKEN:`,
`VERDICT(1-exempt):`, the `inside(1):` lines with `VERDICT(1):`, `VERDICT(2):` and
`VERDICT(3):`, then the teardown's `RESTORED:` / `LEFTOVER:` lines.

- The scaffold's tool check prints lines for every probe in the doc; a
  `SETUP-FAULT: Probe 5a requires ...` line concerns a probe this run does not execute.
- Exit code 0 and `RUN: COMPLETE` means every probe that ran is recorded and the machine
  state is back to BEFORE. Exit code 1 means `RUN: FAILED`, with the reason on that line.
  Exit code 2 means the probe selection was refused and nothing was changed.
- `TEARDOWN: SETUP-FAULT` means the limited-token task would not stop. The run then keeps
  the task, the probe root, the profiles and the exemption, and prints each by exact name
  with `RECOVERY` commands. Run those by hand once the task reads Ready or Disabled; until
  then it is a failed run.
