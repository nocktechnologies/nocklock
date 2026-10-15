# N10825 Windows probes: `run-probe.ps1`

Published output files replace the host, account, and home path with `<host>`, `<user>`, and `<home>`; probe verdicts and setup details are retained.

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
- Let it finish: the global teardown runs in a `finally`. Do not press Ctrl+C (see "If the
  run was interrupted"). Over SSH, start it as a one-shot Scheduled Task (step 4) so a dropped session
  cannot end the run; from a console PowerShell, run it in the foreground.
- 64-bit `powershell.exe` (the default). The script refuses a 32-bit host.

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

   **Over SSH**, run it as a one-shot Scheduled Task. Win32-OpenSSH puts the session in a job
   that is killed on close, so a `Start-Process` child can die with the session; a task belongs
   to Task Scheduler and does not depend on the session staying up. From an **elevated** session,
   with `<dir>` the absolute folder holding `run-probe.ps1`. Use a short `<dir>` without spaces,
   for example `C:\nlprobe`, because `/TR` is length-limited.

   Step 1: write a one-line launcher, `<dir>\nlprobe-run.cmd`, holding:

   ```
   cd /d <dir> && powershell -NoProfile -ExecutionPolicy Bypass -File <dir>\run-probe.ps1 -Mode Desktop -Probes 1,2,3 > <dir>\probe-<ts>.log 2>&1
   ```

   Step 2: clear any earlier result by exact name, then create and start the task:

   ```
   if (Test-Path <dir>\output.txt) { Rename-Item <dir>\output.txt output-prev-<ts>.txt }
   schtasks /Create /TN nlprobe-runner /TR "<dir>\nlprobe-run.cmd" /SC ONCE /ST 00:00 /RL HIGHEST /IT /F
   schtasks /Run /TN nlprobe-runner
   ```

   Replace `<ts>` with a UTC timestamp, as above. The redirect saves the full transcript (every
   `VERDICT` line) to `probe-<ts>.log` in the script folder. The task is named `nlprobe-runner`
   so it never matches the script's own `nocklock-probe-*` leftover glob.

   `/IT` runs it in the logged-on console session and `/RL HIGHEST` elevates it; `output.txt`
   records `elevated=`, which shows whether it was. The `cd /d` in the launcher sets the working
   directory to the script folder, so the log and `output.txt` land there.

   Then poll for completion: `output.txt` exists and ends with a `RUN:` line. The script writes
   that line last, and the rename above means a new `output.txt` can only come from this run.
   No `output.txt`, or no final `RUN:` line, means the run has not finished or was cut short.

   One operator, one run at a time. Do not start a run while `nlprobe-runner` exists.

   When the run is done, stop the task, poll until it is no longer running, then delete it:

   ```
   schtasks /End /TN nlprobe-runner
   schtasks /Query /TN nlprobe-runner /FO LIST
   schtasks /Delete /TN nlprobe-runner /F
   ```

   Repeat the `/Query` until its `Status:` line is not `Running`, and only then run `/Delete`.

5. Bring back `output.txt` and `probe-<ts>.log` (the full transcript), for foreground and task runs alike.

## Reading the result

`output.txt` holds the environment stamps (date, script SHA-256, run id, OS version, build,
edition, architecture, PowerShell version, user, `elevated=`), then the BEFORE and AFTER
state listings: loopback exemptions, listeners on 8899/9999/9998, `nocklock-probe-*`
scheduled tasks, `nocklock-*` / `agent-escape-*` AppContainer profiles (registry
mappings and package folders) and every `%TEMP%\nocklock-probe-*` probe root. Then one `AFTER==BEFORE`
or `AFTER!=BEFORE` line per category, and the final `RUN:` line.

The transcript carries the verdicts: `LAUNCHER-ENV:`, `LIMITED-TOKEN:`,
`VERDICT(1-exempt):`, the `inside(1):` lines with `VERDICT(1):`, `VERDICT(2):`, the
`inside(3) whoami:` lines with `VERDICT(3):`, then the teardown's `RESTORED:` /
`LEFTOVER:` lines.

- Every command inside a container runs through `cmd.exe`, never `powershell.exe`,
  which did not start in a zero-capability container on the first desktop run (exit
  `0xC0000142`, `STATUS_DLL_INIT_FAILED`). A `SETUP-FAULT` that names a
  launch prints its exit code in hex; a negative one is an NTSTATUS, meaning that
  process did not start (`0xC0000142`) or crashed (e.g. `0xC0000005`).
- cmd's exit code alone does not prove the target tool ran: when cmd cannot start it
  (access denied on the exe, or the exe missing) cmd exits with its own code. Each
  capture carries a line only the tool writes: curl's `CURL_DONE exit=<n>` (from
  `--write-out`), python's `PYTHON_RAN`, and a SID in the whoami capture. Without it,
  the launch is a `SETUP-FAULT` that says the tool did not run, never a network or
  probe result. A real curl failure keeps its `CURL_DONE exit=<n>` line (e.g. `7`
  refused, `28` timed out).

- The scaffold's tool check prints lines for every probe in the doc; a
  `SETUP-FAULT: Probe 5a requires ...` line concerns a probe this run does not execute.
- Exit code 0 and `RUN: COMPLETE` means every probe that ran is recorded and the machine
  state is back to BEFORE. Exit code 1 means `RUN: FAILED`, with the reason on that line.
  Exit code 2 means the run was refused and nothing on the machine was changed.
- `VERDICT(1): PHASE 1 DEAD` means the container could not reach the live 8899 listener.
  As the doc requires, the run stops there (`RUN: FAILED - aborted`) and teardown still runs.
- `TEARDOWN: SETUP-FAULT` means the limited-token task would not stop. The run then keeps
  the task, the probe root, the profiles and the exemption, and prints each by exact name
  with `RECOVERY` commands. Run those by hand once the task reads Ready or Disabled; until
  then it is a failed run.

## Recorded runs

- [`output-20260928T0558Z.txt`](output-20260928T0558Z.txt): the first desktop run
  (script `30b25dfd`), `output.txt` and the transcript verbatim. `RUN: COMPLETE`;
  `VERDICT(1)` was a SETUP-FAULT (`powershell.exe` exited `0xC0000142` inside the
  container) and `VERDICT(3)` INDETERMINATE, which this revision of the script addresses.

- [`output-20261012T1947Z.txt`](output-20261012T1947Z.txt) and
  [`RESULTS-20261012T1947Z.md`](RESULTS-20261012T1947Z.md): the second desktop run (script
  `495f2b44`). Probe 1's pivot PASSED (loopback reached, off-box did not resolve), Probe 2
  answered (no admin), Probe 1's 9998 bind + listen is an open SETUP-FAULT (python not on the
  container's PATH) and the SSH drop cut the run before Probe 3. This revision runs python by
  absolute path with a package-SID grant, and documents a one-shot Scheduled Task recipe for SSH (round 3 first used `Start-Process`, which can die with the SSH session; round 4 replaced it). Its off-box claim was too strong:
  `exit=6` shows name resolution failed, not that packets are dropped. Round 2 adds a literal-IP
  `curl` to 1.1.1.1, scored as `VERDICT(1-ip)` against an outer control. Only an immediate connect failure (curl exit 7) is BLOCKED; a timeout (exit 28) is INCONCLUSIVE; any reply is reached. The step is scored on its own line.

## If the run was interrupted

A Ctrl+C, a dropped SSH session or a killed `powershell.exe` can end the run before its
teardown finishes. Take `run_id` from `output.txt` and, in an elevated PowerShell, remove
this run's state by exact name. If the run was started as a Scheduled Task, also run `schtasks /End /TN nlprobe-runner`, repeat `schtasks /Query /TN nlprobe-runner /FO LIST` until `Status:` is not `Running`, then `schtasks /Delete /TN nlprobe-runner /F`. Stop the limited-token task first, and run the rest only once it reads
Ready or Disabled:

```powershell
$runId = '<run_id from output.txt>'
Stop-ScheduledTask -TaskName "nocklock-probe-limited-$runId"; (Get-ScheduledTask -TaskName "nocklock-probe-limited-$runId").State
Unregister-ScheduledTask -TaskName "nocklock-probe-limited-$runId" -Confirm:$false
CheckNetIsolation.exe LoopbackExempt -d "-n=nocklock-probe-$runId"
$probeRoot = Join-Path $env:TEMP "nocklock-probe-$runId"
[void][Reflection.Assembly]::Load([IO.File]::ReadAllBytes("$probeRoot\_launcher.dll"))
foreach ($n in "nocklock-probe-$runId", "nocklock-p3-$runId") { '{0} -> 0x{1:X8}' -f $n, [NockProbe.AC]::DeleteProfile($n) }
Remove-Item -Recurse -Force $probeRoot
```

If Probe 1 reached its 9998 step, also revoke the package SID's read + execute grant on the
python install directory (the directory of `python.exe`, e.g.
`C:\Users\<user>\AppData\Local\Programs\Python\Python312`). Do it **before** the
`DeleteProfile` line above (run it first if you already ran the block, and the SID then shows
as a bare `S-1-15-2-...` entry): read the SID from `icacls <python dir>`, where this run's
entry is named `nocklock-probe-<run_id>`:

```powershell
icacls '<python dir>' /remove:g '*<this run SID>'
```

Stop any `python` still listening on 8899, 9999 or 9998 only after checking that its
command line serves `$probeRoot`
(`Get-CimInstance Win32_Process -Filter "Name='python.exe'" | Select ProcessId, CommandLine`).
