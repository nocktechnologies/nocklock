<#
.SYNOPSIS
  N10825 Windows feasibility probes: Probes 1, 2 and 3, assembled from
  docs/design/windows-feasibility.md ("Probes to run on a real Windows box").

.DESCRIPTION
  Windows PowerShell 5.1 only (powershell.exe, not pwsh). Run from an ELEVATED
  PowerShell session while the operator is logged on interactively at the console
  (the limited-token scheduled task is -LogonType Interactive). See README.md.

  The doc owns every probe line below; this file only orders them, wraps the run in
  try/finally so the global teardown always runs, and records the BEFORE/AFTER state
  and environment stamps to output.txt in the current directory (next to the
  transcript). Keep the doc and this file identical: change the doc first.

  Saved as UTF-8 WITH a byte-order mark. PS 5.1 reads a BOM-less file as ANSI, and
  the doc's em-dashes would then decode to a closing smart quote inside strings.

.PARAMETER Mode
  Desktop (default): nothing is downloaded or installed. DisposableBox: a throwaway VM.

.PARAMETER Probes
  Probe numbers, e.g. -Probes 1,2,3. Probe 2 is scored from Probe 1, so it needs 1.
#>
param(
  [ValidateSet('Desktop', 'DisposableBox')][string]$Mode = 'Desktop',
  [string[]]$Probes = @('1', '2', '3')
)

# --- output.txt: environment stamps and the BEFORE/AFTER state -------------------------
# Lives in the current directory, NOT under $probeRoot (the teardown deletes that).
# Rewritten first, so a refused run never leaves an earlier run's output.txt behind.
# Every line also goes to stdout, so the transcript carries it too.
$outputTxt = Join-Path (Get-Location).Path 'output.txt'
Set-Content -Path $outputTxt -Value '# NockLock N10825 Windows probes (run-probe.ps1)' -Encoding UTF8
function Write-Evidence { process { $_; $_ | Out-File -FilePath $outputTxt -Append -Encoding utf8 } }

# --- Refusals: before anything on the machine is touched -------------------------------
# `-File run-probe.ps1 -Probes 1,2,3` binds one string '1,2,3', hence the split.
$probeList = @()
foreach ($p in @($Probes -split ',').Trim()) {
  if ($p -notmatch '^(1[01]|[1-9])$') { "REFUSED: -Probes entry '$p' is not a probe number 1-11. Nothing was changed." | Write-Evidence; exit 2 }
  $probeList += [int]$p
}
$disposableOnly = @{ 8 = 'installs user-scope packages'; 9 = 'disables the firewall' }   # doc: Probe classification
foreach ($p in $probeList) {
  if ($Mode -eq 'Desktop' -and $disposableOnly.ContainsKey($p)) {
    "REFUSED: Probe $p is DISPOSABLE-BOX ONLY ($($disposableOnly[$p])); never on the desktop. Nothing was changed." | Write-Evidence; exit 2
  }
  if (@(1, 2, 3) -notcontains $p) { "REFUSED: Probe $p is not assembled into this run-probe.ps1 (Probes 1, 2, 3). Nothing was changed." | Write-Evidence; exit 2 }
}
if ($probeList -contains 2 -and $probeList -notcontains 1) {
  "REFUSED: Probe 2 is scored from Probe 1's VERDICT(1-exempt); pass -Probes 1,2. Nothing was changed." | Write-Evidence; exit 2
}
# Stop-VerifiedProcess matches Process.Path, which a 32-bit host reads as empty for a
# 64-bit process: the identity check would then never match and a listener would be left.
if ([Environment]::Is64BitOperatingSystem -and -not [Environment]::Is64BitProcess) {
  "REFUSED: 32-bit PowerShell on 64-bit Windows; run the 64-bit powershell.exe. Nothing was changed." | Write-Evidence; exit 2
}

# Everything this run could leave behind, listed from the machine (not from this run's
# variables) so a leftover from an earlier run shows up in BEFORE too.
function Get-ProbeState {
  $maps = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings'
  [ordered]@{
    exemptions = @(CheckNetIsolation.exe LoopbackExempt -s | Select-String -Pattern 'S-1-15-2-[0-9-]+' -AllMatches |
                   ForEach-Object { $_.Matches.Value } | Sort-Object -Unique)
    ports      = @(Get-NetTCPConnection -State Listen -LocalPort 8899, 9999, 9998 -ErrorAction SilentlyContinue |
                   ForEach-Object { '{0}:{1} pid={2}' -f $_.LocalAddress, $_.LocalPort, $_.OwningProcess } | Sort-Object -Unique)
    tasks      = @(Get-ScheduledTask -ErrorAction SilentlyContinue | Where-Object { $_.TaskName -like 'nocklock-probe-*' } |
                   ForEach-Object { $_.TaskPath + $_.TaskName } | Sort-Object -Unique)
    profiles   = @(@(Get-ChildItem $maps -ErrorAction SilentlyContinue |
                     ForEach-Object { (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Moniker } |
                     Where-Object { $_ -like 'nocklock-*' -or $_ -like 'agent-escape-*' } | ForEach-Object { "mapping:$_" }) +
                   @(Get-ChildItem (Join-Path $env:LOCALAPPDATA 'Packages') -Directory -ErrorAction SilentlyContinue |
                     Where-Object { $_.Name -like 'nocklock-*' -or $_.Name -like 'agent-escape-*' } |
                     ForEach-Object { "folder:$($_.Name)" }) | Sort-Object -Unique)
    probeRoots = @(Get-ChildItem $env:TEMP -Directory -Filter 'nocklock-probe-*' -ErrorAction SilentlyContinue |
                   ForEach-Object { $_.FullName } | Sort-Object)
  }
}
function Write-State([string]$When, $State) {
  foreach ($k in $State.Keys) {
    $v = if ($State[$k].Count) { $State[$k] -join ', ' } else { '(none)' }
    "STATE($When) ${k}: $v"
  }
}

$runId     = (New-Guid).ToString('N')   # run-unique; a 1-second timestamp collides on a fast rerun
$probeRoot = Join-Path $env:TEMP "nocklock-probe-$runId"
$moniker   = "nocklock-probe-$runId"

$elevated = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
  [Security.Principal.WindowsBuiltInRole]::Administrator)
$os = Get-CimInstance Win32_OperatingSystem
$cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
@(
  "date_utc=$((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ'))"
  "script_sha256=$((Get-FileHash -Algorithm SHA256 -LiteralPath $PSCommandPath).Hash)"
  "run_id=$runId mode=$Mode probes=$($probeList -join ',')"
  "os_version=$([Environment]::OSVersion.VersionString)"
  "os_build=$($cv.CurrentBuild).$($cv.UBR)"
  "os_edition=$($cv.EditionID) ($($os.Caption))"
  "os_arch=$($os.OSArchitecture) process_64bit=$([Environment]::Is64BitProcess)"
  "ps=$($PSVersionTable.PSVersion)"
  "user=$([Security.Principal.WindowsIdentity]::GetCurrent().Name) elevated=$elevated"
) | Write-Evidence
$stateBefore = Get-ProbeState
Write-State 'BEFORE' $stateBefore | Write-Evidence
CheckNetIsolation.exe LoopbackExempt -s
logman query -ets
netsh advfirewall show allprofiles state
Test-Path $probeRoot

# Fail-if-exists (no -Force, -ErrorAction Stop): never adopt a pre-existing root.
# With a GUID a collision is effectively impossible, which is the point — if it
# happens it is a bug, not a directory to reuse and inherit stale ACEs from.
New-Item -ItemType Directory -Path $probeRoot -ErrorAction Stop | Out-Null

# From here on the probe root is this run's own, so the global teardown may delete it.
# It runs in the finally after a throw or an abort. Do NOT press Ctrl+C: output from a
# finally on a stopped pipeline can end the teardown early (README: interrupted runs).
$runError = $null
$exitCode = 1
try {

  # --- Run mode (-Mode Desktop|DisposableBox, default Desktop) ---
  # Desktop: NOTHING is downloaded or installed; absent prerequisites = SETUP-FAULT.
  # DisposableBox: may Save-Module, bootstrap NuGet, and fetch software.
  if (-not $Mode) { $Mode = 'Desktop' }

  # --- Tool prerequisites (desktop run) ---
  # On the desktop, required tools must already be present. Each probe declares
  # which commands it needs; a missing command records SETUP-FAULT for that probe
  # and the probe is not scored. Never install on the desktop.
  $requiredTools = @{
    'Probe 1'  = @('python','curl.exe')
    'Probe 5a' = @('git','node','python')
    'Probe 5b' = @('git','node','python','npm','pip')   # disposable-box only
    'Probe 6'  = @('curl.exe','nslookup')
    'Probe 10' = @('curl.exe')
  }
  $setupFaults = @()
  $checkedTools = @{}
  foreach ($probe in $requiredTools.Keys) {
    foreach ($cmd in $requiredTools[$probe]) {
      if (-not $checkedTools.ContainsKey($cmd)) {
        $loc = Get-Command $cmd -ErrorAction SilentlyContinue
        $checkedTools[$cmd] = $loc
        if ($loc) { "$cmd -> $($loc.Source)" }
      }
      if (-not $checkedTools[$cmd]) {
        $setupFaults += "$probe requires $cmd"
        "SETUP-FAULT: $probe requires $cmd — tool not found, probe not scored"
      }
    }
  }

  # --- BEFORE baseline (documented desktop precheck: 0 exemptions, ports free) ---
  $probePorts = 8899, 9999, 9998
  function Get-ExemptCount { @(CheckNetIsolation.exe LoopbackExempt -s | Select-String -Pattern 'S-1-15-2-').Count }
  function Test-ExemptListed { [bool](CheckNetIsolation.exe LoopbackExempt -s | Select-String -SimpleMatch $sid) }   # this run's entry, by SID
  function Get-BusyPorts   { @(Get-NetTCPConnection -State Listen -LocalPort $probePorts -ErrorAction SilentlyContinue).Count }
  $baseExempt = Get-ExemptCount
  $basePorts  = Get-BusyPorts
  "BEFORE: loopbackexempt_count=$baseExempt ports_in_use(8899,9999,9998)=$basePorts (documented desktop baseline: 0, 0)"
  if ($basePorts -ne 0) {
    # A foreign listener on a probe port would answer Probe 1's curls: a wrong-reason pass.
    $setupFaults += 'Probe 1 requires ports 8899/9999/9998 free'
    "SETUP-FAULT: a probe port is already listening — Probe 1 not scored"
  }

  # --- NtObjectManager: disposable box only, never on the desktop ---
  # The scripted steps use the Add-Type launcher below on BOTH boxes. On a throwaway
  # VM, NtObjectManager may be fetched into the probe root for interactive
  # cross-checks; the desktop run never loads or installs it (precheck: ntobj=False).
  if ($Mode -eq 'DisposableBox') {
    Save-Module -Name NtObjectManager -Path (Join-Path $probeRoot 'modules') -Force
    Import-Module (Join-Path $probeRoot 'modules\NtObjectManager')
  }

  # Denial helper used by every "MUST fail" step. It discriminates the HResult:
  # only E_ACCESSDENIED (0x80070005) is a pass; not-found (0x80070002/3) is a
  # FAILED probe — that is the exact bug this round fixes.
  # HResult of the innermost exception, formatted '0x80070005'. A denial from a .NET
  # method call (the launcher, a pipe Connect) arrives wrapped in PowerShell's
  # MethodInvocationException, so the outer exception's HResult is the wrong one.
  function Get-BaseHResult($ErrorRecord) { '0x{0:X8}' -f $ErrorRecord.Exception.GetBaseException().HResult }

  function Assert-AccessDenied {
    param([scriptblock]$Action, [string]$Label)
    # Access-denied from Set-Content/Get-Content is NON-terminating, so it must be
    # forced to terminate or the catch never runs and the helper prints FAIL(no-error)
    # on a real denial. Each call site passes -ErrorAction Stop, which is the
    # guaranteed path regardless of how $ErrorActionPreference scopes into a
    # scriptblock invoked with `&`; this sets the preference too as a backstop.
    $ErrorActionPreference = 'Stop'
    try { & $Action | Out-Null; "FAIL(no-error): $Label" }
    catch [System.UnauthorizedAccessException] { "PASS(denied): $Label" }
    catch {
      $h = Get-BaseHResult $_
      if ($h -eq '0x80070005') { "PASS(denied): $Label" }
      else { "FAIL(wrong-error): $Label -> $($_.Exception.GetBaseException().GetType().FullName) HResult=$h" }
    }
  }

  # Process-identity helpers. Bare PID cleanup can kill an unrelated process after
  # PID reuse; these record and verify PID + StartTime + Path before acting.
  function Write-ProcessIdentity {
    param([System.Diagnostics.Process]$Proc, [string]$FilePath)
    $info = '{0}|{1}|{2}' -f $Proc.Id, $Proc.StartTime.ToString('o'), $Proc.Path
    Set-Content -Path $FilePath -Value $info
  }
  function Stop-VerifiedProcess {
    param([string]$IdentityFile)
    $raw = Get-Content $IdentityFile -ErrorAction SilentlyContinue
    if (-not $raw -or $raw -like 'EXITED:*') { return }
    $parts = $raw -split '\|',3
    # A record without all three fields (a partial write, or a bare PID) cannot be
    # verified. Skip it with a line rather than let [datetime]$null throw and abort the
    # teardown loop before $probeRoot is removed — leftover state is the worse failure.
    if ($parts.Count -lt 3) {
      "TEARDOWN: $IdentityFile holds no verifiable identity — process not stopped"
      return
    }
    $probePid = [int]$parts[0]; $startTime = [datetime]$parts[1]; $path = $parts[2]
    $proc = Get-Process -Id $probePid -ErrorAction SilentlyContinue
    if ($proc -and $proc.StartTime.ToString('o') -eq $startTime.ToString('o') -and $proc.Path -eq $path) {
      Stop-Process -Id $probePid -ErrorAction SilentlyContinue
    }
  }

  # --- The two files the scaffold writes into $probeRoot (doc: "Launcher (desktop
  # path)", "Limited-token runner"). No _inside.ps1: powershell.exe did not start in a
  # zero-capability container on the first desktop run, so Probes 1 and 3 run their inside commands through cmd.exe. ---
  Set-Content -Path (Join-Path $probeRoot '_launcher.cs') -Encoding UTF8 -Value @'
using System;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace NockProbe {
  public static class AC {
    [StructLayout(LayoutKind.Sequential)]
    struct SID_AND_ATTRIBUTES { public IntPtr Sid; public uint Attributes; }
    [StructLayout(LayoutKind.Sequential)]
    struct SECURITY_CAPABILITIES { public IntPtr AppContainerSid; public IntPtr Capabilities; public uint CapabilityCount; public uint Reserved; }
    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct STARTUPINFO {
      public int cb; public string lpReserved, lpDesktop, lpTitle;
      public int dwX, dwY, dwXSize, dwYSize, dwXCountChars, dwYCountChars, dwFillAttribute, dwFlags;
      public short wShowWindow, cbReserved2; public IntPtr lpReserved2, hStdInput, hStdOutput, hStdError;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct STARTUPINFOEX { public STARTUPINFO StartupInfo; public IntPtr lpAttributeList; }
    [StructLayout(LayoutKind.Sequential)]
    struct PROCESS_INFORMATION { public IntPtr hProcess, hThread; public int dwProcessId, dwThreadId; }
    // JOBOBJECT_EXTENDED_LIMIT_INFORMATION with BasicLimitInformation and IoInfo inlined
    // (same layout on x86 and x64: the IoInfo ulongs realign exactly as the nested struct pads).
    [StructLayout(LayoutKind.Sequential)]
    struct JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
      public long PerProcessUserTimeLimit, PerJobUserTimeLimit; public uint LimitFlags;
      public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize; public uint ActiveProcessLimit;
      public UIntPtr Affinity; public uint PriorityClass, SchedulingClass;
      public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount,
                   ReadTransferCount, WriteTransferCount, OtherTransferCount;
      public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }

    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    static extern int CreateAppContainerProfile(string name, string display, string desc, IntPtr caps, uint capCount, out IntPtr sid);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    static extern int DeleteAppContainerProfile(string name);
    [DllImport("userenv.dll", CharSet = CharSet.Unicode)]
    static extern int GetAppContainerFolderPath(string sid, out IntPtr path);
    [DllImport("advapi32.dll")] static extern IntPtr FreeSid(IntPtr sid);
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool ConvertStringSidToSid(string s, out IntPtr sid);
    [DllImport("kernel32.dll")] static extern IntPtr LocalFree(IntPtr p);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool InitializeProcThreadAttributeList(IntPtr list, int count, int flags, ref IntPtr size);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool UpdateProcThreadAttribute(IntPtr list, uint flags, IntPtr attr, IntPtr value, IntPtr size, IntPtr prev, IntPtr retSize);
    [DllImport("kernel32.dll")] static extern void DeleteProcThreadAttributeList(IntPtr list);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern bool CreateProcess(string app, StringBuilder cmd, IntPtr pa, IntPtr ta, bool inherit, uint flags,
      IntPtr env, string cwd, ref STARTUPINFOEX si, out PROCESS_INFORMATION pi);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint WaitForSingleObject(IntPtr h, uint ms);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool GetExitCodeProcess(IntPtr h, out uint code);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(IntPtr h, uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr h);
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateJobObject(IntPtr sa, string name);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool AssignProcessToJobObject(IntPtr job, IntPtr proc);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateJobObject(IntPtr job, uint code);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetInformationJobObject(IntPtr job, int cls, ref JOBOBJECT_EXTENDED_LIMIT_INFORMATION info, uint len);
    [DllImport("kernel32.dll", SetLastError = true)] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")] static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError = true)] static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("advapi32.dll", SetLastError = true)] static extern bool OpenProcessToken(IntPtr proc, uint access, out IntPtr tok);
    [DllImport("advapi32.dll", SetLastError = true)]
    static extern bool GetTokenInformation(IntPtr tok, int cls, IntPtr buf, int len, out int retLen);

    // Win32 failure -> HRESULT_FROM_WIN32 exception, so E_ACCESSDENIED surfaces as
    // UnauthorizedAccessException with HResult 0x80070005 (callers use GetBaseException()).
    static void Check(bool ok) {
      if (!ok) Marshal.ThrowExceptionForHR(unchecked((int)0x80070000) | Marshal.GetLastWin32Error());
    }

    // Run() throws this — never Check()'s HRESULT_FROM_WIN32 shape — when CreateProcess
    // already succeeded and the job-object step failed afterward: that is this harness
    // failing to track a child it already started, not a denial of the launch itself. Left
    // at the CLR default HResult (0x80131500), which cannot collide with an
    // HRESULT_FROM_WIN32(err) value (always 0x8007xxxx), so callers can tell "the launch
    // was denied" from "the launch worked but our bookkeeping didn't" by type, not by
    // reading the same access-denied HResult two different ways.
    public class JobAssignException : Exception {
      public JobAssignException(int win32Error)
        : base("job object assignment failed after CreateProcess succeeded; Win32 error " + win32Error) { }
    }

    // CreateAppContainerProfile with no capabilities; returns the package SID string.
    // Throws if the profile already exists: with a GUID moniker that is a bug, not a profile to adopt.
    public static string CreateProfile(string name) {
      IntPtr sid;
      Marshal.ThrowExceptionForHR(CreateAppContainerProfile(name, name, name, IntPtr.Zero, 0, out sid));
      try { return new SecurityIdentifier(sid).Value; } finally { FreeSid(sid); }
    }

    // DeleteAppContainerProfile; returns the HRESULT (teardown prints it, never throws).
    public static int DeleteProfile(string name) { return DeleteAppContainerProfile(name); }

    // The child's explicit environment block (CREATE_UNICODE_ENVIRONMENT). Windows applies its
    // own AppContainer redirection ON TOP of this block: it appends Packages\<moniker>\AC to the
    // LOCALAPPDATA it is handed and derives TEMP from the result (the first desktop run handed
    // it the AC folder and got ...\AC\Packages\<moniker>\AC). So LOCALAPPDATA carries the base
    // that redirection expects (the AC folder three levels up), TEMP and TMP name AC\Temp
    // (created here), and APPDATA and USERPROFILE name the AC folder itself
    // (%LOCALAPPDATA%\Packages\<moniker>\AC, which CreateAppContainerProfile creates and
    // grants to the package SID). Once Windows' redirection has run (the scaffold's environment
    // self-check proves it), no probe reads or writes the operator's real profile dirs through
    // them. Only the variables tools need to start are copied through.
    // Layout "K=V\0...K=V\0", sorted case-insensitively; StringToHGlobalUni adds the final \0.
    // Returns IntPtr.Zero (inherit) only when the CALLER is itself an AppContainer
    // (Probe 10(a)'s re-container): its own block is already its container's redirected one,
    // and a lookup failure must not hide an escape. Otherwise a failure throws
    // InvalidOperationException with NO inner exception, so it is never read as a launch
    // denial (0x80070005).
    static IntPtr BuildEnvironment(string packageSid) {
      IntPtr p;
      int hr = GetAppContainerFolderPath(packageSid, out p);
      if (hr != 0) {
        bool callerIsAc = false;
        try { callerIsAc = TokenSummary(System.Diagnostics.Process.GetCurrentProcess().Id).StartsWith("AppContainer=True"); }
        catch { }                                   // unreadable own token: treat as not-AC and throw below
        if (callerIsAc) return IntPtr.Zero;
        throw new InvalidOperationException(string.Format("environment block: GetAppContainerFolderPath HRESULT 0x{0:X8}", hr));
      }
      string acDir;
      try { acDir = Marshal.PtrToStringUni(p).TrimEnd('\\'); } finally { Marshal.FreeCoTaskMem(p); }
      string[] copied = { "SystemRoot", "windir", "SystemDrive", "ComSpec", "PATH", "PATHEXT", "PSModulePath",
                          "PROCESSOR_ARCHITECTURE", "NUMBER_OF_PROCESSORS", "OS", "USERNAME", "COMPUTERNAME",
                          "ProgramFiles", "ProgramFiles(x86)", "ProgramW6432", "CommonProgramFiles",
                          "CommonProgramFiles(x86)", "ProgramData", "ALLUSERSPROFILE" };
      var vars = new System.Collections.Generic.SortedDictionary<string, string>(StringComparer.OrdinalIgnoreCase);
      vars["LOCALAPPDATA"] = System.IO.Path.GetDirectoryName(System.IO.Path.GetDirectoryName(System.IO.Path.GetDirectoryName(acDir)));
      try { vars["TEMP"] = vars["TMP"] = System.IO.Directory.CreateDirectory(acDir + "\\Temp").FullName; }
      catch (Exception e) {                        // never an access-denied HResult: a setup fault, not a launch denial
        throw new InvalidOperationException("environment block: cannot create AC\\Temp: " + e.Message);
      }
      vars["APPDATA"] = vars["USERPROFILE"] = acDir;
      foreach (string n in copied) { string v = Environment.GetEnvironmentVariable(n); if (v != null) vars[n] = v; }
      StringBuilder b = new StringBuilder();
      foreach (var kv in vars) b.Append(kv.Key).Append('=').Append(kv.Value).Append('\0');
      return Marshal.StringToHGlobalUni(b.ToString());
    }

    // Starts cmdLine as an AppContainer process for packageSid holding exactly capabilitySids
    // (empty = zero capabilities), cwd = System32 (readable by ALL APPLICATION PACKAGES),
    // environment = BuildEnvironment's explicit block (inherited only when the caller is
    // itself an AppContainer, see BuildEnvironment).
    // Waits up to timeoutMs and returns the exit code. The child starts suspended inside an
    // anonymous job, so a timeout kills its WHOLE tree (TerminateJobObject), not just the
    // direct child, then throws. This job has no KILL_ON_JOB_CLOSE, deliberately: on a normal
    // return from the elevated shell, descendants a probe keeps on purpose survive and are
    // reaped by teardown's verified-identity stop. The case where the CALLER dies mid-Run
    // (the limited task stopped on a timeout) is covered one level up: _limited.ps1 first
    // puts itself in a kill-on-close job (ContainSelf), and this job nests inside it.
    public static int Run(string packageSid, string[] capabilitySids, string cmdLine, int timeoutMs) {
      IntPtr acSid = IntPtr.Zero, caps = IntPtr.Zero, sc = IntPtr.Zero, list = IntPtr.Zero, env = IntPtr.Zero;
      IntPtr[] capPtrs = new IntPtr[capabilitySids.Length];
      bool listInit = false;
      try {
        env = BuildEnvironment(packageSid);
        Check(ConvertStringSidToSid(packageSid, out acSid));
        int saSize = Marshal.SizeOf(typeof(SID_AND_ATTRIBUTES));
        if (capabilitySids.Length > 0) {
          caps = Marshal.AllocHGlobal(saSize * capabilitySids.Length);
          for (int i = 0; i < capabilitySids.Length; i++) {
            Check(ConvertStringSidToSid(capabilitySids[i], out capPtrs[i]));
            SID_AND_ATTRIBUTES sa = new SID_AND_ATTRIBUTES();
            sa.Sid = capPtrs[i]; sa.Attributes = 0x4;   // SE_GROUP_ENABLED
            Marshal.StructureToPtr(sa, caps + i * saSize, false);
          }
        }
        SECURITY_CAPABILITIES s = new SECURITY_CAPABILITIES();
        s.AppContainerSid = acSid; s.Capabilities = caps; s.CapabilityCount = (uint)capabilitySids.Length;
        sc = Marshal.AllocHGlobal(Marshal.SizeOf(typeof(SECURITY_CAPABILITIES)));
        Marshal.StructureToPtr(s, sc, false);

        IntPtr size = IntPtr.Zero;
        InitializeProcThreadAttributeList(IntPtr.Zero, 1, 0, ref size);   // sizing call; fails by design
        list = Marshal.AllocHGlobal(size);
        Check(InitializeProcThreadAttributeList(list, 1, 0, ref size));
        listInit = true;
        Check(UpdateProcThreadAttribute(list, 0, (IntPtr)0x00020009,        // PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES
          sc, (IntPtr)Marshal.SizeOf(typeof(SECURITY_CAPABILITIES)), IntPtr.Zero, IntPtr.Zero));

        STARTUPINFOEX si = new STARTUPINFOEX();
        si.StartupInfo.cb = Marshal.SizeOf(typeof(STARTUPINFOEX));
        si.lpAttributeList = list;
        PROCESS_INFORMATION pi;
        Check(CreateProcess(null, new StringBuilder(cmdLine), IntPtr.Zero, IntPtr.Zero, false,
          0x00080000 | 0x08000000 | 0x00000004 | 0x00000400,   // EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW
                                                                // | CREATE_SUSPENDED | CREATE_UNICODE_ENVIRONMENT
          env, Environment.SystemDirectory, ref si, out pi));
        IntPtr job = IntPtr.Zero;
        try {
          job = CreateJobObject(IntPtr.Zero, null);
          if (job == IntPtr.Zero || !AssignProcessToJobObject(job, pi.hProcess)) {
            int err = Marshal.GetLastWin32Error();
            TerminateProcess(pi.hProcess, 1);                               // never let an untracked child run
            throw new JobAssignException(err);                             // setup fault, not a launch denial
          }
          ResumeThread(pi.hThread);
          if (WaitForSingleObject(pi.hProcess, (uint)timeoutMs) != 0) {
            TerminateJobObject(job, 1);
            throw new TimeoutException("container process exceeded " + timeoutMs + " ms; its job was terminated");
          }
          uint code;
          Check(GetExitCodeProcess(pi.hProcess, out code));
          return (int)code;
        } finally {
          if (job != IntPtr.Zero) CloseHandle(job);
          CloseHandle(pi.hThread); CloseHandle(pi.hProcess);
        }
      } finally {
        if (listInit) DeleteProcThreadAttributeList(list);
        if (list != IntPtr.Zero) Marshal.FreeHGlobal(list);
        if (sc != IntPtr.Zero) Marshal.FreeHGlobal(sc);
        if (caps != IntPtr.Zero) Marshal.FreeHGlobal(caps);
        foreach (IntPtr p in capPtrs) if (p != IntPtr.Zero) LocalFree(p);
        if (acSid != IntPtr.Zero) LocalFree(acSid);
        if (env != IntPtr.Zero) Marshal.FreeHGlobal(env);
      }
    }

    // Puts the CALLING process in a new anonymous job with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    // and never closes the handle. However the caller dies (normal exit, or Stop-ScheduledTask
    // terminating the limited task), the kernel closes that last handle and kills every
    // descendant PROCESS started after this call: CheckNetIsolation, logman, a Run() container
    // (its own job nests inside this one). Kernel objects those processes already created (an
    // ETW session) outlive them; teardown removes those by exact name. Throws if any step fails.
    // Task Scheduler may already hold the caller in a job, so this relies on nested jobs
    // (Windows 8+); a failure fails closed as the positive control's SETUP-FAULT, never an orphan.
    public static void ContainSelf() {
      IntPtr job = CreateJobObject(IntPtr.Zero, null);
      Check(job != IntPtr.Zero);
      JOBOBJECT_EXTENDED_LIMIT_INFORMATION li = new JOBOBJECT_EXTENDED_LIMIT_INFORMATION();
      li.LimitFlags = 0x2000;                                            // KILL_ON_JOB_CLOSE, nothing else
      Check(SetInformationJobObject(job, 9, ref li,                      // JobObjectExtendedLimitInformation
        (uint)Marshal.SizeOf(typeof(JOBOBJECT_EXTENDED_LIMIT_INFORMATION))));
      Check(AssignProcessToJobObject(job, GetCurrentProcess()));
    }

    // A live process's token: AppContainer flag, package SID, integrity-level SID
    // (S-1-16-4096 Low, -8192 Medium, -12288 High). Throws if it cannot be opened.
    public static string TokenSummary(int pid) {
      IntPtr h = OpenProcess(0x1000, false, pid);                         // PROCESS_QUERY_LIMITED_INFORMATION
      Check(h != IntPtr.Zero);
      IntPtr tok = IntPtr.Zero, buf = Marshal.AllocHGlobal(256);
      try {
        int len;
        Check(OpenProcessToken(h, 0x0008, out tok));                       // TOKEN_QUERY
        Check(GetTokenInformation(tok, 29, buf, 4, out len));             // TokenIsAppContainer
        bool isAc = Marshal.ReadInt32(buf) != 0;
        Check(GetTokenInformation(tok, 31, buf, 256, out len));           // TokenAppContainerSid
        IntPtr pkg = Marshal.ReadIntPtr(buf);
        string pkgSid = pkg == IntPtr.Zero ? "-" : new SecurityIdentifier(pkg).Value;
        Check(GetTokenInformation(tok, 25, buf, 256, out len));           // TokenIntegrityLevel
        string il = new SecurityIdentifier(Marshal.ReadIntPtr(buf)).Value;
        return "AppContainer=" + isAc + " PackageSid=" + pkgSid + " IntegrityLevel=" + il;
      } finally {
        if (tok != IntPtr.Zero) CloseHandle(tok);
        CloseHandle(h);
        Marshal.FreeHGlobal(buf);
      }
    }
  }
}
'@
  Set-Content -Path (Join-Path $probeRoot '_limited.ps1') -Encoding UTF8 -Value @'
$probeRoot = $PSScriptRoot
$runId     = (Split-Path -Leaf $probeRoot) -replace '^nocklock-probe-',''
$moniker   = "nocklock-probe-$runId"
$lim       = Join-Path $probeRoot 'limited'
# Line 1 = phase, line 2 = this invocation's id; every result path below is keyed by the id.
$phase, $inv = Get-Content (Join-Path $lim 'request.txt') -ErrorAction Stop
$log       = Join-Path $lim "$inv.log"
$step      = 'setup'
# This invocation's OWN token, so each phase is scored against the token it actually ran under.
whoami /groups | Out-File -FilePath (Join-Path $lim "$inv.token.txt") -Encoding utf8
"PHASE $phase" | Out-File -FilePath $log -Encoding utf8
try {
  # CONTAIN FIRST: this process joins a kill-on-close job, so when a timed-out phase is
  # stopped (Invoke-LimitedPhase), every child it started dies with it instead of carrying
  # on alone. The runner scores no phase whose log lacks `contained=OK`.
  $step = 'contain'
  [void][Reflection.Assembly]::Load([IO.File]::ReadAllBytes((Join-Path $probeRoot '_launcher.dll')))
  [NockProbe.AC]::ContainSelf()
  'contained=OK' | Out-File $log -Append -Encoding utf8
  switch ($phase) {
    'control' { }   # the whoami above plus contained=OK is the whole positive control
    'exempt'  {     # Probe 1's non-elevated exemption step
      CheckNetIsolation.exe LoopbackExempt -a "-n=$moniker" 2>&1 | Out-File $log -Append -Encoding utf8
      "exit=$LASTEXITCODE" | Out-File $log -Append -Encoding utf8
    }
    'probe3'  {
      # The launcher is already loaded: _limited.ps1's contain step loaded it.
      $step = 'createprofile'
      $sid3 = [NockProbe.AC]::CreateProfile("nocklock-p3-$runId")      # throws -> ERROR line (caught above)
      "profile=CREATED sid=$sid3" | Out-File $log -Append -Encoding utf8
      $step = 'grant'
      $d3 = New-Item -ItemType Directory -Path (Join-Path $probeRoot "p3\$inv") -ErrorAction Stop   # this invocation's own dir
      icacls $d3.FullName /grant "*${sid3}:(OI)(CI)(M)" | Out-Null   # the limited token owns p3\<id>\, so it holds WRITE_DAC
      $step = 'run'
      # Two launches through cmd.exe (not powershell.exe, which did not start in a zero-capability
      # container), each with its own exit code and its stderr kept: `whoami /groups` for the token,
      # `set` for the container's own environment, so the verdict shows TEMP/LOCALAPPDATA were redirected.
      # `set` is a cmd builtin, so it ran whenever cmd did; whoami.exe is not (see the SETUP-FAULT arm).
      $rcW = [NockProbe.AC]::Run($sid3, @(), ('cmd.exe /c whoami /groups > "' + (Join-Path $d3.FullName 'whoami-inside.txt') + '" 2>&1'), 60000)
      $rcE = [NockProbe.AC]::Run($sid3, @(), ('cmd.exe /c set > "' + (Join-Path $d3.FullName 'env-inside.txt') + '" 2>&1'), 60000)
      ('launch=OK whoami exit={0} (0x{0:X8}); set exit={1} (0x{1:X8})' -f $rcW, $rcE) | Out-File $log -Append -Encoding utf8
    }
    default   { throw "unknown phase '$phase'" }   # never a silent no-op the runner would accept
  }
} catch {
  $e = $_.Exception.GetBaseException()
  # $step (set by a phase body before each call) says WHICH call failed, so a denial on
  # a setup step is never read as the answer to the probe's question. type= is recorded
  # alongside HResult so a JobAssignException (Run() succeeded at CreateProcess but failed
  # to job-track the child) is never read by its HResult alone: that value is the CLR
  # default (0x80131500), not HRESULT_FROM_WIN32, but the type name is what the scoring
  # below actually keys on.
  ('ERROR: step={0} type={1} HResult=0x{2:X8} {3}' -f $step, $e.GetType().Name, $e.HResult, $e.Message) | Out-File $log -Append -Encoding utf8
} finally {
  # Completion sentinel, written LAST: the outer session never scores a half-written log.
  Set-Content -Path (Join-Path $lim "$inv.done") -Value 'done'
}
'@

  # ORDER: compile + load the launcher and prove the limited token (below) BEFORE any
  # probe starts a listener or touches the loopback exemption. Registering the task is
  # the one machine-wide change that must come first: it is how the token is proven.
  # A launcher that will not compile, load, or register the profile means no launcher
  # probe can run: stop here. The run's try/finally still runs the global teardown.
  $launcherDll = Join-Path $probeRoot '_launcher.dll'
  try {
    $scratch = New-Item -ItemType Directory -Path (Join-Path $probeRoot 'csc-tmp') -ErrorAction Stop
    $oldTmp = $env:TMP; $oldTemp = $env:TEMP
    $env:TMP = $scratch.FullName; $env:TEMP = $scratch.FullName
    try {
      Add-Type -TypeDefinition (Get-Content -Raw (Join-Path $probeRoot '_launcher.cs')) `
        -OutputAssembly $launcherDll -OutputType Library -IgnoreWarnings -ErrorAction Stop   # private P/Invoke structs raise CS0649
    } finally {
      $env:TMP = $oldTmp; $env:TEMP = $oldTemp
    }
    [void][Reflection.Assembly]::Load([IO.File]::ReadAllBytes($launcherDll))
    # Registers the profile (CreateAppContainerProfile): the %LOCALAPPDATA%\Packages\<moniker>\
    # redirection the probes rely on, and what teardown's DeleteProfile removes.
    $sid = [NockProbe.AC]::CreateProfile($moniker)   # SID string; reused by Probes 4, 10, 11
  } catch {
    "SETUP-FAULT: launcher unavailable -> $($_.Exception.GetBaseException().Message); probes 1, 3, 4, 5, 6, 10, 11 not scored"
    throw
  }
  $sid                                               # record this SID string; the icacls probes need it
  icacls $launcherDll /grant "*${sid}:(R)"          # Probe 10(a) loads it inside the container
  # One SID-writable drop dir, created and ACL'd from the OUTER shell (which holds
  # WRITE_DAC; the Low-IL container does not). Inside-container steps hand their verdict
  # logs and any value back out through it — Probe 1's `_inside-1-<name>.txt` captures and,
  # in a run that assembles them, each `_inside.ps1` phase's `_inside-<phase>.log` and
  # Probe 10's WMI child PID (see the bootstrap note above):
  $out = New-Item -ItemType Directory -Force -Path (Join-Path $probeRoot 'out')
  icacls $out.FullName /grant "*${sid}:(OI)(CI)(M)"
  # zero-capability container — the default, and the study's pivot. It doubles as the
  # environment self-check every launcher probe relies on: the child's TEMP and
  # LOCALAPPDATA must lie under this profile's AC folder, or the run stops here.
  # Returns "TEMP=<v> LOCALAPPDATA=<v>" from a `cmd /c set` capture, and $true in
  # $script:redirected only if both are AC or under it (AC\Temp counts) AND exist: a prefix
  # test alone passed the first desktop run's doubled ...\AC\Packages\<moniker>\AC path.
  # Probe 3 reuses it.
  function Test-Redirected([object[]]$Lines, [string]$AcDir) {
    $script:redirected = $true
    $shown = foreach ($n in 'TEMP', 'LOCALAPPDATA') {
      # -join makes a plain string, so an absent line is '' and fails the test below.
      $v = (((@($Lines) -match "^$n=") -replace "^$n=",'') -join ';').TrimEnd('\')
      $ok = ($v -eq $AcDir -or $v.StartsWith("$AcDir\", [StringComparison]::OrdinalIgnoreCase)) -and
            (Test-Path -LiteralPath $v -PathType Container)
      if (-not $ok) { $script:redirected = $false }
      "$n=$v$(if (-not $ok) { ' (not under AC, or missing)' })"
    }
    $shown -join ' '
  }
  $acDir    = (Join-Path $env:LOCALAPPDATA "Packages\$moniker\AC").TrimEnd('\')
  $envSmoke = Join-Path $out.FullName 'env-smoke.txt'
  $rcSmoke  = [NockProbe.AC]::Run($sid, @(), ('cmd.exe /c set > "' + $envSmoke + '"'), 30000)
  $envShown = Test-Redirected (Get-Content $envSmoke -ErrorAction SilentlyContinue) $acDir
  if (-not (Test-Path $envSmoke)) {
    # A negative exit is an NTSTATUS (0xC0000142 = STATUS_DLL_INIT_FAILED): the process never ran.
    "SETUP-FAULT: zero-capability launch wrote no environment capture (exit $rcSmoke = 0x$('{0:X8}' -f $rcSmoke)); run stopped before any probe"
    throw 'launcher environment self-check failed'
  } elseif (-not $redirected) {
    "SETUP-FAULT: container environment not under $acDir ($envShown); run stopped before any probe"
    throw 'launcher environment self-check failed'
  }
  "LAUNCHER-ENV: PASS - $envShown"
  # one capability (internetClient, S-1-15-3-1), for the contrast case:
  [NockProbe.AC]::Run($sid, @('S-1-15-3-1'), 'cmd.exe /c exit 0', 30000)

  $taskName   = "nocklock-probe-limited-$runId"
  $limitedDir = Join-Path $probeRoot 'limited'
  New-Item -ItemType Directory -Path $limitedDir -ErrorAction Stop | Out-Null
  $action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument (
    '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "' + (Join-Path $probeRoot '_limited.ps1') + '"')
  $principal = New-ScheduledTaskPrincipal -UserId ([Security.Principal.WindowsIdentity]::GetCurrent().Name) `
    -LogonType Interactive -RunLevel Limited
  $taskCreated = $false
  $script:limitedDead = $null; $script:limitedStuck = $null   # set only by this run's gate / control
  # Defaults would skip a start on battery; IgnoreNew is kept, so Invoke-LimitedPhase
  # passes the quiescence gate before each /Run (else the /Run is silently ignored).
  $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
  Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings -ErrorAction Stop | Out-Null
  $taskCreated = $true

  # THE ONE QUIESCENCE RULE (see "One quiescence rule" above), and the only place the task
  # is stopped. $true ONLY when the task reads Ready or Disabled after the stop and a wait of
  # up to 30 s; Running, Queued (it would start later and read whatever request.txt then
  # holds) or unreadable is $false. Never throws. A $false is final for the run: it sets
  # $limitedStuck and the fast-fail $limitedDead, and every later call returns $false at once.
  function Assert-LimitedQuiescent {
    if ($script:limitedStuck) { return $false }
    Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
    for ($i = 0; ($st = (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue).State) -in @('Running','Queued') -and $i -lt 30; $i++) { Start-Sleep 1 }
    if ("$st" -in @('Ready','Disabled')) { return $true }
    $script:limitedStuck = "limited task $taskName reads '$st' after Stop-ScheduledTask and a wait of up to 30 s ('' = state unreadable)"
    $script:limitedDead  = $script:limitedStuck
    $false
  }

  # The one abort, run by every limited consumer right after its one verdict: once the gate
  # has failed, no further probe runs; the run's try/finally runs the (keeping) teardown.
  function Stop-RunIfStuck { if ($script:limitedStuck) { throw "SETUP-FAULT: run aborted - $script:limitedStuck" } }

  # Runs one _limited.ps1 phase under a fresh invocation id ($limitedInv, "<phase>-<GUID>")
  # and returns that invocation's log lines ONLY if it completed (its own <id>.done present)
  # AND its own token is proven limited: Medium Mandatory Level (S-1-16-8192) present, High
  # Mandatory Level (S-1-16-12288) absent, AND it ran contained (`contained=OK` in its own
  # log: its children die with it if it is stopped). Otherwise returns $null with the reason in
  # $limitedFault; callers turn $null into SETUP-FAULT, never into a scored result, and
  # then call Stop-RunIfStuck (the gate may have said the task will not stop).
  # `schtasks /Run` returns immediately, hence the bounded poll.
  function Invoke-LimitedPhase {
    param([string]$Phase, [int]$TimeoutSec = 120)
    # A failed positive control, a task that never starts, or one that will not stop fails
    # every later phase at once, instead of each waiting out its own timeout.
    $script:limitedInv = $null         # never left pointing at an earlier invocation
    if ($script:limitedDead) { $script:limitedFault = "limited task unusable ($script:limitedDead)"; return $null }
    $script:limitedFault = $null
    # THE GATE, first: an instance still Running or Queued would pick up the new request.
    if (-not (Assert-LimitedQuiescent)) { $script:limitedFault = $script:limitedStuck; return $null }
    $inv = '{0}-{1}' -f $Phase, [guid]::NewGuid().ToString('N')
    $script:limitedInv = $inv
    $done  = Join-Path $limitedDir "$inv.done"
    $token = Join-Path $limitedDir "$inv.token.txt"
    Set-Content -Path (Join-Path $limitedDir 'request.txt') -Value @($Phase, $inv)
    schtasks /Run /TN $taskName | Out-Null
    if ($LASTEXITCODE -ne 0) { $script:limitedFault = "schtasks /Run exit $LASTEXITCODE"; return $null }
    for ($i = 0; $i -lt $TimeoutSec -and -not (Test-Path $done); $i++) { Start-Sleep 1 }
    if (-not (Test-Path $done)) {
      # TIMEOUT. THE GATE before returning, so a late phase cannot make exemption / profile /
      # ETW changes while the caller carries on; its children die with it (ContainSelf's job).
      # Always $null, even if .done lands after the stop: a timed-out phase is never scored.
      $quiet   = Assert-LimitedQuiescent
      $started = Test-Path $token      # read AFTER the stop: _limited.ps1 writes its token first thing
      $script:limitedFault = "timeout: phase $Phase ($inv) wrote no .done within $TimeoutSec s (started=$started$(if (-not $started) {', console session logged off?'}))"
      if (-not $quiet) {
        $script:limitedFault += "; $script:limitedStuck"   # the caller aborts the run
      } elseif (-not $started) {
        # A task that never started would only repeat the wait: fail every later phase at
        # once. A merely slow phase that did stop costs only itself.
        $script:limitedDead = $script:limitedFault
      }
      return $null
    }
    $medium = [bool](Select-String -Path $token -SimpleMatch 'S-1-16-8192' -ErrorAction SilentlyContinue)
    $high   = [bool](Select-String -Path $token -SimpleMatch 'S-1-16-12288' -ErrorAction SilentlyContinue)
    if (-not $medium -or $high) {
      $script:limitedFault = "phase $Phase ($inv) token not proven limited (Medium present=$medium, High present=$high)"
      return $null
    }
    $lines = Get-Content (Join-Path $limitedDir "$inv.log")
    if ($lines -notcontains 'contained=OK') {
      $script:limitedFault = "phase $Phase ($inv) did not run contained: $((@($lines) -cmatch '^ERROR:') -join '; ')"
      return $null
    }
    $lines
  }

  # POSITIVE CONTROL. limited\control-<GUID>.token.txt is kept verbatim as evidence (the
  # Administrators line should read deny-only); only the two Mandatory Level SIDs are scored.
  if (Invoke-LimitedPhase 'control') {
    "LIMITED-TOKEN: PASS — task token is Medium IL with High absent"
  } elseif ($limitedStuck) {
    "LIMITED-TOKEN: SETUP-FAULT — $limitedFault; run aborted"
    Stop-RunIfStuck
  } else {
    # An unproven token aborts the run HERE, before any probe makes a machine-wide change
    # (listeners, exemption): the teardown then has only the task and the profile to remove.
    "LIMITED-TOKEN: FAIL — $limitedFault; run aborted before any probe"
    throw "SETUP-FAULT: run aborted - limited-token positive control failed"
  }

  # Each probe is a dot-sourced block: its variables stay in script scope (the teardown
  # and Probe 2 read them), and a probe's `return` leaves only its own block.
  if ($probeList -contains 1) {
    "===== Probe 1: zero-capability loopback ====="
    . {
      # A busy probe port (scaffold BEFORE check) means a foreign listener could answer
      # every curl below: do not run Probe 1 at all, so nothing prints as if scored.
      # (`return` leaves this probe's own block in run-probe.ps1, as in Probe 10.)
      if ($setupFaults -match '^Probe 1 ') { "VERDICT(1): SETUP-FAULT - $($setupFaults -match '^Probe 1 ' -join '; '); Probe 1 and Probe 2 not run"; return }

      # terminal A - two listeners OUTSIDE any container (both serve from the probe root).
      # 8899 is the primary target; 9999 is a SECOND real listener so the unrelated-port
      # check below has something to reach — without it, curl to 9999 fails with
      # "connection refused" no matter what the loopback policy does, which is the exact
      # wrong-reason verdict this round removes.
      # $script: (not local): teardown reads these from its own block, same as Invoke-LimitedPhase's state.
      $script:job8899 = Start-Job { python -m http.server 8899 --bind 127.0.0.1 --directory $using:probeRoot }
      $script:job9999 = Start-Job { python -m http.server 9999 --bind 127.0.0.1 --directory $using:probeRoot }

      # terminal A - POSITIVE CONTROLS from OUTSIDE the container: poll each listener
      # up to 10 s (1 s intervals) to confirm it is live before reading inside verdicts.
      # If a listener never answers, record SETUP-FAULT — the inside verdict is unscored.
      $outsideLive = @{}                   # per port; VERDICT(1) reads it
      foreach ($port in @(8899, 9999)) {
        $up = $false
        for ($i = 0; $i -lt 10; $i++) {
          curl.exe -sS -m 1 -o NUL http://127.0.0.1:${port}/ 2>$null
          if ($LASTEXITCODE -eq 0) { $up = $true; break }
          Start-Sleep 1
        }
        $outsideLive[$port] = $up
        if ($up) { "outside $port -> live" }
        else     { "outside $port -> SETUP-FAULT (listener not ready after 10 s)" }
      }

      # terminal B - register the exemption NON-ELEVATED first, through the limited-token
      # task (the SSH shell is elevated, so running -a here would answer Probe 2 for the
      # wrong reason). Presence is read by this run's SID (scaffold's Test-ExemptListed).
      # CLEAN STATE FIRST: a repeated attempt would otherwise find the entry an earlier
      # (possibly elevated-fallback) attempt left, and score it as the limited add's. So remove
      # THIS run's entry by moniker and prove it absent; if it will not go, nothing is measured.
      # The if/elseif chain is ONE expression assigned once, so exactly one verdict prints.
      CheckNetIsolation.exe LoopbackExempt -d "-n=$moniker" | Out-Null
      $preClean    = -not (Test-ExemptListed)
      $nonElevated = if ($preClean) { Invoke-LimitedPhase 'exempt' }
      # THE GATE, before presence is read and before anything elevated touches the exemption:
      # a surviving limited instance could add the entry after either. On $false: this one
      # verdict, no elevated fallback, and the run aborts.
      if (-not (Assert-LimitedQuiescent)) {
        "VERDICT(1-exempt): SETUP-FAULT - $limitedStuck; no elevated fallback, run aborted"
        Stop-RunIfStuck
      }
      # Case-sensitive: only the phase's own `exit=` / `ERROR:` lines, never CheckNetIsolation's "Error:" text.
      $limitedRc   = (@($nonElevated) -cmatch '^(exit=|ERROR:)') -join '; '
      # Presence is read right after the limited attempt, BEFORE any elevated retry can add it.
      # NON-ELEVATED OK needs the limited -a's own exit code (exactly `exit=0`, no ERROR line)
      # AND the entry present — never the log merely being non-empty.
      $limListed = [bool]$nonElevated -and (Test-ExemptListed)
      $limOk     = $limListed -and $limitedRc -ceq 'exit=0'
      $elevOk    = $false
      if ($preClean -and -not $limListed) {
        # Not proven limited, or the limited -a left no entry: add it ELEVATED so the
        # rest of Probe 1 can still run.
        CheckNetIsolation.exe LoopbackExempt -a "-n=$moniker" | Out-Null
        $elevOk = Test-ExemptListed
      }
      $verdict1x = if (-not $preClean) {
          "SETUP-FAULT - this run's entry still listed after -d, so a limited add cannot be measured; Probe 2 not scored"
        } elseif (-not $nonElevated -and $elevOk) {
          "SETUP-FAULT - limited phase not proven ($limitedFault); exemption added ELEVATED, Probe 2 not scored"
        } elseif (-not $nonElevated) {
          "SETUP-FAULT - limited phase not proven ($limitedFault) and elevated -a did not list the entry; Probe 1 not scored"
        } elseif ($limOk) {
          "NON-ELEVATED OK - limited-token -a exited 0 and listed the entry (Probe 2: admin not required) [$limitedRc]"
        } elseif ($limListed) {
          "SETUP-FAULT - entry listed after the limited -a, but it did not report exit=0 [limited: $limitedRc]; Probe 2 not scored"
        } elseif ($elevOk -and $limitedRc -cmatch '^exit=-?[1-9]\d*$') {
          # Scored only when the limited -a ran to completion AND refused (a nonzero exit= line, no
          # ERROR). A body that threw, or exit=0 with the entry absent, is not a refusal: exit codes
          # alone are not trusted either way, so those fall through to SETUP-FAULT.
          "ADMIN REQUIRED - limited-token -a ran ($limitedRc) and left no entry; elevated -a listed it (Probe 2: admin required)"
        } elseif ($elevOk) {
          "SETUP-FAULT - limited -a gave no usable answer (threw, or exit=0 yet no entry) [limited: $limitedRc]; exemption added ELEVATED, Probe 2 not scored"
        } else {
          "SETUP-FAULT - entry absent after limited AND elevated -a [limited: $limitedRc]; Probe 1 not scored"
        }
      "VERDICT(1-exempt): $verdict1x"

      # then, inside a ZERO-capability container: each measured command in its own launch from
      # the elevated shell, run by cmd.exe. Not powershell.exe: it did not start in a
      # zero-capability container (the first desktop run's launch exited 0xC0000142,
      # STATUS_DLL_INIT_FAILED, while cmd.exe started). Never run those curls in this shell: an
      # outer curl answers nothing about the container. cmd writes each command's output (curl's
      # error text included) into the granted $out dir, curl's --write-out appends
      # `CURL_DONE exit=<curl's exit code>`, and the launcher returns cmd's exit code; all are printed
      # verbatim as inside(1) lines, so the verdict is read from the recorded output, not inferred.
      # cmd's exit code alone does not prove curl ran: when cmd cannot start curl.exe (access denied
      # on the exe, or the exe missing) it exits with its own code, which can fall inside curl's 0-255.
      # Only curl writes CURL_DONE, so a capture without `CURL_DONE exit=<launch exit>` is a
      # SETUP-FAULT, recorded in hex, never a network result.
      $log1 = @(); $fault1 = @()
      foreach ($c in @(@('8899',    'curl.exe -sS -m 5 http://127.0.0.1:8899/'),      # MUST succeed, or Phase 1 is dead
                       @('example', 'curl.exe -sS -m 5 https://example.com/'),        # MUST fail (Block Outbound Default Rule)
                       @('9999',    'curl.exe -sS -m 5 http://127.0.0.1:9999/'))) {   # unrelated loopback port: EXPECTED reachable
        $capture = Join-Path $out.FullName "_inside-1-$($c[0]).txt"
        try {
          $rc = [NockProbe.AC]::Run($sid, @(), ('cmd.exe /c ' + $c[1] + ' -w "\nCURL_DONE exit=%{exitcode}\n" > "' + $capture + '" 2>&1'), 60000)
          $got = @(Get-Content $capture -ErrorAction SilentlyContinue)
          $log1 += $got + "$($c[0]) exit=$rc"
          if (-not ($got -ccontains "CURL_DONE exit=$rc")) {
            $fault1 += '{0} curl did not run (no CURL_DONE exit={1}; cmd text above): launch exit={1} (0x{1:X8})' -f $c[0], $rc
          }
        } catch {
          $fault1 += '{0} launch threw {1} HResult={2} {3}' -f $c[0], $_.Exception.GetBaseException().GetType().Name, (Get-BaseHResult $_), $_.Exception.GetBaseException().Message
        }
      }
      $log1 | ForEach-Object { "inside(1): $_" }
      # The agent binds its own listener: python binds 127.0.0.1:9998, listens, prints one line
      # and exits, so the claim (bind + listen inside, outbound-only scope below) is its exit code
      # and nothing is left running to reap. A per-user python (e.g. under %LOCALAPPDATA%\Programs)
      # is unreadable to a zero-capability container: cmd's error text then shows in the capture.
      # python prints PYTHON_RAN first: a capture without it means cmd never started python, a
      # SETUP-FAULT, never the bind's answer.
      $capture = Join-Path $out.FullName '_inside-1-9998.txt'
      $bind9998 = try {
        $rc = [NockProbe.AC]::Run($sid, @(), ('cmd.exe /c python -c "print(''PYTHON_RAN'', flush=True); import socket; s = socket.socket(); ' +
          's.bind((''127.0.0.1'', 9998)); s.listen(1); print(''bind+listen OK'', s.getsockname())" > "' + $capture + '" 2>&1'), 60000)
        'exit={0} (0x{0:X8})' -f $rc
      } catch {
        'threw {0} HResult={1} {2}' -f $_.Exception.GetBaseException().GetType().Name, (Get-BaseHResult $_), $_.Exception.GetBaseException().Message
      }
      $got = @(Get-Content $capture -ErrorAction SilentlyContinue)
      $got | ForEach-Object { "inside(1) 9998: $_" }
      if (-not ($got -ccontains 'PYTHON_RAN')) { $bind9998 = "SETUP-FAULT - python did not run (no PYTHON_RAN), launch $bind9998" }
      "inside(1) 9998 bind+listen: $bind9998"
      $exempt1 = Test-ExemptListed        # read BEFORE Probe 1's teardown, like everything scored below

      # Probe 1's own teardown (see Teardown below), before the next probe runs.
      $job8899, $job9999 | Stop-Job -PassThru | Remove-Job

      # Nothing is scored unless every curl launch carried its matching CURL_DONE line (so curl.exe
      # ran: not denied, missing, untracked, timed out or an NTSTATUS), BOTH outside listeners
      # answered, and this run's exemption is listed: an inside curl that failed against a dead
      # listener or a missing exemption is a setup fault.
      $unscored1 = @($fault1)
      foreach ($port in @(8899, 9999)) { if (-not $outsideLive[$port]) { $unscored1 += "outside $port listener never answered" } }
      if (-not $exempt1) { $unscored1 += "this run's loopback exemption is not listed" }
      $inside8899 = @(@($log1) -cmatch '^8899 exit=')
      if ($inside8899.Count -ne 1) { $unscored1 += "the inside 8899 curl recorded $($inside8899.Count) '8899 exit=' lines, not 1" }
      if ($unscored1.Count) {
        "VERDICT(1): SETUP-FAULT - $($unscored1 -join '; '); not scored"
      } elseif ($inside8899[0] -cne '8899 exit=0') {
        # The doc's stop rule: the first curl failing means Phase 1 is dead; do not run the rest.
        "VERDICT(1): PHASE 1 DEAD - the zero-capability container could not reach the live 8899 listener ($($inside8899 -join '; ')); remaining probes not run"
        throw 'Probe 1: Phase 1 dead (8899 unreachable from the container); run stopped as the doc requires'
      } else {
        "VERDICT(1): 8899 reached; read example.com (MUST fail) and 9999 (against its outside control) from the inside(1) lines above, per the doc's Probe 1 rules"
      }
    }
  }
  if ($probeList -contains 2) {
    "===== Probe 2: does the exemption need elevation? ====="
    . {
      CheckNetIsolation.exe LoopbackExempt -s      # entry present in this session?
      # Probe 2 computes nothing of its own: it restates Probe 1's one verdict next to the -s read.
      if ($verdict1x) { "VERDICT(2): from VERDICT(1-exempt) - $verdict1x; this run's entry listed by -s: $(Test-ExemptListed)" }
      else            { "VERDICT(2): not scored - Probe 1 did not reach its exemption step" }
    }
  }
  if ($probeList -contains 3) {
    "===== Probe 3: AppContainer launch unelevated ====="
    . {
      $p3 = Invoke-LimitedPhase 'probe3'
      $inv3 = $limitedInv                  # this call's id, captured once
      # Read ONLY this invocation's dir; with no proven run, read nothing.
      $d3  = if ($p3) { Join-Path $probeRoot "p3\$inv3" }
      $w   = if ($d3) { Get-Content (Join-Path $d3 'whoami-inside.txt') -ErrorAction SilentlyContinue }
      $e3  = if ($d3) { Get-Content (Join-Path $d3 'env-inside.txt') -ErrorAction SilentlyContinue }
      # The launcher's redirect target, checked with the scaffold's Test-Redirected.
      $ac3  = (Join-Path $env:LOCALAPPDATA "Packages\nocklock-p3-$runId\AC").TrimEnd('\')
      $env3 = "container " + (Test-Redirected $e3 $ac3)
      $p3err = (@($p3) -match '^ERROR:') -join '; '
      $w | ForEach-Object { "inside(3) whoami: $_" }   # verbatim, so any verdict below can be checked against it
      if (-not $p3) {
        "VERDICT(3): SETUP-FAULT - $limitedFault; not scored"
      } elseif ($p3 | Select-String -Pattern '^ERROR: step=run type=JobAssignException') {
        # CreateProcess succeeded; only the job-tracking step after it failed. That is this
        # harness failing to keep its own bookkeeping, not the AppContainer launch being denied,
        # so it must never fall into the FAILS UNELEVATED arm below even though Run() also
        # threw from this same $step.
        "VERDICT(3): SETUP-FAULT - $p3err; not scored"
      } elseif ($p3 | Select-String -Pattern '^ERROR: step=(createprofile|run) .*HResult=0x80070005') {
        # CreateProfile or Run itself was DENIED under the limited token: the answer is "needs admin".
        # A denial on grant is a setup problem and falls through to INDETERMINATE. `.*` between
        # step= and HResult= tolerates the type= field (or any future field) landing between them
        # instead of silently stopping matching the day the log format grows a column.
        "VERDICT(3): FAILS UNELEVATED - $p3err"
      } elseif (-not ($p3 | Select-String -SimpleMatch 'launch=OK')) {
        # Any other failure (grant, a Run timeout, ...) is not a denial. A launcher that did not
        # load never reaches here: no contained=OK, so $p3 is $null and the first arm prints SETUP-FAULT.
        "VERDICT(3): INDETERMINATE - $p3err"
      } elseif (-not ($p3 -cmatch '^launch=OK whoami exit=0 .*; set exit=0 ')) {
        # A capture whose launch exited nonzero measured nothing; the hex names it (an NTSTATUS
        # such as 0xC0000142 means that process did not start; 0xC0000005 that it crashed).
        # Only whoami prints SIDs, so `whoami.exe ran: False` means cmd could not start it (access
        # denied on the exe, or missing); cmd's own error is in the inside(3) whoami lines above.
        "VERDICT(3): SETUP-FAULT - inside capture failed: $((@($p3) -cmatch '^launch=OK') -join '; '); whoami.exe ran: $([bool](@($w) -cmatch 'S-1-\d')); not scored"
      } elseif (-not (($w | Select-String -SimpleMatch 'S-1-16-4096') -and ($w | Select-String -Pattern 'S-1-15-2-1\b'))) {
        "VERDICT(3): INDETERMINATE - launched, but p3\$inv3\whoami-inside.txt shows no Low IL (S-1-16-4096) plus ALL APPLICATION PACKAGES (S-1-15-2-1)"
      } elseif (-not $redirected) {
        # A Low-IL child that still sees host TEMP/LOCALAPPDATA means the launcher's environment block is wrong.
        "VERDICT(3): INDETERMINATE - Low-IL AppContainer child launched, but it was not redirected to $ac3 ($env3)"
      } else {
        "VERDICT(3): WORKS UNELEVATED - limited-token parent created the profile and launched a Low-IL AppContainer child ($env3)"
      }
      Stop-RunIfStuck
    }
  }
} catch {
  $runError = $_.Exception.Message
  "RUN ABORTED: $runError"
} finally {
  "===== Global teardown ====="
  # --- BEFORE (also run this at the very start, to diff against). The scaffold has
  # already recorded $baseExempt / $basePorts; the documented desktop baseline is 0 / 0.
  CheckNetIsolation.exe LoopbackExempt -s
  logman query -ets
  netsh advfirewall show allprofiles state
  Test-Path $probeRoot

  # --- TEARDOWN (desktop run — no package uninstalls). Everything by EXACT name. ---
  $profileNames = @($moniker, "nocklock-p3-$runId", "agent-escape-$runId")   # scaffold, Probe 3, Probe 10
  # THE GATE, before any destructive step. Guarded: a scaffold that failed before registering
  # the task may not have defined the gate either, and no instance can exist then.
  $quiet = (-not $taskCreated) -or (Assert-LimitedQuiescent)
  # Not limited-task state, so these run either way:
  if ($pipeGranted) { $pipeGranted.Dispose() }               # Probe 11
  if ($pipeNoAce)   { $pipeNoAce.Dispose() }
  $job8899, $job9999 | Where-Object { $_ } | Remove-Job -Force -ErrorAction SilentlyContinue   # Probe 1's listeners, by handle (an abort skips its own teardown)
  if ($etwCreated) { logman stop $etwSession -ets 2>$null }  # only if THIS run created it
  # Reap spawned processes BEFORE deleting $probeRoot (identity files live there).
  # Walks the one well-known identity-file path directly — wmi-child.txt (Probe 10b) is the
  # only one this scaffold ever writes, under $probeRoot\out. Built from $probeRoot, not $out: $out isn't assigned until after the
  # launcher compile/CreateProfile step (which can fail and re-throw before that
  # assignment), and this loop must still run — and reach the cleanup below it — on that
  # early-abort path. Never a *.txt scan of $probeRoot either: that would risk reaping (or
  # misreading) a probe's own log or output file that happens to share the directory.
  foreach ($idFile in @((Join-Path $probeRoot 'out\wmi-child.txt'))) {
    Stop-VerifiedProcess -IdentityFile $idFile
  }
  # Probe 9 (VM only): restore firewall to the recorded per-profile state
  if (-not $quiet) {
    # KEEP everything a surviving instance could use or recreate; print it and the recovery.
    "TEARDOWN: SETUP-FAULT - $limitedStuck; kept in place, by exact name:"
    "  scheduled task : $taskName"
    "  probe root     : $probeRoot"
    "  exemption      : $moniker"
    "  profiles       : $($profileNames -join ', ')"
    "RECOVERY (elevated PowerShell). Stop it and read its state; run the rest ONLY once it reads Ready or Disabled:"
    "  Stop-ScheduledTask -TaskName '$taskName'; (Get-ScheduledTask -TaskName '$taskName').State"
    "  Unregister-ScheduledTask -TaskName '$taskName' -Confirm:`$false"
    "  CheckNetIsolation.exe LoopbackExempt -d -n=$moniker"
    "  [void][Reflection.Assembly]::Load([IO.File]::ReadAllBytes('$probeRoot\_launcher.dll'))   # skip in this session"
    foreach ($n in $profileNames) { "  [NockProbe.AC]::DeleteProfile('$n')" }
    if ($etwCreated) { "  logman stop $etwSession -ets" }
    "  Remove-Item -Recurse -Force '$probeRoot'"
  } else {
    if ($taskCreated) {                                      # the limited-token task: exact name, never a wildcard
      Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    CheckNetIsolation.exe LoopbackExempt -d "-n=$moniker" | Out-Null   # machine-wide exemption (Probes 1-2)
    if ('NockProbe.AC' -as [type]) {                         # launcher loaded => profiles may exist
      foreach ($n in $profileNames) {                        # DeleteAppContainerProfile; HRESULT printed, never thrown
        'TEARDOWN: DeleteProfile {0} -> 0x{1:X8}' -f $n, [NockProbe.AC]::DeleteProfile($n)
      }
    }
    Remove-Item -Recurse -Force $probeRoot                   # everything else lived here

    # --- AFTER: ASSERT the BEFORE baseline is restored. One line per check; any
    # LEFTOVER line is a failed run, to be cleaned by hand using the name it prints.
    # (Skipped on the kept branch above: its listing already names what is left.)
    function Assert-Restored([string]$Label, [bool]$Ok) { if ($Ok) { "RESTORED: $Label" } else { "LEFTOVER: $Label" } }
    $mappings = 'HKCU:\Software\Classes\Local Settings\Software\Microsoft\Windows\CurrentVersion\AppContainer\Mappings'
    $leftMaps = @(Get-ChildItem $mappings -ErrorAction SilentlyContinue |
      Where-Object { $profileNames -contains (Get-ItemProperty $_.PSPath -ErrorAction SilentlyContinue).Moniker })
    Assert-Restored "loopback exemptions back to BEFORE ($baseExempt)" ((Get-ExemptCount) -eq $baseExempt)
    if ($sid) {        # unset only if the scaffold stopped before the profile existed
      Assert-Restored "this run's SID absent from LoopbackExempt -s" (-not (Test-ExemptListed))
    }
    Assert-Restored "ports 8899/9999/9998 back to BEFORE ($basePorts listening)" ((Get-BusyPorts) -eq $basePorts)
    if ($taskName) {   # unset only if the scaffold stopped before registering the task
      Assert-Restored "scheduled task $taskName absent" (-not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue))
    }
    foreach ($n in $profileNames) {
      Assert-Restored "AppContainer profile folder $n absent" (-not (Test-Path (Join-Path $env:LOCALAPPDATA "Packages\$n")))
    }
    Assert-Restored "AppContainer Mappings keys for this run's monikers absent" ($leftMaps.Count -eq 0)
    Assert-Restored "probe root $probeRoot absent" (-not (Test-Path $probeRoot))
  }
  logman query -ets                                          # ETW: diff by eye against BEFORE

  # --- AFTER: the machine listing again; AFTER must equal BEFORE. ---
  $stateAfter = Get-ProbeState
  Write-State 'AFTER' $stateAfter | Write-Evidence
  # Covers everything the doc's RESTORED/LEFTOVER lines check (by category, for every run's
  # leftovers, not only this run's names), so a LEFTOVER always shows up here as a mismatch.
  $mismatch = @()
  $(foreach ($k in $stateBefore.Keys) {
    if (($stateAfter[$k] -join ', ') -cne ($stateBefore[$k] -join ', ')) { $mismatch += $k; "AFTER!=BEFORE: $k" }
    else { "AFTER==BEFORE: $k" }
  }) | Write-Evidence
  if ($runError)           { "RUN: FAILED - aborted: $runError" | Write-Evidence }
  elseif ($mismatch.Count) { "RUN: FAILED - AFTER != BEFORE for $($mismatch -join ', '); clean up by the names above" | Write-Evidence }
  else                     { $exitCode = 0; "RUN: COMPLETE - AFTER == BEFORE for every listed category" | Write-Evidence }
}
exit $exitCode
