; pulsemon Windows installer (Inno Setup 6)
;
; Installs the pulsemon dashboard as a native Windows service:
;   - pulsemon.exe  ->  {autopf}\Pulsemon
;   - data dir      ->  C:\ProgramData\Pulsemon  (survives upgrade/uninstall)
;   - service       ->  "pulsemon" (NT SERVICE\Pulsemon VSA, auto-start, restart-on-failure)
;   - shortcuts     ->  Start Menu + optional Desktop
;
; Build (Inno Setup 6 is preinstalled on GitHub Actions Windows runners):
;   ISCC.exe /DMyAppVersion=0.3.0 installer/pulsemon.iss
; The dist\pulsemon-windows-amd64.exe must be built first (see the
; windows-release workflow).

#define MyAppName "Pulsemon"
; Version is set at build time via `ISCC /DMyAppVersion=X.Y.Z` (see the
; windows-release workflow). The #ifndef guard lets the /D define win; without
; it the hard #define below would silently override the command-line version.
#ifndef MyAppVersion
  #define MyAppVersion "0.0.0"
#endif
#define MyAppPublisher "invizen"
#define MyAppExeName "pulsemon.exe"
#define MyServiceName "Pulsemon"
#define MyDataDir "C:\ProgramData\Pulsemon"

[Setup]
; A fixed GUID identifies the app for upgrade/uninstall bookkeeping. Do not
; change it once shipped (a new GUID = a fresh install, not an upgrade).
AppId={{B7A1C2D4-5E6F-4A7B-8C9D-0E1F2A3B4C5D}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
; x64-only (the shipped binary is windows/amd64).
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
; Admin is required: Program Files install + service registration.
PrivilegesRequired=admin
PrivilegesRequiredOverridesAllowed=dialog
OutputDir=output
OutputBaseFilename=pulsemon-setup-{#MyAppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
SetupIconFile=pulsemon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
CloseApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

[Files]
Source: "..\dist\pulsemon-windows-amd64.exe"; DestDir: "{app}"; DestName: "{#MyAppExeName}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Code]
const
  // The service is NAMED "Pulsemon" (capital P), not just display-named. The
  // SCM locks the name in at `sc create` time and its display-name cache is
  // sticky (sc config / Set-Service return success but do not move it), so the
  // reliable way to present the service as "Pulsemon" in services.msc is to make
  // the name itself "Pulsemon". Service names are case-insensitive for lookup,
  // so `sc stop/start/query Pulsemon` all work against it.
  ServiceName = 'Pulsemon';
  DataDir     = 'C:\ProgramData\Pulsemon';

// Run a command to completion, hidden. Returns True on exit code 0.
function RunHidden(exe, params: string): Boolean;
var
  rc: Integer;
begin
  Result := Exec(exe, params, '', SW_HIDE, ewWaitUntilTerminated, rc);
  Result := (rc = 0);
end;

function ServiceExists(): Boolean;
var
  rc: Integer;
begin
  // sc query exits 0 only when the service exists.
  Exec('sc.exe', 'query ' + ServiceName, '', SW_HIDE, ewWaitUntilTerminated, rc);
  Result := (rc = 0);
end;

procedure CreateDataDir;
begin
  if not DirExists(DataDir) then
  begin
    if not CreateDir(DataDir) then
      MsgBox('Could not create the data directory:' #13#10 + DataDir, mbError, MB_OK);
  end;
  // NOTE: the ACL hardening (M1/F30, 2026-10-19 review: ProgramData
  // inheritance grants BUILTIN\Users read on the SQLite DB - SMTP
  // passwords, webhook tokens) happens in GrantDataDirAcls, which runs
  // AFTER sc create in CreateService: the NT SERVICE\Pulsemon SID only
  // exists once the service is registered, so icacls cannot resolve it
  // before that.
end;

procedure GrantDataDirAcls;
begin
  // Runs on EVERY install (after sc create), so an upgrade also repairs a
  // directory an earlier installer created with the inherited ACL.
  // /T: apply to the directory AND every existing file/subdir. Required on
  // the upgrade path: a pre-VSA DB was created by the built-in-account
  // service and carries no VSA grant - without /T the VSA can create new
  // files in the dir but cannot OPEN the existing DB (crash loop).
  RunHidden('icacls.exe', '"' + DataDir + '" /T /inheritance:r /grant "NT SERVICE\Pulsemon:(OI)(CI)(M)" /grant "BUILTIN\Administrators:(OI)(CI)(F)"');
  // Drop the explicit SYSTEM grant a pre-VSA installer left behind (fresh
  // installs have none; the /remove on a missing entry is best-effort).
  RunHidden('icacls.exe', '"' + DataDir + '" /T /remove "NT AUTHORITY\SYSTEM"');
end;

procedure GrantServiceSelfAccess;
var
  rc: Integer;
begin
  // Grant the service's VSA a query-plus ACE on its OWN service object.
  // The SDDL mask CCLCSWLOCRRC decodes to CHANGE_CONFIG|QUERY_STATUS|STOP|
  // START|USER_DEFINED_CONTROL|QUERY_RECOVERY|READ_CONTROL (0x220136) - a
  // full grant, EXCEPT that the VSA's START/STOP are DENIED AT RUN TIME by
  // mandatory integrity enforcement: the service object carries a higher
  // integrity label than the VSA's Medium-integrity token, and the UI
  // policy blocks write-type rights across that gap REGARDLESS of the
  // DACL (probed live from the service's own token on zendev, 2026-11-23
  // and 2026-11-24: DACL grants START|STOP, OpenService with them is
  // access-denied). So the VSA CANNOT stop/start its own service - and
  // the in-dashboard self-update does NOT try (2026-11-24, decision
  // windows-update-staged): it stages the verified binary and tells the
  // operator to restart the service (services.msc / Restart-Service).
  // What this ACE still buys: the QUERY rights (QUERY_CONFIG,
  // QUERY_STATUS, QUERY_RECOVERY, READ_CONTROL) the update flow's state
  // checks need from the VSA token - the default service SD gives the VSA
  // those only via the Authenticated Users ACE, and this makes the
  // guarantee explicit and VSA-specific. One ACE for the VSA's own SID.
  // Mask notes: NOT ALL_ACCESS (no WRITE_DAC / WRITE_OWNER - a compromised
  // service cannot repoint its binPath or re-grant itself). And NOT the
  // "obvious" minimal CLWRRC: sc.exe's SDDL converter rejects that exact
  // mask combined with the 8-part VSA SID and the default audit SACL
  // (ConvertString... FAILED 1336, reproduced with a synthetic 8-part SID
  // - a parser quirk), while CCLCSWLOCRRC converts cleanly. Runs on EVERY
  // install (CreateService runs on upgrades too), repairing an SD an
  // earlier installer left default. The VSA SID is resolved at runtime -
  // it only exists once `sc create` has materialized it (same
  // precondition as GrantDataDirAcls).
  // PowerShell exits 1 on sdset failure, 2 if sdshow cannot confirm the
  // SID landed. Best-effort: a failure warns but never blocks the
  // install - the monitor works; the recovery action (set separately) is
  // what the self-update depends on.
  // History: docs/DECISIONS.md -> windows-vsa-scm-rights,
  //          windows-recovery-restart
  if not Exec('powershell.exe',
    '-NoProfile -Command "$a = New-Object System.Security.Principal.NTAccount ''NT SERVICE\Pulsemon''; $sid = $a.Translate([System.Security.Principal.SecurityIdentifier]).Value; $sddl = ''D:(A;;CCLCSWRPWPDTLOCRRC;;;SY)(A;;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;BA)(A;;CCLCSWLOCRRC;;;IU)(A;;CCLCSWLOCRRC;;;SU)(A;;CCLCSWLOCRRC;;;'' + $sid + '')S:(AU;FA;CCDCLCSWRPWPDTLOCRSDRCWDWO;;;WD)''; sc.exe sdset ' + ServiceName + ' $sddl; if ($LASTEXITCODE -ne 0) { exit 1 }; if ((sc.exe sdshow ' + ServiceName + ') -notmatch [regex]::Escape($sid)) { exit 2 }; exit 0"',
    '', SW_HIDE, ewWaitUntilTerminated, rc) or (rc <> 0) then
    MsgBox('The Pulsemon service was installed, but its virtual account could not be granted its service-query rights (it falls back to the standard grant; the monitor works).' #13#10 +
           'The next installer run repairs this.',
           mbError, MB_OK);
end;

// Wait until the SCM reports the service STOPPED (or the service is
// absent) before the installer touches its .exe, its DB, or its
// registration. `sc.exe stop` is ASYNCHRONOUS: it only REQUESTS the stop,
// and Pulsemon's graceful shutdown (probe drain, alert drain, HTTP drain)
// can take up to 30s. The old fixed 2-second sleep raced that drain:
// BackupDatabasePreUpdate could capture pulsemon.db while its WAL was
// still open/uncheckpointed (a stale or corrupt .preupdate safety copy),
// and the [Files] overwrite / `sc delete` could hit a sharing violation
// or be deferred by the SCM. Poll the SCM (Get-Service reads the same
// state `sc query` does) once per second, up to 35s; absent = stopped.
// On timeout, warn and proceed: the backup is best-effort by design, and
// a still-running binary makes the [Files] overwrite fail with a clear
// Inno error the operator can act on.
// History: docs/DECISIONS.md -> windows-installer-stop-wait
function WaitForServiceStopped(): Boolean;
var
  rc: Integer;
begin
  Result := Exec('powershell.exe',
    '-NoProfile -Command "$deadline = (Get-Date).AddSeconds(35); while ((Get-Date) -lt $deadline) { $svc = Get-Service -Name ' + ServiceName + ' -ErrorAction SilentlyContinue; if (-not $svc -or $svc.Status -eq ''Stopped'') { exit 0 }; Start-Sleep -Seconds 1 }; exit 1"',
    '', SW_HIDE, ewWaitUntilTerminated, rc) and (rc = 0);
  if not Result then
    MsgBox('The Pulsemon service did not report STOPPED within 35 seconds. The pre-upgrade DB copy may be inconsistent, and the binary swap may fail.' #13#10 +
           'If the install fails, stop the Pulsemon service in services.msc and run the installer again.',
           mbInformation, MB_OK);
end;

procedure CreateService;
var
  exePath: string;
begin
  exePath := ExpandConstant('{app}\{#MyAppExeName}');
  CreateDataDir;
  // Rebuild the service registration on every install. A service left by a
  // pre-v0.3.7 installer is named lowercase "pulsemon"; the SCM will not rename
  // it in place, and its display-name cache is sticky (sc config / Set-Service
  // succeed but do not move it, and a reboot does not reconcile it). Deleting
  // and recreating it as "Pulsemon" is the only reliable way to present it that
  // way. Service names are case-insensitive, so `sc delete Pulsemon` works
  // against a legacy "pulsemon" too. PrepareToInstall already stopped a running
  // service before the file copy; the stop below is a safety net. The same
  // delete+recreate is the VSA UPGRADE PATH: a pre-VSA (built-in-account)
  // registration is replaced by the obj= "NT SERVICE\Pulsemon" create below.
  if ServiceExists() then
  begin
    RunHidden('sc.exe', 'stop ' + ServiceName);
    // sc stop is asynchronous: wait for STOPPED before deleting the
    // registration (the stop in PrepareToInstall already waited; this is
    // the safety-net path - see WaitForServiceStopped).
    WaitForServiceStopped;
    RunHidden('sc.exe', 'delete ' + ServiceName);
  end;
  // obj= "NT SERVICE\Pulsemon": the service runs as its own VIRTUAL service
  // account - least privilege, no local account, no password to manage,
  // auditable by name. The SCM materializes the VSA at create time. ICMP
  // needs no elevation (unprivileged SOCK_DGRAM), so no probe path depends
  // on the full-privilege rights the old registration carried.
  if not RunHidden('sc.exe',
      'create ' + ServiceName +
      ' binPath= "' + exePath + '"' +
      ' start= auto' +
      ' obj= "NT SERVICE\Pulsemon"' +
      ' DisplayName= "Pulsemon"') then
  begin
    MsgBox('Failed to create the Pulsemon service. You can create it manually:' #13#10 +
           'sc create ' + ServiceName + ' binPath= "' + exePath + '" start= auto obj= "NT SERVICE\Pulsemon" DisplayName= "Pulsemon"',
           mbError, MB_OK);
    Exit;
  end;
  // Data-dir ACLs: AFTER sc create (the VSA SID must exist first).
  // M1 (F30, 2026-10-19 review): strip ProgramData inheritance (BUILTIN\Users
  // RX on the DB), grant the VSA modify + Administrators full, drop SYSTEM.
  GrantDataDirAcls;
  // Service-SD self-restart grant: also AFTER sc create (the VSA SID must
  // exist). See GrantServiceSelfAccess.
  GrantServiceSelfAccess;
  // Self-update grant: the service swaps its own .exe (rename the running
  // binary aside, rename the new one in), so the VSA needs modify on the
  // app dir. /T: the .exe is copied BEFORE this grant runs, so the file
  // itself must receive it directly (a dir-only grant covers new files).
  // Deliberate: a compromised service can replace its own binary -
  // inherent to self-update; the update flow verifies sha256 + ed25519
  // signature BEFORE the swap, so this adds no network-facing surface.
  RunHidden('icacls.exe', '"' + ExpandConstant('{app}') + '" /T /grant "NT SERVICE\Pulsemon:(OI)(CI)(M)"');
  RunHidden('sc.exe', 'description ' + ServiceName + ' ' + #34 + 'Pulsemon network monitor (ICMP sensor dashboard)' + #34);
  // Restart the service automatically if it crashes (10s, 30s, 60s
  // delays). CRASH SAFETY NET (2026-11-24, windows-update-staged): a
  // crashed service comes back automatically. The in-dashboard
  // self-update does NOT depend on it - it stages the binary and hands
  // the operator the restart (the VSA cannot start its own service,
  // integrity-enforced).
  RunHidden('sc.exe', 'failure ' + ServiceName +
    ' reset= 86400 actions= restart/10000/restart/30000/restart/60000');
end;

procedure StartService;
begin
  RunHidden('sc.exe', 'start ' + ServiceName);
end;

// Open the dashboard port (9299) in Windows Firewall so the dashboard is
// reachable from the LAN. Idempotent: any existing "pulsemon" rule is
// replaced. Runs elevated (the installer requires admin).
// M2 (F31, 2026-10-19 review): profile=private,domain - WITHOUT it, netsh
// defaults to ALL profiles, so a laptop on a Public network (cafe, airport)
// would expose the dashboard to that network. The homelab LAN is private.
procedure OpenFirewallPort;
begin
  RunHidden('netsh.exe', 'advfirewall firewall delete rule name=pulsemon');
  if not RunHidden('netsh.exe',
      'advfirewall firewall add rule name=pulsemon dir=in action=allow protocol=TCP localport=9299 profile=private,domain') then
    MsgBox('Could not open firewall port 9299. The dashboard still works on this' #13#10 +
           'machine (http://localhost:9299); add a firewall rule for LAN access.',
           mbInformation, MB_OK);
end;

// Remove the firewall rule on uninstall.
procedure RemoveFirewallPort;
begin
  RunHidden('netsh.exe', 'advfirewall firewall delete rule name=pulsemon');
end;

// Ask the service whether it is answering on its HTTP port. PowerShell
// ships with every supported Windows; explicit exit codes on every path
// (success = 0, refused/non-200 = 1) so Inno can read the result.
function HealthzAlive(): Boolean;
var
  rc: Integer;
begin
  Result := Exec('powershell.exe',
    '-NoProfile -Command "try { $r = Invoke-WebRequest -UseBasicParsing -Uri ''http://localhost:9299/api/healthz'' -TimeoutSec 2; if ($r.StatusCode -eq 200) { exit 0 } else { exit 1 } } catch { exit 1 }"',
    '', SW_HIDE, ewWaitUntilTerminated, rc) and (rc = 0);
end;

// Open the dashboard in the default browser after install - but only once
// the service is actually answering. The service needs a few seconds to
// bind its port after `sc start`; opening the browser immediately (the old
// behavior) loads a dead port and the dashboard renders its empty "no
// sensors" state, which on an upgrade reads as "the sensors were wiped"
// (nothing was lost). Poll healthz up to ~15s; open as soon as it
// answers. If it never answers (e.g. a TLS install, where the plain-HTTP
// port is not bound), fall back to opening the default URL after the
// timeout - the old behavior.
// History: docs/DECISIONS.md -> windows-upgrade-safety
procedure OpenDashboard;
var
  rc: Integer;
  i: Integer;
begin
  for i := 1 to 5 do
  begin
    if HealthzAlive() then
      Break;
    Sleep(3000);
  end;
  ShellExec('open', 'http://localhost:9299', '', '', SW_SHOWNORMAL, ewNoWait, rc);
end;

procedure StopAndDeleteService;
begin
  if not ServiceExists() then
    Exit;
  RunHidden('sc.exe', 'stop ' + ServiceName);
  // sc stop is asynchronous: wait for the SCM to report STOPPED (up to 35s)
  // before deleting the registration (a delete against a not-yet-stopped
  // service is deferred by the SCM; see WaitForServiceStopped).
  WaitForServiceStopped;
  RunHidden('sc.exe', 'delete ' + ServiceName);
end;

// Copy the SQLite DB to pulsemon.db.preupdate as a pre-upgrade safety
// copy. Called only while the service is STOPPED (PrepareToInstall before
// the file overwrite, and the uninstall path), so a plain file copy is a
// consistent snapshot - no open WAL to replay over it later. The
// in-dashboard self-update path makes the same copy from INSIDE the
// running service via `VACUUM INTO` (see update.go) before the binary
// swap. Best-effort: a failed copy must never block the upgrade - it only
// degrades to "no extra safety net".
// History: docs/DECISIONS.md -> windows-upgrade-safety
procedure BackupDatabasePreUpdate;
begin
  if FileExists(DataDir + '\pulsemon.db') then
    FileCopy(DataDir + '\pulsemon.db', DataDir + '\pulsemon.db.preupdate', True);
end;

// Stop a running pulsemon service BEFORE the [Files] section overwrites
// pulsemon.exe. On an UPGRADE the old binary is locked while the service runs,
// so the file copy fails (file-in-use / "cannot stop the service") without this.
// PrepareToInstall is called by Inno Setup immediately before files are copied -
// the right hook. On a fresh install the service does not exist, so this is a
// no-op. The (now updated) service is restarted in CurStepChanged(ssPostInstall).
function PrepareToInstall(var NeedsRestart: Boolean): String;
begin
  Result := ''; // empty = no message, proceed with the install
  NeedsRestart := False; // the service restart is handled in ssPostInstall
  if ServiceExists() then
  begin
    RunHidden('sc.exe', 'stop ' + ServiceName);
    // sc stop is asynchronous: wait for STOPPED (up to 35s, the graceful
    // shutdown can drain for 30s) so the .exe handle is released before
    // the overwrite and the DB copy below is a consistent snapshot.
    WaitForServiceStopped;
    // Service is stopped and its DB is consistent: make the pre-upgrade
    // safety copy now (see BackupDatabasePreUpdate).
    BackupDatabasePreUpdate;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    CreateService;
    StartService;
    OpenFirewallPort;
    OpenDashboard;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    StopAndDeleteService;
    // Service is stopped: leave a final consistent safety copy of the DB
    // (the data dir itself is kept on uninstall by design).
    BackupDatabasePreUpdate;
    RemoveFirewallPort;
    // The data dir (C:\ProgramData\Pulsemon) is intentionally KEPT on
    // uninstall - it holds the operator's sensors and probe history. Delete
    // it manually if you want a full wipe.
  end;
end;
