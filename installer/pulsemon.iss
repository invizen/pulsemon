; pulsemon Windows installer (Inno Setup 6)
;
; Installs the pulsemon dashboard as a native Windows service:
;   - pulsemon.exe  ->  {autopf}\pulsemon
;   - data dir      ->  C:\ProgramData\pulsemon  (survives upgrade/uninstall)
;   - service       ->  "pulsemon" (LocalSystem, auto-start, restart-on-failure)
;   - shortcuts     ->  Start Menu + optional Desktop
;
; Build (Inno Setup 6 is preinstalled on GitHub Actions Windows runners):
;   ISCC.exe /DMyAppVersion=0.3.0 installer/pulsemon.iss
; The dist\pulsemon-windows-amd64.exe must be built first (see the
; windows-release workflow).

#define MyAppName "pulsemon"
#define MyAppVersion "0.0.0"
#define MyAppPublisher "invizen"
#define MyAppExeName "pulsemon.exe"
#define MyServiceName "pulsemon"
#define MyDataDir "C:\ProgramData\pulsemon"

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
UninstallDisplayIcon={app}\{#MyAppExeName}
CloseApplications=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional icons:"

[Files]
Source: "dist\pulsemon-windows-amd64.exe"; DestDir: "{app}"; DestName: "{#MyAppExeName}"; Flags: ignoreversion

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; Open the dashboard once after install (the service is already running).
Filename: "http://localhost:9299"; Flags: postinstall nowait skipifsilent

[Code]
const
  ServiceName = 'pulsemon';
  DataDir     = 'C:\ProgramData\pulsemon';

// Run a command to completion, hidden. Returns True on exit code 0.
function RunHidden(exe, params: string): Boolean;
begin
  Result := Exec(exe, params, '', SW_HIDE, ewWaitUntilTerminated, nil);
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
end;

procedure CreateService;
var
  exePath: string;
begin
  exePath := ExpandConstant('{app}\{#MyAppExeName}');
  CreateDataDir;
  if ServiceExists() then
    Exit; // idempotent: an upgrade keeps the existing service
  if not RunHidden('sc.exe',
      'create ' + ServiceName +
      ' binPath= "' + exePath + '"' +
      ' start= auto' +
      ' DisplayName= "pulsemon"') then
  begin
    MsgBox('Failed to create the pulsemon service. You can create it manually:' #13#10 +
           'sc create ' + ServiceName + ' binPath= "' + exePath + '" start= auto',
           mbError, MB_OK);
    Exit;
  end;
  RunHidden('sc.exe', 'description ' + ServiceName +
    ' "pulsemon network monitor (ICMP sensor dashboard)"');
  // Restart the service automatically if it crashes (10s, 30s, 60s delays).
  RunHidden('sc.exe', 'failure ' + ServiceName +
    ' reset= 86400 actions= restart/10000/restart/30000/restart/60000');
end;

procedure StartService;
begin
  RunHidden('sc.exe', 'start ' + ServiceName);
end;

procedure StopAndDeleteService;
begin
  if not ServiceExists() then
    Exit;
  RunHidden('sc.exe', 'stop ' + ServiceName);
  // Give the service a moment to finish its clean shutdown (probe drain,
  // alert drain, HTTP drain) before deleting the registration.
  Sleep(2000);
  RunHidden('sc.exe', 'delete ' + ServiceName);
end;

procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssPostInstall then
  begin
    CreateService;
    StartService;
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
begin
  if CurUninstallStep = usUninstall then
  begin
    StopAndDeleteService;
    // The data dir (C:\ProgramData\pulsemon) is intentionally KEPT on
    // uninstall — it holds the operator's sensors and probe history. Delete
    // it manually if you want a full wipe.
  end;
end;
