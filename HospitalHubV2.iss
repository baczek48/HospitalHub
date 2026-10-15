; Inno Setup script dla HospitalHub V2
; Kompilacja: iscc HospitalHubV2.iss (lub prawym -> Compile w Inno Setup IDE)
;
; UWAGA: to jest OSOBNY produkt względem HospitalHub 1.x —
;   * inny AppId  -> Windows traktuje go jako niezależną instalację,
;   * inny katalog docelowy, inna grupa w menu Start, inny plik .exe,
;   * inna nazwa pliku instalatora.
; Dzięki temu obie wersje mogą być zainstalowane i uruchomione jednocześnie,
; a odinstalowanie jednej nie rusza drugiej.

#define MyAppName      "HospitalHub V2"
#define MyAppVersion   "2.0.0"
#define MyAppPublisher "Sebastian Bąk"
#define MyAppExeName   "HospitalHubV2.exe"

[Setup]
; GUID wygenerowany dla V2 — NIE może być taki sam jak w HospitalHub 1.x
AppId={{9C95F6FD-94FE-43B5-87FB-C7CD6477CE2E}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\HospitalHubV2
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=dist_installer
OutputBaseFilename=HospitalHubV2-Setup-{#MyAppVersion}
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
Compression=lzma2/ultra
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin

[Languages]
Name: "pl"; MessagesFile: "compiler:Languages\Polish.isl"

[Tasks]
Name: "desktopicon"; Description: "Utwórz skrót na pulpicie"; GroupDescription: "Skróty:"

[Files]
Source: "dist\HospitalHubV2\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Odinstaluj {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Uruchom {#MyAppName}"; Flags: nowait postinstall skipifsilent
