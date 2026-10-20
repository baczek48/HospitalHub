; Inno Setup script dla HospitalHub (wersja 2.x, projekt hospital_hub_v2)
; Kompilacja: iscc HospitalHubV2.iss (lub prawym -> Compile w Inno Setup IDE)
;
; 2026-10-16 (prośba właściciela): instalator ZASTĘPUJE poprzednie wersje i w
; Windows widnieje jako „HospitalHub”, nie „HospitalHub V2”:
;   * AppId = AppId HospitalHub 1.x -> Windows widzi aktualizację 1.5.x -> 2.x
;     (ten sam wpis w „Aplikacje”, ten sam katalog Program Files\HospitalHub,
;     te same skróty „HospitalHub”),
;   * plik programu instalowany jako HospitalHub.exe (build PyInstallera nadal
;     nazywa się HospitalHubV2.exe — spec bez zmian; onedir szuka _internal
;     obok exe, nazwa pliku nie ma znaczenia),
;   * stara instalacja „HospitalHub V2” (osobny AppId) jest odinstalowywana po
;     cichu przed instalacją — znika jej wpis, katalog i skróty.
; Przed instalacją HospitalHub (każda wersja) musi być zamknięty — instalator
; nie zamyka go sam, żeby nie stracić niezapisanych zmian w vaultach.
;
; Dane użytkownika (config, diagnostyka) są w %APPDATA%\HospitalHubV2 — poza
; {app}; ani instalacja, ani odinstalowanie ich NIE rusza (V1: %APPDATA%\HospitalHub,
; też nietknięte). Pliki .vault leżą tam, gdzie je zapisano.
;
; Test bez UAC: instalacja per-user do wskazanego katalogu, z podmienionymi
; identyfikatorami, żeby nie dotknąć prawdziwych instalacji:
;   iscc /DMyAppId={{...}} /DOldV2AppId={{...}} /DSkipRunningCheck HospitalHubV2.iss
;   HospitalHub-Setup-X.exe /CURRENTUSER /VERYSILENT /SUPPRESSMSGBOXES
;       /TASKS="" /DIR=<katalog> /LOG=<plik>
; Wersję można nadpisać przy kompilacji: iscc /DMyAppVersion=2.0.1 HospitalHubV2.iss

#define MyAppName      "HospitalHub"
#ifndef MyAppVersion
  #define MyAppVersion "2.0.0"
#endif
#define MyAppPublisher "Sebastian Bąk"
#define MyAppExeName   "HospitalHub.exe"
#define BuildExeName   "HospitalHubV2.exe"
; AppId HospitalHub 1.x (C:\claude\hospital_hub\HospitalHub.iss) — aktualizacja w miejscu
#ifndef MyAppId
  #define MyAppId "{{A7F3C4D2-8B1E-4A9F-B5D6-1E3F9C2A7B48}"
#endif
; AppId dawnej osobnej instalacji „HospitalHub V2” — usuwana przed instalacją
#ifndef OldV2AppId
  #define OldV2AppId "{9C95F6FD-94FE-43B5-87FB-C7CD6477CE2E}"
#endif

[Setup]
AppId={#MyAppId}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
DefaultDirName={autopf}\{#MyAppName}
DefaultGroupName={#MyAppName}
DisableProgramGroupPage=yes
OutputDir=dist_installer
OutputBaseFilename=HospitalHub-Setup-{#MyAppVersion}
SetupIconFile=icon.ico
UninstallDisplayIcon={app}\{#MyAppExeName}
UninstallDisplayName={#MyAppName}
Compression=lzma2/ultra
SolidCompression=yes
WizardStyle=modern
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
PrivilegesRequired=admin
; /CURRENTUSER tylko z linii poleceń (testy, brak admina) — kreator bez zmian
PrivilegesRequiredOverridesAllowed=commandline
VersionInfoVersion={#MyAppVersion}
VersionInfoProductName={#MyAppName}
VersionInfoDescription={#MyAppName} — instalator
; Restart Manager zamyka działającą aplikację przed podmianą plików
CloseApplications=yes

[Languages]
Name: "pl"; MessagesFile: "compiler:Languages\Polish.isl"

[Tasks]
Name: "desktopicon"; Description: "Utwórz skrót na pulpicie"; GroupDescription: "Skróty:"

[InstallDelete]
; Biblioteki 1.x nie mogą zostać wymieszane z 2.x w jednym _internal.
Type: filesandordirs; Name: "{app}\_internal"
Type: files; Name: "{app}\{#BuildExeName}"

[Files]
Source: "dist\HospitalHubV2\{#BuildExeName}"; DestDir: "{app}"; DestName: "{#MyAppExeName}"; Flags: ignoreversion
Source: "dist\HospitalHubV2\*"; Excludes: "\{#BuildExeName}"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{group}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{group}\Odinstaluj {#MyAppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"; Tasks: desktopicon

[Run]
; runasoriginaluser (2026-10-20): started elevated by the UAC-elevated
; installer, the app failed on two machines (permissions and more); started
; from the desktop it worked.  Start it as the signed-in user instead.
Filename: "{app}\{#MyAppExeName}"; Description: "Uruchom {#MyAppName}"; Flags: nowait postinstall skipifsilent runasoriginaluser

[Code]
const
  OldV2Key = 'Software\Microsoft\Windows\CurrentVersion\Uninstall\{#OldV2AppId}_is1';

function OldV2Uninstaller(var Cmd: String): Boolean;
begin
  Result := RegQueryStringValue(HKLM64, OldV2Key, 'UninstallString', Cmd)
         or RegQueryStringValue(HKLM32, OldV2Key, 'UninstallString', Cmd)
         or RegQueryStringValue(HKCU, OldV2Key, 'UninstallString', Cmd);
end;

function IsRunning(const ExeName: String): Boolean;
var
  Code: Integer;
begin
  Result := Exec(ExpandConstant('{cmd}'),
    '/C tasklist /FI "IMAGENAME eq ' + ExeName + '" /NH | find /I "' + ExeName + '"',
    '', SW_HIDE, ewWaitUntilTerminated, Code) and (Code = 0);
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  Cmd: String;
  Code: Integer;
begin
  Result := '';
#ifndef SkipRunningCheck
  if IsRunning('HospitalHub.exe') or IsRunning('{#BuildExeName}') then
  begin
    Result := 'HospitalHub jest uruchomiony. Zamknij go całkowicie '
            + '(ikona w zasobniku -> Zamknij całkowicie) i uruchom instalator ponownie.';
    Exit;
  end;
#endif
  if OldV2Uninstaller(Cmd) then
  begin
    Log('Odinstalowuję starą instalację HospitalHub V2: ' + Cmd);
    if not Exec(RemoveQuotes(Cmd), '/VERYSILENT /SUPPRESSMSGBOXES /NORESTART', '',
                SW_HIDE, ewWaitUntilTerminated, Code) or (Code <> 0) then
    begin
      Result := 'Nie udało się odinstalować poprzedniej wersji „HospitalHub V2” '
              + '(kod ' + IntToStr(Code) + '). Odinstaluj ją ręcznie w Ustawienia -> '
              + 'Aplikacje i uruchom instalator ponownie.';
      Exit;
    end;
    // The uninstaller may finish in a copy of itself: wait until its entry is gone.
    Code := 0;
    while OldV2Uninstaller(Cmd) and (Code < 60) do
    begin
      Sleep(500);
      Code := Code + 1;
    end;
    if OldV2Uninstaller(Cmd) then
    begin
      Result := 'Poprzednia wersja „HospitalHub V2” nadal jest zainstalowana. '
              + 'Odinstaluj ją ręcznie w Ustawienia -> Aplikacje i uruchom instalator ponownie.';
      Exit;
    end;
  end;
end;
