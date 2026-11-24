@echo off
REM ---------------------------------------------------------------------------
REM  Build HospitalHub Remote  (portable, bez instalatora)
REM
REM  Wersja HospitalHub na zdalna maszyne szpitala: jeden vault szpitala,
REM  lista maszyn + terminal + SFTP w jednym oknie (remote_main.py).
REM  Wynik:
REM     dist\HospitalHubRemote\HospitalHubRemote.exe
REM     dist_portable\HospitalHubRemote-<wersja>.zip
REM  Uzycie:  build_remote.bat 2.0.24
REM ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0"
set "VER=%~1"
if "%VER%"=="" set "VER=dev"

echo === HospitalHub Remote %VER%: build ===
py -3.13 write_build_info.py "%VER%"
py -3.13 -m PyInstaller --noconfirm HospitalHubRemote.spec
set "PYI_ERR=%errorlevel%"
del /q _build_info.py 2>nul
if not "%PYI_ERR%"=="0" (
    echo BLAD: PyInstaller zwrocil blad. Przerwano.
    exit /b 1
)
if not exist "dist\HospitalHubRemote\HospitalHubRemote.exe" (
    echo BLAD: nie znaleziono dist\HospitalHubRemote\HospitalHubRemote.exe
    exit /b 1
)
copy /y "remote_README.txt" "dist\HospitalHubRemote\CZYTAJ.txt" >nul

REM Rejestr HL7 (2026-11-19): Oracle Instant Client dla kont z haslem 10G
REM (DPY-3015). Caly, niezmieniony folder z licencja Oracle (BASIC_LITE_LICENSE).
set "IC=third_party\instantclient_19_29"
if exist "%IC%\oci.dll" (
    xcopy /e /i /q /y "%IC%" "dist\HospitalHubRemote\instantclient_19_29" >nul
    if errorlevel 1 (
        echo BLAD: nie skopiowano Instant Client. Przerwano.
        exit /b 1
    )
) else (
    echo UWAGA: brak %IC% - paczka bez Oracle Instant Client.
)

if not exist dist_portable mkdir dist_portable
if exist "dist_portable\HospitalHubRemote-%VER%.zip" del /q "dist_portable\HospitalHubRemote-%VER%.zip"
REM Compress-Archive zawodzil na duzym _internal (wyjatek bez kodu bledu),
REM wiec .NET ZipFile + sprawdzenie, czy zip naprawde powstal.
powershell -NoProfile -Command "Add-Type -AssemblyName System.IO.Compression.FileSystem; [IO.Compression.ZipFile]::CreateFromDirectory((Resolve-Path 'dist\HospitalHubRemote').Path, (Join-Path (Resolve-Path 'dist_portable').Path 'HospitalHubRemote-%VER%.zip'), 'Optimal', $true)"
if not exist "dist_portable\HospitalHubRemote-%VER%.zip" (
    echo BLAD: nie udalo sie spakowac zipa.
    exit /b 1
)
echo OK: dist_portable\HospitalHubRemote-%VER%.zip
endlocal
