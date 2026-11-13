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
py -3.13 -m PyInstaller --noconfirm HospitalHubRemote.spec
if errorlevel 1 (
    echo BLAD: PyInstaller zwrocil blad. Przerwano.
    exit /b 1
)
if not exist "dist\HospitalHubRemote\HospitalHubRemote.exe" (
    echo BLAD: nie znaleziono dist\HospitalHubRemote\HospitalHubRemote.exe
    exit /b 1
)
copy /y "remote_README.txt" "dist\HospitalHubRemote\CZYTAJ.txt" >nul

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
