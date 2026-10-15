@echo off
REM ---------------------------------------------------------------------------
REM  Build HospitalHub V2  (onedir + opcjonalny instalator Inno Setup)
REM
REM  Buduje WYLACZNIE projekt z tego katalogu. Nie dotyka C:\claude\hospital_hub.
REM  Wynik:
REM     dist\HospitalHubV2\HospitalHubV2.exe
REM     dist_installer\HospitalHubV2-Setup-2.0.0.exe   (jesli jest Inno Setup)
REM ---------------------------------------------------------------------------
setlocal
cd /d "%~dp0"

echo === HospitalHub V2: build ===
echo Katalog: %CD%
echo.

REM Python 3.13 — domyslny 3.12 nie ma PyQt6 ani PyInstallera
py -3.13 -m PyInstaller --noconfirm HospitalHubV2.spec
if errorlevel 1 (
    echo.
    echo BLAD: PyInstaller zwrocil blad. Przerwano.
    exit /b 1
)

if not exist "dist\HospitalHubV2\HospitalHubV2.exe" (
    echo.
    echo BLAD: nie znaleziono dist\HospitalHubV2\HospitalHubV2.exe
    exit /b 1
)

echo.
echo OK: dist\HospitalHubV2\HospitalHubV2.exe

REM --- instalator (opcjonalnie) ---------------------------------------------
set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if not exist "%ISCC%" set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
REM instalacja Inno Setup "dla biezacego uzytkownika"
if not exist "%ISCC%" set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"

if exist "%ISCC%" (
    echo.
    echo === Budowanie instalatora ===
    "%ISCC%" HospitalHubV2.iss
    if errorlevel 1 (
        echo BLAD: ISCC zwrocil blad.
        exit /b 1
    )
    echo OK: dist_installer\HospitalHubV2-Setup-2.0.0.exe
) else (
    echo.
    echo Inno Setup nie znaleziony - pominieto budowanie instalatora.
    echo Recznie:  iscc HospitalHubV2.iss
)

endlocal
