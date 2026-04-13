@echo off
setlocal

echo === [1/3] Instalowanie PyInstaller ===
pip install pyinstaller --quiet

echo.
echo === [2/3] Budowanie HospitalHub (onedir) ===
rmdir /s /q build 2>nul
rmdir /s /q dist\HospitalHub 2>nul

pyinstaller --onedir --windowed ^
    --name "HospitalHub" ^
    --icon "icon.ico" ^
    --add-data "ui;ui" ^
    --hidden-import win32gui ^
    --hidden-import win32con ^
    --hidden-import win32api ^
    --hidden-import PyQt6.QtNetwork ^
    main.py

if not exist "dist\HospitalHub\HospitalHub.exe" (
    echo BLAD: PyInstaller nie wygenerowal exe
    pause
    exit /b 1
)

echo.
echo === [3/3] Budowanie instalatora (Inno Setup) ===

set "ISCC="
if exist "%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe" set "ISCC=%ProgramFiles(x86)%\Inno Setup 6\ISCC.exe"
if exist "%ProgramFiles%\Inno Setup 6\ISCC.exe"      set "ISCC=%ProgramFiles%\Inno Setup 6\ISCC.exe"
if exist "%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe" set "ISCC=%LOCALAPPDATA%\Programs\Inno Setup 6\ISCC.exe"

if "%ISCC%"=="" (
    echo BLAD: Nie znaleziono Inno Setup 6.
    echo Pobierz z https://jrsoftware.org/isdl.php i zainstaluj.
    pause
    exit /b 1
)

"%ISCC%" HospitalHub.iss
if errorlevel 1 (
    echo BLAD kompilacji instalatora
    pause
    exit /b 1
)

echo.
echo === SUKCES ===
for %%F in (dist_installer\HospitalHub-Setup-*.exe) do echo Instalator: %%F
pause
