@echo off
echo Instalowanie PyInstaller...
pip install pyinstaller --quiet

echo.
echo Budowanie Hospital Vault.exe...
pyinstaller --onefile --windowed ^
    --name "HospitalHub" ^
    --icon "icon.ico" ^
    --add-data "ui;ui" ^
    --hidden-import win32gui ^
    --hidden-import win32con ^
    --hidden-import win32api ^
    --hidden-import PyQt6.QtNetwork ^
    main.py

echo.
if exist "dist\HospitalHub.exe" (
    echo SUKCES! Plik: dist\HospitalHub.exe
) else (
    echo BLAD - sprawdz logi powyzej
)
pause
