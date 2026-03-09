@echo off
echo Instalowanie PyInstaller...
pip install pyinstaller --quiet

echo.
echo Budowanie Hospital Vault.exe...
pyinstaller --onefile --windowed ^
    --name "HospitalHub" ^
    --add-data "ui;ui" ^
    main.py

echo.
if exist "dist\HospitalHub.exe" (
    echo SUKCES! Plik: dist\HospitalHub.exe
) else (
    echo BLAD - sprawdz logi powyzej
)
pause
