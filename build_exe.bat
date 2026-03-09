@echo off
echo Instalowanie PyInstaller...
pip install pyinstaller --quiet

echo.
echo Budowanie Hospital Vault.exe...
pyinstaller --onefile --windowed ^
    --name "HospitalVault" ^
    --add-data "ui;ui" ^
    main.py

echo.
if exist "dist\HospitalVault.exe" (
    echo SUKCES! Plik: dist\HospitalVault.exe
) else (
    echo BLAD - sprawdz logi powyzej
)
pause
