HospitalHub Remote
==================

Wersja HospitalHub na zdalną maszynę szpitala. Bez instalacji: cały folder
można skopiować w dowolne miejsce (np. C:\Narzędzia\HospitalHubRemote).

1. W HospitalHub na swoim komputerze: Plik -> Eksportuj szpital do vaulta...
   (własne hasło pliku; pozycje admina tylko, jeśli zaznaczysz).
2. Plik .vault połóż obok HospitalHubRemote.exe (albo wskaż go przy starcie).
3. Uruchom HospitalHubRemote.exe, wybierz vault, podaj hasło pliku.

Okno: po lewej "Maszyny" (SSH, RDP, WWW, bazy, AMMS), po prawej terminal.
Po połączeniu SSH lewy panel pokazuje "Pliki" (SFTP) tej sesji.
Dwuklik / Enter = połącz, prawy klik = loginy, edycja, usuwanie.
Każda zmiana zapisuje się od razu do pliku .vault.

Ustawienia i crash.log: folder "dane" obok programu
(gdy folder jest tylko do odczytu: %APPDATA%\HospitalHubRemote).
Usunięcie programu = skasowanie folderu.
