# HospitalHub 2

Narzędzie do zarządzania infrastrukturą IT szpitali. Dane połączeń, poświadczenia i notatki trzyma w zaszyfrowanym vaulcie. Zamiast rozrzuconych plików i karteczek masz jedno okno, z którego łączysz się przez SSH, SFTP, RDP i VPN.

**Pobierz:** [najnowszy instalator](https://github.com/baczek48/HospitalHub/releases/latest) (Windows 10/11, x64). Instalator aktualizuje HospitalHub 1.x w miejscu: ten sam wpis w „Aplikacjach”, ten sam katalog i skróty. Vaulty i ustawienia zostają nietknięte.

---

## Funkcje

### Zaszyfrowany vault
- **AES-256-GCM**, klucz wyprowadzany z hasła głównego przez **Argon2id** (64 MB, 3 iteracje).
- Zapis atomowy: awaria w trakcie zapisu nie uszkodzi pliku. Obok vaulta zostaje kopia poprzedniej wersji (`.vault.bak`).
- Hasło główne nie jest nigdzie zapisywane.
- Zmiany zapisujesz ręcznie (`Ctrl+S`). Pasek tytułu pokazuje `[niezapisane]`.

### Szpitale, maszyny, bazy danych
- Struktura: szpital → maszyny (SSH/RDP) → bazy danych → notatki o środowisku.
- Kilka zestawów login/hasło na maszynę i na bazę.
- Kliknięcie komórki kopiuje jej zawartość. Hasło w schowku jest wykluczone z historii schowka Windows (Win+V) i z synchronizacji w chmurze, a po 15 s znika.
- Bazy danych: Oracle, MSSQL i inne. Przycisk uruchamia **SQL Developer** i kopiuje hasło.

### SSH i terminal
- Wbudowany terminal z wieloma kartami, historią do 250 000 linii, kolorowaniem logów i obsługą X11.
- Klucze hostów zapamiętywane przy pierwszym połączeniu (**TOFU**). Zmiana klucza hosta daje wyraźne ostrzeżenie.
- Wysyłanie tej samej komendy do kilku kart naraz.
- Szybkie połączenie z hostem spoza vaulta.

### SFTP
- Przeglądarka plików z edycją w zewnętrznym edytorze. Każdy zapis w edytorze trafia z powrotem na serwer.
- **Bezpieczny zapis:** zmieniony plik idzie na serwer najpierw jako plik tymczasowy, a potem w całości podmienia oryginał. Zerwane połączenie nie zostawi uciętego pliku. Gdy serwer nie pozwala na taką podmianę (plik innego właściciela, katalog bez prawa zapisu), zapis idzie bezpośrednio, z informacją w pasku stanu.
- **Konflikty:** gdy plik zmienił się na serwerze od chwili otwarcia, program pyta, zamiast go nadpisywać. Możesz nadpisać, porównać z wersją z serwera albo nie wgrywać.
- Niewysłane zmiany nie giną: przy zamknięciu trafiają do `Dokumenty\HospitalHub - niewysłane zmiany`.
- Każdy wysłany blok potwierdza serwer, więc pełny dysk czy odrzucony zapis dają błąd od razu.

### RDP
- Połączenia przez podpisany plik `.rdp`. Poświadczenia trafiają do Menedżera poświadczeń Windows (nigdy do argumentów procesu) i są usuwane po 30 s oraz przy zamknięciu programu.
- Mapowanie lokalnych dysków w sesji.

### VPN
- **FortiClient, Stormshield, Barracuda:** uruchomienie klienta, wybór profilu z weryfikacją, uzupełnienie loginu i hasła oraz obsługa 2FA.
- **GlobalProtect, SonicWall NetExtender:** uruchomienie klienta i status.
- **Windows VPN:** notatka i status.
- Status połączenia na liście szpitali, także dla tunelu połączonego przed uruchomieniem HospitalHub.

### Asystent w terminalu (opcjonalny)
- Panel pomocy obok terminala, osobny dla każdej karty. Asystent tylko czyta zawartość terminala i niczego nie wpisuje.
- Przed wysłaniem treści numery **PESEL** są maskowane, także w segmentach HL7 `PID`.
- Wymaga zainstalowanego Claude Code. Bez niego reszta programu działa normalnie.

### Tryb admina
- Osobne hasło admina (Argon2id) ukrywa wybrane maszyny, bazy i poświadczenia.

### Diagnostyka
- Dziennik zdarzeń i log VPN (włączany ręcznie). Eksport diagnostyki przed zapisaniem sprawdza, czy nie zawiera haseł ani tokenów.

---

## Granice zabezpieczeń

- **Tryb admina chroni tylko w interfejsie.** Poświadczenia admina leżą w tym samym pliku vaulta, zaszyfrowanym hasłem głównym. Kto zna hasło główne, może je odczytać poza aplikacją.
- Vault i tryb admina nie blokują się same po bezczynności.
- Asystent w terminalu wysyła zawartość terminala do zewnętrznej usługi AI. Maskowane są tylko numery PESEL, więc nie używaj go przy ekranach z innymi danymi pacjentów. Poza asystentem i połączeniami, które sam uruchamiasz, program nie łączy się z niczym.

---

## Uruchomienie ze źródeł

Wymagania: Windows 10/11, **Python 3.13**.

```bat
git clone -b v2 https://github.com/baczek48/HospitalHub.git
cd HospitalHub
py -3.13 -m pip install -r requirements.txt
py -3.13 main.py
```

Testy:
```bat
py -3.13 -m pytest tests -q
```

Build (PyInstaller, a jeśli jest zainstalowany Inno Setup 6, także instalator):
```bat
build_v2.bat
```

Dane programu: `%APPDATA%\HospitalHubV2\` (konfiguracja, dziennik awarii), klucze hostów SSH w `%USERPROFILE%\.hospitalhub_v2_known_hosts`.

---

## Stos technologiczny

| Warstwa | Biblioteka |
|---|---|
| UI | PyQt6 |
| Terminal | pyte |
| SSH / SFTP | paramiko |
| Szyfrowanie | cryptography (AES-GCM), argon2-cffi |
| Automatyzacja klientów VPN | pywin32, comtypes (UI Automation) |
| Instalator | PyInstaller, Inno Setup |

---

© 2026 Sebastian Bąk. Wszelkie prawa zastrzeżone.
