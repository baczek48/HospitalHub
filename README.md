# HospitalHub

> © 2026 Sebastian Bąk. Wszelkie prawa zastrzeżone.

Narzędzie do zarządzania infrastrukturą IT szpitali. Przechowuje dane połączeń, poświadczenia i notatki w zaszyfrowanym vaulcie — jedno okno zamiast rozrzuconych plików i karteczek.

---

## Pobieranie

Gotowy plik exe (bez instalacji, bez Pythona) w zakładce [**Releases**](https://github.com/baczek48/HospitalHub/releases).

> **Windows SmartScreen** może zapytać przy pierwszym uruchomieniu — kliknij **Więcej informacji → Uruchom mimo to**. Przy kolejnych uruchomieniach nie pyta.

---

## Funkcje

### Zaszyfrowany vault
- Szyfrowanie **AES-256-GCM** + wyprowadzanie klucza **Argon2id** (64 MB RAM, 3 iteracje)
- Atomiczny zapis — awaria w trakcie zapisu nie uszkodzi pliku
- Hasło główne nigdy nie jest przechowywane — weryfikowane przy każdym otwarciu
- Plik `.vault` można bezpiecznie przesłać e-mailem — jest w całości zaszyfrowany

### Maszyny / Hosty
- Połączenia **SSH** z wbudowanym terminalem i przeglądarką plików **SFTP**
- Połączenia **RDP** z automatycznym wstrzykiwaniem poświadczeń (ctypes CredWriteW, czyszczone po 30 s)
- **Mapowanie dysków RDP** — wybór lokalnych dysków udostępnianych w sesji
- Wiele zestawów login/hasło na maszynę
- Przeciąganie wierszy, konfigurowalny drag & drop
- **Szybkie połączenie SSH** — przycisk ⇆ w nagłówku, połącz się z dowolnym hostem bez dodawania do vault

### Bazy danych
- Obsługa **Oracle**, **MSSQL** i innych typów
- Wiele zestawów poświadczeń na bazę
- Przycisk ⛃ w nagłówku panelu uruchamia **SQL Developer** i kopiuje hasło do schowka
- Kopiowanie hasła jednym kliknięciem (auto-wyczyszczenie schowka po 15 s)

### Terminal SSH
- Pełny emulator terminala (VT220/pyte), historia **50 000 linii**
- Rozszerzone kolorowanie logów:
  - Błędy, ostrzeżenia, OK/ACCEPT — czerwony / żółty / zielony
  - Adresy **IPv4** (z portem), **IPv6**, **MAC** — cyjan
  - Metody HTTP (GET, POST...) — żółte; kody **2xx/4xx/5xx** — zielony/żółty/czerwony
  - Adresy e-mail — zielone; daty — szare
  - Słowa odmowy (denied, rejected, down...) — czerwone
  - Słowa pozytywne (enabled, active, true...) — zielone
  - Detekcja promptów powłoki
- Natychmiastowa reakcja na **Ctrl+C** (drain bufora PTY, brak zamrożenia)
- Wiele zakładek sesji, automatyczny resize PTY
- Panel sesji SSH z selektorem szpitali i maszyn

### Przeglądarka SFTP
- Ikony typów plików (foldery, skrypty, logi, archiwa, obrazy, PDF, konfiguracje)
- Edytowalna belka ścieżki — kliknij i wpisz ręcznie
- Historia nawigacji
- Sortowanie z folderami na górze
- Ochrona przed path traversal
- Pliki tymczasowe czyszczone przy zamknięciu aplikacji

### Tryb admina
- Oddzielne hasło admina hashowane **Argon2id**
- Ukrywanie wrażliwych maszyn, baz danych i poświadczeń (fioletowe oznaczenie + 🔒)
- Automatyczna blokada po **5 minutach** nieaktywności
- Ustawianie hasła: **Plik → Ustaw / zmień hasło admina**

### Bezpieczeństwo
- Polityka **TOFU** dla kluczy SSH — ostrzeżenie przy zmianie klucza hosta (możliwy MitM)
- Sanityzacja błędów — hasła nigdy nie trafiają do komunikatów wyjątków
- Ochrona przed **path traversal** przy pobieraniu plików przez SFTP
- Walidacja adresów IP i portów przed uruchomieniem RDP
- RDP: poświadczenia przez **ctypes CredWriteW** — hasło nie pojawia się w argumentach procesu
- Działa w pełni **offline** — brak zewnętrznych połączeń

---

## Obsługa

### Pierwsze uruchomienie
Przy starcie aplikacja pyta o vault:
- **Utwórz nowy vault** → wybierz lokalizację i ustaw hasło główne (min. 8 znaków)
- **Otwórz istniejący vault** → wskaż plik `.vault` i podaj hasło

Ścieżka do pliku jest zapamiętywana — przy kolejnym uruchomieniu od razu pojawia się pole hasła.

### Struktura danych
```
Szpital
  ├─ Maszyny / Hosty  (IP, nazwa, opis, poświadczenia, SSH/RDP)
  ├─ Bazy danych      (host, port, nazwa, typ, poświadczenia, notatka)
  └─ Notatki o środowisku
```

### Zapis
Zmiany **nie są zapisywane automatycznie**. Pasek tytułowy pokazuje `[niezapisane]`.

| Akcja | Skrót |
|---|---|
| Zapisz | `Ctrl+S` |
| Zapisz jako / kopia | `Ctrl+Shift+S` |

### Kopiowanie danych
Kliknięcie dowolnej komórki tabeli kopiuje jej zawartość do schowka.
Przycisk z nazwą użytkownika (kolumna Akcje) kopiuje **hasło** — tooltip wskazuje czyje.

### Szerokość kolumn
Przeciągnij krawędź nagłówka aby zmienić szerokość.
Prawy przycisk myszy na nagłówku → **Zapisz szerokości kolumn** — układ zapamiętany na stałe.

---

## Uruchomienie ze źródeł

```bash
git clone https://github.com/baczek48/HospitalHub.git
cd HospitalHub
pip install -r requirements.txt
python main.py
```

Wymagania: **Python 3.11+**, Windows 10/11

### Budowanie exe

```bat
build_exe.bat
```

lub ręcznie:
```bash
pip install pyinstaller
pyinstaller HospitalHub.spec
# wynik: dist/HospitalHub.exe
```

---

## Stos technologiczny

| Warstwa | Biblioteka |
|---|---|
| UI | PyQt6 |
| Terminal emulator | pyte (VT220) |
| SSH / SFTP | paramiko |
| Szyfrowanie | cryptography (AES-GCM), argon2-cffi |
