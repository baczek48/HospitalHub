# HospitalHub — pełny opis aplikacji (kontekst dla asystenta AI)

> Dokument opisuje stan projektu na 2026-06-15 (ostatni commit `342d357`, wersja instalatora 1.5.3
> + niezacommitowane zmiany w drzewie roboczym). Autor i właściciel: Sebastian Bąk.
> Repo lokalne: `C:\claude\hospital_hub`, GitHub: `baczek48/HospitalHub`.

---

## 1. Czym jest aplikacja

**HospitalHub** to desktopowa aplikacja dla **Windows 10/11** (Python + PyQt6) służąca do zarządzania
infrastrukturą IT szpitali przez osobę lub zespół serwisowy obsługujący **wiele placówek naraz**.

Zastępuje rozrzucone pliki Excel, karteczki i kilkanaście uruchomionych klientów: trzyma dane
połączeń, poświadczenia i notatki w **zaszyfrowanym pliku `.vault`**, a z poziomu tego samego okna
**łączy się** z maszynami (SSH / RDP / WWW), bazami danych (SQL Developer) i **VPN-ami** szpitali.

Kluczowe założenia:
- **Pełny offline** — brak serwera, brak chmury, brak telemetrii. Wszystko w jednym pliku i `%APPDATA%`.
- **Jedno okno = jeden vault**, ale można otworzyć wiele okien/vaultów naraz (jeden proces + tray).
- Interfejs i komunikaty są **po polsku**; kod, komentarze i nazwy — po angielsku.
- Praktyka ponad teorię: bardzo dużo kodu to obejścia realnych zachowań Windows (mstsc, FortiClient,
  GPO, okna klientów VPN), a nie czysta logika domenowa.

---

## 2. Stos technologiczny

| Warstwa | Technologia |
|---|---|
| Język | Python 3.11+ (buduje się i testuje pod **3.13** — patrz §14) |
| GUI | PyQt6 6.10.2 (styl Fusion, style inline przez `setStyleSheet`) |
| Szyfrowanie | `cryptography` 46.x — AES-256-GCM |
| KDF | `argon2-cffi` 25.x — Argon2id |
| SSH/SFTP | `paramiko` 4.0 |
| Emulacja terminala | `pyte` 0.8.2 (VT220) |
| WinAPI | `pywin32` 311 + `ctypes` (okna, tray, Credential Manager, SendInput) |
| Automatyzacja GUI | `pyautogui` 0.9.54 (pomocniczo przy autofillu VPN) |
| Pakowanie | PyInstaller (onedir, `HospitalHub.spec`) + Inno Setup (`HospitalHub.iss`) |
| Testy | pytest (`tests/test_sftp_logic.py`) |

Wszystkie zależności (także tranzytywne) są **przypięte co do wersji** w `requirements.txt` —
świadoma decyzja pod powtarzalny build i bezpieczeństwo łańcucha dostaw.

---

## 3. Struktura plików

```
hospital_hub/
  main.py             (491 l.)  punkt wejścia, excepthook, ikony rysowane w QPainter,
                                AppManager (wiele okien + tray + single-instance IPC)
  crypto.py           (177 l.)  format vaulta, Argon2id, AES-GCM, hash hasła admina
  models.py           (239 l.)  dataclassy + (de)serializacja JSON, lista providerów VPN
  config.py           (189 l.)  ustawienia w %APPDATA%\HospitalHub\config.json
  vpn_connect.py     (3265 l.)  cała obsługa VPN: wykrywanie klientów, connect/disconnect/status,
                                autofill okien, 2FA, adaptery sieciowe
  ui/
    login_dialog.py   (681 l.)  ekran logowania, wybór/tworzenie vaulta, typy vaultów
    main_window.py    (564 l.)  główne okno, menu, lista szpitali, zapis, tryb admina, motyw
    detail_panel.py  (1381 l.)  panel szczegółów szpitala: maszyny, bazy, notatki, przycisk VPN
    dialogs.py        (703 l.)  dialogi CRUD (szpital, maszyna, poświadczenie, baza, hasła)
    ssh_panel.py     (7132 l.)  terminal SSH + przeglądarka SFTP + panel sesji (największy moduł)
    rdp.py            (732 l.)  uruchamianie mstsc, wstrzykiwanie poświadczeń, podpisywanie .rdp
    vpn_panel.py     (1323 l.)  UI vaulta VPN: karty profili, ustawienia, 2FA
    db_connect.py     (123 l.)  launcher SQL Developera
    theme.py          (214 l.)  motyw jasny przez remapowanie kolorów w setStyleSheet
    utils.py           (13 l.)  polskie dialogi Tak/Nie
  tests/test_sftp_logic.py      testy jednostkowe czystych helperów z ssh_panel
  HospitalHub.spec              PyInstaller (onedir, ikona, hidden imports)
  HospitalHub.iss               Inno Setup — instalator HospitalHub-Setup-<wersja>.exe
  build_exe.bat                 starszy build --onefile
  ARCHITECTURE.md / README.md   dokumentacja (UWAGA: ARCHITECTURE.md jest przestarzała — opisuje
                                stan sprzed VPN, RDP i terminala)
```

---

## 4. Model danych (`models.py`)

Wszystko to dataclassy z UUID-em generowanym automatycznie. Deserializacja używa `.get()` z
domyślnymi wartościami, więc **stare vaulty otwierają się po dodaniu nowych pól**.

```
Hospital     id, name, notes, machines[], databases[]
Machine      id, ip, name, description, credentials[],
             connection_type: "SSH" | "RDP" | "WWW",
             rdp_port="3389", rdp_drives[] (np. ["C:", "D:"]), www_url, admin_only
Credential   id, login, password, note, admin_only
Database     id, host, port="1433", name, db_type ("MSSQL"|"Oracle"|...),
             credentials[], note, admin_only
VpnProfile   id, name, provider, server, port, login, password, group, domain,
             notes, app_path, profile_name, requires_2fa
```

Uwagi:
- **Wiele poświadczeń na maszynę i na bazę** (kiedyś baza miała jedno — jest migracja formatu legacy
  `login`/`password` → `credentials[]`).
- `admin_only` na maszynie / bazie / poświadczeniu = element widoczny tylko w trybie admina.
- Providerzy VPN wbudowani: FortiClient, GlobalProtect, Stormshield, Barracuda,
  SonicWall NetExtender, Hillstone Secure Connect, Windows VPN. Użytkownik może dodać własnych
  (`refresh_vpn_providers`, zapis w `config.json`).

---

## 5. Format vaulta i kryptografia (`crypto.py`)

**Format binarny v2** (aktualny):
```
"HHUB"            4 bajty magic
0x02              1 bajt wersji
salt              16 bajtów (losowy per zapis)
nonce             12 bajtów (losowy per zapis)
ciphertext        reszta pliku — AES-256-GCM(JSON)
```
Magic bytes wprowadzono po to, żeby plik nie wyglądał na edytowalny JSON i żeby dało się odróżnić
uszkodzenie pliku od złego hasła. **Format legacy v1** (koperta JSON z base64) jest nadal odczytywany.

- KDF: **Argon2id**, `time_cost=3`, `memory_cost=65536` (64 MB), `parallelism=4`, `hash_len=32`.
- Szyfr: **AES-256-GCM** — poufność + integralność; zły tag → komunikat „Nieprawidłowe hasło”.
- Klucz i plaintext są **zerowane** (`bytearray` → `_zero()`) zaraz po użyciu.
- Hasło główne **nigdzie nie jest zapisywane** — weryfikowane przy każdym otwarciu.
- Hasło admina: osobny hash Argon2id + sól, porównanie przez `hmac.compare_digest`.
- **Zapis atomowy**: szyfrowanie w pamięci → `tempfile.mkstemp` w tym samym katalogu → `flush` +
  `os.fsync` → `os.replace`. Awaria w trakcie zapisu nie uszkodzi istniejącego vaulta.
- Plik `.vault` można bez ryzyka wysłać mailem — jest zaszyfrowany w całości.

---

## 6. Typy vaultów i tryb wielookienny

Przy tworzeniu/otwieraniu vaulta wybiera się jeden z trzech typów (ikona globusa / kłódki / VPN):

| Typ | Zawartość | Rola |
|---|---|---|
| `global` | szpitale, maszyny, bazy | vault firmowy, współdzielony |
| `private` | jw. | prywatny vault użytkownika |
| `vpn` | profile VPN | osobny vault z poświadczeniami VPN — inne okno, inna ikona (zielona kłódka), inne menu |

- `config.json` trzyma **listę zarejestrowanych vaultów** (maks. jeden per typ) + aktywny indeks;
  na ekranie logowania przełącza się je strzałkami, hasło wpisuje się od razu.
- `AppManager` w `main.py` zarządza wieloma otwartymi oknami; **każde okno ma własną ikonę w trayu**
  z menu (Pokaż / Otwórz vault / Zamknij to okno / Zamknij wszystko).
- **Single instance**: `QLocalServer`/`QLocalSocket` — druga instancja wysyła „activate” do pierwszej
  zamiast uruchamiać kolejny proces.
- „Zamknij okno” chowa do traya, „Zamknij całkowicie” zamyka naprawdę (z pytaniem o zapis).
- Globalny `sys.excepthook`: wyjątek w slocie **nie zabija aplikacji** (PyQt6 ≥6.4 woła `qFatal`) —
  ląduje w `%APPDATA%\HospitalHub\crash.log` + nieblokujący komunikat dla użytkownika.

---

## 7. Główne okno i praca z danymi

- Układ: `QSplitter` — po lewej lista szpitali z wyszukiwarką i sortowaniem
  (bez sortowania / A-Z / Z-A, zapamiętywane), po prawej `DetailPanel`.
- `DetailPanel`: tabela **maszyn** (góra) + **bazy danych** i **notatki** (dół, w `QScrollArea`).
- **Zapis nie jest automatyczny** — tytuł pokazuje `[niezapisane]`, `Ctrl+S` zapisuje,
  `Ctrl+Shift+S` zapisuje jako/eksportuje, `Ctrl+O` otwiera inny vault.
- **Kliknięcie komórki kopiuje jej zawartość do schowka** (z wizualnym mignięciem komórki).
  Przycisk z loginem w kolumnie „Akcje” kopiuje **hasło**, schowek jest auto-czyszczony.
- **Drag & drop wierszy** — własna `_DraggableTable` z nadpisanym `dropEvent` (wbudowane
  przenoszenie Qt niszczyło widgety w komórkach); kolejność zapisywana w vaulcie.
- Szerokości kolumn: tryb Interactive + PPM na nagłówku → „Zapisz szerokości kolumn”
  (per tabela, w `config.json`); kolumna „Akcje” ma stałą szerokość, opis się rozciąga.
- Tooltipy pokazują pełną treść przyciętych komórek.
- **Motyw jasny/ciemny** (Widok → Jasny motyw). Implementacja: UI jest napisany w palecie
  GitHub-dark inline, a `theme.py` **monkeypatchuje `QWidget.setStyleSheet`** i remapuje ciemne
  heksy na ciepłą „kość słoniową”. Terminal SSH celowo **zostaje ciemny** (rysowany QPainterem,
  nie przechodzi przez remap). Zmiana motywu działa po restarcie aplikacji.

### Tryb admina
- Osobne hasło (Plik → Ustaw / zmień hasło admina), hash Argon2id.
- Elementy oznaczone `admin_only` są ukryte, dopóki admin nie odblokuje; po odblokowaniu mają
  fioletowe oznaczenie i 🔒.
- Auto-blokada po 5 minutach bezczynności.

---

## 8. Terminal SSH (`ssh_panel.py`)

Najbardziej rozbudowana część aplikacji (ponad 7 tys. linii). Własny widget terminala rysowany
`QPainter`-em na bazie ekranu `pyte` (VT220):

- **Scrollback 50 000 linii**, własny bufor historii, zaznaczanie myszą, kopiowanie.
- **Wiele zakładek sesji** + panel po lewej z kartami maszyn (wybór szpitala, dwuklik = połączenie,
  menu poświadczeń per maszyna); podświetlanie aktywności w nieaktywnych zakładkach.
- **Multi-exec** — tryb rozsyłania wpisywanych komend do wielu sesji naraz (z nagłówkiem ostrzegawczym).
- **Pasek statystyk** — co 5 s jednorazowy `exec` po istniejącym połączeniu: load average,
  pamięć used/total, uptime, zajętość dysku (`/u01` albo `/`).
- **Szukanie w buforze** (Ctrl+F, następny/poprzedni, licznik trafień).
- **Rozszerzone kolorowanie logów**: błędy/ostrzeżenia/OK, IPv4 z portem, IPv6, MAC, metody HTTP,
  kody 2xx/4xx/5xx, e-maile, daty, słowa typu „denied/rejected/down”, „enabled/active/true”,
  detekcja promptów powłoki.
- **Ctrl+C reaguje natychmiast** (drain bufora PTY — wcześniej terminal zamarzał przy zalewie logów).
- Automatyczny resize PTY do rozmiaru okna; opcja „Otwieraj terminal SSH zmaksymalizowany”.
- **Polityka TOFU dla kluczy hosta**: pierwszy klucz zapamiętywany, zmiana klucza → wyraźne
  ostrzeżenie o możliwym MitM (odcisk liczony i formatowany własnym helperem, objętym testami).
- Obsługa `keyboard-interactive` i **ponowne pytanie o hasło w samym terminalu** po błędnej
  autentykacji (zamiast zrywania sesji).
- **Szybkie połączenie SSH** (przycisk ⇆ w nagłówku) — połączenie z dowolnym hostem bez dodawania
  go do vaulta.

---

## 9. Przeglądarka SFTP

Wbudowana w to samo okno co terminal:

- Ikony typów plików (foldery, skrypty, logi, archiwa, obrazy, PDF, konfiguracje), sortowanie
  z folderami na górze, kolumny liczbowe sortowane numerycznie.
- **Edytowalna belka ścieżki** (kliknij i wpisz) + historia nawigacji z menu.
- Zmiana nazwy „w miejscu”, tworzenie katalogów, `chmod` z dialogiem, usuwanie z **policzeniem
  zawartości katalogu** (z limitem, żeby nie zawiesić UI) i poprawną polską odmianą liczebników.
- **Drag & drop**: upload plików z Windows, przenoszenie plików między katalogami zdalnymi,
  wykrywanie konfliktów nazw (skanowanie asynchroniczne) i pytanie o nadpisanie.
- **Otwieranie plików zdalnych lokalnie z auto-uploadem po edycji** — plik jest pobierany do
  katalogu tymczasowego, obserwowany (polling), a po zapisaniu w edytorze odsyłany na serwer;
  wykrywanie plików tylko do odczytu i ostrzeżenie o dużych plikach.
- Transfery w osobnych wątkach z paskiem postępu i **twardym anulowaniem** (sprzątanie plików
  częściowych po obu stronach).
- **Ochrona przed path traversal**; katalog tymczasowy `%TEMP%\HospitalHub_<pid>` kasowany przy wyjściu.

---

## 10. RDP (`rdp.py`)

- Walidacja IP i portu **przed** uruchomieniem `mstsc.exe`.
- **Wstrzykiwanie poświadczeń przez `cmdkey`/`CredWriteW` (ctypes)** — hasło nie pojawia się
  w argumentach procesu; wpis `TERMSRV/<ip>` jest kasowany po 30 s.
- **Mapowanie dysków lokalnych** do sesji (`rdp_drives`).
- Uruchomienie **zawsze przez podpisany plik `.rdp`**: aplikacja tworzy self-signed certyfikat,
  ufa mu (publisher bypass + „local devices trust”), podpisuje plik `rdpsign`-em i uruchamia mstsc
  z tym plikiem. Powód: na komputerach z polityką delegacji poświadczeń (GPO) `mstsc /v:host`
  traktuje połączenie jako ad-hoc i **pyta o hasło** zamiast użyć zapisanego — połączenie z pliku
  `.rdp` jest traktowane jak zaufane połączenie zapisane. Podpis zdejmuje okno „Zweryfikuj wydawcę”.
- **Log diagnostyczny** `%TEMP%\hospitalhub_rdp_sign.log` rozróżnia trzy typowe przyczyny pytania
  o hasło: brak użytecznego poświadczenia / odrzucone `CredWriteW` / polityka mstsc.

**Typ połączenia WWW**: maszyna z `connection_type="WWW"` otwiera `www_url` w przeglądarce
(np. portal PAM).

---

## 11. VPN (`vpn_connect.py` + `vpn_panel.py`)

Osobny vault typu `vpn` z kartami profili (nazwa, provider, serwer, port, login, hasło, grupa,
domena, ścieżka do klienta, nazwa profilu w kliencie, flaga 2FA).

- **Connect / disconnect / status** dla 7 providerów; wykrywanie zainstalowanych klientów
  (rejestr, typowe ścieżki), rozpoznawanie FortiClient **Free Edition** i braku wsparcia CLI.
- **Status** czytany z wielu źródeł: logi klienta (`sslvpn`, GlobalProtect), aktywne adaptery
  sieciowe przez WinAPI (`GetAdaptersAddresses`, z cache), `rasdial`, dopasowanie IP serwera.
- **Autofill okien klientów VPN** przez WinAPI `SendInput` (FortiClient, Stormshield, GlobalProtect,
  natywne okno Windows) — login i hasło są **wklejane przez schowek, nie wpisywane** (okna oparte
  na Chromium gubiły znaki), a odpytywanie statusu jest wstrzymywane na czas autofillu.
- **FortiClient uruchamiany przez `explorer.exe <skrót .lnk>`**, nie `os.startfile` — inaczej
  Electronowy logger klienta się wysypuje; po starcie weryfikowane jest, czy proces naprawdę ruszył,
  a okno jest odnajdywane po procesie, nie tylko po tytule.
- **2FA/OTP**: monitor stdout procesu wykrywa prośbę o kod (wzorce regex), aplikacja pokazuje okno
  na kod i **wpisuje go do okna autoryzacji FortiClienta**.
- **Import tuneli FortiClienta z rejestru** do profili w vaulcie.
- **Windows VPN** jest obsługiwany tylko jako notatka + status (`rasdial`/`rasphone`) — świadome
  ograniczenie: poświadczeń z nowych Ustawień Windows nie da się wypełnić z poziomu CLI.
- **Przycisk VPN per szpital** w panelu szczegółów: dopasowanie profilu **po nazwie szpitala**
  (bez rozróżniania wielkości liter). Kolor przycisku odzwierciedla realny stan (szary → brak
  profilu, żółty → łączy, zielony → połączono), odpytywany cyklicznie. Przy pierwszym kliknięciu
  użytkownik wskazuje swój **osobisty vault VPN** (ścieżka zapamiętana w `config.json`), profile
  trzymane są w pamięci sesji.

---

## 12. Bazy danych i SQL Developer (`db_connect.py`)

- Przycisk ⛃ w nagłówku panelu uruchamia **Oracle SQL Developer** (auto-wykrywanie typowych
  ścieżek instalacji, jednorazowe wskazanie ręczne, zapamiętanie w `config.json`).
- Hasło pierwszego poświadczenia trafia do **schowka z auto-czyszczeniem**, a okno pokazuje komplet
  danych połączenia do wklejenia. Host jest parsowany z formatów JDBC (`...@host:port/SID`).

---

## 13. Konfiguracja i pliki użytkownika

`%APPDATA%\HospitalHub\config.json` — klucze:
`last_vault`, `vault_list[]` (+ `active_vault_index`), `column_widths{}`, `sqldeveloper_path`,
`vpn_provider_paths{}`, `custom_vpn_providers[]`, `vpn_autofill_enabled`, `ssh_start_maximized`,
`hospital_sort_order`, `theme`, `personal_vpn_vault`.

Logi:
- `%APPDATA%\HospitalHub\crash.log` — nieobsłużone wyjątki,
- `%TEMP%\hospitalhub_rdp_sign.log` — diagnostyka RDP,
- logi debugowe VPN (katalog ustalany przez `_resolve_log_dir`).

W `config.json` **nigdy nie ma haseł** — tylko ścieżki i preferencje.

---

## 14. Budowanie i wydania

- Build produkcyjny: **PyInstaller onedir** wg `HospitalHub.spec` (ikona `icon.ico`,
  hidden imports: `win32gui`, `win32con`, `win32api`, `PyQt6.QtNetwork`, `ui.theme`,
  `datas: ui/`), następnie **Inno Setup** (`HospitalHub.iss`) →
  `dist_installer/HospitalHub-Setup-1.5.3.exe` (instalacja do Program Files, wymaga uprawnień
  administratora, polski kreator, skrót na pulpicie).
- **Ważne**: budować i testować interpreterem **`py -3.13`** — domyślny Python 3.12 w tym
  środowisku nie ma PyQt6 ani PyInstallera:
  `py -3.13 -m PyInstaller --noconfirm HospitalHub.spec`
- `build_exe.bat` to starszy wariant `--onefile` (zostawiony pomocniczo).
- Testy: `py -3.13 -m pytest tests/` — pokrywają polską odmianę liczebników, format odcisku klucza
  SSH i liczenie zawartości katalogów przy usuwaniu (bez uruchamiania QApplication).

### Historia wersji (z gita)
- **1.0** — pierwsze wydanie (vault, szpitale, maszyny, bazy).
- **1.1** — auto-connect SQL Developera, kolory terminala.
- **1.2** — ikona-tarcza, uproszczony launcher SQL, uwaga o Defenderze.
- **1.3** — tryb admina, przebudowa SFTP, mapowanie dysków RDP, rozszerzone kolory terminala.
- **1.4** — poprawki statusu VPN, dopracowanie SSH/SFTP, hardening bezpieczeństwa,
  binarny format vaulta (magic bytes), instalator Inno Setup.
- **1.5.0** — przebudowa wydajności terminala, podświetlanie aktywności zakładek.
- **1.5.1** — naprawa scrollbacku, twarde anulowanie transferu SFTP, odzyskiwanie po awarii.
- **1.5.2** — UX SFTP, wydajność wielu zakładek, porządki w VPN.
- **1.5.3** — jasny motyw, wstrzykiwanie poświadczeń RDP, autofill FortiClienta, overhaul SSH/SFTP.
- Po 1.5.3 — dopasowanie okna FortiClienta po procesie, ponowne pytanie o hasło w terminalu.

---

## 15. Model bezpieczeństwa — podsumowanie

- AES-256-GCM + Argon2id, losowe salt/nonce per zapis, zerowanie kluczy w pamięci.
- Hasło główne i hasło admina nigdy nieprzechowywane w jawnej postaci.
- Zapis atomowy chroni vault przed uszkodzeniem.
- TOFU dla kluczy SSH z jawnym ostrzeżeniem o zmianie klucza hosta.
- Poświadczenia RDP przez Credential Manager, kasowane po 30 s; hasło nie trafia do argumentów procesu.
- Sanityzacja komunikatów błędów — hasła nie wyciekają do treści wyjątków.
- Ochrona przed path traversal w SFTP, walidacja IP i portów, czyszczenie plików tymczasowych.
- Schowek czyszczony automatycznie po skopiowaniu hasła.
- Zero połączeń wychodzących poza te, które użytkownik sam inicjuje (SSH/RDP/VPN/WWW).

---

## 16. Znane ograniczenia i świadome decyzje

- **Brak autozapisu** — zmiany trzeba zapisać ręcznie (`Ctrl+S`); to celowe.
- **Zmiana motywu wymaga restartu**; terminal SSH pozostaje ciemny także w jasnym motywie.
- **Windows VPN**: tylko notatka + status, bez przycisku „Połącz” (ograniczenie Windows).
- **FortiClient Free Edition** nie ma CLI — obsługa idzie przez GUI + autofill.
- Autofill VPN zależy od układu okien klienta — jest heurystyczny i może wymagać poprawek
  po aktualizacji klienta VPN.
- `ARCHITECTURE.md` w repo jest **nieaktualna** (opisuje wersję sprzed VPN, RDP i terminala);
  ten dokument jest źródłem prawdy.
- W drzewie roboczym są **niezacommitowane zmiany** (RDP zawsze przez podpisany `.rdp` + log
  diagnostyczny, poprawki VPN i SSH, zmiany w `.spec`) — czekają na build i weryfikację w terenie.

---

## 17. Konwencje pracy nad projektem

- Po każdej zmianie w kodzie **buduje się `HospitalHub.exe`** (bez pytania) — aplikacja jest
  używana produkcyjnie jako exe, nie ze źródeł.
- UI weryfikuje się **wizualnie** (zrzut ekranu z działającej aplikacji), bo zielony build
  nie oznacza, że okno wygląda i działa poprawnie.
- Testuje się przeciw realnym scenariuszom (prawdziwe maszyny, prawdziwe GPO), nie przeciw wygodnym
  atrapom — większość błędów w tym projekcie była środowiskowa, nie logiczna.
