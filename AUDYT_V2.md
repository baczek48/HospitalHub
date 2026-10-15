# HospitalHub V2 — audyt techniczny i roadmapa

> Data: 2026-09-11. Zakres: `C:\claude\hospital_hub_v2` (kod identyczny z V1 poza 13 liniami izolacji
> danych). `C:\claude\hospital_hub` traktowany jako referencja funkcjonalna, **nietknięty**.
>
> **Na tym etapie nie zmieniono ani jednej linii kodu aplikacji.** Dokument jest wyłącznie analizą.
>
> Metoda: przeczytany cały `crypto.py`, `models.py`, `config.py`, `db_connect.py`, `theme.py`,
> `utils.py`, `main.py`, `main_window.py`, `login_dialog.py`, kluczowe ścieżki `detail_panel.py`,
> `rdp.py`, `vpn_panel.py` oraz ~2 500 linii z `ssh_panel.py` i ~1 800 linii z `vpn_connect.py`
> (ścieżki: connect/disconnect/status, autofill, wykrywanie okien i adapterów, worker SSH, render
> terminala, SFTP listing/transfer/watch). Wszystkie odwołania w formacie `plik:linia` wskazują
> realne miejsca w kodzie V2.

---

## 0. Podsumowanie w pięciu zdaniach

1. **Rdzeń danych jest zdrowy** — `crypto.py`, `models.py`, `config.py` są małe, czytelne, testowalne
   i nie wymagają przebudowy; zmiana formatu vaulta nie jest potrzebna.
2. **Dwa moduły przejęły całą aplikację**: `ssh_panel.py` (7 132 l.) i `vpn_connect.py` (3 265 l.)
   to razem 60% kodu i jednocześnie 90% ryzyka.
3. **Najcięższe operacje wykonują się w wątku GUI** — Argon2 przy otwarciu i **każdym zapisie**
   vaulta, status VPN co 2 s, uruchomienie VPN (do ~10 s zamrożenia), 3–5 wywołań PowerShell przy
   każdym RDP.
4. **Niestabilność VPN nie ma jednej przyczyny** — zidentyfikowałem **17 punktów zależnych od
   środowiska użytkownika** w ścieżce FortiClienta; autofill oparty na ślepej kolejności Tab
   i stałych `sleep()` jest z nich najbardziej kruchy i najtrudniejszy do zdiagnozowania zdalnie.
5. **Brakuje warstwy diagnostycznej** — `_dbg()` w `vpn_connect.py:2526` jest pustą funkcją
   (logowanie wyłączone 2026-05-28), więc dziś po nieudanej próbie VPN **nie zostaje żaden ślad**.

---

## 1. AUDYT ARCHITEKTURY

### 1.1 Rozmiary i odpowiedzialności

| Moduł | Linie | Klasy | Odpowiedzialności | Ocena |
|---|---:|---:|---|---|
| `ui/ssh_panel.py` | **7 132** | 20 | terminal, pyte, render, selekcja, szukanie, worker SSH, TOFU, SFTP, transfery, edycja zdalna, panel maszyn, zakładki, dialogi | **krytycznie przeciążony** |
| `vpn_connect.py` | **3 265** | 4 (struct) | 7 providerów, wykrywanie, launch, okna WinAPI, autofill, 2FA, adaptery, rasdial | **krytycznie przeciążony** |
| `ui/detail_panel.py` | 1 381 | 7 | tabele maszyn/baz, notatki, drag&drop, przycisk VPN, ładowanie vaulta VPN | przeciążony |
| `ui/vpn_panel.py` | 1 323 | 6 | karty profili, ustawienia, 2FA, monitor, status | do rozdzielenia |
| `ui/rdp.py` | 732 | 1 | mstsc, Credential Manager, certyfikat, rejestr, diagnostyka | akceptowalny |
| `ui/dialogs.py` | 703 | 5 | dialogi CRUD | akceptowalny |
| `ui/login_dialog.py` | 681 | 3 | logowanie, wybór/tworzenie vaulta | akceptowalny |
| `ui/main_window.py` | 564 | 1 | okno, menu, zapis, admin, motyw | akceptowalny |
| `main.py` | 491 | 1 | start, excepthook, ikony, AppManager, tray, IPC | akceptowalny |
| `models.py` | 239 | 5 | dataclassy + serializacja | **dobry** |
| `ui/theme.py` | 214 | 0 | remap kolorów | **dobry** (sprytny) |
| `config.py` | 189 | 0 | ustawienia | **dobry** |
| `crypto.py` | 177 | 0 | AES-GCM + Argon2id | **dobry** |
| `ui/db_connect.py` | 123 | 0 | SQL Developer | dobry |
| `ui/utils.py` | 13 | 0 | dialog Tak/Nie | dobry |

### 1.2 Graf zależności (stan faktyczny)

```
main.py ──> login_dialog ──> crypto, config, models
   │            │
   │            └──> (zwraca vault_path, password, items, admin_hash, vault_type)
   │
   └──> main_window ──> detail_panel ──┬─> dialogs ──> models
                    │                  ├─> ssh_panel  (SshDialog)
                    │                  ├─> rdp        (connect_rdp)
                    │                  ├─> db_connect (SQL Developer)
                    │                  ├─> vpn_connect (get_status, connect)  ◄── PRZECIEK WARSTW
                    │                  └─> crypto (decrypt vaulta VPN!)       ◄── PRZECIEK WARSTW
                    ├─> vpn_panel ──> vpn_connect
                    └─> theme, config, crypto (encrypt przy zapisie)
```

**Problem:** `detail_panel.py` — widget tabeli — sam odszyfrowuje plik vault
(`detail_panel.py:1274 _load_vpn_vault`), sam odpytuje system o stan VPN
(`detail_panel.py:1216`) i trzyma **globalny stan modułu** (`_vpn_session_profiles`,
`_vpn_session_loaded`). To trzy różne warstwy w jednym widgecie.

### 1.3 Moduły zbyt duże i zbyt wielofunkcyjne

**`ssh_panel.py` — cztery aplikacje w jednym pliku:**

| Blok | Linie | Co to jest |
|---|---|---|
| kolorowanie logów, helpery | 1–710 | czyste funkcje (`_colorize_log`, `_ssh_fingerprint`, `_count_dir_with_cap`) |
| `TerminalWidget` | 712–1690 | emulator + renderer + selekcja + szukanie |
| TOFU + worker SSH | 1788–2356 | polityka kluczy, `_SshWorker`, `_StatsWorker` |
| workery SFTP | 2394–2570 | connect, list, transfer, simple |
| `SftpPanel` | 2999–5185 | **2 186 linii** — cała przeglądarka plików |
| `_EnvironmentPanel` | 5187–5510 | panel maszyn/szpitali w oknie SSH |
| zakładki, sesje, `SshDialog` | 5513–7132 | zarządzanie sesjami, multi-exec, szukanie, geometria |

Jedno okno IDE nie obejmuje nawet spisu treści tego pliku. Każda zmiana w SFTP wymaga
przewinięcia przez terminal, a `git diff` na tym pliku jest nieczytelny.

**`vpn_connect.py` — jeden wielki `if/elif` po nazwie providera:**

- `connect()` — **354 linie**, 7 gałęzi `elif`, każda z własną strategią, własnymi `sleep()`
  i własnym stylem obsługi błędów (`vpn_connect.py:2532`).
- `get_status()` — **190 linii**, 8 gałęzi, każda z innym źródłem prawdy (`vpn_connect.py:3004`).
- `disconnect()` — 118 linii, ta sama struktura (`vpn_connect.py:2886`).
- Dodanie ósmego providera = dopisanie trzech kolejnych gałęzi w trzech miejscach, bez żadnego
  kontraktu, który wymusiłby komplet.

### 1.4 Logika biznesowa zmieszana z UI

| Miejsce | Na czym polega przeciek |
|---|---|
| `rdp.py:100` | moduł systemowy sam pokazuje `QMessageBox` i przyjmuje `parent` — nie da się wywołać RDP bez GUI, nie da się przetestować |
| `db_connect.py:83` | to samo — launcher pokazuje okna dialogowe i `QFileDialog` |
| `detail_panel.py:1274` | widget odszyfrowuje vault i trzyma profile VPN w globalnej zmiennej modułu |
| `detail_panel.py:1216` | widget odpytuje system operacyjny (subprocessy) w timerze GUI |
| `main_window.py:414` | okno robi szyfrowanie + zapis atomowy + obsługę błędów I/O |
| `ssh_panel.py:1788` | polityka kluczy SSH (bezpieczeństwo) renderuje własne modale przez `QMessageBox` |
| `vpn_connect.py` | moduł „systemowy" zwraca **komunikaty po polsku dla użytkownika** jako wartość zwrotną |

Konsekwencja: **nie da się napisać testu na nic, co dotyka VPN, RDP ani vaulta**, bo wszystko
wymaga żywego `QApplication` i żywego Windowsa. Dzisiejszy pakiet testów (30 testów) pokrywa
wyłącznie trzy czyste funkcje wyciągnięte z `ssh_panel`.

### 1.5 Zależności utrudniające rozwój

1. **Brak pakietu** — `sys.path.insert(...)` w **9 plikach** (`ui/rdp.py:22`, `ui/dialogs.py:14`, …).
   Import `models` działa tylko dlatego, że każdy moduł ręcznie majstruje przy `sys.path`.
   To także źródło problemów przy PyInstallerze (`datas=[('ui','ui')]` w spec).
2. **Globalny stan modułowy** — `_last_connected`, `_last_connected_meta`, `_ADAPTERS_CACHE`,
   `_cli_supported_cache`, `_server_ip_cache` (vpn_connect), `_vpn_session_profiles`
   (detail_panel), `_TofuHostKeyPolicy._cache` (ssh_panel), `_rdpsign_path_cache` (rdp).
   Przy **wielu oknach** (a to funkcja produktu) stan jest współdzielony między vaultami.
3. **Sygnały-śmieci** — `DetailPanel` komunikuje się z `MainWindow` przez jeden sygnał
   `data_changed`, który powoduje pełne przebudowanie listy i tabel.
4. **`connect_rdp(machine, parent, admin_unlocked)`** — warstwa systemowa dostaje flagę trybu
   admina, czyli decyzję uprawnieniową podejmuje kod od mstsc.

### 1.6 Blokady GUI (lista miejsc)

| Miejsce | Co blokuje wątek GUI | Szacowany czas |
|---|---|---|
| `login_dialog.py:276` | `decrypt()` → Argon2id 64 MB | **1–4 s** |
| `main_window.py:433` | `encrypt()` przy każdym `Ctrl+S` | **1–4 s** |
| `detail_panel.py:1216` | `vpn_connect.get_status()` w timerze co 2 s | 5–800 ms |
| `detail_panel.py:1230` | `get_status()` przy każdym odświeżeniu przycisku | 5–800 ms |
| `vpn_panel.py:1122` | `connect_monitored()` — `sleep(4)`, `_wait_for_process`, tray retry | **do ~10 s** |
| `detail_panel.py:1298` | to samo z poziomu przycisku VPN przy szpitalu | do ~10 s |
| `rdp.py:169` | `_ensure_signing_cert` + bypass + trust = 3–5× PowerShell | **1–6 s** |
| `ssh_panel.py:4961` | skan katalogu przed usunięciem (jest progres, ale w tym samym wątku przy małych) | zmienne |
| `ssh_panel.py:887` | `_flush_pending` — pyte parse (ma timeslice 12 ms, OK) | kontrolowane |

### 1.7 Duplikacja

- **Schowek — trzy różne implementacje i trzy różne polityki**: `dialogs.py:21` (auto-czyszczenie
  15 s), `vpn_panel.py:1009/1024` (`QApplication.clipboard().setText()` — **bez czyszczenia**),
  `vpn_connect.py:1995` (`_copy_to_clipboard` przez WinAPI, z zapamiętaniem poprzedniej zawartości).
- **Style inline** — **215 wywołań `setStyleSheet`** (vpn_panel 73, ssh_panel 67, detail_panel 35).
  Ten sam styl przycisku jest wklejony kilkanaście razy; zmiana wyglądu = grep po hexach.
- **Wyszukiwanie okien** — 16 wywołań `EnumWindows` w `vpn_connect.py`, sześć prawie identycznych
  funkcji: `_has_visible_window`, `_show_existing_window`, `_restore_tray_window`,
  `_restore_tray_by_process`, `_show_window_by_process`, `_bring_window_to_front`.
- **Uruchamianie procesów** — cztery strategie rozsiane po `connect()`: `os.startfile`,
  `subprocess.Popen`, `_shell_launch` (ShellExecuteW), `explorer.exe <lnk>` — wybierane ad hoc.
- **Sprawdzanie procesu** — `_is_process_running`, `_forticlient_pids`, `_wait_for_process`,
  `_get_vpn_connected_server_ip` — każda odpala własny `tasklist`.

### 1.8 Kandydaci do wydzielenia (serwisy)

| Serwis | Co przejmuje | Skąd |
|---|---|---|
| `VaultService` | otwarcie, zapis, zmiana hasła, admin hash, zapis atomowy — **w wątku roboczym** | login_dialog, main_window |
| `VpnService` + `providers/` | wykrywanie, connect/disconnect/status/diagnostics per provider | vpn_connect (cały) |
| `WindowAutomation` | EnumWindows, tray, fokus, SendInput, schowek | vpn_connect (6 funkcji) |
| `ProcessService` | tasklist/PID/uruchamianie (4 strategie w jednym miejscu) | vpn_connect, db_connect |
| `RdpService` | mstsc, Credential Manager, certyfikat — **bez QMessageBox** | rdp.py |
| `SshService` / `SftpService` | połączenia, transfery, watch — bez widgetów | ssh_panel |
| `DiagnosticsService` | zbieranie i eksport (patrz §6) | nowy |
| `ClipboardService` | jedna polityka kopiowania sekretów | 3 miejsca |
| `Theme`/`Styles` | tokeny + QSS zamiast 215 stringów | theme.py + wszystkie widgety |

### 1.9 Co działa dobrze i **nie powinno** być przebudowywane

- **`crypto.py`** — format binarny z magic bytes, Argon2id, AES-GCM, zerowanie kluczy, kompatybilność
  wsteczna z v1. Czysty, bez zależności od UI. Zostawić.
- **`models.py`** — dataclassy z `.get()` przy deserializacji (tolerancja na nowe pola) i migracją
  starego formatu bazy. Zostawić, ewentualnie rozszerzać.
- **`config.py`** — proste, przewidywalne, jeden plik JSON.
- **`TerminalWidget`** (`ssh_panel.py:712`) — to jest najlepiej zoptymalizowany kod w projekcie:
  koalescencja repaintów (8 ms), timeslice 12 ms na parsowanie pyte, throttling ukrytych zakładek
  (250 ms), back-pressure sterowany kolejką (`pending_chunks`), szybka ścieżka Ctrl+C piszącą
  wprost do kanału. **Nie przepisywać** — tylko przenieść do osobnego modułu.
- **`_SshWorker`** (`ssh_panel.py:2052`) — pętla z `_wake` event, drain kolejki wysyłkowej przed
  odczytem, rozróżnienie „shell exited" od „transport dead" → auto-reconnect. Dobre.
- **Zapis atomowy** (`main_window.py:421`) — poprawny (temp + fsync + `os.replace`).
- **TOFU** (`ssh_panel.py:1892`) — poprawna polityka z jawnym modalem przy zmianie klucza.
- **`_count_dir_with_cap`** (`ssh_panel.py:1711`) — czysta funkcja, iteracyjna, z limitem, objęta
  testami. Wzorzec do naśladowania w całym V2.
- **`theme.remap`** — monkeypatch jest nieortodoksyjny, ale rozwiązał realny problem przy zerowym
  ryzyku; docelowo zastąpi go system tokenów, ale **nie jest to pilne**.

---

## 2. FUNKCJONALNOŚĆ — pełna tabela

Kod V2 jest dziś **identyczny** z V1, więc kolumna „V2" wszędzie oznacza stan odziedziczony.
Kolumna „ZACHOWAĆ" to zobowiązanie: nic z tego nie może zniknąć.

| FUNKCJA | V1 | V2 | ZACHOWAĆ | PLANOWANA ZMIANA |
|---|---|---|---|---|
| **VAULT / KRYPTOGRAFIA** |
| Vault w jednym pliku `.vault` | ✔ | = V1 | **TAK** | bez zmian |
| Format binarny v2 (`HHUB`+salt+nonce+CT) | ✔ | = V1 | **TAK** | bez zmian — **żadnej zmiany formatu** |
| Odczyt formatu legacy v1 (JSON/base64) | ✔ | = V1 | **TAK** | zostaje na zawsze (kompatybilność) |
| Argon2id 3/64MB/4, klucz 32 B | ✔ | = V1 | **TAK** | parametry bez zmian; **wykonanie przenieść do wątku** |
| AES-256-GCM + weryfikacja tagu | ✔ | = V1 | **TAK** | bez zmian |
| Zerowanie klucza i plaintextu | ✔ | = V1 | **TAK** | rozszerzyć o hasło sesji (dziś `str`) |
| Zapis atomowy (temp+fsync+replace) | ✔ | = V1 | **TAK** | bez zmian, przenieść do `VaultService` |
| Hasło główne nieprzechowywane | ✔ | = V1 | **TAK** | bez zmian |
| Zmiana hasła głównego | ✔ | = V1 | **TAK** | + wskaźnik postępu |
| Hasło admina (Argon2id + `compare_digest`) | ✔ | = V1 | **TAK** | bez zmian |
| Brak autozapisu, `[niezapisane]` w tytule | ✔ | = V1 | **TAK** | + opcjonalne ostrzeżenie przed zamknięciem (już jest) |
| **VAULTY I OKNA** |
| Tworzenie nowego vaulta (min. 8 znaków) | ✔ | = V1 | **TAK** | + miernik siły hasła |
| Otwieranie istniejącego vaulta | ✔ | = V1 | **TAK** | bez zmian |
| Typy: global / private / vpn | ✔ | = V1 | **TAK** | bez zmian |
| Lista zarejestrowanych vaultów + przełączanie | ✔ | = V1 | **TAK** | limit „jeden per typ" do rozważenia |
| Szybkie logowanie (zapamiętana ścieżka) | ✔ | = V1 | **TAK** | + postęp odszyfrowania |
| Wiele okien naraz | ✔ | = V1 | **TAK** | naprawić współdzielony stan globalny |
| Ikona w trayu per okno + menu | ✔ | = V1 | **TAK** | + rozróżnienie V1/V2 w tooltipie |
| Single instance (QLocalServer) | ✔ | = V1 | **TAK** | + walidacja nadawcy komunikatu |
| Ukrywanie do traya / zamykanie całkowite | ✔ | = V1 | **TAK** | bez zmian |
| Excepthook + `crash.log` | ✔ | = V1 | **TAK** | + zgłaszanie do diagnostyki |
| **DANE** |
| Szpitale (lista, wyszukiwarka, sortowanie) | ✔ | = V1 | **TAK** | + sortowanie wg ostatniego użycia |
| Maszyny: IP, nazwa, opis, typ (SSH/RDP/WWW) | ✔ | = V1 | **TAK** | + tagi/grupy (nowość) |
| Wiele poświadczeń na maszynę | ✔ | = V1 | **TAK** | bez zmian |
| Bazy: host, port, nazwa, typ, wiele poświadczeń | ✔ | = V1 | **TAK** | bez zmian |
| Migracja starego formatu bazy (1 poświadczenie) | ✔ | = V1 | **TAK** | bez zmian |
| Notatki o środowisku | ✔ | = V1 | **TAK** | + markdown (opcjonalnie) |
| Kolejność wierszy drag & drop | ✔ | = V1 | **TAK** | zachować przy zmianie na model/widok |
| Klik w komórkę = kopiuj + flash | ✔ | = V1 | **TAK** | bez zmian |
| Przycisk loginu kopiuje hasło | ✔ | = V1 | **TAK** | ujednolicić politykę schowka |
| Zapamiętane szerokości kolumn | ✔ | = V1 | **TAK** | bez zmian |
| Duplikowanie maszyny | ✔ | = V1 | **TAK** | bez zmian |
| **TRYB ADMINA** |
| Osobne hasło admina | ✔ | = V1 | **TAK** | bez zmian |
| `admin_only` na maszynie/bazie/poświadczeniu | ✔ | = V1 | **TAK** | bez zmian |
| Auto-blokada po 5 min | ✔ | = V1 | **TAK** | konfigurowalny czas |
| Oznaczenie fioletem + 🔒 | ✔ | = V1 | **TAK** | spójny styl |
| **SSH / TERMINAL** |
| Terminal pyte VT220 + render QPainter | ✔ | = V1 | **TAK** | tylko przeniesienie pliku |
| Scrollback 250 000 linii | ✔ | = V1 | **TAK** | **konfigurowalny** (patrz §3 P6) |
| Wiele zakładek sesji | ✔ | = V1 | **TAK** | bez zmian |
| Multi-exec (rozsyłanie komend) | ✔ | = V1 | **TAK** | + wykluczanie sesji widoczne w UI |
| Statystyki maszyny (load/mem/uptime/dysk) | ✔ | = V1 | **TAK** | interwał konfigurowalny |
| Kolorowanie logów (IP, HTTP, daty, słowa) | ✔ | = V1 | **TAK** | + profil kolorów |
| Szukanie w buforze (Ctrl+F) | ✔ | = V1 | **TAK** | + indeks przyrostowy |
| Natychmiastowy Ctrl+C | ✔ | = V1 | **TAK** | **nie ruszać** |
| Back-pressure / throttling ukrytych zakładek | ✔ | = V1 | **TAK** | **nie ruszać** |
| Auto-reconnect po zerwaniu | ✔ | = V1 | **TAK** | + widoczny status w UI |
| Ponowne pytanie o hasło w terminalu | ✔ | = V1 | **TAK** | bez zmian |
| Auth kluczem/agentem, potem hasło | ✔ | = V1 | **TAK** | + jawny wybór klucza |
| TOFU + modal przy zmianie klucza | ✔ | = V1 | **TAK** | + import znanych hostów |
| X11 forwarding (best-effort) | ✔ | = V1 | **TAK** | bez zmian |
| Szybkie połączenie SSH (bez vaulta) | ✔ | = V1 | **TAK** | bez zmian |
| Panel maszyn w oknie SSH | ✔ | = V1 | **TAK** | ujednolicić z widokiem głównym |
| Terminal maksymalizowany (opcja) | ✔ | = V1 | **TAK** | bez zmian |
| **SFTP** |
| Przeglądarka z ikonami typów | ✔ | = V1 | **TAK** | model/widok zamiast QTableWidget |
| Edytowalna ścieżka + historia | ✔ | = V1 | **TAK** | bez zmian |
| Upload / download z postępem | ✔ | = V1 | **TAK** | + kolejka wielu transferów |
| Twarde anulowanie transferu | ✔ | = V1 | **TAK** | bez zmian |
| Drag & drop (z Windows i wewnątrz) | ✔ | = V1 | **TAK** | bez zmian |
| Wykrywanie konfliktów nazw | ✔ | = V1 | **TAK** | bez zmian |
| Edycja pliku zdalnego z auto-uploadem | ✔ | = V1 | **TAK** | + wskaźnik „obserwowany" |
| Ochrona przed pustym/skróconym plikiem | ✔ | = V1 | **TAK** | bez zmian |
| Wykrywanie plików tylko do odczytu | ✔ | = V1 | **TAK** | bez zmian |
| `chmod`, `mkdir`, rename inline, delete | ✔ | = V1 | **TAK** | bez zmian |
| Liczenie zawartości katalogu przed usunięciem | ✔ | = V1 | **TAK** | bez zmian |
| Ochrona przed path traversal | ✔ | = V1 | **TAK** | bez zmian |
| Sprzątanie plików tymczasowych | ✔ | = V1 | **TAK** | + sprzątanie osieroconych katalogów |
| **RDP** |
| Uruchomienie mstsc | ✔ | = V1 | **TAK** | bez zmian |
| Poświadczenia przez `CredWriteW` | ✔ | = V1 | **TAK** | bez zmian |
| Kasowanie poświadczeń po 30 s | ✔ | = V1 | **TAK** | + kasowanie przy zamknięciu aplikacji |
| Zawsze podpisany plik `.rdp` | ✔ | = V1 | **TAK** | **nie ruszać** (naprawiło regresję GPO) |
| Self-signed cert + TrustedPublisher + bypass | ✔ | = V1 | **TAK** | wynieść do wątku, cache’ować wynik |
| `PublisherPermissions` (Win11 24H2+) | ✔ | = V1 | **TAK** | bez zmian |
| Mapowanie dysków lokalnych | ✔ | = V1 | **TAK** | bez zmian |
| Walidacja IP i portu | ✔ | = V1 | **TAK** | bez zmian |
| Log diagnostyczny RDP | ✔ | = V1 | **TAK** | wpiąć w system diagnostyki |
| **WWW** |
| Typ połączenia WWW (`www_url`) | ✔ | = V1 | **TAK** | bez zmian |
| **VPN** |
| 7 providerów wbudowanych | ✔ | = V1 | **TAK** | przepisać na klasy (§5) |
| Własni providerzy użytkownika | ✔ | = V1 | **TAK** | bez zmian |
| Vault VPN jako osobny typ | ✔ | = V1 | **TAK** | bez zmian |
| Connect / disconnect / status | ✔ | = V1 | **TAK** | **do wątku roboczego** |
| Wykrywanie ścieżek klientów | ✔ | = V1 | **TAK** | + rejestr + PATH + pytanie użytkownika |
| Autofill okien (SendInput + wklejanie) | ✔ | = V1 | **TAK** | przepisać na UI Automation (§5) |
| Wyłącznik autofillu | ✔ | = V1 | **TAK** | bez zmian |
| 2FA/OTP — wykrywanie i wpisywanie | ✔ | = V1 | **TAK** | + ręczne wywołanie okna kodu |
| Import tuneli FortiClienta z rejestru | ✔ | = V1 | **TAK** | bez zmian |
| Status z adapterów (WinAPI + cache) | ✔ | = V1 | **TAK** | **nie ruszać** — to najlepsza część |
| Status z logów klienta | ✔ | = V1 | **TAK** | bez zmian |
| Status z `netstat`/`tasklist` | ✔ | = V1 | **TAK** | ograniczyć częstotliwość |
| Windows VPN (notatka + rasdial) | ✔ | = V1 | **TAK** | bez zmian (ograniczenie systemu) |
| Przycisk VPN przy szpitalu (match po nazwie) | ✔ | = V1 | **TAK** | + jawne powiązanie profil↔szpital |
| Kopiowanie loginu/hasła VPN | ✔ | = V1 | **TAK** | **dodać auto-czyszczenie schowka** |
| **INNE** |
| SQL Developer + dane do wklejenia | ✔ | = V1 | **TAK** | poprawić komunikat (15 s, nie 30 s) |
| Motyw ciemny / jasny | ✔ | = V1 | **TAK** | przełączanie bez restartu |
| Konfiguracja `%APPDATA%` | ✔ | = V1 (własny katalog) | **TAK** | + wersjonowanie schematu |
| Instalator Inno Setup | ✔ | = V1 (własny AppId) | **TAK** | + podpis, + auto-update (opcja) |
| Build PyInstaller onedir | ✔ | = V1 (własne nazwy) | **TAK** | bez zmian |
| Testy jednostkowe (30) | ✔ | = V1 | **TAK** | rozszerzyć wraz z serwisami |

**Funkcje, których dziś nie ma, a warto je rozważyć później** (nie są regresją, są nowością):
eksport/import fragmentu vaulta, historia połączeń, „ostatnio używane", globalne wyszukiwanie po
wszystkich szpitalach, snippety komend SSH, skróty klawiszowe do połączeń, kopia zapasowa vaulta
z rotacją.

---

## 3. WYDAJNOŚĆ

### P1 — Argon2id blokuje GUI przy każdym zapisie **[CRITICAL]**
- **PRZYCZYNA:** `main_window.py:433` woła `encrypt()` synchronicznie; KDF to 64 MB pamięci
  i 3 iteracje. To samo przy otwarciu (`login_dialog.py:276`).
- **SKUTEK:** `Ctrl+S` zamraża całą aplikację na 1–4 s **bez żadnego wskaźnika** — na słabszym
  laptopie wygląda jak zawieszenie. Przy otwartych sesjach SSH terminal w tym czasie nie rysuje.
- **ROZWIĄZANIE:** `VaultService` z operacjami w `QThread`; modal z paskiem postępu i blokadą
  edycji na czas zapisu. Parametrów Argon2 **nie zmieniać**.

### P2 — Status VPN odpytywany synchronicznie w wątku GUI co 2 s **[CRITICAL]**
- **PRZYCZYNA:** `detail_panel.py:481` (`setInterval(2000)`) → `_poll_vpn_status` →
  `vpn_connect.get_status()`. Dla FortiClienta ta ścieżka może wykonać `tasklist` **i** `netstat`
  (`vpn_connect.py:494`), a przy edycjach EMS także `FortiVPN.exe --cli --status` z timeoutem 5 s.
- **SKUTEK:** mikro-zacięcia co 2 s przy każdym szpitalu z profilem VPN; w skrajnym przypadku
  (klient nie odpowiada) zamrożenie do 5 s. `vpn_panel.py` robi to **poprawnie** w `StatusWorker`
  — czyli w projekcie istnieją dwie wersje tej samej operacji.
- **ROZWIĄZANIE:** jeden `VpnStatusService` z własnym wątkiem i sygnałem `status_changed`;
  wszystkie widoki tylko subskrybują. Interwał adaptacyjny (2 s po akcji, 10–15 s w spoczynku).

### P3 — Uruchomienie VPN blokuje GUI do ~10 s **[CRITICAL]**
- **PRZYCZYNA:** `vpn_panel.py:1122` woła `connect_monitored()` synchronicznie. Ścieżka Stormshield
  zawiera `time.sleep(4)`, potem `sleep(2)` przy ponowieniu (`vpn_connect.py:2822`), FortiClient —
  `_wait_forticlient_window(0.5)` + `_is_fortivpn_cli_supported` (subprocess 5 s) +
  `_wait_for_process(4 s)`.
- **SKUTEK:** kliknięcie „Połącz" zamraża okno; użytkownik klika drugi raz, powstaje druga próba.
- **ROZWIĄZANIE:** cała operacja w wątku, przycisk w stanie „łączenie…", anulowanie możliwe.

### P4 — Każdy RDP to 3–5 wywołań PowerShell w wątku GUI **[HIGH]**
- **PRZYCZYNA:** `rdp.py:169` → `_ensure_signing_cert` (PS, timeout 15 s) → `_ensure_publisher_bypass`
  (PS, 10 s) → `_ensure_local_devices_trust` (PS ×2, 10+15 s) — plus `_diag_saved_cred_policy`.
- **SKUTEK:** 1–6 s zamrożenia przy każdym kliknięciu „RDP", więcej przy pierwszym uruchomieniu
  (tworzenie certyfikatu) i na maszynach z wolnym startem PowerShella (AV skanujący `powershell.exe`).
- **ROZWIĄZANIE:** wykonać raz na sesję i zapamiętać w `config.json` (thumbprint + znacznik, że
  trust jest nadany); całość w wątku; PowerShell zastąpić `certutil`/WinAPI tam, gdzie się da.

### P5 — Pełna przebudowa tabel przy każdej zmianie danych **[HIGH]**
- **PRZYCZYNA:** `detail_panel.py:823` — `_refresh_machines()` kasuje wszystkie wiersze i tworzy
  od nowa; dla każdego wiersza `_machine_actions()` buduje **4–5 `QPushButton` z osobnym
  stringiem QSS** (`detail_panel.py:852`), a każdy taki string Qt parsuje osobno.
- **SKUTEK:** szpital ze 100 maszynami = ~500 widgetów i ~500 parsowań QSS przy każdej edycji,
  przełączeniu szpitala i po każdym `data_changed`. Zauważalne od ~50 wierszy.
- **ROZWIĄZANIE:** `QAbstractTableModel` + `QStyledItemDelegate` rysujący przyciski akcji;
  QSS globalny z klasami zamiast stringów per widget.

### P6 — Scrollback 250 000 linii × liczba sesji **[HIGH]**
- **PRZYCZYNA:** `ssh_panel.py:719` — `_SCROLLBACK = 250_000`; komentarz szacuje 25–250 MB
  **na sesję**.
- **SKUTEK:** 6 otwartych zakładek z gadatliwymi logami = kilkaset MB do >1 GB RAM; przy 32-bitowym
  procesie byłby crash, przy 64-bitowym — swap. Dodatkowo `_rebuild_search_matches`
  (`ssh_panel.py:1644`) przechodzi po całej historii.
- **ROZWIĄZANIE:** limit konfigurowalny (domyślnie 50 000), licznik zużycia w UI, opcjonalny zrzut
  historii do pliku zamiast trzymania w RAM.

### P7 — `tasklist` + `netstat` jako element pollingu **[MEDIUM]**
- **PRZYCZYNA:** `_get_vpn_connected_server_ip` (`vpn_connect.py:494`) uruchamia dwa procesy;
  wywoływane z `get_status` dla FortiClienta, gdy nie ma zapisanego `_last_connected`.
- **SKUTEK:** przy 10 profilach i pollingu co 5 s to do 20 procesów na cykl; na maszynach z ciężkim
  antywirusem każdy start procesu to 100–300 ms.
- **ROZWIĄZANIE:** zastąpić `GetExtendedTcpTable` (WinAPI, bez procesu) — analogicznie do już
  zrobionego `GetAdaptersAddresses`; wspólny cache 5–10 s.

### P8 — Zamykanie sesji z `wait(500)` **[MEDIUM]**
- **PRZYCZYNA:** `ssh_panel.py:6599`, `:7110`, `:5181` — `QThread.wait()` z krótkim timeoutem;
  jeśli wątek siedzi w `recv()` paramiko, `wait` mija bezskutecznie.
- **SKUTEK:** „QThread: Destroyed while thread is still running" → losowe wywrotki przy zamykaniu
  okna z wieloma sesjami.
- **ROZWIĄZANIE:** jawne zamknięcie kanału przed `wait`, dłuższy timeout, trzymanie referencji do
  czasu `finished`, sprzątanie w `deleteLater`.

### P9 — Statystyki: nowy kanał SSH co 5 s na sesję **[MEDIUM]**
- **PRZYCZYNA:** `_StatsWorker` (`ssh_panel.py:2357`) woła `exec_command` co 5 s; każde to nowy
  kanał na tym samym transporcie.
- **SKUTEK:** 8 sesji = 96 komend/min do serwerów szpitalnych; na obciążonym serwerze widoczne
  w logach i w `auth.log`.
- **ROZWIĄZANIE:** interwał konfigurowalny (domyślnie 10 s), pauza gdy zakładka niewidoczna,
  wyłącznik globalny.

### P10 — Listing SFTP przez `QTableWidget` **[MEDIUM]**
- **PRZYCZYNA:** `ssh_panel.py:3395` — 4 `QTableWidgetItem` + ikona na wiersz, tworzone w wątku GUI.
- **SKUTEK:** katalog z 20 000 plików (typowe `/var/log`, katalogi wymiany HL7) = kilkanaście sekund
  i skok pamięci.
- **ROZWIĄZANIE:** `QAbstractTableModel` + `QTableView` + ładowanie porcjami; ikony z cache.

### P11 — Kolorowanie logów regexami na każdą porcję **[LOW]**
- **PRZYCZYNA:** `_colorize_log` na chunk 16 KB w wątku workera.
- **SKUTEK:** przy strumieniu 1 MB/s to realny koszt CPU, ale **poza** wątkiem GUI — akceptowalne.
- **ROZWIĄZANIE:** zostawić; ewentualnie wyłącznik kolorowania dla bardzo szybkich strumieni.

### P12 — Cache adapterów 2 s vs. `invalidate_adapter_cache` **[LOW]**
- Działa dobrze (WinAPI zamiast `ipconfig`). **Nie ruszać**, tylko przenieść do serwisu.

---

## 4. UI / UX — koncepcja docelowa

### 4.1 Diagnoza obecnego UI
Dzisiejszy interfejs jest **gęsty i skuteczny**, ale: wszystkie kolory są zaszyte w 215 stringach,
przyciski akcji to emoji i znaki Unicode (`⇆`, `⚙`, `−`, `⛃`, `🌐`) o różnej szerokości w różnych
fontach, dialogi mają sztywne rozmiary (58 wywołań `setFixed*`), a komunikaty błędów to `QMessageBox`
z surową treścią wyjątku. Nie ma dashboardu, nie ma jednego miejsca ze stanem („co jest połączone").

### 4.2 Nawigacja główna
Lewa **szyna ikon** (nie lista szpitali): `Pulpit · Szpitale · Sesje · VPN · Bazy · Diagnostyka ·
Ustawienia`. Drugi panel kontekstowy (lista szpitali / profili / sesji) z wyszukiwarką na górze.
Trzeci obszar — treść. Górny pasek: nazwa vaulta, status zapisu, globalne wyszukiwanie (`Ctrl+K`),
wskaźnik trybu admina, wskaźnik VPN.

### 4.3 Pulpit (dashboard)
Kafelki: aktywne sesje SSH (z możliwością powrotu do okna), stan VPN (per profil, tylko połączone
i łączące się), ostatnio używane maszyny, ostrzeżenia (np. „vault niezapisany 40 min",
„klucz hosta zmieniony", „FortiClient nie wykryty"). Pulpit ma być **stanem świata**, nie ozdobą.

### 4.4 Ekran szpitala
Nagłówek: nazwa, liczniki (maszyny / bazy / poświadczenia), przycisk VPN z jawnym stanem, skrót do
notatek. Poniżej zakładki `Maszyny | Bazy | Notatki | Historia`. Tabela z kolumnami sortowalnymi
i **jednym** przyciskiem akcji głównej (Połącz) + menu kontekstowym dla reszty — zamiast czterech
przycisków w każdym wierszu.

### 4.5 Widok maszyn
Wiersz: status (ping/ostatnie połączenie), IP, nazwa, typ (SSH/RDP/WWW jako czytelny znacznik),
opis, poświadczenia (liczba + pierwszy login), akcje. Podwójny klik = połącz. Klawiatura: `Enter`
łączy, `Ctrl+C` kopiuje IP, `F2` edytuje. Widok kart jako alternatywa dla małych ekranów.

### 4.6 Widok baz danych
To samo co maszyny + kolumna „typ" z ikoną silnika i akcja „Otwórz w SQL Developer" oraz
„Kopiuj dane połączenia" (jeden przycisk zamiast dialogu z listą do ręcznego przepisania).

### 4.7 Widok VPN
Lista profili z jednoznacznym stanem: `Rozłączony / Łączenie… / Połączony (adapter: X, IP: Y)` oraz
**skąd wiemy** (adapter / log / CLI / netstat) — to samo w sobie jest narzędziem diagnostycznym.
Przy każdym profilu: Połącz, Kopiuj hasło (z odliczaniem czyszczenia schowka), Diagnostyka.

### 4.8 Widok aktywnych sesji SSH
Dziś sesje żyją w osobnym oknie i nie ma ich nigdzie indziej. Docelowo lista: host, użytkownik,
czas trwania, stan (aktywna / rozłączona / reconnect), statystyki, przyciski „Pokaż", „Zamknij".

### 4.9 Ustawienia
Jedno okno z sekcjami: Ogólne (motyw, język, DPI), Bezpieczeństwo (czas blokady admina, czas
czyszczenia schowka), SSH (scrollback, statystyki, terminal maksymalizowany), VPN (ścieżki, autofill,
interwał statusu), RDP (dyski, certyfikat), Diagnostyka (poziom logowania, eksport).
Dziś te opcje są rozrzucone po menu `Plik`, `Widok` i oknie VPN.

### 4.10 Komunikaty, statusy, błędy
- **Pasek statusu** zamiast modali dla rzeczy nieblokujących (skopiowano, zapisano, transfer gotowy).
- **Modal tylko dla decyzji** (nadpisać? zaakceptować nowy klucz? usunąć?).
- **Błąd = trzy poziomy**: krótkie zdanie po polsku → „Szczegóły" (rozwijane, treść techniczna) →
  „Kopiuj raport" / „Otwórz diagnostykę". Surowy `str(e)` nigdy jako główny komunikat.
- **Stan operacji długich** zawsze widoczny (zapis vaulta, łączenie VPN, skan katalogu).

### 4.11 Motyw ciemny/jasny
Docelowo **tokeny** (`--surface`, `--text`, `--accent`…) w jednym arkuszu QSS generowanym z palety,
zamiast remapowania hexów. Przełączanie **bez restartu**. Terminal zachowuje własną paletę
(niezależną od motywu aplikacji) — to jest właściwe zachowanie i zostaje.

### 4.12 DPI i rozdzielczości
`PassThrough` jest już ustawiony (`main.py:454`) — dobrze. Do zrobienia: usunąć `setFixedSize`
z okien (zostawić `minimumSize`), przejść na jednostki zależne od `QFontMetrics` zamiast stałych
px w QSS, przetestować 100/125/150/175/200% i dwa monitory o różnym DPI (przenoszenie okna między
nimi to klasyczne źródło rozjechanego layoutu w Qt).

### 4.13 Małe i duże ekrany
- ≤1366×768 (laptopy serwisowe): panel kontekstowy zwijany, tabela w trybie kompaktowym,
  okno SSH bez panelu maszyn.
- ≥2560 px: maksymalna szerokość treści, kolumny nie rozciągają się w nieskończoność,
  możliwość podziału terminala.
- Zapamiętywanie geometrii per monitor (dziś jest tylko dla okna SSH).

---

## 5. VPN — audyt szczegółowy

### 5.1 Pełny przepływ i punkty zależne od środowiska

Każdy wiersz to realne miejsce, w którym dwie maszyny mogą zachować się inaczej.

| # | Etap | Kod | Od czego zależy | Co się dzieje, gdy jest inaczej |
|---|---|---|---|---|
| 1 | Wykrycie instalacji | `vpn_connect.py:259` | klucz `HKLM\SOFTWARE\Fortinet\FortiClient` | instalacja per-user albo 32/64-bit redirection → „nie znaleziono" mimo działającego klienta |
| 2 | Edycja klienta | `:273` `_is_forti_free_edition` | `FA_FCM\installed` + skan Uninstall po `DisplayName` | **nazwa produktu zależy od wersji i języka instalatora**; nowe wydania („FortiClient VPN only") nie pasują do listy `("forticlient vpn","forticlient free")` → błędna klasyfikacja i próba CLI, którego nie ma |
| 3 | Ścieżka exe | `:180`, `:196` | 2 sztywne ścieżki + INSTALLDIR | instalacja na D:, ścieżka z lokalizowaną nazwą, ścieżka z konfiguracji użytkownika |
| 4 | Wsparcie CLI | `:318` | uruchomienie `FortiVPN.exe --cli --status` i szukanie fraz **angielskich** w stdout | klient w innym języku → fraza „error parsing" nie wystąpi → CLI uznane za wspierane, a nie jest |
| 5 | Szybka ścieżka „okno już otwarte" | `:2554` | `_wait_forticlient_window(0.5)`: `tasklist` + `EnumWindows` + tytuł zawierający „FortiClient" | tytuł zależy od wersji i języka; okno w trayu nie jest `IsWindowVisible` → fałszywe „brak okna" |
| 6 | Okno autoryzacji EMS | `:2235` | heurystyka po klasach kontrolek | brak w edycji free; inna struktura w nowych wersjach |
| 7 | Uruchomienie GUI | `:1334` | **`explorer.exe C:\Users\Public\Desktop\FortiClient VPN.lnk`** | **to jest źródło „otwiera folder Dokumenty"**: skrót nie istnieje (instalacja bez skrótu publicznego / usunięty przez użytkownika) albo skojarzenie `.lnk` przejęte przez WinRAR/7-Zip → explorer otwiera katalog profilu. Kod to **wykrywa** (`_wait_for_process` 4 s) i ma fallback, ale użytkownik zdąży zobaczyć otwarty folder |
| 8 | Fallback Popen | `:1385` | `_clean_pyinstaller_env()` + cwd + DETACHED | bez czyszczenia `_MEI*` Electron FortiClienta wywala się na `Logger TraceLog` — zależne od tego, czy uruchamiamy z exe czy ze źródeł |
| 9 | Czekanie na proces | `:23` | `tasklist` co 0,25 s do 4 s | wolny start pod antywirusem → timeout, mimo że klient wystartuje sekundę później |
| 10 | Znalezienie okna do autofillu | `:1514` | tytuł + PID procesu zaczynającego się na „Forti" | poprawne zabezpieczenie, ale przy oknie splash/loading trafia w okno, które zaraz zniknie |
| 11 | Fokus | `:1587` | `AttachThreadInput` + `SetForegroundWindow` | Windows blokuje wymuszanie fokusu, gdy aktywna jest inna aplikacja (reguła foreground lock); **UAC-owe okno klienta działa z wyższym poziomem integralności → SendInput jest ignorowany (UIPI)** |
| 12 | Czekanie na render | `:1601` | `time.sleep(1.5)` | na wolnej maszynie Chromium jeszcze nie narysował pól; na szybkiej — strata czasu |
| 13 | **Nawigacja Tab** | `:1607-1620` | **ślepa sekwencja: Tab → Space → tekst → Enter → Tab → Tab** | **najbardziej kruchy element całego systemu.** Kolejność Tab zależy od wersji klienta, od tego czy pokazuje się baner, czy pole „VPN Name" jest listą czy tekstem, czy zapamiętano poprzedni profil. Jedna zmiana układu = hasło wpisane w złe pole |
| 14 | Wklejanie | `:1630-1660` | schowek + `Ctrl+A`/`Delete`/`Ctrl+V` | wklejanie zamiast wpisywania naprawiło gubione znaki, ale **hasło trafia do schowka systemowego** i zostaje tam do zakończenia sekwencji; menedżery schowka (Win+V, Ditto) je przechwycą |
| 15 | Zatwierdzenie | `:1673` | `Enter` w polu hasła | jeśli fokus jest gdzie indziej (patrz 13) — Enter aktywuje przypadkowy przycisk |
| 16 | 2FA | `:2302` | wykrycie okna „Authentication" + wpisanie kodu | zależne od tytułu okna i układu pól; przy push-notification w ogóle nie ma pola |
| 17 | Potwierdzenie połączenia | `:3004` | adapter (WinAPI) / log / netstat / CLI, plus `_last_connected` | `_last_connected` żyje **tylko w pamięci procesu** — po restarcie aplikacji przy aktywnym tunelu status potrafi pokazać „Disconnected" albo `None`; przy tunelu zestawionym poza HospitalHubem kod świadomie zwraca `None` (`:3143`) |

**Wnioski, których nie zakładałem z góry, tylko wynikają z kodu:**

1. **„Otwiera folder Dokumenty" ma jedną konkretną przyczynę** — punkt 7: skojarzenie plików `.lnk`
   przejęte przez archiwizator albo brak skrótu na pulpicie publicznym. To jest udokumentowane
   w komentarzu w kodzie jako zaobserwowane na konkretnej maszynie.
2. **„Czasami autofill działa, czasami nie"** to suma punktów 11, 12, 13 i 15: wyścig między
   renderowaniem Chromium a stałymi `sleep()`, blokada fokusu Windows i ślepa kolejność Tab.
   Na szybkim komputerze z klientem w domyślnej konfiguracji działa; przy innej wersji klienta,
   wolniejszym dysku albo aktywnym UAC — nie.
3. **„Błąd u innego użytkownika"** najczęściej pochodzi z punktów 1–4: inna edycja/wersja/język
   klienta klasyfikowana błędnie, bo detekcja opiera się na nazwach produktów i frazach angielskich.
4. **Nie ma jak tego zdiagnozować zdalnie** — `_dbg()` jest pustą funkcją (`vpn_connect.py:2526`),
   więc żaden z tych 17 punktów nie zostawia śladu.

### 5.2 Proponowana architektura providerów

```
vpn/
  base.py            VpnProvider (ABC)  — kontrakt + wspólne narzędzia
  registry.py        rejestr providerów, wybór po nazwie, providerzy użytkownika
  service.py         VpnService — kolejka operacji, wątki, cache, sygnały do UI
  automation.py      WindowAutomation — EnumWindows, tray, fokus, SendInput, UIA
  processes.py       ProcessService — PID, uruchamianie (4 strategie), czekanie
  adapters.py        AdapterService — GetAdaptersAddresses, GetExtendedTcpTable, cache
  providers/
    forticlient.py   GlobalProtect.py  stormshield.py  barracuda.py
    sonicwall.py     hillstone.py      windows_vpn.py  generic.py
```

**Kontrakt (`VpnProvider`):**

| Metoda | Zwraca | Sens |
|---|---|---|
| `detect() -> Detection` | zainstalowany?, wersja, edycja, ścieżka exe, źródło wykrycia, pewność | **jedno miejsce** na wiedzę o instalacji |
| `capabilities() -> Caps` | czy ma CLI, czy wspiera autofill, czy zna status, czy obsługuje 2FA | UI wie z góry, co pokazać, a czego nie obiecywać |
| `connect(profile, ctx) -> Result` | ok, komunikat *kluczem* (nie tekstem), uchwyt procesu | wykonywane **zawsze w wątku roboczym** |
| `disconnect(profile) -> Result` | jw. | |
| `status(profile) -> Status` | stan + **źródło** (adapter/log/CLI/netstat) + znacznik czasu | źródło jest częścią odpowiedzi, nie ukrytą logiką |
| `diagnostics() -> Report` | komplet faktów o środowisku (§6) | to, co dziś trzeba zgadywać przez telefon |

Zasady wspólne dla wszystkich providerów:
- **Żadnych komunikatów po polsku w warstwie providera** — zwracają kody, UI je tłumaczy.
- **Żadnych `sleep()` o stałej długości** — tylko „czekaj na warunek z timeoutem" (`wait_for(pred)`).
- **Kolejność strategii jawna i logowana**: `CLI → GUI+automatyzacja → ręcznie`, a nie zagnieżdżone
  `if`-y. Każda próba zapisuje: co próbowaliśmy, dlaczego się nie udało, co robimy dalej.
- **Autofill oparty o UI Automation** (`IUIAutomation` przez `comtypes`) zamiast ślepego Tab:
  znajdź pole po `AutomationId`/`ControlType`/nazwie, ustaw wartość przez `ValuePattern`,
  kliknij przycisk po nazwie. Dla Chromium FortiClienta UIA działa (drzewo dostępności jest
  eksponowane). Ślepy Tab zostaje **wyłącznie jako fallback** i tylko za zgodą użytkownika.
- **Wykrywanie klienta wielościeżkowe**: rejestr (HKLM 64 + 32 + HKCU) → typowe ścieżki → `PATH` →
  skanowanie `Program Files` → ścieżka podana ręcznie. Wersja czytana z zasobów pliku exe
  (`GetFileVersionInfo`), nie z nazwy w Uninstall.

### 5.3 Czego **nie** ruszać w VPN
- `_enumerate_adapters_winapi` + cache (`vpn_connect.py:1104`, `:1176`) — to jest zrobione dobrze
  i jest najtańszym źródłem prawdy o stanie tunelu.
- Dwustopniowe uruchamianie FortiClienta z czyszczeniem `_MEI*` — rozwiązuje realny crash Electrona.
- `_shell_launch` przez ShellExecuteW dla klientów z manifestem `requireAdministrator`.
- Rozróżnienie profili po IP serwera, gdy nie wiadomo, który profil jest połączony.

---

## 6. DIAGNOSTYKA

### 6.1 Architektura

```
diagnostics/
  collector.py     rejestr kolektorów (system, vpn, rdp, ssh, app)
  redactor.py      filtr sekretów — JEDYNA droga zapisu do raportu
  trace.py         TraceRecorder — kroki operacji z czasami i wynikami
  export.py        pakowanie do .zip + manifest + podgląd przed wysłaniem
```

**`TraceRecorder`** to sedno: każda operacja VPN/RDP/SSH tworzy `trace_id` i zapisuje kroki:
```
step="forti.detect"      status=ok    dur=42ms   data={source:"registry", path:"C:\...", version:"7.4.1"}
step="forti.launch"      status=warn  dur=4100ms data={strategy:"explorer_lnk", process_started:false}
step="forti.launch"      status=ok    dur=820ms  data={strategy:"popen_clean_env", pid:9184}
step="forti.window"      status=fail  dur=10000ms data={titles_seen:["FortiClient VPN","Splash"]}
```
Ostatnie N śladów (np. 20) trzymane na dysku rotacyjnie. To zamienia „u mnie nie działa"
w jednoznaczny zapis, który krok zawiódł.

### 6.2 Zakres zbieranych danych

| Sekcja | Zawartość |
|---|---|
| `app` | wersja HospitalHub, tryb (exe/źródła), wersja Pythona i PyQt, ścieżka instalacji, czas startu, ostatnie wpisy z `crash.log` |
| `system` | wersja i build Windows, edycja, architektura, język/locale, DPI i rozdzielczości monitorów, czy proces działa jako admin, poziom integralności, czy UAC włączony |
| `policy` | wykryte GPO istotne dla RDP (delegacja poświadczeń, `DisableSavedCredentials`), polityka wykonywania PowerShell, obecność i stan Defendera/AV (sama nazwa dostawcy) |
| `vpn.<provider>` | zainstalowany?, **wersja z zasobów exe**, edycja, ścieżka + źródło wykrycia, obecność `.lnk` i jego skojarzenie, obecność CLI i wynik `--help`, lista procesów klienta (nazwa+PID), **lista okien: tytuł, klasa, widoczność, PID, rozmiar**, drzewo kontrolek okna logowania (UIA: typ, AutomationId, nazwa — **bez wartości pól**), adaptery sieciowe pasujące do providera (nazwa, opis, stan, czy ma IPv4 — **bez adresów**), źródło ostatniego odczytu statusu |
| `vpn.last_attempt` | pełny trace ostatniej próby: kroki, czasy, wynik, użyta strategia, kody błędów, **komenda z zamaskowanymi argumentami** |
| `rdp` | wynik `_diag_saved_cred_policy`, obecność `rdpsign`, thumbprint certyfikatu, czy trust/bypass ustawione, ostatnie linie logu RDP |
| `ssh` | liczba sesji, wersja paramiko, liczba wpisów TOFU (**bez hostów**), ostatnie błędy połączeń |
| `config` | `config.json` **po redakcji**: ścieżki skrócone do `<APPDATA>\…`, wartości boolean/liczby zachowane, żadnych nazw plików vault |

### 6.3 Redakcja — twarde reguły

`redactor.py` jest **jedynym** sposobem zapisu do raportu i działa jak lista dozwolonych, nie zakazanych:

1. Pola o nazwach pasujących do `pass|pwd|secret|token|otp|code|key|cred|pin|hash|salt` → `"<redacted>"`.
2. Argumenty procesów: dozwolone tylko znane flagi; wartość po `--password`, `-p`, `--token`,
   `--username` → `"<redacted>"`. Domyślnie **cała komenda jest maskowana poza nazwą exe**.
3. Zawartość pól formularzy **nigdy** nie jest czytana — z UIA bierzemy wyłącznie strukturę.
4. Adresy IP i nazwy hostów → maskowane do `10.x.x.x` / `host-<hash8>` (spójny hash w obrębie raportu,
   żeby dało się śledzić relacje bez ujawniania topologii szpitala).
5. Zero dostępu do pliku `.vault`, zero jego nazwy, zero listy szpitali.
6. Schowek nigdy nie jest odczytywany do raportu.
7. Przed zapisem — **skan kontrolny**: raport jest przeszukiwany wzorcami (ciągi >20 znaków
   base64-podobne, `BEGIN PRIVATE KEY`, znane prefiksy tokenów); trafienie = twardy błąd eksportu,
   nie ciche obcięcie.

### 6.4 Format eksportu

```
HospitalHub-diag-2026-09-11-142530.zip
  manifest.json      wersja schematu, czas, id raportu, lista sekcji, suma SHA-256 każdego pliku
  report.json        dane strukturalne (po redakcji)
  report.txt         czytelna wersja dla człowieka
  trace.jsonl        kroki ostatnich prób (po redakcji)
  windows.txt        zrzut tytułów/klas okien klienta VPN
  REDACTION.txt      co zostało usunięte i według jakiej reguły
```

- Bez szyfrowania domyślnie (użytkownik ma móc sam przeczytać zawartość), ale z **opcją**
  zabezpieczenia hasłem przy wysyłce.
- **Podgląd przed zapisem**: okno pokazujące dokładnie to, co trafi do pliku, z przyciskiem
  „Usuń tę sekcję". Nic nie wychodzi z maszyny bez świadomej zgody.
- Ścieżka w UI: `Diagnostyka → VPN → Uruchom test → Eksportuj` — z opcją „Powtórz ostatnią próbę
  połączenia z pełnym śladem".

---

## 7. RDP

### 7.1 Co działa dobrze (zachować bez zmian)
- **`CredWriteW` przez ctypes** (`rdp.py:691`) — hasło nigdy nie trafia do argumentów procesu;
  `CRED_PERSIST_SESSION` kasuje wpis przy wylogowaniu, a timer kasuje po 30 s.
- **Zawsze podpisany `.rdp`** (`rdp.py:154`) — to jest naprawiona regresja: na maszynach z GPO
  delegacji poświadczeń `mstsc /v:host` ignoruje zapisane poświadczenie. Ta decyzja jest
  udokumentowana w kodzie i **nie wolno jej cofać**.
- **Walidacja IP/portu** przed uruchomieniem (`rdp.py:79`).
- **Log diagnostyczny** rozróżniający trzy przyczyny pytania o hasło.
- Plik `.rdp` tworzony przez `mkstemp` (0600) w dedykowanym katalogu.

### 7.2 Co jest kruche
| Element | Dlaczego |
|---|---|
| Tworzenie i zaufanie certyfikatu przez **PowerShell** | `ExecutionPolicy`, AppLocker, Constrained Language Mode, zablokowany `powershell.exe` przez AV — każde z nich wywraca ścieżkę; kod to łyka po cichu i podpis nie powstaje |
| `PublisherPermissions` z kluczem = SHA-256 RawData + `00` | format ustalony **empirycznie** z podglądu rejestru; Microsoft może go zmienić w dowolnej aktualizacji |
| `rdpsign.exe` w Home | kopiowany z WinSxS — ścieżka i obecność zależą od builda |
| Zapis do `HKCU\...\TrustedPublisher`/`LocalDevices` | GPO może to nadpisywać cyklicznie |
| Brak sprzątania po crashu | jeśli aplikacja padnie w ciągu 30 s, wpis `TERMSRV/<ip>` zostaje (łagodzi to `CRED_PERSIST_SESSION`) |
| Wszystko synchronicznie w GUI | patrz §3 P4 |
| `_normalise_default_rdp` (`rdp.py:595`) | **martwy kod** — funkcja nie jest już nigdzie wywoływana po przejściu na „zawsze plik .rdp"; 90 linii, które mylą przy czytaniu |

### 7.3 Co poprawić
1. Wynieść całość do `RdpService` **bez `QMessageBox`** — warstwa systemowa zwraca wynik, UI pokazuje.
2. Przygotowanie certyfikatu **raz na instalację**, wynik (thumbprint + flagi trust) w `config.json`;
   przy kolejnych uruchomieniach tylko szybka weryfikacja istnienia.
3. Zastąpić PowerShell tam, gdzie się da: `certutil` albo bezpośrednio WinAPI/`cryptography`
   do wygenerowania certyfikatu i `CertAddCertificateContextToStore` do zaufania.
4. Gdy podpis się nie uda — **powiedzieć to użytkownikowi** („zobaczysz okno weryfikacji wydawcy,
   to normalne"), zamiast milczeć.
5. Usunąć martwy `_normalise_default_rdp` (albo przywrócić mu sens, jeśli wróci ścieżka `/v:host`).
6. Dodać test połączenia: sprawdzenie portu 3389 przed uruchomieniem mstsc — dziś użytkownik
   czeka na timeout mstsc, żeby dowiedzieć się, że nie ma VPN-a.

---

## 8. SSH / SFTP — propozycja podziału

Wszystkie wymienione funkcje **zostają**. Chodzi wyłącznie o rozbicie jednego pliku na moduły.
Podział przebiega dokładnie po istniejących granicach klas, więc jest to przeniesienie kodu,
a nie przepisywanie logiki.

```
ssh/
  __init__.py
  ansi.py             _colorize_log + wzorce (czyste funkcje, testowalne)        ~350 l.
  screen.py           _TermScreen, _HistRow, konwersje pyte                      ~250 l.
  terminal_widget.py  TerminalWidget: render, selekcja, klawiatura, scrollback   ~900 l.
  terminal_search.py  indeks i nawigacja po trafieniach                          ~150 l.
  hostkeys.py         _ssh_fingerprint, _TofuHostKeyPolicy, _HostKeyPrompt       ~250 l.
  connection.py       _make_client, _SshWorker (czysty transport)                ~400 l.
  stats.py            _StatsWorker                                               ~80 l.
  session.py          _Session, _TerminalPane, cykl życia, auto-reconnect        ~400 l.
  multiexec.py        routing klawiszy do wielu sesji                            ~150 l.
sftp/
  client.py           połączenie, lock, ponowne użycie kanału                    ~200 l.
  listing.py          model katalogu (QAbstractTableModel) + worker              ~400 l.
  transfers.py        upload/download/kolejka/anulowanie                         ~450 l.
  remote_edit.py      pobierz → obserwuj → odeślij, ochrony                      ~400 l.
  fs_ops.py           mkdir/rename/chmod/delete + _count_dir_with_cap            ~300 l.
  icons.py            ikony typów plików z cache                                 ~150 l.
ui/ssh/
  ssh_window.py       SshDialog: układ, zakładki, pasek, geometria               ~700 l.
  machines_panel.py   _EnvironmentPanel                                          ~350 l.
  sftp_panel.py       widok SFTP (tylko UI, logika w sftp/)                      ~700 l.
```

**Kolejność bezpiecznego rozbijania** (każdy krok osobno, z testem po każdym):
1. `ansi.py`, `hostkeys.py`, `fs_ops.py` — czyste funkcje, zerowe ryzyko, **istniejące testy je
   pokrywają i muszą dalej przechodzić**.
2. `stats.py`, `icons.py` — małe, izolowane.
3. `screen.py` + `terminal_widget.py` — przeniesienie 1:1, bez zmian w logice.
4. `connection.py` — `_SshWorker` bez zmian.
5. SFTP: najpierw `client.py`/`transfers.py`, na końcu `listing.py` (bo tam zmienia się też
   QTableWidget → model/view).
6. Na końcu `ssh_window.py` — to, co zostanie.

Zysk: największy plik spada z 7 132 do ~900 linii, każdy moduł da się otworzyć w całości,
a `git diff` przestaje być nieczytelny.

---

## 9. BEZPIECZEŃSTWO

### 9.1 Ocena obecnego stanu

| Obszar | Ocena | Uwagi |
|---|---|---|
| Format vaulta | **dobry** | AES-256-GCM, losowe salt/nonce per zapis, magic bytes, weryfikacja tagu |
| KDF | **dobry** | Argon2id 3/64 MB/4 — zgodne z zaleceniami OWASP dla interaktywnego logowania |
| Zapis | **dobry** | atomowy, bez okna uszkodzenia pliku |
| Hasło admina | **dobry** | osobny hash + `compare_digest` |
| Pamięć — klucz | **dobry** | `bytearray` + zerowanie |
| Pamięć — hasło | **słaby punkt** | hasło główne żyje jako `str` przez całą sesję (`main_window._password`) — niemutowalne, nie da się wyzerować, trafia do zrzutu pamięci |
| Schowek | **niespójny** | 15 s w `dialogs.py:21`, **brak czyszczenia** w `vpn_panel.py:1009/1024`, osobna polityka w `vpn_connect.py:1995` |
| Schowek — autofill VPN | **ryzyko** | hasło VPN ląduje w schowku systemowym na czas sekwencji (do ~4 s) i jest widoczne dla menedżerów schowka (Win+V) |
| Poświadczenia RDP | **dobry** | `CredWriteW`, `CRED_PERSIST_SESSION`, kasowanie po 30 s |
| Logi | **dobry, ale** | `_dbg` wyłączone (brak wycieków, ale i brak diagnostyki); log RDP nie zawiera haseł — sprawdzone |
| Pliki tymczasowe | **dobry** | `mkstemp` 0600, katalog per-PID, sprzątanie przy wyjściu; **do poprawy**: osierocone katalogi po crashu nie są usuwane |
| Konfiguracja | **dobry** | brak haseł, tylko ścieżki |
| TOFU | **dobry** | jawny modal przy zmianie klucza; plik zawiera tylko odciski publiczne |
| IPC single-instance | **do przeglądu** | `QLocalServer` bez weryfikacji nadawcy — dowolny lokalny proces może wysłać „activate" (skutek: podniesienie okna, niski wpływ) |
| Diagnostyka | **nie istnieje** | projekt w §6 zakłada redakcję jako warunek konieczny |
| Komunikaty błędów | **dobry** | brak haseł w treściach wyjątków |

### 9.2 Rekomendacje (bez zmiany kryptografii)

1. **Nie zmieniać formatu vaulta.** Argon2id i AES-GCM są właściwym wyborem; zmiana byłaby ryzykiem
   bez korzyści. Jeśli kiedykolwiek zajdzie potrzeba (np. podniesienie `memory_cost`), to przez
   **wersję w nagłówku**: `_BIN_VERSION = 3` z odczytem v1 i v2 oraz cichą migracją przy najbliższym
   zapisie — nigdy przez zmianę w miejscu.
2. **Ujednolicić schowek**: jeden `ClipboardService` z auto-czyszczeniem (konfigurowalne, domyślnie
   15 s), widocznym odliczaniem i opcją „nie kopiuj, wypełnij bezpośrednio".
3. **Ograniczyć czas życia hasła VPN w schowku** — przy autofillu przez UIA (§5.2) schowek
   przestaje być potrzebny w ogóle.
4. **Hasło sesji** trzymać w `bytearray` i zerować przy zamknięciu okna; nie da się tego zrobić
   idealnie w Pythonie, ale można skrócić czas życia i nie kopiować hasła po strukturach.
5. **Auto-blokada aplikacji** (nie tylko trybu admina) po dłuższej bezczynności — dziś pełny vault
   jest odblokowany dopóki okno żyje.
6. **Sprzątanie osieroconych katalogów** `%TEMP%\HospitalHubV2_<pid>` przy starcie (PID nieistniejący).
7. **Diagnostyka** — wdrożyć dopiero z gotowym `redactor.py` i testami na wycieki (§6.3).

---

## 10. KOMPATYBILNOŚĆ

| Obszar | Ryzyko | Gdzie boli dziś | Co zrobić |
|---|---|---|---|
| Windows 10 vs 11 | **wysokie** | `PublisherPermissions` tylko 24H2+, `LocalDevices` tylko starsze (`rdp.py:438`) | macierz testów: Win10 22H2, Win11 23H2, Win11 24H2+ |
| DPI 125/150/175% | **wysokie** | 58× `setFixed*`, rozmiary czcionek w px w QSS | jednostki względne, `minimumSize` zamiast `fixed`, test na 4 skalach |
| Dwa monitory o różnym DPI | **średnie** | zapamiętywanie geometrii tylko w oknie SSH | zapis geometrii per ekran, obsługa `screenChanged` |
| Uprawnienia (bez admina) | **wysokie** | Stormshield/Hillstone mają manifest `requireAdministrator` — obsłużone przez ShellExecuteW; zapis do HKCU działa, do HKLM nie | jawny komunikat, gdy operacja wymaga podniesienia |
| GPO | **wysokie** | delegacja poświadczeń RDP (obsłużone), `ExecutionPolicy`/AppLocker blokujące PowerShell (**nieobsłużone — cicha porażka**) | wykrywać i raportować, nie milczeć |
| Defender / AV | **średnie** | start `powershell.exe`, `tasklist`, `netstat` spowalniany; exe z PyInstallera bywa fałszywie flagowany | mniej procesów (WinAPI), podpisany instalator, instrukcja wyjątku |
| Wersje klientów VPN | **bardzo wysokie** | detekcja po nazwach produktów i frazach angielskich (§5.1 pkt 2 i 4) | wersja z zasobów exe, macierz „wersja klienta → strategia" |
| Lokalizacje instalacji | **wysokie** | sztywne listy ścieżek | rejestr + PATH + skan + ścieżka ręczna, wszystko raportowane w diagnostyce |
| Język Windows | **wysokie** | fallback `ipconfig` parsuje polskie i angielskie frazy (`vpn_connect.py:1290`), ale tytuły okien i nazwy produktów już nie | nie parsować tekstu zlokalizowanego — WinAPI zamiast wyjścia komend |
| Rozdzielczość ≤1366×768 | **średnie** | okna o stałych rozmiarach, okno VPN 420×700 | układy responsywne (§4.13) |
| Brak zależności | **niskie** | PyQt6/paramiko/pyte pinowane, `pywin32` importowany warunkowo | zostawić, dodać jawny komunikat przy braku `win32gui` |
| PyInstaller | **średnie** | `sys.path.insert` ×9, `datas=[('ui','ui')]`, `_MEI*` psujące Electron (obsłużone) | przejście na pakiet + `--paths`, testowy start exe w CI |
| Konto domenowe / roaming profile | **średnie** | `%APPDATA%` roaming — config wędruje między maszynami razem ze ścieżkami do plików | rozważyć `LOCALAPPDATA` dla cache i ścieżek maszynowych |

---

## 11. PLAN PRAC — roadmapa HospitalHub V2

Zasada nadrzędna: **każdy etap kończy się działającą aplikacją**, a funkcjonalność V1 nie może
zniknąć na żadnym etapie. Kolejność jest dobrana tak, żeby fundament (testowalność, wątki,
diagnostyka) powstał **przed** zmianami w UI — inaczej każda zmiana wyglądu będzie ryzykiem.

---

### ETAP 0 — Fundament projektu **[CRITICAL]**
- **Cel:** móc bezpiecznie zmieniać cokolwiek: struktura pakietu, testy, siatka bezpieczeństwa.
- **Moduły:** nowy `hospitalhub/` jako pakiet, `pyproject.toml`/`setup.cfg`, `conftest.py`,
  `HospitalHubV2.spec`, CI lokalne (skrypt `check.bat`: testy + build + smoke-start exe).
- **Zakres:** usunięcie 9× `sys.path.insert` przez prawdziwe importy pakietowe; snapshot testy
  serializacji `models` (round-trip vault v1/v2); test otwarcia przykładowego vaulta; smoke-test
  startu aplikacji bez GUI (offscreen).
- **Ryzyko:** **średnie** — zmiana importów dotyka wszystkich plików, ale jest mechaniczna.
- **Test:** `pytest` (30 istniejących + nowe) musi przechodzić; `build_v2.bat` musi dać działający
  exe; ręczne: otwarcie realnego vaulta i połączenie SSH.
- **Zależności:** żadne.

### ETAP 1 — Warstwa serwisów i wyjście z wątku GUI **[CRITICAL]**
- **Cel:** żadna operacja dłuższa niż 100 ms nie blokuje interfejsu.
- **Moduły:** `services/vault_service.py`, `services/vpn_status_service.py`,
  `services/rdp_service.py`, `services/clipboard_service.py`; zmiany w `main_window.py`,
  `login_dialog.py`, `detail_panel.py`, `vpn_panel.py`, `rdp.py`.
- **Zakres:** P1, P2, P3, P4 z §3. Argon2 w wątku z paskiem postępu; jeden serwis statusu VPN
  zamiast dwóch implementacji; `connect/disconnect` w wątku; przygotowanie certyfikatu RDP raz,
  z cache w `config.json`; ujednolicony schowek z auto-czyszczeniem (naprawia lukę z §9).
- **Ryzyko:** **wysokie** — dotyka zapisu vaulta (dane użytkownika) i ścieżek połączeń.
  Mitygacja: zapis nadal atomowy, testy na kopii vaulta, etap wdrażany w krokach (najpierw odczyt,
  potem zapis).
- **Test:** zapis vaulta 5 MB bez zamrożenia UI; klik „Połącz VPN" — okno reaguje w trakcie;
  RDP na maszynie z GPO nadal łączy bez pytania o hasło (**regresja krytyczna, test ręczny**);
  hasło znika ze schowka po 15 s.
- **Zależności:** ETAP 0.

### ETAP 2 — Diagnostyka **[CRITICAL]**
- **Cel:** móc powiedzieć „uruchom diagnostykę i wyślij paczkę" i dostać odpowiedź, co zawiodło.
- **Moduły:** `diagnostics/` (collector, redactor, trace, export), zakładka „Diagnostyka" w UI,
  wpięcie `TraceRecorder` w istniejące ścieżki VPN i RDP.
- **Zakres:** §6 w całości. Najpierw `redactor.py` **z testami na wycieki**, dopiero potem kolektory.
- **Ryzyko:** **średnie** — ryzykiem jest wyciek danych w raporcie, dlatego redaktor pierwszy
  i z testami; sama zbiórka danych nie zmienia działania aplikacji.
- **Test:** testy jednostkowe redaktora (hasło/OTP/klucz w każdym możliwym polu → brak w wyjściu);
  ręcznie: wygenerowanie paczki na maszynie, gdzie VPN nie działa, i sprawdzenie, czy da się
  z niej wyczytać przyczynę.
- **Zależności:** ETAP 0 (ETAP 1 pomaga, ale nie jest wymagany).

### ETAP 3 — Przebudowa VPN na providerów **[CRITICAL]**
- **Cel:** koniec z „u jednego działa, u drugiego nie" bez możliwości ustalenia dlaczego.
- **Moduły:** `vpn/` wg §5.2; `vpn_connect.py` zostaje jako cienka warstwa zgodności, dopóki
  wszyscy providerzy nie zostaną przeniesieni.
- **Zakres, w kolejności:** (a) `base.py` + `registry.py` + `service.py`; (b) `WindowsVpnProvider`
  i `GenericProvider` (najprostsze, do sprawdzenia kontraktu); (c) **`FortiClientProvider`** —
  detekcja wielościeżkowa, wersja z zasobów exe, strategie jawne, autofill przez UI Automation
  z fallbackiem na obecną metodę; (d) pozostali providerzy; (e) usunięcie starego `vpn_connect.py`.
- **Ryzyko:** **bardzo wysokie** — to jest kod, który działa u użytkowników mimo swoich wad.
  Mitygacja: stary moduł zostaje do końca etapu; przełącznik „stara/nowa ścieżka VPN" w ustawieniach;
  każdy provider wdrażany osobno i testowany na realnym kliencie; **żadnej zmiany zachowania
  w tym samym kroku co przenosiny kodu**.
- **Test:** dla każdego providera scenariusz na żywej infrastrukturze: klient nieuruchomiony /
  uruchomiony w trayu / okno otwarte / zły login / 2FA / rozłączenie; porównanie trace’ów
  starej i nowej ścieżki; test na ≥2 różnych komputerach (w tym jednym bez uprawnień admina).
- **Zależności:** ETAP 1 (wątki), ETAP 2 (trace jest tu narzędziem pracy, nie dodatkiem).

### ETAP 4 — Rozbicie `ssh_panel.py` **[HIGH]**
- **Cel:** utrzymywalność największego modułu bez zmiany zachowania.
- **Moduły:** `ssh/`, `sftp/`, `ui/ssh/` wg §8.
- **Zakres:** przenoszenie 1:1 w 6 krokach z §8. Jedyna zmiana funkcjonalna w tym etapie:
  `listing.py` na model/widok (P10) — i tylko jako ostatni krok.
- **Ryzyko:** **wysokie** przez objętość, **niskie** merytorycznie (przenosiny). Mitygacja:
  po każdym kroku pełny test ręczny terminala i SFTP; nie łączyć z żadną zmianą wyglądu.
- **Test:** scenariusz: 4 sesje naraz, `docker logs -f` na jednej, Ctrl+C, multi-exec, szukanie,
  upload 500 MB z anulowaniem, edycja pliku zdalnego, usunięcie katalogu z 10 000 plików,
  zmiana klucza hosta.
- **Zależności:** ETAP 0.

### ETAP 5 — Nowy UI **[HIGH]**
- **Cel:** wygląd i ergonomia z §4, przy zachowaniu wszystkich funkcji.
- **Moduły:** `ui/` w całości, nowy `ui/styles/` (tokeny + QSS), `theme.py` → generator palety.
- **Zakres:** nawigacja, pulpit, ekran szpitala, widoki maszyn/baz/VPN/sesji, ustawienia w jednym
  oknie, nowy system komunikatów i błędów, przełączanie motywu bez restartu, DPI, responsywność.
  Tabele przechodzą na model/widok (P5).
- **Ryzyko:** **wysokie** — najłatwiej tu zgubić funkcję. Mitygacja: tabela z §2 jako lista
  kontrolna; każdy widok odhaczany funkcja po funkcji; **weryfikacja wizualna zrzutem ekranu
  z działającej aplikacji, nie samym buildem**.
- **Test:** przejście całej tabeli §2; test na 100/125/150/175%; test na 1366×768 i 2560×1440;
  oba motywy; praca bez myszy.
- **Zależności:** ETAP 1 (serwisy), ETAP 4 (okno SSH), ETAP 3 (widok VPN).

### ETAP 6 — RDP i kompatybilność **[MEDIUM]**
- **Cel:** przewidywalny RDP na każdej maszynie i jawne komunikaty, gdy środowisko przeszkadza.
- **Moduły:** `services/rdp_service.py`, `diagnostics/collectors/policy.py`.
- **Zakres:** §7.3 — certyfikat bez PowerShella tam, gdzie się da; wykrywanie GPO/ExecutionPolicy
  i komunikat zamiast cichej porażki; usunięcie martwego `_normalise_default_rdp`; test portu
  przed mstsc; sprzątanie poświadczeń przy zamknięciu aplikacji.
- **Ryzyko:** **średnie** — dotyka ścieżki, która właśnie została naprawiona. Nie zmieniać zasady
  „zawsze podpisany `.rdp`".
- **Test:** maszyna z GPO delegacji, maszyna bez, Windows Home (brak `rdpsign` w System32),
  konto bez uprawnień admina.
- **Zależności:** ETAP 1, ETAP 2.

### ETAP 7 — Wydajność i higiena **[MEDIUM]**
- **Cel:** domknięcie pozostałych punktów z §3.
- **Zakres:** scrollback konfigurowalny + licznik pamięci (P6); `GetExtendedTcpTable` zamiast
  `netstat`/`tasklist` (P7); cykl życia wątków przy zamykaniu sesji (P8); interwał statystyk (P9);
  sprzątanie osieroconych katalogów tymczasowych; auto-blokada aplikacji (§9.2 pkt 5).
- **Ryzyko:** **niskie**.
- **Test:** 8 sesji × godzina pracy — pomiar RAM i CPU; zamknięcie okna z 8 sesjami 20× bez crasha.
- **Zależności:** ETAP 4.

### ETAP 8 — Wydanie **[MEDIUM]**
- **Cel:** instalator gotowy do rozdania współpracownikom.
- **Zakres:** wersjonowanie (2.0.0), changelog, podpisany instalator (jeśli będzie certyfikat),
  instrukcja migracji z V1 (vaulty działają bez zmian — to mocny punkt), instrukcja wyjątku
  dla Defendera, test instalacji obok V1 na czystej maszynie.
- **Ryzyko:** **niskie**.
- **Test:** instalacja na czystym Windows 10 i 11, obok działającej V1, z importem istniejącego vaulta.
- **Zależności:** wszystkie poprzednie.

### ETAP 9 — Nowe funkcje **[LOW]**
Dopiero tutaj: historia połączeń, globalne wyszukiwanie, tagi maszyn, snippety komend,
kopia zapasowa vaulta z rotacją, eksport/import fragmentów. **Nie wcześniej** — każda nowa funkcja
dołożona przed etapem 5 będzie przepisywana razem z UI.

---

### Podsumowanie priorytetów

| Priorytet | Etapy | Dlaczego |
|---|---|---|
| **CRITICAL** | 0, 1, 2, 3 | bez nich V2 jest tylko kopią V1 z tymi samymi problemami; VPN i blokady GUI to realny ból użytkownika |
| **HIGH** | 4, 5 | utrzymywalność i wygląd — duży zysk, ale bez fundamentu byłyby ryzykiem |
| **MEDIUM** | 6, 7, 8 | domknięcie jakości i wydanie |
| **LOW** | 9 | nowe funkcje dopiero na stabilnej bazie |

**Sugerowana kolejność startu:** ETAP 0 → ETAP 2 (diagnostyka wcześnie, bo od razu daje wiedzę
o maszynach użytkowników) → ETAP 1 → ETAP 3. Diagnostyka przed przebudową VPN oznacza, że
przebudowę będziemy prowadzić na **danych**, a nie na hipotezach.
