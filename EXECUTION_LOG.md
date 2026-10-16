# HospitalHub V2 — dziennik wykonania

> Trwały dziennik zmian, testów i wyników (od 2026-10-14). Wcześniejsza historia
> etapów VPN 1–62: `2026-10-13-hospitalhubv2-etapy-60-62.md`, `AUDYT_V2.md`,
> docstringi modułów `vpn/`. Najnowsze wpisy na dole.

---

## 2026-10-14 — Etap 63: MSAA w `_select_profile()`

**Agenci:** A (audyt bezpieczeństwa, read-only), B (audyt testów, read-only),
A ponownie (niezależny przegląd diffu, read-only). Implementacja: lead (jedyny
właściciel zmian).

**Zmiany produkcyjne** (`vpn/providers/`):
- `forticlient_autofill.py` — `_select_profile` na MSAA: preflight przed pierwszym
  klawiszem; `_ProfileReader` (tylko `win.hwnd`, hwnd/pid == zweryfikowane okno);
  już wybrany = zero klawiszy; Space gdy FOCUSED+COLLAPSED, nazwa/Enter gdy EXPANDED,
  każdorazowo odczyt → warunek → `win.confirm()` → klawisz w jednej operacji guarda;
  potwierdzenie 2 odczyty z rzędu; ponowny odczyt przed każdym zapisem sekretu do
  schowka, przed każdym Ctrl+V i w kroku submit. UIA `focused_control` usunięte.
- `forticlient_profile.py` — `requested_profile_selectable`, odmowa obciętego skanu.
- `msaa_system.py` — `MsaaScan.truncated`.
- `secure_target.py` — `VerifiedWindow.hwnd` (read-only).
- `forticlient.py` — `autofill_login_password(msaa=, tunnels=)`, `configured_tunnels()`.
- `forticlient_runtime.py` — `FortiConnectRuntime(msaa_system=)`.
- `forticlient_connect.py` — opis `gui-profile-select` w `CONNECT_PARITY`.

**Testy:** nowy `tests/test_vpn_forticlient_msaa_select.py`; przepisane testy
Etapu 60 (UIA → MSAA) w `test_vpn_forticlient_profile.py`; fake'i `LinkedMsaa`,
`forti_environment`, `TUNNEL_REGISTRY` w `test_vpn_forticlient_autofill.py`;
podpięcie w 5 innych plikach. Budżet czasu testu 9: 7.5 → 7.6 s (drugi odczyt
potwierdzający). **Wynik: 1416 PASS / 0 FAIL / 0 ERROR.**

**Review:** APPROVE WITH NOTES. Wdrożone: N1 (odmowa przed Shift+Tab, gdy lista
otwarta), N2 (precheck też przed Ctrl+V). Pozostawione: N3 (Enter wymaga EXPANDED,
nie FOCUSED — świadomie), N6 (dwa testy do zaostrzenia), N7 (kosmetyka trace).

**Incydent naprawiony w trakcie:** skrypty edycyjne (zapis Pythona w trybie
tekstowym) zamieniły LF→CRLF; repo ma style mieszane. Przywrócone linia po linii
względem migawki. Na przyszłość: zapisywać binarnie z zachowaniem stylu pliku.

**Niezmienniki:** flagi ×3 False; `vpn_connect.py` i spec nietknięte; zero
interakcji z prawdziwym FortiClientem.

---

## 2026-10-14 — PHASE 0: rozpoznanie

- **Migawka** całego drzewa V2 (bez `build/`, `dist/`, `__pycache__`, `.venv`):
  `hh_v2_snapshot_phase0.tgz` w scratchpadzie sesji Claude (143 pliki, 1.6 MB),
  utworzona `tar --force-local`. Uwaga: scratchpad jest katalogiem sesji — przy
  dłuższej przerwie warto skopiować migawkę w trwałe miejsce poza V1.
- **Testy zmierzone:** 1416 PASS (9.8 s).
- **Dokumentacja istniejąca:** `AUDYT_V2.md` (audyt + makro-roadmapa ETAP 0–9),
  `README_V2.md` (izolacja V1/V2), `OPIS_APLIKACJI.md`, notatka etapów 60–62,
  `smoke/README.md`. Brak ROADMAP/STATUS/LOG — utworzone (bez duplikowania audytu).
- **Stan makro (AUDYT §11):** ETAP 2 diagnostyka — jest (`diagnostics/`);
  ETAP 3 VPN — w toku (Etapy 1–63); ETAP 0 (pakiet, check.bat), ETAP 1 (serwisy,
  Argon2 poza GUI), ETAP 4 (rozbicie `ssh_panel.py`, 7132 l.), ETAP 5 (UI) — nie.
- **Znalezisko:** `comtypes` (1.4.16 w interpreterze) nie jest w spec ani
  `requirements.txt` → zbudowany exe nie odczyta MSAA/UIA (fail-closed). Zadanie H1.
- **Nowe:** `smoke/forticlient_msaa_live.py` — sonda G1 (`once`, `watch`),
  wyłącznie odczyty MSAA, wartość profilu nie jest drukowana (tylko pozycja w
  katalogu tuneli). Uruchomiona `once`: okno FortiClienta nie jest otwarte
  (`no verified FortiClient window`; katalog: ssl=2, ipsec=1) → G1 zablokowana
  na użytkowniku. 1416 PASS po dodaniu.
- **Agenci uruchomieni (read-only):** audyt ścieżek FortiClient V2 + `profile_name`;
  audyt C1 SSH/SFTP; audyt C2–C6 RDP/DB/vault/IPC/konfiguracja.

---

## 2026-10-14 — H1: comtypes / oleacc w buildzie

- **Próbny build** `py -3.13 -m PyInstaller --noconfirm HospitalHubV2.spec` (PyInstaller
  6.19.0): exit 0, `dist\HospitalHubV2\` 145 MB. Exe **nie był uruchamiany**.
- `comtypes` trafia do builda automatycznie (hook `hook-comtypes.client` z
  pyinstaller-hooks-contrib; import wewnątrz funkcji jest wykrywany), razem z
  pregenerowanym `comtypes.gen.UIAutomationClient` (Barracuda).
- **Brakowało** `comtypes.gen.Accessibility` (wrapper `oleacc`, MSAA): generowany przez
  `GetModule` w runtime, nigdzie importowany statycznie. W exe zostałby wygenerowany do
  `%TEMP%\comtypes_cache` — niezweryfikowane.
- **Zmiana:** `HospitalHubV2.spec` — `hiddenimports` += `comtypes.gen.Accessibility`,
  `comtypes.gen._1EA4DBF0_3C3B_11CF_810C_00AA00389B71_0_1_1` (komentarz w pliku).
  sha256 spec: `b2e98311…` → `4b27eed2…`. `requirements.txt` += `comtypes==1.4.16`.
- **Po przebudowie:** oba moduły są w archiwum exe (`archive_viewer --list`).
- **Regresja testów wykryta i naprawiona:** `build/` i `dist/` zawierają kopie `ui/`, a
  dwa tripwire'y (`test_vpn_activation_ui::test_27`, `test_vpn_panel_v2_bridge::test_2`)
  skanowały całe drzewo → po każdym buildzie suite był czerwony. Dodano `build`/`dist`
  do pomijanych katalogów (obok `tests`/`vpn`/`smoke`). 1416 PASS.
- **Do PHASE H:** w exe jest `numpy` (zależność przechodnia `pyautogui`/`pyscreeze`),
  rozmiar 145 MB — sprawdzić, czy `pyautogui` jest jeszcze używany. Uruchomienie exe
  (zachowanie MSAA w zamrożonym procesie) — smoke builda w PHASE G/H.

---

## 2026-10-14 — Audyty PHASE A/C (agenci, read-only) — streszczenie

**FortiClient V2 (L1–L14):** L1 HIGH pusty `profile_name` → dane do wyświetlonego profilu;
L2 HIGH równoległe sesje V2 z dwóch kart/okien (wspólny schowek); L3 COM w kolejnych wątkach
(nie odtworzone empirycznie); L4 brak śladu diagnostycznego trasy V2; L5 mylący komunikat
przy blokadzie profilu; L6 comtypes w buildzie (=H1); L7 przebudowa kart w trakcie sesji;
L8 zamknięcie vaulta w trakcie sesji (QThread); L9 MSAA pod AttachThreadInput — niezmierzone;
L10 IPsec zawsze BLOCKED; L11 `cli-monitor-not-owned-by-panel` (EMS); L12 CLI z `app_path`
bez kotwicy zaufania (jak legacy); L13 login może trafić do pola hasła; L14 wyścig zwalniania
kontrolera.

**C2–C6 (RDP/DB/vault/IPC/konfiguracja):** C4-01..05/07 (vault, zrobione w Etapie 65);
C2-01 szybka ścieżka certyfikatu RDP nie naprawia TrustedPublisher/Root; C2-02 `rdp_drives`
bez walidacji → wstrzyknięcie linii do podpisanego .rdp; C2-03 thumbprint bez walidacji formatu;
C2-04 sprzątanie TERMSRV przy dwóch RDP do jednego IP / `os._exit`, log diag. z loginem bez
rotacji; C3-01 schowek bez wykluczenia z historii Win+V; C3-02 martwy `connect_db` bez filtra
`admin_only`; C4-06 tryb admina chroni tylko w UI (do dokumentacji); C5-01 IPC: brak
`UserAccessOption`, wynik `listen()` niesprawdzany; C6 drobne (walidacja IP/portu bazy).

**C1 SSH/SFTP:** C1-01 CRITICAL wspólny plik tymczasowy → auto-upload na zły serwer;
C1-02..05 HIGH (te same nazwy w jednym oknie, utrata edycji po zmianie zakładki / przy
zamknięciu, powłoka po zamknięciu zakładki w trakcie łączenia); C1-06 HIGH path traversal
przy pobieraniu wielu plików; C1-07..12 MEDIUM (nieatomowy upload i kasowanie przy anulowaniu,
wycieki połączeń SFTP, TOFU przy innym typie klucza, spóźniony listing, współbieżny kanał SFTP
bez timeoutu, `_probe_writable` 'r+' na plikach HL7); C1-13..19 LOW (X11 zawsze, kbd-interactive
transport, lista rozszerzeń, multiexec, timeouty zamykania, ścieżka SFTP do złej sesji,
rekurencja usuwania).

---

## 2026-10-14 — Etap 65: integralność danych vaulta

- **Nowe:** `vault_io.py` — `write_vault_atomic` (tmp + fsync + replace, `.bak` jednej
  generacji, 4 próby `os.replace` przy PermissionError), `vault_kind_error`, `discard_backup`.
- **Zmiany:** `ui/main_window.py` (`_save` zwraca wynik; zapis przez `vault_io`; rollback hasła
  przy nieudanym zapisie; usunięcie `.bak` po zmianie hasła), `main.py` (nieudany zapis nie
  zamyka okna / przerywa wyjście; `normcase` przy wykrywaniu tego samego vaulta),
  `ui/login_dialog.py` (strażnik typu w obu ścieżkach otwierania; tworzenie nigdy nie nadpisuje —
  `exists` + tryb `xb`), `crypto.py` (`verify_admin_password` przy uszkodzonym base64 → False),
  `config.py` (uszkodzony/nie-dict config = brak ustawień; zapis tmp+replace; walidacja indeksu
  i listy vaultów), `tests/conftest.py` (APPDATA per test w tmp; pułapki advapi32 Cred*).
- **Testy:** `tests/test_vault_data.py` (49). Sprawdzone odwrotnie: 15 testów pada na kodzie bazowym.
- **Review:** APPROVE WITH NOTES; wdrożone uwagi 1 (usuwanie `.bak` po zmianie hasła), 2
  (docstring: jedna generacja), 4 (sprzątanie `config.json.tmp`). Pozostawione: 3 (`.bak` może
  być starszy, gdy kopia się nie uda — vault bezpieczny), 5 (`normcase` nie obejmuje 8.3/linków).

---

## 2026-10-14 — Etap 64: FortiClient V2 — luki z audytu przed cutoverem

- **L1:** pusty `profile_name` → BLOCKED `profile-not-specified` przed pierwszym klawiszem,
  wyjątek: dokładnie jeden tunel mierzonego rodzaju i MSAA potwierdza, że jest wyświetlony
  (zero klawiszy profilu, `may_change=False`). `forticlient_profile.sole_tunnel`. Wpis
  `gui-profile-unspecified` w `CONNECT_PARITY` (security). **Decyzja G5 nadal u użytkownika.**
- **L2:** jedna sesja V2 naraz w procesie (`panel_bridge._claim_session`, wynik `busy`).
- **L3:** `msaa_system.ensure_com_apartment` (MTA) przed MSAA i UIA. Pomiar (pasek zadań, 3 kolejne
  wątki, read-only): działało także bez tego — problem NIE odtworzony; poprawka zgodna z
  kontraktem COM, MTA odtwarza zmierzone zachowanie.
- **L4:** ślad `vpn.connect.v2` (flagi i kody, bez loginu/hasła/nazwy profilu); klucze w
  allowliście redaktora.
- **L5:** `PanelConnectOutcome.reason` + komunikaty karty per kod (konfiguracja profilu /
  brak nazwy / IPsec / niepotwierdzony).
- **L7 (po REJECT):** zamiast odraczania przebudowy — blokada edycji, dodawania, sortowania,
  importu i ustawień w trakcie sesji V2 (`_refuse_while_connecting`).
- **L8:** `cleanup` anuluje sesje, kontrolery trzymane do końca wątku, sygnały do panelu
  rozłączone. **L14:** zwalniany tylko własny kontroler.
- **Testy:** `tests/test_vpn_v2_session_guards.py`, sekcje d5*/h* w
  `test_vpn_forticlient_msaa_select.py`; 29 testów opartych na starym zachowaniu pustego
  profilu przeniesionych na maszynę z jednym tunelem (`sole_environment`) — asercje
  bezpieczeństwa bez zmian, przeliczone indeksy strażników (dochodzi odczyt profilu i
  `confirm()` po odczycie MSAA przed sekretem/Enterem).
- **Review 1:** REJECT (L7 — przesunięte indeksy przycisków kart) → przeprojektowane.
  Uwagi N1 (MTA), N3 (allowlista), N4 (sygnały) wdrożone. Review 2: w toku.
- Pozostaje udokumentowane: L9, L10, L11, L12, L13; N2 (zawieszony FortiClient = BUSY dla
  wszystkich kart do restartu).

---

## 2026-10-14 — Etap 66: SSH/SFTP — C1-01..06, C1-17

- `ui/ssh_panel.py`: `sftp_temp_root`/`sftp_temp_path` (katalog per panel + hash
  serwer+ścieżka), `SftpPanel._local_copy_path/_server_identity/temp_dir/bound_to/
  forget_connection`, `_watch_store` (C1-03), `safe_local_name` (C1-06),
  `_SshWorker._stop_requested`/`_close_quietly` + budzenie promptu (C1-05/C1-17),
  flush przed teardownem i kolejność w `closeEvent` (C1-04).
- **Testy:** `tests/test_ssh_sftp_safety.py` (42); odwrotnie: 40/42 pada na bazowym
  `ssh_panel.py` (C1-17 czekał tam 120 s).
- Pozostałe C1-07..19 w kolejce.
- Pułapka narzędziowa: łatki przez heredoc psuły ukośniki (NUL w pliku, `\x` w docstringu) —
  łatki z ukośnikami tylko przez plik skryptu (`r'''…'''`); wykryte i naprawione przed testami.

**Stan:** 1545 PASS / 0 FAIL. Flagi ×3 False. `vpn_connect.py` a929035e… nietknięty.

---

## 2026-10-14 — Review 2/3 Etapów 64/66 i Etap 67 (RDP, schowek)

- **Review 2 (L7 + N1/N3/N4 + Etap 66):** L7 zatwierdzone; **REJECT za S1** — `_watch_store`
  kluczowany gołym `id()` klienta (sieroty po zamknięciu aktywnej karty i po reconnect; id()
  ponownie użyte przez nowego klienta → auto-upload na zły serwer). Naprawa: wpis =
  `(weakref.ref(client), pliki)`, przywracany tylko gdy `ref() is client`; `forget_connection`
  czyści stan aktywny; forget przy reconnect (`_on_sftp_ready`). N-d (`safe_local_name` w ścieżce
  kopii), N-f (`stop()` przez `_close_quietly`).
- **Etap 67:** `ui/rdp.py` — C2-01 szybka ścieżka sprawdza TrustedPublisher/Root i naprawia
  (`_repair_cert_trust`, najwyżej raz na proces — R1); C2-02 `_valid_drives`; C2-03
  `_valid_thumbprint` przed każdym skryptem; C2-04 licznik `_PENDING_CREDENTIALS`,
  `cleanup_pending_credentials()` przed `os._exit` (main.py), log bez loginu i z rotacją,
  zwolnienie poświadczenia przy błędzie przygotowania pliku (R2). `ui/dialogs.py` — C3-01
  `private_mime_data` (formaty wykluczające z historii Win+V i chmury), `clear_secret_from_
  clipboard()` przy wyjściu; `ui/vpn_panel.py` login i hasło VPN przez `_clipboard_copy`.
  `ui/db_connect.py` — C3-02 filtr `admin_only` w (martwym) `connect_db`, tekst 15 s.
- **Review 3:** **REJECT za S2** (błąd sprzed etapu, ta sama klasa): plik pobierany na karcie A,
  sygnał obserwacji po przełączeniu na B → obserwowany przez B. Naprawa: sygnał niesie klienta
  pobrania; `_watch_file` odkłada wpis do magazynu właściciela, gdy to nie bieżący klient.
  N1: `forget_connection` zeruje też `_sftp` i wyłącza przyciski. Review 4 (ukierunkowany): w toku.
- **L13:** przy `paste-did-not-land` pole jest czyszczone (krok pod strażnikiem) — login nie
  zostaje w polu hasła.
- **C4-06:** granice trybu admina, `.bak`, typ vaulta, schowek — `README_V2.md` §7.
- **Incydent testowy:** nowy test `test_c302` przez złą podmianę (`isfile` zamiast
  `_find_sqldeveloper`) otworzył prawdziwy `QFileDialog` na pulpicie i zawiesił dwa przebiegi
  pytest (mój i agenta); proces zabity, test poprawiony. **Wzmocnienie izolacji:** autouse
  `_no_modal_file_dialogs` w `tests/conftest.py` — `QFileDialog.get*` to pułapka
  (`RealSystemBlocked`); sprawdzone, że taki test pada natychmiast zamiast wisieć.
- **Poza zakresem (backlog):** legacy `vpn_connect.py` (1811/1838/2897) i V2
  `input_system.py:169` wkładają login/hasło do schowka przez win32clipboard bez formatów
  wykluczających z historii — C3-01 zamknięte tylko dla UI; dla V2 do zrobienia w
  `Win32InputSystem.copy_to_clipboard`. Weryfikacja live formatów schowka (Win+V) — PHASE G.
- **Testy:** `tests/test_rdp_clipboard_safety.py` (33), `tests/test_ssh_sftp_safety.py` (52).
  **1585 PASS / 0 FAIL.** Flagi ×3 False; `vpn_connect.py` nietknięty.

---

## 2026-10-14 — Review 4 (ukierunkowany): APPROVE WITH NOTES; S3 domknięte

- S2/N1/R1/R2/L13/conftest-dialogi/C2 zatwierdzone. **S3** (dwie karty na ten sam `ip:port` —
  dwa konta, VIP load balancera, bastion — dzieliły kopię lokalną): tożsamość w ścieżce kopii =
  `connection_token(client)` (WeakKeyDictionary + licznik, nigdy nie wydany dwa razy). R1: zbiór
  „raz na proces” trzyma znormalizowany odcisk.
- Dodatkowo: `Win32InputSystem.copy_to_clipboard` (ścieżka V2) oznacza zapis schowka formatami
  wykluczającymi z historii/chmury i zawsze zamyka schowek (`try/finally`); C5-01 kanał
  single-instance per użytkownik (`HospitalHubV2_SingleInstance_<user>`), `UserAccessOption`,
  sprawdzany wynik `listen()`; README_V2 zaktualizowany.
- Uwagi pozostawione: `on_done`/`on_error` uploadu i `_transfer_done` czytają bieżącą listę po
  zmianie karty (tylko flagi/cache, bez uploadu); okna dialogowe przed przechwyceniem klienta
  w `_open_remote`.
- **Stan: 1595 PASS / 0 FAIL.** Etapy 64, 66, 67 zamknięte.

---

## 2026-10-14 — Etap 68: SSH/SFTP C1-07..12, schowek V2, IPC

- **C1-09** TOFU: host znany pod innym typem klucza = „klucz zmieniony” (bez GUI → odmowa);
  uszkodzony known_hosts odkładany `.corrupt-<ts>`; zapis tmp+replace; weryfikacja pod blokadą.
- **C1-07** anulowanie transferu usuwa fragment tylko, gdy cel wcześniej nie istniał (zdalnie:
  stat, nieznane = istnieje; lokalnie: exists); przy nadpisaniu — ostrzeżenie o możliwym
  częściowym nadpisaniu zamiast kasowania pliku.
- **C1-12** `_probe_writable` bez `open('r+')` (IN_CLOSE_WRITE na katalogach HL7): `stat` +
  `mode_allows_write` z uid/gids z `id -u; id -G` (raz na połączenie).
- **C1-08** zamykanie połączeń SFTP osieroconych (karta zamknięta w trakcie łączenia; reconnect).
- **C1-10** generacja listowania — spóźniony wynik z poprzedniego połączenia ignorowany.
- **C1-11** `open_sftp_bounded` (timeout 20 s na otwarcie i odpowiedzi) dla kanału nawigacji
  i flushu edycji (wątek GUI).
- **C3-01 (V2)** `Win32InputSystem.copy_to_clipboard` z formatami wykluczającymi z historii.
- **C5-01** kanał single-instance per użytkownik + `UserAccessOption` + sprawdzony `listen()`.
- Migawka po etapie: `hh_v2_snapshot_etap68.tgz` (scratchpad sesji).
- **Testy: 1618 PASS / 0 FAIL.** Review: w toku. Równolegle: audyt PHASE D/E (agent, read-only).

- **Review Etapu 68: APPROVE WITH NOTES.** Wdrożone: sprzątanie fragmentu po anulowaniu tylko
  przez połączenie transferu (inaczej ostrzeżenie „usuń ręcznie”); błąd odczytu known_hosts
  (OSError) nie kasuje kluczy — odmowa połączenia; root może pisać plik 0444; zamknięcie klienta,
  gdy kanał SFTP się nie otworzy. Pozostawione: fałszywe „tylko do odczytu” przy ACL; alarm
  „klucz zmieniony”, gdy serwer dostanie nowy typ klucza; brak timeoutu `invoke_subsystem`/
  `exec_command`; auto-upload edycji nieatomowy (put obcina plik — docelowo tmp+rename);
  domena w nazwie kanału IPC. **1622 PASS.**

---

## 2026-10-14 — SSH LOW (C1-14/15) i Etap 69: stabilność (audyt PHASE D/E)

- **C1-14:** transport keyboard-interactive zamykany po błędzie; klucz hosta pod nazwą jak
  paramiko (`[host]:port` dla portu ≠ 22 — jednorazowo ponowne pytanie TOFU dla takich hostów
  na ścieżce kbd). **C1-15:** rozszerzona lista niebezpiecznych rozszerzeń.
  **C1-13 (X11 zawsze włączony): NIE zmieniono** — zmiana zachowania, z którego użytkownicy mogą
  korzystać świadomie (Xming); do decyzji użytkownika.
- **Audyt PHASE D/E** (agent; przerwany limitem API, wznowiony). Wdrożone w Etapie 69:
  - **D-05 (mój błąd z C5-01):** `sys.stderr.write` przy nieudanym `listen()` wywróciłby start
    exe bez konsoli → wpis do crash.log; nazwa kanału = sha256(DOMENA\użytkownik)[:16]
    (bez kolizji diakrytyków/domen).
  - **D-04:** excepthook — okno tylko w wątku GUI, bez ponownego wejścia, max 1/10 s;
    `threading.excepthook` loguje; **E-03** rotacja crash.log.
  - **D-01/D-02:** `ui/thread_retire.py` — działające QThread (waiter 2FA, monitor, status) nie
    są niszczone z oknem (qFatal), `terminate()` usunięte; drugi klik nie tworzy drugiego
    waitera 2FA.
  - **E-01:** przy starcie usuwane `%TEMP%\HospitalHubV2_<pid>` martwych procesów (kopie plików
    z SFTP, potencjalnie HL7).
  - **D-09:** PowerShell certyfikatu RDP raz na proces.
  - **D-07:** status VPN w oknie szpitala w `_VpnStatusProbe` (QThread), pomijany gdy okno
    ukryte; przycisk z bufora kluczowanego profilem.
  - **D-06 (AUDYT P1):** `encrypt` przy zapisie vaulta w QThread, lokalna pętla bez wejścia
    użytkownika, flaga `_saving`.
  - Niepotwierdzone: **D-03** (okna SSH są top-level, `parent=None`, zamykane przy wyjściu).
  - Pozostawione: D-08/D-10 (legacy `vpn_connect`, po cutoverze V2), D-11, D-12, E-02, E-04, E-05.
- **Testy:** `tests/test_app_resilience.py`, `tests/test_detail_panel_vpn_status.py`, dopisane
  w `test_vault_data.py`, `test_rdp_clipboard_safety.py`, `test_ssh_sftp_safety.py`.
  **1656 PASS / 0 FAIL.** Review Etapu 69: w toku.

- **Smoke builda (PHASE H, częściowy):** `PyInstaller` exit 0; `HospitalHubV2.exe` uruchomiony z
  `QT_QPA_PLATFORM=offscreen` i izolowanymi `APPDATA`/`TEMP`/`HOSPITALHUB_DIAG_DIR` (scratchpad)
  przez 12 s: proces żył do końca (exit 124 = zabity przez `timeout`), `crash.log` pusty,
  zapis tylko do izolowanego katalogu, brak procesu po zakończeniu. **Nie sprawdzone:** ekran
  logowania wizualnie, MSAA/UIA w zamrożonym procesie, praca na realnym vaulcie.

---

## 2026-10-14 — Review Etapu 69 i domknięcie dnia

- **Review Etapu 69: APPROVE WITH NOTES.** Wdrożone: N2 (sonda statusu VPN zwalniana po
  zakończeniu — wcześniej ~1800 obiektów QThread/h), N4 (`wait_for_retired(3000)` przed
  `os._exit`), N1 (`_pid_alive` z `use_last_error`), N5 (drugi monitor 2FA w oknie szpitala
  przez `retire_thread`). Pozostawione: N3 (krótko szary/stary kolor przycisku VPN po zmianie
  szpitala; klik VPN nadal woła `get_status` synchronicznie), zapisy crash.log z wielu wątków
  bez synchronizacji, odcisk certyfikatu RDP pamiętany do końca procesu.
- **E-04:** `shorten_path` maskuje folder profilu pod `X:\Users\…` (także 8.3, krótkie loginy)
  i organizację w „OneDrive - …”.
- **Raport gotowości** `RELEASE_READINESS_V2.md` + **niezależna weryfikacja** (agent): werdykt
  „NIE gotowe do wdrożenia” uczciwy; wytknięte braki dokumentacji (nieaktualne liczby, status,
  README IPC, roadmapa G7–G9, exe sprzed ostatnich zmian, brakujące pozycje pozostawione) —
  poprawione w tym wpisie i w dokumentach.
- **Rebuild + smoke na aktualnym kodzie:** build exit 0 (exe 22:03:50), start offscreen 12 s z
  izolowanymi katalogami: żył do końca, brak crash.log, brak procesu po zakończeniu.
- **Testy: 1664 PASS / 0 FAIL**, bez skip/xfail. Flagi ×3 False; `vpn_connect.py` a929035e…;
  V1 bez zmian (najnowszy plik 2026-09-11).

---

## 2026-10-15 — decyzje G1–G9, P0, Etap 70 (SFTP), instalator

- **Decyzje właściciela:** G1 czeka na ręczny pomiar (zero interakcji z naszej strony), G2 tylko
  za osobną zgodą po G1, G5 blokada bez fallbacku, G7 Inno Setup zainstalowany, G9 redesign
  odłożony. **G8 — korekta tego samego dnia:** X11 domyślnie **włączony** (zastępuje pierwotne
  „wyłącz domyślnie”); kod SSH bez zmian, dodane testy regresji. Uwaga: przełącznika X11 per
  połączenie w V2 nie było i nie dodano go (polecenie: żadnych innych zmian w SSH/SFTP).
- **Stan wejściowy:** niezmienniki OK (flagi ×3 False, `vpn_connect.py` a929035e…, spec 4b27eed2…),
  1664 PASS.
- **P0 — migawki:** trzy archiwa (phase0, etap68, 2026-10-14_final) — `gzip -t` OK, listy plików
  bez vaultów/config/logów; `2026-10-14_final` rozpakowana i porównana z drzewem: różnią się tylko
  `EXECUTION_STATUS.md` i `RELEASE_READINESS_V2.md` (edytowane po migawce). Nowa
  `hh_v2_snapshot_2026-10-15_pre.tgz`; `SHA256SUMS` w katalogu migawek (`sha256sum -c` OK).
  Kopia poza dyskiem C: nie zrobiona — wymaga wskazania miejsca przez użytkownika.
- **P0 — Git:** audyt 132 plików kandydujących: brak kluczy, haseł, vaultów, `config.json`, logów;
  trafienia to fikstury testowe (`DRY-RUN-PASSWORD-NOT-REAL`, `szpital-a.pl`, IP z przykładów,
  nagłówek klucza w testach redakcji). Realna nazwa tunelu `1SZP` w testach MSAA — do podmiany,
  gdyby repo miało trafić na zewnątrz. `.gitignore` uzupełniony (`.pytest_cache`, `.vscode`,
  `*.bak`, `*.tmp`, `*.tgz`, `*.zip`, `*.rdp`, `*.pem`, `*.key`, `known_hosts*`, `.env*`,
  `crash*.txt`), `core.autocrlf=false` (repo ma mieszane LF/CRLF). `git init` tylko w
  `hospital_hub_v2`, commit bazowy `2682c72`, bez remote. Repo nadrzędne `C:\claude` i V1 bez zmian.
- **Etap 70 — SFTP, edycja w zewnętrznym edytorze.** Cykl: `_open_remote`/`_open_with` (pobranie)
  → kopia `sftp_temp_path` = katalog panelu / sha1(token połączenia + ścieżka zdalna)[:12] /
  nazwa → `_watch_file` → poll mtime co 2 s → `_upload_changed_file`; flush przy zmianie karty
  i zamknięciu. Zgłoszona kolizja (te same nazwy z różnych serwerów/katalogów) była już usunięta
  w C1-01/02 i S3 (10-14) — **odtworzona testem** na starej ścieżce (sama nazwa: 4 FAIL) i
  wykazana jako niemożliwa na obecnej. Znalezione i naprawione luki w tym samym cyklu:
  - **F1:** „Otwórz za pomocą…” pobierał ponownie *do obserwowanej kopii* — poll mógł wysłać
    na serwer pół pobrania, a anulowanie kasowało kopię edytowaną w edytorze. Teraz pobranie
    idzie do prywatnego `.part`, podmiana `os.replace` dopiero po całości, `_download_active`
    wstrzymuje poll/flush.
  - **F2:** po przełączeniu kart tam i z powrotem mógł ruszyć drugi równoległy upload tego samego
    pliku (`_upload_active.clear()` w `switch_sftp`) — usunięte.
  - **F3:** wpis obserwacji ma niezmienny `owner` (weakref klienta); upload/flush tylko gdy
    `owner is` bieżący klient i `remote` zgodny z wpisem; metadane po uploadzie z własnego kanału
    uploadu, nie z `self._sftp`.
  - **P1 — `upload_edit`:** tryb direct = dotychczasowy `put` + weryfikacja rozmiaru (także we
    flushu). Tryb bezpieczny (flaga `SFTP_SAFE_REPLACE_ENABLED = False` do **G10**): ukryty
    `.nazwa.hhv2-xxxx.part` w tym samym katalogu, `O_EXCL` + 0600 przed danymi, weryfikacja
    rozmiaru, chown/chmod oryginału, symlink → podmiana celu, `posix-rename`; każda porażka =
    `SafeReplaceError` z oryginałem nietkniętym, **bez powrotu do direct**.
- **Review Etapu 70 (niezależny agent), runda 1: APPROVE WITH NOTES.** Wdrożone: M1 (otwarcie
  pliku w trakcie jego uploadu — odmowa), M2 (niewysłane edycje nigdy nie są zastępowane
  pobraniem; zapis w trakcie pobierania zostaje i jest wysyłany), M3 (plik tymczasowy, którego nie
  da się usunąć po zerwaniu, jest nazwany w komunikacie), M4 (brak fałszywego błędu po udanej
  podmianie; utracona odpowiedź na rename = „stan NIEZNANY”), L5 (0600 od pierwszego bajtu),
  L7 (`_invalidate_open_remote_cache` liczy ścieżkę dla połączenia, przez które szedł upload),
  komunikat flushu. L6 → lista G10 w `RELEASE_READINESS_V2.md`; L8 pozostawione (LOW).
  **Runda 2: APPROVE WITH NOTES** — MEDIUM: w `_open_remote` (serwer zmieniony) obserwacja była
  zdejmowana przed pobraniem → zapisy mogły przepaść po cichu; poprawione (obserwacja zostaje,
  `_download_active` ją wstrzymuje). LOW: „NIEZNANY” ginął przy anulowaniu — poprawione.
- **Testy:** nowe `tests/test_sftp_edit_collisions.py` (36: prawdziwy `SftpPanel`, workery
  synchronicznie, serwery in-memory z wstrzykiwaniem awarii; bez sieci) i
  `tests/test_ssh_x11_default.py` (3). Fikstura `fake_panel` w `test_ssh_sftp_safety.py` dostała
  `_download_active`. **Mutacje:** cofnięcie każdej poprawki (F1 ×2, F2, F3, P1-fallback, M1, M2 ×2,
  M4-pop, L5, L7, stara ścieżka kopii ×2) daje FAIL. **1703 PASS / 0 FAIL.**
- **Instalator (G7/G6):** ISCC 6.7.1 jest per-user (`%LOCALAPPDATA%\Programs\Inno Setup 6`) —
  `build_v2.bat` szuka tam też. `HospitalHubV2.iss`: `#ifndef MyAppVersion` (wersja z `/D`),
  `PrivilegesRequiredOverridesAllowed=commandline` (kreator nadal wymaga admina; `/CURRENTUSER`
  tylko z linii poleceń), `VersionInfoVersion`, `CloseApplications=yes`, opis danych poza `{app}`.
  Build exe + instalatora exit 0 (20:05). **Cykl per-user do scratchpadu:** instalacja 2.0.0
  (wpis tylko w HKCU, wydawca „Sebastian Bąk” poprawnie, bez skrótu na pulpicie) → start
  offscreen 12 s z izolowanymi APPDATA/TEMP (żył, brak crash.log) → aktualizacja do 2.0.1
  (ten sam katalog, jeden wpis, jeden deinstalator) → start → deinstalacja (katalog, wpis HKCU
  i menu Start usunięte). `%APPDATA%\HospitalHubV2` i instalacja V1 (`C:\Program Files\HospitalHub`,
  222 pliki) bez zmian. Nie zrobione: instalacja admin do Program Files (UAC — użytkownik).
- Flagi ×3 False, `SFTP_SAFE_REPLACE_ENABLED` False, `vpn_connect.py` a929035e…, V1 bez zmian.

---

## 2026-10-15 — G1: pomiar MSAA listy „VPN Name” (FortiClient 7.4.3, read-only)

Sonda `smoke.forticlient_msaa_live watch --seconds 90`, uruchomiona przez nas, interakcja wyłącznie
użytkownika (zero klawiszy z naszej strony). Katalog: ssl=2, ipsec=1. Dwa przebiegi, identyczne:

```
+ 9.92s  hwnd=0x1205b2 refused=profile-control-missing
+10.24s  hwnd=0x1205b2 state=0x40100400 [COLLAPSED FOCUSABLE]         value='Personal VPNs' + ssl tunnel #2/2
+11.20s  hwnd=0x1205b2 state=0x40100200 [EXPANDED FOCUSABLE]          value='Personal VPNs' + ssl tunnel #2/2
+18.69s  hwnd=0x1205b2 state=0x40100404 [FOCUSED COLLAPSED FOCUSABLE] value='Personal VPNs' + ipsec tunnel #1/1
+20.49s  no verified FortiClient window
(2. przebieg: nowe hwnd 0xf00c4, te same stany i wartości: 49.35 / 49.69 / 50.94 / 56.86 / 59.00 s)
```

Ustalenia:
1. **accValue nie podąża za podświetleniem.** Przez 7,5 s / 6 s otwartej listy (przesuwanie strzałkami)
   ani stan, ani wartość się nie zmieniły — wartość zmienia się dopiero przy zatwierdzeniu.
   Zgodne z założeniem Etapu 63 (potwierdzenie = dwa odczyty po zamknięciu listy).
2. **EXPANDED bez FOCUSED.** Otwarta lista nie ma bitu FOCUSED; `list_open` wymaga tylko EXPANDED — zgodne.
3. **Po zamknięciu: FOCUSED + COLLAPSED**, więc bit FOCUSED jest raportowany. Stan na starcie
   (po otwarciu okna): COLLAPSED **bez** FOCUSED.
4. **Etykieta „Personal VPNs” obejmuje też tunel IPsec** — wartość po zamknięciu to „Personal VPNs”
   + nazwa tunelu z `IPSec\Tunnels`. `GROUP_LABELS = {'Personal VPNs': ssl}` opisuje to błędnie
   (etykieta nie wyznacza rodzaju). Skutek dziś: wybór tunelu IPsec = odmowa (fail-closed, L10).
5. **Po zamknięciu listy wybrany był inny tunel (IPsec) niż przed otwarciem (SSL #2)** — do
   wyjaśnienia z użytkownikiem, czy lista była zamknięta Escape (wtedy Escape ZATWIERDZA
   podświetlenie w tej kontrolce), czy Enter/kliknięciem.
6. ~2 s po zatwierdzeniu „no verified FortiClient window”, drugi przebieg na nowym hwnd — do
   wyjaśnienia (zamknięcie okna przez użytkownika czy reakcja FortiClienta na zmianę profilu).

Niezmierzone (ścieżka klawiszowa V2): FOCUSED po Shift+Tab ×2 z pola Username, otwarcie Spacją,
zatwierdzenie Enterem po wpisaniu nazwy. **Ocena G2: jeszcze nie** — wymaga odpowiedzi na pkt 5–6
i pomiaru G1b (ta sama sonda, użytkownik wykonuje dokładnie sekwencję klawiszy V2).

---

## 2026-10-15 — G10: korekta zakresu i test bezpieczeństwa zapisu SFTP

- **Korekta właściciela:** HospitalHub nie obsługuje przesyłek HL7; nie zakładamy, że pliki SFTP
  odbiera system HL7. G10 = „test bezpieczeństwa i zgodności zapisu SFTP”. Usunięte założenia HL7
  dodane w Etapie 70: komentarze `SFTP_SAFE_REPLACE_ENABLED`, `remote_part_path`,
  `_write_private_temp`, docstring `_probe_writable` (C1-12) w `ui/ssh_panel.py`; dane i ścieżki
  testów (`/data/out/config.xml`, treść XML); dokumenty G10. Wpisy dziennika z 2026-10-14 zostają
  jako historia.
- **Nowy `tests/test_sftp_safe_replace_protocol.py` (15):** prawdziwy serwer SFTP paramiko w procesie,
  `socketpair` (bez sieci), katalog tymczasowy, pliki XML; zerwanie połączenia, błąd zapisu,
  anulowanie, brak/odmowa `posix-rename`, brak prawa tworzenia, `O_EXCL`, plik zniknął, katalog;
  tryb bezpośredni dla porównania (zerwanie ucina oryginał).
- **Znalezisko:** zapis potokowy paramiko (`set_pipelined(True)`, także w `sftp.put`) nie zgłasza
  odrzuconego zapisu w środku pliku, jeśli później serwer przyjął ostatni blok — plik ma poprawny
  rozmiar i dziurę, kontrola rozmiaru tego nie łapie. **Tryb bezpieczny:** zapis bez potokowania
  (każdy blok potwierdzany) — test + mutacja (z potokowaniem: 2 FAIL). **Tryb bezpośredni
  (domyślny):** bez zmian, zachowanie utrwalone testem; decyzja użytkownika.
- `SFTP_SAFE_REPLACE_ENABLED` nadal `False`. Wynik, ograniczenia i rekomendacja:
  `RELEASE_READINESS_V2.md` §G10. **1718 PASS / 0 FAIL.**

---

## 2026-10-16 — zapis SFTP z potwierdzeniem każdego bloku (wszystkie ścieżki)

- Dokończona praca z końca 10-15 (niezacommitowana): tryb bezpośredni `upload_edit` (domyślny)
  pisze przez `_write_acknowledged` — uchwyt bez buforowania i bez potokowania, każdy blok czeka
  na status serwera — zamiast `sftp.put`.
- Nowe: `upload_direct` (zapis w miejscu + kontrola rozmiaru) wspólne dla trybu bezpośredniego
  i zwykłego uploadu `_TransferWorker` (przeciąganie, „Wgraj”), który też używał `sftp.put`.
  W `ui/` nie ma już wywołań `sftp.put`.
- Testy: fake w `test_sftp_edit_collisions.py` odrzuca `put` i potokowanie, model pełnego dysku;
  `test_sftp_safe_replace_protocol.py` (22) — prawdziwy serwer paramiko: odrzucony blok w środku,
  pełny dysk, anulowanie, nowy plik — dla edycji i dla uploadu. Mutacje: potokowanie → 4 FAIL,
  powrót do `put` w uploadzie → 2 FAIL.
- Bez zmian: tryb bezpośredni nadal ucina oryginał przy zerwaniu (ochrona = flaga G10, `False`).
  Niezmienniki: flagi ×3 + `SFTP_SAFE_REPLACE_ENABLED` = False, `vpn_connect.py` a929035e.
  **1730 PASS / 0 FAIL.**

---

## 2026-10-16 — G1: odpowiedzi użytkownika (pkt 5–6)

- Przebieg pomiaru: lista otwarta, podświetlenie przesuwane strzałkami w dół i w górę, **lista
  zamknięta Escape**, potem okno FortiClienta zamknięte ręcznie myszą.
- **Pkt 5 → potwierdzone: Escape w tej kontrolce ZATWIERDZA podświetloną pozycję** (nie anuluje).
  Skutek dla V2: brak zmian w kodzie — `_select_profile` nigdy nie wysyła Escape; nazwa i Enter
  idą tylko przy `EXPANDED`, a wynik potwierdzają dwa odczyty po zamknięciu listy. Jeżeli V2
  odmówi z listą otwartą (np. po Spacji), Escape użytkownika zmieni widoczny profil na
  podświetlony — nic nie zostanie wpisane ani połączone; kolejny start sprawdza profil od nowa.
  `initial()` odmawia, gdy lista jest otwarta (Shift+Tab też mógłby zatwierdzić).
- **Pkt 6 → wyjaśnione:** drugi przebieg na nowym hwnd = ręczne zamknięcie i ponowne otwarcie
  okna przez użytkownika, nie reakcja FortiClienta na zmianę profilu.
- **Pozostaje G1b** (bez zmian w ocenie G2: jeszcze nie). Instrukcja dla użytkownika:
  1. Otwórz FortiClient na formularzu VPN, ustaw profil inny niż docelowy, lista zamknięta.
  2. Uruchom sondę w katalogu V2: `py -3.13 -m smoke.forticlient_msaa_live watch --seconds 90`.
  3. Kliknij w pole Username, potem **Shift+Tab, Shift+Tab** (pauza ~1 s po każdym).
  4. **Spacja** (lista ma się otworzyć), wpisz nazwę profilu docelowego, **Enter**.
  5. Odczekaj 5 s, zatrzymaj sondę (Ctrl+C), nie zamykaj okna przed końcem zapisu.
  Do zmierzenia: FOCUSED po drugim Shift+Tab, EXPANDED po Spacji, wartość po Enterze = profil
  docelowy, stan końcowy COLLAPSED.

---

## 2026-10-16 — Etap 71: UX polish, drobne defekty, redesign

- **71A audyt:** czterech niezależnych audytorów (terminal/tmux, wizualny, ergonomia, scenariusze
  codzienne), offscreen z prawdziwymi fontami (harness: Segoe UI 9 pt, oba motywy, skale
  1.0–2.0) i serwerem SSH/SFTP paramiko w procesie (socketpair, bez sieci). 89 znalezisk →
  `UX_AUDIT_V2.md` (statusy, commity). Migawka przed etapem: `hh_v2_snapshot_2026-10-16_pre_ux.tgz`.
- **P0 (bezpieczeństwo, utrata danych, crash):** S-01 zerwane łącze SSH = „exit” (paramiko
  `exit_status_ready()`/`status_event` prawdziwe dla każdego zamkniętego kanału) — auto-reconnect
  nigdy nie działał, a zapisy z edytora ginęły; S-02 zamknięcie okna SSH w trakcie transferu
  zabijało cały proces (0xC0000374); S-03 okna SSH ignorowały blokadę admina i przeżywały
  zamknięcie vaulta; T-18/E-05 wklejanie wielu linii (także do wszystkich sesji multi-exec) bez
  potwierdzenia; E-07 usuwanie z domyślnym „Tak”; **X-01** (znalezione przy naprawie): kolejka
  SFTP po przełączeniu karty wysyłała resztę plików na INNY serwer.
- **Terminal** (`64a327a`): parser i ekran pod tmux/vim/less (SU/SD, alt-screen, BCE, ACS, REP,
  DA/CPR, prefiksy `>`/`=`, SGR z dwukropkiem), worker (dekoder przyrostowy, bez kolorowania w
  aplikacjach pełnoekranowych, Ctrl+C), klawisze xterm, mysz, kursor, atrybuty, rozmiar PTY (V-01).
- **Pakiety 71B:** SFTP (kolejka, nazwy spoza UTF-8, komunikaty), okno główne (wyszukiwanie po
  IP/maszynie/bazie, duplikat szpitala, elipsy), dialogi (polskie znaki, tłumaczenia Qt, porty,
  pytanie o porzucenie zmian), okno SSH (klik zaznacza, klawisze, tytuły, szerokość panelu).
- **71C redesign** (`REDESIGN_V2.md`): R1 jedna paleta formularzy (`ui/style.py`), R2 tabele
  (zwarte akcje, dopasowanie kolumn, menu wszystkich kont, „Połącz jako”), R3 stany puste,
  R4 ikony w jasnym motywie. Decyzje strukturalne (jedno okno SSH na szpital, profil VPN w
  szpitalu, model edycji, aktywna sesja multi-exec) — u właściciela.
- **Weryfikacja:** każda poprawka z testem regresji; mutacje (cofnięcie poprawki → FAIL) dla
  S-01, S-02, S-03, E-07, terminala (3), kolejki SFTP, okna głównego; zrzuty przed/po.
  **1863 PASS / 0 FAIL.** Build exe + instalator po przeglądzie. Smoke startu exe NIE wykonany: działała
  zainstalowana przez użytkownika instancja (Program Files, od 11:04) i mechanizm pojedynczej
  instancji przekazał aktywację — do powtórzenia przy zamkniętej aplikacji.
- **Przegląd kodu** (niezależny recenzent): REQUEST CHANGES — R-01 (wysoka: wyszukiwanie ujawniało
  maszyny/bazy admin-only przy zablokowanym adminie), R-02 (dwa menu przy prawym kliku) i 9
  mniejszych; wszystkie poprawione (`1cfd4ad`, `tests/test_review_71.py`, bez poprawek 11/12 FAIL).
  Przy okazji: wyjątek w konstruktorze widżetu w testach kończył proces pytest po cichu (kod 127,
  hak wyjątków aplikacji) — objaw „zawieszonego” zestawu; przyczyna była w łatce, nie w testach.
- Niezmienniki: flagi ×3 + `SFTP_SAFE_REPLACE_ENABLED` = False, `vpn_connect.py` a929035e,
  `HospitalHubV2.spec` bez zmian, V1 nietknięte.

---

## 2026-10-16 (wieczór) — trzy prośby właściciela po instalacji Etapu 71

- **Jedno okno SSH na szpital** (decyzja 1 z `REDESIGN_V2.md` §5, teraz zlecona): ⇆ i „Połącz
  jako” w tabeli maszyn dodają kartę do otwartego okna SSH tego samego szpitala (ostatnio
  aktywnego; przywracane z minimalizacji). Inny szpital — osobne okno. `SshDialog.window_for`,
  `SshDialog.open_machine`, `DetailPanel._open_ssh`.
- **Kafelki akcji nierówne:** przycisk loginu miał `setMaximumWidth(90)`, więc „root”, „—” i
  „administra…” dawały różne szerokości i przesuwały ⇆/⚙/− w każdym wierszu. Teraz stała
  szerokość (`_LOGIN_BTN_W`), maszyny i bazy. Zrzut przed/po (oba motywy) potwierdza.
- **Log VPN działań i błędów** (`diagnostics/actionlog.py`): przełącznik w ⚙ Ustawienia VPN →
  Diagnostyka (per komputer, `config.vpn_log_enabled`, domyślnie WYŁ.), plik
  `%APPDATA%\HospitalHubV2\diagnostics\logs\vpn.log` (rotacja 1 MB × 4). Zapisuje kliknięcia
  Połącz/Rozłącz i ich wynik (komunikat klienta), zmiany statusu, 2FA, otwarcie klienta,
  zakończone ślady diagnostyczne (kroki z kodami błędów) i nieobsłużone wyjątki aplikacji.
  Bez haseł i loginów (rejestr sekretów → `***`, redaktor, końcowy skan — wpis wyglądający na
  sekret jest pomijany); serwery maskowane, nazwa profilu i provider czytelne. Przyciski „Otwórz
  folder logów” i „Zapisz paczkę diagnostyczną (ZIP)…” (istniejący, bramkowany eksport +
  `vpn_log.txt`). Legacy `vpn_connect.py` nietknięty.
- Mutacje: cofnięcie poprawek okna SSH i szerokości → 2 FAIL. **1877 PASS / 0 FAIL.** Build exe +
  instalator 17:10. Smoke startu exe nie wykonany — działa zainstalowana kopia użytkownika.
