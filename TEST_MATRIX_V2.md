# HospitalHub V2 — macierz testów

> PHASE G dyrektywy wykonawczej. Stan: 2026-10-15, **1718 testów, wszystkie fake/in-process, bez skip/xfail**
> (`py -3.13 -m pytest tests -q -p no:cacheprovider`, ~16–30 s).
>
> **Zasada:** test na fake'ach dowodzi logiki i kontraktów, **nie** działania na żywym systemie.
> Kolumna „live” mówi, co zostało zmierzone na prawdziwym Windows/kliencie i kiedy.

## Izolacja (dotyczy wszystkich testów)

`tests/conftest.py`: pułapki na procesy, pywin32, ctypes user32/shell32/advapi32 (Cred*),
comtypes, `QFileDialog.get*` (2026-10-14); `CONNECT_ENABLED` wymuszone `False` per test;
`APPDATA` per test w katalogu tymczasowym. `tests/test_vpn_test_isolation.py` pilnuje samej
izolacji. Każde trafienie w prawdziwy system = test FAIL (lub sesja FAIL, gdy poza testem).

## Obszary

| Obszar | Pliki testów | Typ | Live (stan) |
|---|---|---|---|
| Vault: crypto, modele, zapis atomowy, `.bak`, typ, config, zamykanie, IPC | `test_vault_data.py` | unit, regression, contract | nie |
| Odporność aplikacji: excepthook, crash.log, wątki przy zamykaniu, sprzątanie %TEMP% | `test_app_resilience.py` | unit, concurrency (prawdziwe QThread) | smoke startu exe (offscreen) 2026-10-14 |
| Okno szpitala — status VPN poza wątkiem GUI | `test_detail_panel_vpn_status.py` | unit, concurrency | nie |
| SSH/SFTP: kopie lokalne, nazwy plików, TOFU, anulowanie, listowanie, timeouty, zamykanie | `test_ssh_sftp_safety.py`, `test_sftp_logic.py` | unit, regression, security | nie |
| SFTP — edycja w zewnętrznym edytorze: pliki o tej samej nazwie (serwery, katalogi, okna, karty), wiązanie z połączeniem, ponowne pobranie, niewysłane edycje, anulowanie, zerwanie transferu, bezpieczna podmiana (tmp + posix-rename, właściciel, symlink, brak rozszerzenia) | `test_sftp_edit_collisions.py` (36; prawdziwy `SftpPanel`, workery synchronicznie, serwery in-memory) | regression, security | nie — test zapisu SFTP G10 w wierszu niżej |
| SFTP — bezpieczny zapis na prawdziwym protokole (G10): zastąpienie pliku, zerwanie połączenia, anulowanie, błąd zapisu serwera (też „dziura” przy poprawnym rozmiarze), brak/odmowa posix-rename, brak prawa tworzenia, `O_EXCL`, tryb bezpośredni dla porównania | `test_sftp_safe_replace_protocol.py` (15; serwer paramiko w procesie przez `socketpair`, pliki XML w katalogu tymczasowym) | integration, regression | nie (żywy serwer POSIX — nie) |
| SSH — X11 domyślnie włączony (G8): żądanie przed PTY, odmowa serwera, brak lokalnego X | `test_ssh_x11_default.py` | regression | nie |
| **Etap 71 (UX):** terminal vs tmux/vim/less — SU/SD, alt-screen, BCE, ACS, REP, odpowiedzi DA/CPR, klawisze xterm, bracketed paste i potwierdzenie wklejania, mysz, UTF-8 na granicy odczytu, kolorowanie | `test_terminal_emulation.py` (40) | regression, security | nie (prawdziwy tmux — ręcznie) |
| **Etap 71:** cykl sesji SSH — zerwanie łącza → auto-reconnect, `exit` ≠ zerwanie; zamykanie okna w trakcie transferu/listowania, Esc, blokada admina i zamknięcie vaulta | `test_ssh_session_lifecycle.py`, `test_ssh_window_close.py` (serwer SSH/SFTP paramiko w procesie, `tests/ssh_fake_server.py`) | integration, regression | nie |
| **Etap 71:** SFTP — kolejka z właścicielem połączenia, dopisywanie, jedno podsumowanie przy zerwaniu, nazwy spoza UTF-8, zmiana nazwy z „/”, klawisze tabeli, tytuł okna, szerokość panelu | `test_sftp_queue_and_listing.py`, `test_ux_ssh_window.py` | integration, regression | nie |
| **Etap 71:** okno główne i dialogi — wyszukiwanie po IP/maszynie/bazie, duplikat szpitala, potwierdzenia „Nie” domyślnie, odmiana, elipsy, porty, pytanie o porzucenie zmian, tłumaczenia Qt, styl formularzy, tabele (dopasowanie kolumn, menu kont), stany puste, VPN dodaj/wróć | `test_ux_main_window.py`, `test_ux_dialogs.py`, `test_ux_confirm_plural.py`, `test_ux_tables.py` | regression | zrzuty offscreen (oba motywy, 1.0–2.0) |
| Instalator: instalacja, start, aktualizacja, deinstalacja, izolacja danych | ręcznie, per-user do scratch (`/CURRENTUSER /VERYSILENT /DIR=`) | e2e | **tak, 2026-10-15** (admin/UAC — nie) |
| RDP i schowek | `test_rdp_clipboard_safety.py` | unit, security | nie (Win+V do weryfikacji) |
| Diagnostyka i redakcja | `test_diagnostics.py`, `test_vpn_trace.py` | unit, security | nie |
| VPN — architektura providerów, routing, flagi | `test_vpn_provider_arch.py`, `test_vpn_v2_routing_gate.py`, `test_vpn_v2_provider_resolution.py`, `test_vpn_shadow_detection.py` | contract | — |
| VPN — FortiClient: detekcja, launch | `test_vpn_forticlient_detect.py`, `_launch.py`, `_launch_fixes.py` | contract | Etapy 17, 57, 59 |
| VPN — bezpieczny cel, bramka aktywacji, focus | `test_vpn_secure_target.py`, `test_vpn_activation_*.py`, `test_vpn_require_visible.py`, `test_vpn_minimised_race.py`, `test_vpn_raise_window.py`, `test_vpn_focus_diagnostics.py`, `test_vpn_control_validation.py` | security, concurrency | Etapy 18–25, 51 |
| VPN — FortiClient autofill, profil (MSAA), puste pola | `test_vpn_forticlient_autofill.py`, `_profile.py`, `_msaa_profile.py`, `_msaa_select.py`, `_caret_probe.py`, `test_forticlient_secure_input.py` | security, regression | odczyt MSAA combo (zamknięte) Etapy 61–62; **stany FOCUSED/EXPANDED — bramka G1** |
| VPN — 2FA, EMS, CLI | `test_vpn_forticlient_2fa.py`, `_auth_window.py`, `test_vpn_v2_twofactor_monitor.py` | contract | EMS/CLI contract-only (brak maszyny) |
| VPN — connect złożony, sesja panelu, anulowanie | `test_vpn_forticlient_connect_*.py`, `test_vpn_panel_v2_bridge.py`, `test_vpn_connect_card_wiring.py`, `test_vpn_v2_session_*.py`, `test_vpn_v2_cancel_and_polling.py` | integration (fake) | live E2E z wstrzymanym Enterem — Etap 51; **live connect — bramka G2** |
| VPN — Stormshield, Barracuda | `test_vpn_stormshield*.py`, `test_vpn_barracuda*.py` | contract | Barracuda UIA autofill — Etap 50C; Stormshield — Etapy 37–41; **live connect — G3/G4** |

## Czego testy nie pokrywają (wymaga live lub ręcznego sprawdzenia)

| Scenariusz | Dlaczego nie fake | Bramka |
|---|---|---|
| Stany MSAA combo „VPN Name” po Space/Enter na 7.4.3 | zachowanie Electron/Chromium | G1 |
| FortiClient V2: profil → login → hasło → Enter → realny tunel → stan UI | realne połączenie | G2 |
| Stormshield / Barracuda V2 connect | realne połączenie | G3/G4 |
| MSAA i UIA w zamrożonym exe (comtypes.gen w buildzie) | proces PyInstaller | smoke z FortiClientem |
| Formaty schowka (brak wpisu w historii Win+V) | zachowanie Windows | ręcznie |
| RDP na maszynie z GPO delegacji, naprawa zaufania certyfikatu | polityki Windows | ręcznie |
| SSH/SFTP na realnym serwerze: edycja zdalna, anulowanie uploadu, reconnect | sieć | ręcznie |
| Instalator: instalacja obok V1, aktualizacja, odinstalowanie | brak Inno Setup + zmiana systemu | G6/G7 |
| Wydajność: zapis vaulta bez zamrożenia, 8 sesji SSH × godzina | pomiar na maszynie | ręcznie |
| **2026-10-16:** jedno okno SSH na szpital (karta zamiast nowego okna), wyrównane przyciski akcji niezależnie od loginu | `test_ssh_one_window.py` | regression | zrzut offscreen przed/po |
| **2026-10-16:** log VPN działań i błędów (opcja w ⚙ Ustawienia VPN): domyślnie wyłączony, bez haseł/loginów, maskowanie serwerów, rotacja 1 MB × 4, ślady i wyjątki w logu, paczka ZIP | `test_vpn_actionlog.py` | regression, security | nie |
| **2026-10-16:** auto-reconnect SSH: maks. 3 próby, potem karta R (nowa runda, przewijanie zachowane) / Esc; próby w jednej linii, po powrocie „Przerwa w połączeniu od–do”; karta i linie dopasowane do szerokości, wiersze szukane po treści (odporność na zmianę rozmiaru) | `test_ssh_reconnect_limit.py` (fałszywy serwer SSH w procesie) | regression | zrzuty offscreen 3 stanów |
| **2026-10-16:** okno SSH zmaksymalizowane → zminimalizowane → przywrócone: geometria Qt = rzeczywisty obszar klienta | `test_ssh_window_restore.py` + pomiar na pulpicie (Win32) | regression | zmierzone na prawdziwym oknie |
| **2026-10-16:** polskie sortowanie (szpitale, profile VPN, SFTP — „ś” po „s”, bez `setlocale`); ikony wektorowe zamiast emoji (ostre przy 1.0–3.0), brak emoji w UI; błysk „skopiowano” widoczny w jasnym motywie; plakietka bez „ducha” | `test_icons_and_sorting.py` | regression | zrzuty offscreen oba motywy, 1.0 i 1.5 |
| **Etap 71:** tmux 3.2+ na prawdziwym serwerze (panele, `seq 1 500`, pasek statusu, `mouse on`, detach/attach), vim/htop/mc/less; Alt+litera, Shift+Tab, AltGr (ą, ę, @) na polskiej klawiaturze | prawdziwy serwer, klawiatura Windows | ręcznie |
| **Etap 71:** zerwanie VPN/sieci w trakcie sesji SSH → auto-reconnect, edycja pliku w edytorze przez zerwanie | sieć | ręcznie |
| **Etap 71:** wygląd na prawdziwym ekranie: 1366×768 przy 125/150 %, 4K przy 200 %, emoji/ikony Win10 vs Win11, „!” w banerze terminala | ekran, DirectWrite | ręcznie |
| **Etap 71:** wylogowanie Windows z niezapisanymi zmianami w vaulcie (S-13) | sesja Windows | ręcznie |
| **Etap 71:** smoke startu zbudowanego exe — gdy żadna inna instancja HospitalHub V2 nie działa (mechanizm pojedynczej instancji) | proces | ręcznie / automatycznie przy zamkniętej aplikacji |

## Procedura przed wydaniem

1. Pełny suite zielony; `CONNECT_ENABLED` ×3 = False w źródle.
2. Build (`build_v2.bat`), smoke startu exe (offscreen, izolowane APPDATA/TEMP).
3. Bramki live G1–G4 w kolejności, każda z udziałem użytkownika; po każdej — analiza i poprawki.
4. Ręczne scenariusze z tabeli wyżej, wynik w `EXECUTION_LOG.md`.
