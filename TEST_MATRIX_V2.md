# HospitalHub V2 — macierz testów

> PHASE G dyrektywy wykonawczej. Stan: 2026-10-14, **1664 testy, wszystkie fake/in-process, bez skip/xfail**
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

## Procedura przed wydaniem

1. Pełny suite zielony; `CONNECT_ENABLED` ×3 = False w źródle.
2. Build (`build_v2.bat`), smoke startu exe (offscreen, izolowane APPDATA/TEMP).
3. Bramki live G1–G4 w kolejności, każda z udziałem użytkownika; po każdej — analiza i poprawki.
4. Ręczne scenariusze z tabeli wyżej, wynik w `EXECUTION_LOG.md`.
