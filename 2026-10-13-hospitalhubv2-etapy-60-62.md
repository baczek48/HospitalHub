# HospitalHub V2 — migracja VPN, etapy 60–62 (2026-10-13)

Stan wyjściowy: Etap 59 (2026-09-17) — pierwszy ręczny live connect V2 = **NOT READY**
(wybór profilu nie działa na FortiClient 7.4.3; puste login/hasło były czyszczone
zamiast pomijane). Flagi cofnięte na `False`.

Stan końcowy: **1367 PASS / 0 FAIL / 0 ERROR**, `CONNECT_ENABLED` = `False` ×3
(FortiClient, Stormshield, Barracuda), `vpn_connect.py` nietknięty
(sha256 `a929035e5b62fb98…`), `HospitalHubV2.spec` bez zmian, zero live connect.

---

## Etap 60 — wybór profilu z weryfikacją + puste pola (1300 PASS)

**Wybór profilu** (`vpn/providers/forticlient_autofill.py::_select_profile`):
1. Shift+Tab ×2 od pola Username (jak w Etapie 44).
2. Odczyt kontrolki z fokusem — musi to być ComboBox procesu zweryfikowanego okna;
   inaczej STOP bez Space/Enter.
3. Combo już pokazuje profil → zero klawiszy.
4. Inaczej sekwencja legacy: Space → nazwa → Enter; Enter tylko gdy fokus to
   combo/ListItem/List tego samego PID.
5. Ponowny odczyt: wartość (po strip) musi być **dokładnie** nazwą profilu.
6. Porażka → `BLOCKED` w fazie `profile`, zero loginu/hasła/wklejenia/Entera,
   schowek przywrócony. Kody: `profile-not-confirmed`, `profile-control-not-combo`,
   `profile-control-foreign-process`, `profile-control-unreadable`.

Nowy seam: `InputSystem.focused_control()` → `FocusedControl` (UIA
`GetFocusedElement`; wartość czytana tylko dla ComboBox; bazowa wersja = „nieznane”).

**Puste pola:** `_fill_field` przy pustej wartości wraca przed Ctrl+A/Delete — pole
nietknięte, jak w legacy (`if login:` / `if password:`).

**CONNECT_PARITY** (`vpn/providers/forticlient_connect.py`):
`gui-autofill-empty-field` (same), `gui-profile-select` (security).

**Testy:** `FakeInput` modeluje combo; helpery `submit_enters` /
`profile_commit_enters` odróżniają Enter profilu od Entera łączącego; 27 nowych
testów w `tests/test_vpn_forticlient_profile.py`. Kontrola odwrotna (3 celowe
mutacje weryfikacji) — testy padały za każdym razem.

Zmienione: `vpn/providers/input_system.py`, `vpn/providers/forticlient_autofill.py`,
`vpn/providers/forticlient_connect.py`, `tests/test_vpn_forticlient_autofill.py`,
`tests/test_vpn_forticlient_profile.py`, `tests/test_vpn_v2_cancel_and_polling.py`.

---

## Etap 61 — sonda read-only na żywym oknie (bez zmian w kodzie)

Okno zweryfikowane (`first_verified_candidate`, bez fokusu): `forticlient.exe`,
klasa `Chrome_WidgetWin_1`. Zero klawiszy, kliknięć, zmian fokusu i schowka.

- **UI Automation nie widzi formularza** Electron: 16 elementów (ramka okna:
  Pane/MenuItem/3×Button), brak podokna renderera (tylko `Intermediate D3D Window`
  procesu GPU), `GetFocusedElement` → obcy proces. Bez zmian po 8 s i po zapytaniu MSAA.
  → `focused_control()` z Etapu 60 na 7.4.3 **zawsze** da `profile-control-unreadable`
  (bezpiecznie, ale bezużytecznie).
- **MSAA widzi formularz** (`AccessibleObjectFromWindow(hwnd, OBJID_CLIENT)`):
  `ROLE_SYSTEM_COMBOBOX`, nazwa `VPN Name`, stan collapsed+focusable, 0 dzieci gdy
  zwinięte, akcja domyślna „otwórz”; pola TEXT `Username` / `Password` (wartości
  nieczytane).
- `accValue` = **etykieta grupy + nazwa**: `"Personal VPNs <nazwa tunelu>"`.
- Tunele w rejestrze (tylko nazwy kluczy): `HKLM\SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels`
  (2) i `...\IPSec\Tunnels` (1).

---

## Etap 62 — warstwa MSAA profilu, read-only, niepodpięta (1367 PASS)

**Nowe moduły:**
- `vpn/providers/msaa_system.py` — `MsaaSystem.combo_boxes(hwnd)` → `MsaaScan` z
  `MsaaNode` (rola, nazwa, `accState`, `accValue`, okno z
  `WindowFromAccessibleObject`). `accValue` tylko dla roli combo. Żadnych akcji.
  `comtypes`/`ctypes` ładowane leniwie.
- `vpn/providers/forticlient_profile.py`:
  - `read_profile_control(target, msaa, hwnd=None)` — okno z
    `first_verified_candidate` lub `verify_owner`; dokładnie jedno combo `VPN Name`
    (0 → `profile-control-missing`, >1 → `profile-control-ambiguous`); okno obiektu
    == zweryfikowany HWND (`profile-control-foreign-window`); ponowny `verify_owner`
    po skanie == ten sam PID (`profile-control-foreign-process`); nieczytelne
    `accState`/`accValue` → blokada.
  - `configured_tunnels(env)` — nazwy kluczy tuneli SSL/IPsec przez istniejące
    `DetectionEnvironment.registry_subkeys` (wartości nigdy nie czytane).
  - `match_profile(displayed, requested, catalog)` — `GROUP_LABELS =
    {"Personal VPNs": ssl}` (tylko zmierzone); `"<etykieta> <nazwa>"`, nazwa ==
    tunel danego rodzaju == żądany profil; bez prefiksu, case-folding i strip.
    Odrzuca: nieznane etykiety (EMS, IPsec, tłumaczenia), niejednoznaczne etykiety,
    pustą nazwę/żądanie, brak katalogu, tunel IPsec pod etykietą SSL, nazwę w SSL i
    IPsec jednocześnie.
  - `verify_displayed_profile(...)` — odczyt + dopasowanie.

**Testy:** `tests/test_vpn_forticlient_msaa_profile.py` (67) — odczyt, brak/duplikat,
obce okno/PID (także podmiana w trakcie skanu), nieczytelne stan/wartość, etykiety,
dokładne dopasowanie, katalog z rejestru, brak akcji (AST), realny seam pod guardem
conftest zwraca `ok=False`. `tests/test_vpn_forticlient_launch.py`: `msaa_system.py`
dopisany do allowlisty modułów z `ctypes`.

`vpn/providers/input_system.py`: docstring `focused_control()` — nie jest źródłem
prawdy o profilu na 7.4.3.

**Live read-only:** `ok=True`, combo zwinięte i bez fokusu; dopasowanie trafiło
dokładnie w jeden (aktualnie wybrany) tunel SSL, pozostałe → `profile-mismatch`.

---

## Otwarte / następny krok (Etap 63 — decyzja usera)

- `_select_profile` (Etap 60) nadal używa UIA `focused_control()` → na 7.4.3 każdy
  autofill z ustawionym profilem blokuje się. Do zrobienia: bezpieczna interakcja z
  combo oparta o MSAA (`accState` focused przed Space, `accValue` + `match_profile`
  po Enterze).
- Etykiety grup dla IPsec i profili EMS niezmierzone → obecnie fail-closed.
- `comtypes` nie jest w `HospitalHubV2.spec` — bez tego zbudowany exe blokuje się
  fail-closed przy każdym profilu.
- Trasa CLI (edycja EMS/płatna) nadal wymaga podpięcia monitora 2FA do panelu
  przed cutoverem.
- Ponowny ręczny live connect dopiero po Etapie 63; po cofnięciu flagi restart
  aplikacji (flaga trzymana w pamięci).

Skrypty sond (jednorazowe, poza projektem): scratchpad sesji, `probe61*.py`,
`probe62.py`.
