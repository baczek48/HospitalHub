# smoke/ — obserwacje na żywym Windows (Etapy 17–24)

Te skrypty **nie są testami jednostkowymi** i celowo leżą poza `tests/`:
`py -3.13 -m pytest tests/ -q` ich nie zbiera i nigdy nie powinien. Patrzą na
maszynę, na której są uruchomione, a dwa z nich ją ruszają.

Powstały po to, żeby odpowiedzieć na jedyne pytanie, na które atrapy odpowiedzieć
nie mogą: **czy prawdziwy FortiClient ma kształt, który założyliśmy w Etapach
12–16?** Od Etapu 24 dochodzi drugie narzędzie, `smoke/activation_live.py`, z
tym samym pytaniem postawionym bramce aktywacji.

## Polecenia

| polecenie | co robi | rusza pulpit? |
|---|---|---|
| `inspect` | detekcja, zaufane katalogi, obrazy procesów, wyszukanie i weryfikacja okien, fałszywe trafienia, porównanie z legacy | nie |
| `controls` | enumeracja kontrolek zweryfikowanego okna + `controls_belong_to` | nie |
| `cli-probe` | `FortiVPN.exe --cli --status` — zapytanie o stan, **zero poświadczeń** | uruchamia proces |
| `focus` | przejęcie focusu → potwierdzenie → rewalidacja → zwolnienie, **bez jednego klawisza** | tak |
| `autofill-dry` | prawdziwy autofill z Etapu 14 na prawdziwym oknie, z **zablokowanym szewem wysyłającym**; `--steal-focus-at N` odbiera oknu foreground w trakcie | tak |
| `tab-order` | dokąd naprawdę trafia Tab — **odczyt** pól (Ctrl+A, Ctrl+C), zero wpisywania, **nigdy Enter** | tak |
| `focus-diagnose` | dlaczego Windows odmawia foreground; próbuje po kolei SetForegroundWindow / AttachThreadInput / BringWindowToTop / ShowWindowAsync / AllowSetForegroundWindow / SetFocus, mierzy bezczynność użytkownika i blokadę foreground; `--minimize-first` = scenariusz B | tak (aktywacje okien, **zero klawiszy**) |
| `focus-sample` | JEDEN pomiar **produkcyjnego** `acquire_focus` z pełnym `FocusResult.diagnostics`; `--wait-active` / `--wait-idle` czekają na właściwy stan wejścia i dopiero wtedy strzelają | tak (aktywacja okna, **zero klawiszy**) |

```
py -3.13 -m smoke.forticlient_live inspect
py -3.13 -m smoke.forticlient_live controls
py -3.13 -m smoke.forticlient_live cli-probe    --i-am-at-the-keyboard
py -3.13 -m smoke.forticlient_live focus        --i-am-at-the-keyboard
py -3.13 -m smoke.forticlient_live autofill-dry --i-am-at-the-keyboard
py -3.13 -m smoke.forticlient_live tab-order    --i-am-at-the-keyboard
py -3.13 -m smoke.forticlient_live focus-diagnose --i-am-at-the-keyboard
py -3.13 -m smoke.forticlient_live focus-diagnose --i-am-at-the-keyboard --minimize-first
```

Flaga `--i-am-at-the-keyboard` nie jest ozdobą: trzy ostatnie polecenia albo
uruchamiają proces, albo zabierają focus temu, co akurat robisz.

## Czego te skrypty NIE robią

Żadnego hasła, żadnego tokenu, żadnego zapisu do schowka, żadnego klawisza,
żadnego `WM_SETTEXT`, żadnego `BM_CLICK`, żadnego połączenia VPN.
`autofill-dry` niesie jawne atrapy (`DRY-RUN-…-NOT-REAL`) i podstawia
`InputSystem`, który **rejestruje zamiast wysyłać** — w rejestrze zapisuje
wyłącznie *długości*, nigdy treść.

`CONNECT_ENABLED` pozostaje `False`, UI pozostaje na `vpn_connect.py`.

## Obserwacje z 2026-09-13 (ta maszyna)

FortiClient **7.x free / VPN-only**, `C:\Program Files\Fortinet\FortiClient`,
Windows 11.

| obszar | wynik |
|---|---|
| detekcja | `installed`, `edition=free`, exe z rejestru — identycznie jak legacy |
| zaufane katalogi | identyczne w legacy i w nowym providerze; wykryty exe leży wewnątrz |
| `QueryFullProcessImageNameW` | działa dla procesów w sesji użytkownika (`FortiClient.exe`, `FortiTray.exe`); **odmawia** dla usług SYSTEM w sesji 0 (`FortiVPN.exe`, `FortiSSLVPNdaemon.exe`) — `ACCESS_DENIED`, czyli fail-closed |
| wyszukanie okna | 1 kandydat spośród 40 okien Fortinetu; ten sam HWND co legacy |
| weryfikacja właściciela | `verified`, pid 1012, `forticlient.exe` w zaufanym katalogu |
| fałszywe trafienia | 0 |
| focus | przejęty, potwierdzony, zrewalidowany, zwolniony — bez klawiszy |
| struktura GUI | okno główne to **Electron** (`Chrome_WidgetWin_1`): **0 kontrolek Edit/Button**, dwoje dzieci (`Chrome_RenderWidgetHostHWND`, `Intermediate D3D Window` — to drugie należy do **innego** procesu FortiClienta) |
| autofill dry-run | cała sekwencja Etapu 14 doszła do `status=done`; 0 realnych zapisów do schowka, 0 wysłanych klawiszy, 0 wycieków |
| sonda CLI | `rc=1`, 0.20 s, `error parsing options: Option 'cli' does not exist` — **oba** markery z `CLI_UNSUPPORTED_MARKERS` obecne; nowa logika i legacy zgodnie mówią `cli_supported=False` |
| okno EMS | **nie istnieje** na tej maszynie (wersja free nie ma EMS) — żadnego okna WinForms ani „Authentication" |

Czego ta maszyna **nie jest w stanie** zweryfikować: okna EMS, ścieżki CLI
connect i 2FA (wersja free ich nie ma).

## Obserwacje z 2026-09-14 (Etap 18)

| obszar | wynik |
|---|---|
| kontrolki okna Electron | `partition_controls` na żywym oknie: `usable=[Chrome_RenderWidgetHostHWND]`, `foreign=[Intermediate D3D Window]` (inny PID FortiClienta), **okno nadal zweryfikowane** — dokładnie to, co przewidziała atrapa |
| kolejność Tab | Tab ×3 → **pole tekstowe**, Tab ×4 → **pole odmawiające kopiowania** (sygnatura pola hasła). Zgadza się z założeniem autofillu (3 Tab → username, 4. Tab → password). Zmierzone **bez profilu**; z nazwą profilu sekwencja wstawia Spację/tekst/Enter i nie była sprawdzana |
| autofill dry-run | `status=done`, 0 realnych zapisów do schowka, 0 wysłanych klawiszy, 0 wycieków |
| blokada foreground | gdy foreground trzyma inne okno (pasek zadań), `SetForegroundWindow` konsekwentnie zwraca 0 → `set-foreground-failed` → `NO_FOCUS` i **zero wpisywania**. Żaden wariant `AttachThreadInput` (do wątku celu ani do wątku foreground) tego nie zdejmuje. Dotyczy tak samo legacy — wspólny `acquire_focus` |
| okno zminimalizowane | `confirm_target` odmawia (`foreground-is-other-window`) — zmierzone w 4 punktach czasu. Migawka tuż po `ShowWindow` potrafi jeszcze pokazywać stary foreground: to wyścig systemu, nie luka |
| `--steal-focus-at` | na tej maszynie **nierozstrzygające**: proces nie ma konsoli (`GetConsoleWindow()==0`), a minimalizacja okna nie przenosi foreground, dopóki trzymamy `AttachThreadInput`. Utrata focusu w trakcie sekwencji jest pokryta testami jednostkowymi |

### Bezpieczeństwo odczytu w `tab-order`

Narzędzie nigdy nie pokazuje treści pola ani jego **długości** — tylko jedną z
trzech kategorii: `NIC` (pole hasła / element nietekstowy), `zaznaczenie CAŁEJ
STRONY` (w tym miejscu nie ma pola tekstowego) albo `POLE TEKSTOWE, niepuste`.
Schowek użytkownika jest zapamiętywany i przywracany.


## Obserwacje z 2026-09-14 (Etap 19 — diagnostyka foreground)

`SPI_GETFOREGROUNDLOCKTIMEOUT = 2147483647 ms` — blokada foreground jest na tej
maszynie praktycznie **wieczna**, więc warunek „blokada wygasła" nie zajdzie
nigdy.

Pomiary przy **bezczynnym pulpicie** (186–234 s od ostatniego prawdziwego
wejścia użytkownika):

| scenariusz | foreground w chwili pomiaru | `SetForegroundWindow` bez attach |
|---|---|---|
| A — klient świeżo uruchomiony | okno klienta | **1 (sukces)** — cel już był foreground |
| B — klient zminimalizowany | okno klienta (mimo `iconic=1`) | **1 (sukces)** |
| C — zwykłe okno z przodu (Notatnik) | `Notepad` | **1 (sukces)** |
| D — pasek zadań z przodu | `Shell_TrayWnd` (explorer) | **1 (sukces)** |

Porównaj z Etapem 18, gdzie **użytkownik aktywnie pracował** i to samo
wywołanie było odrzucane konsekwentnie (`set-foreground-failed`), także po
`AttachThreadInput` do wątku celu **i** do wątku foreground.

**Zmienna rozstrzygająca to bezczynność użytkownika, nie rodzaj okna z przodu.**
Dlatego `focus-diagnose` drukuje czas od ostatniego wejścia i ostrzega, gdy
pulpit jest bezczynny: pomiar wykonany wtedy jest ŁATWIEJSZY niż rzeczywistość
i nie wolno go brać za dowód, że mechanizm zadziała u pracującego użytkownika.

Uboczne obserwacje:

* `AllowSetForegroundWindow(ASFW_ANY)` wołane przez nasz proces zwraca
  `last_error=5` (ACCESS_DENIED) — nie daje nic; kolejny sukces pochodził z
  ogólnej permisywności bezczynnego pulpitu.
* `SetFocus` po `AttachThreadInput` ustawia fokus klawiatury w połączonej
  kolejce, ale **nie zmienia okna foreground** — a `SendInput` idzie do okna
  foreground. To pułapka: guard by przeszedł, a znaki poszłyby gdzie indziej.
* Okno **zminimalizowane potrafi pozostać** `GetForegroundWindow()`, dopóki
  żadne inne okno nie przejmie foreground (zmierzone w scenariuszu B). W
  Etapie 18, gdy foreground przejęło okno Chrome, `confirm_target` poprawnie
  odmówił. Warto rozważyć dodanie `IsIconic` do warunku — **nie zmieniane w
  tym etapie**.
* Okno docelowe i reszta okien klienta leżą na dwóch wątkach procesu
  (`tid=18240` — okno główne, `tid=23172` — pozostałe); wątek okna docelowego
  jest stabilny między uruchomieniami.


## Obserwacje z 2026-09-14 (Etap 20 — pomiar A/B)

**Hipoteza z Etapu 19 (»decyduje bezczynność użytkownika«) została OBALONA.**

Dziewięć próbek tym samym mechanizmem (`SecureWindowTarget.acquire_any(diagnose=True)`):

| próbka | okno z przodu | idle | `set_foreground_ok` |
|---|---|---|---|
| B — klient z przodu | **sam cel** | 35,2 s | ✅ (trywialnie) |
| B — Notatnik | **sam cel** | 58,0 s | ✅ (trywialnie) |
| B — pasek zadań | **sam cel** | 80,6 s | ✅ (trywialnie) |
| Etap 19 / C | Notepad — *przed chwilą uruchomiony przez nasze narzędzie* | ~185 s | ✅ |
| Etap 19 / D | pasek zadań — *przed chwilą aktywowany przez nasze narzędzie* | ~190 s | ✅ |
| **A** | chrome.exe | **0,2 s** | ❌ |
| **A2** | chrome.exe | **0,2 s** | ❌ |
| **B2** | Code.exe | **35,2 s** | ❌ |
| **B3** | Code.exe | **150,2 s** | ❌ |
| Etap 18 | pasek zadań (aktywny użytkownik) | — | ❌ |

Bezczynność **nie różnicuje** wyniku: przy obcym oknie z przodu odmowa jest taka
sama przy 0,2 s i przy 150,2 s. Różnicuje **kto trzyma foreground**:

* cel już jest oknem foreground → sukces trywialny,
* foreground trzyma **inny proces** → odmowa,
* wyjątki z Etapu 19 to chwile, w których nasze własne narzędzie przed sekundami
  uruchomiło proces albo samo ustawiło foreground.

Reszta pomiarów:

* `set_foreground_error` = **0** w każdej odmowie — powtarzalne; `SetForegroundWindow`
  zwraca FALSE bez ustawiania błędu, czyli odmowa polityki, nie błąd wywołania.
* `attach_ok` = **True** w każdej odmowie, a próba bez `AttachThreadInput` w tej
  samej chwili zwraca **0** tak samo → attach **nie zmienia niczego**.
* `foreground_before == foreground_after` w każdej odmowie, próba trwa 1–2 ms →
  **żadnego wyścigu**.
* Typ okna z przodu nie ma znaczenia: Chrome, Code.exe i pasek zadań są po stronie
  odmów, Notepad i pasek zadań po stronie sukcesów.


## smoke/activation_live.py — bramka aktywacji (Etap 24)

| polecenie | co robi | rusza pulpit? |
|---|---|---|
| `probe` | znajduje i weryfikuje okno, jeden `foreground_check`, partycja dzieci okna Electron, stabilność tożsamości | nie |
| `launch` | uruchamia GUI klienta zmigrowaną zdolnością LAUNCH | uruchamia proces |
| `wait` | prawdziwe oczekiwanie bramki; `--minimise-first` (A), `--restore-after N` (B), `--flap N --flap-hold S` (E), `--ui` pokazuje baner Etapu 23 | tak |
| `zero-wait` | klient już z przodu — mierzy, że nie ma żadnego oczekiwania (C) | tak |
| `race` | bramka mówi TAK, cel przestaje być użytecznym foregroundem, dopiero wtedy autofill dry-run (D) | tak |
| `cancel` | prawdziwy baner, prawdziwy przycisk Anuluj; `--after N` klika za operatora (F) | tak |

```
py -3.13 -m smoke.activation_live probe
py -3.13 -m smoke.activation_live launch    --i-am-at-the-keyboard
py -3.13 -m smoke.activation_live wait      --i-am-at-the-keyboard --minimise-first --timeout 8
py -3.13 -m smoke.activation_live wait      --i-am-at-the-keyboard --minimise-first --restore-after 3
py -3.13 -m smoke.activation_live zero-wait --i-am-at-the-keyboard
py -3.13 -m smoke.activation_live race      --i-am-at-the-keyboard
py -3.13 -m smoke.activation_live cancel    --i-am-at-the-keyboard --minimise-first --after 3
```

Żadnego prawdziwego loginu, hasła, tokenu, Entera ani połączenia. `race` używa
rejestratora z `forticlient_live` (zapisuje *długości*, nigdy treść) i tych
samych jawnych atrap. Drukowane są wyłącznie: nazwy stanów, liczniki, kody
powodów, uchwyt okna, pid i nazwa pliku wykonywalnego — **nigdy tytuł okna**.

## Obserwacje z 2026-09-14 (Etap 24 — bramka aktywacji na żywym kliencie)

FortiClient 7.x free, okno `0x205fe`, pid 9408, `forticlient.exe`.

| scenariusz | wynik | liczby |
|---|---|---|
| **9 — Electron/D3D** | `usable=[Chrome_RenderWidgetHostHWND]`, `foreign=[Intermediate D3D Window]`, okno **nadal zweryfikowane**; `foreground_check` pracuje wyłącznie na HWND okna głównego | 2 dzieci, 0 kontrolek Edit/Button; tożsamość stabilna w 3 odczytach |
| **A — klient nie z przodu** | `AWAITING_ACTIVATION` → `ACTIVATION_TIMEOUT`, `reason=target-minimised`; bramka **niczego nie aktywowała** | polls=17, fg_checks=17, waited_s=8.01, repins=0 |
| **B — użytkownik wraca** | `ACTIVATION_OBSERVED` w pierwszym odczycie po powrocie okna | polls=7, waited_s=3.01, repins=0 |
| **C — klient już z przodu** | `ACTIVATION_OBSERVED` bez oczekiwania | polls=1, fg_checks=1, waited_s=**0,000274 s**, ściana zegara 0,000 s |
| **D — utrata foregroundu po sukcesie** | wariant *minimalizacja*: 14 symulowanych wysyłek, **0** w chwili, gdy cel nie był użytecznym foregroundem; `acquire_focus` realnie odzyskał okno | patrz zastrzeżenie niżej |
| **E — okno miga w trakcie** | powrót na **0,05 s został PRZEGAPIONY** — bramka nie ogłosiła sukcesu „z pamięci"; sukces dopiero przy odczycie trafiającym w realną aktywność | polls=8, waited_s=3.51 |
| **F — anulowanie** | `CANCELLED`, zdanie „Anulowano — nic nie zostało wpisane.", przycisk znika, `InputSystem` nietknięty | polls=6, waited_s=3.01 |

### Weto `iconic` z Etapu 22 — pierwszy pomiar na żywo

Okno zminimalizowane **pozostaje** `GetForegroundWindow()` na tym pulpicie
(przewidziane w Etapie 19), a `foreground_check` odmawia z
`reason=target-minimised`, `foreground=True`, `iconic=True`. Weto działa na
prawdziwym kliencie, nie tylko na atrapie.

### Czego ta maszyna NIE potrafi zweryfikować

**Scenariusz D w wariancie „obce okno naprawdę trzyma foreground" jest
programowo niewywoływalny.** Zmierzone: uruchomienie Notatnika otwiera okna
(`0x1067a`, `0x20610`), ale FortiClient **zachowuje foreground** przez całe 10 s
obserwacji. To ta sama ściana, o którą rozbił się `--steal-focus-at` w Etapie
18. Wariant z minimalizacją jest słabszy, bo `acquire_focus` przywraca własne
zminimalizowane okno (`SW_RESTORE`) i legalnie je odzyskuje — więc guard **nie**
odmawia i nie zobaczymy `NO_FOCUS`. Mierzalne pozostaje to, co najważniejsze:
**żadna wysyłka nie nastąpiła, gdy cel nie był widocznym oknem z przodu.**
Pełne `NO_FOCUS` przy obcym oknie pozostaje pokryte testami jednostkowymi i
pomiarami Etapu 18/20.

### Usterka znaleziona przez ten etap

`ActivationWorker.state_changed` emitował stan końcowy **dwa razy** (raz z
obserwatora bramki przy `_finish`, raz z wyniku rozpakowanego przez workera).
Nieszkodliwe na ekranie — renderowanie jest idempotentne — ale sygnał o nazwie
„zmiana stanu" nie powinien strzelać bez zmiany. Poprawione w
`ui/activation_prompt.py` (powtórki są pomijane) i przykryte testem
`test_14b`.
