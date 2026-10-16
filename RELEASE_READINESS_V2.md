# HospitalHub V2 — raport gotowości (PHASE I)

> Stan na 2026-10-15 (aktualizacja po Etapie 70 i decyzjach G1–G9). Rozróżnia trzy poziomy: **kod gotowy** (zaimplementowany, testy fake
> zielone, review), **zweryfikowany live** (zmierzony na prawdziwym Windows/kliencie),
> **gotowy do wdrożenia** (oba poprzednie + build/instalator + procedura wycofania).
> Szczegóły: `EXECUTION_LOG.md`, `EXECUTION_STATUS.md`, `TEST_MATRIX_V2.md`, `ROADMAP_V2.md`.

## Werdykt

**V2 NIE jest gotowe do wdrożenia.** Etap 71 (UX, 2026-10-16): 89 znalezisk audytu — 81
naprawionych i zweryfikowanych (test regresji, mutacja lub zrzut), reszta jawnie opisana w
`UX_AUDIT_V2.md`; 1863 PASS; wymaga ręcznej weryfikacji na prawdziwym ekranie i serwerze (tmux,
reconnect, DPI) — lista w `TEST_MATRIX_V2.md`. Zmiany etapów 63–70 są zaimplementowane, pokryte testami
fake (1718 PASS, bez skip/xfail) i każda przeszła niezależny przegląd (APPROVE WITH NOTES, po
dwóch REJECT poprawionych). Żadna z nich nie była sprawdzona na żywym systemie poza smoke startem
exe i instalatora. Kluczowe ścieżki VPN V2 nie mają weryfikacji live (G1/G2). Instalator buduje
się i przechodzi cykl instalacja/aktualizacja/deinstalacja w trybie per-user; instalacja admin
(UAC) czeka na użytkownika. Na poziomie kodu i testów usunięto wszystkie znalezione luki HIGH/CRITICAL w
obszarach, których dotyczyły etapy; czy to przekłada się na zachowanie w terenie — do
potwierdzenia scenariuszami ręcznymi z `TEST_MATRIX_V2.md`.

## Stan obszarów

| Obszar | Kod | Live | Uwagi |
|---|---|---|---|
| Vault (zapis, typ, hasło, `.bak`, config) | gotowy (Etap 65) | nie | regresje C4-01..05/07 naprawione z testami |
| SSH/SFTP | gotowy (Etapy 66, 68, 70) | nie | C1-01..12, C1-14/15/17 naprawione; Etap 70: kolizje edycji zewnętrznej (F1–F3, M1, M2, L7) naprawione; bezpieczny zapis gotowy za flagą (G10); X11 domyślnie włączony (G8, testy regresji); C1-16, C1-18, C1-19 LOW otwarte |
| RDP | gotowy (Etap 67) | nie | zasada „zawsze podpisany .rdp” zachowana |
| Schowek | gotowy (Etap 67/68) | nie | Win+V do sprawdzenia ręcznie; legacy `vpn_connect.py` nadal kopiuje bez wykluczenia |
| Stabilność (wątki, wyjątki, zapis poza GUI, status VPN poza GUI) | gotowy (Etap 69) | smoke startu exe | D-08/D-10 (legacy VPN w wątku GUI) — po cutoverze V2 |
| IPC single-instance | gotowy | nie | jednorazowo stara i nowa wersja nie widzą się przy aktualizacji |
| Diagnostyka | gotowy | nie | eksport nie jest podpięty do UI |
| VPN legacy (`vpn_connect.py`) | produkcja, nietknięty | tak (historycznie) | — |
| VPN V2 FortiClient | gotowy (Etapy 63–64) | **nie** — bramki G1, G2 | flaga `False`; profil przez MSAA niezmierzony w stanach otwartej listy |
| VPN V2 Stormshield | contract | **nie** — G3 | flow staje przed autofillem |
| VPN V2 Barracuda | contract + autofill UIA (Etap 50C) | **nie** — G4 | — |
| EMS / CLI 2FA (FortiClient płatny) | contract-only | nie (brak maszyny) | `cli-monitor-not-owned-by-panel` — blokada dla szpitali z EMS |
| UI/UX redesign (PHASE F) | **nie rozpoczęty** | — | wymaga decyzji produktowych (patrz niżej) |
| Build PyInstaller | gotowy (exe 2026-10-15 20:05, po wszystkich zmianach) | smoke startu z instalacji (offscreen, 12 s, izolowane katalogi) | MSAA/UIA w zamrożonym procesie niezweryfikowane |
| Instalator Inno Setup | gotowy (`dist_installer\HospitalHub-Setup-2.0.0.exe`, ISCC 6.7.1) | per-user: instalacja, start, aktualizacja 2.0.0→2.0.1, deinstalacja PASS 2026-10-15 | instalacja admin (UAC) — G6 u użytkownika |

## Bramki wymagające użytkownika

| Bramka | Co | Działanie |
|---|---|---|
| G1 | pomiar stanów MSAA listy „VPN Name” | otworzyć FortiClient, uruchomić `py -3.13 -m smoke.forticlient_msaa_live watch --seconds 90`, otworzyć listę, przesunąć podświetlenie (bez Enter), Escape; wkleić wynik |
| G2 | live connect FortiClient V2 | po analizie G1 — **osobna, wyraźna zgoda**; flaga na czas próby, restart aplikacji po cofnięciu |
| G3/G4 | live connect Stormshield / Barracuda V2 | po akceptacji G2 |
| G5 | pusty `profile_name` w V2 | **rozstrzygnięte:** blokada zostaje, bez fallbacku do bieżącego profilu |
| G6 | instalacja/odinstalowanie na maszynie | per-user zrobione; instalacja admin (UAC) — ręcznie |
| G7 | Inno Setup | **rozstrzygnięte:** zainstalowany, skrypt zweryfikowany |
| G8 | X11 | **rozstrzygnięte:** domyślnie włączony, bez zmian w kodzie, testy regresji |
| G9 | redesign UI | **rozstrzygnięte:** odłożony do końca stabilizacji |
| G10 | włączenie bezpiecznej podmiany SFTP | test bezpieczeństwa i zgodności zapisu wykonany — decyzja o fladze, niżej |

## Ryzyka wdrożenia

1. Cutover FortiClient bez G1 = każdy wybór profilu kończy się blokadą (bezpiecznie, ale
   bezużytecznie).
2. Szpitale z FortiClient EMS: trasa CLI bez monitora 2FA w panelu.
3. Zmiana nazwy kanału IPC: przy aktualizacji jednorazowo mogą działać dwie instancje.
4. Nowe zachowania widoczne dla użytkownika: odmowa otwarcia vaulta złego typu, odmowa
   nadpisania istniejącego pliku przy tworzeniu, blokada edycji listy VPN w trakcie łączenia,
   ostrzeżenie TOFU przy zmianie typu klucza hosta, okno „tylko do odczytu” przy plikach z ACL.

5. **Auto-upload edycji SFTP domyślnie nadal nie jest atomowy:** `put` najpierw obcina plik na
   serwerze — przy zerwaniu połączenia plik może zostać ucięty (test protokołowy to pokazuje).
   Bezpieczna podmiana jest zaimplementowana i przetestowana (fake + prawdziwy protokół SFTP),
   ale wyłączona do decyzji G10, bo podmieniony plik jest nowym plikiem (właściciel, tryb, ACL —
   niżej).
6. IPsec w FortiClient V2 zawsze BLOCKED (L10); zawieszony FortiClient = „Trwa inne łączenie”
   dla wszystkich kart do restartu (N2).
7. V2 ma lokalne repo Git (bez remote) + migawki `.tgz` z `SHA256SUMS`; brak kopii poza tym dyskiem.
8. **Etap 71 (2026-10-16) zmienia zachowania widoczne dla użytkownika** (wszystkie świadome,
   z rejestru `UX_AUDIT_V2.md`): Esc nie zamyka okna SSH; zamknięcie okna z transferem lub ≥ 2
   sesjami pyta; zerwane łącze SSH łączy się ponownie zamiast zamykać kartę; wklejenie wielu
   linii bez bracketed paste lub do wielu sesji (multi-exec) pyta; klik w karcie Środowiska
   zaznacza (łączy dwuklik/Enter); potwierdzenia usunięcia mają domyślnie „Nie/Anuluj”; prawy
   klik w terminalu, gdy aplikacja (tmux `mouse on`) prosi o mysz, idzie do aplikacji (wklejenie:
   Shift+prawy klik lub Ctrl+Shift+V); tabele chowają mniej ważne kolumny na wąskim ekranie.
9. Terminal: parser pyte uzupełniony o własną kopię FSM (`_TermStream`) — przy aktualizacji pyte
   sprawdzić zgodność (`test_terminal_emulation.py`).

## Pozostawione znaleziska (świadomie, z przeglądów i audytów)

| ID | Opis | Waga |
|---|---|---|
| Etap 68/70 | auto-upload edycji SFTP nieatomowy, dopóki G10 nie włączy bezpiecznej podmiany | MEDIUM |
| Etap 70 L8 | pobranie zakończone po zamknięciu karty odkłada obserwację martwego połączenia — zapisy tej kopii cicho ignorowane (nic nie idzie w złe miejsce) | LOW |
| Etap 68 | fałszywe „tylko do odczytu” przy ACL dających więcej niż bity trybu | LOW |
| Etap 68 | alarm „klucz zmieniony”, gdy serwer doda nowy typ klucza hosta | LOW |
| Etap 68 | brak timeoutu `invoke_subsystem` / `exec_command` (paramiko) | LOW |
| Review 4 | dialogi przed przechwyceniem klienta w `_open_remote` (`on_done`/`on_error` uploadu i `_transfer_done` — naprawione w Etapie 70) | LOW |
| C1-13 | X11 forwarding zawsze żądany; brak przełącznika per połączenie (nie istniał w V2) | decyzja G8: tak ma być |
| C1-16 | multiexec: hasło z promptu trafia do innych sesji; wklejanie wielolinijkowe bez potwierdzenia | LOW |
| C1-18, C1-19 | ścieżka SFTP do złej sesji po zamknięciu karty; rekurencja przy bardzo głębokim usuwaniu | LOW |
| L9 | MSAA pod `AttachThreadInput` niezmierzone (część G1) | — |
| L10 | IPsec zawsze BLOCKED (etykiety grup niezmierzone) | ograniczenie |
| L11 | trasa CLI (EMS) bez monitora 2FA w panelu | blokada dla EMS |
| L12 | CLI uruchamia `FortiVPN.exe` z katalogu `app_path` bez kotwicy zaufania (jak legacy) | LOW |
| N2 (64) | zawieszony FortiClient blokuje wszystkie karty (BUSY) do restartu | LOW |
| N3 (63) | Enter zatwierdzający wymaga EXPANDED, nie FOCUSED — świadomie | — |
| N6, N7 (63) | dwa testy do zaostrzenia; kosmetyka trace | LOW |
| 65/3, 65/5 | `.bak` może być starszy, gdy kopia się nie uda; `normcase` nie obejmuje 8.3/linków | LOW |
| D-03 | niepotwierdzone (okna SSH są top-level) | — |
| D-08, D-10 | legacy VPN connect/status w wątku GUI, `tasklist`/`netstat` co cykl — po cutoverze V2 | MEDIUM |
| D-11, D-12 | status VPN po indeksie karty; globalne profile VPN w `detail_panel` | LOW |
| N3 (69) | klik VPN w oknie szpitala nadal woła `get_status` synchronicznie; chwilowo szary przycisk po zmianie szpitala | LOW |
| E-02 | pliki `.rdp` po `os._exit`; kopia `rdpsign.exe` w katalogu użytkownika | LOW |
| E-05 | `tmp*.tmp` vaulta na OneDrive po crashu; brak „brak klienta” na przycisku VPN | LOW |
| C4-06 | tryb admina chroni tylko w UI (opisane w `README_V2.md` §7) | ograniczenie |
| C6 | brak walidacji IP/portu bazy w dialogach | LOW |
| H1 | `numpy` w exe (przez `pyautogui`), exe 145 MB | LOW |
| legacy | `vpn_connect.py` kopiuje hasło do schowka bez wykluczenia z historii Win+V | MEDIUM (legacy nietykalny) |

## G10 — test bezpieczeństwa i zgodności zapisu SFTP (2026-10-15)

**Mechanizm** (`upload_edit`, `SFTP_SAFE_REPLACE_ENABLED = True`): ukryty plik
`.nazwa.hhv2-xxxx.part` w tym samym katalogu, tworzony z `O_EXCL` i od razu 0600 → zapis z
potwierdzeniem każdego bloku → kontrola rozmiaru → właściciel i tryb oryginału → `posix-rename`.
Każda porażka = `SafeReplaceError`, oryginał nietknięty, **bez powrotu do zapisu bezpośredniego**.
Flaga **pozostaje `False`** (nie włączana automatycznie).

**Jak testowano** — bez prawdziwych serwerów i danych produkcyjnych, zwykłe pliki XML:
- `tests/test_sftp_safe_replace_protocol.py` (15): prawdziwy serwer SFTP paramiko w procesie
  testu, połączenie przez `socketpair` (bez sieci), katalog tymczasowy jako dysk, wstrzykiwane
  awarie. Sprawdza realne komunikaty protokołu (`open` CREATE|EXCL, `fsetstat`,
  `posix-rename@openssh.com`, kody statusu).
- `tests/test_sftp_edit_collisions.py` (36): serwer in-memory z modelem POSIX (właściciel,
  grupy, tryb, symlink) i pełny cykl panelu.

**Wyniki**

| Wymaganie | Wynik |
|---|---|
| Przerwanie transferu (zerwane połączenie, anulowanie, błąd zapisu serwera) nie uszkadza oryginału | **PASS** — oryginał bajt w bajt; po zerwaniu fragment `.part` zostaje (kanał martwy) i jest nazwany w komunikacie, przy żywym łączu jest usuwany |
| Nieudana podmiana nie powoduje utraty danych | **PASS** — brak `posix-rename` / odmowa rename / brak prawa tworzenia w katalogu / plik zniknął / katalog zamiast pliku: błąd, oryginał nietknięty i nigdy nie otwierany do zapisu |
| Istniejący plik zastępowany poprawnie | **PASS** — pełna treść, rozmiar, postęp; symlink zachowany, podmieniany cel (fake); utracona odpowiedź na rename = komunikat „stan NIEZNANY” |
| Błędy serwera bez niebezpiecznego fallbacku | **PASS** — żadna ścieżka nie wraca do `put` w oryginał (test + mutacja) |
| Zajęta nazwa pliku tymczasowego | **PASS** — `O_EXCL`: cudzy plik nie jest nadpisywany |
| Właściciel, uprawnienia, ACL | udokumentowane niżej; właściciel/tryb przetestowane na modelu POSIX, nie na prawdziwym POSIX |

**Znalezisko w trakcie testu (naprawione w trybie bezpiecznym):** przy zapisie potokowym paramiko
sprawdza odpowiedzi serwera tylko co ~100 żądań — zapis odrzucony w środku (np. pełny dysk,
quota), po którym serwer przyjął ostatni blok, dawał plik o **poprawnym rozmiarze z dziurą** i bez
błędu. Bezpieczny zapis pisze teraz bez potokowania (każdy blok czeka na potwierdzenie; wolniej
na łączach o dużym opóźnieniu, bez znaczenia dla edytowanych plików konfiguracyjnych).
**2026-10-16: naprawione też poza trybem bezpiecznym.** Ten sam mechanizm miał domyślny tryb
bezpośredni edycji i zwykły upload (przeciąganie, „Wgraj”) — oba szły przez `sftp.put` paramiko.
Teraz oba używają `upload_direct`: zapis w miejscu, każdy blok potwierdzany, kontrola rozmiaru;
`sftp.put` nie jest już używany do zapisu (fake w testach rzuca przy próbie). Odrzucony blok
i pełny dysk dają błąd od razu. Test `test_paramiko_put_hides_a_refused_write_behind_the_right_size`
utrwala wadę samej biblioteki (gdy aktualizacja paramiko ją naprawi, test padnie i można go
usunąć). Mutacja (potokowanie / powrót do `put`): 4 i 2 FAIL. **Tryb bezpośredni nadal nie chroni
oryginału** przed zerwaniem w trakcie — to robi wyłącznie bezpieczna podmiana (flaga G10).

**Właściciel, uprawnienia, ACL (ograniczenia — rename tworzy nowy plik):**
- Właściciel: zachowany tylko, gdy serwer pozwala (`chown` na siebie i własną grupę albo root);
  inaczej podmiana **odmawia** — pliku innego użytkownika nie da się zapisać w tym trybie.
- Tryb (bity rwx, setgid itp.): kopiowany z oryginału i weryfikowany po ustawieniu.
- POSIX ACL, xattr, etykiety SELinux, hardlinki: SFTP v3 ich nie widzi ani nie przenosi — po
  podmianie ich **nie będzie**; z klienta nie da się tego wykryć.
- Plik w katalogu bez prawa zapisu (sam plik zapisywalny): podmiana odmawia, tryb bezpośredni działał.
- Serwer bez `posix-rename@openssh.com` (nie-OpenSSH): odmowa z czytelnym błędem.
- Procesy obserwujące katalog na serwerze widzą utworzenie i przeniesienie pliku zamiast zapisu
  w miejscu; przez chwilę w katalogu jest ukryty plik `.part`.

**Czego testy nie pokrywają:** prawdziwy serwer POSIX (OpenSSH na Linuksie) — semantyka
właściciela/trybu/ACL na żywym systemie plików; inne implementacje serwera SFTP.

**Rekomendacja:** tryb bezpieczny jest gotowy i spełnia wymagania bezpieczeństwa zapisu. Przed
włączeniem: jeden kontrolowany test na nieprodukcyjnym serwerze OpenSSH/Linux z plikiem testowym
(w tym plik z ACL i plik innego właściciela) — sprawdzić komunikaty odmowy i zachowanie trybu.
Potem włączyć flagę globalnie (błędy są jawne, oryginał zawsze cały); wyjątek per połączenie tylko,
gdyby odmowy okazały się częste. Niezależnie rozważyć zapis bez potokowania także w trybie
bezpośrednim (znalezisko wyżej).

## Procedura wycofania

- Kod: lokalne repo Git V2 (`git log`; `2682c72` = stan sprzed 2026-10-15) oraz migawki w
  `C:\claude\hospital_hub_v2_snapshots\` (phase0, etap68, 2026-10-14_final, 2026-10-15_pre;
  integralność: `sha256sum -c SHA256SUMS`).
- SFTP: `SFTP_SAFE_REPLACE_ENABLED = False` = zapis jak przed Etapem 70.
- VPN: każda flaga `CONNECT_ENABLED` z powrotem na `False` + restart aplikacji = powrót na legacy.
- Dane: format vaulta niezmieniony; `.vault.bak` (jedna generacja) obok vaulta.
- V1 (`C:\claude\hospital_hub`) nietknięta — pozostaje działającą alternatywą.
