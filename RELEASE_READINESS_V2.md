# HospitalHub V2 — raport gotowości (PHASE I)

> Stan na 2026-10-14. Rozróżnia trzy poziomy: **kod gotowy** (zaimplementowany, testy fake
> zielone, review), **zweryfikowany live** (zmierzony na prawdziwym Windows/kliencie),
> **gotowy do wdrożenia** (oba poprzednie + build/instalator + procedura wycofania).
> Szczegóły: `EXECUTION_LOG.md`, `EXECUTION_STATUS.md`, `TEST_MATRIX_V2.md`, `ROADMAP_V2.md`.

## Werdykt

**V2 NIE jest gotowe do wdrożenia.** Zmiany etapów 63–69 są zaimplementowane, pokryte testami
fake (1664 PASS, bez skip/xfail) i każda przeszła niezależny przegląd (APPROVE WITH NOTES, po
dwóch REJECT poprawionych). Żadna z nich nie była sprawdzona na żywym systemie poza smoke startem
exe. Kluczowe ścieżki VPN V2 nie mają weryfikacji live, a instalatora nie da się zbudować na tej
maszynie. Na poziomie kodu i testów usunięto wszystkie znalezione luki HIGH/CRITICAL w
obszarach, których dotyczyły etapy; czy to przekłada się na zachowanie w terenie — do
potwierdzenia scenariuszami ręcznymi z `TEST_MATRIX_V2.md`.

## Stan obszarów

| Obszar | Kod | Live | Uwagi |
|---|---|---|---|
| Vault (zapis, typ, hasło, `.bak`, config) | gotowy (Etap 65) | nie | regresje C4-01..05/07 naprawione z testami |
| SSH/SFTP | gotowy (Etapy 66, 68) | nie | C1-01..12, C1-14/15/17 naprawione; C1-13 (X11) — decyzja użytkownika; C1-16, C1-18, C1-19 LOW otwarte |
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
| Build PyInstaller | gotowy (exe 2026-10-14 22:03, po wszystkich zmianach) | smoke startu (offscreen, 12 s, izolowane katalogi) | MSAA/UIA w zamrożonym procesie niezweryfikowane |
| Instalator Inno Setup | `HospitalHubV2.iss` istnieje | **nie** — brak ISCC na maszynie | G7 |

## Bramki wymagające użytkownika

| Bramka | Co | Działanie |
|---|---|---|
| G1 | pomiar stanów MSAA listy „VPN Name” | otworzyć FortiClient, uruchomić `py -3.13 -m smoke.forticlient_msaa_live watch --seconds 90`, otworzyć listę, przesunąć podświetlenie (bez Enter), Escape; wkleić wynik |
| G2 | live connect FortiClient V2 | po G1 i G5; flaga na czas próby, restart aplikacji po cofnięciu |
| G3/G4 | live connect Stormshield / Barracuda V2 | po akceptacji G2 |
| G5 | pusty `profile_name` w V2 | dziś BLOCKED (chyba że jeden tunel i on wyświetlony) — rekomendacja: zostawić |
| G6 | instalacja/odinstalowanie na maszynie | po G7 |
| G7 | zainstalowanie Inno Setup 6 (ISCC) | decyzja o instalacji narzędzia |
| G8 | X11 forwarding domyślnie wyłączony? (C1-13) | decyzja produktowa |
| G9 | redesign UI (PHASE F): zakres i kierunek | `AUDYT_V2.md` §4 to koncepcja — potrzebna akceptacja zakresu |

## Ryzyka wdrożenia

1. Cutover FortiClient bez G1 = każdy wybór profilu kończy się blokadą (bezpiecznie, ale
   bezużytecznie).
2. Szpitale z FortiClient EMS: trasa CLI bez monitora 2FA w panelu.
3. Zmiana nazwy kanału IPC: przy aktualizacji jednorazowo mogą działać dwie instancje.
4. Nowe zachowania widoczne dla użytkownika: odmowa otwarcia vaulta złego typu, odmowa
   nadpisania istniejącego pliku przy tworzeniu, blokada edycji listy VPN w trakcie łączenia,
   ostrzeżenie TOFU przy zmianie typu klucza hosta, okno „tylko do odczytu” przy plikach z ACL.

5. **Auto-upload edycji SFTP nie jest atomowy:** `put` najpierw obcina plik na serwerze — przy
   zerwaniu połączenia lub anulowaniu plik na serwerze (np. katalog wymiany HL7) może być ucięty,
   a watcher po stronie serwera może przetworzyć niepełny plik. Najważniejsza z otwartych luk.
6. IPsec w FortiClient V2 zawsze BLOCKED (L10); zawieszony FortiClient = „Trwa inne łączenie”
   dla wszystkich kart do restartu (N2).
7. V2 poza Git — punkty odtworzenia tylko jako migawki `.tgz` w `C:\claude\hospital_hub_v2_snapshots\`.

## Pozostawione znaleziska (świadomie, z przeglądów i audytów)

| ID | Opis | Waga |
|---|---|---|
| Etap 68 | auto-upload edycji SFTP nieatomowy (put obcina plik) | MEDIUM |
| Etap 68 | fałszywe „tylko do odczytu” przy ACL dających więcej niż bity trybu | LOW |
| Etap 68 | alarm „klucz zmieniony”, gdy serwer doda nowy typ klucza hosta | LOW |
| Etap 68 | brak timeoutu `invoke_subsystem` / `exec_command` (paramiko) | LOW |
| Review 4 | `on_done`/`on_error` uploadu i `_transfer_done` czytają listę po zmianie karty (flagi/cache, bez uploadu); dialogi przed przechwyceniem klienta w `_open_remote` | LOW |
| C1-13 | X11 forwarding zawsze żądany | decyzja G8 |
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

## Procedura wycofania

- Kod: V2 nie jest w Git — migawki w `C:\claude\hospital_hub_v2_snapshots\`:
  `hh_v2_snapshot_phase0.tgz` (sprzed zmian 2026-10-14), `hh_v2_snapshot_etap68.tgz`,
  `hh_v2_snapshot_2026-10-14_final.tgz` (stan końcowy). Rozważyć objęcie V2 kontrolą wersji.
- VPN: każda flaga `CONNECT_ENABLED` z powrotem na `False` + restart aplikacji = powrót na legacy.
- Dane: format vaulta niezmieniony; `.vault.bak` (jedna generacja) obok vaulta.
- V1 (`C:\claude\hospital_hub`) nietknięta — pozostaje działającą alternatywą.
