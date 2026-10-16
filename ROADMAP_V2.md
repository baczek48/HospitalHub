# HospitalHub V2 — roadmapa wykonania

> Utworzono: 2026-10-14 (PHASE 0 dyrektywy wykonawczej).
> Ten plik **nie zastępuje** `AUDYT_V2.md` — tamten jest audytem i źródłem
> merytorycznym (ETAP 0–9, §1–§10). Tu jest kolejność wykonania, zależności
> i bramki. Stan bieżący: `EXECUTION_STATUS.md`. Dziennik: `EXECUTION_LOG.md`.
> Szczegóły etapów VPN 1–63: `2026-10-13-hospitalhubv2-etapy-60-62.md`,
> docstringi `vpn/` oraz `CONNECT_PARITY`/`LEGACY_BEHAVIOR` w
> `vpn/providers/forticlient_connect.py`.

## Zasady nienaruszalne (skrót)

- V1 (`C:\claude\hospital_hub`) nietknięty; praca tylko w `C:\claude\hospital_hub_v2`.
- Od 2026-10-15 V2 ma **własne lokalne repo Git** (bez remote; V1 i repo nadrzędne
  `C:\claude` bez zmian). Przed szerokimi zmianami commit + migawka `.tgz`
  (`C:\claude\hospital_hub_v2_snapshots\`, `SHA256SUMS`).
- `CONNECT_ENABLED = False` ×3 (FortiClient, Stormshield, Barracuda) — flagę
  zmienia wyłącznie użytkownik, przy kontrolowanym live teście.
- `SFTP_SAFE_REPLACE_ENABLED = False` (`ui/ssh_panel.py`) do bramki G10.
- `vpn_connect.py` (legacy, sha256 `a929035e…`) — bez zmian bez osobnego uzasadnienia.
- Brak automatycznego fallbacku V2 → legacy.
- `tests/conftest.py` (izolacja od Windows) — nie osłabiać, nie obchodzić.
- Testy: `py -3.13 -m pytest tests -q -p no:cacheprovider` (3.12 nie ma PyQt6).

## Dwie numeracje — nie mylić

| Numeracja | Znaczenie |
|---|---|
| **ETAP 0–9** (`AUDYT_V2.md` §11) | makro-plan produktu |
| **Etap 1–63** | kroki migracji VPN = w całości ETAP 3 z audytu |
| **PHASE A–I** | dyrektywa wykonawcza z 2026-10-14; mapowanie niżej |

Nowe znaczące checkpointy numerujemy dalej jako **Etap 64, 65, …**; drobne
prace grupujemy w tych etapach.

## Kolejność i zależności

```
PHASE A  FortiClient V2 domknięcie ─┐
   └─ bramka G1: live read-only pomiar stanów MSAA combo (użytkownik otwiera listę)
PHASE B  cutover VPN (Forti → Stormshield → Barracuda), każdy z bramką live (użytkownik)
   └─ zależy od: A, H1 (comtypes w buildzie — MSAA/UIA)
PHASE C  SSH/SFTP → RDP → DB/SQL Developer → vault → multi-window/tray/IPC → konfiguracja
   └─ niezależna od B (może iść równolegle, gdy B czeka na użytkownika)
PHASE D  architektura, wątki, cancellation, zamykanie, polling   (= AUDYT ETAP 1 i 7)
PHASE E  integracja Windows + bezpieczeństwo                     (= AUDYT §9, §10, ETAP 6)
PHASE F  UI/UX redesign                                          (= AUDYT ETAP 5) — dopiero po C–E
PHASE G  macierz testów E2E (fake vs live rozdzielone)
PHASE H  build + instalator                                      (= AUDYT ETAP 8)
   └─ H1 (comtypes/oleacc w spec) jest wymagane WCZEŚNIEJ, przed bramką B-Forti
PHASE I  final audit / release readiness
```

## PHASE A — FortiClient V2

| # | Zadanie | Stan |
|---|---|---|
| A1 | MSAA w `_select_profile()` (Etap 63) | **DONE** 2026-10-14, 1416 PASS, review APPROVE WITH NOTES |
| A2 | Puste `profile_name` — analiza miejsc wywołania + fail-closed dla V2 | Etap 64 |
| A3 | Audyt pozostałych ścieżek (detekcja, launch, gate, 2FA/EMS/CLI, UI, polling, cancel, re-entrancy, diagnostyka) | Etap 64 (agent) |
| A4 | Komunikaty UI dla nowych kodów odmowy profilu | Etap 64 |
| G1 | **Bramka:** live read-only pomiar FOCUSED/EXPANDED/COLLAPSED/accValue combo „VPN Name” (zamknięte / otwarte / podświetlone przed zatwierdzeniem) | wymaga użytkownika (otwarcie listy ręcznie); sonda read-only przygotowana |

Kryterium: wszystkie testy zielone; review bezpieczeństwa; luki z A3 naprawione
albo jawnie udokumentowane jako warunek wdrożenia.

## PHASE B — kontrolowany cutover VPN

Dla każdego providera osobno, w kolejności **FortiClient → Stormshield → Barracuda**:
1. zielone testy + kompletność fake coverage; 2. build z wymaganymi zależnościami
(H1); 3. raport do ręcznego testu live; 4. **STOP — użytkownik wykonuje live
connect** (flaga zmieniana tylko na czas próby); 5. analiza, poprawki; 6. akceptacja
dopiero po: wybór profilu, credentials, końcowy Enter, realny stan VPN, powrót UI.

Znane warunki wdrożeniowe (nie blokują maszyny VPN-only/Free):
- `cli-monitor-not-owned-by-panel` — trasa CLI (EMS/płatna) bez monitora 2FA w panelu.
- EMS AUTH_WINDOW — contract-only (brak maszyny EMS).
- Stormshield/Barracuda: flow staje przed autofillem (MANUAL); Barracuda wymaga
  comtypes/UIA w buildzie.

## PHASE C — funkcje aplikacji (audyt → luki → testy → poprawki)

C1 SSH/SFTP (`ui/ssh_panel.py`, 7132 l.) · C2 RDP (`ui/rdp.py`) · C3 DB/SQL Developer
(`ui/db_connect.py`) · C4 vault/crypto/config/models · C5 multi-window/tray/
single-instance/IPC (`main.py`, `ui/main_window.py`) · C6 konfiguracja i zarządzanie
połączeniami (`ui/dialogs.py`, `ui/detail_panel.py`).
Zasada: nie przepisywać stabilnego kodu; naprawiać realne luki.

## PHASE D–I

Zakres zgodny z dyrektywą i `AUDYT_V2.md` (§3 wydajność P1–P12, §9 bezpieczeństwo,
§10 kompatybilność, §11 ETAP 1/5/6/7/8). Każdy obszar: audyt → lista luk w
`EXECUTION_STATUS.md` → poprawki z testami → review → wpis w dzienniku.

## Bramki wymagające użytkownika

| Bramka | Co | Dlaczego nie autonomicznie |
|---|---|---|
| G1 | otwarcie listy „VPN Name” podczas sondy read-only | sonda nie może klikać ani zmieniać fokusu |
| G2 | live connect FortiClient V2 (flaga True na czas próby) | realne połączenie VPN |
| G3 | live connect Stormshield V2 | j.w. |
| G4 | live connect Barracuda V2 | j.w. |
| G5 | **ROZSTRZYGNIĘTE 10-15:** blokada w V2, gdy profil niejednoznaczny; bez fallbacku | — |
| G6 | instalacja/odinstalowanie instalatora na maszynie | per-user (scratch) **zrobione 10-15**; instalacja admin wymaga UAC |
| G7 | **ROZSTRZYGNIĘTE 10-15:** Inno Setup 6.7.1 zainstalowany przez użytkownika | — |
| G8 | **ROZSTRZYGNIĘTE 10-15 (korekta):** X11 domyślnie WŁĄCZONY, zachowanie bez zmian, testy regresji | — |
| G9 | **ROZSTRZYGNIĘTE 10-15:** redesign odłożony do końca stabilizacji; **10-16: właściciel uruchomił Etap 71 (UX polish + redesign)** | — |
| G10 | włączenie bezpiecznej podmiany SFTP (tmp + posix-rename) | test bezpieczeństwa i zgodności zapisu SFTP wykonany 10-15 (pliki XML, bez prawdziwych serwerów); włączenie flagi = decyzja użytkownika |

## Etap 70 (2026-10-15) — SFTP: edycja w zewnętrznym edytorze

Zakres wąski (bez przebudowy SSH/SFTP): kolizje plików o tej samej nazwie, wiązanie
edycji z serwerem/sesją/ścieżką, bezpieczny zapis. Stan: **DONE**, review APPROVE WITH
NOTES ×2. Włączenie bezpiecznej podmiany — bramka G10 (test zapisu SFTP 10-15 PASS, flaga wyłączona). Szczegóły: `EXECUTION_LOG.md`.

## Etap 71 (od 2026-10-16) — UX polish, drobne defekty i redesign (= PHASE F)

Zlecenie właściciela 2026-10-16. Zasady: tylko V2; bez zmian logiki biznesowej, zabezpieczeń
i integracji pod wygląd; bez live VPN i danych produkcyjnych; zielone testy ≠ działający UI —
każda zmiana wizualna sprawdzana na zrzucie (harness offscreen, Segoe UI 9 pt, oba motywy,
skale 1.0–2.0). Migawka przed etapem: `hh_v2_snapshot_2026-10-16_pre_ux.tgz`.

| Krok | Zakres | Stan |
|---|---|---|
| 71A | audyt (4 niezależnych audytorów: terminal/tmux, wizualny, ergonomia, scenariusze) | w toku |
| 71B | reprodukcja → test regresji → minimalna poprawka → pełny zestaw → weryfikacja wizualna | — |
| 71C | redesign: inwentaryzacja ekranów, problemy UX, zasady wizualne, wdrażanie modułami | — |
| 71D | walidacja wizualna i użytkowa (przed/po) | — |
| 71E | dokumentacja, statusy znalezisk (UX-xx), kryteria zamknięcia | — |

Rejestr znalezisk: `UX_AUDIT_V2.md` (statusy: potwierdzony / naprawiony i zweryfikowany /
nierozwiązany / wymaga ręcznego testu).
