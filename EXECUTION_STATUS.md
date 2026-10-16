# HospitalHub V2 — stan wykonania

> Aktualizowane po każdym checkpoincie. Plan: `ROADMAP_V2.md`. Historia: `EXECUTION_LOG.md`.
> Gotowość: `RELEASE_READINESS_V2.md`. Testy: `TEST_MATRIX_V2.md`.

**Ostatnia aktualizacja:** 2026-10-16 (Etap 71 UX) · **Testy:** 1916 PASS / 0 FAIL / 0 ERROR, bez skip/xfail
(`py -3.13 -m pytest tests -q -p no:cacheprovider`) · **Build:** exe + instalator 2026-10-15 20:05,
cykl instalacja → start → aktualizacja → deinstalacja (per-user, bez UAC) PASS

## Niezmienniki

| | Stan |
|---|---|
| `FortiClientProvider.CONNECT_ENABLED` | `False` |
| `StormshieldProvider.CONNECT_ENABLED` | `False` |
| `BarracudaProvider.CONNECT_ENABLED` | `False` |
| `ui/ssh_panel.SFTP_SAFE_REPLACE_ENABLED` | `False` (bramka G10) |
| `vpn_connect.py` sha256 | `a929035e5b62fb98…` (nietknięty) |
| `HospitalHubV2.spec` sha256 | `4b27eed238414e28…` (H1) |
| V1 `C:\claude\hospital_hub` | nietknięty (najnowszy plik 2026-09-11) |
| Git | **lokalne repo tylko w `hospital_hub_v2`** (od 2026-10-15, bez remote); commit bazowy `2682c72` = stan sprzed zmian 10-15 |
| Migawki | `C:\claude\hospital_hub_v2_snapshots\` + `SHA256SUMS` (`sha256sum -c SHA256SUMS`) |

## Decyzje właściciela (2026-10-15)

| Bramka | Decyzja |
|---|---|
| G1 | czeka na ręczny pomiar użytkownika; podczas pomiaru zero klawiszy i interakcji z naszej strony |
| G2 | osobna, wyraźna zgoda użytkownika po analizie G1; flag `CONNECT_ENABLED` nie włączamy |
| G5 | blokada w V2 zostaje, gdy profilu docelowego nie da się jednoznacznie ustalić; bez cichego fallbacku do bieżącego profilu |
| G7 | Inno Setup zainstalowany (6.7.1, per-user); skrypt przygotowany i zweryfikowany — **zrobione** |
| G8 | **X11 domyślnie WŁĄCZONY** (korekta decyzji; zastępuje wcześniejsze „wyłącz domyślnie”). Zachowanie bez zmian, testy regresji dodane |
| G9 | pełny redesign UI odłożony do końca stabilizacji i testów przedwdrożeniowych |

## Ukończone 2026-10-15

| Checkpoint | Review |
|---|---|
| P0 — migawki zweryfikowane (gzip, lista, diff z drzewem), nowa `2026-10-15_pre`, `SHA256SUMS` | — |
| P0 — audyt sekretów + `.gitignore` + `git init` w V2 (commit `2682c72`) | — |
| Etap 70 — SFTP: kolizje plików edytowanych zewnętrznie (F1–F3, L7), bezpieczny zapis `upload_edit` (P1, za flagą) | APPROVE WITH NOTES ×2 (M1–M4, L5 i uwaga z 2. rundy poprawione) |
| G8 — testy regresji X11 (`tests/test_ssh_x11_default.py`) | — |
| G7/G6 — instalator: kompilacja, instalacja, start, aktualizacja 2.0.0→2.0.1, deinstalacja (per-user, scratch) | — |

## Aktywne

Brak. **Etap 71 — UX polish + redesign zakończony 2026-10-16** (rejestr `UX_AUDIT_V2.md`, plan
`REDESIGN_V2.md`): 89 znalezisk, 81 naprawionych i zweryfikowanych, 1863 PASS, build exe +
instalator 2026-10-16 (po przeglądzie). Czeka na użytkownika: ręczna weryfikacja (lista w
`TEST_MATRIX_V2.md`), 4 decyzje redesignu (`REDESIGN_V2.md` §5).

## Zablokowane (wymagają użytkownika)

| Bramka | Co | Wymagane działanie |
|---|---|---|
| **G1** | stany MSAA — **pomiar wykonany 2026-10-15**, pytania 5–6 rozstrzygnięte 2026-10-16 (Escape zatwierdza podświetlenie; okno zamknięte ręcznie) | **G1b** — sonda + sekwencja klawiszy V2 wykonana ręcznie (instrukcja: `EXECUTION_LOG.md`, wpis 2026-10-16 G1) |
| **G2** | live connect FortiClient V2 | po G1 — osobna, wyraźna zgoda |
| **G3/G4** | live connect Stormshield / Barracuda V2 | po akceptacji G2 |
| **G6** | instalacja **admin** do Program Files | wymaga kliknięcia UAC — uruchomić `dist_installer\HospitalHubV2-Setup-2.0.0.exe`, potem odinstalować; per-user zrobione automatycznie |
| **G10** (nowa) | włączenie bezpiecznej podmiany SFTP (`SFTP_SAFE_REPLACE_ENABLED`) | test bezpieczeństwa i zgodności zapisu SFTP — **wykonany 2026-10-15 na plikach XML (fake + prawdziwy protokół SFTP w procesie)**; flaga nadal `False`, decyzja o włączeniu u użytkownika — `RELEASE_READINESS_V2.md` §G10 |

## Jak wznowić (dla następnej sesji)

1. Przeczytaj ten plik, potem `RELEASE_READINESS_V2.md`.
2. Sprawdź niezmienniki (flagi ×3 + `SFTP_SAFE_REPLACE_ENABLED` = False, sha `vpn_connect.py`,
   V1 nietknięte), `git -C C:/claude/hospital_hub_v2 status`, uruchom testy — oczekiwane 1916 PASS.
3. Zapytaj o G1b i o G10.
4. Przed szerokimi zmianami: commit w repo V2 (a dodatkowo migawka `.tgz` + dopisanie do `SHA256SUMS`).
5. Po zmianach: testy, build (`build_v2.bat` — buduje też instalator), smoke startu exe offscreen,
   wpis w `EXECUTION_LOG.md`.

## Kolejka

1. Po G1: korekta `_select_profile` wg zmierzonych stanów; ocena gotowości do G2.
2. G10: decyzja użytkownika o włączeniu bezpiecznej podmiany (rekomendacja w `RELEASE_READINESS_V2.md` §G10). Maskowanie odrzuconego zapisu przez zapis potokowy — naprawione 2026-10-16 we wszystkich ścieżkach zapisu.
3. Pozostawione znaleziska z `RELEASE_READINESS_V2.md` (L8 z Etapu 70, C1-16/18/19, D-08/D-10…).
4. Ręczne scenariusze Windows z `TEST_MATRIX_V2.md` (Win+V, multi-window, RDP).
5. PHASE F (redesign) — po stabilizacji (decyzja G9).
