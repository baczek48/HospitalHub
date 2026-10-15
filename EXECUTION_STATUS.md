# HospitalHub V2 — stan wykonania

> Aktualizowane po każdym checkpoincie. Plan: `ROADMAP_V2.md`. Historia: `EXECUTION_LOG.md`.
> Gotowość: `RELEASE_READINESS_V2.md`. Testy: `TEST_MATRIX_V2.md`.

**Ostatnia aktualizacja:** 2026-10-14 22:10 · **Testy:** 1664 PASS / 0 FAIL / 0 ERROR, bez skip/xfail
(`py -3.13 -m pytest tests -q -p no:cacheprovider`) · **Build:** exe 2026-10-14 22:03, smoke startu OK

## Niezmienniki

| | Stan |
|---|---|
| `FortiClientProvider.CONNECT_ENABLED` | `False` |
| `StormshieldProvider.CONNECT_ENABLED` | `False` |
| `BarracudaProvider.CONNECT_ENABLED` | `False` |
| `vpn_connect.py` sha256 | `a929035e5b62fb98…` (nietknięty) |
| `HospitalHubV2.spec` sha256 | `4b27eed238414e28…` (H1) |
| V1 `C:\claude\hospital_hub` | nietknięty (najnowszy plik 2026-09-11) |
| Git | V2 nie jest śledzony — migawki w `C:\claude\hospital_hub_v2_snapshots\` (phase0 = sprzed zmian 10-14, etap68, 2026-10-14_final = stan końcowy) |

## Ukończone (2026-10-14)

| Checkpoint | Review |
|---|---|
| Etap 63 — MSAA w `_select_profile()` | APPROVE WITH NOTES |
| PHASE 0 — rozpoznanie, dokumenty, sonda G1 | — |
| H1 — comtypes/oleacc w buildzie | — (build + smoke) |
| Etap 64 — FortiClient V2: L1–L5, L7, L8, L13, L14 | REJECT → poprawione → APPROVE WITH NOTES |
| Etap 65 — integralność vaulta | APPROVE WITH NOTES |
| Etap 66 — SSH/SFTP C1-01..06, C1-17 (+S1–S3) | REJECT ×2 → poprawione → APPROVE WITH NOTES |
| Etap 67 — RDP, schowek, IPC | APPROVE WITH NOTES |
| Etap 68 — SSH/SFTP C1-07..12, schowek V2 | APPROVE WITH NOTES |
| Etap 69 — stabilność (audyt PHASE D/E) | APPROVE WITH NOTES |
| PHASE G — macierz testów (`TEST_MATRIX_V2.md`) | — |
| PHASE I — raport gotowości + niezależna weryfikacja | werdykt: NIE gotowe do wdrożenia |

## Aktywne

Brak — dalsza praca wymaga decyzji lub działań użytkownika (niżej).

## Zablokowane (wymagają użytkownika)

| Bramka | Co | Wymagane działanie |
|---|---|---|
| **G1** | stany MSAA listy „VPN Name” | Otwórz FortiClient (ekran logowania VPN), uruchom `py -3.13 -m smoke.forticlient_msaa_live watch --seconds 90`; otwórz listę „VPN Name”, przesuń podświetlenie strzałkami **bez Enter**, zamknij Escape. Wklej wynik. |
| **G2** | live connect FortiClient V2 | po G1 i G5 |
| **G3/G4** | live connect Stormshield / Barracuda V2 | po akceptacji G2 |
| **G5** | pusty `profile_name` w V2 | rekomendacja: zostawić obecną blokadę, uzupełnić nazwy profili w kartach |
| **G6** | instalacja/odinstalowanie instalatora | po G7 |
| **G7** | Inno Setup 6 (ISCC) nie jest zainstalowany | decyzja o instalacji |
| **G8** | X11 forwarding domyślnie (C1-13) | decyzja produktowa |
| **G9** | redesign UI (PHASE F) | zakres i kierunek |

## Jak wznowić (dla następnej sesji)

1. Przeczytaj ten plik, potem `RELEASE_READINESS_V2.md` (pełna lista pozostawionych znalezisk).
2. Sprawdź niezmienniki z tabeli wyżej (flagi ×3 = False, sha `vpn_connect.py`, V1 nietknięte)
   i uruchom testy — oczekiwane 1664 PASS.
3. Zapytaj użytkownika, które bramki są już rozstrzygnięte (G1 wynik sondy, G5, G7, G8, G9)
   oraz o decyzję w sprawie atomowego uploadu SFTP (tmp+rename zmienia to, jak watcher po
   stronie serwera, np. HL7, widzi plik).
4. Przed szerokimi zmianami: nowa migawka do `C:\claude\hospital_hub_v2_snapshots\`
   (`tar --force-local -czf … --exclude=hospital_hub_v2/build --exclude=hospital_hub_v2/dist`).
5. Po zmianach: testy, build (`build_v2.bat`), smoke startu exe offscreen, wpis w `EXECUTION_LOG.md`.

## Kolejka (gdy bramki pozwolą)

1. Po G1: korekta `_select_profile` wg zmierzonych stanów; potem G2.
2. Pozostawione znaleziska (pełna lista: `RELEASE_READINESS_V2.md`), w tym nieatomowy auto-upload
   edycji SFTP (tmp+rename) — najważniejsze z otwartych.
3. PHASE F po decyzji G9; PHASE H instalator po G7.
