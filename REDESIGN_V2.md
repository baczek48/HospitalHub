# HospitalHub V2 — redesign ergonomiczny (Etap 71C)

Podstawa: audyt 2026-10-16 (`UX_AUDIT_V2.md`, raporty A2/A3), zrzuty offscreen z prawdziwymi
fontami Windows. Zasada nadrzędna: **ergonomia pracy administratora przed efektem**; bez zmian
logiki, zabezpieczeń i integracji; wdrażanie modułami, każdy z testami i zrzutem przed/po.

## 1. Inwentaryzacja ekranów

| Ekran | Kod | Funkcja | Częstość |
|---|---|---|---|
| Okno vaulta szpitali | `ui/main_window.py` + `ui/detail_panel.py` | lista szpitali + wyszukiwanie; nagłówek (nazwa, liczniki, szybki SSH, SQL Developer, VPN); tabele maszyn (SSH/RDP/WWW) i baz z akcjami; notatki | ciągle |
| Okno vaulta VPN | `ui/vpn_panel.py` | karty profili: status, połącz/rozłącz, kopiuj login/hasło, edycja; ustawienia klientów | codziennie |
| Okno SSH | `ui/ssh_panel.py` `SshDialog` | karty sesji, multi-exec, terminal, Pliki (SFTP), Środowisko (maszyny szpitala), pasek statystyk | ciągle |
| Dialogi danych | `ui/dialogs.py` | szpital, maszyna, baza, poświadczenie | często |
| Dialogi bezpieczeństwa | `ui/dialogs.py`, `ui/login_dialog.py` | logowanie/utworzenie vaulta, hasło główne, hasło admina | rzadko |
| VPN: 2FA, osobisty vault, baner aktywacji | `ui/vpn_panel.py`, `detail_panel.py`, `ui/activation_prompt.py` | krótkie interakcje | rzadko |

## 2. Problemy UX (z uzasadnieniem)

Naprawione punktowo w 71B (szczegóły w rejestrze): bezpieczeństwo wklejania, potwierdzenia,
reconnect, kolejka SFTP, wyszukiwanie po IP, elipsy, tytuły okien, klawisze. Do redesignu zostały
problemy **strukturalne**:

| # | Problem | Dlaczego ważne | Znaleziska |
|---|---|---|---|
| P1 | Kolumna akcji maszyn/baz ucieka za prawą krawędź przy 1366×768 lub 125–150 % | główna akcja (Połącz) wymaga przewijania w bok | V-05 |
| P2 | Przycisk z loginem kopiuje hasło; loginu nie da się skopiować; dostęp tylko do pierwszego konta | najczęstsza czynność (login + hasło) to 5 kroków przez dialog edycji | E-08, E-09, V-25 |
| P3 | Dwie palety: dialogi szare (Fusion), okna granatowo-czarne | aplikacja wygląda na sklejoną z dwóch; pola dialogów zlewają się z tłem | V-20 |
| P4 | Brak stanów pustych i brak wyników | pusta tabela wygląda jak błąd ładowania | V-15 |
| P5 | Przyciski destrukcyjne nieczytelne, ikony-emoji o różnej wadze | „Usuń” ~2,5:1 kontrastu | V-16, V-21 |
| P6 | Ikony plików SFTP ciemne w jasnym motywie | — | V-11 |

Świadomie **poza** 71C (wymagają decyzji właściciela, opis w §5): model „jedno okno SSH na
kliknięcie” (A3 redesign #1), jawne powiązanie szpital ↔ profil VPN (#6), jeden model edycji
(VPN „na żywo” vs dialogi Zapisz/Anuluj, #7), „aktywna sesja = sesja z fokusem” w multi-exec.

## 3. Zasady wizualne i komponenty wspólne

- **Paleta jedna dla całej aplikacji** (GitHub-dark, już używana w oknach): tło okna `#0d1117`,
  powierzchnie `#161b22`, pola `#21262d`/`#0d1117`, ramki `#30363d`, tekst `#c9d1d9`/`#e6edf3`,
  tekst drugorzędny `#8b949e`, akcent `#1f6feb`/`#58a6ff`, sukces `#3fb950`, ostrzeżenie `#d29922`,
  błąd `#f85149`. Jasny motyw: istniejący remap `ui/theme.py` (bez zmian zasad).
- **Hierarchia przycisków:** główny (akcent, jeden na widok), zwykły (powierzchnia + ramka),
  destrukcyjny (czerwony tekst `#f85149` na powierzchni, czerwony przy hover), ikonowy 28×28.
  Kolejność w dialogach: **Anuluj | Akcja główna** (akcja główna z prawej, domyślna dla Enter),
  bezpieczny przycisk domyślny tylko w pytaniach o usunięcie.
- **Teksty:** zawsze polskie znaki i odmiana (`ui.utils.plural`), komunikat = co się stało +
  co zrobić; długie nazwy → `ui.utils.ElidedLabel` (elipsa + tooltip).
- **Stany:** pusty („Brak maszyn — dodaj pierwszą przyciskiem poniżej”), brak wyników, ładowanie,
  błąd — tekst drugorzędny wyśrodkowany w obszarze, nigdy pusta ramka.
- **Akcje w wierszu:** pierwsza akcja (Połącz) zawsze widoczna; wszystkie akcje wiersza także w
  menu kontekstowym (prawy klik) — mysz i klawiatura mają ten sam zakres.

## 4. Plan wdrażania (modułami)

| Moduł | Zakres | Weryfikacja |
|---|---|---|
| R1 | Paleta dialogów: ciemna paleta Qt zgodna z oknami (P3) | zrzuty wszystkich dialogów przed/po, oba motywy |
| R2 | Tabele maszyn/baz: kolumny dopasowane do szerokości (P1); poświadczenia: klik = hasło jak dotąd, prawy klik i menu wiersza = login/hasło każdego konta, połącz jako (P2) | testy + zrzuty 1050×680, 700×450, 150 %, 200 % |
| R3 | Stany puste i brak wyników (P4); przyciski destrukcyjne (P5) | zrzuty |
| R4 | Ikony SFTP w jasnym motywie (P6) | zrzut jasny |

## 5. Decyzje dla właściciela (nie wdrażane bez zgody)

1. ~~**Jedno okno SSH na szpital**~~ — **WDROŻONE 2026-10-16 na prośbę właściciela:** ⇆ / „Połącz
   jako” przy maszynie szpitala, dla którego okno SSH jest już otwarte, dodaje kartę w tym oknie
   (ostatnio używanym, przywraca je z minimalizacji); inny szpital = osobne okno; „Szybkie SSH”
   bez zmian (`SshDialog.window_for`, `open_machine`; `tests/test_ssh_one_window.py`).
2. **Pole „profil VPN” w szpitalu** zamiast dopasowania po nazwie (zmiana modelu danych vaulta).
3. **Jeden model edycji** — VPN z Zapisz/Anuluj jak reszta, albo reszta „na żywo”.
4. **Multi-exec: aktywna sesja = ta z fokusem** (SFTP i Środowisko śledzą fokus).
