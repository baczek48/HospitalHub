# HospitalHub V2 — projekt niezależny

> Utworzono: 2026-09-11. Baza: `C:\claude\hospital_hub` w stanie z 2026-06-15
> (commit `342d357` + niezacommitowane zmiany w drzewie roboczym — skopiowano **stan roboczy**,
> czyli m.in. RDP zawsze przez podpisany `.rdp`, log diagnostyczny RDP, poprawki VPN i SSH).
>
> **Kod aplikacji jest na tym etapie identyczny z V1.** Zmieniono wyłącznie identyfikatory,
> które decydują o tym, gdzie aplikacja zapisuje swoje dane — po to, żeby uruchomienie V2
> nigdy nie dotknęło danych ani instalacji V1.

---

## 1. Co jest odseparowane od HospitalHub 1.x

| Zasób | HospitalHub 1.x | HospitalHub V2 | Plik |
|---|---|---|---|
| Katalog konfiguracji | `%APPDATA%\HospitalHub\config.json` | `%APPDATA%\HospitalHubV2\config.json` | `config.py` |
| Log awarii | `%APPDATA%\HospitalHub\crash.log` | `%APPDATA%\HospitalHubV2\crash.log` | `main.py` |
| Katalog tymczasowy (SFTP) | `%TEMP%\HospitalHub_<pid>` | `%TEMP%\HospitalHubV2_<pid>` | `main.py`, `ui/ssh_panel.py` (4 miejsca) |
| Kanał single-instance (IPC) | `HospitalHub_SingleInstance` | `HospitalHubV2_SingleInstance_<16 znaków sha256(DOMENA\użytkownik)>` (od 2026-10-14; potok tylko dla bieżącego użytkownika) | `main.py` |
| Znane klucze hostów SSH (TOFU) | `~\.hospitalhub_known_hosts` | `~\.hospitalhub_v2_known_hosts` | `ui/ssh_panel.py` |
| Log diagnostyczny RDP | `%TEMP%\hospitalhub_rdp_sign.log` | `%TEMP%\hospitalhub_v2_rdp_sign.log` | `ui/rdp.py` |
| Certyfikat podpisujący `.rdp` | `CN=HospitalHub RDP Auto-Sign` | `CN=HospitalHub V2 RDP Auto-Sign` | `ui/rdp.py` |
| Log VPN (`vpn_debug.log`) | katalog projektu/exe V1 | katalog projektu/exe V2 | `vpn_connect.py` (bez zmian — ścieżka wynika z lokalizacji) |
| Plik `.exe` | `HospitalHub.exe` | `HospitalHubV2.exe` | `HospitalHubV2.spec` |
| Katalog build/dist | `dist\HospitalHub\` | `dist\HospitalHubV2\` | `HospitalHubV2.spec` |
| Instalator | `HospitalHub-Setup-1.5.3.exe`, AppId `A7F3C4D2-…` | `HospitalHubV2-Setup-2.0.0.exe`, AppId `9C95F6FD-…` | `HospitalHubV2.iss` |
| Katalog instalacji | `C:\Program Files\HospitalHub` | `C:\Program Files\HospitalHubV2` | `HospitalHubV2.iss` |
| Grupa w menu Start | „HospitalHub” | „HospitalHub V2” | `HospitalHubV2.iss` |

**Kanał IPC jest tu najważniejszy.** Bez jego zmiany uruchomienie V2 przy działającej V1 nie
otworzyłoby nowej aplikacji, tylko przywróciło okno V1 (mechanizm pojedynczej instancji).

### Co zostaje wspólne (celowo)
- **Nazwa aplikacji i logo** — tytuł okna, ekran logowania i ikona-tarcza są takie same
  (zgodnie z ustaleniem, że branding się nie zmienia).
- **Pliki `.vault`** — format jest identyczny, więc V2 otworzy każdy istniejący vault.
  V2 nie zapisuje nic do vaulta bez wyraźnej akcji użytkownika (`Ctrl+S`), ale **przy pracy
  na produkcyjnym vaulcie i tak warto trzymać osobną kopię pliku.**
- **Klienci zewnętrzni** (FortiClient, mstsc, SQL Developer) — to programy systemowe, wspólne
  z natury rzeczy.

---

## 2. Uruchomienie ze źródeł

```bat
cd C:\claude\hospital_hub_v2
py -3.13 main.py
```

Zależności są te same co w V1 i są już zainstalowane w interpreterze 3.13. Gdyby trzeba było
postawić je od zera (albo w osobnym venv — patrz niżej):

```bat
py -3.13 -m pip install -r requirements.txt
```

### Opcjonalnie: własny venv (pełna izolacja środowiska)
```bat
cd C:\claude\hospital_hub_v2
py -3.13 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
python main.py
```
`.venv/` jest już wpisane do `.gitignore` tego projektu.

---

## 3. Budowanie

```bat
cd C:\claude\hospital_hub_v2
build_v2.bat
```

Skrypt:
1. uruchamia `py -3.13 -m PyInstaller --noconfirm HospitalHubV2.spec`
   → `dist\HospitalHubV2\HospitalHubV2.exe` (tryb onedir, ikona `icon.ico`),
2. jeśli znajdzie Inno Setup 6, kompiluje `HospitalHubV2.iss`
   → `dist_installer\HospitalHubV2-Setup-2.0.0.exe`.

Ręcznie, gdyby trzeba było po kroku:
```bat
py -3.13 -m PyInstaller --noconfirm HospitalHubV2.spec
iscc HospitalHubV2.iss
```

Build V2 zapisuje wyłącznie do `hospital_hub_v2\build`, `hospital_hub_v2\dist`
i `hospital_hub_v2\dist_installer`.

---

## 4. Gdzie V2 trzyma swoje dane

```
%APPDATA%\HospitalHubV2\
    config.json      ostatni vault, lista vaultów, szerokości kolumn, motyw,
                     ścieżki klientów VPN, ścieżka SQL Developera, preferencje
    crash.log        nieobsłużone wyjątki

%TEMP%\HospitalHubV2_<pid>\      pliki tymczasowe SFTP (kasowane przy wyjściu)
%TEMP%\hospitalhub_v2_rdp_sign.log   diagnostyka RDP

C:\Users\<user>\.hospitalhub_v2_known_hosts   klucze hostów SSH (TOFU)

<katalog projektu lub exe>\vpn_debug.log      log VPN (obecnie wyłączony w kodzie)
```

**Konsekwencja rozdzielenia:** V2 startuje „na czysto” — nie widzi listy vaultów z V1
(przy pierwszym uruchomieniu pokazuje ekran „Utwórz / Otwórz vault”) i nie zna kluczy SSH
zapamiętanych przez V1, więc przy pierwszym połączeniu z każdym hostem zapyta o akceptację
klucza. Jeśli chcesz to pominąć, skopiuj ręcznie `~\.hospitalhub_known_hosts`
na `~\.hospitalhub_v2_known_hosts`.

---

## 5. Czego tu nie ma (zostało w V1)

Nie skopiowano rzeczy, które są własnością V1 albo śmieciem roboczym:
`.git/`, `dist/`, `build/`, `dist_installer/` (gotowe instalatory 1.5.0–1.5.3), `__pycache__/`,
`.pytest_cache/`, `HospitalHub_baisc.exe`, `config.json` z katalogu projektu (kopia prywatnej
konfiguracji użytkownika ze ścieżkami do vaultów), logi (`vpn_debug.log`, `vpn_launch.log`,
`build_*.log`), zrzuty ekranu `*.png`, transkrypty sesji `20??-??-??-*.txt`, katalogi
`Seba J HH\` i `zrzuty_debug\`, oraz `ARCHITECTURE.md` (jest nieaktualna — opisuje wersję
sprzed VPN, RDP i terminala; aktualnym opisem jest `OPIS_APLIKACJI.md`).

---

## 6. Stan

- Testy jednostkowe: `py -3.13 -m pytest tests` → **30 passed**.
- Aplikacja uruchomiona ze źródeł, okno logowania wyświetla się poprawnie, katalog
  `%APPDATA%\HospitalHubV2` powstaje przy starcie.
- Build produkcyjny (`build_v2.bat`) **nie był jeszcze uruchamiany** — czeka na decyzję.
- Kod funkcjonalny jest 1:1 z V1. Żadne ulepszenia nie zostały wprowadzone.

---

## 7. Granice zabezpieczeń (do świadomego użycia)

Opisane na podstawie audytu z 2026-10-14 — żeby nikt nie zakładał więcej, niż kod daje.

- **Tryb admina chroni tylko w interfejsie.** Poświadczenia oznaczone „tylko admin” i skrót
  hasła admina leżą w tym samym pliku vaulta, zaszyfrowanym **hasłem głównym**. Kto zna hasło
  główne, może odszyfrować plik poza aplikacją i odczytać także poświadczenia admina. Tryb
  admina ukrywa je w UI i nie wstrzykuje ich (RDP, SQL Developer), ale nie jest osobnym
  szyfrowaniem. Hasło admina ma minimum 4 znaki.
- **Kopia `.vault.bak`.** Każdy zapis zostawia obok vaulta poprzednią wersję (jedna generacja,
  zaszyfrowana tym samym hasłem). Po zmianie hasła głównego kopia jest usuwana — inaczej stare
  hasło otwierałoby aktualne dane.
- **Typ vaulta nie jest zapisany w pliku.** Wybiera się go przy logowaniu; aplikacja odmawia
  otwarcia, gdy wybrany typ przeczy zawartości (ochrona przed nadpisaniem profili pustą listą).
- **Schowek.** Hasła kopiowane z aplikacji są oznaczane dla Windows jako wykluczone z historii
  schowka (Win+V) i synchronizacji w chmurze, czyszczone po 15 s i przy zamknięciu aplikacji.
- **VPN V2** (gdy zostanie włączony): bez nazwy profilu w karcie FortiClient dane nie są
  wpisywane, chyba że w kliencie jest dokładnie jeden profil i to on jest wyświetlony.
