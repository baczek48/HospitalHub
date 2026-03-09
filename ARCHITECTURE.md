# HospitalHub — Architektura aplikacji

## Przeglad

HospitalHub to aplikacja desktopowa napisana w **Python + PyQt6** sluzaca do zarzadzania danymi infrastruktury IT szpitali. Dane sa przechowywane lokalnie w zaszyfrowanym pliku `.vault` i nie wymagaja zadnego serwera ani polaczenia sieciowego.

---

## Stack technologiczny

| Warstwa | Technologia |
|---|---|
| UI | PyQt6 6.5+ |
| Szyfrowanie | AES-256-GCM (`cryptography`) |
| Wyprowadzanie klucza | Argon2id (`argon2-cffi`) |
| Serializacja danych | JSON (wewnatrz zaszyfrowanego bloku) |
| Konfiguracja | JSON w `%APPDATA%\HospitalHub\config.json` |
| Jezyk | Python 3.11+ |

---

## Struktura plikow

```
vault_app/
  main.py               # Punkt wejscia, motyw graficzny, ikona aplikacji
  crypto.py             # Szyfrowanie / deszyfrowanie pliku vault
  models.py             # Modele danych (dataclassy) + serializacja
  config.py             # Persystencja konfiguracji (ostatni vault, szerokosci kolumn)
  requirements.txt      # Zaleznosci Python
  build_exe.bat         # Skrypt PyInstaller do budowania .exe
  ui/
    login_dialog.py     # Okno logowania (QStackedWidget: szybkie logowanie / wybor vaulta)
    main_window.py      # Glowne okno aplikacji (lista szpitali + panel szczegolów)
    detail_panel.py     # Panel szczegolow szpitala (maszyny, bazy, notatki)
    dialogs.py          # Dialogi: szpital, maszyna, poswiadczenie, baza danych, zmiana hasla
    utils.py            # Pomocnicze: polskie dialogi potwierdzenia (Tak/Nie)
```

---

## Modele danych (`models.py`)

Dane sa reprezentowane przez dataclassy Pythona. Kazdy obiekt ma unikalne UUID (`id`) generowane automatycznie przy tworzeniu.

```
Hospital
  id: str (UUID)
  name: str
  notes: str
  machines: List[Machine]
  databases: List[Database]

Machine
  id: str (UUID)
  ip: str
  name: str
  description: str
  credentials: List[Credential]

Credential
  id: str (UUID)
  login: str
  password: str
  note: str

Database
  id: str (UUID)
  host: str
  port: str
  name: str
  db_type: str           # MSSQL | Oracle | PostgreSQL | MySQL | MariaDB | Inne
  login: str
  password: str
  note: str
```

Serializacja do/z dict (JSON): `models.to_dict(hospitals)` / `models.from_dict(data)`.
Deserializacja uzywa `.get()` z wartosciami domyslnymi — nowe pola dodane w przyszlosci nie zepsuja starszych plikow vault.

---

## Format pliku vault (`crypto.py`)

Plik `.vault` jest tekstowym JSON-em (UTF-8) z kopertą:

```json
{
  "v": 1,
  "salt": "<base64, 16 bajtow losowych>",
  "nonce": "<base64, 12 bajtow losowych>",
  "data": "<base64, zaszyfrowany+uwierzytelniony ciphertext>"
}
```

### Wyprowadzanie klucza

Haslo glowne → **Argon2id** → 32-bajtowy klucz AES:

| Parametr | Wartosc |
|---|---|
| Algorytm | Argon2id |
| time_cost | 3 iteracje |
| memory_cost | 65 536 KB (64 MB) |
| parallelism | 4 watki |
| hash_len | 32 bajty (klucz AES-256) |
| salt | 16 bajtow losowych (per plik) |

### Szyfrowanie

Klucz + dane → **AES-256-GCM** (nonce 12 bajtow):
- Zapewnia poufnosc (szyfrowanie) i integralnosc (tag uwierzytelniajacy GCM).
- Zla weryfikacja tagu (zle haslo lub uszkodzony plik) powoduje wyjatek `InvalidTag`, ktory aplikacja zamienia na komunikat dla uzytkownika.

### Wlasciwosci bezpieczenstwa

- Kazdy zapis generuje nowe losowe `salt` i `nonce` — ten sam vault zapisany dwa razy da rozny ciphertext.
- Klucz i plaintext sa zerowane (`bytearray` → `_zero()`) po uzyciu — ogranicza czas pobytu secrets w pamieci.
- Haslo glowne nie jest nigdzie przechowywane; `config.json` zawiera tylko sciezke do pliku.

---

## Zapis atomowy (`main_window.py → _do_save`)

Aby chronić vault przed uszkodzeniem przy awarii systemu w trakcie zapisu:

1. Szyfrowanie danych w pamieci.
2. Zapis do pliku tymczasowego w tym samym katalogu (`tempfile.mkstemp`).
3. `f.flush()` + `os.fsync()` — wymuszenie zapisu na dysk.
4. `os.replace(tmp, target)` — atomowe zastapienie pliku docelowego (operacja atomowa na tym samym systemie plikow).

Jesli krok 2 lub 3 nie powiedzie sie, plik tymczasowy jest usuwany. Oryginalny vault pozostaje nienaruszony.

---

## Architektura UI

### Okno logowania (`login_dialog.py`)

Uzywa `QStackedWidget` z dwoma stronami:
- **Strona 0 (szybkie logowanie)**: pokazywana gdy `config.json` zawiera istniejacy plik vault. Tylko pole hasla + przycisk logowania. Link "Zmien vault lub utworz nowy" przelacza na strone 1.
- **Strona 1 (wybor)**: przyciski "Utworz nowy vault" i "Otworz istniejacy vault", kazdy otwiera podmenu dialog.

Wynik logowania: krotka `(vault_path, password, List[Hospital])` przekazywana do `MainWindow`.

### Glowne okno (`main_window.py`)

`QSplitter` poziomy:
- **Lewy panel** (190–300 px): lista szpitali (`QListWidget`) z wyszukiwarka.
- **Prawy panel**: `DetailPanel`.

Tytul okna: `"HospitalHub"` lub `"HospitalHub  [niezapisane]"`.

Sygnaly: `DetailPanel.data_changed` → `MainWindow._on_data_changed` → ustawia flage `_unsaved`, odswieza liste.

### Panel szczegolow (`detail_panel.py`)

`QSplitter` pionowy:
- **Gora**: `QGroupBox` z tabela maszyn.
- **Dol**: `QScrollArea` zawierajacy `QGroupBox` baz danych + `QGroupBox` notatek.

Obie tabele uzywaja `_DraggableTable` (podklasa `QTableWidget`) ktora realizuje drag & drop wierszy przez nadpisanie `dropEvent` — blokuje wbudowane przesuniecie Qt itemow (ktore niszczy cell widgety), emituje sygnal `rows_reordered(from_row, to_row)`, a `DetailPanel` samo przepina element na liscie i odswiezta tabele.

Konfiguracja kolumn (`_setup_table_columns`):
- Kolumny danych: tryb `Interactive` (szerokosci zapisywalne w `config.json`).
- Kolumna Opis / Notatka: tryb `Stretch` — wypelnia dostepne miejsce, przypina Akcje do prawej krawedzi.
- Kolumna Akcje: tryb `Fixed`, stala szerokosc 220 px.
- `resizeEvent` + `_fit_columns`: proporcjonalne zmniejszanie kolumn Interactive gdy lacznie przekraczaja szerokosc viewportu — zapobiega wychodzeniu tabeli poza okno.

### Dialogi (`dialogs.py`)

| Dialog | Opis |
|---|---|
| `HospitalDialog` | Nazwa szpitala |
| `MachineDialog` | IP, Nazwa, Opis + wbudowana tabela poswiadczen |
| `CredentialDialog` | Login, Haslo (toggle pokaz/ukryj), Notatka |
| `DatabaseDialog` | Host, Port, Nazwa, Typ (combobox), Login, Haslo, Notatka |
| `ChangePasswordDialog` | Stare haslo, nowe haslo x2 (weryfikacja min. 8 znakow i zgodnosci) |

---

## Konfiguracja aplikacji (`config.py`)

Plik: `%APPDATA%\HospitalHub\config.json`

```json
{
  "last_vault": "C:\\Users\\...\\infrastruktura.vault",
  "column_widths": {
    "machines": [120, 140],
    "databases": [180, 60, 130, 80]
  }
}
```

- `last_vault`: sciezka do ostatnio uzytego pliku vault (weryfikowana przez `os.path.exists` przy starcie).
- `column_widths`: szerokosci kolumn Interactive per tabela, zapisywane recznie przez uzytkownika (PPM na naglowek → "Zapisz szerokosci kolumn").

---

## Budowanie pliku wykonywalnego

```bat
build_exe.bat
```

Uzywa PyInstaller w trybie `--onefile`. Wynikowy `.exe` zawiera interpreter Python oraz wszystkie zaleznosci — nie wymaga instalacji Pythona na komputerze uzytkownika.

---

## Zaleznosci

```
PyQt6>=6.5.0        # GUI
cryptography>=41.0.0 # AES-256-GCM
argon2-cffi>=23.1.0  # Argon2id KDF
```
