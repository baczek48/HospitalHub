# HospitalHub

> © 2026 Sebastian Bąk. Wszelkie prawa zastrzeżone.

Menedzer danych infrastruktury IT dla szpitali. Przechowuje adresy IP maszyn, dane dostepu do baz danych oraz poswiadczenia w jednym zaszyfrowanym pliku `.vault`.

---

## Pierwsze uruchomienie

Przy pierwszym uruchomieniu aplikacja zapyta o utworzenie nowego vaulta lub otwarcie istniejacego.

### Tworzenie nowego vaulta

1. Kliknij **Utworz nowy vault**.
2. Wybierz lokalizacje i nazwe pliku (np. `infrastruktura.vault`).
3. Ustaw haslo glowne — minimum 8 znakow. Haslo musi byc silne, poniewaz chroni wszystkie dane.
4. Kliknij **Utworz vault** — aplikacja otworzy sie z pustym vaultem.

### Otwarcie istniejacego vaulta

1. Kliknij **Otworz istniejacy vault**.
2. Wskazplik `.vault`.
3. Podaj haslo glowne.

Po pierwszym otwarciu aplikacja zapamietuje sciezke do pliku. Nastepne uruchomienie pokazuje od razu pole hasla — bez koniecznosci wskazywania pliku ponownie.

---

## Struktura danych

Dane sa zorganizowane hierachicznie:

```
Szpital
  Maszyny / Hosty
    Adres IP
    Nazwa
    Opis
    Poswiadczenia (login + haslo + notatka, mozna dodac wiele)
  Bazy danych
    Host, Port, Nazwa bazy, Typ (MSSQL / Oracle / PostgreSQL / ...)
    Login, Haslo, Notatka
  Notatki o srodowisku (dowolny tekst)
```

---

## Podstawowa obsługa

### Dodawanie szpitala

Kliknij **+ Dodaj szpital** w lewym panelu, wpisz nazwe i zatwierdz.

### Dodawanie maszyny

Po wybraniu szpitala z listy, w prawym panelu kliknij **+ Dodaj maszyne**.
Wypelnij pola IP (wymagane), Nazwa, Opis.
W oknie maszyny mozna od razu dodac poswiadczenia — kliknij **+ Dodaj poswiadczenie**.

### Dodawanie bazy danych

Kliknij **+ Dodaj baze danych**, wypelnij Host (wymagane), Port, Nazwe bazy, Typ, Login, Haslo, Notatke.

### Edycja i usuwanie

Kazdy wiersz w tabeli ma przyciski **Edytuj** i **Usun** po prawej stronie (kolumna Akcje).

### Zmiana kolejnosci wierszy

Wiersze w tabelach mozna przestawiac przeciagajac i upuszczajac (drag & drop).

---

## Kopiowanie danych do schowka

Klikniecie dowolnej komorki w tabeli (IP, Nazwa, Opis, Host, Port itd.) kopiuje jej zawartosc do schowka.

Przycisk z nazwa uzytkownika (kolumna Akcje) kopiuje **haslo** tego uzytkownika do schowka.
Tooltip przycisku pokazuje, czyje haslo zostanie skopiowane.

---

## Zapis

Zmiany **nie sa zapisywane automatycznie**. Pasek tytulowy pokazuje `[niezapisane]` gdy sa niezapisane zmiany.

| Akcja | Skrot |
|---|---|
| Zapisz | `Ctrl+S` |
| Zapisz jako / Eksportuj kopie | `Ctrl+Shift+S` |

Przy zamykaniu aplikacji z niezapisanymi zmianami pojawi sie pytanie o zapis.

---

## Zmiana hasla glownego

Menu **Plik → Zmien haslo glowne...**
Nalezy podac biezace haslo, nowe haslo (min. 8 znakow) i je potwierdzic.
Vault zostaje natychmiast ponownie zaszyfrowany nowym haslem i zapisany.

---

## Wspoldzielenie vaulta z innymi osobami

Plik `.vault` jest w calosci zaszyfrowany — mozna go bezpiecznie przeslac przez e-mail lub komunikator.
Odbiorca otwiera go w swojej kopii HospitalHub tym samym haslem glownym.

Kazda osoba pracuje na swojej kopii pliku. Przy aktualizacji przesyla sie zaktualizowany plik.

---

## Ustawienia kolumn

Szerokosc kolumn w tabelach mozna zmieniac przeciagajac krawedzie naglowkow.
Kliknij prawym przyciskiem myszy na naglowek tabeli i wybierz **Zapisz szerokosci kolumn**, aby zapamietac biezacy uklad na stale.

---

## Bezpieczenstwo

- Wszystkie dane sa szyfrowane algorytmem **AES-256-GCM**.
- Klucz szyfrujacy jest wyprowadzany z hasla glownego za pomoca **Argon2id** (64 MB RAM, 3 iteracje) — silna ochrona przed atakami brute-force.
- Kazdy zapis generuje nowe losowe **salt** i **nonce** — ten sam plik zaszyfrowany dwa razy da rozne wyniki.
- Zapis jest **atomowy**: dane trafiaja najpierw do pliku tymczasowego, a dopiero po pomyslnym zapisie zastepuja oryginalny plik. Awaria w trakcie zapisu nie uszkodzi vaulta.
- Haslo nie jest nigdzie przechowywane — jedynie sciezka do pliku jest zapamietana lokalnie w `%APPDATA%\HospitalHub\config.json`.

---

## Wymagania systemowe

- Windows 10 / 11
- Python 3.11+ (jezeli uruchamiane ze zrodla)
- Lub plik `.exe` (jezeli dostarczony jako skompilowana aplikacja)
