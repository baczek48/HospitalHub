# HospitalHub V2 — rejestr znalezisk UX (Etap 71)

Audyt 2026-10-16: czterech niezależnych audytorów (A1 terminal/tmux, A2 wizualny, A3 ergonomia,
A4 scenariusze codzienne), offscreen z prawdziwymi fontami Windows, serwer SSH/SFTP paramiko
w procesie (socketpair, bez sieci). Pełne raporty z krokami reprodukcji poza repo (scratchpad sesji
2026-10-16, `ux\audit\A1..A4*.md`); tu — rejestr i stan.

**Statusy:** `NAPRAWIONE` (naprawione i zweryfikowane: test regresji + mutacja albo zrzut) ·
`POTWIERDZONE` (odtworzone, czeka) · `NIEROZWIĄZANE` (świadomie odłożone, powód w uwagach) ·
`RĘCZNY TEST` (wymaga prawdziwego ekranu/serwera/klienta) · `REDESIGN` (przeniesione do 71C).

**Priorytety:** P0 bezpieczeństwo / utrata danych / crash · P1 błąd funkcjonalny lub ryzyko pomyłki
na produkcji · P2 uciążliwość wizualna/ergonomiczna · P3 kosmetyka.

## Scenariusze i cykl życia (A4)

| ID | P | Znalezisko | Status | Commit / uwagi |
|---|---|---|---|---|
| S-01 | P0 | zerwane łącze SSH = „exit”: karta znika, auto-reconnect martwy, zapisy z edytora giną po cichu | NAPRAWIONE | `4ada670`, `0783bfe` — `exit_status`, przepięcie obserwacji na nowe połączenie; test na prawdziwym serwerze 5/5 |
| S-02 | P0 | zamknięcie okna SSH w trakcie transferu/listowania = crash procesu (0xC0000374) | NAPRAWIONE | `a62d6da` — pytanie, odłączenie sygnałów, `retire_thread`; mutacja 2 FAIL |
| S-03 | P0 | okna SSH ignorują blokadę admina i przeżywają zamknięcie vaulta | NAPRAWIONE | `6487113` |
| S-04 | P1 | nazwa pliku spoza UTF-8 blokuje listowanie katalogu SFTP | POTWIERDZONE | |
| S-05 | P1 | upuszczenie pliku w trakcie kolejki pobierania kasuje resztę kolejki | POTWIERDZONE | |
| S-06 | P1 | zerwanie w trakcie kolejki = N modalnych okien z surowymi wyjątkami | POTWIERDZONE | |
| S-07 | P1 | zmiana nazwy SFTP przyjmuje „/” — plik przenoszony gdzie indziej | POTWIERDZONE | |
| S-08 | P2 | zamknięcie okna z łączącymi się sesjami zamraża GUI ~1 s/sesję | NAPRAWIONE | `a62d6da` — jeden budżet 1 s |
| S-09 | P2 | VPN `get_status`/`disconnect` w wątku GUI przy kliknięciu; hasło w argumentach `FortiVPN.exe` | POTWIERDZONE | legacy `vpn_connect.py` jest zamrożony (niezmiennik) — poza zakresem 71; hasło w argumentach → do oceny bezpieczeństwa |
| S-10 | P1 | dodanie szpitala o istniejącej nazwie zaznacza stary szpital | POTWIERDZONE | = E-06 |
| S-11 | P3 | „Nowa sesja”: port „abc” → cicho 22; „host:port” → niezrozumiały błąd | POTWIERDZONE | = E-14 |
| S-12 | P3 | szerokość panelu Pliki resetowana przy każdym resize | POTWIERDZONE | |
| S-13 | P2 | wylogowanie Windows z niezapisanymi zmianami | RĘCZNY TEST | |

## Terminal (A1)

| ID | P | Znalezisko | Status | Commit / uwagi |
|---|---|---|---|---|
| T-01 | P1 | CSI S/T (SU/SD) ignorowane — tmux nakłada linie | NAPRAWIONE | `64a327a` — SU/SD w regionie |
| T-02 | P1 | Ctrl+C wyrzuca odebrane dane — tmux/vim z nieodświeżonym ekranem | NAPRAWIONE | `64a327a` — odrzucanie po Ctrl+C tylko na ekranie powłoki + reset parsera |
| T-03 | P1 | kolorowanie logów wstrzykuje SGR w tmux/vim/less | NAPRAWIONE | `64a327a` — bez podświetlania w alt-screen i w liniach z adresowaniem kursora |
| T-04 | P1 | brak alt-screen: po less/vim/htop zostaje ich klatka, śmieci w scrollbacku | NAPRAWIONE | `64a327a` — osobny bufor, powrót ekranu i kursora |
| T-05 | P2 | alt-screen przecieka do scrollbacka | NAPRAWIONE | `64a327a` — historia tylko z góry ekranu głównego |
| T-06 | P1 | UTF-8 rozcięte na granicy pakietu → `�` | NAPRAWIONE | `64a327a` — dekoder przyrostowy |
| T-07 | P2 | brak BCE przy ED — dziurawe tła mc/vim/htop | NAPRAWIONE | `64a327a` |
| T-08 | P2 | ramki ACS jako `lqqk` | NAPRAWIONE | `64a327a` |
| T-09 | P2 | brak odpowiedzi DA/DSR/CPR | NAPRAWIONE | `64a327a` — osobny sygnał term_reply (nie przez multi-exec) |
| T-10 | P3 | REP nieobsługiwane | NAPRAWIONE | `64a327a` |
| T-11 | P3 | `CSI s/u` ignorowane | NAPRAWIONE | `64a327a` |
| T-12 | P2 | kursor rysowany mimo `?25l` | NAPRAWIONE | `64a327a` |
| T-13 | P3 | podkreślenie/kursywa/przekreślenie/ukrycie nierysowane | NAPRAWIONE | `64a327a` — SGR 8 (ukrycie): pyte go nie przechowuje, NIEROZWIĄZANE |
| T-14 | P3 | znaki szerokie przesuwają tekst, kopiowanie ze spacjami | NAPRAWIONE | `64a327a` — rysowanie i kopiowanie |
| T-15 | P2 | U+FE0F / ZWJ ucina resztę linii (docker compose `✔️`) | NAPRAWIONE | `64a327a` |
| T-16 | P1 | klawisze z modyfikatorami (Ctrl/Alt/Shift+strzałki, Shift+Tab, Alt+litera, Insert…) | NAPRAWIONE | `64a327a` — AltGr = tekst; Alt i Shift+Tab na prawdziwym Windows: RĘCZNY TEST |
| T-17 | P3 | Home/End w trybie aplikacyjnym | NAPRAWIONE | `64a327a` |
| T-18 | P0 | wklejanie: brak bracketed paste, prawy klik wkleja wiele linii bez potwierdzenia | NAPRAWIONE | `64a327a` — CR, bracketed paste, pytanie przy wielu liniach / multi-exec (domyślnie Anuluj) |
| T-19 | P2 | debounce resize A→B→A zostawia rozmiar B | NAPRAWIONE | `64a327a` |
| T-20 | P2 | auto-reconnect nie resetuje trybów terminala | NAPRAWIONE | `64a327a` — miękki reset przy zerwaniu |
| T-21 | P3 | kopiowanie zawiniętej linii wstawia `\n` | NIEROZWIĄZANE | historia nie przechowuje znaczników zawinięcia; niski wpływ |
| T-22 | P3 | SGR z dwukropkami wypisuje śmieci | NAPRAWIONE | `64a327a` (+ vim CSI >4;2m nie jest już podkreśleniem) |
| T-23 | P3 | kursor w „pending wrap” poza ekranem; bez fokusu niewidoczny | NAPRAWIONE | `64a327a` |
| T-24 | P2 | brak raportowania myszy (tmux `mouse on`) | NAPRAWIONE | `64a327a` — ?1000/1002/1003 + SGR 1006, Shift = lokalnie |
| T-25 | P3 | znak szeroki w ostatniej kolumnie | NIEROZWIĄZANE | zachowanie pyte; niski wpływ |
| T-26 | — | zbiorczo: `xterm-256color` obiecuje więcej niż emulator | — | domykane przez T-01…T-24 |

## Wizualne (A2)

| ID | P | Znalezisko | Status | Commit / uwagi |
|---|---|---|---|---|
| V-01 | P1 | terminal gubi ~6 prawych kolumn przy domyślnym oknie (cols ≥ 80 wymuszone) | NAPRAWIONE | `64a327a` — rozmiar PTY = widoczny, min. widgetu 40×10 |
| V-02 | P1 | okno VPN: długie nazwy wypychają Połącz/Login/Hasło poza okno | POTWIERDZONE | |
| V-03 | P2 | nagłówek szpitala ucięty w pół litery; licznik „ukrytych” znika | POTWIERDZONE | |
| V-04 | P2 | lista szpitali: brak elipsy, poziomy pasek, brak tooltipa | POTWIERDZONE | |
| V-05 | P1 | kolumna „Akcje” poza ekranem przy małym oknie / DPI 150–200% | POTWIERDZONE | |
| V-07 | P2 | odmiana liczebników („1 ukrytych”, „22 maszyn”, „Pobrano 2 plików”, „tunel(i)”) | NAPRAWIONE | `44814c5` — wspólne plural() |
| V-08 | P2 | brak polskich znaków („haslo”, „Blad”, „Polacz”) | POTWIERDZONE | |
| V-09 | P2 | „Cancel”, „&Yes/&No” — brak tłumaczeń Qt | POTWIERDZONE | = E-16 |
| V-10 | P2 | jasny motyw: wyłączony „Wgraj” = czarny prostokąt | POTWIERDZONE | |
| V-11 | P3 | jasny motyw: ciemne ikony plików SFTP | POTWIERDZONE | |
| V-12 | P2 | błąd SSH jako modal „SFTP” (dubel komunikatu w terminalu) | POTWIERDZONE | = E-15 |
| V-13 | P3 | „⚠” w terminalu jako tofu | RĘCZNY TEST | |
| V-14 | P3 | pionowa kreska przy „Szpitale” | POTWIERDZONE | |
| V-15 | P3 | brak stanów pustych; „Brak profili VPN” kontrast ~2:1 | POTWIERDZONE | |
| V-16 | P3 | „Usuń” w ciemnym motywie słabo czytelne | POTWIERDZONE | |
| V-17 | P3 | placeholder portu „22 (dom…” | POTWIERDZONE | |
| V-18 | P3 | nagłówek SFTP „UPRAWNIENI” | POTWIERDZONE | |
| V-19 | P2 | okno VPN: rozmiar dryfuje po edycji, min. 640 zostaje | POTWIERDZONE | |
| V-20 | — | niespójne dialogi (paleta, kolejność przycisków, etykiety) | REDESIGN | |
| V-21 | — | ikony-glify i emoji | REDESIGN | |
| V-22 | P3 | Ustawienia VPN: lista ścieżek zapada się | RĘCZNY TEST | |
| V-23 | P2 | domyślne rozmiary okien nie mieszczą się na 1366×768 @150% | RĘCZNY TEST | |
| V-24 | P3 | drobne teksty („tutaj aby”, „<-  Wróć”) | POTWIERDZONE | |
| V-25 | P3 | nagłówki tabeli maszyn | POTWIERDZONE | |

## Ergonomia (A3)

| ID | P | Znalezisko | Status | Commit / uwagi |
|---|---|---|---|---|
| E-01 | P1 | Esc poza terminalem zamyka okno SSH ze wszystkimi sesjami | NAPRAWIONE | `a62d6da` |
| E-02 | P1 | zamknięcie okna z wieloma sesjami bez pytania | NAPRAWIONE | `a62d6da` — pytanie przy ≥ 2 żywych sesjach lub transferze |
| E-03 | P2 | „Ctrl+F” z podpowiedzi wysyła `^F` na serwer | NAPRAWIONE | `64a327a` — Ctrl+Shift+F |
| E-04 | P1 | panel Środowisko: pojedynczy klik łączy, każdy kolejny = nowa sesja/RDP | POTWIERDZONE | |
| E-05 | P0 | prawy klik wkleja wieloliniowy schowek (także do wszystkich sesji multi-exec) | NAPRAWIONE | = T-18 |
| E-06 | P1 | duplikat nazwy szpitala; po dodaniu zaznaczony STARY | POTWIERDZONE | = S-10 |
| E-07 | P0 | potwierdzenia usunięcia z domyślnym „Tak/Yes” — Enter kasuje szpital | NAPRAWIONE | `44814c5` — domyślnie Nie/Anuluj (Enter i Esc), liczby w pytaniu o szpital |
| E-08 | P1 | przycisk z loginem kopiuje hasło; loginu nie da się skopiować | POTWIERDZONE | |
| E-09 | P2 | tylko pierwsze poświadczenie dostępne z widoku | REDESIGN | |
| E-10 | P2 | wyszukiwarka tylko po nazwie szpitala; Enter/↓ nic; filtr gubi zaznaczenie | POTWIERDZONE | |
| E-11 | P2 | brak Delete/F2/Enter/F5 na listach i w SFTP | POTWIERDZONE | |
| E-12 | P2 | Tab utyka w tabelach | POTWIERDZONE | |
| E-13 | P2 | Esc w dialogach porzuca zmiany bez pytania | POTWIERDZONE | |
| E-14 | P2 | porty bez walidacji (cicho 22, „abc” zapisane) | POTWIERDZONE | |
| E-15 | P2 | komunikaty SSH jako modal „SFTP”, sukcesy giną, surowe wyjątki | POTWIERDZONE | |
| E-16 | P2 | Yes/No obok Tak/Nie; brak polskich znaków w dialogach admina | POTWIERDZONE | |
| E-17 | — | niespójne kontrolki dla tych samych akcji | REDESIGN | |
| E-18 | P2 | okna SSH o identycznym tytule; nieaktualne dane po zmianach w vaulcie | POTWIERDZONE | część (blokada admina) w S-03 |
| E-19 | P3 | złe hasło admina zamyka dialog | POTWIERDZONE | |
| E-20 | P2 | VPN w nagłówku: pierwszy klik tylko wczytuje vault; status synchronicznie | NIEROZWIĄZANE | dotyka legacy VPN (niezmiennik) |
| E-21 | P2 | pierwsze RDP: synchroniczne PowerShell bez informacji zwrotnej | RĘCZNY TEST | |
| E-22 | P2 | SFTP: „Usuń” na jednym, „Pobierz” na zaznaczeniu | POTWIERDZONE | |
| E-23 | P2 | VPN: „+ Dodaj” tworzy profil od razu; „Wróć” zostawia śmieć; Esc nie wraca | POTWIERDZONE | |
| E-24 | P3 | klik w komórkę kopiuje jak sekret (czyszczony po 15 s); wyjątek w animacji | POTWIERDZONE | |
| E-25 | P2 | multi-exec: „Duplikuj” ignorowane, aktywna = zawsze pierwsza sesja | POTWIERDZONE | |
| E-26 | P3 | każdy znak w notatkach przebudowuje listę szpitali | POTWIERDZONE | |
