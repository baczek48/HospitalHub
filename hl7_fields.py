# Copied from hl7_scout/hl7_fields.py (2026-11-19) for the "Rejestr HL7" window
# of HospitalHub Portable; keep the two in step by hand.
# Copyright © 2026 Sebastian Bąk. All rights reserved.
# HL7 v2.x field definitions — InfoMedica / AMMS (Asseco Poland)
# Źródło: "Komunikaty HL7 w InfoMedica, AMMS" ver. 2.12.6.6 (2025-05-06)

# Segment name → (short name, description)
SEGMENT_INFO = {
    "MSH": ("Message Header",
            "Nagłówek komunikatu — obecny w każdym komunikacie. Zawiera typ komunikatu, "
            "aplikację wysyłającą/odbierającą, datę i wersję HL7."),
    "EVN": ("Event Type",
            "Typ zdarzenia wyzwalającego komunikat ADT (przyjęcie, wypis, modyfikacja danych)."),
    "PID": ("Patient Identification",
            "Dane demograficzne pacjenta: PESEL (PID.2), MIP InfoMedica (PID.3), "
            "imię/nazwisko, data urodzenia, adres, telefon, obywatelstwo."),
    "PD1": ("Patient Additional Demo",
            "Dodatkowe dane demograficzne pacjenta."),
    "NK1": ("Next of Kin",
            "Dane osoby do kontaktu / najbliższej rodziny pacjenta."),
    "PV1": ("Patient Visit",
            "Informacje o wizycie/pobycie pacjenta: oddział (PV1.3), typ pacjenta "
            "(I=hospitalizowany, O=ambulatoryjny, E=izba przyjęć), numer księgi (PV1.19)."),
    "PV2": ("Patient Visit - Additional",
            "Dodatkowe informacje o wizycie."),
    "ORC": ("Common Order",
            "Wspólne elementy zlecenia. ORC.1 = komenda (NW=nowe, CA=anuluj, RF=modyfikacja). "
            "ORC.5 = status (IP=w trakcie, CM=zakończone). ORC.12 = lekarz zlecający."),
    "OBR": ("Observation Request",
            "Zlecenie/wynik badania. OBR.4 = kod badania, OBR.7 = data wykonania, "
            "OBR.25 = status wyniku (F=finalny, C=korekta). OBR.16 = lekarz zlecający."),
    "OBX": ("Observation / Result",
            "Pojedynczy składnik wyniku. OBX.2 = typ (NM=liczba, CE=kodowany, FT=formatowany tekst, "
            "TX=tekst, ST=krótki tekst, SN=num. strukturalny). OBX.8 = przekroczenie normy (H/L/A/N)."),
    "NTE": ("Notes and Comments",
            "Notatki i komentarze. NTE.2 = typ: P=uwagi zlecającego, PP=uwagi pobranie materiału, "
            "W=uwagi wykonującego, KO=komentarz obok wyniku."),
    "AL1": ("Allergy Information",
            "Informacje o alergii pacjenta."),
    "DG1": ("Diagnosis",
            "Diagnoza ICD-10. DG1.3 = kod ICD, DG1.6 = typ (A=do przyjęcia, W=wstępna, F=końcowa). "
            "DG1.17 = klasyfikacja (SK=składniki leczenia)."),
    "PR1": ("Procedures",
            "Wykonana procedura medyczna."),
    "MRG": ("Merge Patient Information",
            "Połączenie rekordów pacjenta — używany w komunikatach ADT^A30."),
    "MSA": ("Message Acknowledgment",
            "Potwierdzenie komunikatu. Transport: CA=przyjęto, CE=błąd chwilowy, CR=odrzucono. "
            "Aplikacyjne: AA=przyjęto, AE=błąd, AR=odrzucono."),
    "ERR": ("Error",
            "Informacja o błędzie przetwarzania."),
    "IN1": ("Insurance",
            "Informacje o ubezpieczeniu. IN1.3 = nr oddziału NFZ (np. 02), IN1.15 = typ skierowania "
            "(N=NFZ, U=umowa płatnik)."),
    "IN2": ("Insurance - Additional",
            "Dodatkowe dane ubezpieczenia."),
    "GT1": ("Guarantor",
            "Dane gwaranta / płatnika."),
    "SCH": ("Scheduling Activity",
            "Dane harmonogramowania — rejestracja wizyty."),
    "QRD": ("Query Definition",
            "Definicja zapytania — używana w komunikatach QRY^A19 (pytanie o dane pacjenta). "
            "QRD.8 = identyfikator pacjenta (MIP lub PESEL)."),
    "QRF": ("Query Filter",
            "Filtr zapytania."),
    "BPO": ("Blood Product Order",
            "Zamówienie preparatu krwi — używane w komunikatach OMB^O27 (bank krwi)."),
    "BPX": ("Blood Product Dispense Status",
            "Status realizacji zamówienia krwi."),
    "RXO": ("Pharmacy Order",
            "Zlecenie farmakologiczne."),
    "RXE": ("Pharmacy Encoded Order",
            "Zakodowane zlecenie farmakologiczne — używane w komunikatach RDE^O01 (UNITDOSE)."),
    "RXD": ("Pharmacy Dispense",
            "Wydanie leku z apteki."),
    "RXA": ("Pharmacy Administration",
            "Podanie leku pacjentowi — używane w komunikatach RAS^O17."),
    "RXR": ("Pharmacy Route",
            "Droga podania leku."),
    "SLT": ("Sterilization Lot",
            "Zestaw narzędzi — używany w komunikatach sterylizatornii (SLR^S28, SLN^S34)."),
    "MFE": ("Master File Entry",
            "Wpis słownika głównego — używany w komunikatach MFN (synchronizacja słowników)."),
    "ZDP": ("Z-Segment: Drug Properties",
            "Segment niestandardowy — właściwości leku (UNITDOSE/Eskulap Chemioterapia)."),
    "ZDR": ("Z-Segment: Drug Record",
            "Segment niestandardowy — rekord leku."),
    "ZIG": ("Z-Segment: Inventory/Goods",
            "Segment niestandardowy — przyjęcie towaru do magazynu apteki."),
    "ZPI": ("Z-Segment (Custom)",
            "Segment niestandardowy — definicja lokalna wdrożenia InfoMedica/AMMS."),
}

# Segment → field number → (name, description)
FIELD_INFO = {
    "MSH": {
        1:  ("Separator pola",
             "Separator pól — stała wartość `|`."),
        2:  ("Znaki specjalne",
             "Znaki kodowania separatorów: komponentów `^`, powtórzeń `~`, ucieczki `\\`, "
             "subkomponentów `&`. Stała wartość `^~\\&`."),
        3:  ("Aplikacja wysyłająca",
             "Kod systemu wysyłającego zgodny z tabelą ZEWN_SYS w InfoMedica. "
             "Np. SZPM = InfoMedica-Szpital, lub kod systemu zewnętrznego np. SYZ1."),
        4:  ("Urządzenie wysyłające",
             "Nie używane w InfoMedica dla aplikacji SZPM."),
        5:  ("Aplikacja odbierająca",
             "Kod systemu odbierającego zgodny z tabelą ZEWN_SYS. Np. SZPM lub SYZ1."),
        6:  ("Urządzenie odbierające",
             "Nie używane w InfoMedica."),
        7:  ("Data/czas wygenerowania",
             "Data i czas utworzenia komunikatu. Format: YYYYMMDDHHMMSS."),
        8:  ("Bezpieczeństwo",
             "Nie używane w InfoMedica."),
        9:  ("Typ komunikatu",
             "Typ i zdarzenie komunikatu, np. ORM^O01 (zlecenie), ORU^R01 (wynik), "
             "ADT^A01 (przyjęcie), ACK (potwierdzenie)."),
        10: ("Identyfikator komunikatu",
             "Unikalny identyfikator komunikatu — zalecany prefiks oznaczający system "
             "wysyłający i rodzaj zawartości (np. SZ=Szpital, Z=zlecenie → SZ01F28)."),
        11: ("Tryb interpretacji",
             "P = tryb produkcyjny (modyfikuje dane w systemie). "
             "D = tryb uruchomieniowy (dane testowe, nie wpływa na bazę)."),
        12: ("Wersja standardu HL7",
             "Wersja HL7 używana przez InfoMedica: 2.3."),
        15: ("Potwierdzanie transportowe",
             "Typ potwierdzenia transportowego. InfoMedica wysyła AL (zawsze)."),
        16: ("Potwierdzanie aplikacyjne",
             "Typ potwierdzenia aplikacyjnego. InfoMedica wysyła AL (zawsze)."),
        17: ("Kraj",
             "Kod kraju. InfoMedica wysyła PL (Polska)."),
        18: ("Zestaw znaków",
             "Kodowanie znaków: 8859/2 (ISO 8859-2) lub CP1250 (Windows). "
             "Domyślnie CP1250 gdy pole puste. Obsługiwane też: utf8 (UTF-8, znaki \\Xdddd\\)."),
        19: ("Język komunikatu",
             "Zasadniczy język komunikatu. InfoMedica wysyła PL (polski)."),
    },
    "PID": {
        1:  ("Id. wystąpienia segmentu",
             "Numer kolejny segmentu PID. Zwykle 1 — tylko jedno wystąpienie w komunikacie."),
        2:  ("Zewnętrzny id. pacjenta (PESEL)",
             "Numer PESEL pacjenta. W InfoMedica przesyłany w tym polu."),
        3:  ("Id. pacjenta wewnętrzny (MIP)",
             "Medyczny Identyfikator Pacjenta (MIP) — identyfikator techniczny pacjenta "
             "w systemie InfoMedica."),
        4:  ("Alternatywny id. pacjenta",
             "Dodatkowe identyfikatory: DT=dowód tożsamości, PA=paszport, DTUE=dokument UE, "
             "EKUZ=karta ubezpieczenia, PJ=prawo jazdy, KZ=książeczka żeglarska, "
             "NN=pacjent nieznany. Format: <KOD>^^^^<TYP>~<KOD>^^^^<TYP>…"),
        5:  ("Nazwisko i imię pacjenta",
             "Format: <Nazwisko>^<Pierwsze imię>^<Drugie imię>. "
             "PID.5.7 = typ danych: pusta=zwykłe, C=Confidential (ograniczony dostęp)."),
        6:  ("Nazwisko rodowe",
             "Nazwisko panieńskie / rodowe pacjenta."),
        7:  ("Data urodzenia",
             "Data urodzenia w formacie YYYYMMDD."),
        8:  ("Płeć",
             "M = mężczyzna, F = kobieta, U = nieznana."),
        9:  ("Alias pacjenta",
             "Nie używane w InfoMedica."),
        10: ("Rasa",
             "Nie używane w InfoMedica."),
        11: ("Adres pacjenta",
             "Format: <ulica>^^<miasto>^^^^^<kod terytorialny GUS>. "
             "Komponent 5 = kod pocztowy, komponent 8 = kod terytorialny GUS. "
             "Ulica może być podzielona subkomponentami: ulica&nr domu&nr mieszkania."),
        12: ("Region",
             "Nie używane w InfoMedica."),
        13: ("Telefon domowy",
             "Numer telefonu domowego pacjenta. Jeśli wprowadzono email, przesyłany "
             "w dodatkowym powtórzeniu: ^NET^^adres@email.com."),
        14: ("Telefon do pracy",
             "Nie używane w InfoMedica."),
        15: ("Główny język komunikacji",
             "Nie używane w InfoMedica."),
        16: ("Stan cywilny",
             "Nie używane w InfoMedica."),
        17: ("Religia",
             "Nie używane w InfoMedica."),
        18: ("Konto finansowe pacjenta",
             "Nie używane w InfoMedica."),
        19: ("Nr ubezpieczenia",
             "Nie używane w InfoMedica."),
        20: ("Nr prawa jazdy",
             "Nie używane w InfoMedica."),
        21: ("Identyfikacja matki / opiekuna",
             "Identyfikatory opiekuna (dla noworodków). Typy: OP=PESEL opiekuna, "
             "DT=dowód, PA=paszport, NII=imię i nazwisko, KKP=kod kraju pochodzenia. "
             "Format: <KOD>^^^^<TYP>~… W przypadku PESEL wysyłana dodatkowo stała PESEL w CX.4."),
        22: ("Grupa etniczna / pochodzenie",
             "Dane o pochodzeniu etnicznym ze słownika AMMS: POCH_ETNICZNE. "
             "Możliwość przekodowania wartości dla systemów zewnętrznych."),
        23: ("Miejsce urodzenia",
             "Nie używane w InfoMedica."),
        24: ("Znacznik porodu mnogiego",
             "Nie używane w InfoMedica."),
        25: ("Nr kolejny noworodka w porodzie",
             "Numer kolejny noworodka w porodzie mnogim. Może być puste."),
        26: ("Obywatelstwo",
             "Kod kraju pochodzenia/obywatelstwa zgodnie ze słownikiem AMMS (np. PL)."),
    },
    "PV1": {
        1:  ("Id. wystąpienia segmentu",
             "Numer kolejny segmentu PV1. Zwykle 1."),
        2:  ("Rodzaj pacjenta",
             "I = pacjent hospitalizowany, O = pacjent ambulatoryjny, "
             "E = pacjent na izbie przyjęć."),
        3:  ("Lokalizacja pacjenta",
             "Kod jednostki organizacyjnej (oddziału, gabinetu) wg tabeli JOS InfoMedica. "
             "Format: <Kod JOS>^^^^^^^<Odcinek>^<Nazwa jednostki>. "
             "Komponent 1 = kod JOS, komponent 8 = odcinek w ramach JOS, komponent 9 = nazwa."),
        18: ("Typ pacjenta",
             "1 = świadczenie specjalistyczne pierwszorazowe, "
             "2 = świadczenie specjalistyczne, "
             "3 = świadczenie po hospitalizacyjne, "
             "4 = szybka ścieżka onkologiczna."),
        19: ("Numer pobytu / wizyty",
             "Identyfikator pobytu lub numer księgi głównej. "
             "Format: <numer>^<id opieki>^^<system>^VN^<kod księgi>. "
             "PV1.19.1 = numer <nr>/<rok> lub <nr>-<nr_rozszerzony>/<rok>. "
             "PV1.19.2 = identyfikator techniczny opieki w AMMS. "
             "PV1.19.3 = identyfikator techniczny pobytu w AMMS. "
             "PV1.19.4 = stała 'SZPM'. PV1.19.5 = stała 'VN'. PV1.19.6 = id księgi głównej."),
        44: ("Data przyjęcia",
             "Data i czas rozpoczęcia pobytu (przyjęcia pacjenta)."),
        45: ("Data wypisu",
             "Data i czas zakończenia pobytu (wypisu pacjenta), jeśli wypis nastąpił."),
    },
    "IN1": {
        1:  ("Id. wystąpienia segmentu",
             "Numer kolejny segmentu IN1. Zwykle 1."),
        2:  ("Plan ubezpieczeniowy",
             "Nie używane w InfoMedica."),
        3:  ("Ubezpieczyciel / nr NFZ",
             "Numer oddziału NFZ pacjenta (np. 02 = Śląski OW NFZ). "
             "Opcjonalnie ID płatnika jako powtórzenie: <nfz>~<id_platnika>."),
        15: ("Typ planu / skierowanie",
             "N = skierowanie NFZ, U = umowa z płatnikiem. "
             "Wysyłanie zależy od konfiguracji systemu."),
    },
    "ORC": {
        1:  ("Komenda zlecenia",
             "NW = nowe zlecenie, CA = anulowanie zlecenia, "
             "RF = modyfikacja (OPK/urządzenie/jednostka), RE = wynik zlecenia."),
        2:  ("Nr zlecenia u zleceniodawcy",
             "Identyfikator zlecenia nadany przez InfoMedica (zleceniodawcę)."),
        3:  ("Nr zlecenia u wykonawcy",
             "Identyfikator zlecenia nadany przez system zewnętrzny (wykonawcę). "
             "Nie używane w komunikacie nowego zlecenia z InfoMedica."),
        4:  ("Nr grupy zleceń",
             "Identyfikator techniczny grupy zleceń (panel główny InfoMedica). "
             "Puste gdy zlecenie nie jest zgrupowane w panelu."),
        5:  ("Status zlecenia",
             "IP = In Process (w trakcie realizacji), CM = Complete (zakończone), "
             "CA = Cancelled (anulowane). Wysyłany przy modyfikacji ORC.1=RF."),
        6:  ("Znacznik odpowiedzi",
             "W = realizacja bez opisu — system zewnętrzny nie odsyła ORU^R01, "
             "tylko zmianę stanu zlecenia z statusem NAUT."),
        7:  ("Plan wykonań / priorytet",
             "Komponent 4 = planowana data wykonania. "
             "Komponent 6 = priorytet: R=rutynowo, S=pilnie (cito), T=bardzo pilne (histopatologia)."),
        8:  ("Nr zlecenia nadrzędnego",
             "Identyfikator zlecenia nadrzędnego (jeśli zlecenie jest podzleceniem)."),
        9:  ("Moment zlecenia",
             "Data i czas wystawienia zlecenia. Format: YYYYMMDDHHMMSS."),
        12: ("Wydane przez (lekarz zlecający)",
             "Lekarz będący autorem zlecenia. Format: <ID>^<Nazwisko>^<Imię>^^^^^^<stopień>^^<PRZAW&nr_PWZ>^^^^LEK. "
             "Komponent 13 = słownik: LEK (lekarze) lub UZY (użytkownicy). "
             "Komponent 9.1 = typ identyfikatora, 9.2 = wartość (np. PRZAW&<nr_PWZ>). "
             "Komponent 15 = kody specjalizacji jako powtórzenia: <główna>~<dodatkowa1>~…"),
        13: ("Miejsce wprowadzenia zlecenia",
             "Identyfikator odcinka oddziałowego ze słownika JOS InfoMedica."),
        14: ("Telefon zwrotny",
             "Numer telefonu zwrotnego do zlecającego."),
        17: ("Jednostka organizacyjna",
             "Jednostka organizacyjna, w której wprowadzono zlecenie. "
             "Zwykle to samo co PV1.3, ale może być inna (np. blok operacyjny). "
             "Format: <Kod>^<Nazwa>^<Słownik>. Słownik: JOS = jedn. org. szpitala, INST = instytucja ze skierowania. "
             "Dla parametru DDIK dodawane są pola 9 i 10 z danymi instytucji kierującej."),
    },
    "OBR": {
        1:  ("Id. wystąpienia segmentu",
             "Numer kolejny segmentu OBR w komunikacie."),
        2:  ("Nr zlecenia u zleceniodawcy",
             "Identyfikator zlecenia nadany przez InfoMedica. Puste dla badań nie zleconych."),
        3:  ("Nr zlecenia u wykonawcy",
             "Identyfikator zlecenia nadany przez system zewnętrzny (laboratorium, RIS itp.). "
             "Wymagane jeśli przesyłane są wyniki bez zlecenia z InfoMedica."),
        4:  ("Id. zleconej usługi / badania",
             "Kod badania wg słownika Elementów Leczenia InfoMedica (WERF). "
             "Format: <kod>^<nazwa>. Dla parametru ELMA wartość pobierana z OBR.15."),
        7:  ("Data wykonania / planowana",
             "Data i czas wykonania badania lub moment zlecenia (gdy data wykonania niedostępna). "
             "Format: YYYYMMDDHHMMSS."),
        10: ("Osoba pobierająca materiał",
             "Identyfikator osoby pobierającej materiał laboratoryjny. "
             "Format: <ID>^<Nazwisko>^<Imię>. Dana dostępna jeśli uzupełniona w module Punkt pobrań."),
        13: ("Rozpoznanie na zleceniu",
             "Kod rozpoznania ICD-10 dołączony do zlecenia. "
             "Format: <kod ICD-10>^<nazwa>. Nazwa wysyłana przy parametrze RONA."),
        14: ("Data pobrania materiału",
             "Data i czas pobrania materiału do badania. Format: YYYYMMDDHHMMSS."),
        15: ("Pobrany materiał",
             "Informacja o pobranym materiale wg słownika InfoMedica. "
             "Format: <kod>&<nazwa>&<system>. Np. KP&Krew pełna&SZPM."),
        16: ("Zlecenie wydane przez (lekarz)",
             "Lekarz zlecający — to samo co ORC.12."),
        18: ("Numer pobranego materiału",
             "Identyfikator nadany przy pobraniu materiału (numer próbki)."),
        19: ("Pole zleceniodawcy / dodatkowe dane",
             "Lista dodatkowych parametrów zlecenia oddzielona `^`: "
             "<OPK>^<IDZBK>^<CZY_PRZY_LOZKU>^<ESKIEROWANIE>^<NUMER_UMOWY_NFZ>^…. "
             "OPK = ośrodek powstawania kosztów, IDZBK = id zamówienia do banku krwi, "
             "CZY_PRZY_LOZKU = 1/0, ESKIEROWANIE = ROOT&EXT&KLUCZ&KOD, NUMER_UMOWY_NFZ."),
        21: ("Identyfikator zdarzenia medycznego (P1)",
             "UUID zdarzenia medycznego raportowanego do platformy P1 w systemie AMMS. "
             "Format UUID: 123e4567-e89b-12d3-a456-426614174000."),
        24: ("Jednostka wykonująca",
             "Kod jednostki wykonującej badanie ze słownika JOS InfoMedica, "
             "lub zasoby miejsca urządzenia. Wysyłanie zależne od konfiguracji."),
        25: ("Status wyniku",
             "F = finalny (zweryfikowany), C = korekta finalnego wyniku, "
             "P = wstępny (preliminarny). Używany zarówno w zleceniach jak i wynikach."),
        27: ("Krotność wykonania",
             "Liczba krotności wykonania badania — ważna przy rozliczeniu z NFZ."),
        29: ("Nr zlecenia nadrzędnego",
             "Identyfikator wyniku nadrzędnego dla badań dodatkowych (dozleconych). "
             "Format: <OBR.2_nadrzędnego>^<OBR.3_nadrzędnego>."),
        32: ("Lekarz wykonujący",
             "Lekarz wykonujący badanie. Format: <ID>&<Nazwisko>&<Imię>^. "
             "ID musi istnieć w słowniku SLU_OSOBA_ZLEC."),
        33: ("Lekarz opisujący / konsultujący",
             "Lekarz opisujący ~ Lekarz konsultujący 1 ~ Lekarz konsultujący 2 ~ … "
             "Format: <ID>&<Nazwisko>&<Imię>~. Pierwsze wystąpienie = opisujący, kolejne = konsultanci."),
        34: ("Technik wykonujący",
             "Technik wykonujący badanie. Format: <ID>&<Nazwisko>&<Imię>^. "
             "ID musi istnieć w słowniku SLU_OSOBA_ZLEC."),
    },
    "OBX": {
        1:  ("Id. wystąpienia segmentu",
             "Numer kolejny segmentu OBX w komunikacie."),
        2:  ("Typ wartości",
             "NM = wynik numeryczny, CE = wynik kodowany (z normą), "
             "FT = wynik tekstowy sformatowany (znaki \\. br\\ = nowa linia), "
             "TX = wynik tekstowy wielowierszowy (bez interpretacji jednostki/normy), "
             "ST = krótki tekst (tabelaryczny), SN = numeryczny strukturalny (np. >300), "
             "RP = odnośnik (URL do obrazu/dokumentu)."),
        3:  ("Id. wykonanej usługi / badania",
             "Identyfikator składnika wyniku. Format: <kod>^<nazwa>^<system>. "
             "System: kod laboratorium lub SZPM. "
             "Specjalne kody: URL/URLZ = odnośniki, MJPG = miniatura JPG (Base64), "
             "SARSCOV2 = wynik testu SARS-CoV-2."),
        4:  ("Nr grupujący wyniki cząstkowe",
             "Łączy wyniki cząstkowe tego samego badania. Dla mikrobiologii: "
             "musi być zgodny z OBR.26.2 dla antybiogramów."),
        5:  ("Wartość wyniku",
             "Wartość wyniku — typ zależy od OBX.2. "
             "Dla FT: tekst z formatowaniem (\\.br\\ = nowa linia). "
             "Dla CE/NM: wartość liczbowa lub tekstowa. "
             "OBX.5.2 = opis słowny wartości (np. '25,7 %' dla wartości procentowej)."),
        6:  ("Jednostka miary",
             "Jednostka miary wyniku (np. mmol/kg, m/uL, g/dL, %). "
             "Dostępna dla typów CE, NM, ST, SN."),
        7:  ("Wartość referencyjna / norma",
             "Zakres referencyjny (norma), np. 4-10, 4.80-10.80. "
             "Jeśli dłuższa niż 30 znaków lub zawiera znaki nowej linii — "
             "traktowana jako opisowa i pokazywana pod wynikiem."),
        8:  ("Przekroczenie normy",
             "L = poniżej normy, H = powyżej normy, A = wynik poza normą, "
             "N = wynik w normie, pusta = nieokreślona. "
             "OBX.8.2 = dodatkowa wartość alarmowa (parametr ALP#, np. 'wynik alarmowy')."),
        11: ("Status wyniku",
             "F = finalny (zweryfikowany przez autoryzującego), "
             "P = wstępny, C = korekta, X = anulowany."),
        14: ("Data i czas składnika wyniku",
             "Data uzyskania konkretnego składnika wyniku (Format: YYYYMMDDHHMMSS). "
             "Data wykonania całości badania pobierana jest z OBR.7."),
        16: ("Identyfikator osoby autoryzującej",
             "Identyfikator użytkownika InfoMedica lub identyfikator z systemu zewnętrznego "
             "(wymaga konfiguracji przekodowań), który autoryzował wynik."),
    },
    "NTE": {
        1:  ("Id. wystąpienia segmentu",
             "Numer kolejny segmentu NTE."),
        2:  ("Typ komentarza",
             "P = uwagi od zlecającego (część zlecenia), "
             "PP = uwagi związane z pobraniem materiału, "
             "W = uwagi wykonującego (nie są składnikiem wyniku — widoczne jako dodatkowy komentarz), "
             "KO = komentarz obok wyniku (krótki, wyświetlany w wierszu wyniku)."),
        3:  ("Treść komentarza",
             "Treść notatki lub komentarza."),
    },
    "DG1": {
        1:  ("Id. wystąpienia segmentu",
             "Numer kolejny segmentu DG1."),
        2:  ("Metoda kodowania",
             "Nie używane w InfoMedica (przestarzałe od v2.4)."),
        3:  ("Kod diagnozy",
             "Kod wg klasyfikacji ICD-10. W InfoMedica wartości ze słownika Elementów Leczenia "
             "gdy DG1.17=SK (składniki leczenia). Format: <kod>^<nazwa>^<system>."),
        6:  ("Typ diagnozy",
             "A = do przyjęcia (diagnoza wstępna/przyjęciowa), "
             "W = wstępna (robocza), F = końcowa. "
             "Dla komunikatów OMB^O27 (bank krwi) przesyłane są też dodatkowe typy rozpoznań."),
        17: ("Klasyfikacja diagnozy",
             "SK = składniki leczenia — dodatkowe informacje do zlecenia InfoMedica."),
    },
    "MSA": {
        1:  ("Kod potwierdzenia",
             "Potwierdzenie transportowe: CA = przyjęto, CE = błąd chwilowy (można ponowić), "
             "CR = odrzucono (błąd trwały). "
             "Potwierdzenie aplikacyjne: AA = przyjęto, AR = odrzucono (błąd trwały). "
             "AE nie jest używane — InfoMedica albo przyjmuje (AA) albo definitywnie odrzuca (AR)."),
        2:  ("Id. potwierdzanego komunikatu",
             "Wartość MSH.10 komunikatu, którego dotyczy potwierdzenie."),
        3:  ("Tekstowy opis błędu",
             "Opcjonalny opis błędu lub komunikat potwierdzający."),
    },
    "ERR": {
        1:  ("Kod błędu i lokalizacja",
             "Lokalizacja błędu w komunikacie i kod błędu (przestarzałe od v2.5)."),
        3:  ("Kod błędu HL7",
             "Kod błędu wg tabeli HL7."),
        4:  ("Ciężkość błędu",
             "I = informacja, W = ostrzeżenie, E = błąd."),
        8:  ("Komunikat dla użytkownika",
             "Opis błędu czytelny dla użytkownika."),
    },
    "QRD": {
        1:  ("Data/czas zapytania",
             "Moment złożenia zapytania."),
        4:  ("Id. zapytania",
             "Unikalny identyfikator zapytania."),
        8:  ("Kto szukany / identyfikator pacjenta",
             "Identyfikator pacjenta: MIP (identyfikator techniczny InfoMedica) lub PESEL. "
             "Używany w komunikatach QRY^A19 (pytanie o dane pacjenta)."),
        9:  ("Czego szukamy",
             "Typ szukanego rekordu."),
    },
    "MRG": {
        1:  ("Poprzedni id. pacjenta",
             "Identyfikator (MIP) pacjenta, który ma zostać scalony z obecnym."),
        4:  ("Poprzedni alternatywny id.",
             "Alternatywny identyfikator łączonego pacjenta."),
    },
    "EVN": {
        1:  ("Kod zdarzenia",
             "Typ zdarzenia, np. A01=przyjęcie, A03=wypis, A13=cofnięcie wypisu, "
             "A28=dopisanie do skorowidza, A29=kasowanie danych, A30=połączenie rekordów."),
        2:  ("Data/czas zarejestrowania",
             "Data i czas zarejestrowania zdarzenia w systemie."),
        5:  ("Operator",
             "Identyfikator operatora rejestrującego zdarzenie."),
        6:  ("Data/czas faktycznego zdarzenia",
             "Data i czas faktycznego wystąpienia zdarzenia (może różnić się od daty rejestracji)."),
    },
    "BPO": {
        1:  ("Id. wystąpienia segmentu",
             "Numer kolejny segmentu BPO."),
        2:  ("Id. produktu krwi",
             "Kod preparatu krwi wg słownika ISBT (International Society of Blood Transfusion). "
             "Używany w komunikatach OMB^O27 (bank krwi — zamówienie na krew)."),
        5:  ("Ilość",
             "Liczba zamówionych jednostek preparatu."),
        11: ("Data/czas zamówienia",
             "Planowana data i czas transfuzji."),
        16: ("Diagnozy",
             "Rozpoznania powiązane z zamówieniem krwi."),
    },
}

# Segment → color (hex) for UI display
SEGMENT_COLORS = {
    # Header / control
    "MSH": "#1a3a5c",
    "MSA": "#2a2a4a",
    "ERR": "#5c1a1a",
    "EVN": "#3d1a5c",
    # Patient
    "PID": "#1a4a2e",
    "PD1": "#1a4a2e",
    "NK1": "#1a3d2a",
    "MRG": "#1a3d2a",
    # Visit / Insurance
    "PV1": "#1a3d4a",
    "PV2": "#1a3d4a",
    "IN1": "#3a1a3d",
    "IN2": "#3a1a3d",
    "GT1": "#3d1a3a",
    # Orders
    "ORC": "#4a3a1a",
    "OBR": "#1a3a3a",
    # Results
    "OBX": "#2a4a1a",
    "NTE": "#3a3a2a",
    # Clinical
    "AL1": "#4a2a1a",
    "DG1": "#1a2a4a",
    "PR1": "#2a1a4a",
    # Queries
    "QRD": "#2a3a4a",
    "QRF": "#2a3a4a",
    # Pharmacy / Blood
    "RXO": "#3d3a1a",
    "RXE": "#3d3a1a",
    "RXD": "#3d3a1a",
    "RXA": "#3d3a1a",
    "RXR": "#3d3a1a",
    "BPO": "#5c2a2a",
    "BPX": "#5c2a2a",
    # Scheduling / Master file
    "SCH": "#1a3a3d",
    "MFE": "#3a2a1a",
    "SLT": "#2a3a1a",
    # Z-segments (custom InfoMedica/AMMS)
    "ZDP": "#2a2a3a",
    "ZDR": "#2a2a3a",
    "ZIG": "#2a2a3a",
    "ZPI": "#2a2a2a",
}

DEFAULT_SEGMENT_COLOR = "#2a2a2a"


def get_segment_name(seg: str) -> str:
    info = SEGMENT_INFO.get(seg)
    return info[0] if info else seg


def get_segment_description(seg: str) -> str:
    info = SEGMENT_INFO.get(seg)
    return info[1] if info else "Nieznany segment HL7."


def get_field_info(seg: str, field_num: int):
    """Returns (name, description) or None."""
    return FIELD_INFO.get(seg, {}).get(field_num)


def get_segment_color(seg: str) -> str:
    return SEGMENT_COLORS.get(seg, DEFAULT_SEGMENT_COLOR)
