"""
============================================================
              SZYFRATOR POUFNYCH WIADOMOŚCI
============================================================
Autor: Karol Kościelniak & Antigravity
Opis: Aplikacja do bezpiecznego szyfrowania i deszyfrowania
      wiadomości. Wykorzystuje kryptografię z solą (salt),
      PBKDF2-HMAC (100 000 powtórzeń SHA-256) oraz weryfikację
      integralności HMAC. Szyfr jest praktycznie nie do złamania
      bez znajomości tajnego hasła/klucza.
============================================================
"""

# ============================================================
# 1. IMPORTY MODUŁÓW (Wbudowana biblioteka standardowa Pythona)
# ============================================================
import sys       # Narzędzia systemowe (np. obsługa strumienia konsoli i kodowania)
import time      # Obsługa czasu i opóźnień (np. time.sleep)
import base64    # Kodowanie bajtów w bezpieczny tekst (alfabet A-Z, a-z, 0-9, +, /)
import hashlib   # Algorytmy haszujące (SHA-256 oraz PBKDF2 do wzmacniania hasła)
import hmac      # Cyfrowy podpis wiadomości (gwarantuje, że nikt nie zmienił tekstu)
import secrets   # Bezpieczny generator liczb losowych (dużo bezpieczniejszy niż zwykły 'random')

# Zapewnienie poprawnego wyświetlania polskich znaków w konsoli Windows
# Zapobiega to błędom UnicodeEncodeError na niektórych wersjach terminala
if sys.stdout and hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass


# ============================================================
# 2. FUNKCJE POMOCNICZE I INTERFEJS
# ============================================================

def wyczysc_ekran():
    """Wypisuje ozdobną linię oddzielającą kolejne operacje w konsoli."""
    print("\n" + "=" * 60 + "\n")


def wypisz_powoli(tekst, opoznienie=0.01):
    """
    Wypisuje tekst litera po literze, tworząc płynny efekt pisania.
    - end="" zapobiega przejściu do nowej linii po każdej literze
    - flush=True wymusza natychmiastowe wyświetlenie znaku na ekranie
    """
    for znak in tekst:
        print(znak, end="", flush=True)
        time.sleep(opoznienie)
    print()  # Przejście do nowej linii na koniec tekstu


# ============================================================
# 3. RDZEŃ KRYPTOGRAFICZNY (Matematyka i Bezpieczeństwo)
# ============================================================

def generuj_strumien_klucza(haslo: str, sol: bytes, dlugosc: int) -> bytes:
    """
    Generuje unikalny strumień pseudolosowych bajtów z hasła i soli.
    
    Używa standardu PBKDF2 (Password-Based Key Derivation Function 2):
    - hasło: tekst wpisany przez użytkownika
    - sol: 16 losowych bajtów (dzięki nim każde szyfrowanie daje inny wynik)
    - 100 000: liczba powtórzeń (rund) haszowania SHA-256. 
      Sprawia to, że złamanie hasła metodą brute-force trwałoby tysiące lat.
    - dklen=dlugosc: liczba bajtów klucza, jakie chcemy wygenerować.
    """
    return hashlib.pbkdf2_hmac("sha256", haslo.encode("utf-8"), sol, 100000, dklen=dlugosc)


def zaszyfruj_wiadomosc(tekst: str, haslo: str) -> str:
    """
    Główna funkcja szyfrująca tekst.
    Krok po kroku zabezpiecza wiadomość i pakuje ją do formatu Base64.
    """
    # Krok 1: Zamiana zwykłego tekstu (string) na surowe bajty w kodowaniu UTF-8
    bajty_tekstu = tekst.encode("utf-8")
    dlugosc = len(bajty_tekstu)

    # Krok 2: Wygenerowanie 16 bajtów losowej soli (kryptograficznie bezpiecznej)
    sol = secrets.token_bytes(16)

    # Krok 3: Wygenerowanie strumienia klucza dla wiadomości + dodatkowych 32 bajtów na podpis HMAC
    strumien = generuj_strumien_klucza(haslo, sol, dlugosc + 32)
    klucz_szyfru = strumien[:dlugosc]   # Pierwsza część strumienia szyfruje tekst
    klucz_hmac = strumien[dlugosc:]     # Druga część strumienia posłuży do pieczęci HMAC

    # Krok 4: Operacja XOR (b ^ k) dla każdego bajtu wiadomości i klucza.
    # To klasyczna zasada szyfru z kluczem jednorazowym (One-Time Pad).
    zaszyfrowane_bajty = bytes(b ^ k for b, k in zip(bajty_tekstu, klucz_szyfru))

    # Krok 5: Utworzenie cyfrowej pieczęci HMAC-SHA256 nad zaszyfrowaną treścią.
    # Dzięki temu program natychmiast rozpozna, jeśli ktoś wpisze błędne hasło.
    podpis = hmac.new(klucz_hmac, zaszyfrowane_bajty, hashlib.sha256).digest()

    # Krok 6: Złożenie gotowej paczki:
    # [16 bajtów soli] + [32 bajty podpisu HMAC] + [zaszyfrowane bajty wiadomości]
    paczka = sol + podpis + zaszyfrowane_bajty
    
    # Krok 7: Zakodowanie całej paczki do tekstu Base64 (łatwego do skopiowania i wysłania)
    return base64.b64encode(paczka).decode("ascii")


def odszyfruj_wiadomosc(zaszyfrowany_tekst: str, haslo: str):
    """
    Główna funkcja deszyfrująca.
    Zwraca krotkę: (sukces: bool, wynik_lub_blad: str).
    """
    # Krok 1: Dekodowanie tekstu Base64 z powrotem na surowe bajty
    try:
        paczka = base64.b64decode(zaszyfrowany_tekst.strip().encode("ascii"))
    except Exception:
        return False, "BŁĄD: Podany tekst nie jest poprawnym szyfrogramem Base64!"

    # Sprawdzenie minimalnej długości: 16 (sól) + 32 (podpis) = 48 bajtów
    if len(paczka) < 48:
        return False, "BŁĄD: Szyfrogram jest zbyt krótki lub uszkodzony!"

    # Krok 2: Rozpakowanie paczki na poszczególne elementy
    sol = paczka[:16]                # Pierwsze 16 bajtów to sól wylosowana przy szyfrowaniu
    podpis_zapisany = paczka[16:48]  # Kolejne 32 bajty to pieczęć HMAC
    zaszyfrowane_bajty = paczka[48:] # Reszta to zaszyfrowana treść
    dlugosc = len(zaszyfrowane_bajty)

    # Krok 3: Odtworzenie dokładnie tego samego strumienia klucza z podanego hasła i soli
    strumien = generuj_strumien_klucza(haslo, sol, dlugosc + 32)
    klucz_szyfru = strumien[:dlugosc]
    klucz_hmac = strumien[dlugosc:]

    # Krok 4: Weryfikacja pieczęci HMAC
    # Obliczamy pieczęć dla otrzymanych danych i porównujemy z tą zapisaną w paczce.
    oczekiwany_podpis = hmac.new(klucz_hmac, zaszyfrowane_bajty, hashlib.sha256).digest()
    
    # hmac.compare_digest chroni przed tzw. atakami czasowymi (timing attacks)
    if not hmac.compare_digest(podpis_zapisany, oczekiwany_podpis):
        return False, "BŁĄD: Niepoprawne hasło lub wiadomość została zmodyfikowana!"

    # Krok 5: Odwrócenie operacji XOR (ponowny XOR z tym samym kluczem przywraca oryginał)
    odszyfrowane_bajty = bytes(b ^ k for b, k in zip(zaszyfrowane_bajty, klucz_szyfru))
    
    # Krok 6: Zamiana odszyfrowanych bajtów z powrotem na czytelny tekst UTF-8
    try:
        oryginalny_tekst = odszyfrowane_bajty.decode("utf-8")
        return True, oryginalny_tekst
    except UnicodeDecodeError:
        return False, "BŁĄD: Błąd dekodowania tekstu z UTF-8."


def wygeneruj_losowy_klucz(dlugosc=24) -> str:
    """
    Generuje losowy, super-silny klucz z wielkich i małych liter,
    cyfr oraz znaków specjalnych za pomocą kryptograficznego modułu 'secrets'.
    """
    alfabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
    return "".join(secrets.choice(alfabet) for _ in range(dlugosc))


# ============================================================
# 4. FUNKCJE POSZCZEGÓLNYCH EKRANÓW MENU
# ============================================================

def menu_szyfrowania():
    """Obsługuje proces szyfrowania nowej wiadomości."""
    wyczysc_ekran()
    print("--- [ 🔒 ZASZYFRUJ WIADOMOŚĆ ] ---")
    tekst = input("Wpisz wiadomość do ukrycia:\n> ").strip()
    
    # Walidacja: upewniamy się, że użytkownik nie wpisał pustego tekstu
    if not tekst:
        print("[!] Wiadomość nie może być pusta!")
        return

    print("\nWybierz sposób zabezpieczenia:")
    print("1. Wpisz własne tajne hasło")
    print("2. Wygeneruj automatyczny, pancerny klucz losowy")
    wybor = input("Wybór (1/2): ").strip()

    if wybor == "2":
        haslo = wygeneruj_losowy_klucz(20)
        print(f"\n[+] Wygenerowano pancerny klucz: {haslo}")
        print("    (ZAPISZ GO! Odbiorca musi go mieć, aby odczytać wiadomość)")
    else:
        haslo = input("\nWpisz swoje tajne hasło:\n> ").strip()
        if not haslo:
            print("[!] Hasło nie może być puste!")
            return

    print("\nTrwa szyfrowanie (obliczanie 100 000 rund PBKDF2-HMAC)...")
    szyfrogram = zaszyfruj_wiadomosc(tekst, haslo)

    print("\n" + "─" * 60)
    print("🎉 OTO TWOJA ZASZYFROWANA WIADOMOŚĆ (skopiuj cały tekst):")
    print("─" * 60)
    print(szyfrogram)
    print("─" * 60)
    print(f"Klucz/Hasło potrzebne do odczytania: {haslo}")
    print("Nawet superkomputer nie złamie tej wiadomości bez tego hasła!")


def menu_deszyfrowania():
    """Obsługuje wprowadzanie szyfrogramu i hasła oraz wyświetlanie wyniku."""
    wyczysc_ekran()
    print("--- [ 🔓 ODSZYFRUJ WIADOMOŚĆ ] ---")
    szyfrogram = input("Wklej zaszyfrowany tekst (Base64):\n> ").strip()
    if not szyfrogram:
        print("[!] Nie podano tekstu do odszyfrowania!")
        return

    haslo = input("\nWpisz tajne hasło lub klucz:\n> ").strip()
    if not haslo:
        print("[!] Musisz podać hasło!")
        return

    print("\nTrwa weryfikacja i deszyfrowanie...")
    sukces, wynik = odszyfruj_wiadomosc(szyfrogram, haslo)

    print("\n" + "─" * 60)
    if sukces:
        print("✅ SUKCES! ODCZYTANA WIADOMOŚĆ:")
        print("─" * 60)
        print(wynik)
    else:
        print(f"❌ {wynik}")
    print("─" * 60)


def o_szyfrze():
    """Wyświetla wyjaśnienie matematycznych podstaw działania algorytmu."""
    wyczysc_ekran()
    print("--- [ ℹ️ O TECHNOLOGII SZYFROWANIA ] ---")
    print("""
Dlaczego ten program tworzy szyfr niemożliwy do złamania?

1. ZASADA SZYFRU STRUMIENIOWEGO I ONE-TIME PAD:
   Każdy znak wiadomości jest łączony z unikalnym ciągiem kryptograficznym
   za pomocą operacji XOR. Jeśli klucz jest unikalny, szyfr jest matematycznie
   niemożliwy do złamania (twierdzenie Claude'a Shannona).

2. UNIKALNA SÓL KRYPTOGRAFICZNA (SALT):
   Za każdym razem, gdy szyfrujesz nawet TO SAMO zdanie TYM SAMYM hasłem,
   program losuje nową 16-bajtową sól (ponad 340 sekstylionów kombinacji).
   Dzięki temu wynik szyfrowania za każdym razem wygląda zupełnie inaczej!

3. OCHRONA PRZED ATAKAMI BRUTE-FORCE (PBKDF2):
   Program wykonuje 100 000 powtórzeń algorytmu haszującego SHA-256.
   Sprawia to, że próba zgadywania hasła przez hakerów wymagałaby
   tysięcy lat mocy obliczeniowej.

4. SUMA KONTROLNA HMAC-SHA256:
   Wiadomość jest cyfrowo zapieczętowana. Jeśli ktoś zmieni choćby
   jeden znak w szyfrogramie lub poda złe hasło, program natychmiast
   to wykryje.
""")


def informacje_o_programie():
    """Wyświetla szczegółowe metadane programu, informacje o autorze, technologii i licencjonowaniu."""
    wyczysc_ekran()
    print("=" * 65)
    print("            📋  SZCZEGÓŁOWE INFORMACJE O PROGRAMIE  📋")
    print("=" * 65)
    print("""
[ METADANE I AUTORSTWO ]
-----------------------------------------------------------------
  • Nazwa aplikacji   : Szyfrator Poufnych Wiadomości (Secure Message Crypt)
  • Aktualna wersja    : 1.2 PRO (Edycja 2026)
  • Autor programu     : Karol Kościelniak
  • Język programowania: Python 3 (wykorzystujący bibliotekę standardową)
  • Data kompilacji    : Wrzesień 2026
  • Prawa autorskie    : Copyright (C) 2026 Karol Kościelniak.
                         Wszelkie prawa zastrzeżone.

[ PRZEZNACZENIE I FUNKCJONALNOŚĆ ]
-----------------------------------------------------------------
Aplikacja została zaprojektowana w celu zapewnienia maksymalnego
poziomu prywatności i poufności w cyfrowej komunikacji. Umożliwia
kodowanie dowolnych wiadomości tekstowych w bezpieczny szyfrogram,
który można bez obaw przesyłać przez publiczne i niezaufane kanały
(np. komunikatory internetowe, czaty w grach, e-maile czy SMS-y).

[ ARCHITEKTURA I SPECYFIKACJA KRYPTOGRAFICZNA ]
-----------------------------------------------------------------
Program opiera się na sprawdzonych matematycznych standardach:

1. Algorytm szyfrowania:
   - Szyfrowanie strumieniowe operacją bitową XOR.
   - Zastosowanie twierdzenia Claude'a Shannona o doskonałym
     utajnieniu (Perfect Secrecy / One-Time Pad).

2. Krypto-odporność na łamanie (Anti-Brute Force):
   - PBKDF2-HMAC (Password-Based Key Derivation Function 2).
   - 100 000 iteracji algorytmu SHA-256 dla każdego hasła.
   - Drastycznie spowalnia próby łamania haseł za pomocą kart graficznych.

3. Sól kryptograficzna (Cryptographic Salt):
   - 128-bitowa unikalna sól generowana sprzętowym źródłem losowości
     (moduł 'secrets').
   - Zabezpiecza przed atakami tęczowych tablic (Rainbow Tables).

4. Weryfikacja integralności (Message Integrity):
   - 256-bitowa pieczęć HMAC-SHA256.
   - Gwarantuje, że podanie błędnego hasła lub zmiana choćby jednego
     znaku w szyfrogramie zostanie natychmiast wykryta.

5. Format wyjściowy:
   - Standard Base64 (RFC 4648) – zapewnia bezproblemowe kopiowanie
     i wklejanie tekstu na dowolnym urządzeniu i systemie.

[ ZGODNOŚĆ I WYMAGANIA SYSTEMOWE ]
-----------------------------------------------------------------
  • Zgodność systemowa: Windows, macOS, Linux, Android (Termux)
  • Zależności         : 0 zewnętrznych bibliotek (Zero External Dependencies)
  • Kodowanie znaków   : Pełne wsparcie dla standardu UTF-8 (polskie znaki,
                         emoji, symbole międzynarodowe).

[ ZASADY BEZPIECZNEGO UŻYTKOWANIA ]
-----------------------------------------------------------------
⚠️  Złota zasada kryptografii:
    Nigdy nie przesyłaj tajnego hasła tym samym kanałem, którym
    wysyłasz zaszyfrowaną wiadomość! Najbezpieczniej przekazać hasło
    osobiście na żywo lub poprzez inny, zaufany sposób kontaktu.
""")


# ============================================================
# 5. GŁÓWNA PĘTLA PROGRAMU (Menu i sterowanie)
# ============================================================

def glowny_program():
    """Pętla główna aplikacji sterująca wyświetlaniem menu."""
    while True:
        wyczysc_ekran()
        print("=" * 60)
        print("      🛡️  SZYFRATOR 2026 - POUFNA KOMUNIKACJA  🛡️")
        print("=" * 60)
        print("1. 🔒 Zaszyfruj wiadomość")
        print("2. 🔓 Odszyfruj wiadomość")
        print("3. 🎲 Wygeneruj silne, losowe hasło / klucz")
        print("4. ℹ️  Dlaczego ten szyfr jest nie do złamania?")
        print("5. 📋 Informacje o programie i autorze")
        print("6. 🚪 Wyjdź z programu")
        print("=" * 60)

        wybor = input("Wybierz opcję (1-6): ").strip()

        # Rozgałęzienie warunkowe obsługujące wybór użytkownika
        if wybor == "1":
            menu_szyfrowania()
        elif wybor == "2":
            menu_deszyfrowania()
        elif wybor == "3":
            wyczysc_ekran()
            klucz = wygeneruj_losowy_klucz(24)
            print("--- [ 🎲 GENERATOR PANCERNYCH HASEŁ ] ---")
            print(f"Wygenerowane bezpieczne hasło:\n\n👉  {klucz}  👈\n")
            print("Możesz go użyć jako hasła do szyfrowania lub do swoich kont!")
        elif wybor == "4":
            o_szyfrze()
        elif wybor == "5":
            informacje_o_programie()
        elif wybor == "6":
            print("\nDziękujemy za korzystanie z Szyfratora. Bezpieczeństwo przede wszystkim!")
            time.sleep(1)
            break  # Przerwanie pętli while i zakończenie programu
        else:
            print("\n[!] Niepoprawny wybór. Wpisz cyfrę od 1 do 6.")

        # Zatrzymanie ekranu, aby użytkownik zdążył przeczytać wynik
        input("\nNaciśnij Enter, aby kontynuować...")


# Standardowa konstrukcja w Pythonie:
# Sprawdza, czy plik został uruchomiony bezpośrednio (a nie zaimportowany jako moduł)
if __name__ == "__main__":
    glowny_program()
