# 🔐 Szyfrator Poufnych Wiadomości

Prosty program do szyfrowania i odszyfrowywania wiadomości tekstowych
z wykorzystaniem XOR, PBKDF2-HMAC-SHA256 oraz HMAC-SHA256.

## 🚀 Pobierz

👉 **[⬇️ POBIERZ SZYFRATOR](https://github.com/karolkoscielniak222-cloud/Szyfrator/releases)**

### 💻 Wymagania

- Windows 10 / 11
- Nie wymaga instalowania Pythona
- Nie wymaga dodatkowych bibliotek
- Program działa jako pojedynczy plik `.exe`

### ▶️ Uruchomienie

1. Pobierz `szyfrator.exe`.
2. Uruchom plik.
3. Wybierz odpowiednią opcję z menu.
4. Postępuj zgodnie z instrukcjami programu.

> ⚠️ Hasło jest niezbędne do odszyfrowania wiadomości.
> Nie udostępniaj go razem z szyfrogramem.

---

## 🛠️ Dla programistów

Kod źródłowy programu znajduje się w pliku `szyfrator.py`.

Projekt wykorzystuje wyłącznie bibliotekę standardową Pythona.

### Zastosowane mechanizmy

- XOR – szyfrowanie danych
- PBKDF2-HMAC-SHA256 – wyprowadzanie klucza z hasła
- HMAC-SHA256 – kontrola integralności
- losowa sól 128-bitowa
- Base64 – reprezentacja szyfrogramu

### 🐍 Uruchomienie ze źródeł

```bash
python szyfrator.py
