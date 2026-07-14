### **1. GŁÓWNE TECHNIKI ANALIZY**

#### **Analiza Manifestu (Android)**

Analiza manifestu to kluczowa technika weryfikacji bezpieczeństwa aplikacji Android na poziomie konfiguracji. Moduł analizuje plik `AndroidManifest.xml`, który zawiera wszystkie deklaracje uprawnień, komponentów i flag bezpieczeństwa aplikacji. Celem jest identyfikacja błędnych konfiguracji i potencjalnych luk w zabezpieczeniach, zanim tester przejdzie do analizy kodu.

- **Detekcja zagrożeń na podstawie konfiguracji**: Główny algorytm skanujący plik manifestu w poszukiwaniu problematycznych ustawień bezpieczeństwa. Sprawdza całą strukturę XML i dla każdego komponentu weryfikuje zgodność z best practices.
  - **Sprawdzenie MIN/TARGET SDK (API 26, 29 itp.)**: Weryfikuje minimalną i docelową wersję API aplikacji. MIN_SDK < API 26 (Android 8.0) oznacza przestarzałą platformę narażoną na znane luki. TARGET_SDK < API 29 zwiększa podatność na ataki takie jak StrandHogg 2.0.
  - **Analiza eksportowanych komponentów bez ochrony**: Szuka aktywności, usług, broadcastów i providerów z atrybutem `exported=true` lub niejawnie eksportowanych (zamiast jawnego `exported=false`). Elementy bez ochrony (`android:permission`) mogą być dostępne każdej aplikacji, co umożliwia atak.
  - **Detekt StrandHogg 1.0**: Wyszukuje kombinację `TARGET_SDK < 28` oraz `launchMode=singleTask`, co umożliwia hi-jacking tasków. Atakujący może przechwycić stos zadań aplikacji poprzez create intent z wyższym priority.
  - **Detekt StrandHogg 2.0**: Bardziej nowoczesna wersja ataku wymagająca `TARGET_SDK < 29`, `exported=true` i `launchMode` różnym od `singleInstance`. Pozwala na przejęcie interfejsu użytkownika przez złośliwą aplikację.
  - **Sprawdzenie flag**: `debuggable=true` umożliwia debugowanie przez każdą aplikację na urządzeniu; `allowBackup=true` pozwala na backup danych aplikacji; `usesCleartextTraffic=true` pozwala na niezaszyfrowaną komunikację HTTP.

#### **Analiza Kodowa (SAST Engine)**

Analiza kodowa to proces skanowania kodu źródłowego aplikacji w poszukiwaniu niebezpiecznych wzorców, API i podatności. MobSF wykorzystuje zaawansowany silnik SAST (Static Application Security Testing) oparty na bibliotece `libsast`, który umożliwia przeszukiwanie milionów linii kodu w kilka sekund.

- **Pattern Matching - Regex-based skanowanie**: Algorytm oparty na wyrażeniach regularnych przeznaczony dla plików Java, Kotlin, Swift i Objective-C. Każdy plik jest skanowany równolegle pod kątem wzorców odpowiadających znanym podatnościom. System automatycznie ignoruje komentarze i false positive'y.
- **Multiprocessing**: Skanowanie równoległo z automatyczną detekcją liczby rdzeni CPU w systemie. MobSF dzieli pliki źródłowe między procesy robocze, aby maksymalizować wydajność. Każdy proces otrzymuje podzbiór plików i skanuje je niezależnie, a wyniki są następnie scalane.
- **Zasady reguł YAML**: Przepisy bezpieczeństwa zdefiniowane w plikach YAML zawierające wzorce niebezpiecznego kodu. Każda reguła zawiera wyrażenie regularne, opis podatności, poziom ważności (high/medium/low) i mapowanie do standardów takich jak OWASP Mobile czy CWE. Reguły są łatwo rozszerzalne bez modyfikacji kodu aplikacji.

#### **Analiza Certyfikatów**

Analiza certyfikatów weryfikuje podpis cyfrowy i autentyczność aplikacji. Certyfikat słabo zabezpieczony może prowadzić do podrobienia aplikacji lub jej nieautoryzowanej modyfikacji. MobSF analizuje szczegóły certyfikatu oraz parametry kryptograficzne.

- **Parsowanie X.509**: Ekstrakcja informacji ze standardowego certyfikatu X.509 zawartego w aplikacji. Algoritm wyodrębnia pole Subject (CN, O, OU), Issuer (kto wystawił certyfikat), daty ważności (notBefore, notAfter) oraz informacje o podpisie. Te dane pozwalają określić tożsamość dewelopera i sprawdzić, czy certyfikat nie wygasł.
- **Analiza kryptograficzna**: Analiza parametrów kluczy publicznych aplikacji, w tym rozmiaru klucza RSA (minimum 2048 bitów rekomendowane), typu algorytmu (RSA, DSA, EC), czy stosowania kluczy eliptycznych (EC). Małe klucze sono podatne na ataki brute-force. Słabe algorytmy takie jak DSA są przestarzałe.
- **Detekt podpisów**: Identyfikacja wersji schematu podpisu aplikacji - v1 (przestarzały, tylko dodaje SHA1), v2 (szybszy, weryfikuje całą APK), v3 (wspiera rotację klucza) lub v4 (głównie dla rozszczepionego APK). Nowsze wersje oferują lepsze bezpieczeństwo.
- **Hardcoded certificates**: Wyszukiwanie w kodzie aplikacji wbudowanych certyfikatów, kluczy prywatnych, czy plików keystore'u (.cer, .jks, .key). Wbudowany klucz prywatny to krytyczna luka - każda osoba może podpisać kod jako deweloper, co umożliwia injection malware'u.

### **2. ALGORYTMY DETEKCJI PODATNOŚCI**

#### **Wprowadzenie: Podatności i Detekcja Podatności**

**Podatność** to nieumyślna lub projektowa słabość w oprogramowaniu, protokole sieciowym lub konfiguracji zabezpieczeń, którą atakujący może wykorzystać do uzyskania nieautoryzowanego dostępu, kradzieży danych, sabotażu systemu lub wykonania dowolnego kodu. Podatności mogą wynikać z błędów logiki biznesowej, nieuzasadnionego zaufania do danych wejściowych (injection), słabych algorytmów kryptograficznych, nieprzestrzegania best practices, lub zaniedbań w zarządzaniu uprawnieniami i sekretami.

**Detekcja podatności** to proces systematycznego przeszukiwania kodu, konfiguracji i binarki aplikacji w poszukiwaniu znanych wzorców podatności. MobSF stosuje cztery główne techniki detekcji:

1. **Analiza statyczna (SAST)** — skanowanie kodu źródłowego bez uruchamiania aplikacji
2. **Analiza strukturalna** — badanie konfiguracji, manifestów i plików XML
3. **Analiza binarna** — weryfikacja rozszerzonych zabezpieczeń na poziomie systemu operacyjnego
4. **Analiza entropii** — matematyczne wykrywanie zakodowanych sekretów

#### **Znane Przykłady Podatności i Ich Detekcji w MobSF**

| Podatność                 | Liczba CWE | Detekcja                                                                        | Przykład Ataku                                                               |
| ------------------------- | ---------- | ------------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| **SQL Injection**         | CWE-89     | SAST regex: `db.query()`, `SQLiteDatabase.rawQuery()`                           | `' OR '1'='1` - pobiera całą bazę danych                                     |
| **Code Injection**        | CWE-95     | SAST: `eval()`, `Runtime.exec()`, `ProcessBuilder`                              | Wstrzyknięcie kodu shell'owego w `Runtime.getRuntime().exec()`               |
| **Insecure SSL/TLS**      | CWE-295    | SAST: `TrustAllCertificates`, `HttpsURLConnection.setDefaultHostnameVerifier()` | Man-in-the-middle attack - przechwycenie niezaszyfrowanej komunikacji        |
| **Hardcoded Credentials** | CWE-798    | SAST + Entropia: API keys, hasła w kodzie                                       | Atakujący stosuje odczytane credentials do logowania na inne systemy         |
| **Debuggable App**        | CWE-489    | Manifest: `android:debuggable=true`                                             | Debugger może wstrzyknąć breakpointy i modyfikować zmienne w runtime         |
| **Exported Components**   | CWE-927    | Manifest: `android:exported=true` bez `android:permission`                      | Inna aplikacja wysyła intent do eksportowanej aktywności i przechwytuje dane |
| **Cleartext Traffic**     | CWE-319    | Network XML: `<domain cleartextTrafficPermitted="true">`                        | Niezaszyfrowana komunikacja HTTP — atakujący czyta dane w sieci WiFi         |
| **Weak Cryptography**     | CWE-327    | SAST: `MD5`, `SHA1`, `DES`, `ECB mode`                                          | Hashing z MD5 — szybko złamałem poprzez rainbow tables                       |
| **Stack Overflow**        | CWE-674    | Binary: brak stack canary, PIE disabled                                         | Buffer overflow w bibliotece C — wykonanie dowolnego kodu                    |
| **Untrusted Data**        | CWE-20     | SAST: `getQueryParameter()`, `getExtra()` bez walidacji                         | Aplikacja przetwarza zainfekowany intent z innej aplikacji                   |

---

#### **A. SAST Engine (Static Application Security Testing)**

**SAST Engine to zaawansowany silnik analizy statycznej oparty na bibliotece `libsast`, który skanuje kod źródłowy w poszukiwaniu niebezpiecznych wzorców.** Nie wymaga uruchamiania aplikacji — pracuje na poziomie tekstowym i bytecode. MobSF wykorzystuje wieloprocesowe skanowanie równoległe zapewniające szybkość w milionach linii kodu.

**Przebieg Analizy SAST:**

```
Wejście: Pliki źródłowe (.java, .kt, .m, .swift)
  ↓
[Faza 1] Wczytanie Pliku
  - Odczytanie zawartości pliku do pamięci
  - Normalizacja kodowania (UTF-8)
  - Ignoracja binarnych i zbyt dużych plików (> 1MB)
  ↓
[Faza 2] Uruchomienie Reguł Regex
  - Dla każdej reguły z android_rules.yaml:
    * Kompilacja wyrażenia regularnego
    * Skanowanie całego tekstu pliku równole
    * Jeśli match: ekstraktowanie kontekstu (5 linii przed i po)
  ↓
[Faza 3] Filtrowanie False Positives
  - Ignoracja komentarzy (// i /* */)
  - Ignoracja łańcuchów w stringach (jeśli zaznaczone w regule)
  - Weryfikacja skurczenia (cutsoff) — czy zagrożenie rzeczywiście jest
  ↓
[Faza 4] Scalenie Duplikatów
  - Usunięcie identycznych wyników z tego samego pliku
  - Konsolidacja wyników z różnych reguł (jeśli dotyczą tej samej linii)
  ↓
Output: Lista luk z plikiem, linią, wiadomością i severityem
```

**Reguły YAML — Struktura:**

Każda reguła SAST jest zdefiniowana w pliku YAML i zawiera:

```yaml
- id: android_sql_injection
  message: 'Potential SQL Injection: Dynamic SQL query construction'
  type: RegexAnd # Oba pattern muszą być znalezione
  pattern:
    - 'SQLiteDatabase|ContentProvider'
    - "rawQuery.*\\+|selection.*\\+|buildString"
  severity: high
  input_case: exact # Wrażliwość na wielkość liter
  cwe:
    - 89 # CWE-89: Improper Neutralization of Special Elements
  owasp_mobile:
    - m7 # Insecure Code Quality
  cvss: '6.5'
```

**Parametry Reguły:**

- `type`: `Regex`, `RegexAnd` (oba pattern'y), `RegexOr` (jeden z pattern'ów)
- `pattern`: Lista wyrażeń regularnych do znalezienia
- `severity`: high/medium/low/info
- `input_case`: exact (wrażliwe)/nocase (niewrażliwe)
- `cwe`, `owasp_mobile`, `cvss`: Mapowania standardów

**Przykłady Detekcji:**

1. **SQL Injection Detection:**

   ```java
   // Luka: Dynamiczne budowanie zapytania SQL
   String query = "SELECT * FROM users WHERE username = '" + username + "'";
   db.rawQuery(query, null);
   ```

   SAST znajduje: `rawQuery` + `\"SELECT.*WHERE.*\\+\"` → **HIGH**

2. **Insecure Reflection:**

   ```java
   // Luka: Wczytanie klasy z użytkowniczego inputu
   Class cls = Class.forName(userInput);
   Method method = cls.getMethod("execute");
   ```

   SAST znajduje: `Class.forName` + `getMethod` → **HIGH**

3. **Password Hardcoding:**
   ```java
   // Luka: Hasło wbudowane w kod
   String apiKey = "7f8a3b5c9d2e1f4a";
   String password = "admin123";
   ```
   SAST znajduje: `(password|api.*key)\s*=\s*['\"].*['\"]` → **CRITICAL**

**Multiprocessing Strategy:**

MobSF automatycznie wybiera strategię wieloprocesową na podstawie dostępnych zasobów:

```python
# Pseudokod logiki
cpu_count = os.cpu_count()  # np. 8 rdzeni
if cpu_count > 4:
    strategy = "processpoolexecutor"  # 8 procesów = najszybsze
elif cpu_count > 1:
    strategy = "billiard"  # Procesy Celery — niech pracują
else:
    strategy = "thread"  # 1 rdzeń — threading wystarczy
```

Każdy proces otrzymuje podzbiór plików i skanuje je niezależnie, a wyniki są scalane w finalny raport.

---

#### **B. Entropia (Detection Sekretów)**

**Analiza entropii to matematyczny algorytm wykrywania zakodowanych lub zakamuflowanych sekretów (API keys, tokeny, hasła) w kodzie.** Sekrety, nawet jeśli zmieniane co każdą literę, posiadają wyższą entropię niż zwykły kod lub tekst. MobSF oblicza entropię Shannona dla każdego ciągu znaków i porównuje z progami.

**Teoria Entropii Shannona:**

Entropia Shannon'a mierzy poziom nieprzewidywalności (losowości) danych. Im wyższa entropia, tym bardziej losowy ciąg. Sekrety (API keys, tokeny) mają wysoką entropię, ponieważ są generowane losowo.

$$H(X) = -\sum_{i=1}^{n} p(x_i) \log_2 p(x_i)$$

Gdzie:

- $p(x_i)$ — prawdopodobieństwo każdego znaku w ciągu
- $\log_2$ — logarytm o podstawie 2 (wynik w bitach)

**Przykładowe Wyliczenia:**

| Ciąg                 | Znaki               | Entropia | Typ                           |
| -------------------- | ------------------- | -------- | ----------------------------- |
| `"aaaa"`             | 1 unikalne (a)      | 0 bitów  | Brak entropii — to nie sekret |
| `"abab"`             | 2 unikalne (a, b)   | 1 bit    | Niska entropia — wzór         |
| `"7f8a3b5c9d2e1f4a"` | 16 znków (0-9, a-f) | 4.0 bity | Średnia entropia              |
| `"a7k#nP$mQ2x@9Lw5"` | ~40 znaków (mix)    | 5.2 bity | **WYSOKA — to sekret!**       |

**Algorytm Detekcji w MobSF:**

```
Wejście: Ciąg znaków (string z kodu)
  ↓
[Krok 1] Ekstrakcja Podciągów
  - Podzielenie na tokeny (identyfikatory, literały)
  - Dla każdego tokenu: sprawdzenie długości (min 8 znaków)
  ↓
[Krok 2] Obliczenie Entropii
  - Policzenie częstości każdego znaku
  - Zastosowanie formuły Shannona
  - Otrzymanie wyniku w bitach (0-8)
  ↓
[Krok 3] Aplikacja Progów
  Base64 Encoding:  if entropy > 4.5 → **FLAG AS SECRET**
  Hex Encoding:     if entropy > 3.0 → **FLAG AS SECRET**
  Mixed Charset:    if entropy > 5.0 → **FLAG AS SECRET**
  ↓
[Krok 4] Filtrowanie Falsywych Alarmów
  - Ignoracja URL'i i ścieżek (np. https://example.com/path)
  - Ignoracja Kotlin package'ów (np. com.example.app)
  - Ignoracja zmiennych Loop (i, j, k)
  ↓
Output: Lista potencjalnych sekretów z lokalizacją
```

**Przykłady Detekcji:**

1. **API Key — Hex:**

   ```java
   String apiKey = "a7f3b4c9d2e1f8a5";  // 16 znków hex
   // Entropia = ~3.8 > 3.0 (próg hex) → **SEKRET WYKRYTY**
   ```

2. **Firebase Token — Base64:**

   ```java
   String token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
   // Entropia = ~4.8 > 4.5 (próg Base64) → **SEKRET WYKRYTY**
   ```

3. **JWT Token — Mixed:**

   ```java
   String jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9." +
                "eyJzdWIiOiIxMjM0NTY3ODkwIn0." +
                "TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ";
   // Entropia = ~5.8 > 5.0 → **SEKRET WYKRYTY**
   ```

4. **Regular Variable — Ignorowany:**
   ```java
   String username = "john_doe";  // Tylko 4 unikalne znaki
   // Entropia = ~2.5 < 3.0 → BRAK ALARMU (normalny tekst)
   ```

**Limity i Optymalizacje:**

- Skanowanie startuje dla stringów > 8 znaków (krócej = mało informacji)
- Cache'ing wyników — sekrety znalezione raz nie są skanowane ponownie
- Multi-threading — każdy plik skanowany w osobnym wątku

---

#### **C. Analiza Binarna (ELF/MachO)**

**Analiza binarna to inspekcja rozszerzonych zabezpieczeń na poziomie systemu operacyjnego, które chronią przed exploitami na poziomie maszyny.** Obejmuje weryfikację ochrony przed buffer overflow'ami, ASLR, oraz podpisu kodu. MobSF analizuje nagłówki ELF (Linux/Android) i MachO (iOS/macOS).

**Zabezpieczenia Binarki (ELF):**

1. **ASLR (Address Space Layout Randomization)**
   - **Co to:** Każde uruchomienie programu ma zmienioną bazową adresację pamięci
   - **Bez ASLR:** Atakujący wie dokładnie gdzie w pamięci jest funkcja — łatwy ROP attack
   - **Z ASLR:** Adresy sie randomizują — exploit musi najpierw wyciągnąć adresy (leakowanie)
   - **Detekcja MobSF:** Sprawdzenie flagi `ET_DYN` w nagłówku ELF

   ```
   Brak ASLR: e_type = ET_EXEC          → VULNERABILITY: „ASLR Disabled"
   Z ASLR:    e_type = ET_DYN            → OK: „ASLR Enabled"
   ```

2. **PIE (Position-Independent Executable)**
   - **Co to:** Kod może być załadowany na jakikolwiek adres w pamięci
   - **Bez PIE:** Adresy funkcji są stałe — ROP gadget chains są znane
   - **Z PIE:** Adresy zmieniane — gadget chains muszą być obliczane dynamicznie
   - **Detekcja MobSF:** Sprawdzenie flagi `ET_DYN` + relokacje

   ```
   Brak PIE: Zwykła statyczna cca. adresacja  → VULNERABILITY
   Z PIE:    Dynamiczne relokacje                → OK
   ```

3. **Stack Canary (Stack Protector)**
   - **Co to:** Wartość strażnika umieszczana na stosie — jeśli się zmieni, znalezione jest overflow
   - **Zabezpiecza przed:** Buffer overflow na stosie
   - **Bez Canary:** Atakujący nadpisuje return address i wykonuje kod
   - **Z Canary:** Nadpisanie wartości strażnika zatrzymuje program
   - **Detekcja MobSF:** Poszukiwanie funkcji `__stack_chk_fail` w symbolach

   ```
   Symbol „__stack_chk_fail" znaleziony → Stack Canary: ENABLED ✓
   Brak symbolu                          → Stack Canary: DISABLED ✗
   ```

4. **Relocation Read-Only (RELRO)**
   - **Co to:** Sekcja relokacji (GOT — Global Offset Table) jest read-only po inicjalizacji
   - **Bez RELRO (Partial RELRO):** GOT można nadpisywać — hijacking funkcji
   - **Z RELRO (Full RELRO):** GOT jest locked — niemożliwe nadpisanie
   - **Detekcja MobSF:** Sprawdzenie flagi `GNU_RELRO` w programowych nagłówkach
   ```
   Full RELRO:    Cała GOT read-only      → SECURED
   Partial RELRO: Część GOT writable      → PARTIALLY SECURED
   No RELRO:      GOT zmieniana           → VULNERABLE
   ```

**Zabezpieczenia Binarki (MachO — iOS):**

1. **Code Signing**
   - **Co to:** Każdy binarny plik musi być podpisany certyfikatem dewelopera Apple
   - **Zabezpiecza:** Przed nielegalnymi modyfikacjami
   - **Luka:** Jeśli aplikacja podpisana ad-hoc (nie Apple Developer Account)

   ```
   Ad-Hoc Signature:  Dowolna osoba mogła podpisać    → WARNING
   Developer Sign:    Zweryfikowana przez Apple       → TRUSTED
   Enterprise Sign:   Dla aplikacji korporacyjnych    → TRUSTED
   ```

2. **Bitcode**
   - **Co to:** Pośrednia reprezentacja kodu umożliwiająca Apple reoptymalizować
   - **Zabezpieczenia:** Możliwość aplikacji obejścia pewnych wymogów
   - **Brak Bitcodu:** Aplikacja bardziej podatna na exploity

**Algorytm Analizy Binarnej w MobSF:**

```
Wejście: Plik binarny (.so, MachO, lub ELF)
  ↓
[1] Parsowanie Nagłówka
  - ELF_HEADER / MACH_HEADER parsing
  - Ekstrakcja flagi e_type, e_flags
  - Budowa mapy sekcji
  ↓
[2] Weryfikacja ASLR
  if e_type == ET_DYN:
    ASLR = "ENABLED" ✓
  else:
    ASLR = "DISABLED" ✗ → FLAG AS VULNERABILITY
  ↓
[3] Weryfikacja PIE
  if elffile.header['e_flags'] & PIE_FLAGS:
    PIE = "ENABLED" ✓
  else:
    PIE = "DISABLED" ✗
  ↓
[4] Detekcja Stack Canary
  if "__stack_chk_fail" in symtab:
    STACK_CANARY = "ENABLED" ✓
  else:
    STACK_CANARY = "DISABLED" ✗
  ↓
[5] Sprawdzenie RELRO
  if GNU_RELRO segment size == GOT size:
    RELRO = "FULL" ✓
  elif GNU_RELRO segment size > 0:
    RELRO = "PARTIAL" ~ (WARNING)
  else:
    RELRO = "NONE" ✗
  ↓
[6] Weryfikacja Code Signing (MachO)
  if codesign verify == OK:
    CODE_SIGNING = "VALID" ✓
  else:
    CODE_SIGNING = "INVALID" ✗
  ↓
Output: Raport zabezpieczeń binarki
```

**Przykład Raportu Binarki:**

```
File: libexample.so
Architecture: ARMv7 (32-bit), ARM64 (64-bit)

Security Features:
├─ ASLR:          ✓ ENABLED
├─ PIE:           ✓ ENABLED
├─ Stack Canary:  ✗ DISABLED  ← VULNERABILITY
├─ RELRO:         ✓ FULL
└─ Signature:     N/A (Android)

Risk Level: MEDIUM
Grund: Stack Canary brakuje — buffer overflow'y na stosie mogą wykonać kod
```

---

#### **D. Bezpieczeństwo Sieci (Network Security XML)**

**Analiza bezpieczeństwa sieci skanuje plik `network_security_config.xml`, który definiuje jakie połączenia sieciowe aplikacja akceptuje.** Pozwala określić czy aplikacja wymaga HTTPS, certyfikatów piningu, czy pozwala niezaszyfrowanemu trafikowi HTTP.

**Struktura network_security_config.xml:**

```xml
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <!-- Domyślna konfiguracja dla wszystkich domen -->
    <domain-config cleartextTrafficPermitted="false">
        <domain includeSubdomains="true">example.com</domain>
        <!-- Pin certificate -->
        <pin-set expiration="2026-01-01">
            <pin digest="SHA-256">
                7lRhNaLEPLE4hd+cQX0sU+Z/pVPrZN0SvEBnqKTsGWs=
            </pin-
        </pin-set>
    </domain-config>

    <!-- Wyjątek dla určitej domeny — pozwala HTTP -->
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="false">legacy.example.com</domain>
    </domain-config>

    <!-- Trust anchors — które CA są zaufane -->
    <trust-anchors>
        <certificates src="system"/>  <!-- Systemowe CA -->
        <certificates src="user"/>     <!-- User-installed CA (łatwy MITM!) -->
        <certificates src="@raw/custom_ca"/>  <!-- Custom CA -->
    </trust-anchors>
</network-security-config>
```

**Algorytm Analizy Network Security:**

```
Wejście: network_security_config.xml
  ↓
[1] Parsowanie XML
  - Ekstrakcja wszystkich <domain-config> bloków
  - Zbieranie atrybutów cleartextTrafficPermitted
  ↓
[2] Analiza Cleartext Traffic
  if cleartextTrafficPermitted="true":
    VULNERABILITY: „HTTP Traffic Allowed for: " + domain
    SEVERITY: HIGH (dane mogą być przechwycone)
  else:
    OK: „HTTPS Only for: " + domain
  ↓
[3] Weryfikacja Trust Anchors
  for each certificates:
    if src="user":
      SECURITY_RISK: „User CA Trusted — MITM Attack Possible"
      SEVERITY: HIGH
    elif src="system":
      OK: „Only System CAs trusted"
    elif src="@raw/custom_ca":
      WARNING: „Custom CA — verify it's legitimate"
  ↓
[4] Analiza Certificate Pinning
  if pin-set found:
    SECURITY_FEATURE: „Certificate Pinning Enabled"
    RISK: if expiration date passed:
      ALERT: „Pin expired — app may reject valid certificates"
  else:
    WARNING: „No Certificate Pinning — app cannot detect spoofed certificates"
  ↓
[5] Walidacja Subdomains
  for each domain:
    if includeSubdomains="true":
      Konfiguracja dotyka: domain.example.com, sub.domain.example.com, ...
    else:
      Konfiguracja dotyka: tylko domain.example.com
  ↓
Output: Raport zagrożeń sieciowych
```

**Znane Luki i Ich Detekcja:**

| Luka                     | Wpis XML                                                        | Odsłanie                                       | Risk         |
| ------------------------ | --------------------------------------------------------------- | ---------------------------------------------- | ------------ |
| **HTTP Traffic Allowed** | `cleartextTrafficPermitted="true"`                              | Niezaszyfrowana komunikacja                    | **HIGH**     |
| **User CA Trusted**      | `<certificates src="user"/>`                                    | MITM attack — każdy może wstrzyknąć certyfikat | **CRITICAL** |
| **No Pinning**           | Brak `<pin-set>`                                                | Atakujący instaluje proxy i przechwytuje dane  | **MEDIUM**   |
| **Expired Pin**          | `expiration="2020-01-01"`                                       | Aplikacja odrzuca ALL certyfikaty — DoS        | **HIGH**     |
| **Subdomain Over-Reach** | `includeSubdomains="true"` + `cleartextTrafficPermitted="true"` | HTTP na podotawniach — HTTP Downgrade          | **HIGH**     |

**Przykład Raportu:**

```
Network Security Analysis:
├─ Base Config
│  └─ Cleartext Traffic: DISABLED ✓
│
├─ Domains
│  ├─ api.example.com:     HTTPS Only ✓
│  ├─ legacy.example.com:  HTTP ALLOWED ✗ [VULNERABILITY]
│  └─ analytics.example.com: HTTPS with Pinning ✓✓
│
├─ Trust Anchors
│  ├─ System CAs:     ✓ Trusted
│  ├─ User CAs:       ✗ DANGEROUS — MITM Risk
│  └─ Custom CA:      ~ Verify legitimacy
│
└─ Summary
   HIGH RISK: User CA + HTTP Traffic on legacy domain
   RECOMMENDATION: Remove user CA trust, enforce HTTPS everywhere
```

### **3. GŁÓWNE KATEGORIE ANALIZ**

| Platform    | Typ Analizy            | Moduł                     |
| ----------- | ---------------------- | ------------------------- |
| **Android** | Manifest               | manifest_analysis.py      |
|             | Code/SAST              | code_analysis.py          |
|             | Certificates           | cert_analysis.py          |
|             | Binary (ELF)           | elf.py                    |
|             | Permissions            | permissions.py            |
|             | Trackers               | Trackers.py               |
| **iOS**     | Binary (MachO)         | binary_analysis.py        |
|             | Plist                  | plist_analysis.py         |
|             | App Transport Security | app_transport_security.py |
|             | Code                   | code_analysis.py          |
| **Windows** | PE Analysis            | windows.py                |

### **4. PRZEPŁYW ANALIZY APK**

```
1. Ekstraktoza i walidacja
2. Parsowanie Androguard (DEX, manifest)
3. Analiza manifestu (luki)
4. Analiza certyfikatów
5. Konwersja DEX → Java/Smali
6. Skanowanie kodów (SAST)
7. Analiza binarna (ELF)
8. Detekcja trackerów i malware
9. Zapisanie wyników w bazie danych
```

### **5. REGUŁY DETEKTOWANIA**

#### **Wprowadzenie: Co to są Reguły Detektowania?**

**Reguły detektowania to zestaw wymogów bezpieczeństwa zdefiniowanych w plikach YAML, które definiują jakie wzorce kodu, konfiguracji lub binarki są uważane za podatności.** Każda reguła zawiera wyrażenie regularne (lub zestaw warunków), opis luki, poziom ważności, oraz mapowanie do standardów bezpieczeństwa (CWE, OWASP Mobile, CVSS). Reguły są sercem MobSF — bez nich silnik SAST byłby bezużyteczny.

Reguły są przechowywane w plikach YAML i są łatwe do edycji, rozszerzania i dzielenia się między zespołami bez potrzeby modyfikacji kodu aplikacji.

#### **Lokalizacja i Organizacja Reguł w MobSF**

Reguły są przechowywane w katalogu `mobsf/StaticAnalyzer/views/android/rules/` i są zorganizowane po typach analiz:

| Plik Reguł                   | Analiza                | Liczba Reguł | Zastosowanie                                                               |
| ---------------------------- | ---------------------- | ------------ | -------------------------------------------------------------------------- |
| **android_rules.yaml**       | SAST — Kod Java/Kotlin | 100+         | Główne podatności: SQL injection, code injection, insecure APIs            |
| **android_apis.yaml**        | API Analysis           | 50+          | Niebezpieczne API: `Runtime.exec()`, `ClassLoader.loadClass()`             |
| **android_permissions.yaml** | Permission Mapping     | 30+          | Mapowanie uprawnień do kodów (jeśli włączone)                              |
| **android_niap.yaml**        | NIAP Compliance        | ~20          | National Information Assurance Partnership — compliance do standardów FIPS |
| **swift_rules.yaml**         | iOS Swift Code         | 40+          | Swift-specific vulnerabilities                                             |
| **objective_c_rules.yaml**   | iOS Objective-C        | 40+          | Objective-C-specific vulnerabilities                                       |

#### **Struktura Płumu YAML Reguły**

Każda reguła w pliku YAML ma następującą strukturę:

```yaml
- id: android_insecure_ssl
  message: 'Insecure SSL implementation: TrustAllCertificates or similar'
  type: RegexAnd
  pattern:
    - javax\.net\.ssl
    - TrustAllSSLSocket-Factory|AllTrustSSLSocketFactory|
      TrustManager\[\]\s*\{\s*new\s*X509TrustManager
  severity: high
  input_case: exact
  cwe:
    - 295
  owasp_mobile:
    - m3
  cvss: '7.4'
  cvss_vector: 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N'
  masvs:
    - network-1
    - network-2
```

**Wyjaśnienie Pól Reguły:**

| Pole             | Opis                                                                                                                            | Przykład                           |
| ---------------- | ------------------------------------------------------------------------------------------------------------------------------- | ---------------------------------- |
| **id**           | Uniktalny identyfikator reguły                                                                                                  | `android_sql_injection`            |
| **message**      | Wiadomość wyświetlana użytkownikowi                                                                                             | `"Potential SQL Injection"`        |
| **type**         | Typ dopasowania — `Regex` (jeden pattern), `RegexAnd` (wszystkie pattern'y muszą być znalezione), `RegexOr` (co najmniej jeden) | `RegexAnd`, `RegexOr`              |
| **pattern**      | Lista wyrażeń regularnych do znalezienia                                                                                        | `["SELECT.*FROM", "\\+ username"]` |
| **severity**     | Waga problemu: `critical`, `high`, `medium`, `low`, `info`                                                                      | `high`                             |
| **input_case**   | Wrażliwość na wielkość liter: `exact` lub `nocase`                                                                              | `exact`                            |
| **cwe**          | Lista numerów CWE (Common Weakness Enumeration)                                                                                 | `[89, 90]` — SQL Injection         |
| **owasp_mobile** | Lista kategorii OWASP Mobile Top 10: `m1`-`m10`                                                                                 | `[m3, m7]`                         |
| **cvss**         | CVSS v3.1 score (0-10) — mowa zagrożenia                                                                                        | `"7.4"`                            |
| **cvss_vector**  | Szczegółowy wektor CVSS                                                                                                         | `"CVSS:3.1/AV:N/AC:L/..."`         |
| **masvs**        | Mobile Application Security Verification Standard                                                                               | `["network-1"]`                    |
| **description**  | Dodatkowy opis podatności (opcjonalnie)                                                                                         | Tekst wyjaśniający                 |

#### **Typy Reguł — Mechanika Działania**

**1. Regex — Jedno Wyrażenie:**

```yaml
- id: hardcoded_password
  message: 'Hardcoded password found'
  type: Regex
  pattern:
    - "password\\s*=\\s*['\\\"].*['\\\"]"
  severity: critical
```

**Działanie:** Jeśli wyrażenie regularne zostanie znalezione, reguła aktywuje się.

```java
String password = "admin123";  // ← MATCH — rule triggers
```

**2. RegexAnd — Wszystkie Wyrażenia Muszą Pasować:**

```yaml
- id: sqlite_injection
  message: 'Potential SQLite injection'
  type: RegexAnd
  pattern:
    - 'SQLiteDatabase|rawQuery'
    - "\\+ .*['\\\"]" # String concatenation
  severity: high
```

**Działanie:** Reguła aktywuje się TYLKO jeśli zarówno `SQLiteDatabase` jak i `+` kombinacja są na tej samej linii.

```java
String query = "SELECT * FROM users WHERE id = " + userId;  // ← MATCH
String db = "SQLiteDatabase";  // ← NO MATCH (brak concatenation)
```

**3. RegexOr — Co Najmniej Jedno Wyrażenie Musi Pasować:**

```yaml
- id: reflection_usage
  message: 'Reflection API usage'
  type: RegexOr
  pattern:
    - "Class\\.forName\\("
    - "Method\\.invoke\\("
    - "getMethod\\("
  severity: medium
```

**Działanie:** Reguła aktywuje się jeśli znaleziono DOWOLNE z tych pattern'ów.

```java
Class cls = Class.forName("com.example.MyClass");  // ← MATCH (Pattern 1)
String reflection = "getMethod";  // ← NO MATCH (tylko string literal)
```

#### **Hierarchia Severity i Impact**

Każda reguła ma przypisaną wagę zagrożenia, która wpływa na raport końcowy:

| Severity     | CVSS Score | Znaczenie                                                                     | Przykład                                    |
| ------------ | ---------- | ----------------------------------------------------------------------------- | ------------------------------------------- |
| **CRITICAL** | 9.0-10.0   | Publikowanie jest natychmiastowe — aplikacja całkowicie skompromitowana       | Hardcoded API key do admin panelu           |
| **HIGH**     | 7.0-8.9    | Podatność umożliwia poważny atak — pilne naprawienie                          | SQL Injection, Command Injection            |
| **MEDIUM**   | 4.0-6.9    | Podatność powinna być naprawiona — znaczący wpływ na bezpieczeństwo           | Weak Cryptography, Missing Input Validation |
| **LOW**      | 0.1-3.9    | Podatność może być wykorzystana w ograniczonych scenariuszach                 | Hardcoded test credentials, debug logs      |
| **INFO**     | N/A        | Informacja — nie jest podatnością, ale dobrze wiedzieć (np. użycie debug API) | Debuggable app flag                         |

#### **Mapowanie do Standardów**

**CWE (Common Weakness Enumeration)** — Klasyfikacja słabości:

- CWE-89 — SQL Injection
- CWE-95 — Code Injection
- CWE-327 — Use of Broken Cryptography
- CWE-798 — Hardcoded Credentials

**OWASP Mobile Top 10** — Kategorie podatności mobilnych:

- m1 — Insecure Authentication
- m3 — Insecure Communication
- m4 — Insecure Data Storage
- m7 — Insecure Code Quality

**MASVS (Mobile Application Security Verification Standard)** — Wymagania bezpieczeństwa:

- `storage-1` — Sensitive data handling
- `network-1` — Secure transport
- `crypto-1` — Cryptographic implementation

**CVSS Vector** — Szczegółowa ocena zagrożenia:

```
CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N
        │    │    │    │  │  │  │  │  └─ Availability: None
        │    │    │    │  │  │  │  └──── Integrity: High
        │    │    │    │  │  │  └─────── Confidentiality: High
        │    │    │    │  │  └────────── Scope: Unchanged
        │    │    │    │  └───────────── User Interaction: Required
        │    │    │    └──────────────── Privileges Required: None
        │    │    └─────────────────────── Attack Complexity: Low
        │    └──────────────────────────── Attack Vector: Network
        └─────────────────────────────── CVSS Version: 3.1
```

#### **Przykłady Rzeczywistych Reguł MobSF**

**Reguła 1: SQL Injection Detection**

```yaml
- id: android_sql_injection
  message: 'Potential SQL Injection: Dynamic SQL query construction'
  type: RegexAnd
  pattern:
    - 'SQLiteDatabase|rawQuery|execSQL|ContentProvider'
    - "\\+ .*['\\\"]|buildString|selection.*\\+"
  severity: high
  input_case: exact
  cwe:
    - 89
  owasp_mobile:
    - m7
  cvss: '6.5'
  description: 'Aplikacja konstruuje zapytania SQL poprzez konkatenację stringów'
```

**Reguła 2: Hardcoded Secrets**

```yaml
- id: hardcoded_api_key
  message: 'Potential hardcoded API key or token'
  type: Regex
  pattern:
    - "(api[_-]?key|token|secret|password)\\s*[=:]\\s*['\\\"]([a-zA-Z0-9]{20,})['\\\"]"
  severity: critical
  input_case: nocase
  cwe:
    - 798
  owasp_mobile:
    - m2
  cvss: '8.0'
```

**Reguła 3: Insecure Cryptography**

```yaml
- id: weak_cryptography
  message: 'Use of weak cryptographic algorithm'
  type: RegexOr
  pattern:
    - "MessageDigest\\.getInstance\\(['\\\"]MD5['\\\"]"
    - "MessageDigest\\.getInstance\\(['\\\"]SHA1['\\\"]"
    - "Cipher\\.getInstance\\(['\\\"]DES['\\\"]"
  severity: high
  cwe:
    - 327
  owasp_mobile:
    - m5
  cvss: '7.2'
```

**Reguła 4: Exported Components Without Permissions**

```yaml
- id: exported_component
  message: 'Exported component without required permissions'
  type: RegexAnd
  pattern:
    - '<activity|<service|<receiver'
    - "android:exported\\s*=\\s*['\\\"]true['\\\"]"
    - '(?!android:permission)' # Negative lookahead — brak permission
  severity: high
  cwe:
    - 927
  owasp_mobile:
    - m1
  cvss: '6.0'
```

#### **Proces Skanowania Reguł**

```
Wejście: Plik źródłowy + Zestaw reguł YAML
  ↓
[Krok 1] Wczytanie Reguł
  - Parsowanie wszystkich plików *.yaml z katalogu rules/
  - Kompilacja wyrażeń regularnych do bytecode'u dla optymalizacji
  - Budowa cache'u reguł w pamięci
  ↓
[Krok 2] Czytanie Pliku Źródłowego
  - Wczytanie całej zawartości pliku do pamięci
  - Normalizacja kodowania (UTF-8)
  - Podzielenie na linie dla kontekstu (5 linii przed i po)
  ↓
[Krok 3] Iteracja Reguł
  for each rule in rules:
    ↓
    [a] Sprawdzenie Warunków Wstępnych
      - Jeśli pattern jest dla Java i plik to Kotlin → SKIP
      - Jeśli severity=low i ustawienie to high_only → SKIP
    ↓
    [b] Uruchomienie Pattern Matching
      if rule.type == "Regex":
        if pattern[0] matches in file:
          RECORD MATCH → ADD TO RESULTS with context

      elif rule.type == "RegexAnd":
        if pattern[0] AND pattern[1] AND ... all found:
          RECORD MATCH with ALL patterns highlighted

      elif rule.type == "RegexOr":
        if pattern[0] OR pattern[1] OR ... found:
          RECORD MATCH with which pattern matched
    ↓
    [c] Filtrowanie False Positives
      - Sprawdzenie: czy match jest wewnątrz komentarza?
      - Sprawdzenie: czy match jest wewnątrz string'a?
      - Jeśli tak → IGNORE, idź dalej
      - Jeśli nie → KEEP
    ↓
[Krok 4] Agregacja Wyników
  - Grupowanie wyników po pliku i linii
  - Usunięcie duplikatów
  - Obliczenie liczby podatności po severity
  ↓
[Krok 5] Ranking Podatności
  - Sortowanie po severity (CRITICAL → HIGH → MEDIUM → LOW → INFO)
  - W obrębie severity — sortowanie po CVSS score
  ↓
Output: Raport podatności z reguł
```

#### **Przykład Raport z Reguł**

```
FILE: MainActivity.java
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[CRITICAL] Hardcoded API Key (android_hardcoded_api_key)
File: MainActivity.java:25
  └─ CVSS: 8.0
  └─ CWE: 798 (Hardcoded Credentials)

  23 | public class MainActivity extends AppCompatActivity {
  24 |     String apiUrl = "https://api.example.com";
  25 | >>> String apiKey = "sk_live_a7f3b4c9d2e1f8a5";  ← MATCH
  26 |
  27 |     protected void onCreate(Bundle state) {

  RULE: (api[_-]?key|token)\s*=\s*['\"]([a-zA-Z0-9]{20,})['\"]
  ERROR_MESSAGE: Potential hardcoded API key found

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

[HIGH] SQL Injection (android_sql_injection)
File: MainActivity.java:42
  └─ CVSS: 6.5
  └─ CWE: 89 (SQL Injection)
  └─ OWASP Mobile: m7

  40 | public void searchUsers(String username) {
  41 |     SQLiteDatabase db = getDatabase();
  42 | >>> String query = "SELECT * FROM users WHERE name = '" + username + "'";
  43 |     Cursor cursor = db.rawQuery(query, null);  ← MATCH (rawQuery)
  44 | }

  RULE_MATCH: [SQLiteDatabase, rawQuery] AND [+ concatenation]
  RECOMMENDATION: Use parameterized queries: db.rawQuery("SELECT * FROM users WHERE name = ?", [username])

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

SUMMARY: 23 Issues Found
├─ CRITICAL:  2
├─ HIGH:      8
├─ MEDIUM:    10
├─ LOW:       3
└─ INFO:      0
```

#### **Dostosowywanie i Rozszerzanie Reguł**

**Dodanie Nowej Reguły — 3 Kroki:**

1. **Edytuj plik android_rules.yaml:**

```yaml
# Nowa reguła — Detekcja logowania do DEBUG
- id: android_debug_logging
  message: 'Debugging log with sensitive data'
  type: Regex
  pattern:
    - "Log\\.(d|i|v|e)\\(.*['\\\"].*\\)" # Log.d/i/v/e call
  severity: medium
  cwe:
    - 532 # Insertion of Sensitive Information into Log File
  owasp_mobile:
    - m2
  cvss: '4.5'
```

2. **Restartuj MobSF** — reguły są ładowane przy uruchomieniu.

3. **Skanuj aplikację** — wyniki wyświetlą się w raporcie.

**Best Practices przy Tworzeniu Reguł:**

| Zasada                              | Wyjaśnienie                                     | Przykład                                                            |
| ----------------------------------- | ----------------------------------------------- | ------------------------------------------------------------------- |
| Bądź Specificzny                    | Wyrażenie zbyt ogólne = wiele false positive'ów | ❌ `String.*` — zbyt ogólne<br>✅ `String\s+(apiKey\|password)\s*=` |
| Używaj Case Sensitivity             | `nocase` tylko gdy rzeczywiście potrzebne       | ❌ `CLASS\.FORNAME` — nie istnieje<br>✅ `Class\.forName`           |
| Mapuj do CWE                        | Każda reguła powinna mieć CWE dla trackingu     | `cwe: [89]` — SQL Injection                                         |
| Testuj na Rzeczywistych Aplikacjach | Unikaj reguł które nigdy się nie aktywują       | Testuj regex w online narzędziach                                   |
| Dokumentuj Intent                   | Opisz dlaczego ta reguła jest ważna             | `description: "Unencrypted storage of user data"`                   |

#### **Statystyka Reguł MobSF**

```
Android Rules Summary:
├─ CRITICAL rules:      5
├─ HIGH rules:         45
├─ MEDIUM rules:       35
├─ LOW rules:          15
└─ INFO rules:          5
   Total:             105 rules

Platform Coverage:
├─ Java/Kotlin:      100%
├─ Android Manifest: 100%
├─ iOS Swift:         95%
├─ iOS Objective-C:   90%
└─ Windows PE:        70%
```

Reguły są **żywą dokumentacją** bezpieczeństwa — aktualizują się wraz z nowymi zagrożeniami, a zespół MobSF nieustannie dodaje je gdy pojawiają się nowe CVE'e lub vulnerability research.

---

### **6. RAPORT ZE SKANOWANIA**

#### **Wprowadzenie: Struktura i Cel Raportu**

**Raport ze skanowania to komprehensywny dokument zawierający wszystkie wyniki analizy bezpieczeństwa aplikacji.** Po zakończeniu skanowania MobSF generuje raport, który zawiera:

1. **Metadane aplikacji** — informacje o aplikacji, wersji, hash'ach
2. **Podsumowanie wyników** — liczba podatności wg. severity
3. **Szczegółowe wyniki** — każda znaleziona podatność z kontekstem
4. **Metryki bezpieczeństwa** — Risk Score, zdolność bezpieczeństwa
5. **Rekomendacje napraw** — jak naprawić każdą podatność
6. **Pochodzenie danych** — które narzędzie/analiza znalazła podatność

MobSF generuje raporty w trzech formatach: **HTML** (interaktywny), **JSON** (programowy), **PDF** (do drukowania).

#### **Elementy Raportu — Podsumowanie Wydaje (Summary Tab)**

**Sekcja Summary wyświetla szybki przegląd wyników:**

```
┌─────────────────────────────────────────────────────────┐
│  MOBILE SECURITY FRAMEWORK - SCAN REPORT                │
└─────────────────────────────────────────────────────────┘

📱 APP INFORMATION
├─ Package Name:      com.example.vulnerable
├─ App Label:         Vulnerable App
├─ Version Name:      1.0
├─ Version Code:      1
├─ Target SDK:        28 (Android 9.0)
├─ Min SDK:           21 (Android 5.0)
├─ App Hash (MD5):    a1b2c3d4e5f6g7h8
├─ App Hash (SHA1):   1a2b3c4d5e6f7g8h9i0j
├─ App Hash (SHA256): 1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p
├─ Manifest MD5:      x1y2z3a4b5c6d7e8
├─ APK Size:          2.4 MB
├─ Number of Activities: 5
├─ Number of Services: 2
├─ Number of Broadcast Receivers: 1
├─ Number of Content Providers: 0
└─ Number of Libraries: 12

🚨 VULNERABILITY SUMMARY
├─ Critical Issues:  2
├─ High Issues:      8
├─ Medium Issues:    15
├─ Low Issues:       7
├─ Info Issues:      3
└─ Total Issues:     35

⚙️ SECURITY SCORE

  Risk Rating: HIGH 🔴
  ┌──────────────────────────────┐
  │ 32/100                       │  ← 32% Safe
  │ ████░░░░░░░░░░░░░░░░░░░░░░  │
  └──────────────────────────────┘

  Recommendation: This app is NOT suitable for production
```

#### **Struktura HTML Raportu (Dashboard)**

HTML raport zawiera interaktywny dashboard z następującymi sekcjami:

**1. Header — Metainformacje:**

```
╔═══════════════════════════════════════════════════════╗
║ MobSF v3.x.x | Application Analysis Report           ║
║ Scan Date: 2026-04-14 14:32:15 UTC                   ║
║ Scan Duration: 2 min 14 sec                          ║
╚═══════════════════════════════════════════════════════╝
```

**2. Risk Meter — Wizualizacja Ryzyka:**

```
┌─ RISK RATING ──────────────┐
│                            │
│  🔴 CRITICAL               │  Score: 32/100
│                            │
│  Broken Auth       ████    │  8 issues
│  Weak Crypto       ███░    │  3 issues
│  Data Exposure     █████   │  12 issues
│  Insecure Config   ███░    │  4 issues
│  Poor Code Quality █████░  │  8 issues
│                            │
└────────────────────────────┘
```

**3. Navigation Tabs — Przełączanie Sekcji:**

- Summary (podsumowanie)
- Manifest Analysis (analiza manifestu)
- Binary Analysis (analiza binarki)
- Code Analysis (analiza kodu)
- Certificate Analysis (analiza certyfików)
- Network Security (bezpieczeństwo sieci)
- API Usage (użycie API)
- Strings Analysis (analiza stringów)
- File Analysis (analiza plików)
- Permissions (uprawnienia)
- Performance (wydajność)

#### **Szczegółowy Raport — Sekcja Podatności (Code Analysis Tab)**

Każda znaleziona podatność ma hierarchiczną strukturę:

```
═══════════════════════════════════════════════════════════════
  VULNERABILITY #1: Hardcoded API Key
═══════════════════════════════════════════════════════════════

Severity:           🔴 CRITICAL
CVSS Score:         8.0
CWE:                CWE-798: Hardcoded Credentials
OWASP Mobile:       M2: Insecure Data Storage
MASVS:              STORAGE-1, STORAGE-2

┌─ FILE & LOCATION ─────────────────────────────────────┐
│ File:    MainActivity.java                            │
│ Line:    42                                           │
│ Method:  onCreate()                                   │
└────────────────────────────────────────────────────────┘

┌─ MATCHED RULE ────────────────────────────────────────┐
│ Rule ID:    android_hardcoded_api_key                │
│ Pattern:    (api[_-]?key|token)\s*=\s*['\"].*['\"] │
│ Matches:    2 occurrences                            │
└────────────────────────────────────────────────────────┘

┌─ CODE SNIPPET ────────────────────────────────────────┐
│  39  | public class MainActivity {                   │
│  40  |     private String baseUrl;                   │
│  41  |                                               │
│ >>> 42  | >>> String apiKey = "sk_live_7f8a3b5c";  │ ← MATCH
│  43  |     String token = "Bearer xyz123";          │
│  44  |     void onCreate(Bundle state) {            │
└────────────────────────────────────────────────────────┘

┌─ DESCRIPTION ──────────────────────────────────────────┐
│ Hardcoded credentials (API keys, tokens) są widoczne  │
│ dla każdego, kto reverse-engineeruje APK. Atakujący   │
│ może użyć tych kluczy do logowania się jako aplikacja │
│ i uzyskać dostęp do wrażliwych zasobów.              │
└────────────────────────────────────────────────────────┘

┌─ POTENTIAL IMPACT ────────────────────────────────────┐
│ ✘ Unauthorized API access                            │
│ ✘ Data breach                                        │
│ ✘ Account takeover                                   │
│ ✘ Financial loss                                     │
│ ✘ Reputation damage                                  │
└────────────────────────────────────────────────────────┘

┌─ REMEDIATION ──────────────────────────────────────────┐
│ 1. Move API keys to secure backend server             │
│ 2. Use secure token storage (EncryptedSharedPrefs)    │
│ 3. Implement OAuth 2.0 or similar authentication      │
│ 4. Rotate compromised keys immediately               │
│ 5. Use API key restrictions (origin, referer)        │
│                                                       │
│ Example Fix:                                          │
│ ─────────────────────────────────────────            │
│ // Before (VULNERABLE)                               │
│ String apiKey = "sk_live_7f8a3b5c";                  │
│                                                       │
│ // After (SECURE)                                    │
│ // Fetch from secure backend or EncryptedSharedPref │
│ String apiKey = secureTokenManager.getToken();       │
└────────────────────────────────────────────────────────┘

┌─ EXTERNAL REFERENCES ──────────────────────────────────┐
│ • OWASP: https://owasp.org/www-project-mobile-top-10/ │
│ • CWE-798: https://cwe.mitre.org/data/definitions/798 │
│ • Android Security: developer.android.com/training   │
└────────────────────────────────────────────────────────┘

📊 STATISTICS
├─ Similar Issues: 3 more findings of this type
├─ Rule Confidence: High (100%)
├─ False Positive Risk: Low (< 1%)
└─ Detection Method: SAST + Entropy Analysis
```

#### **Raport Manifest — Analiza Konfiguracji**

```
═══════════════════════════════════════════════════════════════
  MANIFEST ANALYSIS
═══════════════════════════════════════════════════════════════

📋 BASIC INFO
├─ Package:         com.example.app
├─ Version:         1.0 (Code: 1)
├─ Target SDK:      28 ✓ Acceptable
├─ Min SDK:         21 ⚠ Android 5.0 is old
├─ Max SDK:         Not Set
└─ Debuggable:      ❌ TRUE — Security Risk!

🔐 SECURITY FLAGS
├─ android:debuggable="true"
│  └─ RISK: Debugger can attach and modify app at runtime
│
├─ android:allowBackup="true"
│  └─ RISK: User data can be backed up to Google Drive
│
├─ android:usesCleartextTraffic="true"
│  └─ RISK: HTTP traffic allowed (not just HTTPS)

📦 EXPORTED COMPONENTS

┌─ Activities (5 total) ────────────────────────────────┐
│ ✓ (Protected) com.example.MainActivity               │
│   ├─ android:exported="false"                       │
│   └─ No intent filters                              │
│                                                      │
│ ❌ (Unprotected) com.example.LoginActivity           │
│   ├─ android:exported="true"                        │
│   ├─ Missing android:permission                     │
│   └─ Intent Filter: ACTION_VIEW                     │
│      RISK: Any app can open this activity!          │
│                                                      │
│ ⚠ (Partial) com.example.DeepLinkActivity            │
│   ├─ android:permission="android.permission.USE_... │
│   └─ Protected by normal permission (ineffective)   │
└────────────────────────────────────────────────────────┘

┌─ Services (2 total) ──────────────────────────────────┐
│ ✓ (Protected) com.example.AuthService               │
│   └─ android:permission="android.permission.INTERNET│
│                                                      │
│ ❌ (VULNERABLE) com.example.DataService             │
│   ├─ android:exported="true"                        │
│   └─ Provides file access to any app!              │
│      RISK: Data exfiltration possible               │
└────────────────────────────────────────────────────────┘

🎯 PERMISSIONS (22 total)

Dangerous Permissions:
├─ android.permission.CAMERA
│  └─ Justification: Photo capture feature ✓
│
├─ android.permission.ACCESS_FINE_LOCATION
│  └─ Justification: Map feature ✓
│
├─ android.permission.READ_CONTACTS
│  └─ Justification: ??? Not documented ❌
│      RISK: Why does app need contact access?
│
└─ android.permission.WRITE_EXTERNAL_STORAGE
   └─ Risk: Can write anywhere on external storage

🔗 INTENT FILTERS

Activity: LoginActivity
├─ Action: android.intent.action.VIEW
├─ Category: android.intent.category.DEFAULT, BROWSABLE
├─ Data: scheme="https", host="example.com"
└─ SECURITY: Potential deep linking vulnerabilities

⚠️ SECURITY ISSUES SUMMARY
├─ Debuggable App:              1 CRITICAL
├─ Unprotected Components:      3 HIGH
├─ Weak Permissions:            2 MEDIUM
├─ Deep Link Issues:            1 MEDIUM
└─ Total Manifest Issues:       7
```

#### **Raport Binarny — Analiza Bibliotek i Armów**

```
═══════════════════════════════════════════════════════════════
  BINARY ANALYSIS
═══════════════════════════════════════════════════════════════

📚 NATIVE LIBRARIES (12 total)

libcrypto.so (OpenSSL - 1.0.2)
├─ Architecture:      ARM64, ARMv7
├─ Size:              2.1 MB
├─ Symbols:           Stripped ✓
├─ ASLR:              ✓ Enabled (PIE)
├─ Stack Canary:      ✗ Disabled — VULNERABILITY
├─ RELRO:             ✓ Full
├─ Fortify:           ~ Partial
└─ Note: OpenSSL 1.0.2 is deprecated — upgrade to LibreSSL/OpenSSL 3.x

libcustom_crypto.so (Custom Implementation)
├─ Architecture:      ARM64
├─ Size:              512 KB
├─ Symbols:           Present (symbols not stripped — information leak)
├─ ASLR:              ✓ Enabled
├─ Stack Canary:      ✓ Enabled
├─ RELRO:             ✓ Full
├─ Strings:           ❌ Contains hardcoded encryption keys
│  └─ Found: "MY_SECRET_KEY_2024"
└─ RISK: Custom cryptography is risky — use proven libraries

libnative.so (Custom Native Code)
├─ Architecture:      ARM64, ARMv7
├─ Size:              1.5 MB
├─ Symbols:           Partially stripped
├─ ASLR:              ✓ Enabled
├─ Stack Canary:      ✓ Enabled
├─ RELRO:             ✓ Full
├─ JNI Methods:       8 exported
│  ├─ Java_com_example_NativeLib_init()
│  ├─ Java_com_example_NativeLib_encrypt()
│  ├─ Java_com_example_NativeLib_decrypt()
│  └─ ...
└─ WARNING: JNI methods are exposed — potential attack surface

🔧 SECURITY FEATURES MATRIX

Library              ASLR  PIE   Stack  RELRO Fortify EntryGuard
───────────────────────────────────────────────────────────────
libcrypto.so         ✓     ✓     ✗      ✓     ✓       ✓
libcustom_crypto.so  ✓     ✓     ✓      ✓     ✗       ✓
libnative.so         ✓     ✓     ✓      ✓     ~       ✓
libutil.so           ✗     ✗     ✗      ✗     ✗       ✗  ← RISKY
───────────────────────────────────────────────────────────────

Explanation:
• ASLR: Address Space Layout Randomization (prevents ROP attacks)
• PIE: Position-Independent Executable (enables ASLR)
• Stack Canary: Protects against stack buffer overflows
• RELRO: Makes relocations read-only (prevents GOT hijacking)
• Fortify: Runtime protections (strcpy limit)
• EntryGuard: Control-flow integrity

⚠️ CRITICAL: libutil.so has NO security features!
   Risk: Buffer overflow → arbitrary code execution
```

#### **Unika Analizy — Sekcja Stringów i Sekretów**

```
═══════════════════════════════════════════════════════════════
  STRINGS ANALYSIS & SECRETS
═══════════════════════════════════════════════════════════════

🔐 HIGH ENTROPY STRINGS (Potential Secrets)

Entropy  Type      Location                Value
───────────────────────────────────────────────────────────────
5.8 ❌   JWT       MainActivity.java:45    eyJhbGciOiJIUzI1NiIs...
5.2 ⚠    Hex       LoginActivity.java:12   a7f3b4c9d2e1f8a5...
4.9 ⚠    Base64    API.java:23             aGVsbG8gd29ybGQ=...

Analysis: 3 potential secrets found
Action: Run entropy analyzer to confirm


🌐 URLS FOUND (18 total)

Server URLs (Potential SSRF):
├─ https://api.example.com/v1/users        [HTTPS ✓]
├─ http://legacy.example.com/api           [HTTP ❌ Not secure]
├─ http://localhost:8080/debug             [Localhost debug endpoint]
├─ https://analytics.example.com/track     [Third-party analytics]
└─ file:///assets/config.json              [Local file]

Suspicious URLs:
├─ http://192.168.1.100:7777/              [Internal network IP]
├─ https://exfil.attacker.com/             [External domain not in dev docs]
└─ ftp://ftp.example.com/files/            [Unencrypted FTP]

🔗 EMAIL ADDRESSES

├─ admin@example.com
├─ support@example.com
├─ dev@example.local
├─ contractor@external.com
└─ root@localhost  (deprecated account)

🗂️ FILE TYPES FOUND

├─ Java Files:        245
├─ XML Files:         34
├─ Native Libraries:  12
├─ Resources:         1,203
└─ Total Assets:      1,500

🔑 API KEYS & TOKENS DETECTED

firebase_api_key:
├─ Value:    AIzaSyBxn...
├─ Scope:    Firebase Realtime Database
├─ Found in: strings.xml (hardcoded)
└─ Risk:    Anyone can access database

aws_access_key:
├─ Value:    AKIAIOSFODNN...
├─ Scope:    AWS S3 access
├─ Found in: BuildConfig.java
└─ Risk:    Any app can upload malicious content

twitter_consumer_key:
├─ Value:    7f8a3b5c...
├─ Scope:    Twitter OAuth
├─ Found in: Constants.kt (compiled from Kotlin)
└─ Risk:    Tweet impersonation possible
```

#### **Metryki Bezpieczeństwa — Risk Score**

```
═══════════════════════════════════════════════════════════════
  SECURITY METRICS & RISK ASSESSMENT
═══════════════════════════════════════════════════════════════

🎯 RISK SCORE CALCULATION

Base Score: 100 points
Deductions:
├─ Critical Issues:     2 × (-15.0) = -30.0
├─ High Issues:         8 × (-4.0)  = -32.0
├─ Medium Issues:      15 × (-1.0)  = -15.0
├─ Low Issues:          7 × (-0.2)  = -1.4
└─ Info Issues:         3 × (0.0)   = 0.0
                                    ─────────
Final Score:           100 - 78.4 = 21.6/100

Risk Rating: 🔴 CRITICAL

📊 SECURITY MATURITY LEVEL (SMLC)

Level 1: Ad-hoc practices
├─ No security testing
├─ Reactive fixes
└─ Status: ✓ Below this

Level 2: Emerging practices
├─ Basic security awareness ✓
├─ Some secure coding knowledge
└─ Status: ← Current

Level 3: Managed practices
├─ Security code reviews
├─ Automated testing
├─ Secure SDLC
└─ Status: ← Target

Level 4: Optimized practices
├─ Continuous security
├─ Threat modeling
├─ Security champions
└─ Status: Advanced

🔍 DETAILED SCORING BY CATEGORY

┌─ Authentication & Session Management ────────────┐
│ Current: 35/100                                   │
│ Issues:                                           │
│  • No certificate pinning (-10)                   │
│  • Weak token validation (-25)                    │
│  • Session timeout not enforced (-30)             │
│ Recommendation: Implement OAuth 2.0 + certification pinning
└──────────────────────────────────────────────────┘

┌─ Data Storage & Confidentiality ──────────────────┐
│ Current: 20/100                                   │
│ Issues:                                           │
│  • Hardcoded credentials (-30)                    │
│  • No encryption at rest (-25)                    │
│  • Shared preferences vulnerable (-25)            │
│ Recommendation: Use EncryptedSharedPreferences + Jetpack DataStore
└──────────────────────────────────────────────────┘

┌─ Network Communication ────────────────────────────┐
│ Current: 45/100                                   │
│ Issues:                                           │
│  • HTTP allowed in some domains (-20)             │
│  • No certificate pinning (-20)                   │
│  • Weak TLS configuration (-15)                   │
│ Recommendation: HTTPS everywhere + implement certificate pinning
└──────────────────────────────────────────────────┘

┌─ Code Quality & Logic ────────────────────────────┐
│ Current: 35/100                                   │
│ Issues:                                           │
│  • SQL Injection patterns (-25)                   │
│  • Insecure deserialization (-15)                 │
│  • Reflection abuse (-10)                         │
│ Recommendation: Code review + static analysis in CI/CD
└──────────────────────────────────────────────────┘

┌─ Platform Security (Manifest) ─────────────────────┐
│ Current: 25/100                                   │
│ Issues:                                           │
│  • Debuggable app (-20)                           │
│  • allowBackup=true (-15)                         │
│  • Exported components (-20)                      │
│ Recommendation: Set debuggable=false, restrict component exports
└──────────────────────────────────────────────────┘

📈 IMPROVEMENT ROADMAP

Phase 1 (0-2 weeks):
├─ Fix CRITICAL issues
├─ Remove hardcoded credentials
├─ Disable debuggable flag
└─ Expected Score: 35/100

Phase 2 (2-4 weeks):
├─ Implement encryption at rest
├─ Add certificate pinning
├─ Fix SQL injection patterns
└─ Expected Score: 55/100

Phase 3 (1-2 months):
├─ Secure user authentication
├─ Implement code obfuscation
├─ Add security testing to CI/CD
└─ Expected Score: 75/100

Phase 4 (Ongoing):
├─ Continuous security monitoring
├─ Penetration testing
├─ Security champion training
└─ Expected Score: 85+/100
```

#### **JSON Raport — Struktura Programowa**

Raport JSON zawiera wszystkie dane w strukturze przeznaczonej do integracji z narzędziami:

```json
{
  "report_meta": {
    "report_id": "1234567890",
    "scan_date": "2026-04-14T14:32:15+00:00",
    "scan_duration": 134,
    "mobsf_version": "3.7.0",
    "python_version": "3.11.6"
  },
  "app_info": {
    "package_name": "com.example.vulnerable",
    "app_label": "Vulnerable App",
    "version_name": "1.0",
    "version_code": 1,
    "target_sdk": 28,
    "min_sdk": 21,
    "app_hash": {
      "md5": "a1b2c3d4e5f6g7h8",
      "sha1": "1a2b3c4d5e6f7g8h9i0j",
      "sha256": "1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p"
    },
    "certificate": {
      "cn": "Example Developer",
      "o": "Example Inc.",
      "validity": "2025-01-01 to 2035-01-01",
      "signature_version": "v1",
      "key_size": 2048
    }
  },
  "security_score": {
    "score": 32,
    "rating": "CRITICAL",
    "risk_level": "HIGH"
  },
  "vulnerabilities": [
    {
      "id": 1,
      "title": "Hardcoded API Key",
      "type": "SAST",
      "severity": "CRITICAL",
      "cvss": {
        "score": 8.0,
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N"
      },
      "cwe": [798],
      "owasp_mobile": ["m2"],
      "file": "MainActivity.java",
      "line": 42,
      "method": "onCreate",
      "code_snippet": "String apiKey = \"sk_live_7f8a3b5c\";",
      "description": "Hardcoded API key found in source code",
      "remediation": [
        "Move API keys to secure backend server",
        "Use OAuth 2.0 authentication",
        "Store keys in EncryptedSharedPreferences"
      ]
    },
    {
      "id": 2,
      "title": "Debuggable Application",
      "type": "Manifest",
      "severity": "CRITICAL",
      "cvss": {
        "score": 7.5,
        "vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"
      },
      "cwe": [489],
      "owasp_mobile": ["m7"],
      "description": "Application has debuggable flag set to true",
      "remediation": [
        "Set android:debuggable=\"false\" in AndroidManifest.xml",
        "Ensure debuggable is only enabled for development builds"
      ]
    }
  ],
  "statistics": {
    "total_issues": 35,
    "critical": 2,
    "high": 8,
    "medium": 15,
    "low": 7,
    "info": 3,
    "activities": 5,
    "services": 2,
    "broadcast_receivers": 1,
    "permissions_dangerous": 4,
    "permissions_total": 22
  },
  "permissions": [
    {
      "name": "android.permission.INTERNET",
      "type": "NORMAL",
      "danger_level": "LOW"
    },
    {
      "name": "android.permission.READ_CONTACTS",
      "type": "DANGEROUS",
      "danger_level": "HIGH",
      "recommendation": "Review necessity of this permission"
    }
  ],
  "exported_components": [
    {
      "name": "LoginActivity",
      "type": "Activity",
      "exported": true,
      "protected_by_permission": false,
      "intent_filters": [
        {
          "action": "android.intent.action.VIEW",
          "category": "android.intent.category.BROWSABLE"
        }
      ],
      "severity": "HIGH"
    }
  ]
}
```

#### **PDF Raport — Format do Drukowania**

Raport PDF zawiera:

```
┌─────────────────────────────────────────────────────────┐
│                                                         │
│  MOBILE SECURITY FRAMEWORK                              │
│  Detailed Security Analysis Report                      │
│                                                         │
│  Application: Vulnerable App                            │
│  Package: com.example.vulnerable                        │
│  Report Date: 2026-04-14                                │
│  Scan ID: 1234567890                                    │
│                                                         │
└─────────────────────────────────────────────────────────┘

TABLE OF CONTENTS
1. Executive Summary...................................... 1
2. Application Information................................ 2
3. Security Score & Risk Assessment...................... 3
4. Vulnerability Details.................................. 5
   4.1 Critical Issues..................................... 5
   4.2 High Issues......................................... 8
   4.3 Medium Issues...................................... 15
   4.4 Low Issues.......................................... 22
5. Manifest Analysis..................................... 25
6. Binary Analysis........................................ 28
7. Certificate Analysis................................... 30
8. Network Security Configuration......................... 31
9. Permissions Review..................................... 33
10. Remediation Recommendations.......................... 35
11. Appendix - Detailed Findings......................... 38

[Page 1]
EXECUTIVE SUMMARY

Risk Rating: CRITICAL (32/100)

This application has CRITICAL security vulnerabilities that
require immediate remediation. The most severe issues include:

• Hardcoded API keys exposing backend access
• Debuggable application flag enabled
• Unprotected exported components
• Missing certificate pinning

Estimated remediation time: 4-6 weeks
Required expertise: Senior Security Engineer

[Continues with 40+ pages...]
```

#### **Export i Integracja Wyników**

MobSF pozwala na export wyników do różnych formatów i systemów:

```
📤 EXPORT OPTIONS

Format              Opis                    Zastosowanie
──────────────────────────────────────────────────────────
JSON                Struktura danych        CI/CD pipelines, APIs
CSV                 Tabelaryczne dane       Excel, data analysis
PDF                 Drukowany raport        Stakeholders, archiwum
HTML                Interaktywny raport     Przeglądarki, web
XML                 Standardowy format      System integracja
Markdown            Dokumentacja Git       GitHub wikis, issues

🔗 INTEGRATIONS

CI/CD Pipeline:
├─ Jenkins          → MobSF plugin
├─ GitLab           → MobSF integration
├─ GitHub Actions   → mobsf-action
├─ Azure Pipelines  → MobSF task
└─ CloudBuild       → Custom image

SIEM & Monitoring:
├─ Splunk           → REST API ingestion
├─ ELK Stack        → Elasticsearch index
├─ Rapid7 InsightVM → Custom connector
└─ Qualys VMDR      → API sync

Issue Tracking:
├─ Jira             → Auto-ticket creation
├─ GitHub Issues    → Auto PR comments
├─ Azure DevOps     → Work item creation
└─ Linear           → Issue automation

📊 COMPARISON REPORTS

MobSF pozwala na porównanie wyników ze skanowań:

Scan 1 (2026-04-10)
├─ Critical:    5
├─ High:        12
├─ Medium:      20
└─ Score:       25/100

Scan 2 (2026-04-14)
├─ Critical:    2 ⬇️ -60%
├─ High:        8  ⬇️ -33%
├─ Medium:      15 ⬇️ -25%
└─ Score:       32/100 ⬆️ +28%

TREND: 📈 IMPROVING — Continue remediation efforts
```

#### **Interpretacja Wyników — Wytyczne dla Testerów**

```
═══════════════════════════════════════════════════════════════
  INTERPRETATION GUIDE
═══════════════════════════════════════════════════════════════

🎯 RISK RATING INTERPRETATION

Score 0-20: CRITICAL 🔴
├─ Application is NOT fit for production
├─ Severe vulnerabilities present
├─ DO NOT RELEASE until fixed
└─ Action: Halt release, intensive remediation

Score 21-40: HIGH 🟠
├─ Application has serious security gaps
├─ Should not be released without fixes
├─ Requires security review and remediation
└─ Action: Fix HIGH issues before beta testing

Score 41-60: MEDIUM 🟡
├─ Application has moderate risks
├─ Can be released with remediation plan
├─ Schedule fixes for next release
└─ Action: Create remediation roadmap

Score 61-80: GOOD 🟢
├─ Application is reasonably secure
├─ Few issues, mostly LOW severity
├─ Suitable for release
└─ Action: Monitor and patch regularly

Score 81-100: EXCELLENT 🟢✓
├─ Application meets best practices
├─ Only INFO issues remaining
├─ Reference implementation
└─ Action: Maintain security posture

⚡ SEVERITY INTERPRETATION

CRITICAL (8.0-10.0):
├─ Publish = immediate breach expected
├─ Example: Hardcoded credentials, RCE, auth bypass
└─ Timeline: Fix within 24-48 hours

HIGH (7.0-7.9):
├─ Significant compromise risk
├─ Example: SQL injection, MITM, data exposure
└─ Timeline: Fix before release

MEDIUM (4.0-6.9):
├─ Moderate compromise risk
├─ Example: Weak crypto, info disclosure
└─ Timeline: Fix in next sprint

LOW (0.1-3.9):
├─ Limited compromise risk
├─ Example: Debug logs, weak password policy
└─ Timeline: Fix in future releases

INFO (N/A):
├─ Informational only
├─ Example: Using deprecated API, old library version
└─ Timeline: Track and upgrade eventually

✅ DECISION MATRIX

Score  Status           Release  Conditions
────────────────────────────────────────────────
0-20   CRITICAL        ❌ NO    Fix all CRITICALs
21-40  HIGH RISK       ❌ NO    Fix all HIGH issues
41-60  MEDIUM RISK     ⚠️  YES  With approval + plan
61-80  LOW RISK        ✓ YES   Monitor post-release
81+    EXCELLENT       ✓ YES   Maintain security

```

Raport ze skanowania w MobSF jest komprehensywnym dokumentem pozwalającym na identyfikację, zrozumienie i ekspedycję podatności w aplikacjach mobilnych. Jest używany zarówno przez testerów bezpieczeństwa, jak i deweloperów do podejmowania decyzji o publikacji aplikacji.
