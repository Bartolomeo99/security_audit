# Audyt Bezpieczenstwa aplikacji serwisu z filmami


### Na potrzeby wykonania audytu wykorzystaliśmy materiały OWASP TOP 10.



# A01: BROKEN ACCESS CONTROL

Kontrola dostępu wymusza takie zasady, aby użytkownicy nie mogli działać poza zamierzonymi uprawnieniami.


Udostępnianie zasobów między źródłami (CORS) to mechanizm oparty na protokole HTTP, który umożliwia serwerowi określanie domen, portów lub schematów, z których przeglądarka może uzyskiwać zasoby. Na przykład, jeśli konfiguracja CORS w naszej aplikacji Django jest ustawiona na True dla wszystkich żądań z nasza_apliakcja.com, nasza aplikacja Django będzie narażona na ataki.
### Code
          
          CORS_ORIGIN_ALLOW_ALL = False
          CORS_ORIGIN_WHITELIST = (
          "https://example.com",
          )

Manipulacja adresem URL:
Również po zalogowaniu nie ma możliwości przełączenia na innego użytkownika wykorzyustując adres URL, ponieważ nie występuje identyfikator użytkownika w samym adresie.

Inną metodą wpływającą na zwiększenie odporności aplikacji jest implementacja uwierzytelnienia JWT(JSON Web Token), który występuje jako dodatek Django Simple JWT, a służy on do bezpiecznego przesyłania danych lub informacji między klientem a serwerem jako obiekt JSON. Każdy JWT zawiera zakodowane obiekty JSON, które mają zestaw roszczeń. Oświadczenia mogą określać, kto wydaje token, jakie uprawnienia są przyznawane klientom lub jak długo token jest ważny. JWT zawiera 3 elementy:

Nagłówek :
                             
        { 
          "alg": "HS256",
          "typ": "JWT",
        }
                              
  Ładunek:  
        
        {
         "sub" : "fist_user",
         "id"  : 1,
         "name": "Jan Kowalski",
         "admin": true
        }
Sygnatura:   Nagłówek i ładunek są kodowane przy użyciu kodowania Base64url. Następnie te dwa są łączone za pomocą separatora. A cały kod jest dostarczany klientowi w procesie uwierzytelniania.   

          HMACSHA256(
            base64UrlEncode(header) + "." +
            base64UrlEncode(payload),
            secret)
#

***
# A02: CRYPTOGRAPHIC FAILURES

Ważnym aspektem bezpieczeństwa aplikacji jest używanie odpowiednich algorytmów kryptograficznych oraz protokołów

W naszej aplikacji występuje domyślne haszowanie wszystkich haseł (domyśnie Django używa algorytmu PBKDF2 z SHA256).


Również, jednym z najważniejszych wymagań jest bezpieczeństwo przesyłanych informacji, ponieważ zawierają wrażliwe dane.

Aplikacja jest hostowana na maszynie wirtualnej, zatem nie posiada certyfikatu TLS.

Zalecanym podejściem jest wymuszenie ruchu poprzez HTTPS:

### Code

                    SECURE_SSL_REDIRECT = TRUE,
                    SESSION_COOKIE = TRUE,
                    CSFR_COOKIE_SECURE = TRUE
                    
  

# A03: INJECTION

Metoda injection może prowadzić do kradzieży danych uwierzytelniających, w tym także haseł. Takie dane moga następnie zostać ujawnione lub sprzedane.

W aplikacji zostały wykorzystane Django Templates, które zapewniają ochronę przed większością ataków XSS (Cross site scripting)

Framework Django zapewnia ochronę przeciwko wsytrzykiwaniu SQL. Kod SQL zapytania jest oddzielony od parametrów zapytania. Ponieważ parametry mogą być dostarczane przez użytkownika, są one zmieniane przez bazowy sterownik bazy danych.

Innym zabezpieczeniem przeciwko SQL injection jest w Django mechanizm ORM (object relational mapping). ORM polega na tym, że użytkownik nie pisze bezpośrednio kodu SQL, lecz używa specjalnego Querysetu. Django następnie konwertuje zapytania z Pythona i komunikuje się z bazą danych.

# A04 INSECURE DESIGN

Insecure Designe reprezentuje pewną metode projektowania aplikacji, z której wynika że niezabezpieczonego projektu nie zdoła zabezpieczyc kod napisany pod kątem bezpieczeństwa, ponieważ 
pewne wymagane zabezpieczenia nie zostały uwzględnione na etapie projektowania aplikacji.
Natomiast bezpieczny projekt może nadal mieć wady implementacyjne prowadzące do luk w zabezpieczeniach.

Korzystając z narzędzia Snyk przeprowadzono analizę kodu. Błąd dotyczył umieszczonej w pliku settings.py zmiennej o nazwie SECRET_KEY.

<img src="https://github.com/KISiM-AGH/audyt-bezpieczenstwa-ksikb/blob/main/images/snyk.png" />


# A05 SECURITY MISCONFIGURATION

Błędy z tej kategorii wynikają z nieprawidłowej konfiguracji aplikacji lub środowiska. Pewne pliki nie mogą być dostępne publicznie.

Nie ma możliwości dostania się do plików poprzez adres url przeglądarki. W aplikacji mogą zostać użyte tylko określone adresy url. W przypadku próby wpisania czegoś innego zwracany jest błąd 404 - nie znaleziono.

<img src="https://github.com/KISiM-AGH/audyt-bezpieczenstwa-ksikb/blob/main/images/error_404.png" />

Framework Django udostępnia moduł django-cors-headers, który zapewnia dodatkowy mechanizm bezpieczeństwa, polegający na wykorzystaniu dodatkowych nagłówków HTTP do poinformaowania przegladarki, czy ma udostępnić dane zwrócone klientowi. Moduł ten nie jest jednak wykorzystywany przez projekt. Brak wykorzystania tego zabezpieczenia może mieć potencjalnie negatywny wpływ na bezpieczeństwo.


# A06: VULNERABLE AND OUTDATED COMPONENTS

W celu ograniczenia podatności na ataki musimy stale aktualizować oraz monitorować poszczególne wersje komponentów naszej aplikacji. Należa do nich m.in. system operacyjny, interfejs API, system zarządzania bazą danych, środowisko oraz biblioteki. Co więcej, konieczne jest usuwanie nieużywanych komponentów oraz plików, gdyż mogą przyczyniać się do zwiększenia ryzyka powstawania luk. Również jest zalecane aby, wszystko pochodziło z oficjalnych źródeł.

W naszej aplikacji głównym problemem jest dość „stara” wersja Django w wersji 3.0.14, podczas gdy obecna stabilna wersja to 4.1.5., dlatego powinna zostać zaktualizowana w celu ograniczenia potencjalnych luk w zabezpieczeniach.

Problem może stanowić również stara wersja adaptera psycopg2. Podczas uruchamiania hosta lokalnego, na którym działa aplikacja, wyświetlane jest ostrzeżenie informujące o zmianach w nadchodzących release-ach. Psycopg2 jest narzędziem łączącym Django i PostgreSQL, więc z punktu widzenia bezpieczeństwa istotne jest, by jego wersja była aktualna.

<img src="https://github.com/KISiM-AGH/audyt-bezpieczenstwa-ksikb/blob/main/images/psycopg2_warning.png" />

# A07: IDENTIFICATON AND AUTHORIZATION FAILURES

Ta sekcja odnosi się do błędów związanych z identyfikacją lub uwierzytelnianiem. W razie wystąpienia takich błędów wzrasta szansa na na uzyskanie dostępu do konta użytkownika.

## Mocne strony aplikacji:
- Hashowanie haseł
- Wymagania dotyczące hasła (musi mieć co najmniej 8 znaków, hasło nie może być zbyt podobne do nazwy użytkownika itp.)
- Mechanizm Captcha
- Możliwość odzyskania zapomnianego hasła poprzez email

## Słabe strony aplikacji:
- Niedostateczna kontrola siły haseł (nie są wymagane liczby czy znaki specjalne)
- Tylko podstawowy mechanizm Captcha
- Brak dodatkowych parametrów uwierzytelniania

<img src="https://github.com/KISiM-AGH/audyt-bezpieczenstwa-ksikb/blob/main/images/rejestracja_1.png" />

<img src="https://github.com/KISiM-AGH/audyt-bezpieczenstwa-ksikb/blob/main/images/rejestracja_2.png" />

# A08: SOFTWARE AND DATA INTEGRITY FAILURES

Niezabezpieczony proces CI/CD może prowadzić do wdrożenia, przez osoby nieautoryzowane, ich własnych aktualizacji, szczególnie tam gdzie proces wdrażania nowych wersji odbywa się automatycznie. 

W celu ograniczenia ryzyka wystąpienia powyższego zagrożenia zaleca się użycie odpowiednich mechanizmów mających na celu rozpoznanie czy komponenty pochodzą z bezpiecznego źródła.

W przypadku audytowanej aplikacji, nowa wersja jest wdrażana manualnie przez programistę, zatem posiada on wgląd zarówno w kod jak i w konfigurację.

# A09: SECURITY LOGGING AND MONITORING FAILURES

W momencie, gdy dochodzi do włamania, użytkownik powinien mieć możliwość uzyskania informacji o tym, jak doszło do włamania i do jakich danych osoba włamująca się uzyskała dostęp. W tym celu niezbędne może okazać się zapisywanie dużej ilości informacji na temat aplikacji i środowiska.

W aplikacji nie są zaimplementowane żadne dodatkowe mechanizmy monitorowania. Nie są również przechowywane szczegółowe informacje dotyczące aplikacji i jej działania.

# A10: SERVER-SIDE REQUEST FORGERY (SSRF)
SSRF może pozwolić na pobranie zdalnego zasobu z niebezpiecznego adresu URL, pomimo zastosowania np. VPN czy ACL. Na tym etapie warto zadbać o wyłączenie przekierowań HTTP.
  
W analizowanej aplikacji występuje brak funkcjonalności pobrania zasobu z niepożądanego adresu URL, czyli na tym etapie występuję ochrona wynikająca z stosunkowo małej liczby funkcjonalności samej aplikacji.

