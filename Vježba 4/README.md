# Password-hashing (iterative hashing, salt, memory-hard functions)

---

# Ilustracija pohrane lozinki

## Spremanje novog korisnika

![Loading a new user.png](https://github.com/nduje/Sigurnost-ra-unala-i-podataka/tree/main/Images/Loading_a_new_user.png)

## Verifikacija lozinke

![Verifying a password.png](https://github.com/nduje/Sigurnost-ra-unala-i-podataka/tree/main/Images/Verifying_a_password.png)

---

# Pohrana lozinki

Mnogi serveri i sustavi za autentikaciju korisnika koriste zaporke/lozinke.

**Lozinke** su zbog svoje jednostavnosti i jeftinosti jedan od najzastupljenijih načina autentikacije korisnika.

Lozinke su objekti čija **povjerljivost** mora biti očuvana i sa strane korisnika i sa strane servera.

Međutim, da bi server potvrdio da je korisnik uistinu korisnik kojim se predstavlja da je, mora se provesti određena provjera.

Prilikom prvog pristupa serveru (npr. *registracija*) korisnik serveru pristupa svoj *username* i svoj ***password*** (lozinku). Server lozinku hashira koristeći snažne i pouzdane kriptografske ***hash*** funkcije.

Server unutar svoje baze podataka sprema korisnikov *username* zajedno sa *hash* vrijednosti njegove lozinke.

Prilikom prijave korisnika, korisnik upisuje svoju lozinku koja se hashira te se ta *hash* vrijednost **uspoređuje** sa *hash* vrijednosti koja je pohranje u bazu podataka zajedno sa korisnikovim *username-om*. Ukoliko postoji podudaranje, korisnik je **autenticiran** i može nastaviti sa svojim akcijama na serveru.

Korištenje kriptografskih *hash* funkcija znamo da je sigurno u ovom slučaju zbog njihovih svojstava:

**one-wayness** i **collision-resistance**.

---

# Opis vježbe

U okviru ove vježbe analizirat ćemo jedan od najzastupljeniji način autentikacije korisnika, a to su **zaporke/lozinke**.

Da bismo uspješno izvršili vježbu, za početak je bilo potrebno instalirati potrebne pakete koji su nam potrebni za pokretanje koda. S obzirom da se prvi put susrećemo s paketima ***prettytable*** i ***passlib***, trebali smo ih instalirati preko Windows Terminala korištenjem sljedećih naredbi:

```python
pip install prettytable
pip install passlib
```

Kroz ovu laboratorijsku vježbu, analizirat ćemo i prokomentirati tri aspekta korištenja zaporki:

- Usporedba *brzih* i *sporih* kriptografskih *hash* funkcija.
- Razumijevanje suštine pojmova *spore/brze* funkcije.
- Demonstracija *memory-hard* funkcija.

### Kod potreban za izvođenje laboratorijske vježbe

```python
from os import urandom
from prettytable import PrettyTable
from timeit import default_timer as time
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from passlib.hash import sha512_crypt, pbkdf2_sha256, argon2

def time_it(function):
    def wrapper(*args, **kwargs):
        start_time = time()
        result = function(*args, **kwargs)
        end_time = time()
        measure = kwargs.get("measure")
        if measure:
            execution_time = end_time - start_time
            return result, execution_time
        return result
    return wrapper

@time_it
def aes(**kwargs):
    key = bytes([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    ])

    plaintext = bytes([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    ])

    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    encryptor.update(plaintext)
    encryptor.finalize()

@time_it
def md5(input, **kwargs):
    digest = hashes.Hash(hashes.MD5(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def sha256(input, **kwargs):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def sha512(input, **kwargs):
    digest = hashes.Hash(hashes.SHA512(), backend=default_backend())
    digest.update(input)
    hash = digest.finalize()
    return hash.hex()

@time_it
def pbkdf2(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = b"12QIp/Kd"
    rounds = kwargs.get("rounds", 10000)
    return pbkdf2_sha256.hash(input, salt=salt, rounds=rounds)

@time_it
def argon2_hash(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = b"0"*22
    rounds = kwargs.get("rounds", 12)              # time_cost
    memory_cost = kwargs.get("memory_cost", 2**10) # kibibytes
    parallelism = kwargs.get("rounds", 1)
    return argon2.using(
        salt=salt,
        rounds=rounds,
        memory_cost=memory_cost,
        parallelism=parallelism
    ).hash(input)

@time_it
def linux_hash_6(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = "12QIp/Kd"
    return sha512_crypt.hash(input, salt=salt, rounds=5000)

@time_it
def linux_hash(input, **kwargs):
    # For more precise measurements we use a fixed salt
    salt = kwargs.get("salt")
    rounds = kwargs.get("rounds", 5000)
    if salt:
        return sha512_crypt.hash(input, salt=salt, rounds=rounds)
    return sha512_crypt.hash(input, rounds=rounds)

@time_it
def scrypt_hash(input, **kwargs):
    salt = kwargs.get("salt", urandom(16))
    length = kwargs.get("length", 32)
    n = kwargs.get("n", 2**14)
    r = kwargs.get("r", 8)
    p = kwargs.get("p", 1)
    kdf = Scrypt(
        salt=salt,
        length=length,
        n=n,
        r=r,
        p=p
    )
    hash = kdf.derive(input)
    return {
        "hash": hash,
        "salt": salt
    }

if __name__ == "__main__":
    ITERATIONS = 100
    password = b"super secret password"

    MEMORY_HARD_TESTS = []
    LOW_MEMORY_TESTS = []

    TESTS = [
        {
            "name": "AES",
            "service": lambda: aes(measure=True)
        },
        {
            "name": "HASH_MD5",
            "service": lambda: sha512(password, measure=True)
        },
        {
            "name": "HASH_SHA256",
            "service": lambda: sha512(password, measure=True)
        }
    ]

    table = PrettyTable()
    column_1 = "Function"
    column_2 = f"Avg. Time ({ITERATIONS} runs)"
    table.field_names = [column_1, column_2]
    table.align[column_1] = "l"
    table.align[column_2] = "c"
    table.sortby = column_2

    for test in TESTS:
        name = test.get("name")
        service = test.get("service")

        total_time = 0
        for iteration in range(0, ITERATIONS):
            print(f"Testing {name:>6} {iteration}/{ITERATIONS}", end="\r")
            _, execution_time = service()
            total_time += execution_time
        average_time = round(total_time/ITERATIONS, 6)
        table.add_row([name, average_time])
        print(f"{table}\n\n")
```

---

## Usporedba *brzih* i *sporih* kriptografskih *hash* funkcija

Prvo razmatranje koje smo proveli u okviru ovih laboratorijskih vježbi je usporedba brzih i sporih kriptografskih *hash* funkcija. Nealternirana verzija koda ispisuje prosječna vremena izvršavanja triju enkripcijskih funkcija (vrši se 100 poziva).

Navedeni algorimi su:

- AES
- HASH_SHA256
- HASH_MD5

Kao što smo već naučili u prethodnim predavanjima, AES je enkripcijski algoritam koji se koristi kod simetrične enkripcije, dok su SHA256 i MD5 kriptografske *hash* funkcije.

Ispis programa je bio u obliku tablice iz koje smo mogli zaključiti da su *hash* funkcije znatno brže od AES enkripcijskog algoritma.

Međutim, u sigurnosti nam to nije uvijek najpogodnije.

### Pre-computed dictionary attack

Postoje različiti načini na koje hakeri mogu izvršiti napad na ovakav sustav. Jedan od načina je tzv. **pre-computed dictionary attack**. Kod ovakvog napada napadač kreira tablicu značajne veličine (od milijun do milijardu redaka). Napadaču je na raspolaganju znatan broj često korištenih/popularnih/predvidljivih lozinki. Napadač koristeći kriptografsku *hash* funkciju hashira lozinke te *hash* vrijednost u paru sa svojom pripadnom lozinkom pohranjuje **sortirano u tablicu**.

Na ovaj način napadač može, ukoliko dođe do *leak-a* *hash* vrijednosti, jednostavnom pretragom tablice saznati korisnikovu lozinku. Da bi se zaštitili od ovakvog napada, često se koriste preventivne metode.

Jedna od preventivnih metoda je **"usporiti"** *hash* funkciju. Upravo iz ovog razloga vidimo zašto ponekad nije idealan slučaj imati najbrži enkripcijski algoritam.

*Hash* funkciju možemo usporiti primjenom **iterativne metode**.

### Iterativna metoda (password stretching)

Umjesto da lozinku ***p*** hashiramo jedanput i pohranimo *hash* vrijednost ***H(p)***, hashirat ćemo ***p*** iterativnih ***n*** puta te pohraniti ***H^n(p) = H(...H(H(p))...)***.

Ovaj proces se proces **ne može paralelizirati** zato što nam za svaku trenutnu *hash* vrijednost treba prethodna *hash* vrijednost. Na taj način se vrijeme hashiranja povećava ***n*** puta.

Korištenjem **iterativne metode** ćemo usporiti napadača te ga možda i demotivirati.

Naravno, logično je da ova metoda usporava i **legitimni server**, ali to nije veliki problem jer ćemo u stvarnoj praksi, za određenog korisnika, *hash* funkcije koristiti jednom, do dva puta dnevno.

Naš izbor ***n-a*** ovisi isključivo o različitim okolnostima te je na nama da procijenimo najbolji odabir za danu situaciju.

### Dodatak kodu

Nakon teorijskog uvoda, vratimo se na našu laboratorijsku vježbu. Sada kada poznajemo moguće opasnosti te njihove preventivne metode, možemo alternirati naš kod kako bismo mogli analizirati utjecaj iterativne metode na izvršavanje *hash* funkcija. Uz dosada korištene AES, SHA256 i MD5 funkcije, pozvat ćemo još i **linux_hash** funkciju. Nju ćemo pozvati dva puta, gdje ćemo, koristeći **iterativnu metodu**, jednom lozinku hashirati **5000** puta, a jednom **1000000** (milijun) puta.

Izmijenili smo idući dio koda:

```python
TESTS = [
        {
            "name": "AES",
            "service": lambda: aes(measure=True)
        },
        {
            "name": "HASH_MD5",
            "service": lambda: sha512(password, measure=True)
        },
        {
            "name": "HASH_SHA256",
            "service": lambda: sha512(password, measure=True)
        },
				{
            "name": "linux_hash_5k",
            "service": lambda: linux_hash(password, measure=True)
        },
        {
            "name": "linux_hash_1M",
            "service": lambda: linux_hash(password, rounds=10**6, measure=True)
        }
    ]
```

Pokretanjem skripte unutar Windows Terminala, dobili smo uvid u rezultate vremenskog mjerenja.

Primijetili smo da je za **5000** hashiranja *hash* funkcija otprilike **1000 puta sporija** od kriptografske **SHA256** *hash* funkcije. Dok je za funkciju koja iterativno hashira **milijun puta** u prosjeku potrebno oko **1.25** **sekundi** što je previše čak i za legitimni server. Međutim, kao što smo već spomenuli, broj iterativnih hashiranja najviše ovisi o okolnostima i trenutnoj situaciji, tako da se radi o relativnim vrijednostima.

Ovime smo završili usporedbu i analizu *brzih* i *sporih* kriptografskih *hash* funkcija.

---

> **NAPOMENA:** U planu je bilo prokomentirati preostala dva *bulleta*, ali to smo preskočili kako nebismo gubili vrijeme predviđeno za laboratorijsku vježbu 5.
>
