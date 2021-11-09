# Message Authentication Code (MAC)

---

# Ilustracija Message Authentication Code (MAC) mehanizma

![Message Authentication Code.png](Message%20Authentication%20Code%20(MAC)%208fc2882c323f4ea3a0972cb24b864f0c/Message_Authentication_Code.png)

### Glavni elementi:

- **message m** - poruka koju izvor šalje odredištu
- **K** - enkripcijski ključ
- **MAC algorithm** - algoritam koji stvara MAC pomoću ključa
- **MACk(m)** - Message Authentication Code

---

# Opis vježbe

Na laboratorijskim vježbama smo imali dva izazova. Prvi izazov smo rješili uz pomoć profesora dok je drugi izazov bio samostalan. Glavna problematika kojom smo se bavili na laboratorijskim vježbama bio je **Message Authentication Code (MAC)**.

**Message Authentication Code** služi kako bi se očuvao integritet poruke.

---

## Princip rada Message Authentication Code mehanizma

Da bismo stvorili MAC potrebni su nam poruka koju namjeravamo poslat te ključ (po mogućnosti velike entropije). Python ima biblioteke koje sadrže funkcije za stvaranje MAC-a. Glavna ideja je da funkciji koja stvara MAC kao argumente pošaljemo **poruku** i **ključ**. Funkcija nam vrati generirani **MAC**. Mi kao izvorište (*source*) poruku zajedno s MAC-om šaljemo odredištu (*destination*).

Kada odredište primi poruku (i MAC), poruku "provuče" kroz isti **MAC algoritam** koristeći **isti ključ**.

Odredište ovime kreira vlastiti MAC kojeg će **usporediti** s onim kojeg smo mi, kao izvorište, poslali.

Ukoliko ne bude podudaranja, odredište će znati da je poruka najvjerojatnije mijenjana te je time **narušen integritet** poruke.

> NAPOMENA: S obzirom na to da je MAC uvijek iste duljine, a poruka može biti proizvoljne duljine, moguće je da dvije različite poruke mogu imati isti MAC. Iako je ova vjerojatnost vrlo mala, ta opcija nije isključena.
> 

---

## Izazov 1

U **Izazovu 1** smo prikazali *background* Message Authentication Code mehanizma. Koristeći vrlo jednostavan primjer smo pokazali kako se generira MAC za neku određenu poruku uz pomoć ključa te kako ćemo provjeriti je li očuvan integritet te iste poruke.

Koristili smo HMAC mehanizam iz Python biblioteke - **cryptography**.

Za početak smo kreirali **tekstualnu datoteku** i u nju unijeli našu poruku koju želimo zaštititi.

Pomoću sljedećeg bloka koda smo sadržaj naše poruke pohranili u varijablu:

```python
with open(filename, "rb") as file:
     message = file.read()
```

Sljedeći korak nam je bio pomoću varijable u koju smo pohranili poruku generirat **MAC** kojeg bismo kasnije poslali (zajedno s porukom i ključem) u funkciju koja bi provjerila je li očuvan integritet poruke. Za generiranje MAC-a smo koristili funkciju ***generate_MAC***:

```python
def generate_MAC(key, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    mac = h.finalize()
    return mac
```

> NAPOMENA: Generirali smo proizvoljno neki ključ.
> 

Nakon što smo generirali MAC, pozvali smo funkciju ***verify_MAC*** koja je na temelju proslijeđene poruke i ključa generirala novi MAC te sigurnom usporedbom provjerila podudaranje s MAC-om kojeg smo joj mi proslijedili. Ukoliko bi podudaranja bilo, funkcija bi vratila istinu, a u suprotnom neistinu. Funkciju ***verify_MAC*** smo definirali na način:

```python
def verify_MAC(key, mac, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(mac)
    except InvalidSignature:
        return False
    else:
        return True
```

Promjenom izvorne poruke te pokretanjem Python skripte (koja je u konzoli ispisala "False*"*) smo dokazali i pokazali na koji način radi Message Authentication Code mehanizam.

---

## Izazov 2

**Izazov 2** je bio samostalni izazov.

Na **lokalnom serveru** su se nalazili direktoriji s našim imenima. Unutar svakog direktorija se nalazilo 20 tekstualnih datoteka. 10 poruka i 10 MAC-ova. Ovaj izazov se uvelike naslanja na **Izazov 1** uz male modifikacije i nadogradnje.

Za početak smo trebali te datoteke preuzeti u naš direktorij na računalu, međutim, da bismo izbjegli manualno preuzimanje datoteka koristili smo program **wget**.

Program smo preuzeli i pohranili u naš direktorij te korištenjem naredbe u terminalu izvršili automatsko preuzimanje datoteka:

```python
wget.exe -r -nH -np --reject "index.html*" http://a507-server.local/challenges/nikolic_malora_duje/
```

Nakon što smo preuzeli tekstualne datoteke, kreirali smo Python skriptu te *importali* potrebne funkcije iz biblioteke **cryptography**:

```python
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature
```

Naš zadatak je bio učitati 20 tekstualnih datoteka (10 poruka i 10 MAC-ova), a zatim provjeriti je li narušen integritet poruke. Na izlazu je bilo potrebno ispisati sadržaj poruke te poklapa li se naš generirani MAC za određenu poruku s MAC-om kojeg smo učitali iz tekstualne datoteke.

U konačnici [kod](https://github.com/nduje/Sigurnost-ra-unala-i-podataka/blob/main/Vje%C5%BEba%203/izazov.py) je izgledao ovako:

```python
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.exceptions import InvalidSignature
import os

def verify_MAC(key, mac, message):
    if not isinstance(message, bytes):
        message = message.encode()

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(message)
    try:
        h.verify(mac)
    except InvalidSignature:
        return False
    else:
        return True

if __name__ == "__main__":

    path = os.path.join("challenges", "nikolic_malora_duje", "mac_challenge")
    print(path)

    key = "nikolic_malora_duje".encode()
    
    for ctr in range(1, 11):
        msg_filename = f"order_{ctr}.txt"
        sig_filename = f"order_{ctr}.sig"

        with open(path + "\\" + msg_filename, "rb") as file:
            message = file.read()

        with open(path +  "\\" + sig_filename, "rb") as file:
            mac = file.read()

        is_authentic = verify_MAC(key, mac, message)

        print(f'Message {message.decode():>45} {"OK" if is_authentic else "NOK":<6}')
```

Za početak valja primjetiti kako smo koristili funkciju ***verify_MAC*** iz prethodnog izazova.

**Ključ** korišten pri stvaranju MAC-a nastao je iz našeg **imena** i **prezimena**.

S obzirom da se naše tekstualne datoteke nisu pohranile u istom direktoriju gdje je bila pohranjena skripta, bilo je potrebno kreirati ***path*** do potrebnog direktorija. Principijalno, to smo napravili "zbrajajući" stringove koji su predstavljali imena poddirektorija.

Da bismo izbjegli redudantnost, čitav proces smo izveli unutar ***for* petlje** koja se ukupno izvršila **10 puta**. Za svaki par poruke i MAC-a po jednom. Unutar *for* petlje smo, za svaki par, pohranili poruku i MAC u varijable *message* i *mac*. Pozivom funkcije ***verify_MAC*** smo provjerili autentičnost poruke te na izlazu ispisali njen sadržaj i OK/NOK (*true/false*).

Na izlazu smo dobili sljedeći [ispis](https://github.com/nduje/Sigurnost-ra-unala-i-podataka/blob/main/Vje%C5%BEba%203/ispis_izazova.txt):

```python
Message     Buy 89 shares of Tesla (2021-11-09T17:23) OK
Message     Buy 92 shares of Tesla (2021-11-13T23:49) OK
Message     Buy 36 shares of Tesla (2021-11-13T17:18) OK
Message    Sell 16 shares of Tesla (2021-11-15T22:42) OK
Message    Sell 90 shares of Tesla (2021-11-15T18:26) OK
Message    Sell 46 shares of Tesla (2021-11-15T04:51) OK
Message    Sell 85 shares of Tesla (2021-11-11T14:48) NOK
Message    Sell 14 shares of Tesla (2021-11-13T05:24) OK
Message     Buy 70 shares of Tesla (2021-11-13T13:32) OK
Message     Buy 47 shares of Tesla (2021-11-12T07:36) OK
```

Ovime smo završili **Izazov 2**, a time i treću laboratorijsku vježbu. Uz to smo, na zanimljiv način, pokazali kako funkcionira nešto što je postalo dio čovjekove svakodnevnice, odnosno **Message Authentication Code** mehanizam.