# Symmetric key cryptography - a crypto challenge

---

# Ilustracija Symmetric key cryptography metode
![Symmetric_key_cryptography.png](/Images/Symmetric_key_cryptography.png)

### Glavni elementi:

- **Plaintext** - podatak koji enkriptiramo
- **Encryption algorithm** - algoritam koji enkriptira podatak
- **Secret symmetric key** - ključ po kojem algoritam enkriptira/dekriptira podatak (simetričan je jer se koristi i za enkripciju i za dekripciju)
- **Ciphertext** - enkriptirani podatak
- **Decryption algorithm** - algoritam koji dekriptira podatak

---

# Opis vježbe

### Zadatak:

- Otkriti koji je naš enkriptirani dokument
- Pronaći odgovorajući ključ te pomoću njega dekriptirati enkriptirani dokument

Za potrebe ove vježbe koristili smo **Pyhton**.

Za rješavanje našeg zadatka, potrebna nam je bila Python biblioteka ***cryptography***.

*Plaintext* ****kojeg smo trebali otkriti bio je enkriptiran korištenjem *high-level* sustava za simetričnu enkripciju - **Fernet**.

S obzirom na to da je jedan od glavnih uvjeta za uspješno obavljanje zadatka bio rad u Pythonu (*verzija 3*), prvo smo morali stvoriti **virtualno okruženje**.

**Virtualno okruženje** smo stvorili kako bismo izbjegli eventualne konflikte (ukoliko se na računalu nalazi instalirano više verzija Pythona).

Na adresi [http://a507-server.local](http://a507-server.local/) se nalazilo nekoliko enkriptiranih datoteka. Došli smo do našeg prvog zadatka koji je bio otkriti koja datoteka od ponuđenih pripada nama.

Da bismo otkrili koja datoteka odgovara kojem studentu, koristili smo idući blok koda:

```python
from cryptography.hazmat.primitives import hashes

def hash(input):
	if not isinstance(input, bytes):
		input = input.encode()

	digest = hashes.Hash(hashes.SHA256())
	digest.update(input)
	hash = digest.finalize()
	
	return hash.hex()

filename = hash('nikolic_malora_duje') + ".encrypted"
```

> NAPOMENA: Prilagodio sam inicijalni blok koda da odgovara onom kojeg sam ja koristio.
> 

Kada smo otkrili koja je naša datoteka, *downloadali* smo je i pohranili u direktorij u kojem se nalazila naša Python skripta za dekripciju podataka.

Naša datoteka je bila enkriptirana **ključem ograničene entropije - 22 bita**.

22 bita znači da ukupno postoji **4.194.304 (2^22) kombinacija** **ključeva**. S obzirom da se radi o relativno malom broju, koristit ćemo **Brute-force napad**.

Kao pomoć za uspješno rješavanje zadatka smo imali sljedeći blok koda:

```python
ctr = 0
while True:
    key_bytes = ctr.to_bytes(32, "big")
    key = base64.urlsafe_b64encode(key_bytes)

    ctr += 1
```

Glavna ideja je bila da kroz *while* petlju iteracijom provjerimo svih 4.194.304 ključeva. Međutim, bio nam je potreban jedan ključan podatak pomoću kojeg bismo znali da je određeni ključ ispravan ključ, a ujedno i uvjet pomoću kojeg bismo izašli iz petlje.

> NAPOMENA: Unutar *while* petlje smo također dodali blok koda koji nam ispisuje trenutni broj testiranih ključeva (svaki tisućiti).
> 

Profesor nam je u jednom dijelu vježbe naglasio kako je enkriptirani podatak **slika**, točnije datoteka **png** formata. Ovo će nam kasnije biti od velike pomoći.

- Enkripcija: **C = E_K(P)**
- Dekripcija: **P = D_k(C)**

Glavno polazište nam je bilo što znamo što je naš *ciphertext*, ali nismo znali ni *plaintext* ni ključ.

Tako da smo do *plaintext-a* došli **trial-and-error** metodom.

Varijabli *ciphertext* smo pridružili vrijednost naše enkriptirane datoteke pomoću sljedećeg bloka koda koji služi za učitavanje datoteka u Pythonu:

```python
with open(filename, "rb") as file:
    ciphertext = file.read()
```

> NAPOMENA: Varijabla *filename* je ime naše enkriptirane datoteke.
> 

Unutar *while* petlje smo prilikom svake iteracije pomoću trenutnog ključa ***k*** pokušali dekripcijskim algoritmom dekriptirati *ciphertext* te bismo tu vrijednost pridružili varijabli *plaintext*.

> NAPOMENA: Ovdje nam je dobro poslužila činjenica da znamo kakvog je tipa enkriptirana datoteka.
> 

Nakon što bismo dobili *plaintext* za trenutnu iteraciju pozvali bismo funkciju ***test_png**.*

U funkciju ***test_png*** slali bismo **header** - prva 32 bita *plaintext-a*.

Unutar funkcije ***test_png*** smo provjeravali odgovara li naša varijabla header (string) header-u datoteka png formata. Ukoliko bi bilo poklapanja, funkcija bi vratila istinu i došlo bi do pucanja *while* petlje. Na ovaj način smo znali i koji je naš *plaintext* i koji je ključ.

Jedino što nam je još preostalo bilo je spremiti naš *plaintext* u obliku datoteke.

To smo učinili pomoću idućeg bloka koda koji služi za spremanje datoteka u Pythonu:

```python
with open(filename, "wb") as file:
    file.write(plaintext)
```

Programu je trebalo malo duže vremena da se izvrti zato što smo prilikom svake iteracije imali dekripciju. Međutim, kada bi se program uspješno izvršio, unutar direktorija u kojem se nalazila Python skripta bi se također stvorila i naša dekriptirana datoteka (*plaintext*).

Uspješnim otvaranjem dekriptirane datoteke smo završili drugu laboratorijsku vježbu koja se bavila Symmetric key kriptografijom.
