# Online and Offline Password Guessing Attacks

---

# Opis vježbe

U okviru pete po redu laboratorijske vježbe, dotaknut ćemo se **online** i **offline** **password guessing** napada. Također ćemo prikazati neke od **alata** koji se koriste kod password guessing napada te ćemo prokomentirati **vremena izvršavanja** kao i moguće **mjere opreza** koje možemo poduzeti da bi se zaštitili od ovakvih vrsta napada.

---

## Online password guessing

Prvi dio laboratorijski vježbi smo posvetili **online password guessing** napadu.

Većinu cjelokupnih laboratorijskih vježbi smo radili u **Windows Terminalu**.

S obzirom da kod online password guessing napada kao **napadač** komuniciramo sa **serverom**, trebali smo se uvjeriti možemo li uspostaviti komunikaciju između nas i servera. To smo učinili **pinganjem** željenog servera:

```python
ping a507-server.local
```

Kako smo bili spojeni na lokalnu mrežu fakulteta, htjeli smo **ograničiti komunikaciju** na uređaje koji se isključivo nalaze u našem laboratoriju. Za to nam je pomogao alat **nmap** kojeg je bilo potrebno instalirati:

```python
sudo apt-get update
sudo apt-get install nmap

nmap
```

> **nmap** - utility for network discovery and security auditing
> 

Korištenjem sljedeće naredbe u Windows Terminalu smo ograničili komunikaciju na **16 različitih IP adresa** (16 uparenih uređaja):

```python
nmap -v 10.0.15.0/28
```

Kako smo spojeni na lokalnu mrežu, mogli smo pristupiti web adresi [http://a507-server.local/](http://a507-server.local/) s koje smo pročitali naše korisničko ime i IP adresu.

U mom slučaju **username** je bio **nikolic_malora_duje**, a **IP adresa 10.0.15.5**.

Korištenjem **ssh klijenta** smo se probali spojiti na server korištenjem našeg username-a i IP adrese:

```python
ssh nikolic_malora_duje@10.0.15.5
```

Međutim, nismo imali pristup serveru jer nas je klijent tražio **lozinku**. Naš zadatak je bio saznati je.

Da bismo izveli **online password guessing** napad, bio nam je potreban alat **hydra** kojeg smo trebali instalirati. Nakon instalacije alata, uz pomoć dva **hint-a** smo započeli naš napad.

### Hintovi:

- lozinka se sastoji od **lowercase** slova (u američkoj abecedi ih ima **26**)
- dužina lozinke je **između** **4** **i 6** **znakova**

Napad smo započeli uz pomoć naredbe:

```python
hydra -l nikolic_malora_duje -x 4:6:a 10.0.15.5 -V -t 1 ssh
```

> NAPOMENA: **4:6:a** predstavlja naš uvjet. **4:6** predstavlja ***range*** lozinke, a **:a** govori da se radi o *lowercase* slovima. **-t** parametar označava koliko zahtjeva šaljemo serveru. Trebamo voditi računa o tome da taj parametar bude mali broj kako ne bismo opteretili server i prouzročili pad servera.
> 

### Matematički pogled na zadatak:

Već smo spomenuli kako se radi o lozinci koja se sastoji od *lowercase* slova te je dužine između 4 i 6 znakova.

S obzirom da se radi o *lowercase* slovima, znamo da ih ima **26** (ASCII tablica, američka abeceda).

A kako je šifra dužine između 4 i 6 znakova, primjenom **kombinatorike** imamo sljedeće rješenje matematičkog problema:

![Math behind our problem (Password guessing attacks).png](Online%20and%20Offline%20Password%20Guessing%20Attacks%20116aa1a51f824e7081d5aa5937b52e26/Math_behind_our_problem_(Password_guessing_attacks).png)

> NAPOMENA: Problem je riješen uz pomoć aproksimacije brojeva na **potencije broja 2**. Uz pomoć kombinatorike smo izračunali da postoji mogućih **2 na 30 kombinacija lozinke**. Pokretanjem zadatka smo dobili povratnu informaciju da je *rate* zahtjeva **64 po minuti**. Što znači da nam je potrebno **2 na 24 minuta** da bi *izvrtili* sve lozinke. Ako se to pretvori u godine, to je ukupno **2 na 5**, odnosno **32 godine**.
> 

S obzirom da se radi o prevelikom vremenskom periodu, koristit ćemo **dictionary** te ćemo izvesti **pre-computed dictionary attack**.

Profesor nam je priložio već kreirani *dictionary* kojeg je bilo potrebno preuzesti sa [http://a507-server.local:8080/](http://a507-server.local:8080/). To smo napravili korištenjem alata **wget**:

```python
wget -r -nH -np --reject "index.html*" http://a507-server.local:8080/dictionary/g4/
```

Unutar *dictionary-a* se sada nalazilo 840 mogućih kombinacija lozinki, od kojih je jedna sigurno bila naša. Ponovnim korištenjem **hydra** alata smo izvršili **online password guessing** napad, ali ovaj put nam je *range* lozinki bio *dictionary*, a ne *4:6:a*:

```python
hydra -l nikolic_malora_duje -P dictionary/g4/dictionary_online.txt 10.0.15.5 -V -t 4 ssh
```

> NAPOMENA: Statistički bi se naša lozinka trebala nalaziti po sredini *dictionary-a*, ali u praksi to ne mora biti slučaj.
> 

Kada smo iz **online password guessing** napada dobili našu lozinku, pomoću **ssh klijenta** smo se *logirali* na *remote* server te od tamo kreće drugi dio laboratorijskih vježbi (**offline password guessing** napad).

> KOMENTAR: Moja lozinka je bila: **coomen**.
> 

---

## Offline password guessing

Nakon što smo se uspješno ulogirali na *remote* server, krećemo sa **offline password guessing** napadom.

Ovu vrstu napada izvest ćemo korištenjem ***hasheva*** koji se nalaze pohranjeni u **Linux** OS-u.

Oni se nalaze u folderu kojem pristup ima samo **administrator**.

Iako smo mi bili povezani kao običan korisnik na server (bez velikih ovlasti), pripadali smo grupi u kojoj pripada i administrator, pa smo uz pomoć **sudo** naredbe mogli pristupiti navedenom folderu.

To smo učinili na sljedeći način:

```python
sudo cat /etc/shadow
```

Pokretanjem ove naredbe nam se ispisala lista korisnika navedena s njihovim ***hashevima***.

Izabrali smo proizvoljno nekog korisnika i njegov ***hash***.

> KOMENTAR: Ja sam odabrao korisnika *freddie_mercury*.
> 

Kopiranu ***hash*** vrijednost smo spremili na naš lokalni uređaj (u **hash.txt** datoteku) s kojeg ćemo kasnije izvesti **offline password guessing** napad.

**Offline password guessing** napad izvest ćemo uz pomoć **hashcat** alata, pa ga prvo trebamo instalirati te provjeriti je li instalacija uspješno izvršena:

```python
sudo apt-get install hashcat

hashcat
```

Kao kod prijašnjeg napada, ovdje također imamo dva *hint-a*.

### Hintovi

- lozinka se sastoji od **lowercase** slova (u američkoj abecedi ih ima **26**)
- dužina lozinke je točno **6** **znakova**

Na temelju pruženih informacija i uz pomoć alata **hashcat**, započeli smo naš napad:

```python
hashcat --force -m 1800 -a 3 hash.txt ?l?l?l?l?l?l --status --status-timer 10
```

> NAPOMENA: *?l?l?l?l?l?l* predstavlja format naše lozinke.
> 

Ukupan broj kombinacija je otprilike isti kao i kod prethodnog napada te unatoč činjenici što je *hash* funkcija brža nekih 100 puta, **razlika** u odnosu na prethodni napad je **zanemarivo mala**.

Stoga smo opet koristili *dictionary* kojeg smo za potrebu prethodnog napada već skinuli.

Sada ćemo uz pomoć *dictionary-a* **smanjiti broj mogućih kombinacija** (cca. 50000) te ponovno, korištenjem **hashcat** alata, izvršiti napad:

```python
hashcat --force -m 1800 -a 0 hash.txt dictionary/g4/dictionary_offline.txt --status --status-timer 10
```

Nakon što nam je u povratnoj informaciji vraćena lozinka, preko **ssh klijenta** smo se prijavili na server kako bismo potvrdili uspješnost izvršenog zadatka:

```python
ssh freddie_mercury@10.0.15.5
```

Uspješnom prijavom na server smo zaključili pete po redu laboratorijske vježbe iz kolegija *Sigurnost računala i podataka*.