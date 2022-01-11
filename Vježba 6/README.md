# Linux permissions and ACLs

---

# Opis vježbe

Na šestoj, a ujedno i posljednjoj laboratorijskoj vježbi smo se upoznali s postupkom upravljanja korisničkim računima na operacijskom sustavu *Linux*. Laboratorijska vježba se uvelike naslanjala na **kontrolu pristupa** *file-ovima* *Linux* operacijskog sustava, a čije smo znanje usvojili na predavanjima.

Laboratorijsku vježbu smo podijelili u četiri glavna koraka kroz koje ćemo na prezentacijskom primjeru vidjeti kako se kontrolira pristup.

### Koraci:

1. Kreiranje novog korisničkog računa
2. Standardna prava pristupa datotekama
3. Kontrola pristupa korištenjem *Access Control Lists (ACL)*
4. Linux procesi i kontrola pristupa

---

# 1. Kreiranje novog korisničkog računa

> U *Linux-u* svaka datoteka ili program (*binary executable file*) ima **vlasnika** (*user or owner*). Svakom **korisniku** pridjeljen je jedinstveni **identifikator** - *User ID (UID)*. Svaki korisnik mora pripadati barem jednoj **grupi** (*group*), pri čemu **više korisnika** može **dijeliti** istu grupu. *Linux* **grupe** također imaju jedinstvene **identifikatore** - *****Group ID (GID)*.
> 

Vježbu smo započeli spajanjem na *Linux* računalu preko Windows Terminala korištenjem naredbe:

```python
wsl
```

Kako bi smo saznali ***identitet*** našeg korisnika, koristili smo naredbu:

```python
id
```

Osim našeg *identiteta* bilo je potrebno uvjeriti se da pripadamo administratorskoj grupi ***sudo*** kako bismo mogli nastaviti s vježbom. Za ispis svih grupa kojoj korisnik pripada koristimo naredbu:

```python
groups
```

Naš sljedeći zadatak (nakon što smo se uvjerili da pripadamo administratorskoj grupi *sudo*) bio je **kreirati novog korisnika**. To vršimo uz pomoć naredbe:

```python
sudo adduser alice4
```

> NAPOMENA: Uz ime korisnika (npr. *alice*) dodali smo sufiks 4, što označava našu laboratorijsku grupu. To smo učinili zbog toga što su studenti iz prethodnih grupa već kreirali korisnike sa tim imenima.
> 

Da bi smo se *logirali* kao novokreirani korisnik koristimo naredbu:

```python
su - alice4
```

Program nas pita da upišemo lozinku koju smo postavili prilikom kreiranja novog korisnika.

Da bi smo se *“odlogirali”* i vratili se u *shell* korisnika koji ima administratorske ovlasti koristimo naredbu:

```python
exit
```

Na isti način smo kreirali i korisnika *bob4* te smo korisnicima koje smo kreirali provjerili *identitet* i grupe u koje oni pripadaju.

---

# 2. Standardna prava pristupa datotekama

U sljedećem koraku smo se *logirali* kao *alice4* te smo *home* direktoriju kreirali novi direktorij *srp*.

Unutar kreiranog direktorija smo također kreirali **tekstualnu datoteku ***security.txt* u koju smo upisali *“Hello world”*.

Naredbe koje smo koristili za izvršavanje navede akcije bile su:

```python
mkdir srp

cd srp

echo "Hello world" > security.txt

cat security.txt
```

> NAPOMENA: Naredbom ***echo*** smo unijeli tekst u datoteku, a naredbom ***cat*** smo ispisali sadržaj te datoteke.
> 

Da bismo provjerili prava vezana za datoteku ili direktorij koristimo naredbu **getfacl**. Za naš primjer smo provjerili tko ima kakve ovlasti za direktorij *srp* i za datoteku *security.txt*. To smo učinili na sljedeći način:

```python
getfacl .

getfacl security.txt
```

Povratnim informacijama smo mogli vidjeti i zaključiti da najveća prava imaju vlasnik i njegova grupa, dok svi ostali *(other)* imaju samo pravo čitanja.

> NAPOMENA: Postoje 3 osnovna prava: pravo **čitanja**, pravo **pisanja**, pravo **izvršavanja**. Ta prava se razlikuju za direktorije i datoteke te predstavljaju druga značenja.
> 

U narednim koracima smo se “poigrali” sa pravima na način da smo:

- oduzeli pravo čitanja datoteke vlasniku *(alice4)*
- dodali pravo čitanja datoteke vlasniku *(alice4)*
- oduzeli pravo izvršavanja direktorija vlasniku *(alice4)*
- dodali pravo izvršavanja direktorija vlasniku *(alice4)*
- dodali pravo čitanja datoteke korisniku *bob4* (odnosno *other*)

Te radnje smo izvršili uz pomoć naredbe ***chmod***:

```python
chmod u-r security.txt

chmod u+r security.txt

chmod u-x .

chmod u+x srp/

chmod o-r security.txt
```

Sljedeći nam je zadatak bio vratiti korisniku *bob4* ****pravo čitanja, ali na “indirektan” način. Odnosno na način da **korisnika *bob4* dodamo u grupu *alice4***. Da bismo to napravili, bila su nam potrebna **administratorska prava** pa smo se *“odlogirali”* sa korisnika *alice4* te se vratili u *shell* korisnika koji ima administratorska prava. Dodavanje korisnika u grupu radimo pomoću naredbe:

```python
usermod -aG alice4 bob4
```

---

# 3. Kontrola pristupa korištenjem *Access Control Lists (ACL)*

Za inspekciju i modifikaciju **ACL-ova** resursa (datoteka i direktorija) koristimo naredbe ***getfacl*** i ***setfacl***.

Korisniku *bob4* moramo ukloniti prava čitanja datoteke *security.txt* kako bismo mogli nastaviti sljedeći korak.

Korisniku *bob4* dodat ćemo prava čitanja korištenjem naredbe *setfacl*:

```python
setfacl -m u:bob4:r security.txt
```

Postoji alternativni način na koji korisniku *bob4* možemo dati prava čitanja. Možemo **kreirati novu grupu** kojoj ćemo **pridijeliti prava** čitanja te ćemo svakog novog korisnika kojem želimo pridjeliti ista prava dodavati u tu grupu.

Kreiranje nove grupe vršimo naredbom:

```python
groupadd alice_reading_group_4
```

> NAPOMENA: Za kreiranje nove naredbe moramo imati administratorske ovlasti.
> 

Sada ćemo korisniku *bob4* ****pridjeliti prava čitanja dodavanjem ga u grupu *alice_reading_group_4*.

Međutim prvo korisniku *bob4* moramo ukinuti prethodno dodijeljena prava, prava dodijeliti grupi *alice_reading_group_4* te onda korisnika *bob4* dodati u grupu:

```python
setfacl -r u:bob4 security.txt

setfacl g:alice_reading_group_4:r security.txt

usermod -aG alice_reading_group_4 bob4
```

---

# 4. Linux procesi i kontrola pristupa

***Linux* procesi** su programi koji se trenutno izvršavaju u odgovarajućem adresnom prostoru. Svaki proces ima **vlasnika (UID)** i jedinstveni **identifikator procesa**, *process identifier* **PID**.

Da bismo uspješno odradili posljednji od četiri navedena velika koraka, moramo korisnika *bob4* ukloniti iz grupe *alice_reading_group_4*. To radimo sljedećom naredbom:

```python
gpasswd -d bob4 alice_reading_group_4
```

U direktoriju u kojem se trenutno nalazimo u ulozi administratora ćemo otvoriti **Visual Studio Code** te unutar njega napisati ***python* skriptu** kojom ćemo **provjeravati *user ID-eve*** korisnika (koji pokreću skriptu) te ćemo provjeravati **možemo li**, kao taj korisnik, **otvoriti datoteku** *security.txt*.

Sadržaj *python* skripte glasi:

```python
import os

print('Real (R), effective (E) and saved (S) UIDs:') 
print(os.getresuid())

with open('/home/alice4/srp/security.txt', 'r') as f:
    print(f.read())
```

Kada izvršimo skriptu kao administrator:

- R: 1000, E: 1000, S: 1000
- možemo otvoriti datoteku

> NAPOMENA: Iako administrator se ne nalazi u ACL-u koji je vezan za datoteku *security.txt*, on svejedno može tu datoteku otvoriti što je i intuitivno.
> 

Kada izvršimo skriptu kao *alice4*:

- R: 1006, E: 1006, S: 1006
- možemo otvoriti datoteku

Kada izvršimo skriptu kao *bob4*:

- R: 1007, E: 1007, S: 1007
- ne možemo otvoriti datoteku jer nemamo prava (*permission denied*)

## Dodatni zadatak

Poznato je da pristup ***/etc/shadow** file-u* ima samo *root* korisnik, odnosno onaj korisnik koji se nalazi u grupi *root*. Također je poznato da se u *shadow file-u* nalaze *hash-evi* *password-a*.

Znamo da mi kao korisnik možemo mijenjati našu korisničku lozinku (i bez administratorskih prava).

Postavlja se pitanje: “Kako?”.

Kada korisnik pošalje zahtjev za promjenu lozinke, on privremeno preuzme ID od *root* korisnika (efektivni) te mu je na taj način omogućen pristup i modifikacija *shadow file-a*.

Dakle u slučaju kad je korisnik *bob4* htio promijeniti lozinku naredbom:

```python
passwd
```

Njegovi ID-evi su glasili:

| Real | Effective | Saved |
| --- | --- | --- |
| 1007 | 1000 | 1000 |

> NAPOMENA: 1000 je ID od korisnika *student* koji ima administratorska prava.
> 

Komentarom na dodatni zadatak smo zaključili šeste po redu laboratorijske vježbe, a ujedno i **posljednje laboratorijske vježbe** iz kolegija *Sigurnost računala i podataka.*