# Man-in-the-middle attacks (ARP spoofing)

---

# Opis vježbe

Za potrebe ove vježbe radili smo u terminalu.

Korištenjem *docker* tehnologije virtualizirali smo 3 uređaja te smo ih povezali u virtualnu mrežu. 

### Uređaji:

- **evil-station** - uređaj kojim ćemo prisluškivati promet između klijenta i servera
- **station-1** - uređaj koji će se ponašati kao klijent
- **station-2** - uređaj koji će se ponašati kao server

Spojili smo se u terminal **station-1** uređaja te smo naredbom **ifconfig** saznali njegovu IP (172.29.0.2) i MAC (:02) adresu. Preostalo nam je još saznati IP (172.29.0.4) i MAC (:04) adresu **station-2** uređaja. Najlakši način na koji smo to mogli učiniti je **pinganjem** **station-2** uređaja.

Korištenjem **netcat** alata uspostavili smo vezu klijent-server između uređaja **station-1** i **station-2**. 

Promet između navedena dva uređaja odvijao se u oba smjera.

Sljedeći potez je bio ubaciti napadača **evil-station** u kanal kojim komuniciraju ****uređaji **station-1** i **station-2**. Ovim potezom se također narušava **vjerodostojnost**.

Da bismo presreli promet između dvije žrtve, izvoru podataka (u našem slučaju je to bio **station-1**) smo se, u ulozi napadača (**evil-station**), trebali predstaviti kao **station-2**. Da bismo postigli takvu situaciju, koristili smo alat **arpspoof**.

Uspješno smo se kao napadač pronašli između dvije žrtve te možemo čitati podatke koji se razmjenjuju između njih. U ovoj situaciji je narušena i **povjerljivost** podataka.

Da bismo narušili i **dostupnost** podataka, prvo moramo razumjeti na koji način funkcionira ARP spoofing. Kako napadač uspije zavarati žrtve?

Ideja je da se napadač (**evil-station**) meti napada (**station-1**) predstavi kao domaćin (**station-2**). Tada **station-1** svoje podatke šalje **evil-stationu**, a **evil-station** ih prosljeđuje **stationu-2**.

Kada ih **evil-station** nebi prosljeđivao **stationu-2**, tada bi bila narušena **i dostupnost** podataka.

Valja napomenuti kako je nakon narušavanja **dostupnosti** podataka još uvijek moguća razmjena podataka u smjeru od **stationa-2** prema **stationu-1**.

Komentarom na **dostupnost** podataka zaključili smo prvu laboratorijsku vježbu koja se bavila Man-in-the-middle napadima.

---

# Ilustracija Man-in-the-middle napada

![ARP spoofing.png](Man-in-the-middle%20attacks%20(ARP%20spoofing)%209155ea1c36db4ef78c792cb05a86622e/ARP_spoofing.png)

---

# Primjer izgleda terminala za vrijeme ARP spoofinga

![c6b082fb-5092-4bb1-8300-7741fed2561c_copy.jpg](Man-in-the-middle%20attacks%20(ARP%20spoofing)%209155ea1c36db4ef78c792cb05a86622e/c6b082fb-5092-4bb1-8300-7741fed2561c_copy.jpg)