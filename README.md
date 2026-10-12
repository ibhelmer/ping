# Ping med Python og Scapy

Et enkelt undervisningseksempel på en IPv4-pingfunktion. Programmet sender ICMP Echo Request og kontrollerer, om svaret er et tilsvarende ICMP Echo Reply.

## Filer

- `ping_scapy.py`: løsningen med dansk kommenteret kode.
- `requirements.txt`: programmets Python-afhængighed, Scapy.
- `.gitignore`: udelader blandt andet Python-cache og lokale virtuelle miljøer fra nye commits.
- `main.py`: den eksisterende fil i repoet; den er bevaret uændret.

## Funktioner

Som standard sendes fire ping med en timeout på to sekunder pr. pakke. Programmet viser sekvensnummer, TTL og round-trip time (RTT) for hvert godkendt svar og afslutter med antal sendte, modtagne og tabte pakker. Der er en pause på ét sekund efter hvert forsøg, undtagen det sidste; det er ikke et fast sendeinterval på ét sekund.

Både IPv4-adresser og værtsnavne kan bruges. Et svar tælles kun som et vellykket ping, når ICMP-type, kode, afsenderadresse, identifikation og sekvensnummer matcher. Andre svar, eksempelvis ICMP-fejl, vises uden at blive talt som vellykkede ping.

## Installation og kørsel

### Windows

Installer Python 3 og [Npcap](https://npcap.com/). Følg [Scapys installationsvejledning](https://scapy.readthedocs.io/en/latest/installation.html) for Npcap-indstillinger.

Kør følgende i repoets mappe:

```powershell
python -m pip install -r requirements.txt
```

Åbn derefter terminalen som administrator og kør:

```powershell
python ping_scapy.py 192.168.1.1
```

### Debian, Ubuntu eller Kali Linux

```bash
sudo apt update
sudo apt install python3-scapy
sudo python3 ping_scapy.py 192.168.1.1
```

Erstat `192.168.1.1` med adressen på den vært, du vil teste. Startes programmet uden et argument, spørger det efter en IP-adresse eller et værtsnavn:

```bash
sudo python3 ping_scapy.py
```

## Brug funktionen fra Python

```python
from ping_scapy import ping

besvaret = ping("192.168.1.1", antal=10, timeout=1.0)
print("Mindst ét ping blev besvaret:", besvaret)
```

`ping()` returnerer `True`, hvis mindst ét ping besvares korrekt, ellers `False`. Ved direkte kørsel afslutter programmet med exitkode `0` ved mindst ét godkendt svar og `1` ved ingen godkendte svar, en håndteret fejl eller afbrydelse. Funktionen kræver de samme netværksrettigheder, når den importeres.

Antal og timeout ændres via funktionsparametrene; kommandolinjen accepterer kun værten som første argument.

## Hvordan virker det?

```python
pakke = IP(dst=ip) / ICMP(type=8, code=0, id=identifikation, seq=sekvens) / Raw(load=b"Scapy ping")
svar = sr1(pakke, timeout=timeout, verbose=False, chainCC=True)
```

`/` sammensætter protokollagene. `sr1()` sender pakken og venter på det første matchende svar. ICMP-type `8` er Echo Request, og type `0` er Echo Reply. RTT beregnes i millisekunder som forskellen mellem Scapys modtage- og afsendelsestidsstempler.

## Afgrænsning og kontrol

Eksemplet understøtter IPv4, ikke IPv6. Det er et undervisningsprogram og ikke en komplet erstatning for operativsystemets pingkommando. Manglende svar er ikke i sig selv bevis for, at en vært er slukket.

Syntaksen kan kontrolleres uden at sende netværkspakker:

```bash
python -m py_compile ping_scapy.py
```

Koden er syntakskontrolleret ved upload. Der er ikke udført en test mod et fysisk netværk i forbindelse med denne upload.

## Referencer

- [Scapy: installation](https://scapy.readthedocs.io/en/latest/installation.html)
- [Scapy: brug og pakkeopbygning](https://scapy.readthedocs.io/en/latest/usage.html)
- [RFC 792: Internet Control Message Protocol](https://www.rfc-editor.org/rfc/rfc792)
