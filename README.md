# Ping med Python og Scapy

Et dansk undervisningseksempel på IPv4-ping med både terminalprogram og grafisk brugerflade.
Scapy bygger og sender ICMP Echo Request og kontrollerer de modtagne svar.
Operativsystemets `ping`-kommando bruges ikke.

**Grafisk version: 1.0.0 · Copyright © 2026 Ib Helmer Nielsen**

## Filer

| Fil | Formål |
| --- | --- |
| `ping_gui.py` | Grafisk brugerflade med Tkinter. Start denne fil for at bruge GUI'en. |
| `ping_engine.py` | GUI'ens Scapy-ping, svarvalidering, statistik og CSV-eksport. |
| `start_ping_gui.bat` | Windows-startfil; bruger `.venv`, når den findes. |
| `tests/test_ping.py` | Automatiserede, netværksfri tests. |
| `ping_scapy.py` | Den eksisterende, dansk kommenterede terminalversion; uændret. |
| `main.py` | Det oprindelige undervisningseksempel; uændret. |
| `requirements.txt` | Python-afhængigheden Scapy; uændret. |
| `.gitignore` | Udelader blandt andet Python-cache og virtuelle miljøer; uændret i repoet. |

## Grafisk version

GUI'en er baseret på samme pakkeopbygning og kontrol af Echo Reply som `ping_scapy.py`.
Den har dansk brugerflade, Start/Stop, en resultattabel, en løbende RTT-graf, statistik,
CSV-eksport og en Om-knap med forklaring, version, copyright og link til repository.

### Windows: installation

Brug **Python 3.10 eller nyere med Tcl/Tk/Tkinter** og installer
[Npcap](https://npcap.com/#download). Følg
[Scapys aktuelle Windows-vejledning](https://scapy.readthedocs.io/en/latest/installation.html#windows).
Scapy anbefaler at slå *WinPcap compatibility mode* fra i Npcap-installationen.

Hent repoet med GitHub Desktop, eller brug Git:

```powershell
git clone https://github.com/ibhelmer/ping.git
cd ping
```

Har du allerede repoet lokalt, kan du hente opdateringen med `git pull` i mappen.
Opret et virtuelt miljø og installer Scapy:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

Det er ikke nødvendigt at aktivere miljøet eller ændre PowerShells execution policy.

### Windows: start

Åbn PowerShell **som administrator**, gå til repoets mappe, og kør:

```powershell
.\.venv\Scripts\python.exe ping_gui.py
```

Alternativt: højreklik på `start_ping_gui.bat` og vælg **Kør som administrator**.
Startfilen installerer ikke noget og foretager ikke automatisk rettighedsforhøjelse.
Den bruger `.venv\Scripts\python.exe`, hvis filen findes, ellers `python` fra PATH.

Uden et virtuelt miljø kan du bruge følgende i den Python-installation, du vil køre programmet med:

```powershell
python -m pip install -r requirements.txt
python ping_gui.py
```

### Debian, Ubuntu eller Kali Linux

Kør fra et grafisk skrivebord:

```bash
sudo apt update
sudo apt install python3-scapy python3-tk
sudo python3 ping_gui.py
```

GUI'en kræver adgang til skrivebordets display. Hvis `sudo` giver en display-/autorisationsfejl,
skal sessionens `DISPLAY`/`XAUTHORITY` håndteres efter din distributions opsætning.
En almindelig SSH-session uden grafisk viderestilling kan ikke vise Tkinter-vinduet;
brug i stedet terminalversionen. Slå ikke generelt displayets adgangskontrol fra.

### Indstillinger

| Felt | Standard | Tilladte værdier og betydning |
| --- | --- | --- |
| IPv4-adresse eller værtsnavn | `127.0.0.1` | En enkelt vært, eksempelvis din routers adresse. Ingen URL, port eller IPv6. |
| Antal | `4` | `1–65535`, eller `0` for at fortsætte indtil Stop. |
| Timeout | `2` s | `0,1–30` sekunders svartimeout pr. ping. |
| Pause efter forsøg | `1` s | `0,1–60` sekunder efter hvert svar/timeout, undtagen det sidste. |
| Udgående TTL | `64` | `1–255`. Tabelkolonnen TTL viser derimod det modtagne svars TTL. |
| Data | `32` byte | `0–1400` byte ICMP-data, uden IP- og ICMP-headere. |

Både decimalkomma og decimalpunktum accepteres i timeout og pause.
**Pause er ikke et fast sendeinterval**: tiden mellem afsendelser omfatter også svarets ventetid
og Scapys behandling. Der er højst ét pingforsøg i gang ad gangen.

Tryk **Start**, eller brug Enter. **Antal 0** fortsætter indtil **Stop** eller Escape.
Stop afbryder pausen og forhindrer nye forsøg. Et igangværende `sr1()`-kald eller DNS-opslag
færdiggøres først. DNS har operativsystemets tidsgrænser, ikke feltet Timeout; også driver-/ARP-arbejde
kan påvirke ventetiden. Vinduet arbejder videre imens.

Hver Start nulstiller forrige måling. Eksportér resultaterne først, når de skal gemmes.
GUI'en vælger automatisk netkort gennem Scapys routning; der er ikke manuel netkortvælger.

### Resultater og statistik

Et svar tæller kun som **Svar**, når afsenderens IPv4-adresse samt ICMP-type `0`, kode `0`,
identifikation og sekvensnummer matcher det sendte Echo Request.
RTT beregnes af Scapys sende- og modtagetidsstempler, ikke af hele funktionens køretid.
Manglende eller ugyldige tidsstempler vises uden en RTT-værdi og indgår ikke i RTT-gennemsnittet.

**Timeout**, **ICMP-fejl** og **Andet svar** tæller ikke som godkendte svar.
ICMP-fejl viser blandt andet Destination Unreachable eller Time Exceeded og den konkrete kode.
En lokal DNS-, driver- eller rettighedsfejl stopper målingen med en fejlmeddelelse og tælles
ikke som et afsluttet pingforsøg. Statistikken opdateres, når det enkelte forsøg afsluttes.

Grafen viser de seneste 120 forsøg. Kryds betyder intet målbart Echo Reply; det er **ikke 0 ms RTT**.
Grafen brydes ved manglende målepunkter. Tabellen har både lodret og vandret rullepanel.

For at begrænse hukommelsesforbruget bevares de **seneste 5000 resultater** i tabel og CSV.
Statistikken dækker fortsat **hele den aktuelle måling**, også efter at ældre rækker er fjernet.
CSV-eksport er et øjebliksbillede og kan foretages, mens målingen kører. Der er ikke automatisk
lagring af tidligere målinger, og data går tabt ved lukning, medmindre de er eksporteret.

### CSV-format

CSV-filen bruger **UTF-8 med BOM**, **semikolon** mellem felterne og **decimalkomma** i `rtt_ms`.
Det passer blandt andet til danske Excel-indstillinger. Filerne indeholder en kolonneoverskrift:

```text
timestamp;host;target_ipv4;number;icmp_sequence;source_ipv4;status;rtt_ms;reply_ttl;request_payload_bytes;message
```

| Kolonne | Indhold |
| --- | --- |
| `timestamp` | Tidspunkt, hvor forsøget afsluttes, i ISO 8601 med lokal UTC-forskydning. |
| `host` | Det indtastede værtsnavn eller den indtastede adresse. |
| `target_ipv4` | Den IPv4-adresse, der faktisk blev testet. |
| `number` | Fortløbende forsøgsnummer i målingen. |
| `icmp_sequence` | Pakkens 16-bit ICMP-sekvensnummer; starter forfra efter 65535, mens id ændres. |
| `source_ipv4` | Afsender af det modtagne svar; tom ved timeout. |
| `status` | `Svar`, `Timeout`, `ICMP-fejl` eller `Andet svar`. |
| `rtt_ms` | RTT i millisekunder med tre decimaler; tom uden en gyldig RTT-måling. |
| `reply_ttl` | TTL fra det modtagne svar; tom ved timeout. |
| `request_payload_bytes` | Antal sendte ICMP-databyte, uden protokolheadere. |
| `message` | Forklaring eller ICMP-fejlkode. |

Felter med skilletegn citeres efter almindelige CSV-regler. Visse potentielle formelværdier
forsynes med en indledende apostrof ved eksport for at modvirke regnearksformler.

## Den eksisterende terminalversion

`ping_scapy.py` og `main.py` er bevaret uændret. Terminalversionen kan stadig bruges uden GUI:

```powershell
python ping_scapy.py 192.168.1.1
```

På Linux:

```bash
sudo python3 ping_scapy.py 192.168.1.1
```

Uden argument spørger `ping_scapy.py` efter en IPv4-adresse eller et værtsnavn.
Som standard sender det fire ping med to sekunders timeout og et sekunds pause efter hvert
forsøg undtagen det sidste. Antal og timeout ændres via funktionsparametre, ikke CLI-flag:

```python
from ping_scapy import ping

besvaret = ping("192.168.1.1", antal=10, timeout=1.0)
print("Mindst ét ping blev besvaret:", besvaret)
```

Funktionen returnerer `True`, hvis mindst ét ping besvares korrekt, ellers `False`.
Ved direkte kørsel er exitkoden `0` ved mindst ét godkendt svar og `1` ved ingen godkendte
svar, en håndteret fejl eller afbrydelse. Importeret brug kræver samme netværksrettigheder.

## Opbygning til undervisning

Grundprincippet er fortsat:

```python
pakke = IP(dst=ip) / ICMP(type=8, code=0, id=identifikation, seq=sekvens) / Raw(load=b"Scapy ping")
svar = sr1(pakke, timeout=timeout, verbose=False)
```

`/` sammensætter protokollagene. ICMP-type `8` er Echo Request, og type `0` er Echo Reply.
GUI'ens konkrete udgave i `ping_engine.py` tilføjer TTL, datastørrelse og strukturerede resultater.
Den bruger `chainEX=True`, så sendefejl kan rapporteres i vinduet.

`ping_gui.py` kører Tkinter i hovedtråden. En worker-tråd i `ping_engine.py` står for DNS og Scapy.
En trådsikker kø og Tkinter `after()` overfører status og resultater; worker-tråden kalder aldrig widgets.
Logik og GUI er adskilt, så svarvalidering, statistik, stopadfærd og CSV kan testes uden netværk.

## Test og kendte afgrænsninger

```powershell
python -m py_compile ping_gui.py ping_engine.py ping_scapy.py
python -m unittest discover -s tests -v
```

På en Linux-testmaskine uden et fysisk display kan GUI-testene køres med Xvfb:

```bash
xvfb-run -a python -m unittest discover -s tests -v
```

Ved udarbejdelsen af GUI version 1.0.0 blev **31 tests bestået**, herunder GUI-test under Xvfb.
**Én test af faktiske Scapy-pakketyper blev sprunget over**, fordi Scapy ikke var installeret i
buildmiljøet og ikke kunne hentes der. De øvrige pakketests bruger attrapper; GUI/worker-tests bruger
simulerede netværksresultater. Syntaks og layout er også kontrolleret, inklusive vinduets minimumsstørrelse.
**Der er ikke udført en live-netværkstest eller en Windows/Npcap-test i buildmiljøet.**

Kør derfor en lokal kontrol med `127.0.0.1`, din egen router, et gyldigt værtsnavn og et ugyldigt
værtsnavn efter installation. Kontrollér også Stop under en timeout og ved Antal 0.

Programmet understøtter kun IPv4 og er et undervisnings-/diagnoseværktøj, ikke en komplet
erstatning for operativsystemets ping eller et system til vedvarende overvågning.
Manglende svar beviser ikke, at en vært er slukket: ICMP kan filtreres eller begrænses.
Test kun netværk og værter, du har tilladelse til at undersøge.

## Referencer

- [Repository](https://github.com/ibhelmer/ping)
- [Scapy: installation](https://scapy.readthedocs.io/en/latest/installation.html)
- [Scapy: send/modtag og sr1](https://scapy.readthedocs.io/en/latest/api/scapy.sendrecv.html)
- [Scapy: brug og pakkeopbygning](https://scapy.readthedocs.io/en/latest/usage.html)
- [Python: Tkinter og trådmodel](https://docs.python.org/3/library/tkinter.html#threading-model)
- [RFC 792: Internet Control Message Protocol](https://www.rfc-editor.org/rfc/rfc792)
