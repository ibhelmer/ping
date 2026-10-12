#!/usr/bin/env python3
"""En simpel IPv4-ping med Scapy.

Kør: python ping_scapy.py 192.168.1.1
Uden et argument spørger programmet efter en IP-adresse eller et værtsnavn.
Kræver Scapy og rettigheder til at sende/modtage rå netværkspakker.
På Windows kræves desuden Npcap.
"""

import os
import socket
import sys
import time

from scapy.all import ICMP, IP, Raw, sr1
from scapy.error import Scapy_Exception


def ping(vaert: str, antal: int = 4, timeout: float = 2.0) -> bool:
    """Send ICMP Echo Request. Returner True, hvis mindst ét ping besvares."""
    if not vaert.strip() or not 1 <= antal <= 65535 or not 0 < timeout < float("inf"):
        raise ValueError("Angiv en vært, antal 1–65535 og en positiv, endelig timeout.")

    # Omsæt et værtsnavn til IPv4. En IPv4-adresse kan også bruges direkte.
    ip = socket.gethostbyname(vaert.strip())
    identifikation = os.getpid() & 0xFFFF
    modtaget = 0

    print(f"Pinger {vaert} ({ip}) med {antal} ICMP-pakker:\n")

    for sekvens in range(1, antal + 1):
        # / sammensætter lagene: IPv4-header / ICMP-header / data.
        pakke = (
            IP(dst=ip)
            / ICMP(type=8, code=0, id=identifikation, seq=sekvens)
            / Raw(load=b"Scapy ping")
        )

        # Send én pakke og vent på et matchende svar eller timeout.
        svar = sr1(pakke, timeout=timeout, verbose=False, chainCC=True)

        if svar is None:
            print(f"Timeout: seq={sekvens} — intet svar inden for {timeout:g} s")
        elif (
            IP in svar and ICMP in svar
            and svar[IP].src == ip
            and svar[ICMP].type == 0 and svar[ICMP].code == 0
            and svar[ICMP].id == identifikation
            and svar[ICMP].seq == sekvens
        ):
            # RTT i millisekunder ud fra Scapys sende- og modtagetidsstempler.
            rtt_ms = float(svar.time - pakke.sent_time) * 1000
            modtaget += 1
            print(
                f"Svar fra {svar[IP].src}: seq={sekvens} "
                f"ttl={svar[IP].ttl} tid={rtt_ms:.2f} ms"
            )
        else:
            # Eksempelvis ICMP Destination Unreachable eller Time Exceeded.
            print(f"Fejl/andet svar: seq={sekvens} — {svar.summary()}")

        if sekvens < antal:
            time.sleep(1)

    tab = antal - modtaget
    print(f"\nSendt={antal}, modtaget={modtaget}, tabt={tab} ({tab / antal:.0%} tab)")
    return modtaget > 0


if __name__ == "__main__":
    try:
        vaert = sys.argv[1] if len(sys.argv) > 1 else input("IP-adresse eller værtsnavn: ")
        sys.exit(0 if ping(vaert) else 1)
    except socket.gaierror:
        sys.exit("Fejl: IP-adressen eller værtsnavnet kunne ikke findes.")
    except PermissionError:
        sys.exit("Fejl: Kør programmet som administrator eller med sudo.")
    except (OSError, Scapy_Exception, ValueError) as fejl:
        sys.exit(f"Fejl: {fejl}")
    except (KeyboardInterrupt, EOFError):
        sys.exit("\nAfbrudt.")
