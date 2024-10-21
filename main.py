# App til ping en IP addresse
#  Følgende parametre:
#     param dest_ip: IP-adressen på destinationen som skal pinges.
#     param count: Antal pings.
#     param timeout: Timeout i msekunder.
# Ib Helmer Nielsen/ UCN 2024
# Import
from scapy.all import *
import time

def icmp_ping(dest_ip, count=4, timeout=2):
    for i in range(count):
        packet = IP(dst=dest_ip) / ICMP()                           # Lav en ICMP-pakke
        # Registrerer afsendelsestidspunktet
        start_time = time.time()
        reply = sr1(packet, timeout=timeout, verbose=False)   # Sender pakke og venter på svar
        if reply:
            round_trip_time = (time.time() - start_time) * 1000     # Konverterer til millisekunder
            print(f"Ping til {dest_ip}: svar modtaget! TTL={reply.ttl} Tid={round_trip_time:.2f}ms")
        else:
            print(f"Ping til {dest_ip}: Ingen svar.")

if __name__ == "__main__":
    # Indtast den IP-adresse du vil teste her
    ip_address = input("Indtast IP-adresse for ping: ")
    icmp_ping(ip_address)