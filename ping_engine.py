#!/usr/bin/env python3
"""Netværksdel til Scapy Ping GUI, baseret på repoets ping_scapy.py.

Samme princip: IP / ICMP Echo Request / Raw -> sr1 -> kontroller Echo Reply.
Ingen Tkinter-kald her; resultater sendes til GUI'en gennem en kø.
Copyright (c) 2026 Ib Helmer Nielsen.
"""
from __future__ import annotations

import csv
import ipaddress
import math
import re
import secrets
import socket
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from threading import Event
from typing import Any, Callable, Iterable

VERSION = "1.0.0"
REPOSITORY = "https://github.com/ibhelmer/ping"
MAX_ROWS = 5000


@dataclass(frozen=True)
class Settings:
    host: str
    count: int = 4             # 0 betyder fortsæt indtil Stop.
    timeout: float = 2.0
    pause: float = 1.0         # Pause EFTER svar/timeout, ikke fast sendeinterval.
    ttl: int = 64
    payload_bytes: int = 32    # Data alene, uden IP- og ICMP-headere.

    def validate(self) -> None:
        host = self.host.strip()
        if not host or len(host) > 253:
            raise ValueError("Angiv en IPv4-adresse eller et værtsnavn (højst 253 tegn).")
        if ":" in host:
            raise ValueError("Kun IPv4 understøttes. Angiv ikke IPv6, port eller en URL.")
        try:
            ascii_host = host.rstrip(".").encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise ValueError("Værtsnavnet er ugyldigt.") from exc
        label = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
        if not all(re.fullmatch(label, part) for part in ascii_host.split(".")):
            raise ValueError("Angiv kun en IP-adresse eller et værtsnavn, ikke en URL eller sti.")
        if re.fullmatch(r"[0-9.]+", host) and "." in host:
            try:
                ipaddress.IPv4Address(host)
            except ipaddress.AddressValueError as exc:
                raise ValueError("IPv4-adressen er ugyldig.") from exc
        for name, value, lower, upper in (
            ("Antal", self.count, 0, 65535),
            ("TTL", self.ttl, 1, 255),
            ("Datastørrelse", self.payload_bytes, 0, 1400),
        ):
            if type(value) is not int or not lower <= value <= upper:
                raise ValueError(f"{name} skal være et heltal mellem {lower} og {upper}.")
        for name, value, lower, upper in (
            ("Timeout", self.timeout, 0.1, 30),
            ("Pause", self.pause, 0.1, 60),
        ):
            if isinstance(value, bool) or not isinstance(value, (float, int)):
                raise ValueError(f"{name} skal være et tal.")
            if not math.isfinite(value) or not lower <= value <= upper:
                raise ValueError(f"{name} skal være mellem {lower} og {upper} sekunder.")


@dataclass(frozen=True)
class Result:
    timestamp: str
    number: int
    sequence: int
    target: str
    source: str
    status: str
    rtt_ms: float | None
    ttl: int | None
    payload_bytes: int
    message: str


@dataclass
class Statistics:
    """Statistik for alle afsluttede forsøg, også når gamle tabelrækker fjernes."""
    sent: int = 0
    received: int = 0
    timed: int = 0
    total_ms: float = 0.0
    min_ms: float | None = None
    max_ms: float | None = None

    def add(self, result: Result) -> None:
        self.sent += 1
        if result.status == "Svar":
            self.received += 1
            if result.rtt_ms is not None:
                self.timed += 1
                self.total_ms += result.rtt_ms
                self.min_ms = result.rtt_ms if self.min_ms is None else min(self.min_ms, result.rtt_ms)
                self.max_ms = result.rtt_ms if self.max_ms is None else max(self.max_ms, result.rtt_ms)

    @property
    def lost(self) -> int:
        return self.sent - self.received

    @property
    def loss_percent(self) -> float:
        return 100.0 * self.lost / self.sent if self.sent else 0.0

    @property
    def average_ms(self) -> float | None:
        return self.total_ms / self.timed if self.timed else None


def resolve_ipv4(host: str) -> str:
    """Slå én IPv4-adresse op. GUI-tråden må ikke vente på DNS."""
    ip = socket.gethostbyname(host.strip())
    address = ipaddress.IPv4Address(ip)
    if address.is_multicast or address.is_unspecified or ip == "255.255.255.255":
        raise ValueError("Vælg en enkelt vært, ikke multicast, 0.0.0.0 eller broadcast.")
    return str(address)


def classify_reply(request: Any, reply: Any, settings: Settings, ip: str, number: int) -> Result:
    """Godkend kun Echo Reply med samme afsender, type, kode, id og sekvens.

    Lag tilgås ved navn, som Scapy understøtter. Det gør også funktionen
    testbar med små pakkeattrapper uden netværk eller administratorrettigheder.
    """
    status, source, ttl, rtt = "Timeout", "", None, None
    message = f"Intet svar inden for {settings.timeout:g} s"
    if reply is not None:
        status, message = "Andet svar", "Svaret matcher ikke dette Echo Request."
        if "IP" in reply:
            source, ttl = str(reply["IP"].src), int(reply["IP"].ttl)
        if "IP" in reply and "ICMP" in reply:
            icmp, sent_icmp = reply["ICMP"], request["ICMP"]
            if (source == ip and icmp.type == 0 and icmp.code == 0
                    and icmp.id == sent_icmp.id and icmp.seq == sent_icmp.seq):
                status, message = "Svar", "ICMP Echo Reply"
                try:
                    measured = float(reply.time - request.sent_time) * 1000.0
                    if math.isfinite(measured) and measured >= 0:
                        rtt = measured
                except (AttributeError, TypeError, ValueError):
                    pass
                if rtt is None:
                    message += "; RTT-tidsstempel mangler eller er ugyldigt"
            elif icmp.type in (3, 11, 12):
                status = "ICMP-fejl"
                explanation = {3: "Destination Unreachable", 11: "Time Exceeded", 12: "Parameter Problem"}
                message = f"{explanation[int(icmp.type)]}: type={int(icmp.type)}, kode={int(icmp.code)}"
            else:
                message = f"Ikke et godkendt Echo Reply: type={int(icmp.type)}, kode={int(icmp.code)}"
    return Result(
        datetime.now().astimezone().isoformat(timespec="milliseconds"),
        number, int(request["ICMP"].seq), ip, source, status, rtt, ttl,
        settings.payload_bytes, message,
    )


def send_once(settings: Settings, ip: str, number: int, identifier: int) -> Result:
    """Scapy sender/modtager selv; operativsystemets pingkommando anvendes ikke."""
    try:
        from scapy.all import ICMP, IP, Raw, sr1
    except ImportError as exc:
        raise RuntimeError("Scapy mangler. Kør: python -m pip install -r requirements.txt") from exc
    # ICMP-felter er 16 bit. Skift id ved sekvensomløb i kontinuerlig drift.
    sequence = (number - 1) % 65535 + 1
    ident = (identifier + (number - 1) // 65535) & 0xFFFF
    request = IP(dst=ip, ttl=settings.ttl) / ICMP(type=8, code=0, id=ident, seq=sequence)
    if settings.payload_bytes:
        payload = (b"Scapy ping " * ((settings.payload_bytes + 10) // 11))[:settings.payload_bytes]
        request = request / Raw(load=payload)
    # chainEX fører sendefejl tilbage til worker-tråden i stedet for kun at logge dem.
    reply = sr1(request, timeout=settings.timeout, verbose=False, chainEX=True)
    return classify_reply(request, reply, settings, ip, number)


def run_ping(
    settings: Settings, stop: Event, emit: Callable[[str, Any], None],
    exchange: Callable[[Settings, str, int, int], Result] | None = None,
    resolver: Callable[[str], str] | None = None,
) -> None:
    """Worker: send kun købeskeder, aldrig widgetkald. Stop afbryder pausen.

    Et igangværende sr1-/DNS-kald afsluttes først. Der sendes derefter ikke
    flere pakker. Injicerbare funktioner gør testen helt netværksfri.
    """
    try:
        settings.validate()
        if stop.is_set():
            return
        emit("status", "Slår værtsnavn op …")
        ip = (resolver or resolve_ipv4)(settings.host)
        if stop.is_set():
            return
        emit("resolved", ip)
        identifier = secrets.randbelow(65536)
        number = 1
        while not stop.is_set() and (settings.count == 0 or number <= settings.count):
            emit("status", f"Venter på svar: nr. {number} → {ip}")
            result = (exchange or send_once)(settings, ip, number, identifier)
            emit("result", result)
            if settings.count and number >= settings.count:
                break
            number += 1
            if stop.wait(settings.pause):
                break
    except socket.gaierror:
        emit("error", "Værtsnavnet kunne ikke findes. Kontrollér adressen og DNS-forbindelsen.")
    except PermissionError:
        emit("error", "Adgang nægtet. Start som administrator på Windows eller med sudo på Linux.")
    except Exception as exc:
        # Workerens fejl skal være synlig i GUI'en, ikke kun i en skjult terminal.
        emit("error", f"{type(exc).__name__}: {exc}\n\nPå Windows: kontrollér Npcap og administratorrettigheder.")
    finally:
        emit("done", stop.is_set())


def write_csv(path: str | Path, results: Iterable[Result], host: str) -> None:
    """UTF-8 med BOM, semikolon og decimalkomma til blandt andet dansk Excel."""
    def safe(value: str) -> str:
        return "'" + value if value.lstrip().startswith(("=", "+", "-", "@")) else value

    with open(path, "w", newline="", encoding="utf-8-sig") as stream:
        writer = csv.writer(stream, delimiter=";")
        writer.writerow(("timestamp", "host", "target_ipv4", "number", "icmp_sequence", "source_ipv4",
                         "status", "rtt_ms", "reply_ttl", "request_payload_bytes", "message"))
        for item in results:
            rtt = "" if item.rtt_ms is None else f"{item.rtt_ms:.3f}".replace(".", ",")
            writer.writerow((item.timestamp, safe(host), item.target, item.number, item.sequence,
                             item.source, item.status, rtt, "" if item.ttl is None else item.ttl,
                             item.payload_bytes, safe(item.message)))
