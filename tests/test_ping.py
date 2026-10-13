"""Netværksfri tests. Kør: python -m unittest discover -s tests -v

Pakkeattrapper tester logikken; disse tests er ikke en test af Npcap/drivere.
Copyright (c) 2026 Ib Helmer Nielsen.
"""
import csv
import importlib.util
import os
import socket
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from ping_engine import Result, Settings, Statistics, classify_reply, resolve_ipv4, run_ping, write_csv


class Packet(dict):
    """Minimal attrap af Scapys adgang til navngivne lag og tidsstempler."""
    pass


def request():
    packet = Packet(ICMP=SimpleNamespace(id=1234, seq=7))
    packet.sent_time = 100.0
    return packet


def reply(**changes):
    fields = dict(type=0, code=0, id=1234, seq=7)
    fields.update(changes)
    packet = Packet(IP=SimpleNamespace(src="192.0.2.1", ttl=61), ICMP=SimpleNamespace(**fields))
    packet.time = 100.012
    return packet


def result(number=1, status="Svar", rtt_ms=12.0):
    return Result("2026-10-13T12:00:00.123+02:00", number, number, "192.0.2.1", "192.0.2.1",
                  status, rtt_ms, 61, 32, "ICMP Echo Reply")


class SettingsTests(unittest.TestCase):
    def test_defaults_and_idna(self):
        for host in ("127.0.0.1", "localhost", "router.example", "router.example.", "bøger.example"):
            Settings(host).validate()

    def test_invalid_hosts(self):
        for host in ("", " ", "https://example.com", "::1", "host/path", "two hosts", "256.1.2.3", "=1+1", "-router"):
            with self.subTest(host=host), self.assertRaises(ValueError):
                Settings(host).validate()

    def test_numeric_limits(self):
        for change in (dict(count=-1), dict(count=65536), dict(count=True), dict(count=1.5),
                       dict(ttl=0), dict(ttl=256), dict(payload_bytes=-1), dict(payload_bytes=1401),
                       dict(timeout=0), dict(timeout=float("nan")), dict(timeout=float("inf")),
                       dict(pause=0), dict(pause=61), dict(pause=True)):
            with self.subTest(change=change), self.assertRaises(ValueError):
                replace(Settings("localhost"), **change).validate()

    def test_continuous_and_empty_payload(self):
        Settings("localhost", count=0, payload_bytes=0, ttl=1, pause=0.1).validate()

    def test_resolves_ipv4(self):
        with patch("ping_engine.socket.gethostbyname", return_value="192.0.2.1"):
            self.assertEqual(resolve_ipv4("example.test"), "192.0.2.1")

    def test_rejects_non_unicast(self):
        for ip in ("224.0.0.1", "255.255.255.255", "0.0.0.0"):
            with self.subTest(ip=ip), patch("ping_engine.socket.gethostbyname", return_value=ip):
                with self.assertRaises(ValueError):
                    resolve_ipv4("example.test")


class ReplyTests(unittest.TestCase):
    def classify(self, answer, sent=None):
        return classify_reply(sent if sent is not None else request(), answer, Settings("example.test"), "192.0.2.1", 7)

    def test_success_and_timestamp_rtt(self):
        item = self.classify(reply())
        self.assertEqual(item.status, "Svar")
        self.assertEqual(item.sequence, 7)
        self.assertEqual(item.ttl, 61)
        self.assertAlmostEqual(item.rtt_ms, 12.0)

    def test_timeout(self):
        item = self.classify(None)
        self.assertEqual(item.status, "Timeout")
        self.assertIsNone(item.rtt_ms)
        self.assertIsNone(item.ttl)

    def test_wrong_fields_never_count_as_reply(self):
        for change in (dict(id=1235), dict(seq=8), dict(type=8), dict(code=1)):
            with self.subTest(change=change):
                self.assertNotEqual(self.classify(reply(**change)).status, "Svar")

    def test_wrong_source(self):
        answer = reply()
        answer["IP"].src = "192.0.2.2"
        self.assertNotEqual(self.classify(answer).status, "Svar")

    def test_missing_protocol_layers(self):
        for answer in (Packet(), Packet(IP=SimpleNamespace(src="192.0.2.1", ttl=64))):
            self.assertEqual(self.classify(answer).status, "Andet svar")

    def test_icmp_errors(self):
        for icmp_type in (3, 11, 12):
            with self.subTest(icmp_type=icmp_type):
                self.assertEqual(self.classify(reply(type=icmp_type)).status, "ICMP-fejl")

    def test_missing_timestamp_keeps_reply_without_fake_rtt(self):
        sent = request()
        sent.sent_time = None
        item = self.classify(reply(), sent)
        self.assertEqual(item.status, "Svar")
        self.assertIsNone(item.rtt_ms)

    def test_negative_nan_and_infinite_rtt(self):
        for stamp in (99, float("nan"), float("inf")):
            answer = reply()
            answer.time = stamp
            self.assertIsNone(self.classify(answer).rtt_ms)


class StatisticsTests(unittest.TestCase):
    def test_empty(self):
        stats = Statistics()
        self.assertEqual(stats.loss_percent, 0)
        self.assertIsNone(stats.average_ms)

    def test_mixed_results(self):
        stats = Statistics()
        for item in (result(rtt_ms=10), result(rtt_ms=30), result(status="Timeout", rtt_ms=None),
                     result(status="ICMP-fejl", rtt_ms=None)):
            stats.add(item)
        self.assertEqual((stats.sent, stats.received, stats.lost), (4, 2, 2))
        self.assertEqual(stats.loss_percent, 50)
        self.assertEqual((stats.min_ms, stats.average_ms, stats.max_ms), (10, 20, 30))

    def test_unknown_rtt_is_not_zero(self):
        stats = Statistics()
        stats.add(result(rtt_ms=None))
        stats.add(result(rtt_ms=20))
        self.assertEqual(stats.received, 2)
        self.assertEqual(stats.average_ms, 20)


class WorkerTests(unittest.TestCase):
    def setUp(self):
        self.events = []
        self.stop = threading.Event()
        self.settings = Settings("example.test", count=2, pause=0.1)

    def emit(self, kind, value):
        self.events.append((kind, value))

    def run_worker(self, **kwargs):
        run_ping(self.settings, self.stop, self.emit,
                 resolver=kwargs.pop("resolver", lambda host: "192.0.2.1"), **kwargs)

    def test_finite_count(self):
        calls = []
        def exchange(settings, ip, number, identifier):
            calls.append(number)
            return result(number)
        self.run_worker(exchange=exchange)
        self.assertEqual(calls, [1, 2])
        self.assertEqual(self.events[-1], ("done", False))

    def test_pre_cancelled_does_not_resolve_or_send(self):
        self.stop.set()
        self.run_worker(resolver=lambda host: self.fail("DNS must not run"),
                        exchange=lambda *args: self.fail("Network must not run"))
        self.assertEqual(self.events, [("done", True)])

    def test_stop_during_resolution_prevents_send(self):
        def resolver(host):
            self.stop.set()
            return "192.0.2.1"
        self.run_worker(resolver=resolver, exchange=lambda *args: self.fail("Network must not run"))
        self.assertEqual(self.events[-1], ("done", True))

    def test_stop_after_result_no_further_ping(self):
        calls = []
        def exchange(settings, ip, number, identifier):
            calls.append(number)
            self.stop.set()
            return result(number)
        self.settings = replace(self.settings, count=0, pause=60)
        self.run_worker(exchange=exchange)
        self.assertEqual(calls, [1])
        self.assertEqual(self.events[-1], ("done", True))

    def test_dns_error(self):
        def resolver(host):
            raise socket.gaierror("test")
        self.run_worker(resolver=resolver)
        self.assertTrue(any(kind == "error" and "DNS" in value for kind, value in self.events))
        self.assertEqual(self.events[-1], ("done", False))

    def test_permission_error_does_not_count_as_sent(self):
        def exchange(*args):
            raise PermissionError("test")
        self.run_worker(exchange=exchange)
        self.assertTrue(any(kind == "error" for kind, _ in self.events))
        self.assertFalse(any(kind == "result" for kind, _ in self.events))

    def test_unexpected_error_is_reported(self):
        def exchange(*args):
            raise RuntimeError("driver unavailable")
        self.run_worker(exchange=exchange)
        self.assertTrue(any(kind == "error" and "driver unavailable" in value for kind, value in self.events))
        self.assertEqual(self.events[-1][0], "done")


class CsvTests(unittest.TestCase):
    def test_csv_format_and_missing_rtt(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "måling.csv"
            write_csv(path, [result(), result(2, "Timeout", None)], "example.test")
            self.assertTrue(path.read_bytes().startswith(b"\xef\xbb\xbf"))
            with path.open(encoding="utf-8-sig", newline="") as stream:
                rows = list(csv.DictReader(stream, delimiter=";"))
            self.assertEqual(rows[0]["rtt_ms"], "12,000")
            self.assertEqual(rows[1]["rtt_ms"], "")
            self.assertEqual(rows[0]["host"], "example.test")

    def test_formula_cells_are_escaped(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "safe.csv"
            write_csv(path, [replace(result(), message="=1+1")], "@host")
            text = path.read_text(encoding="utf-8-sig")
            self.assertIn("'=1+1", text)
            self.assertIn("'@host", text)


@unittest.skipUnless(importlib.util.find_spec("scapy"), "Scapy er ikke installeret; rigtige pakketyper testes ikke")
class ScapyConstructionTests(unittest.TestCase):
    def test_real_packet_construction_without_network(self):
        from ping_engine import send_once
        from scapy.all import IP, ICMP
        for number, size, expected_id, expected_seq in ((1, 32, 1234, 1), (65536, 0, 1235, 1)):
            def echo(packet, **kwargs):
                self.assertEqual(packet[ICMP].id, expected_id)
                self.assertEqual(packet[ICMP].seq, expected_seq)
                self.assertEqual(len(bytes(packet[ICMP].payload)), size)
                self.assertTrue(kwargs["chainEX"])
                packet.sent_time = 100.0
                response = IP(src="192.0.2.1", ttl=61) / ICMP(type=0, id=packet[ICMP].id, seq=packet[ICMP].seq)
                response.time = 100.010
                return response
            with patch("scapy.all.sr1", side_effect=echo):
                item = send_once(Settings("example.test", payload_bytes=size), "192.0.2.1", number, 1234)
            self.assertEqual(item.status, "Svar")
            self.assertAlmostEqual(item.rtt_ms, 10)


@unittest.skipUnless(os.name == "nt" or os.environ.get("DISPLAY"), "GUI kræver et grafisk display (evt. Xvfb)")
class GuiTests(unittest.TestCase):
    def setUp(self):
        from ping_gui import PingApp
        self.app = PingApp()
        self.app.withdraw()
        self.app.update()

    def tearDown(self):
        self.app.close()

    def test_initial_state_and_clear(self):
        self.assertEqual(self.app.stats.sent, 0)
        self.app._add_result(result())
        self.app._refresh()
        self.assertEqual(len(self.app.table.get_children()), 1)
        self.app.clear()
        self.assertEqual(len(self.app.table.get_children()), 0)

    def test_local_decimal_input(self):
        self.app.fields["timeout"].set("1,5")
        self.assertEqual(self.app._settings().timeout, 1.5)

    def test_retention_keeps_full_statistics(self):
        with patch("ping_gui.MAX_ROWS", 3):
            for number in range(1, 6):
                self.app._add_result(result(number))
            self.assertEqual(len(self.app.table.get_children()), 3)
            self.assertEqual(self.app.stats.sent, 5)

    def test_worker_updates_widgets_through_queue(self):
        def fake_worker(settings, stop, emit):
            emit("resolved", "192.0.2.1")
            emit("result", result())
            emit("done", False)
        with patch("ping_gui.run_ping", side_effect=fake_worker):
            self.app.start()
            deadline = time.monotonic() + 2
            while self.app.running and time.monotonic() < deadline:
                self.app.update()
                time.sleep(0.01)
        self.assertFalse(self.app.running)
        self.assertEqual(self.app.stats.received, 1)
        self.assertEqual(str(self.app.start_button["state"]), "normal")

    def test_about_opens(self):
        self.app.about()
        self.app.update()
        import tkinter as tk
        self.assertTrue(any(isinstance(child, tk.Toplevel) for child in self.app.winfo_children()))


if __name__ == "__main__":
    unittest.main()
