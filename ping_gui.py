#!/usr/bin/env python3
"""Grafisk IPv4-ping med Tkinter og Scapy. Start: python ping_gui.py

GUI'en udvider ping_scapy.py uden at ændre terminalversionen.
Copyright (c) 2026 Ib Helmer Nielsen.
"""
from __future__ import annotations

import queue
import sys
import threading
import tkinter as tk
import webbrowser
from collections import deque
from datetime import datetime
from tkinter import filedialog, messagebox, ttk

from ping_engine import MAX_ROWS, REPOSITORY, VERSION, Result, Settings, Statistics, run_ping, write_csv


def milliseconds(value: float | None) -> str:
    return "—" if value is None else f"{value:.2f} ms"


class PingApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(f"Scapy Ping — v{VERSION}")
        self.geometry("1100x840")
        self.minsize(940, 780)
        self.configure(background="#eef2f6")
        self.messages: queue.Queue = queue.Queue()
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.running = False
        self.closed = False
        self.failed = False
        self.results: deque[Result] = deque(maxlen=MAX_ROWS)
        self.table_ids: deque[str] = deque()
        self.stats = Statistics()
        self.last_host = ""
        self.host = tk.StringVar(value="127.0.0.1")
        self.fields = {name: tk.StringVar(value=value) for name, value in (
            ("count", "4"), ("timeout", "2"), ("pause", "1"), ("ttl", "64"), ("payload_bytes", "32"))}
        self.status = tk.StringVar(value="Klar. Angiv en vært, og tryk Start.")
        self.resolved = tk.StringVar(value="Ingen aktiv måling")
        self.retention = tk.StringVar()
        self.autoscroll = tk.BooleanVar(value=True)
        self.metric_vars = {name: tk.StringVar(value="—") for name in (
            "Sendt", "Modtaget", "Tabt", "Pakketab", "Min. RTT", "Gns. RTT", "Maks. RTT")}
        self._build()
        self._refresh()
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.bind("<Return>", lambda _event: self.start() if not self.running else None)
        self.bind("<Escape>", lambda _event: self.stop())
        self.poll_id = self.after(100, self._poll)

    def _build(self) -> None:
        style = ttk.Style(self)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("TFrame", background="#eef2f6")
        style.configure("TLabel", background="#eef2f6", font=("Segoe UI", 10))
        style.configure("TButton", padding=(12, 5), font=("Segoe UI", 10))
        style.configure("TLabelframe", background="#eef2f6")
        style.configure("TLabelframe.Label", background="#eef2f6", font=("Segoe UI", 10, "bold"))
        style.configure("TCheckbutton", background="#eef2f6")
        style.configure("Treeview", rowheight=28, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        style.configure("Metric.TLabel", font=("Segoe UI", 15, "bold"), foreground="#173b58")
        style.configure("Muted.TLabel", foreground="#536575", font=("Segoe UI", 9))
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

        banner = tk.Frame(self, background="#142d45", padx=20, pady=8)
        banner.grid(row=0, column=0, sticky="ew")
        banner.columnconfigure(0, weight=1)
        tk.Label(banner, text="SCAPY PING", background="#142d45", foreground="white",
                 font=("Segoe UI", 20, "bold")).grid(row=0, column=0, sticky="w")
        tk.Label(banner, text="IPv4 · ICMP Echo Request / Reply · Netværksdiagnostik",
                 background="#142d45", foreground="#c9dbe7", font=("Segoe UI", 10)).grid(row=1, column=0, sticky="w")
        ttk.Button(banner, text="Om", command=self.about).grid(row=0, column=1, rowspan=2, padx=(14, 0))

        body = ttk.Frame(self, padding=14)
        body.grid(row=1, column=0, sticky="nsew")
        body.columnconfigure(0, weight=1)
        body.rowconfigure(4, weight=1, minsize=100)
        settings = ttk.LabelFrame(body, text="Mål og indstillinger", padding=8)
        settings.grid(row=0, column=0, sticky="ew")
        for column in range(5):
            settings.columnconfigure(column, weight=1)
        ttk.Label(settings, text="IPv4-adresse eller værtsnavn").grid(row=0, column=0, columnspan=5, sticky="w")
        self.host_entry = ttk.Entry(settings, textvariable=self.host, font=("Segoe UI", 12))
        self.host_entry.grid(row=1, column=0, columnspan=5, sticky="ew", pady=(2, 6))
        self.inputs: list[ttk.Entry] = [self.host_entry]
        descriptions = (
            ("count", "Antal (0 = fortsæt)"), ("timeout", "Timeout (s)"),
            ("pause", "Pause efter forsøg (s)"), ("ttl", "Udgående TTL"), ("payload_bytes", "Data (byte)"),
        )
        for column, (name, label) in enumerate(descriptions):
            ttk.Label(settings, text=label).grid(row=2, column=column, sticky="w", padx=(0, 10))
            entry = ttk.Entry(settings, textvariable=self.fields[name], width=12)
            entry.grid(row=3, column=column, sticky="ew", padx=(0, 10), pady=(2, 0))
            self.inputs.append(entry)
        ttk.Label(settings, textvariable=self.resolved, style="Muted.TLabel").grid(
            row=4, column=0, columnspan=5, sticky="w", pady=(4, 0))

        actions = ttk.Frame(body)
        actions.grid(row=1, column=0, sticky="ew", pady=(6, 6))
        self.start_button = ttk.Button(actions, text="Start", command=self.start)
        self.start_button.pack(side="left")
        self.stop_button = ttk.Button(actions, text="Stop", command=self.stop, state="disabled")
        self.stop_button.pack(side="left", padx=6)
        self.clear_button = ttk.Button(actions, text="Ryd resultater", command=self.clear)
        self.clear_button.pack(side="left")
        self.export_button = ttk.Button(actions, text="Gem CSV …", command=self.export, state="disabled")
        self.export_button.pack(side="left", padx=6)
        ttk.Checkbutton(actions, text="Følg seneste svar", variable=self.autoscroll).pack(side="right")

        metrics = ttk.LabelFrame(body, text="Statistik for afsluttede ping", padding=(10, 6))
        metrics.grid(row=2, column=0, sticky="ew")
        for column, (name, var) in enumerate(self.metric_vars.items()):
            metrics.columnconfigure(column, weight=1)
            ttk.Label(metrics, text=name, style="Muted.TLabel").grid(row=0, column=column, sticky="w")
            ttk.Label(metrics, textvariable=var, style="Metric.TLabel").grid(row=1, column=column, sticky="w", padx=(0, 8))

        graph = ttk.LabelFrame(body, text="RTT i millisekunder · de seneste 120 forsøg", padding=4)
        graph.grid(row=3, column=0, sticky="ew", pady=(6, 6))
        self.canvas = tk.Canvas(graph, height=85, background="white", highlightthickness=0)
        self.canvas.pack(fill="x", expand=True)
        self.canvas.bind("<Configure>", lambda _event: self._draw_graph())

        table_frame = ttk.Frame(body)
        table_frame.grid(row=4, column=0, sticky="nsew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)
        columns = ("number", "time", "source", "status", "ttl", "rtt", "message")
        self.table = ttk.Treeview(table_frame, columns=columns, show="headings", height=8)
        for column, title, width, stretch in (
            ("number", "Nr.", 55, False), ("time", "Tid", 100, False),
            ("source", "Svar fra", 135, False), ("status", "Status", 100, False),
            ("ttl", "TTL", 50, False), ("rtt", "RTT (ms)", 85, False),
            ("message", "Detaljer", 290, True),
        ):
            self.table.heading(column, text=title)
            self.table.column(column, width=width, minwidth=width, stretch=stretch, anchor="w")
        self.table.tag_configure("Svar", foreground="#176438")
        self.table.tag_configure("Timeout", foreground="#8a5100")
        self.table.tag_configure("ICMP-fejl", foreground="#ae2831")
        self.table.tag_configure("Andet svar", foreground="#8a5100")
        self.table.grid(row=0, column=0, sticky="nsew")
        vertical = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        vertical.grid(row=0, column=1, sticky="ns")
        horizontal = ttk.Scrollbar(table_frame, orient="horizontal", command=self.table.xview)
        horizontal.grid(row=1, column=0, sticky="ew")
        self.table.configure(yscrollcommand=vertical.set, xscrollcommand=horizontal.set)
        ttk.Label(body, textvariable=self.retention, style="Muted.TLabel").grid(row=5, column=0, sticky="w", pady=(5, 0))
        ttk.Label(body, text="Start nulstiller forrige måling. Eksportér først, hvis den skal gemmes.",
                  style="Muted.TLabel").grid(row=6, column=0, sticky="w", pady=(2, 0))
        ttk.Label(body, textvariable=self.status, wraplength=1000).grid(row=7, column=0, sticky="ew", pady=(8, 0))
        ttk.Label(body, text=f"© 2026 Ib Helmer Nielsen  |  Version {VERSION}  |  Kun netværk, du har tilladelse til at teste.",
                  style="Muted.TLabel").grid(row=8, column=0, sticky="w", pady=(8, 0))
        self.host_entry.focus_set()

    def _settings(self) -> Settings:
        try:
            settings = Settings(
                host=self.host.get().strip(), count=int(self.fields["count"].get()),
                timeout=float(self.fields["timeout"].get().replace(",", ".")),
                pause=float(self.fields["pause"].get().replace(",", ".")),
                ttl=int(self.fields["ttl"].get()), payload_bytes=int(self.fields["payload_bytes"].get()),
            )
        except ValueError as exc:
            raise ValueError("Antal, TTL og data skal være heltal. Timeout og pause skal være tal.") from exc
        settings.validate()
        return settings

    def start(self) -> None:
        if self.running:
            return
        try:
            settings = self._settings()
        except ValueError as exc:
            messagebox.showerror("Kontrollér indstillinger", str(exc), parent=self)
            return
        self.clear()
        self.last_host = settings.host
        self.running, self.failed = True, False
        self.stop_event = threading.Event()
        self._set_running(True)
        self.status.set("Starter måling …")
        self.worker = threading.Thread(
            target=run_ping, args=(settings, self.stop_event, lambda kind, value: self.messages.put((kind, value))),
            daemon=True, name="scapy-ping-worker",
        )
        self.worker.start()

    def stop(self) -> None:
        if self.running:
            self.stop_event.set()
            self.stop_button.configure(state="disabled")
            self.status.set("Stop anmodet. Afventer igangværende DNS-opslag eller ping; ingen nye ping startes.")

    def _set_running(self, active: bool) -> None:
        for widget in self.inputs:
            widget.configure(state="disabled" if active else "normal")
        self.start_button.configure(state="disabled" if active else "normal")
        self.stop_button.configure(state="normal" if active else "disabled")
        self.clear_button.configure(state="disabled" if active else "normal")

    def clear(self) -> None:
        if self.running:
            return
        self.results.clear()
        self.table_ids.clear()
        self.stats = Statistics()
        children = self.table.get_children()
        if children:
            self.table.delete(*children)
        self.last_host = ""
        self.resolved.set("Ingen aktiv måling")
        self.status.set("Klar. Angiv en vært, og tryk Start.")
        self.export_button.configure(state="disabled")
        self._refresh()

    def _add_result(self, result: Result) -> None:
        self.stats.add(result)
        self.results.append(result)
        if len(self.table_ids) >= MAX_ROWS:
            self.table.delete(self.table_ids.popleft())
        time_text = datetime.fromisoformat(result.timestamp).strftime("%H:%M:%S.%f")[:-3]
        row = self.table.insert("", "end", values=(
            result.number, time_text, result.source or "—", result.status,
            result.ttl if result.ttl is not None else "—",
            "—" if result.rtt_ms is None else f"{result.rtt_ms:.2f}", result.message,
        ), tags=(result.status,))
        self.table_ids.append(row)
        if self.autoscroll.get():
            self.table.see(row)
        self.export_button.configure(state="normal")

    def _poll(self) -> None:
        if self.closed:
            return
        changed = False
        # Begræns arbejde pr. tick, så vinduet stadig kan modtage tastatur og klik.
        for _ in range(250):
            try:
                kind, value = self.messages.get_nowait()
            except queue.Empty:
                break
            if kind == "result":
                self._add_result(value)
                changed = True
            elif kind == "resolved":
                self.resolved.set(f"{self.last_host} → {value}  |  Netkort vælges automatisk af Scapys routning")
            elif kind == "status" and not self.stop_event.is_set():
                self.status.set(value)
            elif kind == "error":
                self.failed = True
                self.status.set("Målingen blev afbrudt af en fejl.")
                messagebox.showerror("Ping kunne ikke gennemføres", value, parent=self)
                if self.closed:
                    return
            elif kind == "done":
                self.running = False
                self._set_running(False)
                if not self.failed:
                    self.status.set("Målingen er stoppet." if value else "Målingen er færdig.")
        if changed:
            self._refresh()
        if not self.closed:
            self.poll_id = self.after(100, self._poll)

    def _refresh(self) -> None:
        values = (self.stats.sent, self.stats.received, self.stats.lost,
                  f"{self.stats.loss_percent:.1f} %", milliseconds(self.stats.min_ms),
                  milliseconds(self.stats.average_ms), milliseconds(self.stats.max_ms))
        for var, value in zip(self.metric_vars.values(), values):
            var.set(str(value))
        self.retention.set(
            f"Tabel og CSV: {len(self.results)} seneste resultater (maks. {MAX_ROWS}). "
            "Statistikken dækker hele den aktuelle måling."
        )
        self._draw_graph()

    def _draw_graph(self) -> None:
        canvas = self.canvas
        canvas.delete("all")
        width, height = max(100, canvas.winfo_width()), max(80, canvas.winfo_height())
        left, right, top, bottom = 65, width - 18, 15, height - 25
        points = list(self.results)[-120:]
        times = [item.rtt_ms for item in points if item.rtt_ms is not None]
        ymax = max(1.0, max(times, default=1.0) * 1.2)
        for fraction in (0, 0.5, 1):
            y = bottom - fraction * (bottom - top)
            canvas.create_line(left, y, right, y, fill="#e3e9ed")
            canvas.create_text(left - 8, y, text=f"{fraction * ymax:.1f}", anchor="e", fill="#536575")
        if not points:
            canvas.create_text(width / 2, height / 2, text="Svartider vises her, når målingen starter.", fill="#536575")
            return
        previous = None
        for index, item in enumerate(points):
            x = left + index * (right - left) / max(1, len(points) - 1)
            if item.status == "Svar" and item.rtt_ms is not None:
                y = bottom - item.rtt_ms / ymax * (bottom - top)
                if previous is not None:
                    canvas.create_line(*previous, x, y, fill="#187ca5", width=2)
                canvas.create_oval(x - 2, y - 2, x + 2, y + 2, fill="#187ca5", outline="")
                previous = (x, y)
            else:
                # Et kryds betyder intet målbart Echo Reply; det er IKKE en RTT på 0 ms.
                canvas.create_line(x - 3, bottom - 6, x + 3, bottom, fill="#b7522b", width=2)
                canvas.create_line(x - 3, bottom, x + 3, bottom - 6, fill="#b7522b", width=2)
                previous = None
        canvas.create_text(left, height - 9, text=f"Nr. {points[0].number}", anchor="w", fill="#536575")
        canvas.create_text(right, height - 9, text=f"Nr. {points[-1].number}", anchor="e", fill="#536575")
        canvas.create_text(width / 2, height - 9, text="Kryds: intet målbart Echo Reply", fill="#8a5100")

    def export(self) -> None:
        if not self.results:
            return
        path = filedialog.asksaveasfilename(
            parent=self, title="Gem ping-resultater", defaultextension=".csv",
            initialfile=f"ping_{datetime.now():%Y%m%d_%H%M%S}.csv",
            filetypes=[("CSV-filer", "*.csv"), ("Alle filer", "*.*")],
        )
        if not path:
            return
        snapshot = list(self.results)
        try:
            write_csv(path, snapshot, self.last_host)
        except (OSError, UnicodeError) as exc:
            messagebox.showerror("CSV kunne ikke gemmes", str(exc), parent=self)
            return
        messagebox.showinfo("CSV gemt", f"{len(snapshot)} resultater er gemt i:\n{path}", parent=self)

    def about(self) -> None:
        window = tk.Toplevel(self)
        window.title("Om Scapy Ping")
        window.resizable(False, False)
        window.transient(self)
        content = ttk.Frame(window, padding=22)
        content.pack(fill="both", expand=True)
        ttk.Label(content, text=f"Scapy Ping · version {VERSION}", font=("Segoe UI", 16, "bold")).pack(anchor="w")
        description = (
            "Et grafisk undervisnings- og diagnoseværktøj baseret på ping_scapy.py.\n\n"
            "Indtast en IPv4-adresse eller et værtsnavn, og tryk Start. Antal 0\n"
            "fortsætter indtil Stop. Pause er ventetiden efter hvert svar/timeout.\n"
            "Stop afventer det aktuelle ping eller DNS-opslag.\n\n"
            "Scapy bygger IP / ICMP Echo Request / data og modtager svaret.\n"
            "RTT måles med Scapys sendetidsstempel og modtagetidsstempel.\n"
            "Kun korrekte Echo Reply tæller som modtagne ping. Timeout og\n"
            "ICMP-fejl tæller som tab; en lokal sendefejl stopper målingen.\n\n"
            "Manglende svar beviser ikke, at en vært er slukket: ICMP kan filtreres.\n"
            "Netkortet vælges automatisk af Scapys routning. Kun IPv4 understøttes.\n\n"
            f"Tabel og CSV bevarer de seneste {MAX_ROWS} resultater. Statistikken\n"
            "omfatter hele målingen. Enter starter; Escape stopper.\n\n"
            "Windows kræver Npcap og passende rettigheder.\n"
            "Test kun netværk, du har tilladelse til at undersøge.\n\n"
            "Copyright © 2026 Ib Helmer Nielsen"
        )
        ttk.Label(content, text=description, justify="left").pack(anchor="w", pady=14)
        ttk.Button(content, text="Åbn repository på GitHub", command=lambda: webbrowser.open(REPOSITORY)).pack(side="left")
        ttk.Button(content, text="Luk", command=window.destroy).pack(side="right")

    def close(self) -> None:
        self.closed = True
        self.stop_event.set()
        self.after_cancel(self.poll_id)
        self.destroy()


def main() -> int:
    if sys.platform == "win32":
        try:
            import ctypes
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except (AttributeError, OSError):
            pass
    try:
        app = PingApp()
    except tk.TclError as exc:
        print(f"GUI kunne ikke startes: {exc}\nBrug et grafisk skrivebord og en Python-installation med Tkinter.", file=sys.stderr)
        return 1
    app.mainloop()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
