"""
gui/app.py — Main window, layout, and queue polling loop
All widget updates happen here on the main thread via queue.Queue.
"""
import queue
import json
from pathlib import Path
from tkinter import filedialog, messagebox
from datetime import datetime
import os
import customtkinter as ctk

from gui.vm_card import VMCard
from gui.report_panel import ReportWindow, format_report_text
from hunting.models import Report

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

COLORS = {
    "bg":          "#0d1117",
    "panel":       "#161b22",
    "card":        "#1c2128",
    "card_border": "#30363d",
    "accent":      "#388bfd",
    "accent2":     "#58a6ff",
    "success":     "#3fb950",
    "warning":     "#d29922",
    "danger":      "#f85149",
    "muted":       "#8b949e",
    "text":        "#e6edf3",
    "text_dim":    "#8b949e",
    "hunt_active": "#d2a53a",
}

try:
    from fabric import Connection
    FABRIC_OK = True
except ImportError:
    FABRIC_OK = False


class ThreatHunterApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("ThreatHunter  ·  VM Fleet Console")
        self.geometry("1100x740")
        self.minsize(900, 600)
        self.configure(fg_color=COLORS["bg"])

        self._queue: queue.Queue = queue.Queue()
        self._vm_configs: list   = []
        self._cards: list        = []

        self._build_ui()
        self._load_vms()
        self._poll_queue()   # start the 100ms polling loop

    # ── Queue Polling ──────────────────────────────────────────────────────────
    def _poll_queue(self):
        """Drain the event queue and update widgets — runs on main thread."""
        try:
            while True:
                event = self._queue.get_nowait()
                self._handle_event(event)
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _handle_event(self, event: dict):
        t    = event["type"]
        card = event.get("card")

        if t == "test_done":
            card.set_status(event["status"], event["msg"])
            card.set_buttons(True)
            self.log(f"[{'OK' if event['status']=='Online' else 'FAIL'}] "
                     f"{card.vm_config.get('hostname','')} — {event['msg'][:80]}")

        elif t == "progress":
            card.set_progress(event["cur"], event["tot"], event["name"])

        elif t == "hunt_done":
            report: Report = event["report"]
            card.set_report(report)
            if report.error:
                card.set_status("Error", report.error[:60])
                self.log(f"[ERROR] {report.vm}: {report.error[:80]}")
            else:
                summary = (f"Done — HIGH:{report.high_count}  "
                           f"MED:{report.medium_count}  "
                           f"LOW:{report.low_count}")
                card.set_status("Done", summary)
                self.log(f"[HUNT] {report.vm}: {summary}")
                self.after(200, lambda r=report: self.show_report(r))
            card.set_buttons(True)
            self.lbl_status.configure(
                text=f"  Hunt complete: {report.vm}")

    # ── UI Layout ──────────────────────────────────────────────────────────────
    def _build_ui(self):
        # Title bar
        title_bar = ctk.CTkFrame(self, fg_color=COLORS["panel"],
                                 corner_radius=0, height=52)
        title_bar.pack(fill="x", side="top")
        title_bar.pack_propagate(False)

        ctk.CTkLabel(title_bar, text="  ⚡ ThreatHunter",
                     font=("JetBrains Mono", 16, "bold"),
                     text_color=COLORS["accent2"]).pack(side="left", padx=4)
        ctk.CTkLabel(title_bar, text="VM Fleet Console",
                     font=("Consolas", 12),
                     text_color=COLORS["muted"]).pack(side="left")

        btn_cfg = dict(font=("Consolas", 11), height=32, corner_radius=6)
        for text, color, hover, cmd in [
            ("⟳  Reload",   COLORS["card"], COLORS["accent"],   self._reload_vms),
            ("💾 Save All", COLORS["card"], COLORS["success"],  self._save_all),
            ("🎯 Hunt All", "#2a1f0a",      "#d2a53a",          self._hunt_all),
            ("🔗 Test All", COLORS["card"], COLORS["accent"],   self._test_all),
        ]:
            ctk.CTkButton(title_bar, text=text, width=100,
                          fg_color=color, hover_color=hover,
                          **btn_cfg, command=cmd).pack(side="right", padx=4, pady=10)

        # Main pane
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.pack(fill="both", expand=True)
        main.columnconfigure(0, weight=1)
        main.rowconfigure(0, weight=3)
        main.rowconfigure(1, weight=1)

        # Fleet panel
        fleet = ctk.CTkFrame(main, fg_color=COLORS["panel"], corner_radius=0)
        fleet.grid(row=0, column=0, sticky="nsew")
        fleet.rowconfigure(1, weight=1)
        fleet.columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(fleet, fg_color=COLORS["card_border"],
                           corner_radius=0, height=32)
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.pack_propagate(False)
        ctk.CTkLabel(hdr, text="  VM FLEET",
                     font=("Consolas", 10, "bold"),
                     text_color=COLORS["muted"]).pack(side="left", padx=8, pady=6)
        self.lbl_count = ctk.CTkLabel(hdr, text="0 hosts",
                                       font=("Consolas", 10),
                                       text_color=COLORS["accent"])
        self.lbl_count.pack(side="left", pady=6)

        self.fleet_scroll = ctk.CTkScrollableFrame(
            fleet, fg_color=COLORS["panel"], corner_radius=0)
        self.fleet_scroll.grid(row=1, column=0, sticky="nsew")
        self.fleet_scroll.columnconfigure(0, weight=1)

        # Console log
        log_frame = ctk.CTkFrame(main, fg_color=COLORS["bg"], corner_radius=0)
        log_frame.grid(row=1, column=0, sticky="nsew")
        log_frame.rowconfigure(1, weight=1)
        log_frame.columnconfigure(0, weight=1)

        log_hdr = ctk.CTkFrame(log_frame, fg_color=COLORS["card_border"],
                               corner_radius=0, height=28)
        log_hdr.grid(row=0, column=0, sticky="ew")
        log_hdr.pack_propagate(False)
        ctk.CTkLabel(log_hdr, text="  CONSOLE LOG",
                     font=("Consolas", 10, "bold"),
                     text_color=COLORS["muted"]).pack(side="left", padx=8, pady=4)
        ctk.CTkButton(log_hdr, text="Clear", width=50, height=20,
                      font=("Consolas", 9), fg_color="transparent",
                      hover_color=COLORS["card"], text_color=COLORS["muted"],
                      command=self._clear_log).pack(side="right", padx=6, pady=4)

        self.log_box = ctk.CTkTextbox(log_frame, font=("Consolas", 10),
                                      fg_color=COLORS["bg"],
                                      text_color=COLORS["text_dim"],
                                      corner_radius=0, height=140)
        self.log_box.grid(row=1, column=0, sticky="nsew")
        self.log_box.configure(state="disabled")

        # Status bar
        status_bar = ctk.CTkFrame(self, fg_color=COLORS["card_border"],
                                  corner_radius=0, height=24)
        status_bar.pack(fill="x", side="bottom")
        status_bar.pack_propagate(False)
        self.lbl_status = ctk.CTkLabel(status_bar, text="  Ready",
                                       font=("Consolas", 9),
                                       text_color=COLORS["muted"])
        self.lbl_status.pack(side="left", padx=8)
        ctk.CTkLabel(status_bar,
                     text=("Fabric ✓  " if FABRIC_OK else "Fabric NOT installed  "),
                     font=("Consolas", 9),
                     text_color=COLORS["success"] if FABRIC_OK else COLORS["danger"]
                     ).pack(side="right", padx=8)

    # ── VM Loading ─────────────────────────────────────────────────────────────
    def _load_vms(self):
        config_path = Path("vms.json")
        if not config_path.exists():
            self.log("[ERROR] vms.json not found")
            return
        try:
            with open(config_path) as f:
                self._vm_configs = json.load(f)
        except Exception as e:
            self.log(f"[ERROR] Failed to parse vms.json: {e}")
            return

        for w in self.fleet_scroll.winfo_children():
            w.destroy()
        self._cards.clear()

        for i, cfg in enumerate(self._vm_configs):
            card = VMCard(self.fleet_scroll, cfg, self._queue, self)
            card.grid(row=i, column=0, sticky="ew", padx=10, pady=(6, 0))
            self._cards.append(card)

        n = len(self._cards)
        self.lbl_count.configure(text=f"{n} host{'s' if n!=1 else ''}")
        self.log(f"[INFO] Loaded {n} VM(s) from vms.json")

    def _reload_vms(self):
        self._load_vms()

    # ── Bulk Actions ───────────────────────────────────────────────────────────
    def _test_all(self):
        self.log("[INFO] Testing all VMs…")
        for card in self._cards:
            card.test_conn()

    def _hunt_all(self):
        self.log("[INFO] Starting hunt on all VMs…")
        for card in self._cards:
            card.hunt()

    def _save_all(self):
        done = [c for c in self._cards if c.report]
        if not done:
            messagebox.showinfo("No Reports", "Run Hunt first.")
            return
        folder = filedialog.askdirectory(title="Choose save folder")
        if not folder:
            return
        saved = 0
        for card in done:
            ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = os.path.join(folder, f"report_{card.report.vm}_{ts}.txt")
            try:
                with open(path, "w") as f:
                    f.write(format_report_text(card.report))
                saved += 1
            except Exception as e:
                self.log(f"[ERROR] Save failed for {card.report.vm}: {e}")
        messagebox.showinfo("Saved", f"Saved {saved} report(s) to:\n{folder}")

    # ── Report ─────────────────────────────────────────────────────────────────
    def show_report(self, report: Report):
        win = ReportWindow(self, report)
        win.lift()
        win.focus_force()

    # ── Logging ────────────────────────────────────────────────────────────────
    def log(self, message: str):
        ts = datetime.now().strftime("%H:%M:%S")
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"[{ts}] {message}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _clear_log(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")
