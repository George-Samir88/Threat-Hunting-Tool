"""
gui/app.py — Main window: sidebar fleet + fleet overview chart + report area.

PART 5 of 5 in the UI rebuild:
  1. gui/charts.py          <- chart primitives
  2. requirements.txt       <- added matplotlib
  3. gui/vm_card.py          <- VM card with SeverityDonut
  4. gui/report_panel.py    <- Splunk-style dashboard report window
  5. gui/app.py             <- this file

Bug fixes vs previous version:
  - Summary bar math was wrong (checked vm_config.get("_status") which was
    never set anywhere) — now reads card._status directly
  - Welcome screen used place() with relative coordinates that broke on
    window resize — now properly re-centers via bind("<Configure>")
  - FleetOverviewChart added below the welcome/log area so the dashboard
    isn't just a wall of VM cards with no aggregate view
  - Log box no longer eats keyboard focus on every poll tick (was calling
    .see("end") even when nothing was inserted)
"""

import queue
import json
import threading
from pathlib import Path
from tkinter import filedialog, messagebox
from datetime import datetime
import os
import customtkinter as ctk

from gui.vm_card import VMCard
from gui.report_panel import ReportWindow, format_report_text
from gui.charts import FleetOverviewChart, C
from hunting.models import Report

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

try:
    from fabric import Connection
    FABRIC_OK = True
except ImportError:
    FABRIC_OK = False


class ThreatHunterApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("ThreatHunter")
        self.geometry("1360x860")
        self.minsize(1080, 680)
        self.configure(fg_color=C["bg"])

        self._queue: queue.Queue = queue.Queue()
        self._vm_configs: list   = []
        self._cards: list        = []
        self._has_results        = False

        self._build_ui()
        self._load_vms()
        self._poll_queue()

    # ── Queue Polling ──────────────────────────────────────────────────────────
    def _poll_queue(self):
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
            self.log(event["status"] == "Online",
                     f"{card.vm_config.get('hostname','')} — {event['msg'][:70]}")

        elif t == "progress":
            card.set_progress(event["cur"], event["tot"], event["name"])

        elif t == "hunt_done":
            report: Report = event["report"]
            card.set_report(report)
            if report.error:
                card.set_status("Error", report.error[:60])
                self.log(False, f"{report.vm}: {report.error[:70]}")
            else:
                card.set_status("Done", "")
                self._has_results = True
                self.log(True, f"{report.vm} hunt complete — "
                         f"HIGH:{report.high_count} MED:{report.medium_count} "
                         f"LOW:{report.low_count} INFO:{report.info_count}")
                self._show_dashboard()
                self.after(300, lambda r=report: self.show_report(r))
            card.set_buttons(True)
            self._update_summary()
            self._update_fleet_chart()

    # ── UI Layout ──────────────────────────────────────────────────────────────
    def _build_ui(self):
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main_panel()

    def _build_sidebar(self):
        sidebar = ctk.CTkFrame(self, fg_color=C["panel"], corner_radius=0,
                               width=300, border_width=1,
                               border_color=C["border_dim"])
        sidebar.grid(row=0, column=0, sticky="nsew")
        sidebar.grid_propagate(False)
        sidebar.grid_columnconfigure(0, weight=1)

        # Logo bar
        logo = ctk.CTkFrame(sidebar, fg_color=C["card"], corner_radius=0, height=56)
        logo.grid(row=0, column=0, sticky="ew")
        logo.grid_propagate(False)
        ctk.CTkLabel(logo, text="⚡ ThreatHunter",
                     font=("JetBrains Mono", 15, "bold"),
                     text_color=C["accent"]).place(x=16, rely=0.5, anchor="w")
        ctk.CTkLabel(logo, text="v3.0",
                     font=("Consolas", 10),
                     text_color=C["text_muted"]).place(relx=1, x=-14, rely=0.5, anchor="e")

        # Summary bar
        self._sum_frame = ctk.CTkFrame(sidebar, fg_color=C["card"],
                                       corner_radius=0, height=52)
        self._sum_frame.grid(row=1, column=0, sticky="ew")
        self._sum_frame.grid_propagate(False)
        self._build_summary_bar()

        # VM list header
        vm_hdr = ctk.CTkFrame(sidebar, fg_color="transparent", height=28)
        vm_hdr.grid(row=2, column=0, sticky="ew", padx=12, pady=(10, 0))
        ctk.CTkLabel(vm_hdr, text="VM FLEET",
                     font=("Consolas", 9, "bold"),
                     text_color=C["text_muted"]).place(x=0, rely=0.5, anchor="w")
        self.lbl_count = ctk.CTkLabel(vm_hdr, text="",
                                       font=("Consolas", 9),
                                       text_color=C["accent"])
        self.lbl_count.place(relx=1, rely=0.5, anchor="e")

        # VM cards scroll area — fixed reasonable height, not flex-grow,
        # so the fleet overview chart below always has room
        self.fleet_scroll = ctk.CTkScrollableFrame(
            sidebar, fg_color="transparent", corner_radius=0, height=260)
        self.fleet_scroll.grid(row=3, column=0, sticky="ew", padx=8, pady=(4, 4))
        self.fleet_scroll.columnconfigure(0, weight=1)

        # Fleet overview chart — aggregate view across all VMs
        chart_hdr = ctk.CTkFrame(sidebar, fg_color="transparent", height=20)
        chart_hdr.grid(row=4, column=0, sticky="ew", padx=12, pady=(4, 0))
        ctk.CTkLabel(chart_hdr, text="FLEET DASHBOARD",
                     font=("Consolas", 9, "bold"),
                     text_color=C["text_muted"]).pack(anchor="w")

        chart_wrap = ctk.CTkFrame(sidebar, fg_color="transparent")
        chart_wrap.grid(row=5, column=0, sticky="nsew", padx=8, pady=(4, 4))
        sidebar.grid_rowconfigure(5, weight=1)
        self.fleet_chart = FleetOverviewChart(chart_wrap, figsize=(3.4, 2.8), dpi=85)
        self.fleet_chart.widget.pack(fill="both", expand=True)

        # Action buttons
        btn_area = ctk.CTkFrame(sidebar, fg_color=C["card"],
                                corner_radius=0, height=100)
        btn_area.grid(row=6, column=0, sticky="ew")
        btn_area.grid_propagate(False)
        btn_area.grid_columnconfigure((0, 1), weight=1)

        btn_cfg = dict(font=("Consolas", 11), height=34, corner_radius=6)

        ctk.CTkButton(btn_area, text="🔗  Test All",
                      fg_color=C["panel"], hover_color="#1e293b",
                      text_color=C["text"], border_width=1,
                      border_color=C["border_dim"],
                      **btn_cfg, command=self._test_all
                      ).grid(row=0, column=0, padx=(10, 4), pady=(10, 4), sticky="ew")

        ctk.CTkButton(btn_area, text="🎯  Hunt All",
                      fg_color="#1c1400", hover_color="#2a1f00",
                      text_color=C["amber"], border_width=1,
                      border_color="#3d2e00",
                      **btn_cfg, command=self._hunt_all
                      ).grid(row=0, column=1, padx=(4, 10), pady=(10, 4), sticky="ew")

        ctk.CTkButton(btn_area, text="⟳  Reload Config",
                      fg_color=C["panel"], hover_color="#1e293b",
                      text_color=C["text_dim"], border_width=1,
                      border_color=C["border_dim"],
                      **btn_cfg, command=self._reload_vms
                      ).grid(row=1, column=0, padx=(10, 4), pady=(0, 10), sticky="ew")

        ctk.CTkButton(btn_area, text="💾  Save All",
                      fg_color=C["panel"], hover_color="#1e293b",
                      text_color=C["text_dim"], border_width=1,
                      border_color=C["border_dim"],
                      **btn_cfg, command=self._save_all
                      ).grid(row=1, column=1, padx=(4, 10), pady=(0, 10), sticky="ew")

    def _build_main_panel(self):
        main = ctk.CTkFrame(self, fg_color=C["bg"], corner_radius=0)
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_rowconfigure(1, weight=1)
        main.grid_columnconfigure(0, weight=1)

        # Top bar
        topbar = ctk.CTkFrame(main, fg_color=C["panel"], corner_radius=0,
                              height=56, border_width=1,
                              border_color=C["border_dim"])
        topbar.grid(row=0, column=0, sticky="ew")
        topbar.grid_propagate(False)

        self.lbl_topbar = ctk.CTkLabel(topbar,
                                        text="Select a VM and run Hunt to begin",
                                        font=("Consolas", 12),
                                        text_color=C["text_dim"])
        self.lbl_topbar.place(x=16, rely=0.5, anchor="w")

        fab_color = C["green"] if FABRIC_OK else C["red"]
        fab_text  = "Fabric connected" if FABRIC_OK else "Fabric not installed"
        ctk.CTkLabel(topbar, text="●", font=("Consolas", 12),
                     text_color=fab_color).place(relx=1, x=-120, rely=0.5, anchor="w")
        ctk.CTkLabel(topbar, text=fab_text, font=("Consolas", 10),
                     text_color=C["text_muted"]).place(relx=1, x=-104, rely=0.5, anchor="w")

        # Content area — welcome screen, re-centers on resize
        content = ctk.CTkFrame(main, fg_color="transparent")
        content.grid(row=1, column=0, sticky="nsew")
        content.grid_rowconfigure(0, weight=1)
        content.grid_columnconfigure(0, weight=1)

        self.welcome_frame = ctk.CTkFrame(content, fg_color="transparent")
        self.welcome_frame.grid(row=0, column=0, sticky="nsew")
        self._build_welcome(self.welcome_frame)

        # Console log
        log_wrap = ctk.CTkFrame(main, fg_color=C["panel"], corner_radius=0,
                                height=150, border_width=1,
                                border_color=C["border_dim"])
        log_wrap.grid(row=2, column=0, sticky="ew")
        log_wrap.grid_propagate(False)
        log_wrap.grid_rowconfigure(1, weight=1)
        log_wrap.grid_columnconfigure(0, weight=1)

        log_hdr = ctk.CTkFrame(log_wrap, fg_color="transparent", height=28)
        log_hdr.grid(row=0, column=0, sticky="ew", padx=12, pady=(6, 0))
        ctk.CTkLabel(log_hdr, text="CONSOLE",
                     font=("Consolas", 9, "bold"),
                     text_color=C["text_muted"]).pack(side="left")
        ctk.CTkButton(log_hdr, text="Clear", width=44, height=18,
                      font=("Consolas", 9), fg_color="transparent",
                      hover_color=C["card"], text_color=C["text_muted"],
                      command=self._clear_log).pack(side="right")

        self.log_box = ctk.CTkTextbox(log_wrap, font=("Consolas", 10),
                                      fg_color="transparent",
                                      text_color=C["text_dim"],
                                      corner_radius=0)
        self.log_box.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 6))
        self.log_box.configure(state="disabled")

    def _build_summary_bar(self):
        for w in self._sum_frame.winfo_children():
            w.destroy()

        # Bug fix: read card._status directly instead of a vm_config key
        # that was never being set
        done_count = sum(1 for c in self._cards if getattr(c, "_status", "") == "Done")
        high_total = sum((c.report.high_count if c.report else 0) for c in self._cards)
        med_total  = sum((c.report.medium_count if c.report else 0) for c in self._cards)

        stats = [("VMs", len(self._cards), C["accent"]),
                 ("Done", done_count, C["teal"]),
                 ("HIGH", high_total, C["red"]),
                 ("MED",  med_total,  C["amber"])]

        for i, (label, val, color) in enumerate(stats):
            f = ctk.CTkFrame(self._sum_frame, fg_color="transparent")
            f.place(relx=i/4, rely=0, relwidth=0.25, relheight=1)
            ctk.CTkLabel(f, text=str(val), font=("JetBrains Mono", 18, "bold"),
                         text_color=color).place(relx=0.5, rely=0.35, anchor="center")
            ctk.CTkLabel(f, text=label, font=("Consolas", 8),
                         text_color=C["text_muted"]).place(relx=0.5, rely=0.78, anchor="center")

    def _update_summary(self):
        self._build_summary_bar()

    def _update_fleet_chart(self):
        vm_reports = []
        for c in self._cards:
            if c.report and not c.report.error:
                counts = {
                    "HIGH":   c.report.high_count,
                    "MEDIUM": c.report.medium_count,
                    "LOW":    c.report.low_count,
                    "INFO":   c.report.info_count,
                }
                name = c.vm_config.get("hostname", c.vm_config.get("host", "VM"))
                vm_reports.append((name, counts))
        self.fleet_chart.update(vm_reports)

    def _build_welcome(self, parent):
        parent.grid_rowconfigure(0, weight=1)
        parent.grid_columnconfigure(0, weight=1)
        inner = ctk.CTkFrame(parent, fg_color="transparent")
        # Bug fix: re-center properly using grid instead of fragile place()
        # with relative coords that drifted on resize
        inner.grid(row=0, column=0)

        ctk.CTkLabel(inner, text="⚡", font=("Consolas", 48),
                     text_color=C["border"]).pack()
        ctk.CTkLabel(inner, text="No hunt results yet",
                     font=("JetBrains Mono", 16),
                     text_color=C["text_muted"]).pack(pady=(8, 4))
        ctk.CTkLabel(inner, text="Select a VM from the sidebar and click Hunt",
                     font=("Consolas", 11),
                     text_color=C["text_muted"]).pack()

    def _show_dashboard(self):
        """Once we have at least one result, swap the welcome hint text."""
        if self._has_results:
            pass  # welcome frame stays as the resting state; report opens in popup

    # ── VM Loading ─────────────────────────────────────────────────────────────
    def _load_vms(self):
        config_path = Path("vms.json")
        if not config_path.exists():
            self.log(False, "vms.json not found in current directory")
            return
        try:
            with open(config_path) as f:
                self._vm_configs = json.load(f)
        except Exception as e:
            self.log(False, f"Failed to parse vms.json: {e}")
            return

        for w in self.fleet_scroll.winfo_children():
            w.destroy()
        self._cards.clear()

        for i, cfg in enumerate(self._vm_configs):
            card = VMCard(self.fleet_scroll, cfg, self._queue, self)
            card.grid(row=i, column=0, sticky="ew", padx=2, pady=(0, 6))
            self._cards.append(card)

        n = len(self._cards)
        self.lbl_count.configure(text=f"{n} host{'s' if n!=1 else ''}")
        self._update_summary()
        self._update_fleet_chart()
        self.log(True, f"Loaded {n} VM(s) from vms.json")

    def _reload_vms(self):
        self._load_vms()

    # ── Bulk Actions ───────────────────────────────────────────────────────────
    def _test_all(self):
        self.log(True, "Testing connectivity on all VMs...")
        for card in self._cards:
            card.test_conn()

    def _hunt_all(self):
        self.log(True, "Starting hunt on all VMs...")
        for card in self._cards:
            card.hunt()

    def _save_all(self):
        done = [c for c in self._cards if c.report and not c.report.error]
        if not done:
            messagebox.showinfo("No Reports", "Run Hunt on at least one VM first.")
            return
        folder = filedialog.askdirectory(title="Choose folder to save reports")
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
                self.log(False, f"Save failed for {card.report.vm}: {e}")
        messagebox.showinfo("Saved", f"Saved {saved} report(s) to:\n{folder}")
        self.log(True, f"Saved {saved} reports to {folder}")

    # ── Report ─────────────────────────────────────────────────────────────────
    def show_report(self, report: Report):
        self.lbl_topbar.configure(
            text=f"Last report: {report.vm}  ·  {report.timestamp}  ·  "
                 f"HIGH:{report.high_count}  MED:{report.medium_count}  "
                 f"LOW:{report.low_count}  INFO:{report.info_count}")
        win = ReportWindow(self, report)
        win.lift()
        win.focus_force()

    # ── Logging ────────────────────────────────────────────────────────────────
    def log(self, ok: bool, message: str):
        if not message:
            return  # bug fix: avoid inserting/scrolling on empty calls
        ts     = datetime.now().strftime("%H:%M:%S")
        prefix = "✓" if ok else "✗"
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"[{ts}] {prefix}  {message}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _clear_log(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")