"""
gui/app.py — Splunk-like Professional Threat Hunting Dashboard.

v5.0 FIXES:
  - Sidebar wider (340px) to accommodate taller VM cards
  - Cards now use pack() layout - buttons always visible
  - Better spacing between cards
  - Responsive card width (fills sidebar)
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
    SIDEBAR_WIDTH = 340
    DETAILS_WIDTH = 320

    def __init__(self):
        super().__init__()
        self.title("ThreatHunter — Security Operations Center")
        self.geometry("1600x900")
        self.minsize(1400, 800)
        self.configure(fg_color=C["bg"])

        self._queue: queue.Queue = queue.Queue()
        self._vm_configs: list = []
        self._cards: list = []
        self._has_results = False
        self._last_reports: list = []

        self._build_ui()
        self._load_vms()
        self._poll_queue()

    def _poll_queue(self):
        try:
            while True:
                event = self._queue.get_nowait()
                self._handle_event(event)
        except queue.Empty:
            pass
        self.after(100, self._poll_queue)

    def _handle_event(self, event: dict):
        t = event["type"]
        card = event.get("card")

        if t == "test_done":
            card.set_status(event["status"], event["msg"])
            card.set_buttons(True)
            self.log(event["status"] == "Online",
                     f"{card.vm_config.get('hostname','')} — {event['msg'][:70]}")
            self._update_details_panel()

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
                self._last_reports.append(report)
                self._last_reports = self._last_reports[-20:]
                self.log(True, f"{report.vm} complete — H:{report.high_count} M:{report.medium_count} L:{report.low_count} I:{report.info_count}")
                self._show_dashboard()
                self.after(300, lambda r=report: self.show_report(r))
            card.set_buttons(True)
            self._update_summary()
            self._update_fleet_chart()
            self._update_details_panel()
            self._update_findings_table()

    def _build_ui(self):
        self.grid_columnconfigure(0, weight=0, minsize=self.SIDEBAR_WIDTH)
        self.grid_columnconfigure(1, weight=1)
        self.grid_columnconfigure(2, weight=0, minsize=self.DETAILS_WIDTH)
        self.grid_rowconfigure(0, weight=1)

        self._build_sidebar()
        self._build_main_content()
        self._build_details_panel()
        self._build_console()

    def _build_sidebar(self):
        sidebar = ctk.CTkFrame(self, fg_color=C["panel"], corner_radius=0,
                               width=self.SIDEBAR_WIDTH, border_width=0)
        sidebar.grid(row=0, column=0, sticky="nsew", rowspan=2)
        sidebar.grid_propagate(False)
        sidebar.grid_columnconfigure(0, weight=1)
        sidebar.grid_rowconfigure(3, weight=1)

        # Logo
        logo = ctk.CTkFrame(sidebar, fg_color=C["card"], corner_radius=0, height=48)
        logo.grid(row=0, column=0, sticky="ew")
        logo.grid_propagate(False)
        ctk.CTkLabel(logo, text="⚡ ThreatHunter",
                     font=("JetBrains Mono", 15, "bold"),
                     text_color=C["accent"]).place(x=14, rely=0.5, anchor="w")
        ctk.CTkLabel(logo, text="v3.0",
                     font=("Consolas", 10),
                     text_color=C["text_dim"]).place(relx=1, x=-12, rely=0.5, anchor="e")

        # Quick Stats
        stats = ctk.CTkFrame(sidebar, fg_color=C["card"], corner_radius=0, height=56)
        stats.grid(row=1, column=0, sticky="ew", pady=(1, 0))
        stats.grid_propagate(False)
        self._stats_labels = {}
        self._build_stats_bar(stats)

        # VM List Header
        hdr = ctk.CTkFrame(sidebar, fg_color="transparent", height=28)
        hdr.grid(row=2, column=0, sticky="ew", padx=10, pady=(10, 4))
        ctk.CTkLabel(hdr, text="TARGET SYSTEMS",
                     font=("Consolas", 10, "bold"),
                     text_color=C["text_dim"]).pack(side="left")
        self.lbl_vm_count = ctk.CTkLabel(hdr, text="",
                                          font=("Consolas", 10),
                                          text_color=C["accent"])
        self.lbl_vm_count.pack(side="right")

        # VM Cards Scroll Area - use pack for cards inside
        self.fleet_scroll = ctk.CTkScrollableFrame(
            sidebar, fg_color="transparent", corner_radius=0)
        self.fleet_scroll.grid(row=3, column=0, sticky="nsew", padx=6, pady=(0, 6))
        self.fleet_scroll.columnconfigure(0, weight=1)

        # Action Buttons
        btn_area = ctk.CTkFrame(sidebar, fg_color=C["card"],
                                corner_radius=0, height=110)
        btn_area.grid(row=4, column=0, sticky="ew")
        btn_area.grid_propagate(False)
        btn_area.grid_columnconfigure((0, 1), weight=1)

        btn_cfg = dict(font=("Consolas", 11), height=32, corner_radius=5)

        ctk.CTkButton(btn_area, text="🔗 Test All",
                      fg_color=C["panel"], hover_color="#1e293b",
                      text_color=C["text"], border_width=1,
                      border_color=C["border_dim"],
                      **btn_cfg, command=self._test_all
                      ).grid(row=0, column=0, padx=(8, 4), pady=(10, 4), sticky="ew")

        ctk.CTkButton(btn_area, text="🎯 Hunt All",
                      fg_color="#1c1400", hover_color="#2a1f00",
                      text_color=C["amber"], border_width=1,
                      border_color="#3d2e00",
                      **btn_cfg, command=self._hunt_all
                      ).grid(row=0, column=1, padx=(4, 8), pady=(10, 4), sticky="ew")

        ctk.CTkButton(btn_area, text="⟳ Reload",
                      fg_color=C["panel"], hover_color="#1e293b",
                      text_color=C["text_dim"], border_width=1,
                      border_color=C["border_dim"],
                      **btn_cfg, command=self._reload_vms
                      ).grid(row=1, column=0, padx=(8, 4), pady=(0, 10), sticky="ew")

        ctk.CTkButton(btn_area, text="💾 Save",
                      fg_color=C["panel"], hover_color="#1e293b",
                      text_color=C["text_dim"], border_width=1,
                      border_color=C["border_dim"],
                      **btn_cfg, command=self._save_all
                      ).grid(row=1, column=1, padx=(4, 8), pady=(0, 10), sticky="ew")

    def _build_stats_bar(self, parent):
        stats = [("VMs", "0", C["accent"]),
                 ("Done", "0", C["teal"]),
                 ("HIGH", "0", C["red"]),
                 ("MED", "0", C["amber"])]

        for i, (label, val, color) in enumerate(stats):
            f = ctk.CTkFrame(parent, fg_color="transparent")
            f.place(relx=i/4, rely=0, relwidth=0.25, relheight=1)
            lbl_val = ctk.CTkLabel(f, text=val, font=("JetBrains Mono", 18, "bold"),
                                 text_color=color)
            lbl_val.place(relx=0.5, rely=0.3, anchor="center")
            lbl_name = ctk.CTkLabel(f, text=label, font=("Consolas", 9),
                                    text_color=C["text_dim"])
            lbl_name.place(relx=0.5, rely=0.72, anchor="center")
            self._stats_labels[label] = lbl_val

    def _build_main_content(self):
        main = ctk.CTkFrame(self, fg_color=C["bg"], corner_radius=0)
        main.grid(row=0, column=1, sticky="nsew")
        main.grid_rowconfigure(2, weight=1)
        main.grid_columnconfigure(0, weight=1)

        # Top bar
        topbar = ctk.CTkFrame(main, fg_color=C["panel"], corner_radius=0,
                              height=48, border_width=0)
        topbar.grid(row=0, column=0, sticky="ew")
        topbar.grid_propagate(False)

        self.lbl_topbar = ctk.CTkLabel(topbar,
                                        text="Security Operations Center — Ready",
                                        font=("Consolas", 12),
                                        text_color=C["text_dim"])
        self.lbl_topbar.place(x=14, rely=0.5, anchor="w")

        fab_color = C["green"] if FABRIC_OK else C["red"]
        fab_text = "● Fabric Ready" if FABRIC_OK else "● Fabric Missing"
        ctk.CTkLabel(topbar, text=fab_text, font=("Consolas", 10),
                     text_color=fab_color).place(relx=1, x=-14, rely=0.5, anchor="e")

        # KPI Row
        kpi_frame = ctk.CTkFrame(main, fg_color="transparent")
        kpi_frame.grid(row=1, column=0, sticky="ew", padx=12, pady=(10, 6))
        kpi_frame.grid_columnconfigure((0,1,2,3,4,5), weight=1)

        self.kpi_cards = []
        kpi_data = [
            ("TOTAL VMs", "0", C["accent"], "#0a1530"),
            ("ONLINE", "0", C["green"], "#0f2d15"),
            ("HIGH", "0", C["red"], "#2d0f0f"),
            ("MEDIUM", "0", C["amber"], "#2d1f00"),
            ("LOW", "0", C["green"], "#0f2d15"),
            ("INFO", "0", C["accent"], "#0a1530"),
        ]
        for i, (title, val, color, bg) in enumerate(kpi_data):
            card = self._build_kpi_card(kpi_frame, title, val, color, bg)
            card.grid(row=0, column=i, padx=4, sticky="nsew")
            self.kpi_cards.append((title, card))

        # Findings Table
        table_frame = ctk.CTkFrame(main, fg_color=C["panel"], corner_radius=8,
                                    border_width=1, border_color=C["border_dim"])
        table_frame.grid(row=2, column=0, sticky="nsew", padx=12, pady=(6, 12))
        table_frame.grid_rowconfigure(1, weight=1)
        table_frame.grid_columnconfigure(0, weight=1)

        tbl_hdr = ctk.CTkFrame(table_frame, fg_color="transparent", height=32)
        tbl_hdr.grid(row=0, column=0, sticky="ew", padx=10, pady=(6, 0))
        ctk.CTkLabel(tbl_hdr, text="FINDINGS OVERVIEW",
                     font=("Consolas", 11, "bold"),
                     text_color=C["text_dim"]).pack(side="left")
        self.lbl_findings_count = ctk.CTkLabel(tbl_hdr, text="",
                                                font=("Consolas", 10),
                                                text_color=C["accent"])
        self.lbl_findings_count.pack(side="right")

        self.findings_scroll = ctk.CTkScrollableFrame(
            table_frame, fg_color="transparent", corner_radius=0)
        self.findings_scroll.grid(row=1, column=0, sticky="nsew", padx=6, pady=(0, 6))
        self.findings_scroll.columnconfigure(0, weight=1)

        self._build_findings_table_empty()

    def _build_kpi_card(self, parent, title, value, color, bg_color):
        card = ctk.CTkFrame(parent, fg_color=bg_color, corner_radius=6,
                            border_width=1, border_color=color)
        card.grid_propagate(False)
        card.configure(height=60)

        ctk.CTkLabel(card, text=value, font=("JetBrains Mono", 22, "bold"),
                     text_color=color).place(relx=0.5, y=8, anchor="n")
        ctk.CTkLabel(card, text=title, font=("Consolas", 9, "bold"),
                     text_color=C["text_dim"]).place(relx=0.5, y=38, anchor="n")
        return card

    def _build_details_panel(self):
        panel = ctk.CTkFrame(self, fg_color=C["panel"], corner_radius=0,
                             width=self.DETAILS_WIDTH, border_width=0)
        panel.grid(row=0, column=2, sticky="nsew")
        panel.grid_propagate(False)
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(1, weight=1)

        chart_hdr = ctk.CTkFrame(panel, fg_color="transparent", height=28)
        chart_hdr.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 4))
        ctk.CTkLabel(chart_hdr, text="FLEET OVERVIEW",
                     font=("Consolas", 10, "bold"),
                     text_color=C["text_dim"]).pack(anchor="w")

        chart_wrap = ctk.CTkFrame(panel, fg_color="transparent")
        chart_wrap.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 6))
        self.fleet_chart = FleetOverviewChart(chart_wrap, figsize=(3.8, 3.0), dpi=90)
        self.fleet_chart.widget.pack(fill="both", expand=True)

        timeline_hdr = ctk.CTkFrame(panel, fg_color="transparent", height=28)
        timeline_hdr.grid(row=2, column=0, sticky="ew", padx=10, pady=(6, 4))
        ctk.CTkLabel(timeline_hdr, text="EVENT TIMELINE",
                     font=("Consolas", 10, "bold"),
                     text_color=C["text_dim"]).pack(anchor="w")

        self.timeline_scroll = ctk.CTkScrollableFrame(
            panel, fg_color="transparent", corner_radius=0)
        self.timeline_scroll.grid(row=3, column=0, sticky="nsew", padx=8, pady=(0, 10))
        self.timeline_scroll.columnconfigure(0, weight=1)

        self._build_timeline_empty()

    def _build_timeline_empty(self):
        for w in self.timeline_scroll.winfo_children():
            w.destroy()
        ctk.CTkLabel(self.timeline_scroll, text="No events yet",
                     font=("Consolas", 11), text_color=C["text_dim"]).pack(pady=20)

    def _build_findings_table_empty(self):
        for w in self.findings_scroll.winfo_children():
            w.destroy()

        empty = ctk.CTkFrame(self.findings_scroll, fg_color="transparent")
        empty.pack(pady=40)
        ctk.CTkLabel(empty, text="🛡️", font=("Consolas", 48),
                     text_color=C["border_dim"]).pack()
        ctk.CTkLabel(empty, text="No hunt results yet",
                     font=("JetBrains Mono", 14, "bold"),
                     text_color=C["text_dim"]).pack(pady=(8, 4))
        ctk.CTkLabel(empty, text="Select a VM and click Hunt to begin threat hunting",
                     font=("Consolas", 11), text_color=C["text_dim"]).pack()

    def _build_console(self):
        console = ctk.CTkFrame(self, fg_color=C["panel"], corner_radius=0,
                               height=120, border_width=0)
        console.grid(row=1, column=1, columnspan=2, sticky="ew")
        console.grid_propagate(False)
        console.grid_rowconfigure(1, weight=1)
        console.grid_columnconfigure(0, weight=1)

        hdr = ctk.CTkFrame(console, fg_color="transparent", height=24)
        hdr.grid(row=0, column=0, sticky="ew", padx=10, pady=(4, 0))
        ctk.CTkLabel(hdr, text="CONSOLE",
                     font=("Consolas", 9, "bold"),
                     text_color=C["text_dim"]).pack(side="left")
        ctk.CTkButton(hdr, text="Clear", width=44, height=18,
                      font=("Consolas", 9), fg_color="transparent",
                      hover_color=C["card"], text_color=C["text_dim"],
                      command=self._clear_log).pack(side="right")

        self.log_box = ctk.CTkTextbox(console, font=("Consolas", 10),
                                      fg_color="transparent",
                                      text_color=C["text_dim"],
                                      corner_radius=0, height=80)
        self.log_box.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 4))
        self.log_box.configure(state="disabled")

    # ── Update Methods ─────────────────────────────────────────────────────────
    def _update_summary(self):
        done_count = sum(1 for c in self._cards if getattr(c, "_status", "") == "Done")
        online_count = sum(1 for c in self._cards if getattr(c, "_status", "") == "Online")
        high_total = sum((c.report.high_count if c.report else 0) for c in self._cards)
        med_total = sum((c.report.medium_count if c.report else 0) for c in self._cards)
        low_total = sum((c.report.low_count if c.report else 0) for c in self._cards)
        info_total = sum((c.report.info_count if c.report else 0) for c in self._cards)

        self._stats_labels["VMs"].configure(text=str(len(self._cards)))
        self._stats_labels["Done"].configure(text=str(done_count))
        self._stats_labels["HIGH"].configure(text=str(high_total))
        self._stats_labels["MED"].configure(text=str(med_total))

        kpi_values = {
            "TOTAL VMs": str(len(self._cards)),
            "ONLINE": str(online_count),
            "HIGH": str(high_total),
            "MEDIUM": str(med_total),
            "LOW": str(low_total),
            "INFO": str(info_total),
        }
        for title, card in self.kpi_cards:
            if title in kpi_values:
                for child in card.winfo_children():
                    if isinstance(child, ctk.CTkLabel) and child.cget("font")[1] == 22:
                        child.configure(text=kpi_values[title])

    def _update_fleet_chart(self):
        vm_reports = []
        for c in self._cards:
            if c.report and not c.report.error:
                counts = {
                    "HIGH": c.report.high_count,
                    "MEDIUM": c.report.medium_count,
                    "LOW": c.report.low_count,
                    "INFO": c.report.info_count,
                }
                name = c.vm_config.get("hostname", c.vm_config.get("host", "VM"))
                vm_reports.append((name, counts))
        self.fleet_chart.update(vm_reports)

    def _update_details_panel(self):
        if not self._last_reports:
            return

        for w in self.timeline_scroll.winfo_children():
            w.destroy()

        for report in reversed(self._last_reports[-10:]):
            self._build_timeline_event(self.timeline_scroll, report)

    def _build_timeline_event(self, parent, report: Report):
        if report.error:
            bg = "#2d0f0f"
            border = C["red"]
            time_text = f"✕ {report.vm}"
        else:
            total = report.high_count + report.medium_count + report.low_count + report.info_count
            if report.high_count > 0:
                bg = "#2d0f0f"
                border = C["red"]
            elif report.medium_count > 0:
                bg = "#2d1f00"
                border = C["amber"]
            elif total > 0:
                bg = "#0f2d15"
                border = C["green"]
            else:
                bg = C["card"]
                border = C["border_dim"]
            time_text = f"✓ {report.vm}"

        event = ctk.CTkFrame(parent, fg_color=bg, corner_radius=4,
                             border_width=1, border_color=border)
        event.pack(fill="x", pady=2, padx=2)

        top = ctk.CTkFrame(event, fg_color="transparent")
        top.pack(fill="x", padx=8, pady=(4, 0))

        ctk.CTkLabel(top, text=time_text,
                     font=("Consolas", 10, "bold"),
                     text_color=border).pack(side="left")

        ctk.CTkLabel(top, text=report.timestamp,
                     font=("Consolas", 9),
                     text_color=C["text_dim"]).pack(side="right")

        if not report.error:
            counts = ctk.CTkFrame(event, fg_color="transparent")
            counts.pack(fill="x", padx=8, pady=(0, 4))

            for sev, count, color in [
                ("H", report.high_count, C["red"]),
                ("M", report.medium_count, C["amber"]),
                ("L", report.low_count, C["green"]),
                ("I", report.info_count, C["accent"]),
            ]:
                if count > 0:
                    ctk.CTkLabel(counts, text=f"{sev}:{count}",
                                 font=("Consolas", 9, "bold"),
                                 text_color=color).pack(side="left", padx=(0, 8))

    def _update_findings_table(self):
        for w in self.findings_scroll.winfo_children():
            w.destroy()

        all_findings = []
        for c in self._cards:
            if c.report and not c.report.error:
                for f in c.report.findings:
                    if f.evidence and not f.skipped:
                        all_findings.append((c.vm_config.get("hostname", "VM"), f))

        if not all_findings:
            self._build_findings_table_empty()
            self.lbl_findings_count.configure(text="")
            return

        self.lbl_findings_count.configure(text=f"{len(all_findings)} findings")

        header = ctk.CTkFrame(self.findings_scroll, fg_color=C["card"], corner_radius=0, height=28)
        header.pack(fill="x", pady=(0, 2))
        header.pack_propagate(False)

        headers = [("VM", 120), ("Check", 200), ("Severity", 80), ("Details", 400)]
        x = 10
        for text, width in headers:
            lbl = ctk.CTkLabel(header, text=text, font=("Consolas", 9, "bold"),
                               text_color=C["text_dim"], width=width, anchor="w")
            lbl.place(x=x, rely=0.5, anchor="w")
            x += width + 10

        for vm, finding in all_findings[:50]:
            self._build_finding_row(self.findings_scroll, vm, finding)

    def _build_finding_row(self, parent, vm: str, finding):
        bg = {"HIGH": "#2d0f0f", "MEDIUM": "#2d1f00", 
              "LOW": "#0f2d15", "INFO": "#0a1530"}.get(finding.severity, C["card"])

        row = ctk.CTkFrame(parent, fg_color=bg, corner_radius=4,
                           border_width=1, border_color=C["border_dim"])
        row.pack(fill="x", pady=1, padx=2)
        row.configure(height=32)
        row.pack_propagate(False)

        ctk.CTkLabel(row, text=vm[:14], font=("Consolas", 9),
                     text_color=C["text"], width=120, anchor="w").place(x=10, rely=0.5, anchor="w")

        ctk.CTkLabel(row, text=finding.check_name[:25], font=("Consolas", 9),
                     text_color=C["text_dim"], width=200, anchor="w").place(x=130, rely=0.5, anchor="w")

        sev_color = C.get(finding.severity, C["text_dim"])
        ctk.CTkLabel(row, text=finding.severity, font=("Consolas", 9, "bold"),
                     text_color=sev_color, width=80, anchor="w").place(x=340, rely=0.5, anchor="w")

        desc = finding.description[:60] if finding.description else ""
        ctk.CTkLabel(row, text=desc, font=("Consolas", 9),
                     text_color=C["text_dim"], width=400, anchor="w").place(x=430, rely=0.5, anchor="w")

    def _show_dashboard(self):
        if self._has_results:
            self._update_findings_table()

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
            card.pack(fill="x", padx=4, pady=(0, 6))  # Use pack for responsive width
            self._cards.append(card)

        n = len(self._cards)
        self.lbl_vm_count.configure(text=f"{n} hosts")
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
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
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
            return
        ts = datetime.now().strftime("%H:%M:%S")
        prefix = "✓" if ok else "✕"
        self.log_box.configure(state="normal")
        self.log_box.insert("end", f"[{ts}] {prefix}  {message}\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def _clear_log(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")