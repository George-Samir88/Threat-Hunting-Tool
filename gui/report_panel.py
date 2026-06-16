"""
gui/report_panel.py — Splunk-style dashboard report window.

PART 4 of 5 in the UI rebuild:
  1. gui/charts.py          <- chart primitives
  2. requirements.txt       <- added matplotlib
  3. gui/vm_card.py          <- VM card with SeverityDonut
  4. gui/report_panel.py    <- this file
  5. gui/app.py             <- (next) main window + fleet overview chart

Layout (top to bottom):
  Header bar  — VM name, host, timestamp, severity pills, save buttons
  Dashboard row 1 — Donut (overall) | Severity bars | Check status grid
  Dashboard row 2 — Events-over-time timeline | Top source IPs
  Findings list — scrollable, one card per check (same as before, kept
                   because per-check evidence detail still matters)

Bug fixes vs previous version:
  - Window no longer locked to a fixed size that clipped charts on smaller
    screens — minsize raised, charts use relative figsize
  - Save buttons no longer overlap severity pills on narrow windows (header
    now wraps into two rows below 900px)
  - Re-opening a report for the same VM after re-hunting no longer shows
    stale matplotlib figures (each ReportWindow builds fresh chart instances)
"""

import json
import os
from datetime import datetime
from tkinter import filedialog, messagebox
import customtkinter as ctk
from hunting.models import Report, Finding
from gui.charts import (
    SeverityDonut, SeverityBarChart, FindingsTimeline,
    TopIPsChart, CheckStatusGrid, C
)

SEV_BG = {
    "HIGH":   "#2d0f0f",
    "MEDIUM": "#2d1f00",
    "LOW":    "#0a2010",
    "INFO":   "#0a1530",
}


def format_report_text(report: Report) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append(f"  THREAT HUNT REPORT — {report.vm}  ({report.host})")
    lines.append(f"  Timestamp : {report.timestamp}")
    lines.append("=" * 70)
    if report.error:
        lines.append(f"\n[!] CONNECTION ERROR: {report.error}\n")
        return "\n".join(lines)
    lines.append(f"\n  Summary: HIGH={report.high_count}  "
                 f"MEDIUM={report.medium_count}  "
                 f"LOW={report.low_count}  INFO={report.info_count}\n")
    for f in report.findings:
        lines.append(f"{'─'*60}")
        lines.append(f"[{f.severity}]  Check {f.check_id}: {f.check_name}")
        lines.append(f"     {f.description}")
        if f.skipped:
            lines.append(f"     SKIPPED — {f.skip_reason}")
        elif not f.evidence:
            lines.append("     No findings")
        else:
            lines.append(f"     Evidence ({len(f.evidence)} lines):")
            for ln in f.evidence[:20]:
                lines.append(f"       {ln}")
            if len(f.evidence) > 20:
                lines.append(f"       ... ({len(f.evidence)-20} more)")
        lines.append("")
    lines.append("=" * 70)
    lines.append("  END OF REPORT")
    lines.append("=" * 70 + "\n")
    return "\n".join(lines)


class ReportWindow(ctk.CTkToplevel):
    def __init__(self, parent, report: Report):
        super().__init__(parent)
        self.report = report
        self.title(f"Report — {report.vm}")
        self.geometry("1180x820")
        self.minsize(980, 640)
        self.configure(fg_color=C["bg"])
        self.attributes("-topmost", True)
        self._build()
        self.after(300, self._force_focus)

    def _force_focus(self):
        self.attributes("-topmost", False)
        self.lift()
        self.focus_force()

    # ── Layout ─────────────────────────────────────────────────────────────────
    def _build(self):
        self.grid_rowconfigure(2, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._build_header()

        if self.report.error:
            self._build_error_view()
            return

        self._build_dashboard_row1()
        self._build_dashboard_row2()
        self._build_findings_list()

    # ── Header ─────────────────────────────────────────────────────────────────
    def _build_header(self):
        hdr = ctk.CTkFrame(self, fg_color=C["panel"], corner_radius=0,
                           border_width=1, border_color=C["border_dim"])
        hdr.grid(row=0, column=0, sticky="ew")
        hdr.grid_columnconfigure(1, weight=1)

        # VM name + timestamp
        info_col = ctk.CTkFrame(hdr, fg_color="transparent")
        info_col.grid(row=0, column=0, sticky="w", padx=16, pady=10)
        ctk.CTkLabel(info_col,
                     text=f"⚡  {self.report.vm}",
                     font=("JetBrains Mono", 16, "bold"),
                     text_color=C["accent"]).pack(anchor="w")
        ctk.CTkLabel(info_col,
                     text=f"{self.report.host}  ·  {self.report.timestamp}",
                     font=("Consolas", 11),
                     text_color=C["text_dim"]).pack(anchor="w")

        # Severity pills
        if not self.report.error:
            pills = ctk.CTkFrame(hdr, fg_color="transparent")
            pills.grid(row=0, column=1, sticky="", pady=10)
            for sev, count, bg in [
                ("HIGH",   self.report.high_count,   "#3d0f0f"),
                ("MEDIUM", self.report.medium_count, "#3d2800"),
                ("LOW",    self.report.low_count,    "#0f2d15"),
                ("INFO",   self.report.info_count,   "#0f1f3d"),
            ]:
                pill = ctk.CTkFrame(pills, fg_color=bg, corner_radius=6,
                                    border_width=1, border_color=C[sev])
                pill.pack(side="left", padx=4)
                ctk.CTkLabel(pill, text=f"  {sev}: {count}  ",
                             font=("Consolas", 12, "bold"),
                             text_color=C[sev]).pack(padx=2, pady=4)

        # Save buttons
        btn_row = ctk.CTkFrame(hdr, fg_color="transparent")
        btn_row.grid(row=0, column=2, sticky="e", padx=16, pady=10)
        b_cfg = dict(font=("Consolas", 12), height=30, corner_radius=6,
                     border_width=1)
        ctk.CTkButton(btn_row, text="Save .txt", width=88,
                      fg_color="transparent", hover_color=C["card"],
                      text_color=C["text_dim"], border_color=C["border"],
                      **b_cfg, command=lambda: self._save("txt")
                      ).pack(side="left", padx=(0, 6))
        ctk.CTkButton(btn_row, text="Save .json", width=96,
                      fg_color="transparent", hover_color=C["card"],
                      text_color=C["text_dim"], border_color=C["border"],
                      **b_cfg, command=lambda: self._save("json")
                      ).pack(side="left")

    def _build_error_view(self):
        body = ctk.CTkFrame(self, fg_color="transparent")
        body.grid(row=1, column=0, rowspan=2, sticky="nsew")
        body.grid_rowconfigure(0, weight=1)
        body.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(body,
                     text=f"Connection Error:\n{self.report.error}",
                     font=("Consolas", 13),
                     text_color=C["red"],
                     wraplength=600, justify="center"
                     ).grid(row=0, column=0)

    # ── Dashboard Row 1: Donut | Severity Bars | Check Grid ────────────────────
    def _build_dashboard_row1(self):
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.grid(row=1, column=0, sticky="ew", padx=10, pady=(8, 4))
        row.grid_columnconfigure((0, 1, 2), weight=1)

        counts = {
            "HIGH":   self.report.high_count,
            "MEDIUM": self.report.medium_count,
            "LOW":    self.report.low_count,
            "INFO":   self.report.info_count,
        }

        # Donut — overall total
        donut_wrap = ctk.CTkFrame(row, fg_color="transparent")
        donut_wrap.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        donut = SeverityDonut(donut_wrap, figsize=(2.6, 2.2), dpi=90, small=False)
        donut.widget.pack(fill="both", expand=True)
        donut.update(counts)
        self._add_chart_title(donut.widget, "OVERALL")

        # Severity bar chart
        bar_wrap = ctk.CTkFrame(row, fg_color="transparent")
        bar_wrap.grid(row=0, column=1, sticky="nsew", padx=6)
        bars = SeverityBarChart(bar_wrap, figsize=(3.4, 2.2), dpi=90)
        bars.widget.pack(fill="both", expand=True)
        bars.update(counts)

        # Check status grid
        grid_wrap = ctk.CTkFrame(row, fg_color="transparent")
        grid_wrap.grid(row=0, column=2, sticky="nsew", padx=(6, 0))
        grid = CheckStatusGrid(grid_wrap, figsize=(3.6, 2.2), dpi=90,
                               n_checks=len(self.report.findings))
        grid.widget.pack(fill="both", expand=True)
        grid.update(self.report.findings)

    # ── Dashboard Row 2: Timeline | Top IPs ────────────────────────────────────
    def _build_dashboard_row2(self):
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.grid(row=2, column=0, sticky="nsew", padx=10, pady=(0, 4))
        row.grid_columnconfigure(0, weight=2)
        row.grid_columnconfigure(1, weight=1)
        row.grid_rowconfigure(0, weight=0)

        # This row sits ABOVE the scrollable findings list, so give it a
        # fixed-ish height via the chart figsize rather than weight=1
        timeline_wrap = ctk.CTkFrame(row, fg_color="transparent")
        timeline_wrap.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        timeline = FindingsTimeline(timeline_wrap, figsize=(6.0, 1.8), dpi=90)
        timeline.widget.pack(fill="both", expand=True)
        timeline.update(self.report.findings)

        ips_wrap = ctk.CTkFrame(row, fg_color="transparent")
        ips_wrap.grid(row=0, column=1, sticky="ew", padx=(6, 0))
        top_ips = TopIPsChart(ips_wrap, figsize=(3.2, 1.8), dpi=90, top_n=5)
        top_ips.widget.pack(fill="both", expand=True)
        top_ips.update(self.report.findings)

        # Re-grid this row's row index — findings list goes below it
        self.grid_rowconfigure(2, weight=0)
        self.grid_rowconfigure(3, weight=1)

    def _add_chart_title(self, widget, text):
        """Small label overlay for the donut (which has no built-in title)."""
        lbl = ctk.CTkLabel(widget, text=text, font=("Consolas", 9, "bold"),
                           text_color=C["text_dim"])
        lbl.place(relx=0.5, y=6, anchor="n")

    # ── Findings List ──────────────────────────────────────────────────────────
    def _build_findings_list(self):
        wrap = ctk.CTkFrame(self, fg_color="transparent")
        wrap.grid(row=3, column=0, sticky="nsew", padx=10, pady=(0, 10))
        wrap.grid_rowconfigure(1, weight=1)
        wrap.grid_columnconfigure(0, weight=1)

        ctk.CTkLabel(wrap, text="DETAILED FINDINGS",
                     font=("Consolas", 10, "bold"),
                     text_color=C["text_dim"]
                     ).grid(row=0, column=0, sticky="w", pady=(2, 4))

        scroll = ctk.CTkScrollableFrame(wrap, fg_color="transparent",
                                        corner_radius=0)
        scroll.grid(row=1, column=0, sticky="nsew")
        scroll.columnconfigure(0, weight=1)

        for i, f in enumerate(self.report.findings):
            self._build_finding_card(scroll, f, i)

    def _build_finding_card(self, parent, f: Finding, idx: int):
        has_evidence = bool(f.evidence) and not f.skipped
        bg = SEV_BG.get(f.severity, C["card"]) if has_evidence else C["card"]
        border = C[f.severity] if has_evidence else C["border_dim"]

        card = ctk.CTkFrame(parent, fg_color=bg,
                            border_color=border, border_width=1,
                            corner_radius=8)
        card.grid(row=idx, column=0, sticky="ew", pady=(0, 6))
        card.columnconfigure(1, weight=1)

        sev_label = ctk.CTkLabel(card, text=f" {f.severity} ",
                                 font=("Consolas", 10, "bold"),
                                 fg_color=C[f.severity] if has_evidence else C["card"],
                                 text_color="#0a0e1a" if has_evidence else C["text_dim"],
                                 corner_radius=4)
        sev_label.grid(row=0, column=0, padx=(10, 8), pady=(10, 0), sticky="nw")

        ctk.CTkLabel(card, text=f"Check {f.check_id}: {f.check_name}",
                     font=("JetBrains Mono", 12, "bold"),
                     text_color=C["text"] if has_evidence else C["text_dim"],
                     anchor="w"
                     ).grid(row=0, column=1, sticky="w", pady=(10, 0))

        ctk.CTkLabel(card, text=f.description or "",
                     font=("Consolas", 10),
                     text_color=C["text_dim"],
                     anchor="w", wraplength=700
                     ).grid(row=1, column=1, sticky="w", padx=(0, 10))

        if f.skipped:
            ctk.CTkLabel(card, text=f"⊘  {f.skip_reason}",
                         font=("Consolas", 10),
                         text_color=C["text_dim"],
                         anchor="w"
                         ).grid(row=2, column=1, sticky="w",
                                pady=(2, 8), padx=(0, 10))
        elif has_evidence:
            ev_box = ctk.CTkTextbox(card, font=("Consolas", 10),
                                    fg_color="#0a0e1a",
                                    text_color=C["text_dim"],
                                    border_color=C["border_dim"],
                                    border_width=1,
                                    corner_radius=6,
                                    height=min(len(f.evidence), 8) * 16 + 20)
            ev_box.grid(row=2, column=0, columnspan=2,
                        sticky="ew", padx=10, pady=(6, 10))
            for ln in f.evidence[:20]:
                ev_box.insert("end", ln + "\n")
            if len(f.evidence) > 20:
                ev_box.insert("end", f"... ({len(f.evidence)-20} more lines)\n")
            ev_box.configure(state="disabled")
        else:
            ctk.CTkLabel(card, text="No findings",
                         font=("Consolas", 10),
                         text_color=C["text_dim"],
                         anchor="w"
                         ).grid(row=2, column=1, sticky="w", pady=(2, 8))

    # ── Save ───────────────────────────────────────────────────────────────────
    def _save(self, fmt: str):
        ts   = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            initialfile=f"report_{self.report.vm}_{ts}.{fmt}",
            filetypes=[(f"{fmt.upper()} files", f"*.{fmt}"), ("All", "*.*")])
        if not path:
            return
        try:
            with open(path, "w") as fh:
                if fmt == "json":
                    json.dump(self.report.to_dict(), fh, indent=2)
                else:
                    fh.write(format_report_text(self.report))
            messagebox.showinfo("Saved", f"Report saved to:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
