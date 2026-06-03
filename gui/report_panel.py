"""
gui/report_panel.py — Report formatting, display, and save logic
"""
import json
import os
from datetime import datetime
from tkinter import filedialog, messagebox
import customtkinter as ctk
from hunting.models import Report

COLORS = {
    "bg":          "#0d1117",
    "panel":       "#161b22",
    "card":        "#1c2128",
    "card_border": "#30363d",
    "accent":      "#388bfd",
    "accent2":     "#58a6ff",
    "success":     "#3fb950",
    "text":        "#e6edf3",
    "muted":       "#8b949e",
}
SEVERITY_COLORS = {
    "HIGH":   "#f85149",
    "MEDIUM": "#d29922",
    "LOW":    "#3fb950",
    "INFO":   "#79c0ff",
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
                 f"LOW={report.low_count}  "
                 f"INFO={report.info_count}\n")

    for f in report.findings:
        lines.append(f"{'─'*60}")
        lines.append(f"[{f.severity}]  Check {f.check_id}: {f.check_name}")
        lines.append(f"     {f.description}")

        if f.skipped:
            lines.append(f"     SKIPPED — {f.skip_reason}")
        elif not f.evidence:
            lines.append("     Result : No findings")
        else:
            lines.append(f"     Evidence ({len(f.evidence)} lines):")
            for line in f.evidence[:20]:
                lines.append(f"       {line}")
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
        self.geometry("860x640")
        self.configure(fg_color=COLORS["bg"])
        self.attributes("-topmost", True)
        self._build()
        self.after(300, self._force_focus)

    def _force_focus(self):
        self.attributes("-topmost", False)
        self.lift()
        self.focus_force()

    def _build(self):
        # Top bar
        top = ctk.CTkFrame(self, fg_color=COLORS["panel"], corner_radius=0)
        top.pack(fill="x")
        ctk.CTkLabel(top, text=f"  ⚡ HUNT REPORT  ·  {self.report.vm}",
                     font=("JetBrains Mono", 13, "bold"),
                     text_color=COLORS["accent2"]).pack(side="left", padx=12, pady=8)
        ctk.CTkButton(top, text="Save .txt", width=90, height=28,
                      font=("Consolas", 11), fg_color=COLORS["card"],
                      hover_color=COLORS["accent"],
                      command=lambda: self._save("txt")).pack(side="right", padx=6, pady=8)
        ctk.CTkButton(top, text="Save .json", width=90, height=28,
                      font=("Consolas", 11), fg_color=COLORS["card"],
                      hover_color=COLORS["success"],
                      command=lambda: self._save("json")).pack(side="right", padx=0, pady=8)

        # Severity strip
        if not self.report.error:
            strip = ctk.CTkFrame(self, fg_color=COLORS["panel"],
                                 corner_radius=0, height=36)
            strip.pack(fill="x")
            for sev, color in SEVERITY_COLORS.items():
                count = getattr(self.report, f"{sev.lower()}_count")
                ctk.CTkLabel(strip, text=f"  {sev}: {count}  ",
                             font=("Consolas", 10, "bold"),
                             text_color=color, fg_color=COLORS["card"],
                             corner_radius=4).pack(side="left", padx=6, pady=6)

        # Text area
        self.text = ctk.CTkTextbox(self, font=("Consolas", 11),
                                   fg_color=COLORS["card"],
                                   text_color=COLORS["text"],
                                   wrap="none", corner_radius=0)
        self.text.pack(fill="both", expand=True)
        content = format_report_text(self.report)
        self.text.insert("1.0", content)
        self._colorize()
        self.text.configure(state="disabled")

    def _colorize(self):
        tw = self.text._textbox
        for sev, color in SEVERITY_COLORS.items():
            tw.tag_configure(f"sev_{sev}", foreground=color)
            idx = "1.0"
            while True:
                pos = tw.search(f"[{sev}]", idx, stopindex="end")
                if not pos:
                    break
                tw.tag_add(f"sev_{sev}", pos, f"{pos}+{len(sev)+2}c")
                idx = f"{pos}+1c"

    def _save(self, fmt: str):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            initialfile=f"report_{self.report.vm}_{ts}.{fmt}",
            filetypes=[(f"{fmt.upper()} files", f"*.{fmt}"), ("All", "*.*")])
        if not path:
            return
        try:
            with open(path, "w") as f:
                if fmt == "json":
                    json.dump(self.report.to_dict(), f, indent=2)
                else:
                    f.write(format_report_text(self.report))
            messagebox.showinfo("Saved", f"Report saved:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))
