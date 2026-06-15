"""
gui/charts.py — Reusable matplotlib chart widgets, Splunk-dashboard style.

PART 1 of 5 in the UI rebuild:
  1. gui/charts.py          <- this file (chart primitives)
  2. hunting/models.py      <- adds timestamp/IP fields needed by charts
  3. gui/vm_card.py         <- VM card using SeverityDonut from this file
  4. gui/report_panel.py    <- dashboard report window using all charts here
  5. gui/app.py             <- main window wiring + fleet overview chart

All charts are embedded matplotlib Figures inside customtkinter frames,
styled to match the dark navy theme. Each chart class exposes:
  - __init__(parent, **kwargs)  -> builds empty/placeholder chart
  - update(data)                -> redraws with new data
  - widget                       -> the actual tk widget to grid/pack
"""

import tkinter as tk
import customtkinter as ctk
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from collections import Counter
from datetime import datetime
import re

# ─── Shared palette (mirrors gui/app.py C dict — keep in sync) ────────────────
C = {
    "bg":         "#0a0e1a",
    "panel":      "#0f1629",
    "card":       "#1a2235",
    "border":     "#1e3a5f",
    "border_dim": "#1a2744",
    "accent":     "#3b82f6",
    "teal":       "#14b8a6",
    "amber":      "#f59e0b",
    "red":        "#ef4444",
    "green":      "#22c55e",
    "purple":     "#a855f7",
    "text":       "#f1f5f9",
    "text_dim":   "#94a3b8",
    "text_muted": "#475569",
    "HIGH":       "#ef4444",
    "MEDIUM":     "#f59e0b",
    "LOW":        "#22c55e",
    "INFO":       "#3b82f6",
}

SEV_ORDER  = ["HIGH", "MEDIUM", "LOW", "INFO"]
SEV_COLORS = [C["HIGH"], C["MEDIUM"], C["LOW"], C["INFO"]]


def _style_axes(ax, fig):
    """Apply consistent dark theme styling to a matplotlib axes."""
    fig.patch.set_facecolor(C["panel"])
    ax.set_facecolor(C["panel"])
    for spine in ax.spines.values():
        spine.set_color(C["border_dim"])
    ax.tick_params(colors=C["text_muted"], labelsize=8)
    ax.xaxis.label.set_color(C["text_dim"])
    ax.yaxis.label.set_color(C["text_dim"])
    ax.title.set_color(C["text"])
    ax.grid(True, color=C["border_dim"], linewidth=0.5, alpha=0.6)


class BaseChart:
    """Common scaffolding: Figure + Canvas inside a CTkFrame."""

    def __init__(self, parent, figsize=(4, 2.4), dpi=90, title=""):
        self.frame = ctk.CTkFrame(parent, fg_color=C["panel"],
                                  corner_radius=8, border_width=1,
                                  border_color=C["border_dim"])
        self.title = title
        self.fig = Figure(figsize=figsize, dpi=dpi)
        self.fig.patch.set_facecolor(C["panel"])
        self.canvas = FigureCanvasTkAgg(self.fig, master=self.frame)
        self.canvas.get_tk_widget().configure(bg=C["panel"], highlightthickness=0)
        self.canvas.get_tk_widget().pack(fill="both", expand=True, padx=6, pady=6)

    @property
    def widget(self):
        return self.frame

    def _redraw(self):
        self.fig.tight_layout(pad=0.6)
        self.canvas.draw()

    def clear_message(self, ax, message="No data yet"):
        ax.text(0.5, 0.5, message, ha="center", va="center",
                color=C["text_muted"], fontsize=9, transform=ax.transAxes)
        ax.set_xticks([])
        ax.set_yticks([])


# ─── 1. Severity Donut — per-VM card mini chart or report overview ────────────
class SeverityDonut(BaseChart):
    """Donut chart showing HIGH/MEDIUM/LOW/INFO finding counts."""

    def __init__(self, parent, figsize=(2.6, 2.6), dpi=90, small=False):
        super().__init__(parent, figsize=figsize, dpi=dpi, title="Severity")
        self.small = small
        self.ax = self.fig.add_subplot(111)
        self._draw_empty()

    def _draw_empty(self):
        self.ax.clear()
        self.ax.set_facecolor(C["panel"])
        self.ax.pie([1], colors=[C["border_dim"]],
                    wedgeprops=dict(width=0.42, edgecolor=C["panel"]))
        if not self.small:
            self.ax.text(0, 0, "—", ha="center", va="center",
                         color=C["text_muted"], fontsize=14, weight="bold")
        self._redraw()

    def update(self, counts: dict):
        """counts = {'HIGH': n, 'MEDIUM': n, 'LOW': n, 'INFO': n}"""
        self.ax.clear()
        self.ax.set_facecolor(C["panel"])

        values = [counts.get(s, 0) for s in SEV_ORDER]
        total  = sum(values)

        if total == 0:
            self._draw_empty()
            return

        # Only show non-zero slices, but keep color mapping consistent
        nz_values, nz_colors = [], []
        for v, c in zip(values, SEV_COLORS):
            if v > 0:
                nz_values.append(v)
                nz_colors.append(c)

        wedges, _ = self.ax.pie(
            nz_values, colors=nz_colors,
            wedgeprops=dict(width=0.42, edgecolor=C["panel"], linewidth=1.5),
            startangle=90)

        center_text = str(total)
        center_size = 18 if not self.small else 13
        self.ax.text(0, 0, center_text, ha="center", va="center",
                     color=C["text"], fontsize=center_size, weight="bold")
        if not self.small:
            self.ax.text(0, -0.28, "findings", ha="center", va="center",
                         color=C["text_muted"], fontsize=7)

        self._redraw()


# ─── 2. Severity Bar — horizontal bars, used in report sidebar ────────────────
class SeverityBarChart(BaseChart):
    """Horizontal bar chart, one bar per severity level."""

    def __init__(self, parent, figsize=(3.2, 2.0), dpi=90):
        super().__init__(parent, figsize=figsize, dpi=dpi, title="Findings by Severity")
        self.ax = self.fig.add_subplot(111)
        self._draw_empty()

    def _draw_empty(self):
        self.ax.clear()
        _style_axes(self.ax, self.fig)
        self.clear_message(self.ax)
        self._redraw()

    def update(self, counts: dict):
        self.ax.clear()
        _style_axes(self.ax, self.fig)

        values = [counts.get(s, 0) for s in SEV_ORDER]
        if sum(values) == 0:
            self.clear_message(self.ax)
            self._redraw()
            return

        y_pos = range(len(SEV_ORDER))
        bars = self.ax.barh(y_pos, values, color=SEV_COLORS, height=0.55)
        self.ax.set_yticks(y_pos)
        self.ax.set_yticklabels(SEV_ORDER, fontsize=8)
        self.ax.invert_yaxis()
        max_v = max(values) if max(values) > 0 else 1
        self.ax.set_xlim(0, max_v * 1.25)

        for bar, val in zip(bars, values):
            if val > 0:
                self.ax.text(bar.get_width() + max_v * 0.03,
                             bar.get_y() + bar.get_height()/2,
                             str(val), va="center", ha="left",
                             color=C["text"], fontsize=9, weight="bold")
        self.ax.set_title(self.title, fontsize=9, loc="left")
        self._redraw()


# ─── 3. Findings Timeline — events over time (line/scatter) ──────────────────
class FindingsTimeline(BaseChart):
    """
    Line chart of finding-evidence counts over time, bucketed by hour.
    Splunk-style 'events over time' panel.
    """

    TS_PATTERNS = [
        re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"),          # ISO8601
        re.compile(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"),           # syslog "Jun  8 14:23:01"
    ]

    def __init__(self, parent, figsize=(7.5, 2.2), dpi=90):
        super().__init__(parent, figsize=figsize, dpi=dpi, title="Events Over Time")
        self.ax = self.fig.add_subplot(111)
        self._draw_empty()

    def _draw_empty(self):
        self.ax.clear()
        _style_axes(self.ax, self.fig)
        self.clear_message(self.ax, "No timestamped events")
        self._redraw()

    def _extract_hour(self, line: str, fallback_year: int):
        for pat in self.TS_PATTERNS:
            m = pat.search(line)
            if not m:
                continue
            raw = m.group(1)
            for fmt in ("%Y-%m-%dT%H:%M:%S", "%b %d %H:%M:%S"):
                try:
                    dt = datetime.strptime(raw, fmt)
                    if fmt == "%b %d %H:%M:%S":
                        dt = dt.replace(year=fallback_year)
                    return dt.replace(minute=0, second=0, microsecond=0)
                except ValueError:
                    continue
        return None

    def update(self, findings: list):
        """findings = list of Finding objects (with .evidence lists)"""
        self.ax.clear()
        _style_axes(self.ax, self.fig)

        now = datetime.now()
        bucket = Counter()
        for f in findings:
            for line in (f.evidence or []):
                hour = self._extract_hour(line, now.year)
                if hour:
                    bucket[hour] += 1

        if not bucket:
            self.clear_message(self.ax, "No timestamped events")
            self._redraw()
            return

        hours  = sorted(bucket.keys())
        counts = [bucket[h] for h in hours]
        labels = [h.strftime("%H:%M") for h in hours]

        self.ax.plot(range(len(hours)), counts, color=C["accent"],
                     marker="o", markersize=4, linewidth=1.6)
        self.ax.fill_between(range(len(hours)), counts, color=C["accent"], alpha=0.12)

        step = max(1, len(hours) // 8)
        self.ax.set_xticks(range(0, len(hours), step))
        self.ax.set_xticklabels([labels[i] for i in range(0, len(hours), step)],
                                rotation=0, fontsize=7)
        self.ax.set_title(self.title, fontsize=9, loc="left")
        self.ax.set_ylabel("events", fontsize=8)
        self._redraw()


# ─── 4. Top Source IPs — horizontal bar of attacker IPs ───────────────────────
class TopIPsChart(BaseChart):
    """Top source IPs seen across all findings' evidence lines."""

    IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

    def __init__(self, parent, figsize=(3.6, 2.2), dpi=90, top_n=5):
        super().__init__(parent, figsize=figsize, dpi=dpi, title="Top Source IPs")
        self.top_n = top_n
        self.ax = self.fig.add_subplot(111)
        self._draw_empty()

    def _draw_empty(self):
        self.ax.clear()
        _style_axes(self.ax, self.fig)
        self.clear_message(self.ax, "No IPs found")
        self._redraw()

    def update(self, findings: list):
        self.ax.clear()
        _style_axes(self.ax, self.fig)

        counter = Counter()
        for f in findings:
            for line in (f.evidence or []):
                for ip in self.IP_RE.findall(line):
                    counter[ip] += 1

        if not counter:
            self.clear_message(self.ax, "No IPs found")
            self._redraw()
            return

        top = counter.most_common(self.top_n)
        ips, counts = zip(*top)
        y_pos = range(len(ips))

        bars = self.ax.barh(y_pos, counts, color=C["red"], height=0.5, alpha=0.85)
        self.ax.set_yticks(y_pos)
        self.ax.set_yticklabels(ips, fontsize=8, family="monospace")
        self.ax.invert_yaxis()

        max_c = max(counts)
        self.ax.set_xlim(0, max_c * 1.25)
        for bar, val in zip(bars, counts):
            self.ax.text(bar.get_width() + max_c * 0.03,
                         bar.get_y() + bar.get_height()/2,
                         str(val), va="center", ha="left",
                         color=C["text"], fontsize=8, weight="bold")

        self.ax.set_title(self.title, fontsize=9, loc="left")
        self._redraw()


# ─── 5. Check Status Grid — small multiples, one cell per check ───────────────
class CheckStatusGrid(BaseChart):
    """
    Grid of small colored tiles, one per check, color = severity if findings
    exist, gray if clean, dark if skipped. Splunk single-value-panel style.
    """

    def __init__(self, parent, figsize=(7.5, 1.4), dpi=90, n_checks=8):
        super().__init__(parent, figsize=figsize, dpi=dpi, title="Check Status")
        self.n_checks = n_checks
        self.ax = self.fig.add_subplot(111)
        self._draw_empty()

    def _draw_empty(self):
        self.ax.clear()
        self.ax.set_facecolor(C["panel"])
        self.ax.set_xticks([])
        self.ax.set_yticks([])
        for spine in self.ax.spines.values():
            spine.set_visible(False)
        for i in range(self.n_checks):
            self.ax.add_patch(plt.Rectangle((i, 0), 0.9, 0.9,
                              facecolor=C["border_dim"], edgecolor="none"))
            self.ax.text(i + 0.45, 0.45, str(i+1), ha="center", va="center",
                         color=C["text_muted"], fontsize=9, weight="bold")
        self.ax.set_xlim(0, self.n_checks)
        self.ax.set_ylim(0, 1)
        self._redraw()

    def update(self, findings: list):
        self.ax.clear()
        self.ax.set_facecolor(C["panel"])
        self.ax.set_xticks([])
        self.ax.set_yticks([])
        for spine in self.ax.spines.values():
            spine.set_visible(False)

        for i, f in enumerate(findings):
            if f.skipped:
                color = "#1a2233"
                txt_color = C["text_muted"]
            elif f.evidence:
                color = C[f.severity]
                txt_color = C["bg"]
            else:
                color = "#16321f"
                txt_color = C["green"]

            self.ax.add_patch(plt.Rectangle((i, 0), 0.9, 0.9,
                              facecolor=color, edgecolor=C["border_dim"], linewidth=0.5))
            self.ax.text(i + 0.45, 0.45, str(f.check_id), ha="center", va="center",
                         color=txt_color, fontsize=9, weight="bold")
            # short label below
            label = f.check_name.split()[0][:6]
            self.ax.text(i + 0.45, -0.18, label, ha="center", va="top",
                         color=C["text_muted"], fontsize=6, rotation=0)

        self.ax.set_xlim(0, self.n_checks)
        self.ax.set_ylim(-0.4, 1)
        self.ax.set_title(self.title, fontsize=9, loc="left", pad=2)
        self._redraw()


# ─── 6. Fleet Overview — stacked bar across all VMs ───────────────────────────
class FleetOverviewChart(BaseChart):
    """
    Stacked horizontal bar chart: one row per VM, segments = HIGH/MED/LOW/INFO.
    Used in the main window sidebar/dashboard for a fleet-wide view.
    """

    def __init__(self, parent, figsize=(3.6, 3.0), dpi=90):
        super().__init__(parent, figsize=figsize, dpi=dpi, title="Fleet Overview")
        self.ax = self.fig.add_subplot(111)
        self._draw_empty()

    def _draw_empty(self):
        self.ax.clear()
        _style_axes(self.ax, self.fig)
        self.clear_message(self.ax, "Run a hunt to see results")
        self._redraw()

    def update(self, vm_reports: list):
        """vm_reports = list of (vm_name, counts_dict)"""
        self.ax.clear()
        _style_axes(self.ax, self.fig)

        vm_reports = [(n, c) for n, c in vm_reports if c and sum(c.values()) > 0]
        if not vm_reports:
            self.clear_message(self.ax, "Run a hunt to see results")
            self._redraw()
            return

        names = [n for n, _ in vm_reports]
        y_pos = range(len(names))
        left  = [0] * len(names)

        for sev, color in zip(SEV_ORDER, SEV_COLORS):
            values = [c.get(sev, 0) for _, c in vm_reports]
            self.ax.barh(y_pos, values, left=left, color=color,
                         height=0.5, label=sev)
            left = [l + v for l, v in zip(left, values)]

        self.ax.set_yticks(y_pos)
        self.ax.set_yticklabels(names, fontsize=8)
        self.ax.invert_yaxis()
        self.ax.legend(loc="lower right", fontsize=7, frameon=False,
                       labelcolor=C["text_dim"], ncol=4)
        self.ax.set_title(self.title, fontsize=9, loc="left")
        self._redraw()
