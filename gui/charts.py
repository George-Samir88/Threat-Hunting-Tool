"""
gui/charts.py — Reusable matplotlib chart widgets, Splunk-dashboard style.

v4.0 FIXES:
  - FindingsTimeline: Fixed Windows timestamp parsing (.NET Date format)
  - FindingsTimeline: Changed from line chart to stacked bar chart
  - FindingsTimeline: Shows all 24 hours including empty ones
  - FindingsTimeline: Proper chronological order with date context
"""

import tkinter as tk
import customtkinter as ctk
import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from collections import Counter, defaultdict
from datetime import datetime, timedelta
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
    "text":       "#ffffff",
    "text_dim":   "#cbd5e1",
    "text_muted": "#8b9bb4",
    "HIGH":       "#ef4444",
    "MEDIUM":     "#f59e0b",
    "LOW":        "#22c55e",
    "INFO":       "#3b82f6",
}

SEV_ORDER  = ["HIGH", "MEDIUM", "LOW", "INFO"]
SEV_COLORS = [C["HIGH"], C["MEDIUM"], C["LOW"], C["INFO"]]

# ─── Font size scale (bumped +1 to +2pt from the original pass) ──────────────
FS_TINY   = 8
FS_SMALL  = 9
FS_BASE   = 10
FS_MED    = 11
FS_LARGE  = 16
FS_XLARGE = 20


def _style_axes(ax, fig):
    fig.patch.set_facecolor(C["panel"])
    ax.set_facecolor(C["panel"])
    for spine in ax.spines.values():
        spine.set_color(C["border_dim"])
    ax.tick_params(colors=C["text_dim"], labelsize=FS_SMALL)
    ax.xaxis.label.set_color(C["text_dim"])
    ax.yaxis.label.set_color(C["text_dim"])
    ax.title.set_color(C["text"])
    ax.grid(True, color=C["border_dim"], linewidth=0.5, alpha=0.6)


class BaseChart:
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
                color=C["text_dim"], fontsize=FS_BASE, transform=ax.transAxes)
        ax.set_xticks([])
        ax.set_yticks([])


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
                         color=C["text_dim"], fontsize=FS_MED, weight="bold")
        self._redraw()

    def update(self, counts: dict):
        self.ax.clear()
        self.ax.set_facecolor(C["panel"])

        values = [counts.get(s, 0) for s in SEV_ORDER]
        total  = sum(values)

        if total == 0:
            self._draw_empty()
            return

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
        center_size = FS_XLARGE if not self.small else FS_LARGE - 2
        self.ax.text(0, 0, center_text, ha="center", va="center",
                     color=C["text"], fontsize=center_size, weight="bold")
        if not self.small:
            self.ax.text(0, -0.28, "findings", ha="center", va="center",
                         color=C["text_dim"], fontsize=FS_SMALL)

        self._redraw()


class SeverityBarChart(BaseChart):
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
        self.ax.set_yticklabels(SEV_ORDER, fontsize=FS_SMALL, color=C["text"], weight="bold")
        self.ax.invert_yaxis()
        max_v = max(values) if max(values) > 0 else 1
        self.ax.set_xlim(0, max_v * 1.25)

        for bar, val in zip(bars, values):
            if val > 0:
                self.ax.text(bar.get_width() + max_v * 0.03,
                             bar.get_y() + bar.get_height()/2,
                             str(val), va="center", ha="left",
                             color=C["text"], fontsize=FS_BASE, weight="bold")
        self.ax.set_title(self.title, fontsize=FS_MED, loc="left", color=C["text"])
        self._redraw()


class FindingsTimeline(BaseChart):
    """
    Timeline chart showing event distribution over the last 24 hours.
    Uses stacked bar chart with color-coded severity levels.

    v4.0 FIXES:
      - Added Windows .NET Date format parsing (/Date(1781878819550)/)
      - Changed from line chart to stacked bar chart (better for discrete events)
      - Shows all 24 hours including empty ones (as 0)
      - Proper chronological order (left-to-right, past-to-future)
      - Date context in title and x-axis labels
    """

    # Timestamp patterns to match various log formats
    TS_PATTERNS = [
        # ISO format: 2024-06-19T17:33:45
        (re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})"), "%Y-%m-%dT%H:%M:%S"),
        # Linux syslog: Jun 19 17:33:45
        (re.compile(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"), "%b %d %H:%M:%S"),
        # Windows Event Log: /Date(1781878819550)/ (JSON .NET format)
        (re.compile(r"/Date\((\d+)\)/"), "epoch_ms"),
    ]

    def __init__(self, parent, figsize=(7.5, 2.2), dpi=90):
        super().__init__(parent, figsize=figsize, dpi=dpi, title="Events Over Time")
        self.ax = self.fig.add_subplot(111)
        self._draw_empty()

    def _draw_empty(self):
        self.ax.clear()
        _style_axes(self.ax, self.fig)
        self.ax.text(0.5, 0.5, "No timestamped events", ha="center", va="center",
                     color=C["text_dim"], fontsize=FS_BASE, transform=self.ax.transAxes)
        self.ax.set_xticks([])
        self.ax.set_yticks([])
        self._redraw()

    def _parse_timestamp(self, line: str):
        """Parse timestamp from various formats including Windows .NET Date."""
        now = datetime.now()

        for pattern, fmt in self.TS_PATTERNS:
            m = pattern.search(line)
            if not m:
                continue
            raw = m.group(1)

            try:
                if fmt == "epoch_ms":
                    # Handle .NET JSON Date format: /Date(1781878819550)/
                    epoch_ms = int(raw)
                    dt = datetime.fromtimestamp(epoch_ms / 1000)
                elif fmt == "%b %d %H:%M:%S":
                    dt = datetime.strptime(raw, fmt)
                    dt = dt.replace(year=now.year)
                else:
                    dt = datetime.strptime(raw, fmt)
                return dt.replace(minute=0, second=0, microsecond=0)
            except (ValueError, OSError):
                continue
        return None

    def update(self, findings: list):
        """Update timeline with findings from the last 24 hours."""
        self.ax.clear()
        _style_axes(self.ax, self.fig)

        now = datetime.now()
        cutoff = now - timedelta(hours=24)

        # Collect events by hour and severity
        hourly = defaultdict(lambda: defaultdict(int))

        for f in findings:
            if not f.evidence or f.skipped:
                continue
            for line in f.evidence:
                ts = self._parse_timestamp(line)
                if ts and ts >= cutoff:
                    hourly[ts][f.severity] += 1

        if not hourly:
            self._draw_empty()
            return

        # Generate all 24 hours (including empty ones)
        hours = []
        current = cutoff.replace(minute=0, second=0, microsecond=0)
        while current <= now:
            hours.append(current)
            current += timedelta(hours=1)

        # Stacked bar chart by severity
        sevs = ["HIGH", "MEDIUM", "LOW", "INFO"]
        colors = [C["HIGH"], C["MEDIUM"], C["LOW"], C["INFO"]]
        bottom = [0] * len(hours)

        for sev, color in zip(sevs, colors):
            counts = [hourly.get(h, {}).get(sev, 0) for h in hours]
            if any(counts):
                self.ax.bar(range(len(hours)), counts, bottom=bottom,
                           color=color, width=0.8, alpha=0.85, label=sev)
                bottom = [b + c for b, c in zip(bottom, counts)]

        # X-axis labels
        step = max(1, len(hours) // 6)
        ticks = list(range(0, len(hours), step))
        labels = []
        for i in ticks:
            h = hours[i]
            if h.day != now.day:
                labels.append(h.strftime("%b %d\n%H:00"))
            else:
                labels.append(h.strftime("%H:00"))

        self.ax.set_xticks(ticks)
        self.ax.set_xticklabels(labels, fontsize=FS_SMALL, color=C["text_dim"])

        max_total = max(bottom) if bottom else 0
        self.ax.set_ylim(0, max(max_total * 1.2, 1))
        self.ax.set_ylabel("Events", fontsize=FS_BASE, color=C["text_dim"])

        # Title with date range
        title_text = f"Events Over Time ({hours[0].strftime('%b %d %H:%M')} - {hours[-1].strftime('%b %d %H:%M')})"
        self.ax.set_title(title_text, fontsize=FS_MED, loc="left", color=C["text"], pad=10)

        if any(any(hourly.get(h, {}).get(sev, 0) for h in hours) for sev in sevs):
            self.ax.legend(loc="upper right", fontsize=FS_SMALL, frameon=False,
                          labelcolor=C["text_dim"], ncol=4)

        self.ax.grid(True, axis="y", color=C["border_dim"], linewidth=0.5, alpha=0.4)
        self.ax.set_axisbelow(True)

        self._redraw()


class TopIPsChart(BaseChart):
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

        bars = self.ax.barh(y_pos, counts, color=C["red"], height=0.5, alpha=0.9)
        self.ax.set_yticks(y_pos)
        self.ax.set_yticklabels(ips, fontsize=FS_SMALL, family="monospace",
                                color=C["text"], weight="bold")
        self.ax.invert_yaxis()

        max_c = max(counts)
        self.ax.set_xlim(0, max_c * 1.25)
        for bar, val in zip(bars, counts):
            self.ax.text(bar.get_width() + max_c * 0.03,
                         bar.get_y() + bar.get_height()/2,
                         str(val), va="center", ha="left",
                         color=C["text"], fontsize=FS_BASE, weight="bold")

        self.ax.set_title(self.title, fontsize=FS_MED, loc="left", color=C["text"])
        self._redraw()


class CheckStatusGrid(BaseChart):
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
                         color=C["text_dim"], fontsize=FS_BASE, weight="bold")
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
                txt_color = C["text_dim"]
            elif f.evidence:
                color = C[f.severity]
                txt_color = "#0a0e1a"
            else:
                color = "#16321f"
                txt_color = C["green"]

            self.ax.add_patch(plt.Rectangle((i, 0), 0.9, 0.9,
                              facecolor=color, edgecolor=C["border_dim"], linewidth=0.5))
            self.ax.text(i + 0.45, 0.45, str(f.check_id), ha="center", va="center",
                         color=txt_color, fontsize=FS_BASE, weight="bold")
            label = f.check_name.split()[0][:6]
            self.ax.text(i + 0.45, -0.2, label, ha="center", va="top",
                         color=C["text_dim"], fontsize=FS_TINY, rotation=0)

        self.ax.set_xlim(0, self.n_checks)
        self.ax.set_ylim(-0.42, 1)
        self.ax.set_title(self.title, fontsize=FS_MED, loc="left", pad=2, color=C["text"])
        self._redraw()


class FleetOverviewChart(BaseChart):
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
        self.ax.set_yticklabels(names, fontsize=FS_SMALL, color=C["text"], weight="bold")
        self.ax.invert_yaxis()
        self.ax.legend(loc="lower right", fontsize=FS_TINY, frameon=False,
                       labelcolor=C["text_dim"], ncol=4)
        self.ax.set_title(self.title, fontsize=FS_MED, loc="left", color=C["text"])
        self._redraw()