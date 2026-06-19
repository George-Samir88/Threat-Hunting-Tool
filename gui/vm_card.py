"""
gui/vm_card.py — Professional VM Card with responsive vertical layout.

v5.0 COMPLETE REDESIGN:
  - Vertical layout: Info area (top) + Action buttons (bottom)
  - Full hostname visible with text wrapping
  - Buttons ALWAYS visible in a row at the bottom
  - Severity indicator as colored dots (not chart)
  - Responsive: adapts to any width
  - Proper padding and spacing for readability
  - Status as left border color (like Splunk)
"""

import threading
import queue
import customtkinter as ctk
from hunting.models import Report
from gui.charts import C

STATUS_CONFIG = {
    "Unknown":  {"color": "#64748b", "bg": "#1e293b", "border": "#334155"},
    "Online":    {"color": "#22c55e", "bg": "#0f2d15", "border": "#22c55e"},
    "Offline":   {"color": "#ef4444", "bg": "#2d0f0f", "border": "#ef4444"},
    "Hunting":   {"color": "#f59e0b", "bg": "#2d1f00", "border": "#f59e0b"},
    "Done":      {"color": "#3b82f6", "bg": "#0a1530", "border": "#3b82f6"},
    "Error":     {"color": "#ef4444", "bg": "#2d0f0f", "border": "#ef4444"},
}

OS_CONFIG = {
    "linux":   {"label": "LINUX",   "color": "#f59e0b", "bg": "#2d1f00"},
    "windows": {"label": "WINDOWS", "color": "#3b82f6", "bg": "#0a1530"},
    "unknown": {"label": "OS: ?",   "color": "#64748b", "bg": "#1e293b"},
}


class VMCard(ctk.CTkFrame):
    """
    Professional VM card with vertical layout.

    Layout:
    ┌────────────────────────────────────────┐
    │ [●] Hostname              [OS: LINUX] │  <- Top row
    │ 192.168.1.7:22  ·  georgesamir  🔑   │  <- Info row
    │                                        │
    │ ● HIGH: 0  ● MED: 0  ● LOW: 0        │  <- Severity row
    │                                        │
    │ [  Test  ] [  Hunt  ] [ Report ]       │  <- Buttons row
    └────────────────────────────────────────┘
    """

    def __init__(self, parent, vm_config: dict, event_queue: queue.Queue, app, **kwargs):
        super().__init__(parent,
                         fg_color=C["card"],
                         border_color=C["border_dim"],
                         border_width=1,
                         corner_radius=8,
                         **kwargs)

        self.vm_config = vm_config
        self.queue = event_queue
        self.app = app
        self.report: Report = None
        self._status = "Unknown"

        self._build()
        self._bind_hover()

    def _bind_hover(self):
        """Bind hover to self and all children."""
        for widget in [self] + list(self.winfo_children()):
            widget.bind("<Enter>", lambda e: self._on_hover())
            widget.bind("<Leave>", lambda e: self._on_leave())

    def _on_hover(self):
        self.configure(fg_color="#1e2740", border_color="#2d3a5c")

    def _on_leave(self):
        cfg = STATUS_CONFIG.get(self._status, STATUS_CONFIG["Unknown"])
        self.configure(fg_color=C["card"], border_color=cfg["border"])

    def _build(self):
        # Use pack for simpler, more reliable layout
        # Each section is a frame that packs top-to-bottom

        # === TOP SECTION: Status + Hostname + OS badge ===
        top_frame = ctk.CTkFrame(self, fg_color="transparent")
        top_frame.pack(fill="x", padx=12, pady=(10, 4))

        # Status dot (left)
        self.status_dot = ctk.CTkLabel(top_frame, text="●",
                                       font=("Consolas", 14, "bold"),
                                       text_color=STATUS_CONFIG["Unknown"]["color"],
                                       width=20)
        self.status_dot.pack(side="left", padx=(0, 8))

        # Hostname (center, expands)
        hostname = self.vm_config.get("hostname", self.vm_config.get("host", "Unknown"))
        self.lbl_name = ctk.CTkLabel(top_frame, text=hostname,
                                     font=("JetBrains Mono", 14, "bold"),
                                     text_color=C["text"], anchor="w")
        self.lbl_name.pack(side="left", fill="x", expand=True)

        # OS badge (right)
        os_hint = (self.vm_config.get("os_hint") or "unknown").lower()
        if os_hint not in OS_CONFIG:
            os_hint = "unknown"
        os_cfg = OS_CONFIG[os_hint]

        self.os_badge = ctk.CTkLabel(top_frame,
                                     text=f" {os_cfg['label']} ",
                                     font=("Consolas", 9, "bold"),
                                     fg_color=os_cfg["bg"],
                                     corner_radius=3,
                                     text_color=os_cfg["color"],
                                     height=20, width=55)
        self.os_badge.pack(side="right", padx=(8, 0))

        # Status badge (right of OS badge)
        self.status_badge = ctk.CTkLabel(top_frame, text="—",
                                         font=("Consolas", 9, "bold"),
                                         fg_color="#1e293b",
                                         corner_radius=3,
                                         text_color="#64748b",
                                         height=20, width=55)
        self.status_badge.pack(side="right")

        # === INFO SECTION: IP + Username + Auth ===
        info_frame = ctk.CTkFrame(self, fg_color="transparent")
        info_frame.pack(fill="x", padx=12, pady=(0, 6))

        auth_icon = "🔑" if self.vm_config.get("key_path") else "🔒"
        ip_text = f"{self.vm_config.get('host','')}:{self.vm_config.get('port',22)}"
        user_text = f"{self.vm_config.get('username','')} {auth_icon}"

        self.lbl_info = ctk.CTkLabel(info_frame,
                                     text=f"{ip_text}  ·  {user_text}",
                                     font=("Consolas", 10),
                                     text_color=C["text_dim"], anchor="w")
        self.lbl_info.pack(side="left", fill="x", expand=True)

        # Detail text (right side, shows status messages)
        self.lbl_detail = ctk.CTkLabel(info_frame, text="",
                                       font=("Consolas", 9),
                                       text_color=C["text_dim"], anchor="e")
        self.lbl_detail.pack(side="right")

        # === SEVERITY SECTION: Colored dots with counts ===
        self.severity_frame = ctk.CTkFrame(self, fg_color="transparent")
        self.severity_frame.pack(fill="x", padx=12, pady=(0, 8))

        self._build_severity_dots({"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0})

        # === BUTTONS SECTION: Test | Hunt | Report ===
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.pack(fill="x", padx=12, pady=(0, 10))

        btn_cfg = dict(font=("Consolas", 11, "bold"), height=32, corner_radius=6, border_width=1)

        # Test button
        self.btn_test = ctk.CTkButton(btn_frame, text="🔗 Test",
                                      fg_color="transparent", hover_color="#27344f",
                                      text_color=C["text"], border_color=C["border"],
                                      **btn_cfg, command=self.test_conn)
        self.btn_test.pack(side="left", fill="x", expand=True, padx=(0, 4))

        # Hunt button
        self.btn_hunt = ctk.CTkButton(btn_frame, text="🎯 Hunt",
                                      fg_color="transparent", hover_color="#2a1f00",
                                      text_color=C["amber"], border_color="#5a4200",
                                      **btn_cfg, command=self.hunt)
        self.btn_hunt.pack(side="left", fill="x", expand=True, padx=4)

        # Report button
        self.btn_report = ctk.CTkButton(btn_frame, text="📄 Report",
                                        fg_color="transparent", hover_color="#27344f",
                                        text_color=C["text_dim"], border_color=C["border_dim"],
                                        state="disabled",
                                        **btn_cfg, command=self._open_report)
        self.btn_report.pack(side="left", fill="x", expand=True, padx=(4, 0))

    def _build_severity_dots(self, counts: dict):
        """Build colored severity dots with counts."""
        for w in self.severity_frame.winfo_children():
            w.destroy()

        total = sum(counts.values())
        if total == 0:
            lbl = ctk.CTkLabel(self.severity_frame, text="No findings",
                               font=("Consolas", 9), text_color=C["text_dim"])
            lbl.pack(side="left")
            return

        colors = {"HIGH": C["red"], "MEDIUM": C["amber"], "LOW": C["green"], "INFO": C["accent"]}

        for sev in ["HIGH", "MEDIUM", "LOW", "INFO"]:
            count = counts.get(sev, 0)
            color = colors[sev] if count > 0 else "#334155"

            dot_frame = ctk.CTkFrame(self.severity_frame, fg_color="transparent")
            dot_frame.pack(side="left", padx=(0, 12))

            # Colored dot
            dot = ctk.CTkLabel(dot_frame, text="●",
                               font=("Consolas", 10),
                               text_color=color)
            dot.pack(side="left", padx=(0, 4))

            # Label
            lbl = ctk.CTkLabel(dot_frame, text=f"{sev[0]}:{count}",
                               font=("Consolas", 9, "bold"),
                               text_color=color)
            lbl.pack(side="left")

    # ── Public API ─────────────────────────────────────────────────────────────
    def set_status(self, status: str, detail: str = ""):
        self._status = status
        cfg = STATUS_CONFIG.get(status, STATUS_CONFIG["Unknown"])

        self.status_dot.configure(text_color=cfg["color"])
        self.status_badge.configure(text=status, text_color=cfg["color"],
                                     fg_color=cfg["bg"])
        self.configure(border_color=cfg["border"])

        if detail:
            self.lbl_detail.configure(text=detail[:50])
        else:
            self.lbl_detail.configure(text="")

    def set_progress(self, cur: int, tot: int, name: str):
        self.lbl_detail.configure(text=f"Check {cur}/{tot}: {name[:30]}")

    def set_buttons(self, enabled: bool):
        s = "normal" if enabled else "disabled"
        self.btn_test.configure(state=s)
        self.btn_hunt.configure(state=s)

    def set_os_badge(self, os_type: str):
        os_type = (os_type or "unknown").lower()
        if os_type not in OS_CONFIG:
            os_type = "unknown"
        cfg = OS_CONFIG[os_type]
        self.os_badge.configure(text=f" {cfg['label']} ",
                                text_color=cfg["color"],
                                fg_color=cfg["bg"])

    def set_report(self, report: Report):
        self.report = report
        self.set_os_badge(report.os_type)

        if report.error:
            self._build_severity_dots({"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0})
            self.btn_report.configure(state="disabled",
                                      text_color=C["text_dim"],
                                      border_color=C["border_dim"])
            return

        counts = {
            "HIGH": report.high_count,
            "MEDIUM": report.medium_count,
            "LOW": report.low_count,
            "INFO": report.info_count,
        }
        self._build_severity_dots(counts)
        self.btn_report.configure(state="normal",
                                  text_color=C["teal"],
                                  border_color=C["teal"])

    def _open_report(self):
        if self.report:
            self.app.show_report(self.report)

    # ── Thread Actions ─────────────────────────────────────────────────────────
    def test_conn(self):
        self.set_status("Unknown", "Testing connection...")
        self.set_buttons(False)

        def task():
            from transport.ssh import SSHTransport
            ssh = SSHTransport(
                host=self.vm_config["host"],
                port=int(self.vm_config.get("port", 22)),
                username=self.vm_config["username"],
                key_path=self.vm_config.get("key_path"),
                password=self.vm_config.get("password"),
            )
            try:
                ssh.connect()
                ok, out = ssh.run_command("hostname && uptime")
                ssh.close()
                status = "Online" if ok else "Offline"
                msg = out.splitlines()[-1][:70] if out else "No output"
            except Exception as e:
                status = "Offline"
                msg = str(e)[:70]
            self.queue.put({"type": "test_done", "card": self,
                            "status": status, "msg": msg})

        threading.Thread(target=task, daemon=True).start()

    def hunt(self):
        self.set_status("Hunting", "Initializing...")
        self.set_buttons(False)
        self._build_severity_dots({"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0})

        def progress_cb(cur, tot, name):
            self.queue.put({"type": "progress", "card": self,
                            "cur": cur, "tot": tot, "name": name})

        def task():
            from hunting.engine import run_hunt
            report = run_hunt(self.vm_config, progress_cb)
            self.queue.put({"type": "hunt_done", "card": self, "report": report})

        threading.Thread(target=task, daemon=True).start()