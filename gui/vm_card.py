"""
gui/vm_card.py — VM card with embedded SeverityDonut chart.

Contrast/readability pass: font sizes bumped +1-2pt, colors pulled from the
brightened palette in gui/charts.py (C dict).
"""

import threading
import queue
import customtkinter as ctk
from hunting.models import Report
from gui.charts import SeverityDonut, C

STATUS_COLOR = {
    "Unknown": "#a8b8d0",
    "Online":  "#22c55e",
    "Offline": "#ef4444",
    "Hunting": "#f59e0b",
    "Done":    "#3b82f6",
    "Error":   "#ef4444",
}

STATUS_ICON = {
    "Unknown": "○",
    "Online":  "●",
    "Offline": "●",
    "Hunting": "◐",
    "Done":    "●",
    "Error":   "●",
}

BORDER_COLOR = {
    "Unknown": C["border_dim"],
    "Online":  C["border_dim"],
    "Offline": C["border_dim"],
    "Hunting": C["amber"],
    "Done":    C["border"],
    "Error":   C["red"],
}


class VMCard(ctk.CTkFrame):
    def __init__(self, parent, vm_config: dict, event_queue: queue.Queue, app, **kwargs):
        super().__init__(parent,
                         fg_color=C["card"],
                         border_color=C["border_dim"],
                         border_width=1,
                         corner_radius=10, **kwargs)
        self.vm_config = vm_config
        self.queue     = event_queue
        self.app       = app
        self.report: Report = None
        self._status   = "Unknown"
        self._build()
        self.bind("<Enter>", self._on_hover)
        self.bind("<Leave>", self._on_leave)

    # ── Hover (only affects fill, never border) ─────────────────────────────────
    def _on_hover(self, _=None):
        self.configure(fg_color="#222d45")

    def _on_leave(self, _=None):
        self.configure(fg_color=C["card"])

    # ── Layout ─────────────────────────────────────────────────────────────────
    def _build(self):
        self.grid_columnconfigure(1, weight=1)

        # Status dot
        self.dot = ctk.CTkLabel(self, text="○",
                                font=("Consolas", 18),
                                text_color=STATUS_COLOR["Unknown"], width=24)
        self.dot.grid(row=0, column=0, rowspan=3, padx=(12, 4), pady=10, sticky="n")

        # Hostname
        hostname = self.vm_config.get("hostname", self.vm_config.get("host", "Unknown"))
        self.lbl_name = ctk.CTkLabel(self, text=hostname,
                                     font=("JetBrains Mono", 14, "bold"),
                                     text_color=C["text"], anchor="w")
        self.lbl_name.grid(row=0, column=1, sticky="w", pady=(10, 0))

        # host:port · user
        info = f"{self.vm_config.get('host','')}:{self.vm_config.get('port',22)}  ·  {self.vm_config.get('username','')}"
        ctk.CTkLabel(self, text=info, font=("Consolas", 10),
                     text_color=C["text_dim"], anchor="w"
                     ).grid(row=1, column=1, sticky="w")

        # Progress / detail label
        self.lbl_detail = ctk.CTkLabel(self, text="",
                                       font=("Consolas", 10),
                                       text_color=C["text_dim"], anchor="w")
        self.lbl_detail.grid(row=2, column=1, sticky="w", pady=(0, 8))

        # Severity donut (small)
        self.donut = SeverityDonut(self, figsize=(1.0, 1.0), dpi=80, small=True)
        self.donut.widget.configure(fg_color="transparent", border_width=0)
        self.donut.widget.grid(row=0, column=2, rowspan=3, padx=(4, 8), pady=8)

        # Status badge — fixed width so "Hunting"/"Offline" don't clip
        self.badge = ctk.CTkLabel(self, text="—",
                                  font=("Consolas", 10, "bold"),
                                  fg_color="#222d45",
                                  corner_radius=4,
                                  text_color=C["text_dim"],
                                  width=72, height=22)
        self.badge.grid(row=0, column=3, padx=(0, 4), pady=(10, 0), sticky="e")

        # Buttons
        btn_wrap = ctk.CTkFrame(self, fg_color="transparent")
        btn_wrap.grid(row=1, column=3, rowspan=2, padx=(0, 10), pady=(0, 8))

        b_cfg = dict(font=("Consolas", 11), height=27, corner_radius=5,
                     border_width=1)

        self.btn_test = ctk.CTkButton(
            btn_wrap, text="Test", width=56,
            fg_color="transparent", hover_color="#27344f",
            text_color=C["text"], border_color=C["border"],
            **b_cfg, command=self.test_conn)
        self.btn_test.pack(side="left", padx=(0, 4))

        self.btn_hunt = ctk.CTkButton(
            btn_wrap, text="Hunt", width=56,
            fg_color="transparent", hover_color="#2a1f00",
            text_color=C["amber"], border_color="#5a4200",
            **b_cfg, command=self.hunt)
        self.btn_hunt.pack(side="left", padx=(0, 4))

        self.btn_report = ctk.CTkButton(
            btn_wrap, text="Report", width=62,
            fg_color="transparent", hover_color="#27344f",
            text_color=C["text_dim"], border_color=C["border_dim"],
            state="disabled",
            **b_cfg, command=self._open_report)
        self.btn_report.pack(side="left")

    # ── Public API ─────────────────────────────────────────────────────────────
    def set_status(self, status: str, detail: str = ""):
        self._status = status
        color = STATUS_COLOR.get(status, C["text_dim"])
        icon  = STATUS_ICON.get(status, "○")
        self.dot.configure(text=icon, text_color=color)
        self.badge.configure(text=status, text_color=color, fg_color="#222d45")
        self.configure(border_color=BORDER_COLOR.get(status, C["border_dim"]))

        if detail:
            txt = detail if len(detail) <= 42 else detail[:42] + "…"
            self.lbl_detail.configure(text=txt)
        else:
            self.lbl_detail.configure(text="")

    def set_progress(self, cur: int, tot: int, name: str):
        self.lbl_detail.configure(text=f"Check {cur}/{tot}: {name[:30]}")

    def set_buttons(self, enabled: bool):
        s = "normal" if enabled else "disabled"
        self.btn_test.configure(state=s)
        self.btn_hunt.configure(state=s)

    def set_report(self, report: Report):
        """Called when a hunt finishes — updates donut and report button."""
        self.report = report

        if report.error:
            self.donut.update({"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0})
            self.btn_report.configure(state="disabled",
                                      text_color=C["text_dim"],
                                      border_color=C["border_dim"])
            return

        counts = {
            "HIGH":   report.high_count,
            "MEDIUM": report.medium_count,
            "LOW":    report.low_count,
            "INFO":   report.info_count,
        }
        self.donut.update(counts)
        self.btn_report.configure(state="normal",
                                  text_color=C["teal"],
                                  border_color=C["teal"])

    def _open_report(self):
        if self.report:
            self.app.show_report(self.report)

    # ── Thread Actions ─────────────────────────────────────────────────────────
    def test_conn(self):
        self.set_status("Unknown", "Testing connection…")
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
                msg    = out.splitlines()[-1][:70] if out else "No output"
            except Exception as e:
                status = "Offline"
                msg    = str(e)[:70]
            self.queue.put({"type": "test_done", "card": self,
                            "status": status, "msg": msg})

        threading.Thread(target=task, daemon=True).start()

    def hunt(self):
        self.set_status("Hunting", "Initializing…")
        self.set_buttons(False)
        self.donut.update({"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0})

        def progress_cb(cur, tot, name):
            self.queue.put({"type": "progress", "card": self,
                            "cur": cur, "tot": tot, "name": name})

        def task():
            from hunting.engine import run_hunt
            report = run_hunt(self.vm_config, progress_cb)
            self.queue.put({"type": "hunt_done", "card": self, "report": report})

        threading.Thread(target=task, daemon=True).start()
