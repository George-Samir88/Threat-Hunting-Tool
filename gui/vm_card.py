"""
gui/vm_card.py — Per-VM card widget
Communicates with the main app via a thread-safe queue — never touches
the engine or SSH directly.
"""
import threading
import queue
import customtkinter as ctk
from hunting.models import Report

COLORS = {
    "card":        "#1c2128",
    "card_border": "#30363d",
    "text":        "#e6edf3",
    "text_dim":    "#8b949e",
    "muted":       "#8b949e",
}
STATUS_COLORS = {
    "Unknown":  "#8b949e",
    "Online":   "#3fb950",
    "Offline":  "#f85149",
    "Hunting":  "#d2a53a",
    "Done":     "#388bfd",
    "Error":    "#f85149",
}


class VMCard(ctk.CTkFrame):
    def __init__(self, parent, vm_config: dict, event_queue: queue.Queue, app, **kwargs):
        super().__init__(parent,
                         fg_color=COLORS["card"],
                         border_color=COLORS["card_border"],
                         border_width=1, corner_radius=8, **kwargs)
        self.vm_config   = vm_config
        self.queue       = event_queue
        self.app         = app
        self.report: Report = None
        self._build()

    def _build(self):
        self.columnconfigure(1, weight=1)

        self.dot = ctk.CTkLabel(self, text="●", font=("Consolas", 18),
                                text_color=STATUS_COLORS["Unknown"], width=30)
        self.dot.grid(row=0, column=0, rowspan=2, padx=(12, 6), pady=10)

        self.lbl_name = ctk.CTkLabel(
            self, text=self.vm_config.get("hostname", self.vm_config["host"]),
            font=("JetBrains Mono", 13, "bold"),
            text_color=COLORS["text"], anchor="w")
        self.lbl_name.grid(row=0, column=1, sticky="w", pady=(10, 0))

        self.lbl_host = ctk.CTkLabel(
            self,
            text=f"{self.vm_config['host']}:{self.vm_config.get('port',22)}  ·  {self.vm_config['username']}",
            font=("Consolas", 10), text_color=COLORS["text_dim"], anchor="w")
        self.lbl_host.grid(row=1, column=1, sticky="w", pady=(0, 10))

        self.badge = ctk.CTkLabel(self, text=" Unknown ", font=("Consolas", 10),
                                  fg_color="#2d333b", corner_radius=4,
                                  text_color=STATUS_COLORS["Unknown"])
        self.badge.grid(row=0, column=2, padx=8, pady=(10, 0))

        self.lbl_progress = ctk.CTkLabel(self, text="", font=("Consolas", 9),
                                         text_color=COLORS["muted"], anchor="e")
        self.lbl_progress.grid(row=1, column=2, padx=8, pady=(0, 10), sticky="e")

        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.grid(row=0, column=3, rowspan=2, padx=(0, 12), pady=6)

        self.btn_test = ctk.CTkButton(
            btn_frame, text="Test", width=64, height=28,
            font=("Consolas", 11), fg_color="#2d333b",
            hover_color="#388bfd", text_color=COLORS["text"],
            command=self.test_conn)
        self.btn_test.pack(side="left", padx=3)

        self.btn_hunt = ctk.CTkButton(
            btn_frame, text="Hunt", width=64, height=28,
            font=("Consolas", 11), fg_color="#2d333b",
            hover_color="#d2a53a", text_color=COLORS["text"],
            command=self.hunt)
        self.btn_hunt.pack(side="left", padx=3)

        self.btn_report = ctk.CTkButton(
            btn_frame, text="Report", width=64, height=28,
            font=("Consolas", 11), fg_color="#2d333b",
            hover_color="#3fb950", text_color=COLORS["muted"],
            state="disabled", command=self._open_report)
        self.btn_report.pack(side="left", padx=3)

    # ── Public API (called from main thread only) ──────────────────────────────
    def set_status(self, status: str, detail: str = ""):
        color = STATUS_COLORS.get(status, COLORS["muted"])
        self.dot.configure(text_color=color)
        self.badge.configure(text=f" {status} ", text_color=color)
        if detail:
            txt = detail if len(detail) <= 45 else detail[:45] + "…"
            self.lbl_progress.configure(text=txt)

    def set_progress(self, current: int, total: int, name: str):
        self.lbl_progress.configure(text=f"Check {current}/{total}: {name[:28]}")

    def set_buttons(self, enabled: bool):
        s = "normal" if enabled else "disabled"
        self.btn_test.configure(state=s)
        self.btn_hunt.configure(state=s)

    def set_report(self, report: Report):
        self.report = report
        self.btn_report.configure(state="normal", text_color=COLORS["text"])

    def _open_report(self):
        if self.report:
            self.app.show_report(self.report)

    # ── Actions (spawn threads, communicate via queue) ─────────────────────────
    def test_conn(self):
        self.set_status("Unknown", "Testing…")
        self.set_buttons(False)

        def task():
            from transport.ssh import SSHTransport
            from paramiko.ssh_exception import AuthenticationException, NoValidConnectionsError
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
                msg = out[:80]
            except Exception as e:
                status = "Offline"
                msg = str(e)[:80]

            self.queue.put({
                "type": "test_done",
                "card": self,
                "status": status,
                "msg": msg,
            })

        threading.Thread(target=task, daemon=True).start()

    def hunt(self):
        self.set_status("Hunting", "Starting…")
        self.set_buttons(False)

        def progress_cb(cur, tot, name):
            self.queue.put({
                "type": "progress",
                "card": self,
                "cur": cur, "tot": tot, "name": name,
            })

        def task():
            from hunting.engine import run_hunt
            report = run_hunt(self.vm_config, progress_cb)
            self.queue.put({
                "type": "hunt_done",
                "card": self,
                "report": report,
            })

        threading.Thread(target=task, daemon=True).start()
