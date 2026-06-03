#!/usr/bin/env python3
"""
ThreatHunter GUI - VM Fleet Threat Hunting Tool
Built with customtkinter · Dark Theme
"""

import customtkinter as ctk
import tkinter as tk
from tkinter import filedialog, messagebox
import json
import threading
import os
import re
from datetime import datetime
from pathlib import Path

# ─── Try importing Fabric ────────────────────────────────────────────────────
try:
    from fabric import Connection
    from invoke.exceptions import UnexpectedExit
    from paramiko.ssh_exception import SSHException, AuthenticationException, NoValidConnectionsError
    FABRIC_AVAILABLE = True
except ImportError:
    FABRIC_AVAILABLE = False

# ─── Theme & Palette ─────────────────────────────────────────────────────────
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
    "info":        "#79c0ff",
    "muted":       "#8b949e",
    "text":        "#e6edf3",
    "text_dim":    "#8b949e",
    "hunt_active": "#d2a53a",
}

SEVERITY_COLORS = {
    "HIGH":   "#f85149",
    "MEDIUM": "#d29922",
    "LOW":    "#3fb950",
    "INFO":   "#79c0ff",
}

STATUS_COLORS = {
    "Unknown":  "#8b949e",
    "Online":   "#3fb950",
    "Offline":  "#f85149",
    "Hunting":  "#d2a53a",
    "Done":     "#388bfd",
    "Error":    "#f85149",
}

# ─── Hunt Checks ─────────────────────────────────────────────────────────────
HUNT_CHECKS = [
    {
        "id": 1,
        "name": "Failed SSH Logins",
        "log": "/var/log/auth.log",
        "alt_log": "/var/log/secure",
        "pattern": r"Failed password|authentication failure|Invalid user",
        "severity": "HIGH",
        "description": "Brute-force / credential stuffing attempts",
    },
    {
        "id": 2,
        "name": "Successful Logins",
        "log": "/var/log/auth.log",
        "alt_log": "/var/log/secure",
        "pattern": r"Accepted password|Accepted publickey|session opened for user",
        "severity": "INFO",
        "description": "Successful authentication events",
    },
    {
        "id": 3,
        "name": "Sudo Escalations",
        "log": "/var/log/auth.log",
        "alt_log": "/var/log/secure",
        "pattern": r"sudo:.*COMMAND|sudo:.*authentication failure",
        "severity": "MEDIUM",
        "description": "Privilege escalation via sudo",
    },
    {
        "id": 4,
        "name": "Cron Job Activity",
        "log": "/var/log/syslog",
        "alt_log": "/var/log/cron",
        "pattern": r"CRON\[|crond\[|CMD \(",
        "severity": "LOW",
        "description": "Scheduled task executions",
    },
    {
        "id": 5,
        "name": "New User / Group Changes",
        "log": "/var/log/auth.log",
        "alt_log": "/var/log/secure",
        "pattern": r"useradd|userdel|groupadd|usermod|passwd changed",
        "severity": "HIGH",
        "description": "Account manipulation events",
    },
    {
        "id": 6,
        "name": "Kernel / OOM Events",
        "log": "/var/log/kern.log",
        "alt_log": "/var/log/messages",
        "pattern": r"Out of memory|oom_kill|segfault|kernel BUG|RIP:",
        "severity": "MEDIUM",
        "description": "Kernel errors and OOM kills",
    },
    {
        "id": 7,
        "name": "Network Listening Ports",
        "log": None,  # live command check
        "alt_log": None,
        "pattern": None,
        "severity": "INFO",
        "description": "Active listening sockets (ss -tlnp)",
        "command": "ss -tlnp 2>/dev/null || netstat -tlnp 2>/dev/null || echo 'No tool available'",
    },
    {
        "id": 8,
        "name": "Recently Modified /etc Files",
        "log": None,
        "alt_log": None,
        "pattern": None,
        "severity": "MEDIUM",
        "description": "Files in /etc modified in last 24h",
        "command": "find /etc -maxdepth 2 -newer /etc/hostname -type f 2>/dev/null | head -30",
    },
    {
        "id": 9,
        "name": "SUID / SGID Binaries",
        "log": None,
        "alt_log": None,
        "pattern": None,
        "severity": "HIGH",
        "description": "Suspicious setuid/setgid executables",
        "command": "find /usr /bin /sbin /tmp /var/tmp -perm /6000 -type f 2>/dev/null | head -30",
    },
]

TOTAL_CHECKS = len(HUNT_CHECKS)


# ─── VM Data Model ────────────────────────────────────────────────────────────
class VMEntry:
    def __init__(self, data: dict):
        self.hostname   = data.get("hostname", data.get("host", "unknown"))
        self.host       = data.get("host", "")
        self.port       = int(data.get("port", 22))
        self.username   = data.get("username", "root")
        self.key_path   = data.get("key_path")
        self.password   = data.get("password")
        self.status     = "Unknown"
        self.report     = None
        self.last_conn_info = ""

    def connect_kwargs(self):
        kw = {}
        if self.key_path:
            path = os.path.expanduser(self.key_path)
            if os.path.exists(path):
                kw["key_filename"] = [path]
        if self.password:
            kw["password"] = self.password
        return kw

    def get_connection(self):
        if not FABRIC_AVAILABLE:
            raise RuntimeError("Fabric not installed. Run: pip install fabric")
        return Connection(
            host=self.host,
            user=self.username,
            port=self.port,
            connect_kwargs=self.connect_kwargs(),
            connect_timeout=10,
        )


# ─── Hunting Engine ───────────────────────────────────────────────────────────
def run_connectivity_test(vm: VMEntry):
    """Returns (success: bool, message: str)"""
    try:
        c = vm.get_connection()
        result = c.run("hostname && uptime", hide=True, timeout=15)
        c.close()
        return True, result.stdout.strip()
    except Exception as e:
        return False, str(e)


def run_hunt(vm: VMEntry, progress_cb=None):
    """Run all hunt checks. Returns report dict."""
    report = {
        "vm":        vm.hostname,
        "host":      vm.host,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "findings":  [],
        "error":     None,
    }
    try:
        c = vm.get_connection()

        for i, check in enumerate(HUNT_CHECKS, 1):
            if progress_cb:
                progress_cb(i, TOTAL_CHECKS, check["name"])

            finding = {
                "check":       check["name"],
                "description": check["description"],
                "severity":    check["severity"],
                "log":         check.get("log", "N/A"),
                "lines":       [],
                "skipped":     False,
                "skip_reason": "",
            }

            try:
                if check.get("command"):
                    # Live command check
                    r = c.run(check["command"], hide=True, timeout=20, warn=True)
                    output = r.stdout.strip()
                    if output:
                        finding["lines"] = output.splitlines()
                    finding["log"] = f"[CMD] {check['command'][:60]}"
                else:
                    # Log file check — try primary, then alt
                    log_file = None
                    for lf in [check["log"], check.get("alt_log")]:
                        if not lf:
                            continue
                        test = c.run(f"test -r {lf} && echo exists", hide=True, warn=True, timeout=5)
                        if "exists" in test.stdout:
                            log_file = lf
                            break

                    if not log_file:
                        finding["skipped"] = True
                        finding["skip_reason"] = f"Log not found: {check['log']} / {check.get('alt_log','')}"
                    else:
                        finding["log"] = log_file
                        cmd = f"grep -Ei '{check['pattern']}' {log_file} 2>/dev/null | tail -20"
                        r = c.run(cmd, hide=True, timeout=20, warn=True)
                        lines = [l for l in r.stdout.splitlines() if l.strip()]
                        finding["lines"] = lines

            except Exception as e:
                finding["skipped"] = True
                finding["skip_reason"] = f"Error: {e}"

            report["findings"].append(finding)

        c.close()

    except Exception as e:
        report["error"] = str(e)

    return report


def format_report_text(report: dict) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append(f"  THREAT HUNT REPORT — {report['vm']}  ({report['host']})")
    lines.append(f"  Timestamp : {report['timestamp']}")
    lines.append("=" * 70)

    if report.get("error"):
        lines.append(f"\n[!] CONNECTION ERROR: {report['error']}\n")
        return "\n".join(lines)

    for f in report["findings"]:
        sev = f["severity"]
        tag = f"[{sev}]"
        lines.append(f"\n{'─'*60}")
        lines.append(f"{tag}  {f['check']}")
        lines.append(f"     Source : {f['log']}")
        lines.append(f"     Desc   : {f['description']}")

        if f["skipped"]:
            lines.append(f"     Status : SKIPPED — {f['skip_reason']}")
        elif not f["lines"]:
            lines.append("     Result : No matching entries found")
        else:
            lines.append(f"     Hits   : {len(f['lines'])} lines")
            lines.append("     Evidence:")
            for ln in f["lines"][:15]:
                lines.append(f"       {ln}")
            if len(f["lines"]) > 15:
                lines.append(f"       ... ({len(f['lines'])-15} more lines)")

    lines.append(f"\n{'='*70}")
    lines.append("  END OF REPORT")
    lines.append("=" * 70 + "\n")
    return "\n".join(lines)


# ─── VM Card Widget ───────────────────────────────────────────────────────────
class VMCard(ctk.CTkFrame):
    def __init__(self, parent, vm: VMEntry, app, **kwargs):
        super().__init__(parent, fg_color=COLORS["card"],
                         border_color=COLORS["card_border"], border_width=1,
                         corner_radius=8, **kwargs)
        self.vm  = vm
        self.app = app
        self._build()

    def _build(self):
        self.columnconfigure(1, weight=1)

        # Status dot
        self.dot = ctk.CTkLabel(self, text="●", font=("Consolas", 18),
                                text_color=STATUS_COLORS["Unknown"], width=30)
        self.dot.grid(row=0, column=0, rowspan=2, padx=(12, 6), pady=10)

        # Hostname + IP
        self.lbl_name = ctk.CTkLabel(self, text=self.vm.hostname,
                                     font=("JetBrains Mono", 13, "bold"),
                                     text_color=COLORS["text"], anchor="w")
        self.lbl_name.grid(row=0, column=1, sticky="w", pady=(10, 0))

        self.lbl_host = ctk.CTkLabel(
            self, text=f"{self.vm.host}:{self.vm.port}  ·  {self.vm.username}",
            font=("Consolas", 10), text_color=COLORS["text_dim"], anchor="w")
        self.lbl_host.grid(row=1, column=1, sticky="w", pady=(0, 10))

        # Status badge
        self.badge = ctk.CTkLabel(self, text=" Unknown ", font=("Consolas", 10),
                                  fg_color="#2d333b", corner_radius=4,
                                  text_color=STATUS_COLORS["Unknown"])
        self.badge.grid(row=0, column=2, padx=8, pady=(10, 0))

        # Progress label
        self.lbl_progress = ctk.CTkLabel(self, text="", font=("Consolas", 9),
                                         text_color=COLORS["muted"], anchor="e")
        self.lbl_progress.grid(row=1, column=2, padx=8, pady=(0, 10), sticky="e")

        # Buttons frame
        btn_frame = ctk.CTkFrame(self, fg_color="transparent")
        btn_frame.grid(row=0, column=3, rowspan=2, padx=(0, 12), pady=6)

        self.btn_test = ctk.CTkButton(
            btn_frame, text="Test", width=64, height=28,
            font=("Consolas", 11), fg_color="#2d333b",
            hover_color="#388bfd", text_color=COLORS["text"],
            command=self._test_conn)
        self.btn_test.pack(side="left", padx=3)

        self.btn_hunt = ctk.CTkButton(
            btn_frame, text="Hunt", width=64, height=28,
            font=("Consolas", 11), fg_color="#2d333b",
            hover_color="#d2a53a", text_color=COLORS["text"],
            command=self._hunt)
        self.btn_hunt.pack(side="left", padx=3)

        self.btn_view = ctk.CTkButton(
            btn_frame, text="Report", width=64, height=28,
            font=("Consolas", 11), fg_color="#2d333b",
            hover_color="#3fb950", text_color=COLORS["muted"],
            state="disabled", command=self._view_report)
        self.btn_view.pack(side="left", padx=3)

    def set_status(self, status: str, detail: str = ""):
        color = STATUS_COLORS.get(status, COLORS["muted"])
        self.dot.configure(text_color=color)
        self.badge.configure(text=f" {status} ", text_color=color)
        if detail:
            max_len = 45
            txt = detail if len(detail) <= max_len else detail[:max_len] + "…"
            self.lbl_progress.configure(text=txt)

    def set_progress(self, current: int, total: int, name: str = ""):
        self.lbl_progress.configure(text=f"Check {current}/{total}: {name[:28]}")

    def set_buttons(self, enabled: bool):
        state = "normal" if enabled else "disabled"
        self.btn_test.configure(state=state)
        self.btn_hunt.configure(state=state)

    def enable_report(self):
        self.btn_view.configure(state="normal", text_color=COLORS["text"])

    def _test_conn(self):
        self.set_status("Unknown", "Testing…")
        self.set_buttons(False)
        def task():
            ok, msg = run_connectivity_test(self.vm)
            self.vm.status = "Online" if ok else "Offline"
            self.vm.last_conn_info = msg
            self.after(0, lambda: self.set_status(self.vm.status, msg))
            self.after(0, lambda: self.set_buttons(True))
            self.after(0, lambda: self.app.log(
                f"[{'OK' if ok else 'FAIL'}] {self.vm.hostname}: {msg[:80]}"))
        threading.Thread(target=task, daemon=True).start()

    def _hunt(self):
        self.vm.status = "Hunting"
        self.set_status("Hunting", "Starting…")
        self.set_buttons(False)
        def task():
            def progress_cb(cur, tot, name):
                self.after(0, lambda: self.set_progress(cur, tot, name))
            report = run_hunt(self.vm, progress_cb)
            self.vm.report = report
            self.vm.status = "Done"
            summary = f"Done — {sum(1 for f in report['findings'] if f['lines'])} checks with hits"
            if report.get("error"):
                self.vm.status = "Error"
                summary = f"Error: {report['error'][:60]}"
            self.after(0, lambda: self.set_status(self.vm.status, summary))
            self.after(0, lambda: self.set_buttons(True))
            if not report.get("error"):
                self.after(0, self.enable_report)
            self.after(0, lambda: self.app.on_hunt_complete(self.vm))
            self.after(0, lambda: self.app.log(
                f"[HUNT] {self.vm.hostname}: {summary}"))
            if not report.get("error"):
                self.after(200, lambda: self.app.show_report(self.vm))
        threading.Thread(target=task, daemon=True).start()

    def _view_report(self):
        self.app.show_report(self.vm)


# ─── Report Viewer Popup ──────────────────────────────────────────────────────
class ReportWindow(ctk.CTkToplevel):
    def __init__(self, parent, vm: VMEntry):
        super().__init__(parent)
        self.vm = vm
        self.title(f"Report — {vm.hostname}")
        self.geometry("860x620")
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
        ctk.CTkLabel(top, text=f"  ⚡ HUNT REPORT  ·  {self.vm.hostname}",
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

        # Severity summary strip
        if self.vm.report and not self.vm.report.get("error"):
            strip = ctk.CTkFrame(self, fg_color=COLORS["panel"], corner_radius=0, height=36)
            strip.pack(fill="x")
            for sev, color in SEVERITY_COLORS.items():
                count = sum(1 for f in self.vm.report["findings"]
                            if f["severity"] == sev and f["lines"])
                ctk.CTkLabel(strip, text=f" {sev}: {count} ",
                             font=("Consolas", 10, "bold"),
                             text_color=color,
                             fg_color=COLORS["card"], corner_radius=4
                             ).pack(side="left", padx=6, pady=6)

        # Text area
        self.text = ctk.CTkTextbox(self, font=("Consolas", 11),
                                   fg_color=COLORS["card"],
                                   text_color=COLORS["text"],
                                   wrap="none", corner_radius=0)
        self.text.pack(fill="both", expand=True, padx=0, pady=0)

        if self.vm.report:
            content = format_report_text(self.vm.report)
            self.text.insert("1.0", content)
            # Color-tag severity lines
            self._apply_colors()
        self.text.configure(state="disabled")

    def _apply_colors(self):
        text_widget = self.text._textbox
        for sev, color in SEVERITY_COLORS.items():
            tag = f"sev_{sev}"
            text_widget.tag_configure(tag, foreground=color)
            idx = "1.0"
            while True:
                pos = text_widget.search(f"[{sev}]", idx, stopindex="end")
                if not pos:
                    break
                end = f"{pos}+{len(sev)+2}c"
                text_widget.tag_add(tag, pos, end)
                idx = end

    def _save(self, fmt: str):
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        default = f"report_{self.vm.hostname}_{ts}.{fmt}"
        path = filedialog.asksaveasfilename(
            defaultextension=f".{fmt}",
            initialfile=default,
            filetypes=[(f"{fmt.upper()} files", f"*.{fmt}"), ("All", "*.*")])
        if not path:
            return
        try:
            if fmt == "json":
                with open(path, "w") as f:
                    json.dump(self.vm.report, f, indent=2)
            else:
                with open(path, "w") as f:
                    f.write(format_report_text(self.vm.report))
            messagebox.showinfo("Saved", f"Report saved:\n{path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))


# ─── Main Application ─────────────────────────────────────────────────────────
class ThreatHunterApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("ThreatHunter  ·  VM Fleet Console")
        self.geometry("1100x740")
        self.minsize(900, 600)
        self.configure(fg_color=COLORS["bg"])
        self.vms: list[VMEntry] = []
        self.vm_cards: list[VMCard] = []
        self._build_ui()
        self._load_vms()

    # ── UI Layout ──────────────────────────────────────────────────────────────
    def _build_ui(self):
        # ─ Title bar ─
        title_bar = ctk.CTkFrame(self, fg_color=COLORS["panel"],
                                 corner_radius=0, height=52)
        title_bar.pack(fill="x", side="top")
        title_bar.pack_propagate(False)

        ctk.CTkLabel(title_bar,
                     text="  ⚡ ThreatHunter",
                     font=("JetBrains Mono", 16, "bold"),
                     text_color=COLORS["accent2"]).pack(side="left", padx=4)
        ctk.CTkLabel(title_bar,
                     text="VM Fleet Console",
                     font=("Consolas", 12),
                     text_color=COLORS["muted"]).pack(side="left", padx=0)

        # Global action buttons
        btn_cfg = dict(font=("Consolas", 11), height=32, corner_radius=6)
        self.btn_reload = ctk.CTkButton(title_bar, text="⟳  Reload",
            width=90, fg_color=COLORS["card"], hover_color=COLORS["accent"],
            **btn_cfg, command=self._reload_vms)
        self.btn_reload.pack(side="right", padx=6, pady=10)

        self.btn_save_all = ctk.CTkButton(title_bar, text="💾 Save All",
            width=100, fg_color=COLORS["card"], hover_color=COLORS["success"],
            **btn_cfg, command=self._save_all)
        self.btn_save_all.pack(side="right", padx=0, pady=10)

        self.btn_hunt_all = ctk.CTkButton(title_bar, text="🎯 Hunt All",
            width=100, fg_color="#2a1f0a", hover_color="#d2a53a",
            text_color=COLORS["hunt_active"], **btn_cfg, command=self._hunt_all)
        self.btn_hunt_all.pack(side="right", padx=6, pady=10)

        self.btn_test_all = ctk.CTkButton(title_bar, text="🔗 Test All",
            width=100, fg_color=COLORS["card"], hover_color=COLORS["accent"],
            **btn_cfg, command=self._test_all)
        self.btn_test_all.pack(side="right", padx=0, pady=10)

        # ─ Main pane ─
        main = ctk.CTkFrame(self, fg_color="transparent")
        main.pack(fill="both", expand=True, padx=0, pady=0)
        main.columnconfigure(0, weight=1)
        main.rowconfigure(0, weight=3)
        main.rowconfigure(1, weight=1)

        # VM Fleet panel
        fleet_frame = ctk.CTkFrame(main, fg_color=COLORS["panel"], corner_radius=0)
        fleet_frame.grid(row=0, column=0, sticky="nsew")
        fleet_frame.rowconfigure(1, weight=1)
        fleet_frame.columnconfigure(0, weight=1)

        fleet_hdr = ctk.CTkFrame(fleet_frame, fg_color=COLORS["card_border"],
                                 corner_radius=0, height=32)
        fleet_hdr.grid(row=0, column=0, sticky="ew")
        fleet_hdr.pack_propagate(False)
        ctk.CTkLabel(fleet_hdr, text="  VM FLEET",
                     font=("Consolas", 10, "bold"),
                     text_color=COLORS["muted"]).pack(side="left", pady=6, padx=8)
        self.lbl_vm_count = ctk.CTkLabel(fleet_hdr, text="0 hosts",
                                          font=("Consolas", 10),
                                          text_color=COLORS["accent"])
        self.lbl_vm_count.pack(side="left", pady=6)

        self.fleet_scroll = ctk.CTkScrollableFrame(
            fleet_frame, fg_color=COLORS["panel"], corner_radius=0)
        self.fleet_scroll.grid(row=1, column=0, sticky="nsew")
        self.fleet_scroll.columnconfigure(0, weight=1)

        # Log / console panel
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
                     text_color=COLORS["muted"]).pack(side="left", pady=4, padx=8)
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
        fabric_ok = "Fabric ✓" if FABRIC_AVAILABLE else "Fabric NOT installed — pip install fabric"
        ctk.CTkLabel(status_bar, text=fabric_ok + "  ",
                     font=("Consolas", 9),
                     text_color=COLORS["success"] if FABRIC_AVAILABLE else COLORS["danger"]
                     ).pack(side="right", padx=8)

    # ── VM Loading ─────────────────────────────────────────────────────────────
    def _load_vms(self):
        config_path = Path("vms.json")
        if not config_path.exists():
            self.log("[ERROR] vms.json not found. Creating sample file…")
            sample = [
                {"hostname": "example-host", "host": "192.168.1.1", "port": 22,
                 "username": "admin", "key_path": "~/.ssh/id_rsa", "password": None}
            ]
            with open(config_path, "w") as f:
                json.dump(sample, f, indent=2)
            self.log("[INFO] Sample vms.json created. Edit it and reload.")

        try:
            with open(config_path) as f:
                data = json.load(f)
        except Exception as e:
            self.log(f"[ERROR] Failed to parse vms.json: {e}")
            return

        # Clear existing cards
        for w in self.fleet_scroll.winfo_children():
            w.destroy()
        self.vms.clear()
        self.vm_cards.clear()

        for entry in data:
            vm = VMEntry(entry)
            self.vms.append(vm)
            card = VMCard(self.fleet_scroll, vm, self)
            card.grid(row=len(self.vms)-1, column=0, sticky="ew",
                      padx=10, pady=(6, 0))
            self.vm_cards.append(card)

        self.lbl_vm_count.configure(text=f"{len(self.vms)} host{'s' if len(self.vms)!=1 else ''}")
        self.log(f"[INFO] Loaded {len(self.vms)} VM(s) from vms.json")
        self.lbl_status.configure(text=f"  {len(self.vms)} VMs loaded from vms.json")

    def _reload_vms(self):
        self._load_vms()

    # ── Bulk Actions ───────────────────────────────────────────────────────────
    def _test_all(self):
        self.log("[INFO] Testing all VMs…")
        for card in self.vm_cards:
            card._test_conn()

    def _hunt_all(self):
        self.log("[INFO] Starting hunt on all VMs…")
        for card in self.vm_cards:
            card._hunt()

    def _save_all(self):
        done = [vm for vm in self.vms if vm.report]
        if not done:
            messagebox.showinfo("No Reports", "No hunt reports available yet. Run Hunt first.")
            return
        folder = filedialog.askdirectory(title="Choose save folder")
        if not folder:
            return
        saved = 0
        for vm in done:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = os.path.join(folder, f"report_{vm.hostname}_{ts}.txt")
            try:
                with open(path, "w") as f:
                    f.write(format_report_text(vm.report))
                saved += 1
            except Exception as e:
                self.log(f"[ERROR] Could not save {vm.hostname}: {e}")
        messagebox.showinfo("Saved", f"Saved {saved} report(s) to:\n{folder}")
        self.log(f"[INFO] Saved {saved} reports to {folder}")

    # ── Callbacks ──────────────────────────────────────────────────────────────
    def on_hunt_complete(self, vm: VMEntry):
        done = sum(1 for v in self.vms if v.report)
        self.lbl_status.configure(text=f"  Hunt complete: {vm.hostname} · {done}/{len(self.vms)} VMs done")

    def show_report(self, vm: VMEntry):
        if not vm.report:
            return
        win = ReportWindow(self, vm)
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


# ─── Entry Point ──────────────────────────────────────────────────────────────
if __name__ == "__main__":
    app = ThreatHunterApp()
    app.mainloop()