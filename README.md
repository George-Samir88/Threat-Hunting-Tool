# ⚡ ThreatHunter — VM Fleet Threat Hunting Tool

A dark-themed desktop GUI for running automated threat hunting checks across multiple Linux VMs over SSH. Built with Python, `customtkinter`, and `fabric`.

---

## 📸 Features

- **VM Fleet Panel** — manage multiple VMs from a single dashboard, each displayed as a live status card
- **Connectivity Test** — test SSH access per VM or all at once (`hostname && uptime`)
- **Automated Hunt Engine** — runs 8 security checks per VM in background threads (GUI never freezes)
- **Auto Report Popup** — report window opens automatically when hunting completes, stays focused
- **Save Reports** — export findings as `.txt` or `.json` with timestamped filenames
- **Save All** — bulk export reports for all VMs to a chosen folder
- **Dark Theme** — GitHub-style dark UI built with `customtkinter`
- **Lab Setup Script** — one command configures SSH key auth and injects realistic log noise on target VMs

---

## 🔍 Hunt Checks (8 Checks)

| # | Check | Severity | Source |
|---|-------|----------|--------|
| 1 | SSH Brute Force (5+ failures from same IP) | HIGH / MEDIUM | `/var/log/auth.log` or `/var/log/secure` |
| 2 | Successful Login After Failures | HIGH | `/var/log/auth.log` or `/var/log/secure` |
| 3 | Sudo Abuse (non-admin users, auth failures) | HIGH | `/var/log/auth.log` or `/var/log/secure` |
| 4 | New User / Group Created | HIGH | `/var/log/auth.log` or `/var/log/secure` |
| 5 | Unexpected Cron Entries (off-hours / non-root) | MEDIUM | `/var/log/cron` or spool |
| 6 | Unexpected Package Activity | MEDIUM | `/var/log/yum.log` or `dpkg.log` |
| 7 | Auditd Privilege Escalation | HIGH | `/var/log/audit/audit.log` |
| 8 | Suspicious Bash History | HIGH | `~/.bash_history` |

Each check falls back to alternative log paths automatically. Missing files are skipped and noted in the report.

---

## 📁 Project Structure

```
Final Project/
├── main.py                  # Entry point — launches the GUI
├── vms.json                 # VM connection config (do not commit)
├── vms.example.json         # Safe example config (commit this)
├── requirements.txt
├── README.md
├── gui/
│   ├── __init__.py
│   ├── app.py               # Main window, layout, queue polling loop
│   ├── vm_card.py           # Per-VM card widget
│   └── report_panel.py      # Report display + save logic
├── hunting/
│   ├── __init__.py
│   ├── engine.py            # Orchestrates checks per VM, returns Report
│   ├── checks.py            # All 8 individual check functions
│   └── models.py            # Finding + Report dataclasses
├── transport/
│   ├── __init__.py
│   └── ssh.py               # Fabric SSH wrapper (connect, run, fetch_log)
└── setup/
    ├── __init__.py
    └── setup_lab.py         # Lab environment setup script
```

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10+
- SSH access to target Linux VMs
- Windows / Linux / macOS desktop (requires a display for the GUI)

### Installation

```bash
# 1. Clone the repo
git clone https://github.com/George-Samir88/ThreatHunter.git
cd ThreatHunter

# 2. Create a virtual environment (recommended)
python -m venv venv

# Windows
venv\Scripts\activate

# Linux / macOS
source venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt
```

### Configuration

Copy the example config and fill in your VM details:

```bash
cp vms.example.json vms.json
```

Edit `vms.json`:

```json
[
  {
    "hostname": "kali-lab",
    "host": "192.168.72.216",
    "port": 22,
    "username": "georgesamir",
    "key_path": "~/.ssh/id_ed25519",
    "password": null
  }
]
```

| Field | Description |
|-------|-------------|
| `hostname` | Display name shown in the GUI card |
| `host` | IP address of the VM |
| `port` | SSH port (default `22`) |
| `username` | SSH login username |
| `key_path` | Path to private key — `null` if not used |
| `password` | SSH password — `null` if using key only |

> ⚠️ **`vms.json` is in `.gitignore`** — your credentials will never be committed.

---

## 🧪 Lab Setup (SSH Key + Log Injection)

Before hunting, run the setup script once to:
1. Generate an SSH keypair (if you don't have one)
2. Push your public key to the VM's `authorized_keys` using password auth
3. Inject realistic suspicious log entries across all 8 log targets
4. Verify key-based auth works

```bash
python setup/setup_lab.py --key ~/.ssh/id_ed25519
```

Options:

| Flag | Description |
|------|-------------|
| `--key` | Path to local SSH private key (default: `~/.ssh/id_ed25519`) |
| `--vm` | Target only one VM by hostname |
| `--password` | SSH password (prompted securely if not provided) |
| `--inject-only` | Skip key setup, only inject logs |
| `--vms-file` | Path to vms.json (default: `vms.json`) |

After setup completes, update `vms.json` to set `"password": null` — key auth is now configured.

---

## ▶️ Running the GUI

```bash
python main.py
```

> **If you see `ModuleNotFoundError: No module named 'gui'`** — make sure you run from
> the project root and that `__init__.py` files exist in each subfolder:
> ```powershell
> cd "C:\Users\YourName\Desktop\Final Project"
> New-Item -Path "gui\__init__.py" -ItemType File -Force
> New-Item -Path "hunting\__init__.py" -ItemType File -Force
> New-Item -Path "transport\__init__.py" -ItemType File -Force
> python main.py
> ```
> Alternatively, add these two lines at the very top of `main.py`:
> ```python
> import sys, os
> sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
> ```

---

## 🏗️ Architecture

### Threading Model
- Each hunt runs in a background `threading.Thread` — the GUI never freezes
- Worker threads communicate with the main thread via `queue.Queue`
- The main window polls the queue every 100ms with `root.after(100, poll_queue)`
- **Tkinter is not thread-safe** — widgets are only updated from the main thread

### SSH Transport
- `transport/ssh.py` wraps Fabric's `Connection`
- `fetch_log()` pulls remote log files locally via `Connection.get()` then parses in Python
- More reliable than streaming grep over a live SSH channel

### Data Models
- `Finding` and `Report` are Python `dataclasses`
- Clean field access and JSON serialization via `dataclasses.asdict()`

### Check Baselines
Each check uses a customizable known-good baseline defined at the top of `hunting/checks.py`:

| Baseline | Purpose |
|----------|---------|
| `EXPECTED_SUDO_USERS` | Users allowed to run sudo without alerting |
| `KNOWN_GOOD_CRON_USERS` | Users allowed to have scheduled cron jobs |
| `KNOWN_GOOD_PACKAGES` | Packages that should not trigger alerts |

Edit these to match your environment before running hunts.

---

## 🖥️ VirtualBox Networking Note

If your VM uses **NAT** (default), it won't be reachable from your host machine.

**Recommended — Host-Only Adapter:**
Add Adapter 2 in VirtualBox → Network → Host-Only. The VM gets a `192.168.x.x` IP reachable directly on port 22.

**Alternative — Port Forwarding:**

| Name | Protocol | Host IP | Host Port | Guest Port |
|------|----------|---------|-----------|------------|
| SSH | TCP | 127.0.0.1 | 2222 | 22 |

Then use `"host": "127.0.0.1"` and `"port": 2222` in `vms.json`.

---

## 📦 Dependencies

| Package | Purpose |
|---------|---------|
| `customtkinter` | Modern dark-themed GUI framework |
| `fabric` | SSH connections and remote command execution |
| `paramiko` | SSH protocol library (used by Fabric) |
| `invoke` | Command execution layer (used by Fabric) |

---

## 👤 Author

**George Samir**
Cybersecurity Threat Hunting & Incident Response
NTI — Threat Hunting & Incident Response Track
[LinkedIn](https://linkedin.com/in/george-samir) · [GitHub](https://github.com/George-Samir88)

---

## 📄 License

MIT License — free to use, modify, and distribute.
