# ⚡ ThreatHunter — VM Fleet Threat Hunting Tool

A dark-themed desktop GUI for running automated threat hunting checks across multiple Linux VMs over SSH. Built with Python and `customtkinter`.

---

## 📸 Features

- **VM Fleet Panel** — manage multiple VMs from a single dashboard, each displayed as a live status card
- **Connectivity Test** — test SSH access per VM or all at once (`hostname && uptime`)
- **Automated Hunt Engine** — runs 9 security checks per VM in background threads (GUI never freezes)
- **Auto Report Popup** — report window opens automatically when hunting completes
- **Save Reports** — export findings as `.txt` or `.json` with timestamped filenames
- **Save All** — bulk export reports for all VMs to a chosen folder
- **Dark Theme** — GitHub-style dark UI built with `customtkinter`

---

## 🔍 Hunt Checks

| # | Check | Severity | Source |
|---|-------|----------|--------|
| 1 | Failed SSH Logins | HIGH | `/var/log/auth.log` |
| 2 | Successful Logins | INFO | `/var/log/auth.log` |
| 3 | Sudo Escalations | MEDIUM | `/var/log/auth.log` |
| 4 | Cron Job Activity | LOW | `/var/log/syslog` |
| 5 | New User / Group Changes | HIGH | `/var/log/auth.log` |
| 6 | Kernel / OOM Events | MEDIUM | `/var/log/kern.log` |
| 7 | Network Listening Ports | INFO | `ss -tlnp` (live) |
| 8 | Recently Modified /etc Files | MEDIUM | `find /etc` (live) |
| 9 | SUID / SGID Binaries | HIGH | `find /usr /bin ...` (live) |

Checks fall back to alternative log paths automatically (e.g. `/var/log/secure` on RHEL/CentOS). Missing log files are skipped and noted in the report.

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

# 2. (Recommended) Create a virtual environment
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
    "key_path": "~/.ssh/id_rsa",
    "password": null
  },
  {
    "hostname": "ubuntu-soc",
    "host": "10.0.0.5",
    "port": 22,
    "username": "analyst",
    "key_path": null,
    "password": "yourpassword"
  }
]
```

| Field | Description |
|-------|-------------|
| `hostname` | Display name shown in the GUI |
| `host` | IP address or hostname of the VM |
| `port` | SSH port (default `22`) |
| `username` | SSH login username |
| `key_path` | Path to private key file — use `null` if not applicable |
| `password` | SSH password — use `null` if using key only |

> ⚠️ **`vms.json` is in `.gitignore`** — your credentials will never be committed to the repo.

### Run

```bash
python project.py
```

---

## 📁 Project Structure

```
ThreatHunter/
├── project.py           # Main application
├── vms.json             # Your VM config (ignored by git)
├── vms.example.json     # Safe example config (committed)
├── requirements.txt     # Python dependencies
└── README.md
```

---

## 🖥️ VirtualBox Networking Note

If your VM uses **NAT** (default VirtualBox setting), it won't be directly reachable from your host. Two options:

**Option A — Port Forwarding**
In VirtualBox: Settings → Network → Adapter 1 → Advanced → Port Forwarding

| Name | Protocol | Host IP | Host Port | Guest Port |
|------|----------|---------|-----------|------------|
| SSH | TCP | 127.0.0.1 | 2222 | 22 |

Then use `"host": "127.0.0.1"` and `"port": 2222` in `vms.json`.

**Option B — Host-Only Adapter (recommended)**
Add a second adapter set to **Host-Only** — the VM gets a real `192.168.x.x` IP reachable directly on port 22.

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
[LinkedIn](https://linkedin.com/in/george-samir976327) · [GitHub](https://github.com/George-Samir88)

---

## 📄 License

MIT License — free to use, modify, and distribute.
