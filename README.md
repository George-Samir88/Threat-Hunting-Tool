# ⚡ ThreatHunter — Multi-OS Threat Hunting Platform

A professional, dark-themed desktop GUI for automated threat hunting across **Linux** and **Windows** VMs via SSH. Built with Python, `customtkinter`, `matplotlib`, and `fabric`.

Supports both **Linux OpenSSH** and **Windows OpenSSH Server** with automatic OS detection, OS-specific check sets, and Splunk-inspired dashboards.

---

## 📸 Features

### 🖥️ Multi-OS Support
- **Automatic OS Detection** — detects Linux vs Windows automatically via SSH probes
- **Linux Hunt Checks** — 8 checks for SSH logs, sudo abuse, cron, packages, auditd, bash history
- **Windows Hunt Checks** — 9 checks for Event Logs, failed/successful logins, process creation, PowerShell execution, scheduled tasks, services, account creation
- **Cross-Platform SSH** — same SSH transport works for both Linux and Windows OpenSSH Server

### 🎨 Professional Dashboard (Splunk-Inspired)
- **3-Column Layout** — Sidebar Fleet | Main Dashboard | Details Panel
- **KPI Cards** — real-time severity counts (HIGH, MEDIUM, LOW, INFO)
- **Fleet Overview Chart** — stacked bar chart across all VMs
- **Event Timeline** — 24-hour stacked bar chart with severity color coding
- **Findings Table** — sortable table with VM, Check, Severity, Details
- **Severity Mini-Bar** — per-VM horizontal severity indicator on cards

### 🔍 Hunt Engine
- **Background Threading** — GUI never freezes during hunts
- **Progress Callbacks** — live progress updates per check
- **Auto Report Popup** — report window opens automatically on completion
- **Bulk Operations** — Test All, Hunt All, Save All with one click

### 🛡️ Security Checks

#### Linux Checks (8 checks)
| # | Check | Severity | Source |
|---|-------|----------|--------|
| 1 | SSH Brute Force (5+ failures from same IP) | HIGH / MEDIUM | `/var/log/auth.log` or `/var/log/secure` |
| 2 | Successful Login After Failures | HIGH | `/var/log/auth.log` or `/var/log/secure` |
| 3 | Sudo Abuse (non-admin users, auth failures) | HIGH | `/var/log/auth.log` or `/var/log/secure` |
| 4 | New User / Group Created | HIGH | `/var/log/auth.log` or `/var/log/secure` |
| 5 | Unexpected Cron Entries (off-hours / non-root) | MEDIUM | `/var/log/syslog`, `/var/log/cron`, cron spool |
| 6 | Unexpected Package Activity | MEDIUM | `/var/log/dpkg.log`, `/var/log/yum.log`, `dnf.log` |
| 7 | Auditd Privilege Escalation | HIGH | `/var/log/audit/audit.log` |
| 8 | Suspicious Bash History | HIGH | `~/.bash_history`, `~/.zsh_history` |

#### Windows Checks (9 checks)
| # | Check | Severity | Source |
|---|-------|----------|--------|
| 1 | List Available Event Logs | INFO | `Get-WinEvent -ListLog` |
| 2 | Read Recent Events (Critical/Error) | INFO | `System`, `Application` logs |
| 3 | Search for Failed Logins (Event ID 4625) | HIGH | `Security` log |
| 4 | Search for Successful Logins (Event ID 4624) | MEDIUM | `Security` log |
| 5 | Process Creation Events (Event ID 4688) | MEDIUM | `Security` log |
| 6 | PowerShell Execution Hunting (Event ID 4104) | HIGH | `PowerShell/Operational` |
| 7 | Hunt for Scheduled Tasks | HIGH | `Get-ScheduledTask` |
| 8 | Hunt for Service Installation (Event ID 7045) | HIGH | `System` log |
| 9 | Hunt for Account Creation (Event ID 4720/4732) | HIGH | `Security` log |

#### Utility Operations (Windows — Manual)
| # | Operation | Purpose |
|---|-----------|---------|
| 10 | Export Logs for Offline Analysis | Export `.evtx` files for SIEM analysis |
| 11 | Fast IOC Hunting | Sweep logs for threat intelligence indicators |
| 12 | Investigation One-Liner Bundle | Network connections, processes, prefetch, etc. |

---

## 📁 Project Structure

```
Final Project/
├── main.py                      # Entry point — launches the GUI
├── vms.json                     # VM connection config (do not commit)
├── vms.example.json             # Safe example config
├── requirements.txt             # Python dependencies
├── README.md                    # This file
├── gui/
│   ├── __init__.py
│   ├── app.py                   # Main window — 3-column dashboard layout
│   ├── vm_card.py               # VM card with severity mini-bar + OS badge
│   ├── report_panel.py          # Report popup — charts + findings
│   └── charts.py                # Matplotlib charts (donut, bar, timeline, fleet)
├── hunting/
│   ├── __init__.py
│   ├── engine.py                # Orchestrates checks — OS detection + branch
│   ├── checks.py                # Linux hunt checks (8 checks)
│   ├── windows_checks.py        # Windows hunt checks (9 checks + 3 utilities)
│   ├── os_detect.py             # Remote OS detection over SSH
│   └── models.py                # Finding + Report dataclasses
├── transport/
│   ├── __init__.py
│   └── ssh.py                   # Fabric SSH wrapper with Windows OpenSSH fixes
└── setup/
    ├── __init__.py
    └── setup_lab.py             # Lab environment setup (SSH keys + log injection)
```

---

## 🚀 Getting Started

### Prerequisites

- **Python 3.10+**
- **SSH access** to target VMs (Linux OpenSSH or Windows OpenSSH Server)
- **Windows VMs** — Windows 10/Server 2019+ with OpenSSH Server installed
- **Display** — GUI requires a desktop environment (Windows/Linux/macOS)

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
    "host": "192.168.1.7",
    "port": 22,
    "username": "georgesamir",
    "os_hint": "linux",
    "key_path": "~/.ssh/id_ed25519",
    "password": "your_password_here"
  },
  {
    "hostname": "windows-10-machine",
    "host": "192.168.1.9",
    "port": 22,
    "username": "smith",
    "os_hint": "windows",
    "key_path": null,
    "password": "your_password_here"
  }
]
```

| Field | Description | Required |
|-------|-------------|----------|
| `hostname` | Display name in the GUI | ✅ Yes |
| `host` | IP address or hostname | ✅ Yes |
| `port` | SSH port (default `22`) | ✅ Yes |
| `username` | SSH login username | ✅ Yes |
| `password` | SSH password (also used for sudo on Linux) | ✅ Yes |
| `key_path` | Path to private key — `null` for password-only | ❌ Optional |
| `os_hint` | `"linux"` or `"windows"` — cosmetic badge only | ❌ Optional |

> ⚠️ **`vms.json` is in `.gitignore`** — your credentials will never be committed.
>
> The `os_hint` field is **cosmetic only** — the engine always auto-detects the OS
> at runtime. It just shows a badge on the VM card before the first hunt.

---

## 🪟 Windows OpenSSH Server Setup

### Install OpenSSH Server on Windows

```powershell
# Check if OpenSSH Server is installed
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'

# Install if missing
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0

# Start and enable the service
Start-Service sshd
Set-Service -Name sshd -StartupType 'Automatic'

# Verify firewall rule
Get-NetFirewallRule -Name *ssh*
```

### Configure Password Authentication

Edit `C:\ProgramData\ssh\sshd_config` as Administrator:

```config
PasswordAuthentication yes
PubkeyAuthentication yes
Subsystem powershell C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

Restart the service:

```powershell
Restart-Service sshd
```

### Verify Connection

```bash
ssh smith@192.168.1.9
```

You should see:

```
Microsoft Windows [Version 10.0.19045.2965]
(c) Microsoft Corporation. All rights reserved.

smith@DESKTOP-G5U64LK C:\Users\smith>
```

---

## 🧪 Lab Setup (SSH Key + Log Injection)

Before hunting, run the setup script once to:
1. Generate an SSH keypair (if you don't have one)
2. Push your public key to the VM's `authorized_keys` using password auth
3. Inject realistic suspicious log entries across all log targets
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

> **On Kali Linux**, `auth.log` only gets populated if `rsyslog` is installed:
> ```bash
> sudo apt update && sudo apt install rsyslog -y
> sudo systemctl enable rsyslog --now
> ```
> Verify with `sudo tail /var/log/auth.log` before running a hunt.

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

### OS Detection Flow

```
SSH Connect
    │
    ▼
Run OS Detection Probes:
  1. `ver` (cmd.exe builtin)
  2. `uname -s` (POSIX)
  3. `echo %OS%` (Windows env)
  4. `echo $0` (POSIX shell)
  5. PowerShell version check
    │
    ▼
Classify OS → "linux" | "windows" | "unknown"
    │
    ▼
Select Check Set:
  Linux  → 8 Linux checks (checks.py)
  Windows → 9 Windows checks (windows_checks.py)
  Unknown → Report with error (no guessing)
```

### Windows Hunt Execution

```
SSH to Windows VM (cmd.exe default shell)
    │
    ▼
Wrap PowerShell commands:
  powershell -NoProfile -NonInteractive -Command "..."
    │
    ▼
Execute Windows-specific checks:
  - Get-WinEvent (Event IDs 4624, 4625, 4688, 7045, 4720, 4732)
  - Get-ScheduledTask
  - Get-Process
  - Get-NetTCPConnection
    │
    ▼
Parse JSON output via ConvertTo-Json
    │
    ▼
Return Finding objects (same model as Linux)
```

### Threading Model
- Each hunt runs in a background `threading.Thread` — the GUI never freezes
- Worker threads communicate with the main thread via `queue.Queue`
- The main window polls the queue every 100ms with `root.after(100, poll_queue)`
- **Tkinter is not thread-safe** — widgets are only updated from the main thread

### SSH Transport (Windows-Compatible)

```python
from transport.ssh import SSHTransport

ssh = SSHTransport(
    host="192.168.1.9",
    port=22,
    username="smith",
    password="1234",
    timeout=20,           # Connection timeout
    banner_timeout=45,   # Windows OpenSSH needs longer
)

ssh.connect(retries=2, retry_delay=3.0)
# Auto-retry with increasing banner_timeout on failure
```

**Key Windows fixes:**
- `banner_timeout` — Windows OpenSSH is slower to present SSH banner (default 30s)
- `look_for_keys=False` — prevents "Too many authentication failures"
- `allow_agent=False` — disables SSH agent when using password
- `auth_timeout` — separate from connection timeout
- `fetch_log_windows()` — PowerShell `Get-Content` instead of Linux `sudo cat`

### GUI Layout

```
┌─────────────────────────────────────────────────────────────────────┐
│  [Logo]  ThreatHunter v3.0                    [Status]     │  Header
├──────────┬────────────────────────────────────┬─────────────┤
│          │  [KPI Cards: VMs | Done | HIGH |   │             │
│  VM      │   MED | LOW | INFO ]              │  Event      │
│  Fleet   │                                    │  Timeline   │
│  List    │  [Fleet Overview Chart]            │  (Recent    │
│  (Sidebar│                                    │   Hunts)    │
│   340px) │  [Findings Table]                  │   320px     │
│          │                                    │             │
│          │                                    │             │
├──────────┴────────────────────────────────────┴─────────────┤
│  [Console Log]                                    [Clear]   │  Console
└─────────────────────────────────────────────────────────────┘
```

### Data Models

```python
@dataclass
class Finding:
    check_id: int
    check_name: str
    severity: str          # HIGH | MEDIUM | LOW | INFO
    description: str
    evidence: List[str]
    skipped: bool = False
    skip_reason: str = ""

@dataclass
class Report:
    vm: str
    host: str
    timestamp: str
    findings: List[Finding]
    error: Optional[str] = None
    os_type: str = "unknown"  # "linux" | "windows" | "unknown"
```

---

## 🎯 Hunt Check Details

### Linux Checks

#### Check 1: SSH Brute Force
- **Source**: `/var/log/auth.log` or `/var/log/secure`
- **Pattern**: 5+ failed password attempts from same IP
- **Severity**: HIGH for external IPs, MEDIUM for RFC1918 (internal)
- **Evidence**: IP address, attempt count, sample log lines

#### Check 2: Successful Login After Failures
- **Source**: `/var/log/auth.log` or `/var/log/secure`
- **Pattern**: 3+ failures followed by successful login from same IP
- **Severity**: HIGH (credential stuffing indicator)
- **Evidence**: IP, failure count, success line

#### Check 3: Sudo Abuse
- **Source**: `/var/log/auth.log` or `/var/log/secure`
- **Patterns**:
  - User NOT in sudoers
  - Sudo authentication failure
  - Sudo command from unexpected user
- **Severity**: HIGH
- **Evidence**: User, command, log line

#### Check 4: New User / Group Created
- **Source**: `/var/log/auth.log` or `/var/log/secure`
- **Commands**: `useradd`, `groupadd`, `usermod`
- **Severity**: HIGH
- **Evidence**: Full log lines

#### Check 5: Unexpected Cron Entries
- **Sources**: `/var/log/syslog`, `/var/log/cron`, `/var/spool/cron`
- **Patterns**:
  - Off-hours execution (00:00-05:00)
  - Non-root cron users
  - Suspicious commands in crontab
- **Severity**: MEDIUM
- **Evidence**: Crontab entries, off-hours lines

#### Check 6: Unexpected Package Activity
- **Sources**: `/var/log/dpkg.log`, `/var/log/yum.log`, `/var/log/dnf.log`
- **Pattern**: Install/remove/purge of non-baseline packages
- **Severity**: MEDIUM
- **Evidence**: Package name, action, log line

#### Check 7: Auditd Privilege Escalation
- **Source**: `/var/log/audit/audit.log`
- **Patterns**:
  - `sudo`/`su` execution (USER_AUTH, USER_CMD, USER_START)
  - Authentication failures
- **Severity**: HIGH
- **Evidence**: Audit log lines with context

#### Check 8: Suspicious Bash History
- **Sources**: `~/.bash_history`, `~/.zsh_history`
- **Patterns**:
  - `wget`/`curl` downloads
  - Netcat reverse shells
  - Base64 decoding
  - `/dev/tcp/` redirects
  - `chmod +x` on downloaded files
  - Python/Perl one-liners
- **Severity**: HIGH
- **Evidence**: Matching command lines

### Windows Checks

#### Check 1: List Available Event Logs
- **Command**: `Get-WinEvent -ListLog`
- **Purpose**: Enumerate available log channels and record counts
- **Alert**: Flags if Security log is disabled (defense evasion indicator)
- **Severity**: INFO (reconnaissance), HIGH if Security log disabled

#### Check 2: Read Recent Events
- **Logs**: `System`, `Application`
- **Filter**: Critical/Error events in last 24 hours
- **Severity**: INFO, MEDIUM if 10+ errors
- **Evidence**: Event time, level, provider, message

#### Check 3: Search for Failed Logins (Event ID 4625)
- **Log**: `Security`
- **Pattern**: 5+ failed logons from same source IP
- **Severity**: HIGH (brute force indicator)
- **Evidence**: Target user, source IP, failure reason, count

#### Check 4: Search for Successful Logins (Event ID 4624)
- **Log**: `Security`
- **Pattern**: Logon Type 10 (RDP) or 3 (Network) from non-baseline accounts
- **Severity**: MEDIUM
- **Evidence**: User, source IP, logon type, workstation

#### Check 5: Process Creation Events (Event ID 4688)
- **Log**: `Security` (requires "Audit Process Creation" policy)
- **Pattern**: LOLBins execution (certutil, mshta, regsvr32, rundll32, etc.)
- **Severity**: MEDIUM
- **Evidence**: Process name, parent process, command line

#### Check 6: PowerShell Execution Hunting (Event ID 4104)
- **Log**: `Microsoft-Windows-PowerShell/Operational`
- **Patterns**:
  - Encoded commands (`-enc`, `-encodedcommand`)
  - Profile bypass (`-nop`, `-noprofile`)
  - Hidden windows (`-w hidden`, `-windowstyle hidden`)
  - `IEX` / `Invoke-Expression`
  - `DownloadString` / `DownloadFile`
  - Obfuscation (`-bxor`, `FromBase64String`)
- **Severity**: HIGH
- **Evidence**: Script block snippet, timestamp

#### Check 7: Hunt for Scheduled Tasks
- **Command**: `Get-ScheduledTask`
- **Patterns**:
  - Non-Microsoft tasks with suspicious actions
  - Executables from temp/appdata directories
  - Encoded commands in task actions
- **Severity**: HIGH
- **Evidence**: Task name, author, action, markers

#### Check 8: Hunt for Service Installation (Event ID 7045)
- **Log**: `System`
- **Patterns**: New services with suspicious binary paths
- **Severity**: HIGH
- **Evidence**: Service name, image path, start type

#### Check 9: Hunt for Account Creation (Event ID 4720/4732)
- **Log**: `Security`
- **Patterns**:
  - New user accounts (4720)
  - Users added to privileged groups (4732/4728)
- **Severity**: HIGH
- **Evidence**: Account name, creator, group name

---

## 🎨 Dashboard Components

### VM Card (Sidebar)
```
┌────────────────────────────────────────┐
│ ●  Hostname              [LINUX] [Done]│
│ 192.168.1.7:22  ·  user  🔑           │
│                                        │
│ ● H:0  ● M:0  ● L:0  ● I:0           │
│                                        │
│ [🔗 Test] [🎯 Hunt] [📄 Report]        │
└────────────────────────────────────────┘
```

### KPI Cards (Main Dashboard)
```
┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐ ┌─────┐
│  2  │ │  1  │ │  6  │ │  2  │ │  0  │ │  0  │
│ VMs │ │Done │ │HIGH │ │ MED │ │ LOW │ │INFO │
└─────┘ └─────┘ └─────┘ └─────┘ └─────┘ └─────┘
```

### Findings Table
```
VM          Check                    Severity  Details
─────────────────────────────────────────────────────────
kali-lab    SSH Brute Force          HIGH      38 attempts
kali-lab    Suspicious History       HIGH      51 matches
win-10      Failed Logins            HIGH      5 attempts
win-10      Scheduled Tasks          HIGH      1 suspicious
```

### Event Timeline
- **X-axis**: Last 24 hours (all hours shown, including empty)
- **Y-axis**: Event count
- **Bars**: Stacked by severity (red=HIGH, amber=MEDIUM, green=LOW, blue=INFO)
- **Title**: Full date range (e.g., "Jun 19 17:00 - Jun 20 17:00")

---

## 🔧 Customization

### Baselines (Linux)

Edit `hunting/checks.py`:

```python
# Users allowed to run sudo without alerting
EXPECTED_SUDO_USERS = {"root", "georgesamir", "analyst", "admin"}

# Users allowed to have scheduled cron jobs
KNOWN_GOOD_CRON_USERS = {"root", "syslog", "cron"}

# Packages that should not trigger alerts
KNOWN_GOOD_PACKAGES = {
    "bash", "coreutils", "openssh-server", "sudo",
    "python3", "systemd", "apt", "dpkg", "vim",
    # ... add your environment-specific packages
}
```

### Baselines (Windows)

Edit `hunting/windows_checks.py`:

```python
# Users expected to log in (baseline accounts)
EXPECTED_LOGIN_USERS = {"Administrator", "georgesamir", "analyst", "SYSTEM", "smith"}

# Known-good scheduled task prefixes (to exclude from alerts)
KNOWN_GOOD_TASK_PREFIXES = (
    "\\microsoft\\windows\\",
    "\\microsoftedgeupdate",
    "\\onedrive",
)

# Living-off-the-land binaries to flag
LOLBINS = {
    "certutil.exe", "bitsadmin.exe", "mshta.exe",
    "regsvr32.exe", "rundll32.exe", "wmic.exe",
    # ... add/remove as needed
}
```

### PowerShell Patterns

```python
# Suspicious PowerShell execution patterns
SUSPICIOUS_PS_PATTERNS = {
    r"-enc(odedcommand)?\b": "Base64-encoded payload",
    r"-nop\b|-noprofile\b": "Profile bypass",
    r"IEX\s*\(|Invoke-Expression": "Dynamic execution",
    # ... add custom patterns
}
```

---

## 🐛 Troubleshooting

### Windows OpenSSH Connection Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| `timed out` | Banner timeout too short | Increase `banner_timeout` to 45-60s |
| `Too many authentication failures` | Paramiko tries all keys first | Set `look_for_keys=False` |
| `Authentication failed` | Password auth disabled | Enable `PasswordAuthentication yes` in `sshd_config` |
| `Connection refused` | sshd not running | `Start-Service sshd` |
| `blank output` | cmd.exe vs PowerShell | Use `powershell -Command` wrapper |

### Linux Connection Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| `auth.log not found` | rsyslog not installed | `sudo apt install rsyslog && sudo systemctl enable rsyslog --now` |
| `audit.log not found` | auditd not installed | `sudo apt install auditd && sudo systemctl enable auditd --now` |
| `Permission denied` | Key file permissions | `chmod 600 ~/.ssh/id_ed25519` |

### GUI Issues

| Symptom | Cause | Solution |
|---------|-------|----------|
| `ModuleNotFoundError: No module named 'gui'` | Missing `__init__.py` | Create `__init__.py` files in all subfolders |
| Charts not showing | Matplotlib backend | Ensure `matplotlib.use("TkAgg")` is set |
| Window too small | DPI scaling | Set `CTk` scaling: `ctk.set_widget_scaling(1.0)` |

---

## 🖥️ VirtualBox Networking

### Host-Only Adapter (Recommended)
Add Adapter 2 in VirtualBox → Network → Host-Only. The VM gets a `192.168.x.x` IP reachable directly on port 22.

### Port Forwarding (Alternative)

| Name | Protocol | Host IP | Host Port | Guest Port |
|------|----------|---------|-----------|------------|
| SSH | TCP | 127.0.0.1 | 2222 | 22 |

Then use `"host": "127.0.0.1"` and `"port": 2222` in `vms.json`.

---

## 📦 Dependencies

| Package | Version | Purpose |
|---------|---------|---------|
| `customtkinter` | ^5.2 | Modern dark-themed GUI framework |
| `matplotlib` | ^3.8 | Charts and visualizations |
| `fabric` | ^3.2 | SSH connections and remote execution |
| `paramiko` | ^3.4 | SSH protocol library (used by Fabric) |
| `invoke` | ^2.2 | Command execution layer (used by Fabric) |

---

## 👤 Author

**George Samir**
Cybersecurity Threat Hunting & Incident Response
NTI — Threat Hunting & Incident Response Track

[LinkedIn](https://linkedin.com/in/george-samir976327/) · [GitHub](https://github.com/George-Samir88)

---

## 📄 License

MIT License — free to use, modify, and distribute.
