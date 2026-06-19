"""
hunting/checks.py — Individual Linux hunt check functions.
Each check receives an SSHTransport and returns a Finding.
"""
import re
from collections import defaultdict
from datetime import datetime
from typing import List
from hunting.models import Finding
from transport.ssh import SSHTransport

# ─── Known-good baselines (customize for your environment) ────────────────────
EXPECTED_SUDO_USERS   = {"root", "georgesamir", "analyst", "admin"}
KNOWN_GOOD_CRON_USERS = {"root", "syslog", "cron"}
KNOWN_GOOD_PACKAGES   = {
    "bash", "coreutils", "openssh-server", "openssh-client",
    "sudo", "python3", "systemd", "apt", "dpkg", "vim", "curl", "wget",
    # system packages commonly installed during setup — extend as needed
    "rsyslog", "auditd", "libauparse0t64", "libauplugin1",
    "libestr0", "libfastjson4", "liblognorm5", "kali",
    "libc", "man", "libaudit", "libcap",
}

# Dict: regex pattern → human-readable label
SUSPICIOUS_HISTORY_PATTERNS = {
    r"wget\s+http":  "wget download",
    r"curl\s+http":  "curl download",
    r"\bnc\b.*-e":   "netcat reverse shell",
    r"\bncat\b":     "ncat usage",
    r"base64\s+-d":  "base64 decode",
    r"/dev/tcp/":    "bash TCP redirect",
    r"chmod\s+\+x":  "chmod +x",
    r"python\s+-c":  "python one-liner",
    r"perl\s+-e":    "perl one-liner",
    r"bash\s+-i":    "interactive bash",
}

RFC1918 = re.compile(
    r"^(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)$"
)

# Log file paths — primary + fallback (Debian/Kali first, RHEL/CentOS fallback)
AUTH_LOGS  = ["/var/log/auth.log",        "/var/log/secure"]
CRON_LOGS  = ["/var/log/cron",            "/var/log/syslog"]
PKG_LOGS   = ["/var/log/dpkg.log",        "/var/log/apt/history.log",
              "/var/log/yum.log",         "/var/log/dnf.log"]
AUDIT_LOGS = ["/var/log/audit/audit.log"]
HISTORY_PATHS = [
    "/home/georgesamir/.bash_history",
    "/home/georgesamir/.zsh_history",
    "/home/analyst/.bash_history",
    "/root/.bash_history",
    "/root/.zsh_history",
]

# Debian/Kali use /var/spool/cron/crontabs/, RHEL/CentOS use /var/spool/cron/
CRON_SPOOL_DIRS = ["/var/spool/cron/crontabs", "/var/spool/cron"]


def _fetch_first_available(ssh: SSHTransport, paths: list) -> tuple:
    """Try each path in order, return (path, content) for first readable one."""
    for path in paths:
        ok, content = ssh.fetch_log(path)
        if ok:
            return path, content
    return None, None


# ─── Check 1 — SSH Brute Force ────────────────────────────────────────────────
def check_ssh_brute_force(ssh: SSHTransport) -> Finding:
    path, content = _fetch_first_available(ssh, AUTH_LOGS)
    finding = Finding(
        check_id=1,
        check_name="SSH Brute Force",
        severity="HIGH",
        description="",
    )
    if not content:
        finding.skipped = True
        finding.skip_reason = f"Log not found: {AUTH_LOGS}"
        return finding
    pattern  = re.compile(r"Failed password.*?from\s+([\d\.]+)\s+port", re.IGNORECASE)
    failures = defaultdict(list)
    for line in content.splitlines():
        m = pattern.search(line)
        if m:
            failures[m.group(1)].append(line)
    evidence     = []
    max_severity = "LOW"
    for ip, lines in failures.items():
        if len(lines) >= 5:
            sev = "MEDIUM" if RFC1918.match(ip) else "HIGH"
            if sev == "HIGH":
                max_severity = "HIGH"
            elif max_severity != "HIGH":
                max_severity = "MEDIUM"
            evidence.append(f"[{sev}] {ip} — {len(lines)} failed attempts")
            evidence.extend(lines[:5])
            if len(lines) > 5:
                evidence.append(f"  ... ({len(lines) - 5} more lines)")
    finding.severity    = max_severity if evidence else "INFO"
    finding.description = (
        f"Brute force detected from "
        f"{len([ip for ip, l in failures.items() if len(l) >= 5])} IP(s). "
        f"Source: {path}"
        if evidence else
        f"No brute force patterns detected. Source: {path}"
    )
    finding.evidence = evidence
    return finding


# ─── Check 2 — Successful Login After Failures ────────────────────────────────
def check_login_after_failures(ssh: SSHTransport) -> Finding:
    path, content = _fetch_first_available(ssh, AUTH_LOGS)
    finding = Finding(
        check_id=2,
        check_name="Successful Login After Failures",
        severity="HIGH",
        description="",
    )
    if not content:
        finding.skipped = True
        finding.skip_reason = f"Log not found: {AUTH_LOGS}"
        return finding
    fail_pattern    = re.compile(r"Failed password.*?from\s+([\d\.]+)", re.IGNORECASE)
    success_pattern = re.compile(r"Accepted\s+\w+\s+for\s+\S+\s+from\s+([\d\.]+)", re.IGNORECASE)
    failures  = defaultdict(int)
    successes = {}
    for line in content.splitlines():
        m = fail_pattern.search(line)
        if m:
            failures[m.group(1)] += 1
        m = success_pattern.search(line)
        if m:
            successes[m.group(1)] = line
    evidence = []
    for ip, line in successes.items():
        if failures[ip] >= 3:
            evidence.append(f"IP {ip} had {failures[ip]} failures then succeeded:")
            evidence.append(f"  {line}")
    finding.description = (
        f"Credential stuffing indicator: {len(evidence) // 2} IP(s) succeeded after failures. "
        f"Source: {path}"
        if evidence else
        f"No success-after-failure patterns detected. Source: {path}"
    )
    finding.evidence = evidence
    return finding


# ─── Check 3 — Sudo Abuse ─────────────────────────────────────────────────────
def check_sudo_abuse(ssh: SSHTransport) -> Finding:
    path, content = _fetch_first_available(ssh, AUTH_LOGS)
    finding = Finding(
        check_id=3,
        check_name="Sudo Abuse",
        severity="HIGH",
        description="",
    )
    if not content:
        finding.skipped = True
        finding.skip_reason = f"Log not found: {AUTH_LOGS}"
        return finding
    evidence = []
    patterns = [
        # PID bracket is optional — logger-injected lines omit it.
        # Match "NOT in sudoers" regardless of whether COMMAND= is present —
        # some distros log the attempted command even on rejection.
        # False positives from embedded script text are blocked by requiring
        # the syslog tag to be exactly "sudo:" or "sudo[PID]:" at the start.
        (re.compile(r"\bsudo(?:\[\d+\])?:\s+(\S+)\s+:.*?NOT in sudoers", re.IGNORECASE),
         "User NOT in sudoers"),
        (re.compile(r"\bsudo(?:\[\d+\])?\b.*pam_unix.*authentication failure.*user=(\S+)", re.IGNORECASE),
         "Sudo auth failure"),
        (re.compile(r"\bsudo(?:\[\d+\])?:\s+(\S+)\s+:.*?COMMAND=(.*)", re.IGNORECASE),
         "Sudo command"),
    ]
    for line in content.splitlines():
        for pattern, label in patterns:
            m = pattern.search(line)
            if m:
                user = m.group(1) if m.lastindex >= 1 else "unknown"
                if label == "Sudo command" and user in EXPECTED_SUDO_USERS:
                    continue
                evidence.append(f"[{label}] user={user}")
                evidence.append(f"  {line.strip()}")
                break
    finding.description = (
        f"Sudo abuse detected: {len(evidence) // 2} event(s). Source: {path}"
        if evidence else
        f"No sudo abuse detected. Source: {path}"
    )
    finding.evidence = evidence
    return finding


# ─── Check 4 — New User / Group Created ──────────────────────────────────────
def check_user_group_creation(ssh: SSHTransport) -> Finding:
    path, content = _fetch_first_available(ssh, AUTH_LOGS)
    finding = Finding(
        check_id=4,
        check_name="New User / Group Created",
        severity="HIGH",
        description="",
    )
    if not content:
        finding.skipped = True
        finding.skip_reason = f"Log not found: {AUTH_LOGS}"
        return finding
    # PID bracket is optional — logger-injected lines omit it
    pattern  = re.compile(r"\b(useradd|groupadd|usermod)(?:\[\d+\])?:", re.IGNORECASE)
    evidence = [line.strip() for line in content.splitlines() if pattern.search(line)]
    finding.description = (
        f"Account manipulation detected: {len(evidence)} event(s). Source: {path}"
        if evidence else
        f"No account manipulation detected. Source: {path}"
    )
    finding.evidence = evidence
    return finding


# ─── Check 5 — Unexpected Cron Entries ───────────────────────────────────────
def check_suspicious_cron(ssh: SSHTransport) -> Finding:
    path, content = _fetch_first_available(ssh, CRON_LOGS)
    finding = Finding(
        check_id=5,
        check_name="Unexpected Cron Entries",
        severity="MEDIUM",
        description="",
    )
    spool_evidence = []
    spool_dir      = None
    users          = None
    try:
        for candidate in CRON_SPOOL_DIRS:
            # run_sudo uses Fabric's sudo runner with pty=True — password coerced to str
            ok, out = ssh.run_sudo(f"ls -1 {candidate}")
            if ok and out and out.strip():
                spool_dir = candidate
                users     = out
                break
        if spool_dir and users:
            for user in users.splitlines():
                user = user.strip()
                if not user:
                    continue
                cron_path = f"{spool_dir}/{user}"
                # crontab -l is the only reliable way to read crontab files
                # (-rw------- perms block even root via cat)
                ok, spool = ssh.run_sudo(f"crontab -u {user} -l")
                if not ok or not spool:
                    continue
                for line in spool.splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        spool_evidence.append(f"[crontab:{user}] {line}")
    except Exception:
        pass
    if not content and not spool_evidence:
        finding.skipped = True
        finding.skip_reason = "No cron logs or spool entries found"
        return finding
    evidence = []
    if content:
        off_hours = re.compile(r"\s(0[0-5]):\d{2}:\d{2}\s")
        non_root  = re.compile(r"CROND.*?\((?!root|syslog|cron)(\S+)\)\s+CMD")
        for line in content.splitlines():
            if off_hours.search(line) and "CROND" in line:
                evidence.append(f"[off-hours cron] {line.strip()}")
            elif non_root.search(line):
                m    = non_root.search(line)
                user = m.group(1) if m else "unknown"
                if user not in KNOWN_GOOD_CRON_USERS:
                    evidence.append(f"[non-root cron user={user}] {line.strip()}")
    evidence.extend(spool_evidence)
    finding.description = (
        f"Suspicious cron activity: {len(evidence)} event(s). "
        f"Source: {path or spool_dir or 'spool'}"
        if evidence else
        f"No suspicious cron activity. Source: {path or 'N/A'}"
    )
    finding.evidence = evidence
    return finding


# ─── Check 6 — Unexpected Package Activity ───────────────────────────────────
def check_package_activity(ssh: SSHTransport) -> Finding:
    path, content = _fetch_first_available(ssh, PKG_LOGS)
    finding = Finding(
        check_id=6,
        check_name="Unexpected Package Activity",
        severity="MEDIUM",
        description="",
    )
    if not content:
        finding.skipped = True
        finding.skip_reason = f"Log not found: {PKG_LOGS}"
        return finding
    # Match only explicit install/remove/purge actions — ignore status lines
    # dpkg.log format: "YYYY-MM-DD HH:MM:SS install|remove|purge pkg:arch old new"
    # yum.log format:  "MMM DD HH:MM:SS install|remove|purge pkg"
    install_pattern = re.compile(
        r"^(?:\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}|\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(install|remove|purge)\s+([\w\-\.]+)",
        re.IGNORECASE,
    )
    evidence = []
    for line in content.splitlines():
        m = install_pattern.match(line)
        if m:
            action  = m.group(1).lower()
            package = m.group(2).lower().split(":")[0].split("-")[0]
            base = re.split(r"[-_]\d", package)[0]
            if base not in KNOWN_GOOD_PACKAGES:
                evidence.append(f"[{action.upper()}] {line.strip()}")
    finding.description = (
        f"Unexpected package activity: {len(evidence)} event(s). Source: {path}"
        if evidence else
        f"No unexpected package activity. Source: {path}"
    )
    finding.evidence = evidence
    return finding


# ─── Check 7 — Auditd Privilege Escalation ───────────────────────────────────
def check_auditd_privesc(ssh: SSHTransport) -> Finding:
    path, content = _fetch_first_available(ssh, AUDIT_LOGS)
    finding = Finding(
        check_id=7,
        check_name="Auditd Privilege Escalation",
        severity="HIGH",
        description="",
    )
    if not content:
        finding.skipped = True
        finding.skip_reason = (
            "audit.log not found or auditd not running — "
            "install with: sudo apt install auditd && sudo systemctl enable auditd --now"
        )
        return finding
    sudo_su_pattern = re.compile(
        r'type=(USER_AUTH|USER_CMD|USER_START).*exe="/usr/bin/(sudo|su)".*(res=success|res=failed)',
        re.IGNORECASE,
    )
    userauth_pattern = re.compile(r"type=USER_AUTH.*res=failed", re.IGNORECASE)
    evidence = []
    for line in content.splitlines():
        if sudo_su_pattern.search(line):
            evidence.append(f"[PRIVESC] {line.strip()}")
        elif userauth_pattern.search(line):
            evidence.append(f"[AUTH failure] {line.strip()}")
    finding.description = (
        f"Privilege escalation via auditd: {len(evidence)} event(s). Source: {path}"
        if evidence else
        f"No auditd escalation events. Source: {path}"
    )
    finding.evidence = evidence
    return finding


# ─── Check 8 — Suspicious Command History ────────────────────────────────────
def check_bash_history(ssh: SSHTransport) -> Finding:
    finding = Finding(
        check_id=8,
        check_name="Suspicious Command History",
        severity="HIGH",
        description="",
    )
    path, content = _fetch_first_available(ssh, HISTORY_PATHS)
    if path is None:
        finding.skipped = True
        finding.skip_reason = "No history file readable"
        return finding
    if not content:
        finding.description = f"History file readable but empty. Source: {path}"
        return finding
    compiled = [
        (re.compile(pattern, re.IGNORECASE), label)
        for pattern, label in SUSPICIOUS_HISTORY_PATTERNS.items()
    ]
    evidence = []
    for line in content.splitlines():
        line = line.strip()
        if not line:
            continue
        for regex, label in compiled:
            if regex.search(line):
                evidence.append(f"[{label}]  {line}")
                break
    finding.description = (
        f"Suspicious commands in history: {len(evidence)} match(es). Source: {path}"
        if evidence else
        f"No suspicious history entries. Source: {path}"
    )
    finding.evidence = evidence
    return finding


# ─── Registry ─────────────────────────────────────────────────────────────────
ALL_CHECKS = [
    check_ssh_brute_force,
    check_login_after_failures,
    check_sudo_abuse,
    check_user_group_creation,
    check_suspicious_cron,
    check_package_activity,
    check_auditd_privesc,
    check_bash_history,
]