"""
hunting/windows_checks.py — Windows Event Log hunt operations.

All checks run PowerShell over the existing SSH transport (Windows OpenSSH
Server defaults to cmd.exe, so every command is wrapped as:
  powershell -NoProfile -NonInteractive -Command "..."
). No WinRM, no extra dependencies — same SSHTransport used for Linux.

Each function takes an SSHTransport and returns a Finding, matching the
exact same model used by hunting/checks.py (Linux side), so the report
panel, charts, and severity scoring work identically for both OS types.
"""

import json
import re
from collections import defaultdict
from datetime import datetime
from typing import List, Optional
from hunting.models import Finding
from transport.ssh import SSHTransport

# ─── Known-good baselines — customize for your environment ────────────────────
EXPECTED_LOGIN_USERS = {"Administrator", "georgesamir", "analyst", "SYSTEM"}
SUSPICIOUS_PS_PATTERNS = {
    r"-enc(odedcommand)?\b":        "Base64-encoded PowerShell payload",
    r"-nop\b|-noprofile\b":         "Profile bypass (common in malicious scripts)",
    r"-w\s+hidden|-windowstyle\s+hidden": "Hidden window execution",
    r"IEX\s*\(|Invoke-Expression":  "Dynamic code execution (IEX)",
    r"DownloadString|DownloadFile": "Remote payload download",
    r"-bxor|FromBase64String":      "Obfuscation / decoding routine",
    r"Net\.WebClient":              "Outbound web request via .NET",
    r"bypass\b":                    "Execution policy bypass",
}

RUNSPACE_TIMEOUT = 25  # PowerShell cold-start is slower than a plain shell cmd


# ─── PowerShell execution helpers ───────────────────────────────────────────

def _run_ps(ssh: SSHTransport, script: str, timeout: int = RUNSPACE_TIMEOUT):
    """
    Execute a PowerShell snippet over the SSH session and return (ok, stdout).
    Wraps the script so embedded double quotes survive the cmd.exe -> SSH ->
    PowerShell quoting chain. Output is requested as compact JSON wherever
    structured data is needed, since parsing PowerShell's default table
    output with regex is fragile across locales/widths.
    """
    # Escape double quotes for the outer cmd.exe-style invocation
    escaped = script.replace('"', '\\"')
    cmd = f'powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "{escaped}"'
    return ssh.run_command(cmd, timeout=timeout)


def _run_ps_json(ssh: SSHTransport, script: str, timeout: int = RUNSPACE_TIMEOUT):
    """
    Same as _run_ps, but appends ` | ConvertTo-Json -Depth 4` and parses the
    result. Returns (ok, parsed_object_or_None, raw_stdout).
    """
    ok, out = _run_ps(ssh, f"{script} | ConvertTo-Json -Depth 4 -Compress")
    if not ok or not out.strip():
        return ok, None, out
    try:
        parsed = json.loads(out)
        # PowerShell returns a single dict for 1-item results; normalize to list
        if isinstance(parsed, dict):
            parsed = [parsed]
        return ok, parsed, out
    except (json.JSONDecodeError, ValueError):
        return ok, None, out


# ─── Check 1 — List Available Event Logs ──────────────────────────────────────
def check_list_event_logs(ssh: SSHTransport) -> Finding:
    """
    Enumerates registered Windows Event Log channels and their record counts.
    This is primarily a reconnaissance/context check — it tells the analyst
    which logs actually have data worth hunting through, and flags if core
    security logging is disabled (a common defense-evasion indicator).
    """
    finding = Finding(
        check_id=1,
        check_name="List Available Event Logs",
        severity="INFO",
        description="",
    )

    ok, parsed, raw = _run_ps_json(
        ssh,
        "Get-WinEvent -ListLog * -ErrorAction SilentlyContinue | "
        "Where-Object {$_.RecordCount -gt 0} | "
        "Sort-Object -Property RecordCount -Descending | "
        "Select-Object -First 25 LogName, RecordCount, IsEnabled"
    )

    if not ok or parsed is None:
        finding.skipped = True
        finding.skip_reason = "Get-WinEvent unavailable or returned no data — verify PowerShell access and log service status"
        return finding

    evidence = []
    security_log_found = False
    security_log_disabled = False

    for entry in parsed:
        name    = entry.get("LogName", "Unknown")
        count   = entry.get("RecordCount", 0)
        enabled = entry.get("IsEnabled", True)
        evidence.append(f"[{name}] {count} records, enabled={enabled}")
        if name.lower() == "security":
            security_log_found = True
            if not enabled:
                security_log_disabled = True

    # Flag if Security log is disabled — strong defense-evasion signal
    if security_log_disabled:
        finding.severity = "HIGH"
        evidence.insert(0, "[ALERT] Security event log is DISABLED — possible audit tampering")
    elif not security_log_found:
        finding.severity = "MEDIUM"
        evidence.insert(0, "[WARNING] Security log channel not found in enumeration")

    finding.description = (
        f"Enumerated {len(parsed)} active event log channel(s)."
        + (" Security log disabled — investigate immediately." if security_log_disabled else "")
    )
    finding.evidence = evidence
    return finding


# ─── Check 2 — Read Recent Events ─────────────────────────────────────────────
def check_recent_events(ssh: SSHTransport, hours: int = 24) -> Finding:
    """
    Pulls the most recent System + Application + Security events as a
    general activity snapshot. Flags unusually high event volume (possible
    log flooding to bury malicious activity) and any Critical/Error level
    entries from the System log (possible service crashes from tampering).
    """
    finding = Finding(
        check_id=2,
        check_name="Read Recent Events",
        severity="INFO",
        description="",
    )

    script = (
        f"$cutoff = (Get-Date).AddHours(-{hours}); "
        "Get-WinEvent -FilterHashtable @{LogName='System','Application'; "
        "StartTime=$cutoff} -ErrorAction SilentlyContinue -MaxEvents 200 | "
        "Where-Object {$_.LevelDisplayName -in @('Critical','Error')} | "
        "Select-Object -First 20 TimeCreated, LevelDisplayName, ProviderName, Id, "
        "@{N='Msg';E={$_.Message.Substring(0,[Math]::Min(120,$_.Message.Length))}}"
    )

    ok, parsed, raw = _run_ps_json(ssh, script)

    if not ok:
        finding.skipped = True
        finding.skip_reason = "Failed to query System/Application logs"
        return finding

    if parsed is None:
        finding.description = f"No Critical/Error events in System or Application logs (last {hours}h)."
        return finding

    evidence = []
    for e in parsed:
        ts  = e.get("TimeCreated", "")
        lvl = e.get("LevelDisplayName", "")
        src = e.get("ProviderName", "")
        eid = e.get("Id", "")
        msg = e.get("Msg", "")
        evidence.append(f"[{ts}] {lvl} | {src} (EventID {eid}) — {msg}")

    if len(evidence) >= 10:
        finding.severity = "MEDIUM"
    finding.description = f"{len(evidence)} Critical/Error event(s) in System/Application logs over the last {hours}h."
    finding.evidence = evidence
    return finding


# ─── Check 3 — Search for Failed Logins (Event ID 4625) ──────────────────────
def check_failed_logins(ssh: SSHTransport, hours: int = 24) -> Finding:
    """
    Hunts Security log Event ID 4625 (failed logon). Groups by source IP /
    target account to surface brute-force patterns, mirroring the Linux
    SSH-brute-force check's logic but using Windows logon failure semantics.
    """
    finding = Finding(
        check_id=3,
        check_name="Search for Failed Logins",
        severity="HIGH",
        description="",
    )

    # Event ID 4625 properties: [0]=SubjectUserSid, [1]=SubjectUserName, [2]=SubjectDomainName,
    # [3]=SubjectLogonId, [4]=TargetUserSid, [5]=TargetUserName, [6]=TargetDomainName,
    # [7]=TargetLogonId, [8]=LogonType, [9]=FailureReason, [10]=Status, [11]=SubStatus,
    # [12]=LogonProcessName, [13]=AuthenticationPackageName, [14]=WorkstationName,
    # [15]=TransmittedServices, [16]=LmPackageName, [17]=KeyLength, [18]=ProcessId,
    # [19]=ProcessName, [20]=IpAddress, [21]=IpPort
    script = (
        f"$cutoff = (Get-Date).AddHours(-{hours}); "
        "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4625; "
        "StartTime=$cutoff} -ErrorAction SilentlyContinue -MaxEvents 500 | "
        "ForEach-Object { "
        "$x = $_.Properties; "
        "[PSCustomObject]@{ "
        "Time=$_.TimeCreated; "
        "TargetUser=$x[5].Value; "
        "SourceIP=$x[20].Value; "
        "FailureReason=$x[9].Value; "
        "LogonType=$x[8].Value; "
        "SubStatus=$x[11].Value "
        "} } | Select-Object -First 100"
    )

    ok, parsed, raw = _run_ps_json(ssh, script)

    if not ok:
        finding.skipped = True
        finding.skip_reason = "Security log query failed — may require elevated session or auditing not enabled for logon failures"
        return finding

    if parsed is None:
        finding.description = f"No failed logon events (4625) in the last {hours}h."
        return finding

    by_ip   = defaultdict(list)
    by_user = defaultdict(list)

    for e in parsed:
        ip   = e.get("SourceIP") or "unknown"
        user = e.get("TargetUser") or "unknown"
        line = f"[{e.get('Time','')}] target={user} source={ip} reason={e.get('FailureReason','')} substatus={e.get('SubStatus','')}"
        by_ip[ip].append(line)
        by_user[user].append(line)

    evidence     = []
    max_severity = "LOW"

    for ip, lines in by_ip.items():
        if ip == "unknown" or ip == "-" or ip == "::1" or ip == "127.0.0.1":
            continue
        if len(lines) >= 5:
            max_severity = "HIGH"
            evidence.append(f"[BRUTE FORCE] {ip} — {len(lines)} failed attempts")
            evidence.extend(lines[:5])
            if len(lines) > 5:
                evidence.append(f"  ... ({len(lines)-5} more)")

    for user, lines in by_user.items():
        if len(lines) >= 5 and user not in ("unknown", "-") and not user.endswith("$"):
            if max_severity != "HIGH":
                max_severity = "MEDIUM"
            evidence.append(f"[TARGETED ACCOUNT] {user} — {len(lines)} failures")

    finding.severity    = max_severity if evidence else "INFO"
    finding.description = (
        f"Failed logon brute-force pattern detected across {len(by_ip)} source IP(s)."
        if evidence else
        f"{len(parsed)} failed logon event(s) found, no brute-force pattern (threshold: 5+ from one source)."
    )
    finding.evidence = evidence or [f"{len(parsed)} total failed logons, below alert threshold"]
    return finding


# ─── Check 4 — Search for Successful Logins (Event ID 4624) ──────────────────
def check_successful_logins(ssh: SSHTransport, hours: int = 24) -> Finding:
    """
    Hunts Security log Event ID 4624 (successful logon), cross-referenced
    against Check 3's failure data conceptually (same pattern as the Linux
    "login after failures" check) — flags logon Type 10 (RDP) and Type 3
    (network) from non-baseline accounts as worth a second look.
    """
    finding = Finding(
        check_id=4,
        check_name="Search for Successful Logins",
        severity="MEDIUM",
        description="",
    )

    # Event ID 4624 properties: [0]=SubjectUserSid, [1]=SubjectUserName, [2]=SubjectDomainName,
    # [3]=SubjectLogonId, [4]=TargetUserSid, [5]=TargetUserName, [6]=TargetDomainName,
    # [7]=TargetLogonId, [8]=LogonType, [9]=LogonProcessName, [10]=AuthenticationPackageName,
    # [11]=WorkstationName, [12]=LogonGuid, [13]=TransmittedServices, [14]=LmPackageName,
    # [15]=KeyLength, [16]=ProcessId, [17]=ProcessName, [18]=IpAddress, [19]=IpPort,
    # [20]=ImpersonationLevel, [21]=RestrictedAdminMode, [22]=TargetOutboundUserName,
    # [23]=TargetOutboundDomainName, [24]=VirtualAccount, [25]=TargetLinkedLogonId, [26]=ElevatedToken
    script = (
        f"$cutoff = (Get-Date).AddHours(-{hours}); "
        "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4624; "
        "StartTime=$cutoff} -ErrorAction SilentlyContinue -MaxEvents 300 | "
        "ForEach-Object { "
        "$x = $_.Properties; "
        "[PSCustomObject]@{ "
        "Time=$_.TimeCreated; "
        "TargetUser=$x[5].Value; "
        "SourceIP=$x[18].Value; "
        "LogonType=$x[8].Value; "
        "WorkstationName=$x[11].Value "
        "} } | Where-Object {$_.TargetUser -notlike '*$'} | "
        "Select-Object -First 100"
    )

    ok, parsed, raw = _run_ps_json(ssh, script)

    if not ok:
        finding.skipped = True
        finding.skip_reason = "Security log query failed for successful logons"
        return finding

    if parsed is None:
        finding.description = f"No successful logon events (4624) in the last {hours}h."
        return finding

    # Logon Type reference: 2=Interactive, 3=Network, 7=Unlock, 10=RemoteInteractive(RDP)
    INTERESTING_TYPES = {"10": "RDP/Remote Desktop", "3": "Network logon"}

    evidence = []
    for e in parsed:
        user = e.get("TargetUser") or "unknown"
        ip   = e.get("SourceIP") or "-"
        ltype = str(e.get("LogonType") or "")
        ws   = e.get("WorkstationName") or "-"
        if user not in EXPECTED_LOGIN_USERS and ltype in INTERESTING_TYPES:
            evidence.append(
                f"[{e.get('Time','')}] user={user} source={ip} workstation={ws} "
                f"type={INTERESTING_TYPES[ltype]} (non-baseline account)")

    finding.description = (
        f"{len(evidence)} successful logon(s) from non-baseline accounts via RDP/network. Source: Security log (4624)"
        if evidence else
        f"{len(parsed)} successful logon(s) reviewed, all from expected accounts/logon types."
    )
    finding.evidence = evidence
    if not evidence:
        finding.severity = "INFO"
    return finding


# ─── Check 5 — Search for Process Creation Events (Event ID 4688) ────────────
def check_process_creation(ssh: SSHTransport, hours: int = 24) -> Finding:
    """
    Hunts Security log Event ID 4688 (process creation — requires "Audit
    Process Creation" policy enabled with command-line logging). Flags
    processes spawned from suspicious parent/child pairs and known
    LOLBins (living-off-the-land binaries) commonly abused for execution.
    """
    finding = Finding(
        check_id=5,
        check_name="Process Creation Events",
        severity="MEDIUM",
        description="",
    )

    LOLBINS = {
        "certutil.exe", "bitsadmin.exe", "mshta.exe", "regsvr32.exe",
        "rundll32.exe", "wmic.exe", "cscript.exe", "wscript.exe",
        "psexec.exe", "at.exe",
    }

    # Event ID 4688 properties: [0]=SubjectUserSid, [1]=SubjectUserName, [2]=SubjectDomainName,
    # [3]=SubjectLogonId, [4]=NewProcessId, [5]=NewProcessName, [6]=TokenElevationType,
    # [7]=ProcessId, [8]=CommandLine, [9]=TargetUserSid, [10]=TargetUserName,
    # [11]=TargetDomainName, [12]=TargetLogonId, [13]=ParentProcessId, [14]=ParentProcessName
    script = (
        f"$cutoff = (Get-Date).AddHours(-{hours}); "
        "Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688; "
        "StartTime=$cutoff} -ErrorAction SilentlyContinue -MaxEvents 300 | "
        "ForEach-Object { "
        "$x = $_.Properties; "
        "[PSCustomObject]@{ "
        "Time=$_.TimeCreated; "
        "NewProcess=$x[5].Value; "
        "ParentProcess=$x[14].Value; "
        "CommandLine=$x[8].Value; "
        "SubjectUser=$x[1].Value "
        "} } | Select-Object -First 150"
    )

    ok, parsed, raw = _run_ps_json(ssh, script)

    if not ok:
        finding.skipped = True
        finding.skip_reason = (
            "Security log query failed for 4688 — process creation auditing "
            "may not be enabled (gpedit: Audit Process Creation + "
            "'Include command line in process creation events')"
        )
        return finding

    if parsed is None:
        finding.description = f"No process creation events (4688) in the last {hours}h — auditing may be disabled."
        finding.severity = "INFO"
        return finding

    evidence = []
    for e in parsed:
        new_proc    = (e.get("NewProcess") or "").split("\\")[-1].lower()
        parent_proc = (e.get("ParentProcess") or "").split("\\")[-1]
        cmdline     = e.get("CommandLine") or ""
        subject     = e.get("SubjectUser") or "?"
        if new_proc in LOLBINS:
            evidence.append(
                f"[LOLBin] {e.get('Time','')} user={subject} parent={parent_proc} -> {new_proc}  cmd={cmdline[:100]}")

    finding.description = (
        f"{len(evidence)} living-off-the-land binary execution(s) detected among {len(parsed)} process creation events."
        if evidence else
        f"{len(parsed)} process creation event(s) reviewed, no known LOLBins observed."
    )
    finding.evidence = evidence
    if not evidence:
        finding.severity = "INFO"
    return finding


# ─── Check 6 — Look for PowerShell Execution ──────────────────────────────────
def check_powershell_execution(ssh: SSHTransport, hours: int = 24) -> Finding:
    """
    Hunts PowerShell's own operational log (Event ID 4104 — Script Block
    Logging) for obfuscation/evasion patterns: encoded commands, IEX,
    download cradles, hidden windows, execution policy bypass. This is
    the single highest-value Windows hunt check — most post-exploitation
    tooling (Empire, Cobalt Strike, Mimikatz wrappers) is delivered via
    PowerShell one-liners that show up here even when AV is silent.
    """
    finding = Finding(
        check_id=6,
        check_name="PowerShell Execution Hunting",
        severity="HIGH",
        description="",
    )

    script = (
        f"$cutoff = (Get-Date).AddHours(-{hours}); "
        "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; "
        "Id=4104; StartTime=$cutoff} -ErrorAction SilentlyContinue -MaxEvents 300 | "
        "Select-Object -First 150 TimeCreated, "
        "@{N='ScriptBlock';E={$_.Message}}"
    )

    ok, parsed, raw = _run_ps_json(ssh, script)

    if not ok:
        finding.skipped = True
        finding.skip_reason = (
            "PowerShell Operational log query failed — Script Block Logging "
            "may not be enabled (gpedit: Turn on PowerShell Script Block Logging)"
        )
        return finding

    if parsed is None:
        finding.description = f"No PowerShell script block events in the last {hours}h, or logging is disabled."
        finding.severity = "INFO"
        return finding

    compiled = [(re.compile(p, re.IGNORECASE), label)
                for p, label in SUSPICIOUS_PS_PATTERNS.items()]

    evidence = []
    for e in parsed:
        ts    = e.get("TimeCreated", "")
        block = e.get("ScriptBlock", "") or ""
        for regex, label in compiled:
            if regex.search(block):
                snippet = block.strip().replace("\n", " ")[:140]
                evidence.append(f"[{label}] {ts} — {snippet}")
                break

    finding.description = (
        f"{len(evidence)} suspicious PowerShell script block(s) detected among {len(parsed)} logged executions."
        if evidence else
        f"{len(parsed)} PowerShell script block(s) reviewed, no known evasion patterns matched."
    )
    finding.evidence = evidence
    if not evidence:
        finding.severity = "INFO"
    return finding


# ════════════════════════════════════════════════════════════════════════════
# Checks 7-12: Persistence, Account Management, Log Export, IOC Hunting,
# and Investigation One-Liners
# ════════════════════════════════════════════════════════════════════════════

# ─── Check 7 — Hunt for Scheduled Tasks ───────────────────────────────────────
def check_scheduled_tasks(ssh: SSHTransport) -> Finding:
    """
    Enumerates all scheduled tasks and flags ones created/modified recently
    or pointing at suspicious actions (scripts, encoded commands, temp paths,
    LOLBins). Scheduled tasks are one of the most common Windows persistence
    mechanisms — equivalent in importance to the Linux cron check.
    """
    finding = Finding(
        check_id=7,
        check_name="Hunt for Scheduled Tasks",
        severity="MEDIUM",
        description="",
    )

    KNOWN_GOOD_TASK_PREFIXES = (
        "\\microsoft\\windows\\",  # built-in OS maintenance tasks
        "\\microsoftedgeupdate",  # Add this
        "\\onedrive",             # Add this
    )
    # Check 8: Service Installation — whitelist Microsoft services
    KNOWN_GOOD_SERVICES = (
    "Microsoft Update Health Service",
    "Windows Update",
    "Windows Defender",
    )
    SUSPICIOUS_ACTION_MARKERS = (
        "powershell", "cmd.exe", "wscript", "cscript", "mshta",
        "regsvr32", "rundll32", "\\temp\\", "\\appdata\\", "-enc",
        "downloadstring", "iex ",
    )

    script = (
        "Get-ScheduledTask | ForEach-Object { "
        "$t = $_; $a = (Get-ScheduledTaskInfo -TaskName $t.TaskName -TaskPath $t.TaskPath "
        "-ErrorAction SilentlyContinue); "
        "$actions = ($t.Actions | ForEach-Object { \"$($_.Execute) $($_.Arguments)\" }) -join ' ; '; "
        "[PSCustomObject]@{ "
        "Name=$t.TaskName; Path=$t.TaskPath; State=$t.State; "
        "Author=$t.Author; LastRun=$a.LastRunTime; "
        "NextRun=$a.NextRunTime; Actions=$actions "
        "} } | Select-Object -First 200"
    )

    ok, parsed, raw = _run_ps_json(ssh, script)

    if not ok:
        finding.skipped = True
        finding.skip_reason = "Get-ScheduledTask query failed — Task Scheduler service may be unavailable"
        return finding

    if parsed is None:
        finding.description = "No scheduled tasks returned (unexpected on a normal Windows install)."
        finding.severity = "INFO"
        return finding

    evidence = []
    for t in parsed:
        path    = (t.get("Path") or "").lower()
        actions = (t.get("Actions") or "").lower()
        name    = t.get("Path", "") + t.get("Name", "")

        is_builtin = any(path.startswith(p) for p in KNOWN_GOOD_TASK_PREFIXES)
        if is_builtin:
            continue

        hits = [m for m in SUSPICIOUS_ACTION_MARKERS if m in actions]
        if hits:
            evidence.append(
                f"[SUSPICIOUS] {name}  author={t.get('Author','?')}  "
                f"state={t.get('State','?')}  markers={','.join(hits)}  "
                f"action={t.get('Actions','')[:120]}")
        elif not is_builtin:
            # Non-builtin task with no suspicious markers — log at lower priority
            evidence.append(
                f"[non-builtin] {name}  author={t.get('Author','?')}  state={t.get('State','?')}")

    suspicious_count = sum(1 for e in evidence if e.startswith("[SUSPICIOUS]"))
    if suspicious_count > 0:
        finding.severity = "HIGH"
    elif evidence:
        finding.severity = "LOW"
    else:
        finding.severity = "INFO"

    finding.description = (
        f"{suspicious_count} suspicious scheduled task(s) found among {len(parsed)} total tasks."
        if suspicious_count else
        f"{len(parsed)} scheduled task(s) reviewed, {len(evidence)} non-builtin, none flagged as suspicious."
    )
    finding.evidence = evidence
    return finding


# ─── Check 8 — Hunt for Service Installation ──────────────────────────────────
def check_service_installation(ssh: SSHTransport, hours: int = 24) -> Finding:
    """
    Hunts Event ID 7045 (a new service was installed on the system) from the
    System log, and cross-checks currently running services with unusual
    binary paths (temp dirs, user profile dirs, unsigned-looking paths).
    Service installation is a classic technique for both persistence and
    privilege escalation (SYSTEM-level service execution).
    """
    finding = Finding(
        check_id=8,
        check_name="Hunt for Service Installation",
        severity="HIGH",
        description="",
    )

    SUSPICIOUS_PATH_MARKERS = ("\\temp\\", "\\appdata\\", "\\downloads\\",
                               "\\users\\public\\", "\\programdata\\")

    # Event ID 7045 properties: [0]=ServiceName, [1]=ImagePath, [2]=ServiceType, [3]=StartType, [4]=Account
    script = (
        f"$cutoff = (Get-Date).AddHours(-{hours}); "
        "Get-WinEvent -FilterHashtable @{LogName='System'; Id=7045; "
        "StartTime=$cutoff} -ErrorAction SilentlyContinue -MaxEvents 200 | "
        "ForEach-Object { "
        "$x = $_.Properties; "
        "[PSCustomObject]@{ "
        "Time=$_.TimeCreated; "
        "ServiceName=$x[0].Value; "
        "ImagePath=$x[1].Value; "
        "StartType=$x[3].Value; "
        "Account=$x[4].Value "
        "} } | Select-Object -First 100"
    )

    ok, parsed, raw = _run_ps_json(ssh, script)

    if not ok:
        finding.skipped = True
        finding.skip_reason = "System log query failed for service installation events (7045)"
        return finding

    evidence = []

    if parsed is not None:
        for s in parsed:
            img = (s.get("ImagePath") or "").lower()
            hits = [m for m in SUSPICIOUS_PATH_MARKERS if m in img]
            tag = "[SUSPICIOUS PATH] " if hits else "[new service] "
            evidence.append(
                f"{tag}{s.get('Time','')}  name={s.get('ServiceName','?')}  "
                f"path={s.get('ImagePath','')}  start={s.get('StartType','')}  account={s.get('Account','')}")

    suspicious_count = sum(1 for e in evidence if e.startswith("[SUSPICIOUS PATH]"))

    if suspicious_count > 0:
        finding.severity = "HIGH"
    elif evidence:
        finding.severity = "MEDIUM"
    else:
        finding.severity = "INFO"

    finding.description = (
        f"{suspicious_count} service(s) installed from suspicious paths (temp/appdata/downloads) "
        f"among {len(evidence)} new service installation event(s) in the last {hours}h."
        if suspicious_count else
        f"{len(evidence)} new service installation event(s) in the last {hours}h, no suspicious binary paths."
        if evidence else
        f"No service installation events (7045) in the last {hours}h."
    )
    finding.evidence = evidence
    return finding


# ─── Check 9 — Hunt for Account Creation ──────────────────────────────────────
def check_account_creation(ssh: SSHTransport, hours: int = 24) -> Finding:
    """
    Hunts Event ID 4720 (user account created) and 4732/4728 (member added
    to a local/global group — especially Administrators). New accounts and
    silent privilege-group additions are the Windows equivalent of the
    Linux useradd/groupadd/usermod check.
    """
    finding = Finding(
        check_id=9,
        check_name="Hunt for Account Creation",
        severity="HIGH",
        description="",
    )

    # Event ID 4720: [0]=TargetUserName, [1]=TargetDomainName, [2]=TargetSid,
    # [3]=SubjectUserSid, [4]=SubjectUserName, [5]=SubjectDomainName, [6]=SubjectLogonId
    # Event ID 4732 (local group member added): [0]=TargetUserName, [1]=TargetDomainName,
    # [2]=TargetSid, [3]=MemberSid, [4]=SubjectUserSid, [5]=SubjectUserName,
    # [6]=SubjectDomainName, [7]=SubjectLogonId
    # Event ID 4728 (global group member added): similar structure
    script = (
        f"$cutoff = (Get-Date).AddHours(-{hours}); "
        "$created = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4720; "
        "StartTime=$cutoff} -ErrorAction SilentlyContinue -MaxEvents 100 | "
        "ForEach-Object { $x=$_.Properties; "
        "[PSCustomObject]@{Type='UserCreated'; Time=$_.TimeCreated; "
        "Target=$x[0].Value; Actor=$x[4].Value} }; "
        "$grouped = Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4732,4728; "
        "StartTime=$cutoff} -ErrorAction SilentlyContinue -MaxEvents 100 | "
        "ForEach-Object { $x=$_.Properties; "
        "[PSCustomObject]@{Type='AddedToGroup'; Time=$_.TimeCreated; "
        "Target=$x[0].Value; Group=$x[2].Value; Actor=$x[5].Value} }; "
        "@($created) + @($grouped) | Select-Object -First 150"
    )

    ok, parsed, raw = _run_ps_json(ssh, script)

    if not ok:
        finding.skipped = True
        finding.skip_reason = "Security log query failed for account creation/group membership events"
        return finding

    if parsed is None:
        finding.description = f"No account creation or privileged-group changes in the last {hours}h."
        finding.severity = "INFO"
        return finding

    evidence = []
    for e in parsed:
        etype = e.get("Type", "")
        ts    = e.get("Time", "")
        target = e.get("Target", "?")
        actor  = e.get("Actor", "?")
        if etype == "UserCreated":
            evidence.append(f"[NEW USER] {ts}  account={target}  created_by={actor}")
        else:
            group = e.get("Group", "")
            tag = "[PRIVESC]" if "admin" in group.lower() else "[GROUP CHANGE]"
            evidence.append(f"{tag} {ts}  user={target}  added_to={group}  by={actor}")

    privesc_count = sum(1 for e in evidence if e.startswith("[PRIVESC]"))
    finding.severity = "HIGH" if (evidence and (privesc_count > 0 or any("[NEW USER]" in e for e in evidence))) else "INFO"
    finding.description = (
        f"{len(evidence)} account creation / privileged group change(s) detected"
        + (f", including {privesc_count} Administrators group addition(s)." if privesc_count else ".")
    )
    finding.evidence = evidence
    return finding


# ─── Check 10 — Export Logs for Offline Analysis ─────────────────────────────
def export_logs_offline(ssh: SSHTransport, log_names: list = None,
                        hours: int = 24, output_dir: str = ".") -> Finding:
    """
    Exports the specified Windows Event Logs to remote .evtx files for
    offline analysis (e.g. in Event Viewer, Timeline Explorer, or
    EvtxECmd). Unlike the other checks, this doesn't return alert-style
    findings — it's a utility action whose Finding just confirms what
    was exported and where, so it still surfaces cleanly in the report.
    """
    if log_names is None:
        log_names = ["Security", "System", "Microsoft-Windows-PowerShell/Operational"]

    finding = Finding(
        check_id=10,
        check_name="Export Logs for Offline Analysis",
        severity="INFO",
        description="",
    )

    exported = []
    failed   = []

    for log_name in log_names:
        remote_filename = re.sub(r"[^\w\-]", "_", log_name) + ".evtx"
        remote_path = f"$env:TEMP\\{remote_filename}"

        script = (
            f"$cutoff = (Get-Date).AddHours(-{hours}); "
            f"wevtutil epl \"{log_name}\" \"{remote_path}\" "
            f"/q:\"*[System[TimeCreated[@SystemTime>='$($cutoff.ToUniversalTime().ToString('o'))']]]\""
        )
        ok, out = _run_ps(ssh, script, timeout=40)

        if ok:
            try:
                check_ok, exists_out = ssh.run_command(
                    f'powershell -Command "Test-Path \\"{remote_path}\\""')
                if check_ok and "True" in exists_out:
                    exported.append(f"{log_name} -> remote:{remote_path}")
                else:
                    failed.append(f"{log_name} (export reported success but file not found)")
            except Exception as e:
                failed.append(f"{log_name} (verification error: {e})")
        else:
            failed.append(f"{log_name} ({out[:80]})")

    evidence = [f"[EXPORTED] {e}" for e in exported] + [f"[FAILED] {f}" for f in failed]
    finding.description = (
        f"Exported {len(exported)}/{len(log_names)} requested log(s) to {output_dir} "
        f"(last {hours}h). Remote .evtx files left in %TEMP% for retrieval — "
        f"use the Report's Save function or a manual `scp` to pull them locally."
    )
    finding.evidence = evidence
    return finding


# ─── Check 11 — Fast IOC Hunting ──────────────────────────────────────────────
def fast_ioc_hunt(ssh: SSHTransport, iocs: dict = None, hours: int = 72) -> Finding:
    """
    Sweeps recent Security + Sysmon (if present) + PowerShell logs for a
    supplied set of IOCs (IPs, domains, file hashes, filenames) in a single
    pass. This is the "I have threat intel, does it match anything here"
    check — built for speed during active investigations rather than
    scheduled baseline hunting.

    iocs = {
        "ips":       ["185.220.101.42", ...],
        "domains":   ["evil.example", ...],
        "hashes":    ["e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", ...],
        "filenames": ["payload.exe", "backdoor.dll", ...],
    }
    """
    finding = Finding(
        check_id=11,
        check_name="Fast IOC Hunting",
        severity="HIGH",
        description="",
    )

    if not iocs or not any(iocs.values()):
        finding.skipped = True
        finding.skip_reason = "No IOCs supplied — call fast_ioc_hunt(ssh, iocs={...}) with at least one indicator list"
        return finding

    all_terms = []
    for category in ("ips", "domains", "hashes", "filenames"):
        all_terms.extend(iocs.get(category, []))

    if not all_terms:
        finding.skipped = True
        finding.skip_reason = "IOC dict provided but all lists were empty"
        return finding

    # Build a single PowerShell -match regex alternation for speed —
    # one log sweep instead of N sweeps per IOC.
    escaped_terms = [re.escape(t) for t in all_terms]
    pattern       = "|".join(escaped_terms)

    script = (
        f"$cutoff = (Get-Date).AddHours(-{hours}); "
        f"$pattern = '{pattern}'; "
        "$hits = @(); "
        "foreach ($log in @('Security','System','Microsoft-Windows-PowerShell/Operational')) { "
        "  try { "
        "    Get-WinEvent -FilterHashtable @{LogName=$log; StartTime=$cutoff} "
        "    -ErrorAction SilentlyContinue -MaxEvents 1000 | "
        "    Where-Object { $_.Message -match $pattern } | "
        "    ForEach-Object { $hits += [PSCustomObject]@{ "
        "      Log=$log; Time=$_.TimeCreated; Id=$_.Id; "
        "      Msg=$_.Message.Substring(0,[Math]::Min(160,$_.Message.Length)) } } "
        "  } catch {} "
        "}; "
        "$hits | Select-Object -First 100"
    )

    ok, parsed, raw = _run_ps_json(ssh, script, timeout=45)

    if not ok:
        finding.skipped = True
        finding.skip_reason = "IOC sweep query failed across Security/System/PowerShell logs"
        return finding

    if parsed is None:
        finding.severity = "INFO"
        finding.description = (
            f"Swept {len(all_terms)} IOC(s) across Security/System/PowerShell logs "
            f"(last {hours}h) — no matches found."
        )
        return finding

    evidence = []
    for e in parsed:
        evidence.append(
            f"[MATCH] {e.get('Log','')}  {e.get('Time','')}  EventID={e.get('Id','')}  "
            f"{e.get('Msg','')}")

    finding.description = (
        f"{len(evidence)} IOC match(es) found among {len(all_terms)} supplied indicator(s) "
        f"across Security/System/PowerShell logs (last {hours}h)."
    )
    finding.evidence = evidence
    return finding


# ─── Check 12 — Useful One-Liner Bundle During Investigations ────────────────
INVESTIGATION_ONE_LINERS = {
    "logged_on_users":
        "query user 2>$null; quser 2>$null",
    "active_network_connections":
        "Get-NetTCPConnection -State Established | "
        "Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess",
    "listening_ports":
        "Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess",
    "recent_files_modified":
        "Get-ChildItem -Path C:\\Users -Recurse -File -ErrorAction SilentlyContinue | "
        "Where-Object {$_.LastWriteTime -gt (Get-Date).AddHours(-2)} | "
        "Select-Object -First 50 FullName,LastWriteTime",
    "running_processes_unsigned":
        "Get-Process | ForEach-Object { try { "
        "$sig = Get-AuthenticodeSignature $_.Path -ErrorAction SilentlyContinue; "
        "if ($sig.Status -ne 'Valid') { "
        "[PSCustomObject]@{Name=$_.Name; Path=$_.Path; Status=$sig.Status} } "
        "} catch {} } | Select-Object -First 30",
    "local_admins":
        "Get-LocalGroupMember -Group 'Administrators' | Select-Object Name,PrincipalSource",
    "startup_items":
        "Get-CimInstance Win32_StartupCommand | Select-Object Name,Command,Location,User",
    "prefetch_recent":
        "Get-ChildItem 'C:\\Windows\\Prefetch\\*.pf' -ErrorAction SilentlyContinue | "
        "Sort-Object LastWriteTime -Descending | Select-Object -First 20 Name,LastWriteTime",
}


def run_investigation_one_liners(ssh: SSHTransport, selected: list = None) -> Finding:
    """
    Runs a curated bundle of fast triage one-liners used during active
    investigations — logged-on users, network connections, listening ports,
    recently modified files, unsigned running processes, local admins,
    startup items, and recent Prefetch entries. Returns everything as a
    single Finding with one evidence section per one-liner, since these are
    context/triage data rather than pass/fail alerts.

    selected: optional list of keys from INVESTIGATION_ONE_LINERS to run;
              defaults to all of them.
    """
    finding = Finding(
        check_id=12,
        check_name="Investigation One-Liner Bundle",
        severity="INFO",
        description="",
    )

    keys_to_run = selected or list(INVESTIGATION_ONE_LINERS.keys())
    evidence    = []
    ran_count   = 0

    for key in keys_to_run:
        script = INVESTIGATION_ONE_LINERS.get(key)
        if not script:
            evidence.append(f"[SKIPPED] {key} — unknown one-liner key")
            continue

        ok, out = _run_ps(ssh, script, timeout=20)
        label = key.replace("_", " ").title()

        if not ok or not out.strip():
            evidence.append(f"[{label}] no output / command failed")
            continue

        ran_count += 1
        evidence.append(f"── {label} ──")
        for line in out.strip().splitlines()[:15]:
            evidence.append(f"  {line}")

    finding.description = f"Ran {ran_count}/{len(keys_to_run)} investigation one-liner(s) successfully."
    finding.evidence = evidence
    return finding


# ─── Registry — full Windows check set, mirrors hunting/checks.py ALL_CHECKS ──
# Checks 10-12 are utility/data-gathering operations rather than pass/fail
# alerts; the engine runs the standard alerting checks (1-9) by default and
# exposes 10-12 as opt-in/manual operations since they require extra
# parameters (output_dir, iocs, selected one-liners) the automated
# hunt loop can't supply on its own.
ALL_WINDOWS_CHECKS = [
    check_list_event_logs,
    check_recent_events,
    check_failed_logins,
    check_successful_logins,
    check_process_creation,
    check_powershell_execution,
    check_scheduled_tasks,
    check_service_installation,
    check_account_creation,
]

# Utility operations — called explicitly by the GUI/CLI with extra params,
# not part of the automatic per-VM hunt loop.
UTILITY_OPERATIONS = {
    "export_logs":        export_logs_offline,
    "fast_ioc_hunt":       fast_ioc_hunt,
    "investigation_oneliners": run_investigation_one_liners,
}