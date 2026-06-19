"""
hunting/engine.py — Orchestrates all checks against one VM, returns a Report.
Called from the GUI via a background thread — never touches widgets directly.

Branching logic:
  1. Connect over SSH (same transport for both OS types — Windows OpenSSH
     Server speaks the same SSH protocol, just lands in cmd.exe instead of
     bash by default).
  2. Run os_detect.detect_os() once per hunt.
  3. If Windows  -> run hunting.windows_checks.ALL_WINDOWS_CHECKS (9 checks)
     If Linux    -> run hunting.checks.ALL_CHECKS (8 checks)
     If unknown  -> return a Report with a single skipped Finding explaining
                    detection failed, rather than guessing and producing a
                    report full of false "skipped: log not found" noise.

The Report.os_type field (added to hunting/models.py) records what was

detected so the GUI/report panel can show an OS badge without re-running
detection.
"""

from typing import Callable, Optional
from hunting.models import Report, Finding
from hunting.os_detect import detect_os, OSInfo
from transport.ssh import SSHTransport

# Import both check sets — the engine decides at runtime which to use
from hunting.checks import ALL_CHECKS as LINUX_CHECKS
from hunting.windows_checks import ALL_WINDOWS_CHECKS as WINDOWS_CHECKS


def _build_unknown_os_report(vm_config: dict, os_info: OSInfo) -> Report:
    """
    When OS detection can't confidently classify the host, return a Report
    with one explanatory Finding instead of silently running the wrong
    check set (which would just produce 8-9 confusing "log not found"
    skips and look like a tool bug rather than a detection failure).
    """
    report = Report(
        vm=vm_config.get("hostname", vm_config.get("host", "unknown")),
        host=vm_config.get("host", ""),
        os_type="unknown",
    )
    report.findings.append(Finding(
        check_id=0,
        check_name="OS Detection",
        severity="INFO",
        description=(
            "Could not confidently determine whether this host is Windows "
            "or Linux. No hunt checks were run."
        ),
        skipped=True,
        skip_reason=(
            f"All detection probes returned ambiguous or empty results "
            f"(raw probe output: '{os_info.raw_version or '(none)'}'). "
            f"Verify SSH access works manually (`ssh user@host`) and that "
            f"the account has permission to run basic shell builtins."
        ),
    ))
    return report


def run_hunt(
    vm_config: dict,
    progress_cb: Optional[Callable[[int, int, str], None]] = None,
) -> Report:
    """
    Run all checks against a single VM, automatically selecting the Linux
    or Windows check set based on detected OS.

    progress_cb(current, total, check_name) — called from worker thread.
    All GUI updates must go through a queue; never call widgets here.
    """
    vm_name = vm_config.get("hostname", vm_config.get("host", "unknown"))
    vm_host = vm_config.get("host", "")

    ssh = SSHTransport(
        host=vm_host,
        port=int(vm_config.get("port", 22)),
        username=vm_config["username"],
        key_path=vm_config.get("key_path"),
        password=vm_config.get("password"),
    )

    try:
        ssh.connect()
    except Exception as e:
        report = Report(vm=vm_name, host=vm_host, os_type="unknown")
        report.error = str(e)
        return report

    try:
        # ── Step 1: detect OS ────────────────────────────────────────────────
        if progress_cb:
            progress_cb(0, 1, "Detecting OS...")

        os_info = detect_os(ssh)

        if os_info.os_type == "unknown":
            return _build_unknown_os_report(vm_config, os_info)

        # ── Step 2: select check set ─────────────────────────────────────────
        if os_info.is_windows:
            check_set = WINDOWS_CHECKS
        else:
            check_set = LINUX_CHECKS

        report = Report(vm=vm_name, host=vm_host, os_type=os_info.os_type)
        total = len(check_set)

        # ── Step 3: run checks ───────────────────────────────────────────────
        for i, check_fn in enumerate(check_set, 1):
            check_name = check_fn.__name__.replace("check_", "").replace("_", " ").title()
            if progress_cb:
                progress_cb(i, total, check_name)
            try:
                finding = check_fn(ssh)
            except Exception as e:
                finding = Finding(
                    check_id=i,
                    check_name=check_name,
                    severity="INFO",
                    description=f"Check failed with exception: {e}",
                    skipped=True,
                    skip_reason=str(e),
                )
            report.findings.append(finding)

        return report

    finally:
        ssh.close()