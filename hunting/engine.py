"""
hunting/engine.py — Orchestrates all checks against one VM, returns a Report.
Called from the GUI via ThreadPoolExecutor — never touches widgets directly.
"""
from hunting.models import Report, Finding
from hunting.checks import ALL_CHECKS
from transport.ssh import SSHTransport
from typing import Callable, Optional


def run_hunt(
    vm_config: dict,
    progress_cb: Optional[Callable[[int, int, str], None]] = None,
) -> Report:
    """
    Run all checks against a single VM.
    progress_cb(current, total, check_name) — called from worker thread.
    All GUI updates must go through a queue; never call widgets here.
    """
    report = Report(
        vm=vm_config.get("hostname", vm_config.get("host", "unknown")),
        host=vm_config.get("host", ""),
    )

    ssh = SSHTransport(
        host=vm_config["host"],
        port=int(vm_config.get("port", 22)),
        username=vm_config["username"],
        key_path=vm_config.get("key_path"),
        password=vm_config.get("password"),
    )

    try:
        ssh.connect()
    except Exception as e:
        report.error = str(e)
        return report

    total = len(ALL_CHECKS)
    try:
        for i, check_fn in enumerate(ALL_CHECKS, 1):
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
    finally:
        ssh.close()

    return report
