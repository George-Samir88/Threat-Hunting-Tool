"""
hunting/os_detect.py — Remote OS detection over an established SSH connection.

Why detection matters: Windows OpenSSH ships with `cmd.exe` as the default
shell, not `powershell.exe`. A command like `uname -a` will return a Windows
"is not recognized" error rather than throwing an SSH-level exception, so we
can't rely on exceptions alone — we inspect the actual output text.

Detection strategy (in order, stops at first confident match):
  1. Try `ver` (cmd.exe builtin) — works even before knowing the shell type,
     since OpenSSH on Windows defaults to cmd.exe for non-interactive use.
  2. Try `uname -s` — works on Linux/macOS, fails or returns Windows error
     text on Windows.
  3. Cross-check with `echo %OS%` (cmd) vs `echo $0` (posix shell) as a
     tie-breaker if the first two are ambiguous (e.g. custom shells).
"""

from dataclasses import dataclass
from typing import Optional
from transport.ssh import SSHTransport


@dataclass
class OSInfo:
    os_type: str            # "windows" | "linux" | "unknown"
    shell: str               # "cmd" | "powershell" | "posix" | "unknown"
    raw_version: str = ""    # raw banner text used for the decision
    confidence: str = "low"  # "high" | "medium" | "low"

    @property
    def is_windows(self) -> bool:
        return self.os_type == "windows"

    @property
    def is_linux(self) -> bool:
        return self.os_type == "linux"


# Substrings that reliably indicate a Windows cmd.exe / PowerShell session
_WINDOWS_MARKERS = (
    "microsoft windows",
    "microsoft corporation",
    "is not recognized as an internal or external command",
    "windows_nt",
    "windowspowershell",
)

# Substrings that reliably indicate a POSIX shell
_LINUX_MARKERS = (
    "linux",
    "gnu/linux",
    "/bin/bash",
    "/bin/sh",
    "command not found",
)


def detect_os(ssh: SSHTransport) -> OSInfo:
    """
    Run a small set of cheap, side-effect-free probe commands and classify
    the remote host. Designed to work whether the SSH session lands in
    cmd.exe, PowerShell, or a POSIX shell.
    """

    # ── Probe 1: `ver` — cmd.exe builtin, near-instant, no PowerShell needed ──
    ok, out = ssh.run_command("ver")
    out_lower = out.lower()
    if ok and out.strip():
        if any(marker in out_lower for marker in _WINDOWS_MARKERS):
            return OSInfo(os_type="windows", shell="cmd",
                          raw_version=out.strip(), confidence="high")

    # ── Probe 2: `uname -s` — POSIX builtin, fails cleanly on Windows ─────────
    ok, out = ssh.run_command("uname -s")
    out_lower = out.lower()
    if ok and out.strip():
        if "linux" in out_lower:
            return OSInfo(os_type="linux", shell="posix",
                          raw_version=out.strip(), confidence="high")
        if any(marker in out_lower for marker in _WINDOWS_MARKERS):
            # uname doesn't exist on Windows; cmd.exe echoes an error message
            # containing one of the Windows markers instead of failing silently
            return OSInfo(os_type="windows", shell="cmd",
                          raw_version=out.strip(), confidence="medium")

    # ── Probe 3: tie-breaker — try a PowerShell-specific call ────────────────
    # If the session is already in PowerShell (rare but possible depending on
    # the user's default shell config in sshd_config), $PSVersionTable exists.
    ok, out = ssh.run_command('powershell -NoProfile -Command "$PSVersionTable.PSVersion.Major"')
    if ok and out.strip().isdigit():
        return OSInfo(os_type="windows", shell="powershell",
                      raw_version=f"PowerShell major version {out.strip()}",
                      confidence="high")

    # ── Probe 4: last resort — POSIX shell variable expansion ────────────────
    ok, out = ssh.run_command("echo $0")
    if ok and out.strip() and "$0" not in out:
        # A real POSIX shell expanded $0; cmd.exe would print "$0" literally
        return OSInfo(os_type="linux", shell="posix",
                      raw_version=out.strip(), confidence="medium")

    return OSInfo(os_type="unknown", shell="unknown",
                  raw_version="", confidence="low")


def detect_os_cached(vm_config: dict, ssh: SSHTransport) -> OSInfo:
    """
    Convenience wrapper for the hunting engine: detects OS once per hunt run
    and stashes the result on the vm_config dict (in-memory only, not
    persisted back to vms.json) so repeated calls within the same hunt don't
    re-probe the connection.
    """
    cache_key = "_os_info_cache"
    if cache_key in vm_config and isinstance(vm_config[cache_key], OSInfo):
        return vm_config[cache_key]

    info = detect_os(ssh)
    vm_config[cache_key] = info
    return info