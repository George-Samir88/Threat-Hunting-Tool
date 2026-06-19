"""
transport/ssh.py — Fabric SSH wrapper
Handles connect, run_command, run_sudo, fetch_log with clean error handling.
Optimized for both Linux and Windows OpenSSH Server connections.

Windows OpenSSH Server fixes:
  - banner_timeout: Windows OpenSSH is slower to present the SSH banner
    than Linux sshd. Default paramiko banner_timeout is 15s, which is
    often insufficient. We default to 30s with auto-increase on retry.
  - look_for_keys=False / allow_agent=False: When using password auth,
    prevents paramiko from trying all keys in ~/.ssh/ first, which causes
    "Too many authentication failures" on Windows OpenSSH Server.
  - stdout+stderr merge: Windows OpenSSH often puts command output in
    stderr (especially for cmd.exe), so we check both streams.
  - Windows-specific methods: fetch_log_windows() and file_exists_windows()
    use PowerShell instead of Linux sudo/cat/test commands.
"""
import os
import time
from pathlib import Path
from typing import Optional, Tuple
from fabric import Connection
from paramiko.ssh_exception import (
    AuthenticationException, NoValidConnectionsError, SSHException,
    BadAuthenticationType
)


class SSHTransport:
    def __init__(self, host: str, port: int, username: str,
                 key_path: Optional[str] = None, password: Optional[str] = None,
                 timeout: int = 15, banner_timeout: int = 30):
        self.host     = host
        self.port     = port
        self.username = username
        self.key_path = key_path
        self.password = password
        self.timeout  = timeout
        self.banner_timeout = banner_timeout
        self._conn: Optional[Connection] = None

    def _connect_kwargs(self) -> dict:
        """Build connection kwargs optimized for the target OS type."""
        kw = {}

        # Authentication settings
        if self.key_path:
            path = Path(self.key_path).expanduser()
            if path.exists():
                kw["key_filename"] = [str(path)]
                # When using key auth, don't try password or agent
                kw["allow_agent"] = True
                kw["look_for_keys"] = False
            else:
                print(f"[WARN] Key file not found: {path}, falling back to password")

        if self.password:
            kw["password"] = self.password
            # When password is provided and no valid key, disable agent and key lookup
            # to prevent "Too many authentication failures" on Windows OpenSSH Server
            if not self.key_path or not Path(self.key_path).expanduser().exists():
                kw["allow_agent"] = False
                kw["look_for_keys"] = False

        # Banner timeout — CRITICAL for Windows OpenSSH Server which is slower
        # to present the SSH banner than Linux sshd. Default paramiko is 15s.
        # References: paramiko docs, Fabric issue #2157, StackOverflow #25609153
        kw["banner_timeout"] = self.banner_timeout

        # Auth timeout — separate from connection timeout
        kw["auth_timeout"] = self.timeout

        return kw

    def connect(self, retries: int = 2, retry_delay: float = 2.0) -> None:
        """
        Establish SSH connection with retry logic for Windows OpenSSH Server.
        Windows OpenSSH is often slower to present the banner and may need
        multiple attempts, especially on first connection after service start.

        Retries with auto-increasing banner_timeout on banner/timeout errors.
        """
        last_error = None

        for attempt in range(retries + 1):
            try:
                self._conn = Connection(
                    host=self.host,
                    user=self.username,
                    port=self.port,
                    connect_kwargs=self._connect_kwargs(),
                    connect_timeout=self.timeout,
                )
                self._conn.open()
                return  # Success

            except (AuthenticationException, BadAuthenticationType) as e:
                # Authentication failed — no point retrying with same credentials
                raise AuthenticationException(
                    f"Authentication failed for {self.username}@{self.host}:{self.port} — "
                    f"check username/password or key permissions. Error: {e}"
                ) from e

            except (NoValidConnectionsError, SSHException, TimeoutError) as e:
                last_error = e
                error_str = str(e).lower()

                # Check if it's a banner timeout issue — common with Windows OpenSSH
                if "banner" in error_str or "timeout" in error_str:
                    if attempt < retries:
                        # Increase banner timeout for next attempt
                        self.banner_timeout += 15
                        print(f"[RETRY {attempt+1}/{retries}] Banner timeout, increasing to {self.banner_timeout}s...")
                        time.sleep(retry_delay)
                        continue

                # Check if connection was refused
                if "refused" in error_str or "connection" in error_str:
                    if attempt < retries:
                        print(f"[RETRY {attempt+1}/{retries}] Connection issue, waiting {retry_delay}s...")
                        time.sleep(retry_delay)
                        continue

                # Other SSH errors — don't retry
                raise

            except Exception as e:
                last_error = e
                if attempt < retries:
                    print(f"[RETRY {attempt+1}/{retries}] Unexpected error: {e}, waiting {retry_delay}s...")
                    time.sleep(retry_delay)
                    continue
                raise

        # All retries exhausted
        raise SSHException(
            f"Failed to connect to {self.host}:{self.port} after {retries+1} attempts. "
            f"Last error: {last_error}"
        )

    def close(self) -> None:
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def run_command(self, cmd: str, timeout: int = 30, pty: bool = False) -> Tuple[bool, str]:
        """
        Run a non-privileged command. Returns (success, stdout_or_error).

        pty=True requests a pseudo-terminal — needed for some Windows commands
        that require an interactive shell context (e.g., query user, quser).
        """
        try:
            r = self._conn.run(cmd, hide=True, warn=True, timeout=timeout, pty=pty)
            # Combine stdout and stderr since Windows OpenSSH often puts
            # command output in stderr (especially for cmd.exe)
            output = r.stdout.strip()
            if not output and r.stderr.strip():
                output = r.stderr.strip()
            return True, output
        except Exception as e:
            return False, str(e)

    def run_sudo(self, cmd: str, timeout: int = 30) -> Tuple[bool, str]:
        """
        Run a command with sudo. Uses stored password for the sudo prompt.
        Falls back to passwordless sudo (NOPASSWD) if no password stored.
        Returns (success, stdout_or_error).

        NOTE: This is Linux-only. On Windows, use run_command() directly
        as the user typically has the required privileges, or use
        run_command() with PowerShell elevation if needed.
        """
        try:
            r = self._conn.sudo(
                cmd,
                hide=True,
                warn=True,
                timeout=timeout,
                password=self.password or "",
            )
            return True, r.stdout.strip()
        except Exception as e:
            return False, str(e)

    def fetch_log(self, remote_path: str) -> Tuple[bool, str]:
        """
        Read a remote file via sudo cat (Linux).
        Using sudo cat instead of SFTP get() ensures root-owned logs
        (auth.log, secure, audit.log) are always readable.
        Returns (success, content_or_error).
        """
        try:
            ok, out = self.run_sudo(f"test -e {remote_path} && echo exists || echo missing")
            if "missing" in out:
                return False, f"File not found: {remote_path}"

            ok, content = self.run_sudo(f"cat {remote_path}")
            if not ok:
                return False, content

            return True, content

        except Exception as e:
            return False, str(e)

    def fetch_log_windows(self, remote_path: str) -> Tuple[bool, str]:
        """
        Read a remote file on Windows using PowerShell Get-Content.
        Windows equivalent of fetch_log() — does not use sudo (Windows
        OpenSSH runs as the connected user, typically with admin privileges).
        Returns (success, content_or_error).
        """
        try:
            # First check if file exists using Test-Path
            ps_check = f'Test-Path "{remote_path}"'
            ok, out = self.run_command(f'powershell -Command "{ps_check}"')
            if not ok or "True" not in out:
                return False, f"File not found: {remote_path}"

            # Read the file content using Get-Content -Raw
            ps_read = f'Get-Content "{remote_path}" -Raw'
            ok, content = self.run_command(f'powershell -Command "{ps_read}"')
            if not ok:
                return False, content

            return True, content

        except Exception as e:
            return False, str(e)

    def file_exists(self, remote_path: str) -> bool:
        """Check if a file exists (Linux version using test -e)."""
        _, out = self.run_command(f"test -e {remote_path} && echo yes || echo no")
        return "yes" in out

    def file_exists_windows(self, remote_path: str) -> bool:
        """Check if a file exists on Windows using PowerShell Test-Path."""
        ok, out = self.run_command(f'powershell -Command "Test-Path \'{remote_path}\'"')
        return ok and "True" in out

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.close()