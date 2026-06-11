"""
transport/ssh.py — Fabric SSH wrapper
Handles connect, run_command, run_sudo, fetch_log with clean error handling.
"""
import os
import tempfile
from typing import Optional, Tuple
from fabric import Connection, Config
from paramiko.ssh_exception import (
    AuthenticationException, NoValidConnectionsError, SSHException
)


class SSHTransport:
    def __init__(self, host: str, port: int, username: str,
                 key_path: Optional[str] = None, password: Optional[str] = None,
                 timeout: int = 10):
        self.host     = host
        self.port     = port
        self.username = username
        self.key_path = key_path
        self.password = password
        self.timeout  = timeout
        self._conn: Optional[Connection] = None

    def _connect_kwargs(self) -> dict:
        kw = {}
        if self.key_path:
            path = os.path.expanduser(self.key_path)
            if os.path.exists(path):
                kw["key_filename"] = [path]
        if self.password:
            kw["password"] = self.password
        return kw

    def connect(self) -> None:
        # Pass sudo password via Fabric Config so sudo runner handles
        # the prompt correctly without needing a PTY or -S flag
        config = Config(overrides={"sudo": {"password": self.password or ""}})
        self._conn = Connection(
            host=self.host,
            user=self.username,
            port=self.port,
            config=config,
            connect_kwargs=self._connect_kwargs(),
            connect_timeout=self.timeout,
        )
        # Force the connection open immediately so auth errors surface here
        self._conn.open()

    def close(self) -> None:
        if self._conn:
            try:
                self._conn.close()
            except Exception:
                pass
            self._conn = None

    def run_command(self, cmd: str, timeout: int = 30) -> Tuple[bool, str]:
        """Run a command. Returns (success, stdout_or_error)."""
        try:
            r = self._conn.run(cmd, hide=True, warn=True, timeout=timeout)
            return True, r.stdout.strip()
        except Exception as e:
            return False, str(e)

    def run_sudo(self, cmd: str, timeout: int = 30) -> Tuple[bool, str]:
        """
        Run a privileged command via Fabric's sudo runner.
        Password is supplied via Config at connect time — no PTY needed.
        Returns (success, stdout_or_error).
        """
        try:
            r = self._conn.sudo(cmd, hide=True, warn=True, timeout=timeout)
            return True, r.stdout.strip()
        except Exception as e:
            return False, str(e)

    def fetch_log(self, remote_path: str) -> Tuple[bool, str]:
        """
        Pull a remote log file into a local temp file and return its contents.
        Pulling locally and parsing in Python is more reliable than streaming.
        Returns (success, content_or_error).
        """
        try:
            # Check file exists and is readable first
            ok, out = self.run_command(
                f"test -r {remote_path} && echo exists || echo missing")
            if "missing" in out:
                return False, f"File not found or not readable: {remote_path}"

            with tempfile.NamedTemporaryFile(delete=False, suffix=".log") as tmp:
                tmp_path = tmp.name

            self._conn.get(remote_path, tmp_path)

            with open(tmp_path, "r", errors="replace") as f:
                content = f.read()

            os.unlink(tmp_path)
            return True, content

        except Exception as e:
            return False, str(e)

    def file_exists(self, remote_path: str) -> bool:
        ok, out = self.run_command(
            f"test -r {remote_path} && echo yes || echo no")
        return "yes" in out

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.close()