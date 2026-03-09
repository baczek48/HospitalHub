"""RDP connection launcher for Windows.

Strategy:
  1. Store credentials in Windows Credential Manager via cmdkey.exe
     (key = TERMSRV/<ip>  — the exact namespace mstsc looks up).
  2. Launch mstsc.exe /v:<ip>[:<port>]  — it picks up the stored creds.
  3. After 10 s delete the stored credentials so they don't persist.

No extra libraries required; works on every Windows installation.
"""

import os
import re
import subprocess

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QMessageBox

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import models

_MSTSC   = r"C:\Windows\System32\mstsc.exe"
_CMDKEY  = r"C:\Windows\System32\cmdkey.exe"
_NO_WIN  = getattr(subprocess, "CREATE_NO_WINDOW", 0)   # suppress console flash

# Allowed characters for hostname/IP: alphanumeric, dots, hyphens only
_IP_RE = re.compile(r'^[A-Za-z0-9.\-]{1,253}$')


def _validate_ip(ip: str) -> str:
    """Return sanitized IP/hostname or raise ValueError."""
    ip = ip.strip()
    if not ip or not _IP_RE.match(ip):
        raise ValueError(f"Nieprawidłowy adres hosta: {ip!r}")
    return ip


def _validate_port(port: str) -> int:
    """Return port as int (1–65535) or raise ValueError."""
    try:
        p = int(port.strip()) if port.strip() else 3389
    except ValueError:
        raise ValueError(f"Nieprawidłowy port: {port!r}")
    if not 1 <= p <= 65535:
        raise ValueError(f"Port poza zakresem: {p}")
    return p


# ──────────────────────────────────────────────────────────────────────────────

def connect_rdp(machine: "models.Machine", parent=None) -> None:
    """Open an RDP session for *machine*.

    If the machine has credentials stored in the vault, they are injected
    automatically so the user does not have to type them.  The temporary
    Credential Manager entry is removed ~10 s after launch.

    Shows a QMessageBox on error (missing mstsc, launch failure, etc.).
    """
    if not os.path.exists(_MSTSC):
        QMessageBox.critical(
            parent,
            "Błąd RDP",
            "Nie znaleziono mstsc.exe.\n"
            "Funkcja RDP jest dostępna tylko na systemie Windows.",
        )
        return

    try:
        ip   = _validate_ip(machine.ip)
        port = _validate_port(machine.rdp_port or "3389")
    except ValueError as exc:
        QMessageBox.critical(parent, "Błąd RDP", str(exc))
        return

    # mstsc syntax: /v:host  or  /v:host:port  (only when non-standard)
    target = f"{ip}:{port}" if port != 3389 else ip

    cred = machine.credentials[0] if machine.credentials else None
    injected = False

    if cred and cred.login and cred.password:
        injected = _cmdkey_add(ip, cred.login, cred.password)

    try:
        subprocess.Popen(
            [_MSTSC, f"/v:{target}"],
            creationflags=_NO_WIN,
        )
    except Exception as exc:
        if injected:
            _cmdkey_delete(ip)
        QMessageBox.critical(
            parent,
            "Błąd RDP",
            f"Nie można uruchomić mstsc.exe:\n{exc}",
        )
        return

    # Schedule cleanup — 10 s is more than enough for mstsc to authenticate.
    if injected:
        QTimer.singleShot(10_000, lambda: _cmdkey_delete(ip))


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _cmdkey_add(ip: str, login: str, password: str) -> bool:
    """Store credentials in Credential Manager.  Returns True on success."""
    try:
        r = subprocess.run(
            [_CMDKEY,
             f"/generic:TERMSRV/{ip}",
             f"/user:{login}",
             f"/pass:{password}"],
            creationflags=_NO_WIN,
            capture_output=True,
            check=False,
        )
        return r.returncode == 0
    except Exception:
        return False


def _cmdkey_delete(ip: str) -> None:
    """Remove the temporary Credential Manager entry."""
    try:
        subprocess.run(
            [_CMDKEY, f"/delete:TERMSRV/{ip}"],
            creationflags=_NO_WIN,
            capture_output=True,
            check=False,
        )
    except Exception:
        pass
