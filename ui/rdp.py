"""RDP connection launcher for Windows.

Strategy:
  1. Store credentials in Windows Credential Manager via ctypes (CredWriteW)
     (target = TERMSRV/<ip>  — the exact namespace mstsc looks up).
  2. Launch mstsc.exe /v:<ip>[:<port>]  — it picks up the stored creds.
  3. After 10 s delete the stored credentials so they don't persist.

No extra libraries required; works on every Windows installation.
"""

import ctypes
import ctypes.wintypes
import os
import re
import subprocess
import tempfile

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QMessageBox

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import models

_MSTSC   = r"C:\Windows\System32\mstsc.exe"
_NO_WIN  = getattr(subprocess, "CREATE_NO_WINDOW", 0)   # suppress console flash

# ──────────────────────────────────────────────────────────────────────────────
# Windows Credential Manager via ctypes (avoids cmdkey.exe password in argv)
# ──────────────────────────────────────────────────────────────────────────────

CRED_TYPE_GENERIC         = 1
CRED_PERSIST_LOCAL_MACHINE = 2

class _CREDENTIAL(ctypes.Structure):
    _fields_ = [
        ("Flags", ctypes.wintypes.DWORD),
        ("Type", ctypes.wintypes.DWORD),
        ("TargetName", ctypes.wintypes.LPWSTR),
        ("Comment", ctypes.wintypes.LPWSTR),
        ("LastWritten", ctypes.wintypes.FILETIME),
        ("CredentialBlobSize", ctypes.wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
        ("Persist", ctypes.wintypes.DWORD),
        ("AttributeCount", ctypes.wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", ctypes.wintypes.LPWSTR),
        ("UserName", ctypes.wintypes.LPWSTR),
    ]

_advapi32 = ctypes.windll.advapi32
_CredWriteW = _advapi32.CredWriteW
_CredDeleteW = _advapi32.CredDeleteW

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

def connect_rdp(machine: "models.Machine", parent=None,
                admin_unlocked: bool = False) -> None:
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

    vis_creds = machine.credentials if admin_unlocked else [
        c for c in machine.credentials if not c.admin_only]
    cred = vis_creds[0] if vis_creds else None
    injected = False

    if cred and cred.login and cred.password:
        injected = _cmdkey_add(ip, cred.login, cred.password)

    # Generate .rdp file with resource settings:
    #   - clipboard: always ON
    #   - printers: always OFF
    #   - drive mapping: per machine setting
    rdp_file = _make_rdp_file(target, machine)

    try:
        subprocess.Popen(
            [_MSTSC, rdp_file],
            creationflags=_NO_WIN,
        )
    except Exception as exc:
        if injected:
            _cmdkey_delete(ip)
        _cleanup_rdp_file(rdp_file)
        QMessageBox.critical(
            parent,
            "Błąd RDP",
            f"Nie można uruchomić mstsc.exe:\n{exc}",
        )
        return

    # Schedule cleanup — 30 s gives mstsc enough time even on slow networks.
    def _cleanup():
        if injected:
            _cmdkey_delete(ip)
        _cleanup_rdp_file(rdp_file)
    QTimer.singleShot(30_000, _cleanup)


# ──────────────────────────────────────────────────────────────────────────────
# .rdp file generation
# ──────────────────────────────────────────────────────────────────────────────

def _make_rdp_file(target: str, machine: "models.Machine") -> str:
    """Create a temporary .rdp file with resource/device settings.

    Settings:
      - redirectclipboard:i:1  — clipboard always enabled
      - redirectprinters:i:0   — printers always disabled
      - drivestoredirect:s:... — selected drives or empty
    """
    drives = getattr(machine, 'rdp_drives', [])

    lines = [
        f"full address:s:{target}",
        "redirectclipboard:i:1",
        "redirectprinters:i:0",
    ]
    if drives:
        # mstsc format: "C:\;D:\;" for specific drives
        drive_str = ";".join(f"{d}\\" for d in drives) + ";"
        lines.append(f"drivestoredirect:s:{drive_str}")
    else:
        lines.append("drivestoredirect:s:")

    rdp_dir = os.path.join(os.path.realpath(tempfile.gettempdir()), 'hhub_rdp')
    os.makedirs(rdp_dir, exist_ok=True)
    # Use mkstemp for unpredictable filename and restrictive permissions (0o600)
    fd, rdp_path = tempfile.mkstemp(suffix='.rdp', dir=rdp_dir)
    with os.fdopen(fd, 'wb') as f:
        f.write(('\r\n'.join(lines) + '\r\n').encode('utf-8'))
    return rdp_path


def _cleanup_rdp_file(path: str) -> None:
    """Remove temporary .rdp file."""
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _cmdkey_add(ip: str, login: str, password: str) -> bool:
    """Store credentials in Credential Manager via ctypes.

    Uses CredWriteW directly — password never appears in process arguments.
    """
    try:
        target = f"TERMSRV/{ip}"
        pw_bytes = password.encode("utf-16-le")

        blob = (ctypes.c_byte * len(pw_bytes)).from_buffer_copy(pw_bytes)

        cred = _CREDENTIAL()
        cred.Flags = 0
        cred.Type = CRED_TYPE_GENERIC
        cred.TargetName = target
        cred.CredentialBlobSize = len(pw_bytes)
        cred.CredentialBlob = blob
        cred.Persist = CRED_PERSIST_LOCAL_MACHINE
        cred.UserName = login

        return bool(_CredWriteW(ctypes.byref(cred), 0))
    except Exception:
        return False


def _cmdkey_delete(ip: str) -> None:
    """Remove the temporary Credential Manager entry via ctypes."""
    try:
        target = f"TERMSRV/{ip}"
        _CredDeleteW(target, CRED_TYPE_GENERIC, 0)
    except Exception:
        pass
