"""Database tool launcher — SQL Developer.

Strategy:
  1. Auto-detect SQL Developer in common install paths (or ask user once).
  2. Launch SQL Developer.
  3. Copy the first credential's password to clipboard (30 s auto-clear)
     and show a popup with all connection details ready to paste.
"""

import os
import subprocess
import sys

from PyQt6.QtWidgets import QFileDialog, QMessageBox

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import models
from config import load_sqldeveloper_path, save_sqldeveloper_path
from ui.dialogs import _clipboard_copy

_NO_WIN = getattr(subprocess, "CREATE_NO_WINDOW", 0)

_SQLDEVELOPER_SEARCH = [
    r"C:\Program Files\Oracle\SQL Developer\sqldeveloper.exe",
    r"C:\Program Files (x86)\Oracle\SQL Developer\sqldeveloper.exe",
    r"C:\sqldeveloper\sqldeveloper.exe",
    r"C:\Oracle\sqldeveloper\sqldeveloper.exe",
    r"C:\app\sqldeveloper\sqldeveloper.exe",
]


def _find_sqldeveloper() -> str | None:
    saved = load_sqldeveloper_path()
    if saved and os.path.exists(saved):
        return saved
    for p in _SQLDEVELOPER_SEARCH:
        if os.path.exists(p):
            save_sqldeveloper_path(p)
            return p
    return None


def _parse_host(raw: str) -> str:
    """Strip JDBC prefix — return bare hostname/IP."""
    s = raw.strip()
    at = s.rfind("@")
    if at != -1:
        s = s[at + 1:].lstrip("/")
    for ch in (":", "/"):
        idx = s.find(ch)
        if idx != -1:
            s = s[:idx]
            break
    return s or raw.strip()


# ──────────────────────────────────────────────────────────────────────────────

def launch_sqldeveloper(parent=None) -> None:
    """Just open SQL Developer — no database context."""
    path = _find_sqldeveloper()

    if path is None:
        path, _ = QFileDialog.getOpenFileName(
            parent,
            "Zlokalizuj SQL Developer",
            r"C:\Program Files",
            "SQL Developer (sqldeveloper.exe);;Wszystkie pliki (*.*)",
        )
        if not path:
            return
        save_sqldeveloper_path(path)

    try:
        subprocess.Popen([path], creationflags=_NO_WIN)
    except Exception as exc:
        QMessageBox.critical(
            parent, "Błąd SQL Developer",
            f"Nie można uruchomić SQL Developer:\n{exc}",
        )


def connect_db(db: models.Database, parent=None) -> None:
    """Launch SQL Developer and copy the first credential's password to clipboard."""
    path = _find_sqldeveloper()

    if path is None:
        path, _ = QFileDialog.getOpenFileName(
            parent,
            "Zlokalizuj SQL Developer",
            r"C:\Program Files",
            "SQL Developer (sqldeveloper.exe);;Wszystkie pliki (*.*)",
        )
        if not path:
            return
        save_sqldeveloper_path(path)

    try:
        subprocess.Popen([path], creationflags=_NO_WIN)
    except Exception as exc:
        QMessageBox.critical(
            parent, "Błąd SQL Developer",
            f"Nie można uruchomić SQL Developer:\n{exc}",
        )
        return

    cred = db.credentials[0] if db.credentials else None
    if cred and cred.password:
        _clipboard_copy(cred.password)

    host_clean = _parse_host(db.host)
    lines = [
        f"Host:    {host_clean}",
        f"Port:    {db.port}",
        f"Baza:    {db.name}",
        f"Login:   {cred.login if cred else '—'}",
    ]
    if cred and cred.password:
        lines.append("Hasło:   skopiowane do schowka (wyczyszczone po 30 s)")

    QMessageBox.information(
        parent, "SQL Developer uruchomiony", "\n".join(lines)
    )
