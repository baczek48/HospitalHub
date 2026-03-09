"""Database tool launcher (SQL Developer and others).

Strategy:
  1. Auto-detect SQL Developer in common install paths.
  2. If not found, ask the user to locate sqldeveloper.exe once — save path.
  3. Launch the tool.
  4. Copy the first credential's password to clipboard (30 s auto-clear)
     so the user can paste it immediately into the connection dialog.
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

# Common SQL Developer install paths on Windows
_SQLDEVELOPER_SEARCH = [
    r"C:\Program Files\Oracle\SQL Developer\sqldeveloper.exe",
    r"C:\Program Files (x86)\Oracle\SQL Developer\sqldeveloper.exe",
    r"C:\sqldeveloper\sqldeveloper.exe",
    r"C:\Oracle\sqldeveloper\sqldeveloper.exe",
    r"C:\app\sqldeveloper\sqldeveloper.exe",
]


def _find_sqldeveloper() -> str | None:
    """Return path to sqldeveloper.exe: configured → auto-detect → None."""
    saved = load_sqldeveloper_path()
    if saved and os.path.exists(saved):
        return saved
    for p in _SQLDEVELOPER_SEARCH:
        if os.path.exists(p):
            save_sqldeveloper_path(p)
            return p
    return None


def _parse_host(raw: str) -> str:
    """Strip JDBC prefix if present — return bare hostname/IP."""
    # jdbc:oracle:thin:@host:port:sid  →  host
    # jdbc:oracle:thin:@//host:port/service  →  host
    s = raw.strip()
    at = s.rfind("@")
    if at != -1:
        s = s[at + 1:].lstrip("/")
    # take the part before the first colon or slash
    for ch in (":", "/"):
        idx = s.find(ch)
        if idx != -1:
            s = s[:idx]
            break
    return s or raw.strip()


# ──────────────────────────────────────────────────────────────────────────────

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
            parent,
            "Błąd SQL Developer",
            f"Nie można uruchomić SQL Developer:\n{exc}",
        )
        return

    cred = db.credentials[0] if db.credentials else None
    if cred and cred.password:
        _clipboard_copy(cred.password)
        host_clean = _parse_host(db.host)
        QMessageBox.information(
            parent,
            "SQL Developer uruchomiony",
            f"SQL Developer został uruchomiony.\n\n"
            f"Host:    {host_clean}\n"
            f"Port:    {db.port}\n"
            f"Baza:    {db.name}\n"
            f"Login:   {cred.login}\n"
            f"Hasło:   skopiowane do schowka (zostanie wyczyszczone po 30 s)",
        )
    else:
        QMessageBox.information(
            parent,
            "SQL Developer uruchomiony",
            "SQL Developer został uruchomiony.\n"
            "(Brak zapisanych poświadczeń dla tej bazy.)",
        )
