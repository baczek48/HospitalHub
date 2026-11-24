"""Menu „Info” i okno „O programie” — wspólne dla HospitalHub i Portable.

Wersja i data wydania pochodzą z :mod:`app_version` (wpisywane przez skrypt
budujący), reszta jest odczytywana na żywo: system, uprawnienia, foldery.
„Kopiuj informacje” daje gotowy tekst do zgłoszenia problemu.
"""

from __future__ import annotations

import ctypes
import os
import platform
import sys
from datetime import date
from pathlib import Path

from PyQt6.QtCore import PYQT_VERSION_STR, QT_VERSION_STR, Qt, QUrl
from PyQt6.QtGui import QDesktopServices, QGuiApplication
from PyQt6.QtWidgets import (
    QDialog, QGridLayout, QHBoxLayout, QLabel, QMenu, QPushButton, QVBoxLayout,
)

import app_version


def _is_admin() -> bool | None:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return None


def _windows() -> str:
    try:
        ver = sys.getwindowsversion()
        name = "Windows 11" if ver.build >= 22000 else f"Windows {platform.release()}"
        return f"{name} (kompilacja {ver.build})"
    except Exception:
        return platform.platform()


def _release_date() -> str:
    raw = app_version.RELEASE_DATE
    try:
        return date.fromisoformat(raw).strftime("%d.%m.%Y")
    except Exception:
        return raw or "—"


def data_dir() -> Path:
    from config import app_data_dir
    return app_data_dir()


def logs_dir() -> Path:
    try:
        from diagnostics import base_dir
        return base_dir() / "logs"
    except Exception:
        return data_dir() / "diagnostics" / "logs"


def info_rows(variant: str) -> list[tuple[str, str]]:
    """Everything the window shows, in order — also what „Kopiuj” copies."""
    admin = _is_admin()
    rows = [
        ("Program", f"{app_version.APP_NAME} {variant}".strip()),
        ("Wersja", app_version.version_label()),
        ("Data wydania", _release_date()),
        ("Autor", app_version.AUTHOR),
        ("Licencja", app_version.COPYRIGHT),
        ("Strona", app_version.REPO_URL),
        ("System", _windows()),
        ("Uprawnienia", "—" if admin is None
         else ("administrator" if admin else "zwykły użytkownik")),
        ("Środowisko", f"Python {platform.python_version()}, Qt {QT_VERSION_STR}, "
                       f"PyQt {PYQT_VERSION_STR}"),
        ("Folder danych", str(data_dir())),
        ("Logi", str(logs_dir())),
    ]
    return rows


def info_text(variant: str) -> str:
    return "\n".join(f"{k}: {v}" for k, v in info_rows(variant))


def _open(path_or_url: str) -> None:
    if "://" in path_or_url:
        QDesktopServices.openUrl(QUrl(path_or_url))
        return
    path = Path(path_or_url)
    path.mkdir(parents=True, exist_ok=True)
    QDesktopServices.openUrl(QUrl.fromLocalFile(str(path)))


class AboutDialog(QDialog):
    def __init__(self, variant: str = "", parent=None):
        super().__init__(parent)
        self._variant = variant
        self.setWindowTitle(f"O programie {app_version.APP_NAME}")
        self.setMinimumWidth(560)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 18, 20, 16)
        lay.setSpacing(12)

        title = QLabel(f"{app_version.APP_NAME} {variant}".strip())
        title.setStyleSheet("font-size: 20px; font-weight: 600;")
        lay.addWidget(title)

        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(6)
        skip = {"Program"}
        r = 0
        for key, value in info_rows(variant):
            if key in skip:
                continue
            k = QLabel(key)
            k.setStyleSheet("color: #8b949e;")
            k.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
            if key == "Strona":
                v = QLabel(f'<a href="{value}">{value.removeprefix("https://")}</a>')
                v.setOpenExternalLinks(True)
            else:
                v = QLabel(value)
                v.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
            # A path wraps at its backslashes into a stray "C:" line; it stays
            # on one line (selectable, copied in full by "Kopiuj").
            v.setWordWrap(key not in ("Folder danych", "Logi"))
            grid.addWidget(k, r, 0)
            grid.addWidget(v, r, 1)
            if key in ("Folder danych", "Logi"):
                btn = QPushButton("Otwórz")
                btn.setObjectName(f"open_{'data' if key == 'Folder danych' else 'logs'}")
                btn.clicked.connect(lambda _=False, p=value: _open(p))
                grid.addWidget(btn, r, 2)
            r += 1
        grid.setColumnStretch(1, 1)
        lay.addLayout(grid)

        buttons = QHBoxLayout()
        self._copy = QPushButton("Kopiuj informacje")
        self._copy.setToolTip("Wersja, system i foldery — do zgłoszenia problemu")
        self._copy.clicked.connect(self._copy_info)
        latest = QPushButton("Sprawdź aktualizacje…")
        latest.clicked.connect(lambda: _check_updates(self._variant, self))
        close = QPushButton("Zamknij")
        close.setDefault(True)
        close.clicked.connect(self.accept)
        buttons.addWidget(self._copy)
        buttons.addWidget(latest)
        buttons.addStretch(1)
        buttons.addWidget(close)
        lay.addLayout(buttons)

    def _copy_info(self) -> None:
        QGuiApplication.clipboard().setText(info_text(self._variant))
        self._copy.setText("Skopiowano ✓")


#: How each registered vault type is named in the menu (config.vault_list).
VAULT_LABELS = (("global", "vault główny"), ("vpn", "vault VPN"),
                ("private", "vault prywatny"))


def show_in_explorer(path: str) -> None:
    """Explorer opens the vault's folder with the vault file selected."""
    import subprocess
    subprocess.Popen(["explorer.exe", f"/select,{os.path.normpath(path)}"])


def vault_entries(own_path: str = "") -> list[tuple[str, str]]:
    """(menu text, path) of every vault that exists — the registered ones,
    or for Portable the one it opened (`own_path`)."""
    if own_path:
        return [(f"Pokaż vault ({os.path.basename(own_path)})", own_path)]             if os.path.isfile(own_path) else []
    from config import load_vault_list
    by_type = {v.get("type"): v.get("path", "") for v in load_vault_list()}
    return [(f"Pokaż {label} ({os.path.basename(by_type[t])})", by_type[t])
            for t, label in VAULT_LABELS if by_type.get(t)]


def add_info_menu(menu_bar, parent, variant: str = "", own_vault=None) -> QMenu:
    """The „Info” drop-down: about window, update check, where the vaults
    are.  `own_vault` (Portable) returns the path of the vault it opened."""
    menu = menu_bar.addMenu("Info")

    def rebuild():
        menu.clear()
        menu.addAction(f"O programie {app_version.APP_NAME}…",
                       lambda: AboutDialog(variant, parent).exec())
        menu.addAction("Sprawdź aktualizacje…", lambda: _check_updates(variant, parent))
        entries = vault_entries(own_vault() if own_vault else "")
        if entries:
            menu.addSeparator()
            for text, path in entries:
                act = menu.addAction(text, lambda p=path: show_in_explorer(p))
                act.setToolTip(path)
        menu.setToolTipsVisible(True)

    rebuild()
    menu.aboutToShow.connect(rebuild)
    return menu


def _check_updates(variant: str, parent) -> None:
    from ui.update_dialog import UpdateDialog
    UpdateDialog(variant or "V2", parent).exec()
