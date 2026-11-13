"""Opening a vault in HospitalHub Portable (2026-10-28).

The vault opened last time is remembered: the dialog then asks for its
password only, with "Zmień…" for another file (owner, 2026-10-28).  Without
one, the ``*.vault`` files of the program's folder are offered.  Only
hospital vaults open here (no VPN vaults).

Enter always means "Otwórz", never "Zamknij": the "Otwórz" button is
disabled while the vault decrypts, and Qt then handed the same Enter to the
next button — "Zamknij", which ended the program (owner, 2026-10-28).
"""

from __future__ import annotations

import glob
import os

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QApplication, QComboBox, QDialog, QFileDialog, QHBoxLayout, QLabel,
    QLineEdit, QPushButton, QVBoxLayout, QWidget,
)

import models
from crypto import decrypt
from vault_io import vault_kind_error

__all__ = ["RemoteLoginDialog", "candidate_vaults"]


def candidate_vaults(folder: str, last: str = "") -> list[str]:
    """The vault files to offer: the last one opened (if it still exists),
    then the ``*.vault`` files of `folder`, by name, without duplicates."""
    found = sorted(glob.glob(os.path.join(folder, "*.vault")),
                   key=lambda p: os.path.basename(p).lower()) if folder else []
    result = []
    for p in ([last] if last and os.path.isfile(last) else []) + found:
        key = os.path.normcase(os.path.abspath(p))
        if key not in {os.path.normcase(os.path.abspath(r)) for r in result}:
            result.append(p)
    return result


APP_NAME = "HospitalHub Portable"

_QSS = """
QDialog { background:#0d1117; }
QLabel#title { color:#e6edf3; font-size:20px; font-weight:bold; }
QLabel#vault { color:#8b949e; font-size:11px; }
QLabel#error { color:#f85149; font-size:11px; }
QLabel#caption { color:#8b949e; font-size:11px; }
QPushButton#change { background:transparent; border:none; color:#58a6ff;
    font-size:11px; padding:0 2px; }
QPushButton#change:hover { color:#79c0ff; text-decoration:underline; }
QLineEdit#password, QComboBox#file { background:#161b22; color:#e6edf3;
    border:1px solid #30363d; border-radius:8px; padding:8px 12px; font-size:13px; }
QLineEdit#password:focus, QComboBox#file:focus { border-color:#1f6feb; }
QPushButton#browse { background:#161b22; color:#c9d1d9; border:1px solid #30363d;
    border-radius:8px; padding:8px 12px; }
QPushButton#browse:hover { border-color:#58a6ff; }
QPushButton#open { background:#1f6feb; color:#ffffff; border:none;
    border-radius:8px; padding:10px; font-size:13px; font-weight:bold; }
QPushButton#open:hover { background:#388bfd; }
QPushButton#open:disabled { background:#1c2433; color:#8b949e; }
"""


class RemoteLoginDialog(QDialog):
    """Logo, name, password, "Otwórz" — the vault's name small, with
    "Zmień" for another file (owner, 2026-10-28: no technical look)."""

    def __init__(self, folder: str, last: str = "", parent=None):
        super().__init__(parent)
        self.setWindowTitle(APP_NAME)
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, False)
        self.setFixedWidth(380)
        self.setStyleSheet(_QSS)
        self._folder = folder
        self._result = None
        self._opening = False

        lay = QVBoxLayout(self)
        lay.setContentsMargins(36, 32, 36, 28)
        lay.setSpacing(0)

        logo = QLabel()
        logo.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon = QApplication.windowIcon()
        if not icon.isNull():
            logo.setPixmap(icon.pixmap(72, 72))
        lay.addWidget(logo)
        lay.addSpacing(12)

        title = QLabel(APP_NAME)
        title.setObjectName("title")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        lay.addWidget(title)
        lay.addSpacing(6)

        remembered = bool(last) and os.path.isfile(last)

        # The remembered vault: its name, small, and "Zmień".
        self._remembered_row = QWidget()
        rrow = QHBoxLayout(self._remembered_row)
        rrow.setContentsMargins(0, 0, 0, 0)
        rrow.setSpacing(4)
        rrow.addStretch()
        name = os.path.splitext(os.path.basename(last))[0] if remembered else ""
        self._remembered_lbl = QLabel(name)
        self._remembered_lbl.setObjectName("vault")
        self._remembered_lbl.setToolTip(last if remembered else "")
        rrow.addWidget(self._remembered_lbl)
        change = QPushButton("Zmień")
        change.setObjectName("change")
        change.setAutoDefault(False)
        change.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        change.setCursor(Qt.CursorShape.PointingHandCursor)
        change.clicked.connect(self._show_file_row)
        rrow.addWidget(change)
        rrow.addStretch()
        lay.addWidget(self._remembered_row)

        # No remembered vault (or "Zmień"): the files to choose from.
        self._file_row = QWidget()
        frow = QVBoxLayout(self._file_row)
        frow.setContentsMargins(0, 8, 0, 0)
        frow.setSpacing(6)
        caption = QLabel("Plik vaulta szpitala")
        caption.setObjectName("caption")
        frow.addWidget(caption)
        row = QHBoxLayout()
        row.setSpacing(6)
        self._combo = QComboBox()
        self._combo.setObjectName("file")
        for p in candidate_vaults(folder, last):
            self._combo.addItem(os.path.basename(p), p)
            self._combo.setItemData(self._combo.count() - 1, p,
                                    Qt.ItemDataRole.ToolTipRole)
        if self._combo.count() == 0:
            self._combo.setPlaceholderText("Brak plików .vault obok programu")
        row.addWidget(self._combo, 1)
        browse = QPushButton("Wybierz…")
        browse.setObjectName("browse")
        browse.setAutoDefault(False)
        browse.clicked.connect(self._browse)
        row.addWidget(browse)
        frow.addLayout(row)
        lay.addWidget(self._file_row)
        self._remembered_row.setVisible(remembered)
        self._file_row.setVisible(not remembered)

        lay.addSpacing(22)
        self._pass = QLineEdit()
        self._pass.setObjectName("password")
        self._pass.setEchoMode(QLineEdit.EchoMode.Password)
        self._pass.setPlaceholderText("Hasło")
        self._pass.textEdited.connect(lambda _t: self._show_error(""))
        lay.addWidget(self._pass)

        self._error = QLabel()
        self._error.setObjectName("error")
        self._error.setWordWrap(True)
        self._error.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._error.setVisible(False)
        lay.addSpacing(6)
        lay.addWidget(self._error)

        lay.addSpacing(12)
        self._open_btn = QPushButton("Otwórz")
        self._open_btn.setObjectName("open")
        self._open_btn.setAutoDefault(False)
        self._open_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._open_btn.clicked.connect(self._open)
        lay.addWidget(self._open_btn)

        self._pass.setFocus()

    def _show_error(self, text: str) -> None:
        self._error.setText(text)
        self._error.setVisible(bool(text))
        self.adjustSize()

    def keyPressEvent(self, event):
        # Enter is "Otwórz" here and nowhere else (see the module docstring).
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            event.accept()
            self._open()
            return
        super().keyPressEvent(event)

    def _show_file_row(self) -> None:
        self._remembered_row.setVisible(False)
        self._file_row.setVisible(True)
        self._combo.setFocus()

    def _browse(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Otwórz vault", self._folder,
            "Vault files (*.vault);;Wszystkie pliki (*)")
        if not path:
            return
        at = self._combo.findData(path)
        if at < 0:
            self._combo.insertItem(0, os.path.basename(path), path)
            self._combo.setItemData(0, path, Qt.ItemDataRole.ToolTipRole)
            at = 0
        self._combo.setCurrentIndex(at)
        self._pass.setFocus()

    def _open(self) -> None:
        if self._opening:
            return
        path = self._combo.currentData()
        password = self._pass.text()
        if not path:
            self._show_file_row()
            self._show_error("Wybierz plik vaulta.")
            return
        if not password:
            self._show_error("Podaj hasło.")
            return
        try:
            with open(path, "rb") as f:
                content = f.read()
        except OSError as e:
            self._show_error(f"Nie można odczytać pliku: {e}")
            return
        self._show_error("")
        # Argon2 takes a moment: show that first, then decrypt.
        self._opening = True
        self._set_busy(True)
        QTimer.singleShot(50, lambda: self._finish(path, password, content))

    def _set_busy(self, busy: bool) -> None:
        self._pass.setEnabled(not busy)
        self._open_btn.setEnabled(not busy)
        self._open_btn.setText("Otwieranie…" if busy else "Otwórz")

    def _finish(self, path: str, password: str, content: bytes) -> None:
        try:
            data = decrypt(content, password)
            error = vault_kind_error(data, "global")
            if error:
                raise ValueError(error)
        except ValueError as e:
            self._opening = False
            self._set_busy(False)
            self._show_error(str(e))
            self._pass.clear()
            self._pass.setFocus()
            return
        except Exception as e:
            self._opening = False
            self._set_busy(False)
            self._show_error(f"Nieoczekiwany błąd: {e}")
            return
        self._result = (path, password, models.from_dict(data),
                        data.get("admin_hash", ""), data.get("admin_salt", ""))
        self.accept()

    def get_result(self):
        return self._result


def _esc(text: str) -> str:
    return (text.replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))
