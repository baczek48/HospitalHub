import os
import sys

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFileDialog, QMessageBox, QFormLayout, QStackedWidget,
    QApplication,
)
from PyQt6.QtCore import Qt, QSize, QTimer
from PyQt6.QtGui import QFont, QPixmap, QPainter, QColor, QIcon
from PyQt6.QtSvg import QSvgRenderer

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crypto import encrypt, decrypt
import models
from config import (load_last_vault, save_last_vault, load_vault_list,
                     register_vault, load_active_vault_index, save_active_vault_index)


def _svg_icon(svg_str: str, size: int = 24) -> QPixmap:
    renderer = QSvgRenderer(svg_str.encode())
    pm = QPixmap(size, size)
    pm.fill(QColor(0, 0, 0, 0))
    painter = QPainter(pm)
    renderer.render(painter)
    painter.end()
    return pm

_ICON_GLOBE = (
    '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">'
    '<circle cx="12" cy="12" r="9.5" stroke="#8b949e" stroke-width="1.6"/>'
    '<ellipse cx="12" cy="12" rx="4.5" ry="9.5" stroke="#8b949e" stroke-width="1.4"/>'
    '<line x1="2.5" y1="9" x2="21.5" y2="9" stroke="#8b949e" stroke-width="1.2"/>'
    '<line x1="2.5" y1="15" x2="21.5" y2="15" stroke="#8b949e" stroke-width="1.2"/>'
    '</svg>'
)

_ICON_LOCK = (
    '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">'
    '<rect x="5" y="11" width="14" height="10" rx="1.5" stroke="#8b949e" stroke-width="1.6"/>'
    '<path d="M8 11V8a4 4 0 1 1 8 0v3" stroke="#8b949e" stroke-width="1.6" stroke-linecap="round"/>'
    '<circle cx="12" cy="16" r="1.5" fill="#8b949e"/>'
    '</svg>'
)

_ICON_VPN = (
    '<svg viewBox="0 0 24 24" fill="none" xmlns="http://www.w3.org/2000/svg">'
    '<path d="M12 2L4 6v5c0 5.25 3.4 10.15 8 11.4 4.6-1.25 8-6.15 8-11.4V6L12 2z" '
    'stroke="#8b949e" stroke-width="1.5" stroke-linejoin="round" fill="none"/>'
    '<path d="M9 12h6M12 9v6" stroke="#8b949e" stroke-width="1.6" stroke-linecap="round"/>'
    '</svg>'
)

_VAULT_ICON_MAP = {"global": _ICON_GLOBE, "private": _ICON_LOCK, "vpn": _ICON_VPN}


class LoginDialog(QDialog):
    def __init__(self):
        super().__init__()
        self._result = None
        self.setWindowTitle("HospitalHub")
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, False)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self._stack = QStackedWidget()
        root.addWidget(self._stack)

        # Build vault list — migrate legacy single vault if needed
        self._vaults = load_vault_list()
        last_vault = load_last_vault()
        if last_vault and not self._vaults:
            register_vault(last_vault, "global", os.path.basename(last_vault))
            self._vaults = load_vault_list()

        if self._vaults:
            self._active_idx = min(load_active_vault_index(), len(self._vaults) - 1)
            self._stack.addWidget(self._make_quick_page())
            self._stack.addWidget(self._make_choose_page())
            self._stack.setCurrentIndex(0)
            self.setFixedSize(400, 340)
        else:
            self._active_idx = 0
            self._stack.addWidget(self._make_choose_page())
            self._stack.setCurrentIndex(0)
            self.setFixedSize(400, 360)

    # ------------------------------------------------------------------ #
    # Quick login page                                                     #
    # ------------------------------------------------------------------ #

    def _make_quick_page(self):
        page = self._make_page_widget()
        layout = QVBoxLayout(page)
        layout.setSpacing(0)
        layout.setContentsMargins(44, 28, 44, 24)

        # App logo
        app_icon = QApplication.instance().windowIcon()
        if not app_icon.isNull():
            icon_lbl = QLabel()
            icon_lbl.setPixmap(app_icon.pixmap(QSize(80, 80)))
            icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(icon_lbl)
        layout.addSpacing(10)

        title = QLabel("HospitalHub")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = QFont()
        font.setPointSize(22)
        font.setBold(True)
        title.setFont(font)
        title.setStyleSheet("color: #c9d1d9; letter-spacing: 1px;")
        layout.addWidget(title)

        layout.addSpacing(14)

        # Vault switcher — compact: just ◀ icon ▶
        if len(self._vaults) > 1:
            switcher = QHBoxLayout()
            switcher.setAlignment(Qt.AlignmentFlag.AlignCenter)
            switcher.setSpacing(6)

            btn_prev = QPushButton("◀")
            btn_prev.setFixedSize(28, 28)
            btn_prev.setCursor(Qt.CursorShape.PointingHandCursor)
            btn_prev.setStyleSheet(
                "QPushButton { background: transparent; color: #484f58; border: none;"
                " font-size: 12px; }"
                "QPushButton:hover { color: #c9d1d9; }"
            )
            btn_prev.clicked.connect(lambda: self._switch_vault(-1))
            switcher.addWidget(btn_prev)

            self._vault_icon_lbl = QLabel()
            self._vault_icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self._vault_icon_lbl.setFixedSize(28, 28)
            switcher.addWidget(self._vault_icon_lbl)

            btn_next = QPushButton("▶")
            btn_next.setFixedSize(28, 28)
            btn_next.setCursor(Qt.CursorShape.PointingHandCursor)
            btn_next.setStyleSheet(
                "QPushButton { background: transparent; color: #484f58; border: none;"
                " font-size: 12px; }"
                "QPushButton:hover { color: #c9d1d9; }"
            )
            btn_next.clicked.connect(lambda: self._switch_vault(1))
            switcher.addWidget(btn_next)

            layout.addLayout(switcher)
            self._update_vault_display()

        layout.addSpacing(14)

        self._pass_edit = QLineEdit()
        self._pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._pass_edit.setPlaceholderText("Podaj hasło...")
        self._pass_edit.setMinimumHeight(40)
        self._pass_edit.setStyleSheet(
            "QLineEdit { background: #21262d; border: 1px solid #30363d; border-radius: 6px;"
            " padding: 0 14px; font-size: 13px; color: #c9d1d9; }"
            "QLineEdit:focus { border-color: #1f6feb; }"
        )
        self._pass_edit.returnPressed.connect(self._do_open_active)
        layout.addWidget(self._pass_edit)

        layout.addSpacing(8)

        btn_open = QPushButton("Zaloguj się")
        btn_open.setMinimumHeight(42)
        btn_open.setDefault(True)
        btn_open.setStyleSheet(
            "QPushButton { background: #1f6feb; color: #fff; border: none; border-radius: 6px;"
            " font-size: 13px; font-weight: bold; }"
            "QPushButton:hover { background: #388bfd; }"
            "QPushButton:pressed { background: #1158c7; }"
        )
        btn_open.clicked.connect(self._do_open_active)
        layout.addWidget(btn_open)

        layout.addStretch()

        btn_change = QPushButton("Zmień vault lub utwórz nowy")
        btn_change.setStyleSheet(
            "QPushButton { color: #6e7681; font-size: 10px; border: none;"
            " background: transparent; }"
            "QPushButton:hover { color: #8b949e; }"
        )
        btn_change.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_change.clicked.connect(self._switch_to_choose)
        layout.addWidget(btn_change, alignment=Qt.AlignmentFlag.AlignCenter)

        self._pass_edit.setFocus()
        return page

    def _switch_vault(self, direction: int):
        if not self._vaults:
            return
        self._active_idx = (self._active_idx + direction) % len(self._vaults)
        save_active_vault_index(self._active_idx)
        self._update_vault_display()
        self._pass_edit.clear()
        self._pass_edit.setFocus()

    def _update_vault_display(self):
        v = self._vaults[self._active_idx]
        svg = _VAULT_ICON_MAP.get(v.get("type", "global"), _ICON_GLOBE)
        self._vault_icon_lbl.setPixmap(_svg_icon(svg, 22))

    def _do_open_active(self):
        vault_path = self._vaults[self._active_idx]["path"]
        self._do_open(vault_path)

    def _do_open(self, vault_path: str):
        if getattr(self, '_opening', False):
            return
        password = self._pass_edit.text()
        if not password:
            QMessageBox.warning(self, "Błąd", "Podaj hasło.")
            return
        try:
            content = open(vault_path, "rb").read()
        except FileNotFoundError:
            QMessageBox.critical(self, "Błąd", "Plik vault nie istnieje.\nWybierz inny vault.")
            return

        # Show visual feedback, then defer decrypt so the UI repaints first.
        # Argon2 key derivation takes 1-4s depending on hardware.
        self._opening = True
        self._pass_edit.setEnabled(False)
        self._pass_edit.clear()
        self._pass_edit.setPlaceholderText("Odszyfrowywanie...")
        QTimer.singleShot(50, lambda: self._finish_open(vault_path, password, content))

    def _finish_open(self, vault_path: str, password: str, content: bytes):
        try:
            data = decrypt(content, password)
            save_last_vault(vault_path)
            vtype = self._vaults[self._active_idx].get("type", "global") if self._vaults else "global"
            items = models.vpn_from_dict(data) if vtype == "vpn" else models.from_dict(data)
            self._result = (vault_path, password, items,
                            data.get("admin_hash", ""), data.get("admin_salt", ""), vtype)
            self.accept()
        except FileNotFoundError:
            self._opening = False
            self._pass_edit.setEnabled(True)
            self._pass_edit.setPlaceholderText("Podaj haslo...")
            QMessageBox.critical(self, "Błąd", "Plik vault nie istnieje.\nWybierz inny vault.")
        except ValueError as e:
            self._opening = False
            self._pass_edit.setEnabled(True)
            self._pass_edit.setPlaceholderText("Podaj haslo...")
            QMessageBox.critical(self, "Błąd uwierzytelniania", str(e))
            self._pass_edit.clear()
            self._pass_edit.setFocus()
        except Exception as e:
            self._opening = False
            self._pass_edit.setEnabled(True)
            self._pass_edit.setPlaceholderText("Podaj haslo...")
            QMessageBox.critical(self, "Błąd", f"Nieoczekiwany błąd: {e}")

    def _switch_to_choose(self):
        self.setFixedSize(400, 360)
        self._stack.setCurrentIndex(self._stack.count() - 1)

    # ------------------------------------------------------------------ #
    # Choose page                                                          #
    # ------------------------------------------------------------------ #

    def _make_choose_page(self):
        page = self._make_page_widget()
        layout = QVBoxLayout(page)
        layout.setSpacing(0)
        layout.setContentsMargins(44, 28, 44, 28)

        # App logo
        app_icon = QApplication.instance().windowIcon()
        if not app_icon.isNull():
            icon_lbl = QLabel()
            icon_lbl.setPixmap(app_icon.pixmap(QSize(80, 80)))
            icon_lbl.setAlignment(Qt.AlignmentFlag.AlignCenter)
            layout.addWidget(icon_lbl)
        layout.addSpacing(10)

        title = QLabel("HospitalHub")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        font = QFont()
        font.setPointSize(22)
        font.setBold(True)
        title.setFont(font)
        title.setStyleSheet("color: #c9d1d9; letter-spacing: 1px;")
        layout.addWidget(title)

        subtitle = QLabel("Menedżer danych infrastruktury IT")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle.setStyleSheet("color: #6e7681; font-size: 11px; padding: 4px 0 0 0;")
        layout.addWidget(subtitle)

        layout.addSpacing(22)

        btn_new = QPushButton("Utwórz nowy vault")
        btn_new.setMinimumHeight(44)
        btn_new.setStyleSheet(
            "QPushButton { background: #1f6feb; color: #fff; border: none; border-radius: 6px;"
            " font-size: 13px; }"
            "QPushButton:hover { background: #388bfd; }"
            "QPushButton:pressed { background: #1158c7; }"
        )
        btn_new.clicked.connect(self._create_new)
        layout.addWidget(btn_new)

        layout.addSpacing(8)

        btn_open = QPushButton("Otwórz istniejący vault")
        btn_open.setMinimumHeight(44)
        btn_open.setStyleSheet(
            "QPushButton { background: #21262d; color: #c9d1d9; border: 1px solid #30363d;"
            " border-radius: 6px; font-size: 13px; }"
            "QPushButton:hover { background: #30363d; }"
        )
        btn_open.clicked.connect(self._open_existing)
        layout.addWidget(btn_open)

        layout.addStretch()
        return page

    @staticmethod
    def _make_page_widget():
        from PyQt6.QtWidgets import QWidget
        return QWidget()

    def _create_new(self):
        dlg = _CreateVaultDialog(self)
        if dlg.exec():
            result = dlg.get_result()
            vault_type = dlg.get_vault_type()
            save_last_vault(result[0])
            register_vault(result[0], vault_type)
            self._set_active_by_path(result[0])
            self._result = result + (vault_type,)
            self.accept()

    def _open_existing(self):
        dlg = _OpenVaultDialog(self)
        if dlg.exec():
            result = dlg.get_result()
            vault_type = dlg.get_vault_type()
            save_last_vault(result[0])
            register_vault(result[0], vault_type)
            self._set_active_by_path(result[0])
            self._result = result + (vault_type,)
            self.accept()

    def _set_active_by_path(self, path: str):
        from config import load_vault_list
        normed = os.path.normpath(path)
        for i, v in enumerate(load_vault_list()):
            if os.path.normpath(v["path"]) == normed:
                save_active_vault_index(i)
                return

    def get_result(self):
        return self._result


# ------------------------------------------------------------------ #
# Sub-dialogs                                                         #
# ------------------------------------------------------------------ #

class _CreateVaultDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._result = None
        self._vault_type = "global"
        self.setWindowTitle("Utwórz nowy vault")
        self.setFixedSize(460, 290)
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        # Vault type selector
        type_row = QHBoxLayout()
        type_row.setSpacing(8)
        self._btn_global = QPushButton("Ogólny")
        self._btn_global.setIcon(QIcon(_svg_icon(_ICON_GLOBE, 18)))
        self._btn_global.setMinimumHeight(36)
        self._btn_global.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_global.clicked.connect(lambda: self._set_vault_type("global"))
        type_row.addWidget(self._btn_global)

        self._btn_private = QPushButton("Prywatny")
        self._btn_private.setIcon(QIcon(_svg_icon(_ICON_LOCK, 18)))
        self._btn_private.setMinimumHeight(36)
        self._btn_private.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_private.clicked.connect(lambda: self._set_vault_type("private"))
        type_row.addWidget(self._btn_private)

        self._btn_vpn = QPushButton("VPN")
        self._btn_vpn.setIcon(QIcon(_svg_icon(_ICON_VPN, 18)))
        self._btn_vpn.setMinimumHeight(36)
        self._btn_vpn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_vpn.clicked.connect(lambda: self._set_vault_type("vpn"))
        type_row.addWidget(self._btn_vpn)

        layout.addLayout(type_row)
        self._update_type_buttons()

        form = QFormLayout()
        form.setSpacing(8)

        path_row = QHBoxLayout()
        self._path_edit = QLineEdit()
        self._path_edit.setPlaceholderText("Wybierz lokalizację pliku...")
        path_row.addWidget(self._path_edit)
        btn_browse = QPushButton("Przeglądaj")
        btn_browse.setMaximumWidth(100)
        btn_browse.clicked.connect(self._browse)
        path_row.addWidget(btn_browse)
        form.addRow("Lokalizacja:", path_row)

        self._pass_edit = QLineEdit()
        self._pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._pass_edit.setPlaceholderText("Minimum 8 znaków")
        form.addRow("Hasło główne:", self._pass_edit)

        self._pass_confirm = QLineEdit()
        self._pass_confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self._pass_confirm.setPlaceholderText("Powtórz hasło")
        self._pass_confirm.returnPressed.connect(self._create)
        form.addRow("Potwierdź hasło:", self._pass_confirm)

        layout.addLayout(form)
        layout.addStretch()

        btn_row = QHBoxLayout()
        btn_cancel = QPushButton("Anuluj")
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)
        btn_create = QPushButton("Utwórz vault")
        btn_create.setDefault(True)
        btn_create.clicked.connect(self._create)
        btn_row.addWidget(btn_create)
        layout.addLayout(btn_row)

    def _set_vault_type(self, vtype: str):
        self._vault_type = vtype
        self._update_type_buttons()

    def _update_type_buttons(self):
        active = (
            "QPushButton { background: #1f6feb; color: #fff; border: none; border-radius: 6px;"
            " font-size: 12px; font-weight: bold; }"
        )
        inactive = (
            "QPushButton { background: #21262d; color: #8b949e; border: 1px solid #30363d;"
            " border-radius: 6px; font-size: 12px; }"
            "QPushButton:hover { background: #30363d; }"
        )
        for btn, vtype in [(self._btn_global, "global"), (self._btn_private, "private"), (self._btn_vpn, "vpn")]:
            btn.setStyleSheet(active if self._vault_type == vtype else inactive)

    def _browse(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Utwórz vault", "", "Vault files (*.vault);;Wszystkie pliki (*)"
        )
        if path:
            if not path.endswith(".vault"):
                path += ".vault"
            self._path_edit.setText(path)

    def _create(self):
        path = self._path_edit.text().strip()
        password = self._pass_edit.text()
        confirm = self._pass_confirm.text()

        if not path:
            QMessageBox.warning(self, "Błąd", "Wybierz lokalizację pliku.")
            return
        if len(password) < 8:
            QMessageBox.warning(self, "Błąd", "Hasło musi mieć minimum 8 znaków.")
            return
        if password != confirm:
            QMessageBox.warning(self, "Błąd", "Hasła nie są identyczne.")
            return

        if self._vault_type == "vpn":
            data = {"vpn_profiles": []}
        else:
            data = {"hospitals": []}
        try:
            content = encrypt(data, password)
            with open(path, "wb") as f:
                f.write(content)
            if self._vault_type == "vpn":
                self._result = (path, password, models.vpn_from_dict(data), "", "")
            else:
                self._result = (path, password, models.from_dict(data), "", "")
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Nie można utworzyć vault:\n{e}")

    def get_result(self):
        return self._result

    def get_vault_type(self):
        return self._vault_type


class _OpenVaultDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._result = None
        self._vault_type = "global"
        self.setWindowTitle("Otwórz vault")
        self.setFixedSize(460, 240)
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        # Vault type selector
        type_row = QHBoxLayout()
        type_row.setSpacing(8)
        self._btn_global = QPushButton("Ogólny")
        self._btn_global.setIcon(QIcon(_svg_icon(_ICON_GLOBE, 18)))
        self._btn_global.setMinimumHeight(36)
        self._btn_global.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_global.clicked.connect(lambda: self._set_vault_type("global"))
        type_row.addWidget(self._btn_global)

        self._btn_private = QPushButton("Prywatny")
        self._btn_private.setIcon(QIcon(_svg_icon(_ICON_LOCK, 18)))
        self._btn_private.setMinimumHeight(36)
        self._btn_private.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_private.clicked.connect(lambda: self._set_vault_type("private"))
        type_row.addWidget(self._btn_private)

        self._btn_vpn = QPushButton("VPN")
        self._btn_vpn.setIcon(QIcon(_svg_icon(_ICON_VPN, 18)))
        self._btn_vpn.setMinimumHeight(36)
        self._btn_vpn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._btn_vpn.clicked.connect(lambda: self._set_vault_type("vpn"))
        type_row.addWidget(self._btn_vpn)

        layout.addLayout(type_row)
        self._update_type_buttons()

        form = QFormLayout()
        form.setSpacing(8)

        path_row = QHBoxLayout()
        self._path_edit = QLineEdit()
        self._path_edit.setPlaceholderText("Wybierz plik vault...")
        path_row.addWidget(self._path_edit)
        btn_browse = QPushButton("Przeglądaj")
        btn_browse.setMaximumWidth(100)
        btn_browse.clicked.connect(self._browse)
        path_row.addWidget(btn_browse)
        form.addRow("Plik vault:", path_row)

        self._pass_edit = QLineEdit()
        self._pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._pass_edit.returnPressed.connect(self._open)
        form.addRow("Hasło główne:", self._pass_edit)

        layout.addLayout(form)
        layout.addStretch()

        btn_row = QHBoxLayout()
        btn_cancel = QPushButton("Anuluj")
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)
        btn_open = QPushButton("Otwórz")
        btn_open.setDefault(True)
        btn_open.clicked.connect(self._open)
        btn_row.addWidget(btn_open)
        layout.addLayout(btn_row)

    def _set_vault_type(self, vtype: str):
        self._vault_type = vtype
        self._update_type_buttons()

    def _update_type_buttons(self):
        active = (
            "QPushButton { background: #1f6feb; color: #fff; border: none; border-radius: 6px;"
            " font-size: 12px; font-weight: bold; }"
        )
        inactive = (
            "QPushButton { background: #21262d; color: #8b949e; border: 1px solid #30363d;"
            " border-radius: 6px; font-size: 12px; }"
            "QPushButton:hover { background: #30363d; }"
        )
        for btn, vtype in [(self._btn_global, "global"), (self._btn_private, "private"), (self._btn_vpn, "vpn")]:
            btn.setStyleSheet(active if self._vault_type == vtype else inactive)

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Otwórz vault", "", "Vault files (*.vault);;Wszystkie pliki (*)"
        )
        if path:
            self._path_edit.setText(path)

    def _open(self):
        path = self._path_edit.text().strip()
        password = self._pass_edit.text()

        if not path:
            QMessageBox.warning(self, "Błąd", "Wybierz plik vault.")
            return
        if not password:
            QMessageBox.warning(self, "Błąd", "Podaj hasło.")
            return

        try:
            with open(path, "rb") as f:
                content = f.read()
            data = decrypt(content, password)
            if self._vault_type == "vpn":
                items = models.vpn_from_dict(data)
            else:
                items = models.from_dict(data)
            self._result = (path, password, items,
                            data.get("admin_hash", ""), data.get("admin_salt", ""))
            self.accept()
        except FileNotFoundError:
            QMessageBox.critical(self, "Błąd", "Plik nie istnieje.")
        except ValueError as e:
            QMessageBox.critical(self, "Błąd uwierzytelniania", str(e))
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Nieoczekiwany błąd: {e}")

    def get_result(self):
        return self._result

    def get_vault_type(self):
        return self._vault_type

