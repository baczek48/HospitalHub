import os
import sys

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QFileDialog, QMessageBox, QFormLayout, QStackedWidget,
    QApplication,
)
from PyQt6.QtCore import Qt, QSize
from PyQt6.QtGui import QFont

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crypto import encrypt, decrypt
import models
from config import load_last_vault, save_last_vault


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

        last_vault = load_last_vault()
        if last_vault:
            self._stack.addWidget(self._make_quick_page(last_vault))
            self._stack.addWidget(self._make_choose_page())
            self._stack.setCurrentIndex(0)
            self.setFixedSize(400, 340)
        else:
            self._stack.addWidget(self._make_choose_page())
            self._stack.setCurrentIndex(0)
            self.setFixedSize(400, 360)

    # ------------------------------------------------------------------ #
    # Quick login page                                                     #
    # ------------------------------------------------------------------ #

    def _make_quick_page(self, vault_path: str):
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

        layout.addSpacing(22)

        self._pass_edit = QLineEdit()
        self._pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._pass_edit.setPlaceholderText("Podaj hasło...")
        self._pass_edit.setMinimumHeight(40)
        self._pass_edit.setStyleSheet(
            "QLineEdit { background: #21262d; border: 1px solid #30363d; border-radius: 6px;"
            " padding: 0 14px; font-size: 13px; color: #c9d1d9; }"
            "QLineEdit:focus { border-color: #1f6feb; }"
        )
        self._pass_edit.returnPressed.connect(lambda: self._do_open(vault_path))
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
        btn_open.clicked.connect(lambda: self._do_open(vault_path))
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

    def _do_open(self, vault_path: str):
        password = self._pass_edit.text()
        if not password:
            QMessageBox.warning(self, "Błąd", "Podaj hasło.")
            return
        try:
            with open(vault_path, "rb") as f:
                content = f.read()
            data = decrypt(content, password)
            save_last_vault(vault_path)
            self._result = (vault_path, password, models.from_dict(data),
                            data.get("admin_hash", ""), data.get("admin_salt", ""))
            self.accept()
        except FileNotFoundError:
            QMessageBox.critical(self, "Błąd", "Plik vault nie istnieje.\nWybierz inny vault.")
        except ValueError as e:
            QMessageBox.critical(self, "Błąd uwierzytelniania", str(e))
            self._pass_edit.clear()
            self._pass_edit.setFocus()
        except Exception as e:
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
            save_last_vault(result[0])
            self._result = result
            self.accept()

    def _open_existing(self):
        dlg = _OpenVaultDialog(self)
        if dlg.exec():
            result = dlg.get_result()
            save_last_vault(result[0])
            self._result = result
            self.accept()

    def get_result(self):
        return self._result


# ------------------------------------------------------------------ #
# Sub-dialogs                                                         #
# ------------------------------------------------------------------ #

class _CreateVaultDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._result = None
        self.setWindowTitle("Utwórz nowy vault")
        self.setFixedSize(460, 240)
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

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

        data = {"hospitals": []}
        try:
            content = encrypt(data, password)
            with open(path, "wb") as f:
                f.write(content)
            self._result = (path, password, models.from_dict(data), "", "")
            self.accept()
        except Exception as e:
            QMessageBox.critical(self, "Błąd", f"Nie można utworzyć vault:\n{e}")

    def get_result(self):
        return self._result


class _OpenVaultDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._result = None
        self.setWindowTitle("Otwórz vault")
        self.setFixedSize(460, 190)
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

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
            self._result = (path, password, models.from_dict(data),
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
