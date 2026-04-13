import copy

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QComboBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QFormLayout, QMessageBox,
    QApplication, QCheckBox, QWidget,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QIntValidator

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import models
from ui.utils import confirm

_CLIPBOARD_CLEAR_MS = 15_000   # auto-clear password after 15 s


def _clipboard_copy(text: str) -> None:
    """Copy text to clipboard and schedule automatic clearing after 15 s."""
    cb = QApplication.clipboard()
    cb.setText(text)
    QTimer.singleShot(_CLIPBOARD_CLEAR_MS,
                      lambda: cb.clear() if cb.text() == text else None)


class HospitalDialog(QDialog):
    def __init__(self, parent=None, name: str = ""):
        super().__init__(parent)
        self._name = name
        self.setWindowTitle("Szpital")
        self.setFixedSize(380, 130)
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        layout.addWidget(QLabel("Nazwa szpitala:"))
        self._name_edit = QLineEdit(name)
        self._name_edit.setPlaceholderText("np. Szpital Miejski Kraków")
        self._name_edit.returnPressed.connect(self._accept)
        layout.addWidget(self._name_edit)

        btn_row = QHBoxLayout()
        btn_cancel = QPushButton("Anuluj")
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)
        btn_ok = QPushButton("OK")
        btn_ok.setDefault(True)
        btn_ok.clicked.connect(self._accept)
        btn_row.addWidget(btn_ok)
        layout.addLayout(btn_row)

    def _accept(self):
        name = self._name_edit.text().strip()
        if not name:
            QMessageBox.warning(self, "Błąd", "Podaj nazwę szpitala.")
            return
        self._name = name
        self.accept()

    def get_name(self) -> str:
        return self._name


class CredentialDialog(QDialog):
    def __init__(self, parent=None, credential: models.Credential = None,
                 admin_mode: bool = False):
        super().__init__(parent)
        self._cred = copy.deepcopy(credential) if credential else models.Credential()
        self._admin_mode = admin_mode
        self.setWindowTitle("Poświadczenie")
        self.setFixedSize(400, 230 if admin_mode else 200)
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(8)

        form = QFormLayout()
        form.setSpacing(8)

        self._login_edit = QLineEdit(self._cred.login)
        self._login_edit.setPlaceholderText("Login / użytkownik")
        form.addRow("Login:", self._login_edit)

        pass_row = QHBoxLayout()
        self._pass_edit = QLineEdit(self._cred.password)
        self._pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        pass_row.addWidget(self._pass_edit)
        btn_show = QPushButton("Pokaż")
        btn_show.setMaximumWidth(70)
        btn_show.setCheckable(True)
        btn_show.toggled.connect(
            lambda checked: self._pass_edit.setEchoMode(
                QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password
            )
        )
        pass_row.addWidget(btn_show)
        form.addRow("Hasło:", pass_row)

        self._note_edit = QLineEdit(self._cred.note)
        self._note_edit.setPlaceholderText("np. konto serwisowe, konto admina")
        form.addRow("Notatka:", self._note_edit)

        if self._admin_mode:
            self._admin_cb = QCheckBox("Tylko admin (ukryte bez odblokowania)")
            self._admin_cb.setChecked(self._cred.admin_only)
            form.addRow("", self._admin_cb)

        layout.addLayout(form)
        layout.addStretch()

        btn_row = QHBoxLayout()
        btn_cancel = QPushButton("Anuluj")
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)
        btn_ok = QPushButton("Zapisz")
        btn_ok.setDefault(True)
        btn_ok.clicked.connect(self._accept)
        btn_row.addWidget(btn_ok)
        layout.addLayout(btn_row)

    def _accept(self):
        login = self._login_edit.text().strip()
        if not login:
            QMessageBox.warning(self, "Błąd", "Podaj login.")
            return
        self._cred.login = login
        self._cred.password = self._pass_edit.text()
        self._cred.note = self._note_edit.text().strip()
        if self._admin_mode:
            self._cred.admin_only = self._admin_cb.isChecked()
        self.accept()

    def get_credential(self) -> models.Credential:
        return self._cred


class MachineDialog(QDialog):
    def __init__(self, parent=None, machine: models.Machine = None,
                 admin_mode: bool = False):
        super().__init__(parent)
        self._machine = copy.deepcopy(machine) if machine else models.Machine()
        self._admin_mode = admin_mode
        self.setWindowTitle("Maszyna / Host")
        self.setMinimumSize(560, 460)
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        self._form = QFormLayout()
        self._form.setSpacing(8)

        self._ip_edit = QLineEdit(self._machine.ip)
        self._ip_edit.setPlaceholderText("np. 192.168.1.100")
        self._form.addRow("Adres IP:", self._ip_edit)

        self._name_edit = QLineEdit(self._machine.name)
        self._name_edit.setPlaceholderText("np. PROD-APP-01, serwer-integracji")
        self._form.addRow("Nazwa:", self._name_edit)

        self._desc_edit = QLineEdit(self._machine.description)
        self._desc_edit.setPlaceholderText("np. Usługi integracyjne — Tomcat/Apache, Wildfly")
        self._form.addRow("Opis:", self._desc_edit)

        # Admin only — visible only in admin mode
        if self._admin_mode:
            self._admin_cb = QCheckBox("Tylko admin (ukryta bez odblokowania)")
            self._admin_cb.setChecked(self._machine.admin_only)
            self._form.addRow("", self._admin_cb)

        # Connection type
        self._type_combo = QComboBox()
        self._type_combo.addItems(["SSH", "RDP", "WWW"])
        idx = self._type_combo.findText(self._machine.connection_type)
        self._type_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self._type_combo.currentTextChanged.connect(self._on_type_changed)
        self._form.addRow("Typ połączenia:", self._type_combo)

        # WWW URL — visible only when WWW is selected
        self._www_url_edit = QLineEdit(self._machine.www_url or "")
        self._www_url_edit.setPlaceholderText("https://pam.example.com/session/123")
        self._form.addRow("URL:", self._www_url_edit)

        # RDP port — visible only when RDP is selected
        self._rdp_port_edit = QLineEdit(self._machine.rdp_port or "3389")
        self._rdp_port_edit.setPlaceholderText("3389")
        self._rdp_port_edit.setMaximumWidth(100)
        self._rdp_port_edit.setValidator(QIntValidator(1, 65535, self))
        self._form.addRow("Port RDP:", self._rdp_port_edit)
        self._rdp_port_row = self._form.rowCount() - 1   # index of the row just added

        # RDP drive mapping — detect local drives and show checkboxes
        self._rdp_drive_widget = QWidget()
        drive_lay = QHBoxLayout(self._rdp_drive_widget)
        drive_lay.setContentsMargins(0, 0, 0, 0)
        drive_lay.setSpacing(12)
        self._drive_checkboxes: list[QCheckBox] = []
        saved = set(self._machine.rdp_drives)
        for letter in self._detect_drives():
            cb = QCheckBox(letter)
            cb.setChecked(letter in saved)
            self._drive_checkboxes.append(cb)
            drive_lay.addWidget(cb)
        drive_lay.addStretch()
        self._rdp_drive_label = QLabel("Dyski:")
        self._form.addRow(self._rdp_drive_label, self._rdp_drive_widget)

        # Set initial visibility
        self._on_type_changed(self._type_combo.currentText())

        layout.addLayout(self._form)

        layout.addWidget(QLabel("Poświadczenia (login + hasło):"))

        self._cred_table = QTableWidget(0, 3)
        self._cred_table.setHorizontalHeaderLabels(["Login", "Notatka", "Akcje"])
        self._cred_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self._cred_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self._cred_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents
        )
        self._cred_table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self._cred_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._cred_table.verticalHeader().setVisible(False)
        self._cred_table.setAlternatingRowColors(True)
        layout.addWidget(self._cred_table)

        btn_add_cred = QPushButton("+ Dodaj poświadczenie")
        btn_add_cred.setMaximumWidth(210)
        btn_add_cred.clicked.connect(self._add_credential)
        layout.addWidget(btn_add_cred)

        layout.addStretch()

        btn_row = QHBoxLayout()
        btn_cancel = QPushButton("Anuluj")
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)
        btn_ok = QPushButton("Zapisz maszynę")
        btn_ok.setDefault(True)
        btn_ok.clicked.connect(self._accept)
        btn_row.addWidget(btn_ok)
        layout.addLayout(btn_row)

        self._refresh_credentials()

    def _visible_creds(self):
        if self._admin_mode:
            return self._machine.credentials
        return [c for c in self._machine.credentials if not c.admin_only]

    def _refresh_credentials(self):
        self._cred_table.setRowCount(0)
        for i, cred in enumerate(self._visible_creds()):
            self._cred_table.insertRow(i)
            prefix = "🔒 " if cred.admin_only else ""
            self._cred_table.setItem(i, 0, QTableWidgetItem(prefix + cred.login))
            self._cred_table.setItem(i, 1, QTableWidgetItem(cred.note))
            self._cred_table.setCellWidget(i, 2, self._make_cred_actions(cred))
            self._cred_table.setRowHeight(i, 36)

    def _make_cred_actions(self, cred: models.Credential):
        from PyQt6.QtWidgets import QWidget
        w = QWidget()
        row = QHBoxLayout(w)
        row.setContentsMargins(4, 2, 4, 2)
        row.setSpacing(4)

        btn_copy = QPushButton("Kopiuj hasło")
        btn_copy.clicked.connect(lambda _, c=cred: _clipboard_copy(c.password))
        row.addWidget(btn_copy)

        btn_edit = QPushButton("Edytuj")
        btn_edit.setMaximumWidth(68)
        btn_edit.clicked.connect(lambda _, c=cred: self._edit_credential(c))
        row.addWidget(btn_edit)

        btn_del = QPushButton("Usuń")
        btn_del.setMaximumWidth(58)
        btn_del.setStyleSheet("color: #c0392b;")
        btn_del.clicked.connect(lambda _, c=cred: self._delete_credential(c))
        row.addWidget(btn_del)

        return w

    def _add_credential(self):
        dlg = CredentialDialog(self, admin_mode=self._admin_mode)
        if dlg.exec():
            self._machine.credentials.append(dlg.get_credential())
            self._refresh_credentials()

    def _edit_credential(self, cred: models.Credential):
        dlg = CredentialDialog(self, cred, admin_mode=self._admin_mode)
        if dlg.exec():
            updated = dlg.get_credential()
            cred.login = updated.login
            cred.password = updated.password
            cred.note = updated.note
            cred.admin_only = updated.admin_only
            self._refresh_credentials()

    def _delete_credential(self, cred: models.Credential):
        if confirm(self, "Usuń poświadczenie", f"Usunąć poświadczenie '{cred.login}'?"):
            self._machine.credentials.remove(cred)
            self._refresh_credentials()

    def _on_type_changed(self, text: str) -> None:
        is_rdp = text == "RDP"
        is_www = text == "WWW"
        self._rdp_port_edit.setVisible(is_rdp)
        lbl = self._form.labelForField(self._rdp_port_edit)
        if lbl:
            lbl.setVisible(is_rdp)
        self._rdp_drive_widget.setVisible(is_rdp)
        self._rdp_drive_label.setVisible(is_rdp)
        self._www_url_edit.setVisible(is_www)
        lbl_www = self._form.labelForField(self._www_url_edit)
        if lbl_www:
            lbl_www.setVisible(is_www)

    @staticmethod
    def _detect_drives() -> list[str]:
        """Return list of drive letters present on this machine, e.g. ['C:', 'D:']."""
        drives = []
        if sys.platform == 'win32':
            import ctypes
            bitmask = ctypes.windll.kernel32.GetLogicalDrives()
            for i in range(26):
                if bitmask & (1 << i):
                    drives.append(f"{chr(65 + i)}:")
        return drives

    def _accept(self):
        ip = self._ip_edit.text().strip()
        conn_type = self._type_combo.currentText()
        if not ip and conn_type == "WWW" and not self._www_url_edit.text().strip():
            QMessageBox.warning(self, "Błąd", "Podaj adres IP lub URL.")
            return
        elif not ip and conn_type != "WWW":
            QMessageBox.warning(self, "Błąd", "Podaj adres IP maszyny.")
            return
        self._machine.ip = ip
        self._machine.name = self._name_edit.text().strip()
        self._machine.description = self._desc_edit.text().strip()
        self._machine.connection_type = self._type_combo.currentText()
        self._machine.rdp_port = self._rdp_port_edit.text().strip() or "3389"
        self._machine.rdp_drives = [cb.text() for cb in self._drive_checkboxes if cb.isChecked()]
        self._machine.www_url = self._www_url_edit.text().strip()
        if self._admin_mode:
            self._machine.admin_only = self._admin_cb.isChecked()
        self.accept()

    def get_machine(self) -> models.Machine:
        return self._machine


class DatabaseDialog(QDialog):
    def __init__(self, parent=None, database: models.Database = None,
                 admin_mode: bool = False):
        super().__init__(parent)
        self._db = copy.deepcopy(database) if database else models.Database()
        self._admin_mode = admin_mode
        self.setWindowTitle("Baza danych")
        self.setMinimumSize(520, 480)
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(8)

        form = QFormLayout()
        form.setSpacing(8)

        self._host_edit = QLineEdit(self._db.host)
        self._host_edit.setPlaceholderText("np. 192.168.1.200 lub db.serwer.local")
        form.addRow("Host:", self._host_edit)

        _is_new = database is None
        self._port_edit = QLineEdit("1521" if _is_new else str(self._db.port))
        self._port_edit.setPlaceholderText("np. 1521")
        form.addRow("Port:", self._port_edit)

        self._name_edit = QLineEdit(self._db.name)
        self._name_edit.setPlaceholderText("np. HIS_PROD, AP_DB")
        form.addRow("Nazwa bazy:", self._name_edit)

        self._type_combo = QComboBox()
        self._type_combo.addItems(["Oracle", "MSSQL", "PostgreSQL", "MySQL", "MariaDB", "Inne"])
        if _is_new:
            self._type_combo.setCurrentIndex(0)
        else:
            idx = self._type_combo.findText(self._db.db_type)
            if idx >= 0:
                self._type_combo.setCurrentIndex(idx)
        form.addRow("Typ:", self._type_combo)

        self._note_edit = QLineEdit(self._db.note)
        self._note_edit.setPlaceholderText("Opcjonalna notatka")
        form.addRow("Notatka:", self._note_edit)

        if self._admin_mode:
            self._admin_cb = QCheckBox("Tylko admin (ukryta bez odblokowania)")
            self._admin_cb.setChecked(self._db.admin_only)
            form.addRow("", self._admin_cb)

        layout.addLayout(form)

        layout.addWidget(QLabel("Poświadczenia (login + hasło):"))

        self._cred_table = QTableWidget(0, 3)
        self._cred_table.setHorizontalHeaderLabels(["Login", "Notatka", "Akcje"])
        self._cred_table.horizontalHeader().setSectionResizeMode(
            0, QHeaderView.ResizeMode.ResizeToContents
        )
        self._cred_table.horizontalHeader().setSectionResizeMode(
            1, QHeaderView.ResizeMode.Stretch
        )
        self._cred_table.horizontalHeader().setSectionResizeMode(
            2, QHeaderView.ResizeMode.ResizeToContents
        )
        self._cred_table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
        self._cred_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._cred_table.verticalHeader().setVisible(False)
        self._cred_table.setAlternatingRowColors(True)
        layout.addWidget(self._cred_table)

        btn_add_cred = QPushButton("+ Dodaj poświadczenie")
        btn_add_cred.setMaximumWidth(210)
        btn_add_cred.clicked.connect(self._add_credential)
        layout.addWidget(btn_add_cred)

        layout.addStretch()

        btn_row = QHBoxLayout()
        btn_cancel = QPushButton("Anuluj")
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)
        btn_ok = QPushButton("Zapisz bazę")
        btn_ok.setDefault(True)
        btn_ok.clicked.connect(self._accept)
        btn_row.addWidget(btn_ok)
        layout.addLayout(btn_row)

        self._refresh_credentials()

    def _visible_creds(self):
        if self._admin_mode:
            return self._db.credentials
        return [c for c in self._db.credentials if not c.admin_only]

    def _refresh_credentials(self):
        self._cred_table.setRowCount(0)
        for i, cred in enumerate(self._visible_creds()):
            self._cred_table.insertRow(i)
            prefix = "🔒 " if cred.admin_only else ""
            self._cred_table.setItem(i, 0, QTableWidgetItem(prefix + cred.login))
            self._cred_table.setItem(i, 1, QTableWidgetItem(cred.note))
            self._cred_table.setCellWidget(i, 2, self._make_cred_actions(cred))
            self._cred_table.setRowHeight(i, 36)

    def _make_cred_actions(self, cred: models.Credential):
        from PyQt6.QtWidgets import QWidget
        w = QWidget()
        row = QHBoxLayout(w)
        row.setContentsMargins(4, 2, 4, 2)
        row.setSpacing(4)

        btn_copy = QPushButton("Kopiuj hasło")
        btn_copy.clicked.connect(lambda _, c=cred: _clipboard_copy(c.password))
        row.addWidget(btn_copy)

        btn_edit = QPushButton("Edytuj")
        btn_edit.setMaximumWidth(68)
        btn_edit.clicked.connect(lambda _, c=cred: self._edit_credential(c))
        row.addWidget(btn_edit)

        btn_del = QPushButton("Usuń")
        btn_del.setMaximumWidth(58)
        btn_del.setStyleSheet("color: #c0392b;")
        btn_del.clicked.connect(lambda _, c=cred: self._delete_credential(c))
        row.addWidget(btn_del)

        return w

    def _add_credential(self):
        dlg = CredentialDialog(self, admin_mode=self._admin_mode)
        if dlg.exec():
            self._db.credentials.append(dlg.get_credential())
            self._refresh_credentials()

    def _edit_credential(self, cred: models.Credential):
        dlg = CredentialDialog(self, cred, admin_mode=self._admin_mode)
        if dlg.exec():
            updated = dlg.get_credential()
            cred.login    = updated.login
            cred.password = updated.password
            cred.note     = updated.note
            cred.admin_only = updated.admin_only
            self._refresh_credentials()

    def _delete_credential(self, cred: models.Credential):
        if confirm(self, "Usuń poświadczenie", f"Usunąć poświadczenie '{cred.login}'?"):
            self._db.credentials.remove(cred)
            self._refresh_credentials()

    def _accept(self):
        host = self._host_edit.text().strip()
        if not host:
            QMessageBox.warning(self, "Błąd", "Podaj host bazy danych.")
            return
        self._db.host = host
        self._db.port = self._port_edit.text().strip()
        self._db.name = self._name_edit.text().strip()
        self._db.db_type = self._type_combo.currentText()
        self._db.note = self._note_edit.text().strip()
        if self._admin_mode:
            self._db.admin_only = self._admin_cb.isChecked()
        self.accept()

    def get_database(self) -> models.Database:
        return self._db


class ChangePasswordDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._result = None
        self.setWindowTitle("Zmień hasło główne")
        self.setFixedSize(400, 210)
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(8)

        form = QFormLayout()
        form.setSpacing(8)

        self._old_pass = QLineEdit()
        self._old_pass.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Bieżące hasło:", self._old_pass)

        self._new_pass = QLineEdit()
        self._new_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self._new_pass.setPlaceholderText("Minimum 8 znaków")
        form.addRow("Nowe hasło:", self._new_pass)

        self._confirm_pass = QLineEdit()
        self._confirm_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self._confirm_pass.setPlaceholderText("Powtórz nowe hasło")
        form.addRow("Potwierdź:", self._confirm_pass)

        layout.addLayout(form)
        layout.addStretch()

        btn_row = QHBoxLayout()
        btn_cancel = QPushButton("Anuluj")
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)
        btn_ok = QPushButton("Zmień hasło")
        btn_ok.setDefault(True)
        btn_ok.clicked.connect(self._accept)
        btn_row.addWidget(btn_ok)
        layout.addLayout(btn_row)

    def _accept(self):
        old = self._old_pass.text()
        new = self._new_pass.text()
        confirm_text = self._confirm_pass.text()

        if not old:
            QMessageBox.warning(self, "Błąd", "Podaj bieżące hasło.")
            return
        if len(new) < 8:
            QMessageBox.warning(self, "Błąd", "Nowe hasło musi mieć minimum 8 znaków.")
            return
        if new != confirm_text:
            QMessageBox.warning(self, "Błąd", "Nowe hasła nie są identyczne.")
            return

        self._result = (old, new)
        self.accept()

    def get_passwords(self):
        return self._result


class AdminSetupDialog(QDialog):
    """Dialog to set or change the admin password."""
    def __init__(self, parent=None, is_change: bool = False):
        super().__init__(parent)
        self._password = None
        title = "Zmień hasło admina" if is_change else "Ustaw hasło admina"
        self.setWindowTitle(title)
        self.setFixedSize(400, 200 if is_change else 170)
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(8)

        form = QFormLayout()
        form.setSpacing(8)

        if is_change:
            self._old_pass = QLineEdit()
            self._old_pass.setEchoMode(QLineEdit.EchoMode.Password)
            form.addRow("Biezace haslo admina:", self._old_pass)
        else:
            self._old_pass = None

        self._new_pass = QLineEdit()
        self._new_pass.setEchoMode(QLineEdit.EchoMode.Password)
        self._new_pass.setPlaceholderText("Minimum 4 znaki")
        form.addRow("Nowe haslo admina:", self._new_pass)

        self._confirm = QLineEdit()
        self._confirm.setEchoMode(QLineEdit.EchoMode.Password)
        self._confirm.setPlaceholderText("Powtorz haslo")
        form.addRow("Potwierdz:", self._confirm)

        layout.addLayout(form)
        layout.addStretch()

        btn_row = QHBoxLayout()
        btn_cancel = QPushButton("Anuluj")
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)
        btn_ok = QPushButton("Zapisz")
        btn_ok.setDefault(True)
        btn_ok.clicked.connect(self._accept)
        btn_row.addWidget(btn_ok)
        layout.addLayout(btn_row)

    def _accept(self):
        new = self._new_pass.text()
        if len(new) < 4:
            QMessageBox.warning(self, "Blad", "Haslo admina musi miec minimum 4 znaki.")
            return
        if new != self._confirm.text():
            QMessageBox.warning(self, "Blad", "Hasla nie sa identyczne.")
            return
        self._password = new
        self.accept()

    def get_old_password(self) -> str | None:
        return self._old_pass.text() if self._old_pass else None

    def get_password(self) -> str:
        return self._password


class AdminUnlockDialog(QDialog):
    """Dialog to enter admin password to unlock hidden items."""
    def __init__(self, parent=None):
        super().__init__(parent)
        self._password = None
        self.setWindowTitle("Odblokuj tryb admina")
        self.setFixedSize(360, 120)
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(10)

        row = QHBoxLayout()
        row.addWidget(QLabel("Haslo admina:"))
        self._pass_edit = QLineEdit()
        self._pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._pass_edit.returnPressed.connect(self._accept)
        row.addWidget(self._pass_edit)
        layout.addLayout(row)

        btn_row = QHBoxLayout()
        btn_cancel = QPushButton("Anuluj")
        btn_cancel.clicked.connect(self.reject)
        btn_row.addWidget(btn_cancel)
        btn_ok = QPushButton("Odblokuj")
        btn_ok.setDefault(True)
        btn_ok.clicked.connect(self._accept)
        btn_row.addWidget(btn_ok)
        layout.addLayout(btn_row)

    def _accept(self):
        pw = self._pass_edit.text()
        if not pw:
            return
        self._password = pw
        self.accept()

    def get_password(self) -> str:
        return self._password
