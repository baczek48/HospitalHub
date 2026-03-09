import copy

from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QLabel, QLineEdit,
    QPushButton, QComboBox, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QFormLayout, QMessageBox,
    QApplication,
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QIntValidator

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import models
from ui.utils import confirm

_CLIPBOARD_CLEAR_MS = 30_000   # auto-clear password after 30 s


def _clipboard_copy(text: str) -> None:
    """Copy text to clipboard and schedule automatic clearing after 30 s."""
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
    def __init__(self, parent=None, credential: models.Credential = None):
        super().__init__(parent)
        self._cred = copy.deepcopy(credential) if credential else models.Credential()
        self.setWindowTitle("Poświadczenie")
        self.setFixedSize(400, 200)
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
        self.accept()

    def get_credential(self) -> models.Credential:
        return self._cred


class MachineDialog(QDialog):
    def __init__(self, parent=None, machine: models.Machine = None):
        super().__init__(parent)
        self._machine = copy.deepcopy(machine) if machine else models.Machine()
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

        # Connection type
        self._type_combo = QComboBox()
        self._type_combo.addItems(["SSH", "RDP"])
        idx = self._type_combo.findText(self._machine.connection_type)
        self._type_combo.setCurrentIndex(idx if idx >= 0 else 0)
        self._type_combo.currentTextChanged.connect(self._on_type_changed)
        self._form.addRow("Typ połączenia:", self._type_combo)

        # RDP port — visible only when RDP is selected
        self._rdp_port_edit = QLineEdit(self._machine.rdp_port or "3389")
        self._rdp_port_edit.setPlaceholderText("3389")
        self._rdp_port_edit.setMaximumWidth(100)
        self._rdp_port_edit.setValidator(QIntValidator(1, 65535, self))
        self._form.addRow("Port RDP:", self._rdp_port_edit)
        self._rdp_port_row = self._form.rowCount() - 1   # index of the row just added
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

    def _refresh_credentials(self):
        self._cred_table.setRowCount(0)
        for i, cred in enumerate(self._machine.credentials):
            self._cred_table.insertRow(i)
            self._cred_table.setItem(i, 0, QTableWidgetItem(cred.login))
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
        dlg = CredentialDialog(self)
        if dlg.exec():
            self._machine.credentials.append(dlg.get_credential())
            self._refresh_credentials()

    def _edit_credential(self, cred: models.Credential):
        dlg = CredentialDialog(self, cred)
        if dlg.exec():
            updated = dlg.get_credential()
            cred.login = updated.login
            cred.password = updated.password
            cred.note = updated.note
            self._refresh_credentials()

    def _delete_credential(self, cred: models.Credential):
        if confirm(self, "Usuń poświadczenie", f"Usunąć poświadczenie '{cred.login}'?"):
            self._machine.credentials.remove(cred)
            self._refresh_credentials()

    def _on_type_changed(self, text: str) -> None:
        is_rdp = text == "RDP"
        self._rdp_port_edit.setVisible(is_rdp)
        lbl = self._form.labelForField(self._rdp_port_edit)
        if lbl:
            lbl.setVisible(is_rdp)

    def _accept(self):
        ip = self._ip_edit.text().strip()
        if not ip:
            QMessageBox.warning(self, "Błąd", "Podaj adres IP maszyny.")
            return
        self._machine.ip = ip
        self._machine.name = self._name_edit.text().strip()
        self._machine.description = self._desc_edit.text().strip()
        self._machine.connection_type = self._type_combo.currentText()
        self._machine.rdp_port = self._rdp_port_edit.text().strip() or "3389"
        self.accept()

    def get_machine(self) -> models.Machine:
        return self._machine


class DatabaseDialog(QDialog):
    def __init__(self, parent=None, database: models.Database = None):
        super().__init__(parent)
        self._db = copy.deepcopy(database) if database else models.Database()
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

    def _refresh_credentials(self):
        self._cred_table.setRowCount(0)
        for i, cred in enumerate(self._db.credentials):
            self._cred_table.insertRow(i)
            self._cred_table.setItem(i, 0, QTableWidgetItem(cred.login))
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
        dlg = CredentialDialog(self)
        if dlg.exec():
            self._db.credentials.append(dlg.get_credential())
            self._refresh_credentials()

    def _edit_credential(self, cred: models.Credential):
        dlg = CredentialDialog(self, cred)
        if dlg.exec():
            updated = dlg.get_credential()
            cred.login    = updated.login
            cred.password = updated.password
            cred.note     = updated.note
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
