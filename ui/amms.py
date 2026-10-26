"""AMMS button of the hospital header (2026-10-26).

Left click opens the hospital's web AMMS in the AMMS browser and signs in
(``amms_login``); right click edits the URL, the login and the password,
which live in the hospital, in the vault.
"""

import copy

from PyQt6.QtCore import QThread, pyqtSignal, Qt
from PyQt6.QtWidgets import (
    QDialog, QVBoxLayout, QHBoxLayout, QFormLayout, QLineEdit, QPushButton,
    QLabel,
)

import amms_login
from ui.style import FormStyled
from ui.dialogs import _DiscardGuard


#: What the status line next to the button says about each outcome:
#: (text, colour).
OUTCOME_TEXTS = {
    amms_login.LOGGED_IN: ("AMMS: zalogowano", "#3fb950"),
    amms_login.NEEDS_2FA: ("AMMS: wpisz kod 2FA w przeglądarce", "#d29922"),
    amms_login.SUBMITTED: ("AMMS: dane wysłane — sprawdź okno przeglądarki", "#d29922"),
    amms_login.REJECTED: ("AMMS: logowanie odrzucone", "#f85149"),
    amms_login.OPENED: ("AMMS: otwarto (brak zapisanego loginu)", "#58a6ff"),
    amms_login.NO_BROWSER: ("AMMS: nie znaleziono Chrome ani Edge", "#f85149"),
    amms_login.BROWSER_FAILED: ("AMMS: przeglądarka nie wystartowała", "#f85149"),
    amms_login.FORM_NOT_FOUND: ("AMMS: brak formularza logowania (VPN? URL?)", "#f85149"),
    amms_login.FILL_MISMATCH: ("AMMS: pola nie przyjęły danych — wpisz ręcznie", "#f85149"),
    amms_login.CANCELLED: ("AMMS: przerwano", "#8b949e"),
    amms_login.ERROR: ("AMMS: błąd połączenia z przeglądarką", "#f85149"),
}


def outcome_text(outcome: str) -> tuple[str, str]:
    return OUTCOME_TEXTS.get(outcome, (f"AMMS: {outcome}", "#8b949e"))


class AmmsWorker(QThread):
    """Runs ``amms_login.sign_in`` off the UI thread."""

    progress = pyqtSignal(str)
    done = pyqtSignal(str, str)          # outcome, detail

    def __init__(self, url: str, login: str, password: str, parent=None,
                 sign_in=None):
        super().__init__(parent)
        self._url, self._login, self._password = url, login, password
        self._sign_in = sign_in or amms_login.sign_in
        self._stop = False

    def cancel(self) -> None:
        self._stop = True

    def run(self):
        try:
            result = self._sign_in(self._url, self._login, self._password,
                                   progress=self.progress.emit,
                                   should_stop=lambda: self._stop)
        except Exception as e:                   # never let a worker die silently
            result = amms_login.AmmsResult(amms_login.ERROR, str(e))
        finally:
            self._password = ""
        self.done.emit(result.outcome, result.detail)


class AmmsDialog(_DiscardGuard, FormStyled, QDialog):
    """URL, login and password of a hospital's AMMS."""

    def __init__(self, parent=None, hospital=None):
        super().__init__(parent)
        h = hospital
        self._values = (h.amms_url, h.amms_login, h.amms_password) if h else ("", "", "")
        self.setWindowTitle("AMMS" + (f" — {h.name}" if h and h.name else ""))
        self.setFixedSize(460, 210)
        self.setWindowFlag(Qt.WindowType.WindowContextHelpButtonHint, False)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        layout.setSpacing(8)

        form = QFormLayout()
        form.setSpacing(8)
        self._url_edit = QLineEdit(self._values[0])
        self._url_edit.setPlaceholderText("http://192.0.2.10/index.html")
        form.addRow("URL:", self._url_edit)

        self._login_edit = QLineEdit(self._values[1])
        self._login_edit.setPlaceholderText("Użytkownik AMMS")
        form.addRow("Login:", self._login_edit)

        pass_row = QHBoxLayout()
        self._pass_edit = QLineEdit(self._values[2])
        self._pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        pass_row.addWidget(self._pass_edit)
        btn_show = QPushButton("Pokaż")
        btn_show.setMaximumWidth(70)
        btn_show.setCheckable(True)
        btn_show.toggled.connect(
            lambda checked: self._pass_edit.setEchoMode(
                QLineEdit.EchoMode.Normal if checked else QLineEdit.EchoMode.Password))
        pass_row.addWidget(btn_show)
        form.addRow("Hasło:", pass_row)
        layout.addLayout(form)

        hint = QLabel("Puste URL usuwa AMMS z tego szpitala.")
        hint.setStyleSheet("color: #8b949e; font-size: 10px;")
        layout.addWidget(hint)
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
        url = self._url_edit.text().strip()
        if url:
            url = amms_login.normalize_url(url)
            login = self._login_edit.text().strip()
            password = self._pass_edit.text()
        else:
            login = password = ""
        self._values = (url, login, password)
        self.accept()

    def values(self) -> tuple[str, str, str]:
        """(url, login, password) as saved."""
        return copy.copy(self._values)
