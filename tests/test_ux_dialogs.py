"""Dialogs (UX audit 2026-10-16, Etap 71): E-13 discard guard, E-14/S-11
ports, E-19 admin unlock stays open, V-08 Polish letters, V-09 Qt in Polish."""

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.mark.parametrize("text, want", [
    ("", 22), ("22", 22), (" 2222 ", 2222), ("abc", None), ("22a", None),
    ("0", None), ("65535", 65535), ("99999", None),
])
def test_parse_port(text, want):
    from ui.utils import parse_port
    assert parse_port(text, 22) == want


@pytest.mark.parametrize("text, want", [
    ("10.0.0.1:2222", ("10.0.0.1", "2222")), ("host", ("host", "")),
    ("fe80::1", ("fe80::1", "")), ("h:abc", ("h:abc", "")),
])
def test_split_host_port(text, want):
    from ui.utils import split_host_port
    assert split_host_port(text) == want


def _machine_dialog(app):
    import models
    from ui.dialogs import MachineDialog
    m = models.Machine(ip="10.0.0.1", name="app")
    d = MachineDialog(None, m)
    d.show()
    app.processEvents()
    return d


def test_e13_escape_with_edits_asks_and_can_keep_the_form(app, monkeypatch):
    from ui import dialogs
    asked = []
    monkeypatch.setattr(dialogs, "confirm", lambda *a, **k: asked.append(a[1]) or False)
    d = _machine_dialog(app)
    d._desc_edit.setText("zmieniony opis")
    d.reject()
    assert asked == ["Odrzucić zmiany?"] and d.isVisible()
    monkeypatch.setattr(dialogs, "confirm", lambda *a, **k: True)
    d.reject()
    assert not d.isVisible()


def test_e13_no_edits_close_without_a_question(app, monkeypatch):
    from ui import dialogs
    monkeypatch.setattr(dialogs, "confirm",
                        lambda *a, **k: pytest.fail("pytanie bez zmian"))
    d = _machine_dialog(app)
    d.reject()
    assert not d.isVisible()


def test_e14_a_bad_rdp_port_is_refused_at_save(app, monkeypatch):
    from ui import dialogs
    warned = []
    monkeypatch.setattr(dialogs.QMessageBox, "warning",
                        staticmethod(lambda *a, **k: warned.append(a[2])))
    d = _machine_dialog(app)
    d._type_combo.setCurrentText("RDP")
    d._rdp_port_edit.setValidator(None)
    d._rdp_port_edit.setText("99999")
    d._accept()
    assert warned and "65535" in warned[0] and d._machine.rdp_port != "99999"


def test_s11_new_session_takes_host_colon_port_and_refuses_bad_ports(app, monkeypatch):
    from ui import ssh_panel as sp
    warned = []
    monkeypatch.setattr(sp.QMessageBox, "warning",
                        staticmethod(lambda *a, **k: warned.append(a[2])))
    d = sp._AddSessionDialog()
    d._ip_edit.setText("10.0.0.1:2222")
    d._user_edit.setText("root")
    d._accept()
    assert d.get_values()[0] == "10.0.0.1" and d.get_values()[3] == 2222
    d._port_edit.setText("abc")
    d._accept()
    assert warned and "65535" in warned[-1]


def test_e19_a_wrong_admin_password_keeps_the_dialog_open(app):
    from ui.dialogs import AdminUnlockDialog
    d = AdminUnlockDialog(verify=lambda pw: pw == "dobre")
    d.show()
    d._pass_edit.setText("złe")
    d._accept()
    assert d.isVisible() and "Nieprawidłowe" in d._error_lbl.text()
    assert d._pass_edit.text() == ""
    d._pass_edit.setText("dobre")
    d._accept()
    assert d.get_password() == "dobre"


def test_v08_no_ascii_polish_left_in_the_ui():
    import re
    bad = re.compile(r"[\"'][^\"']*\b(haslo|hasla|Haslo|Blad|Powtorz|Potwierdz|Polacz|"
                     r"mozna|odczytac|uprawnien|Biezace|miec)\b")
    root = os.path.join(_PARENT, "ui")
    hits = []
    for name in os.listdir(root):
        if name.endswith(".py"):
            for n, line in enumerate(open(os.path.join(root, name), encoding="utf-8"), 1):
                if not line.lstrip().startswith("#") and bad.search(line):
                    hits.append(f"{name}:{n}")
    assert hits == []


def test_v09_qt_buttons_in_polish(app):
    import main
    from PyQt6.QtWidgets import QMessageBox
    assert main.install_polish_translations(app) is True
    box = QMessageBox()
    box.setStandardButtons(QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel)
    texts = {b.text().replace("&", "") for b in box.buttons()}
    assert "Tak" in texts and "Anuluj" in texts
