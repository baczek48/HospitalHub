"""The Portable list look (ui/list_style.py, 2026-11-19) is an application
style sheet.  With it installed every setStyleSheet sends events to widgets
that already exist — 2.0.40 crashed on start in the file panel, whose event
filter on the path field ran before its table was built (owner's screenshot:
"'SftpPanel' object has no attribute '_table'")."""

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
if os.path.dirname(_HERE) not in sys.path:
    sys.path.insert(0, os.path.dirname(_HERE))


@pytest.fixture
def styled_app():
    from PyQt6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication([])
    before = app.styleSheet()
    from ui import list_style
    list_style.install(app)
    yield app
    app.setStyleSheet(before)


def test_the_sheet_has_the_chevrons_and_no_arrow_buttons(styled_app):
    from ui import list_style
    css = list_style.application_qss()
    assert "chevron-right" in css and "chevron-down" in css
    assert "QScrollBar::add-line" in css
    right, down = list_style.chevron_paths("#8b949e")
    assert os.path.exists(right) and os.path.exists(down)


def test_the_portable_window_builds_under_the_sheet(styled_app, tmp_path,
                                                    monkeypatch):
    import sys as _sys
    errors = []
    monkeypatch.setattr(_sys, "excepthook",
                        lambda *a: errors.append(a[1]))
    import models
    from crypto import encrypt
    from ui.remote_window import RemoteWindow
    h = models.Hospital(name="S", machines=[models.Machine(ip="10.0.0.1")])
    path = tmp_path / "s.vault"
    path.write_bytes(encrypt(models.to_dict([h]), "p"))
    w = RemoteWindow(str(path), "p", models.from_dict(models.to_dict([h])))
    w.show()
    styled_app.processEvents()
    w.close_without_asking()
    styled_app.processEvents()
    assert errors == []


def test_dialogs_and_the_hl7_window_build_under_the_sheet(styled_app,
                                                          monkeypatch):
    import sys as _sys
    errors = []
    monkeypatch.setattr(_sys, "excepthook", lambda *a: errors.append(a[1]))
    import models
    from ui.dialogs import DatabaseDialog, MachineDialog
    from ui.hl7_registry_window import Hl7RegistryWindow
    from ui.remote_login import RemoteLoginDialog
    from ui.ssh_panel import TerminalWidget, _TerminalPane
    made = [MachineDialog(None), DatabaseDialog(None),
            Hl7RegistryWindow(models.Hospital(name="S")),
            _TerminalPane(TerminalWidget(), "t")]
    try:
        made.append(RemoteLoginDialog())
    except TypeError:
        pass
    for w in made:
        w.show()
    styled_app.processEvents()
    for w in made:
        w.close()
    styled_app.processEvents()
    assert errors == []
