"""2026-10-16: an SSH window minimized from maximized came back with Qt's
geometry forced to the screen's available area while Windows had already
maximized it — Qt laid the content out 23 px taller than the real client
area and the bottom went under the screen edge (measured on the desktop:
Qt (0,0,1920,1032) vs client (0,23,1920,1009)).  Restoring must leave a
window Windows brought back maximized alone."""

import os
import sys
from types import SimpleNamespace

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.dirname(_HERE), _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def _restore(monkeypatch, maximized_after: bool, same_screen: bool):
    import models
    from ui import ssh_panel as sp
    monkeypatch.setattr(sp.SshDialog, "_add_first_session", lambda self: None)
    dlg = sp.SshDialog(models.Machine(ip="192.0.2.1"))
    calls = []
    try:
        scr = dlg.screen() if same_screen else SimpleNamespace(
            availableGeometry=lambda: SimpleNamespace(topLeft=lambda: None))
        monkeypatch.setattr(dlg, "isMaximized", lambda: maximized_after)
        for name in ("setGeometry", "showMaximized", "showNormal", "move"):
            monkeypatch.setattr(dlg, name, lambda *a, n=name: calls.append(n))
        dlg._restore_maximized(scr)
    finally:
        sp.SshDialog.close_without_asking(dlg)
    return calls


def test_window_back_maximized_on_its_screen_is_left_alone(app, monkeypatch):
    assert _restore(monkeypatch, maximized_after=True, same_screen=True) == []


def test_window_back_unmaximized_is_maximized_again(app, monkeypatch):
    calls = _restore(monkeypatch, maximized_after=False, same_screen=True)
    assert "setGeometry" not in calls and calls[-1] == "showMaximized"


def test_window_back_on_another_monitor_moves_while_normal(app, monkeypatch):
    calls = _restore(monkeypatch, maximized_after=True, same_screen=False)
    assert calls == ["showNormal", "move", "showMaximized"]
