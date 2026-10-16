"""SSH window ergonomics (UX audit 2026-10-16, Etap 71): E-04 one click
selects, E-11 file-table keys, E-18 window title, S-12 Files panel width."""

import os
import sys
import time

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.dirname(_HERE), _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

pytest.importorskip("paramiko")
from test_ssh_window_close import app, sp, world, open_dialog, pump  # noqa: E402,F401


@pytest.fixture
def dlg(sp, world):
    d = open_dialog(sp)
    yield d
    d.close_without_asking()
    pump(300)


def _click(widget, double=False):
    from PyQt6.QtCore import Qt, QPointF, QEvent
    from PyQt6.QtGui import QMouseEvent
    t = QEvent.Type.MouseButtonDblClick if double else QEvent.Type.MouseButtonPress
    return QMouseEvent(t, QPointF(5, 5), QPointF(5, 5), Qt.MouseButton.LeftButton,
                       Qt.MouseButton.LeftButton, Qt.KeyboardModifier.NoModifier)


def test_e04_one_click_selects_a_double_click_connects(sp, dlg):
    import models
    env = dlg._env_panel
    m = models.Machine(ip="10.9.9.9", name="x",
                       credentials=[models.Credential(login="u", password="pw")])
    opened = []
    env.open_machine.connect(opened.append)
    env._card_clicked(m, _click(None))
    assert opened == [] and id(m) in env._selected
    env._card_double_clicked(m, _click(None, double=True))
    assert opened == [m]


def test_e18_the_title_names_the_session(sp, dlg):
    pump(200)
    assert "u@10.0.0.7" in dlg.windowTitle() and dlg.windowTitle().startswith("SSH")


def test_s12_the_files_panel_keeps_its_width_on_resize(sp, dlg):
    dlg.resize(1400, 800)
    pump(100)
    total = sum(dlg._main_splitter.sizes())
    dlg._main_splitter.setSizes([420, total - 420])
    dlg._on_splitter_moved(420, 1)
    dlg.resize(1600, 900)
    pump(100)
    assert abs(dlg._main_splitter.sizes()[0] - 420) <= 2


def test_e11_keys_in_the_file_table(sp, dlg, monkeypatch):
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest
    p = dlg._sftp_panel
    end = time.monotonic() + 5
    while time.monotonic() < end and p._listing_active:
        pump(50)
    calls = []
    monkeypatch.setattr(p, "_go_up", lambda: calls.append("up"))
    monkeypatch.setattr(p, "_list", lambda path: calls.append(("list", path)))
    QTest.keyClick(p._table, Qt.Key.Key_Backspace)
    QTest.keyClick(p._table, Qt.Key.Key_F5)
    assert calls == ["up", ("list", p._path)]
