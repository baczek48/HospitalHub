"""2026-10-16: another machine of the same hospital opens as a tab of the SSH
window already open for it; action buttons line up whatever the login."""

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.dirname(_HERE), _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


class _FakeDialog:
    created = []

    def __init__(self, machine, hospital=None, **kw):
        self._hospital = hospital
        self.machines = [machine]
        self.visible = False
        _FakeDialog.created.append(self)

    def show(self):
        self.visible = True

    showMaximized = show

    def open_machine(self, machine):
        self.machines.append(machine)


def _panel(monkeypatch, hospitals):
    from ui import detail_panel as dp
    _FakeDialog.created = []
    monkeypatch.setattr(dp, "SshDialog", _FakeDialog)
    _FakeDialog.window_for = classmethod(
        lambda cls, owner, hospital: next(
            (d for d in reversed(cls.created) if d._hospital is hospital and d.visible),
            None))
    p = dp.DetailPanel()
    p.show_hospital(hospitals[0], hospitals)
    return p


def test_second_machine_of_the_hospital_becomes_a_tab(app, monkeypatch):
    import models
    a, b = models.Machine(ip="10.0.0.1"), models.Machine(ip="10.0.0.2")
    h = models.Hospital(name="H", machines=[a, b])
    p = _panel(monkeypatch, [h])
    p._open_ssh(a)
    p._open_ssh(b)
    assert len(_FakeDialog.created) == 1
    assert _FakeDialog.created[0].machines == [a, b]


def test_other_hospital_gets_its_own_window(app, monkeypatch):
    import models
    h1 = models.Hospital(name="H1", machines=[models.Machine(ip="10.0.0.1")])
    h2 = models.Hospital(name="H2", machines=[models.Machine(ip="10.0.1.1")])
    p = _panel(monkeypatch, [h1, h2])
    p._open_ssh(h1.machines[0])
    p.show_hospital(h2, [h1, h2])
    p._open_ssh(h2.machines[0])
    assert len(_FakeDialog.created) == 2


def test_window_for_picks_the_last_used_visible_window(app):
    from types import SimpleNamespace
    from ui import ssh_panel as sp
    owner, hosp = object(), object()

    def win(seq, visible=True, hospital=hosp):
        return SimpleNamespace(owner_window=lambda: owner, _hospital=hospital,
                               isVisible=lambda: visible, _activated_seq=seq)
    old, new, hidden, other = win(1), win(5), win(9, visible=False), win(7, hospital=object())
    saved = list(sp.SshDialog._alive)
    sp.SshDialog._alive[:] = [old, new, hidden, other]
    try:
        assert sp.SshDialog.window_for(owner, hosp) is new
        assert sp.SshDialog.window_for(object(), hosp) is None
    finally:
        sp.SshDialog._alive[:] = saved


def test_open_machine_adds_a_tab_in_a_real_window(app, monkeypatch):
    import models
    from ui import ssh_panel as sp
    monkeypatch.setattr(sp.SshDialog, "_add_first_session", lambda self: None)
    added = []
    monkeypatch.setattr(sp.SshDialog, "_add_session",
                        lambda self, **kw: added.append(kw))
    h = models.Hospital(name="H")
    m1 = models.Machine(ip="10.0.0.1", credentials=[models.Credential(login="a", password="p")])
    m2 = models.Machine(ip="10.0.0.2", name="db",
                        credentials=[models.Credential(login="b", password="q")])
    dlg = sp.SshDialog(m1, hospital=h)
    try:
        dlg.show()
        dlg.showMinimized()
        app.processEvents()
        dlg.open_machine(m2)
        app.processEvents()
        assert added[-1]["ip"] == "10.0.0.2" and added[-1]["user"] == "b"
        assert not dlg.isMinimized()
    finally:
        dlg.close_without_asking()


def test_action_buttons_line_up_whatever_the_login(app):
    import models
    from PyQt6.QtWidgets import QPushButton
    from ui import detail_panel as dp
    p = dp.DetailPanel()
    xs = []
    for login in ("root", None, "administrator_systemu_dlugi"):
        creds = [models.Credential(login=login, password="x")] if login else []
        w = p._machine_actions(models.Machine(ip="1.1.1.1", credentials=creds))
        w.resize(300, 34)
        w.show()
        app.processEvents()
        btns = w.findChildren(QPushButton)
        xs.append([b.x() for b in btns])
        w.hide()
    assert xs[0] == xs[1] == xs[2]
