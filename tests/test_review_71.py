"""Code review of Etap 71 (2026-10-16): R-01 … R-11."""

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.dirname(_HERE), _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

ESC = "\x1b"


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def _vault():
    import models
    hidden = models.Machine(ip="10.99.0.7", name="root-backup", admin_only=True)
    db = models.Database(host="secret-db", name="X", admin_only=True)
    return [models.Hospital(name="Szpital A", machines=[hidden], databases=[db])]


def test_r01_search_does_not_reveal_admin_only_entries(app, tmp_path):
    from ui.main_window import MainWindow
    w = MainWindow(str(tmp_path / "v.vault"), "pw", _vault())
    for query in ("10.99", "root-backup", "secret-db"):
        w._search_edit.setText(query)
        assert w._hospital_list.count() == 0, query
    w._admin_unlocked = True
    w._search_edit.setText("10.99")
    assert w._hospital_list.count() == 1
    w._unsaved = False


def test_r02_one_right_click_one_menu_with_duplicate(app, monkeypatch):
    import models
    from PyQt6.QtCore import QPoint
    from PyQt6.QtWidgets import QMenu
    from ui.detail_panel import DetailPanel
    h = models.Hospital(name="H", machines=[models.Machine(ip="1.2.3.4")])
    p = DetailPanel()
    p.show_hospital(h, [h])
    shown = []
    monkeypatch.setattr(QMenu, "exec", lambda self, *a: shown.append(
        [x.text() for x in self.actions()]))
    p._machines_table.customContextMenuRequested.emit(QPoint(5, 5))
    assert len(shown) == 1 and "Duplikuj" in shown[0]


def test_r03_a_kept_transfer_window_keeps_the_vault(app, monkeypatch):
    import main
    from types import SimpleNamespace
    from ui import ssh_panel as sp
    kept = SimpleNamespace(close_for_vault=lambda: False)
    monkeypatch.setattr(sp.SshDialog, "windows_of", classmethod(lambda cls, w: [kept]))
    removed = []
    mgr = SimpleNamespace(remove_window=removed.append)
    win = SimpleNamespace(_unsaved=False)
    main.AppManager._force_close_window(mgr, win)
    assert removed == []


@pytest.mark.parametrize("seq, attr, want", [
    (f"{ESC}[38;5;58mX", "fg", "5f5f00"),
    (f"{ESC}[38;2;10;58;20;1mX", "bold", True),
    (f"{ESC}[4m{ESC}[4:0mX", "underscore", False),
    (f"{ESC}[58;5;9;1mX", "bold", True),
])
def test_r05_sgr_58_only_as_an_attribute(app, seq, attr, want):
    from ui import ssh_panel as sp
    t = sp.TerminalWidget()
    t.feed(seq)
    t.flush_now()
    assert getattr(t._screen.buffer[0][0], attr) == want


def test_r06_multi_exec_paste_is_bracketed_only_if_every_session_is(app, monkeypatch):
    from ui import ssh_panel as sp
    t = sp.TerminalWidget()
    sent = []
    t.char_input.connect(sent.append)
    t.feed(f"{ESC}[?2004h")
    t.flush_now()
    t.paste_targets = lambda: 2
    t.paste_bracketed_everywhere = lambda: False
    asked = []
    monkeypatch.setattr(t, "_confirm_paste",
                        lambda text, lines, targets, br: asked.append(br) or True)
    t.paste("a\nb\n")
    assert asked == [False] and sent == [b"a\rb\r"]


def test_r07_exit_then_a_closed_link_is_not_reconnected(app):
    from types import SimpleNamespace
    from ui import ssh_panel as sp
    session = SimpleNamespace(reconnecting=False,
                              term=SimpleNamespace(last_command=b"exit"))
    dlg = SimpleNamespace(_sessions=[session],
                          _schedule_reconnect=lambda s: pytest.fail("reconnect"))
    sp.SshDialog._on_session_dropped(dlg, session)
    assert session.reconnecting is False


def test_r09_saved_widths_are_the_users_not_the_squeezed(app, monkeypatch):
    import models
    from PyQt6.QtWidgets import QApplication
    from ui import detail_panel as dp
    saved = {}
    monkeypatch.setattr(dp, "save_column_widths", lambda k, v: saved.__setitem__(k, v))
    h = models.Hospital(name="H", databases=[models.Database(host="h", name="n")])
    p = dp.DetailPanel()
    p.show_hospital(h, [h])
    p.resize(500, 600)
    p.show()
    QApplication.processEvents()
    assert p._db_table.isColumnHidden(4), "wąski panel: kolumny ściśnięte/ukryte"
    p._db_table._header_ctx_menu_filter._callback()
    assert 0 not in saved["databases"] and len(saved["databases"]) == 4
    assert saved["databases"] == list(p._db_table._fit_spec[1])
    p.hide()


def test_r10_a_child_credential_dialog_is_not_an_edit(app, monkeypatch):
    import models
    from ui import dialogs
    monkeypatch.setattr(dialogs, "confirm", lambda *a, **k: pytest.fail("fałszywe pytanie"))
    d = dialogs.MachineDialog(None, models.Machine(ip="1.1.1.1"))
    d.show()
    app.processEvents()
    child = dialogs.CredentialDialog(d)                 # opened and cancelled
    child.show(); app.processEvents(); child.hide()
    d.reject()
    assert not d.isVisible()


def test_r11_soft_reset_leaves_line_drawing(app):
    from ui import ssh_panel as sp
    t = sp.TerminalWidget()
    t.feed(f"{ESC})0\x0e")                              # dead session left in SO
    t.feed(sp._TERM_SOFT_RESET + "q")
    t.flush_now()
    assert t._screen.buffer[t._screen.cursor.y][t._screen.cursor.x - 1].data == "q"
