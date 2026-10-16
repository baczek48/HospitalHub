"""2026-10-16 (owner's request): after a dropped link the tab reconnects by
itself at most 3 times; then it stops and offers R (another round, scrollback
kept) / Esc (close).  Real paramiko server in-process, no network."""

import os
import sys
import time

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.dirname(_HERE), _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

pytest.importorskip("paramiko")
from ssh_fake_server import FakeServer  # noqa: E402


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def pump(cond, timeout=8.0):
    from PyQt6.QtWidgets import QApplication
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        QApplication.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


def screen_text(term):
    term.flush_now()
    return "\n".join("".join(c.data for c in term._screen.buffer[y].values())
                     for y in range(term._screen.lines))


@pytest.fixture
def dialog(app, tmp_path, monkeypatch):
    import models
    from PyQt6.QtCore import QTimer
    from ui import ssh_panel as sp
    srv = FakeServer(str(tmp_path))
    monkeypatch.setattr(sp, "_make_client", srv.make_client_patch())
    # An SFTP connect racing the refused server reports through a modal box —
    # it would block the test's event pump.
    monkeypatch.setattr(sp.QMessageBox, "warning", lambda *a, **k: None)
    # The backoff (2 s, 4 s, 6 s) shortened; everything else is the real path.
    monkeypatch.setattr(sp.SshDialog, "_schedule_reconnect",
                        lambda self, s: QTimer.singleShot(
                            10, lambda: self._do_auto_reconnect(s))
                        if s in self._sessions and s.reconnecting else None)
    m = models.Machine(ip="10.0.0.5", credentials=[
        models.Credential(login="u", password=srv.password)])
    dlg = sp.SshDialog(m)
    dlg.resize(1100, 700)
    dlg.show()
    # Shell ready (prompt on screen) — a drop before that is a login error,
    # not a dropped link.
    assert pump(lambda: dlg._sessions and "$" in screen_text(dlg._sessions[0].term))
    yield dlg, srv
    srv.refuse = False
    dlg.close_without_asking()
    srv.drop()


def test_three_failed_attempts_then_stop_with_r_and_esc(dialog):
    dlg, srv = dialog
    s = dlg._sessions[0]
    srv.refuse = True                    # VPN gone: every connect is refused
    srv.drop()
    assert pump(lambda: s.reconnect_exhausted)
    assert s.reconnect_attempts == 3 and not s.reconnecting
    assert s.pane._error_mode
    pump(lambda: False, timeout=0.5)     # nothing keeps knocking
    assert s.reconnect_attempts == 3
    text = screen_text(s.term)
    assert "3 próby" in text and "Połącz ponownie" in text and "Zamknij" in text


def test_r_starts_another_round_and_keeps_the_scrollback(dialog):
    from PyQt6.QtCore import QEvent, Qt
    from PyQt6.QtGui import QKeyEvent
    from PyQt6.QtWidgets import QApplication
    dlg, srv = dialog
    s = dlg._sessions[0]
    srv.refuse = True
    srv.drop()
    assert pump(lambda: s.reconnect_exhausted)
    srv.refuse = False                   # VPN back
    QApplication.sendEvent(s.term, QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_R,
                                             Qt.KeyboardModifier.NoModifier, "r"))
    assert pump(lambda: not s.pane._error_mode and not s.reconnecting
                and not s.reconnect_exhausted and s.worker._channel is not None)
    text = screen_text(s.term)
    assert "Przerwa w połączeniu" in text                 # the banner says it came back
    assert "Próba" not in text and "Brak połączenia" not in text   # attempts and card gone


def test_esc_closes_the_tab(dialog):
    from PyQt6.QtCore import QEvent, Qt
    from PyQt6.QtGui import QKeyEvent
    from PyQt6.QtWidgets import QApplication
    dlg, srv = dialog
    s = dlg._sessions[0]
    srv.refuse = True
    srv.drop()
    assert pump(lambda: s.reconnect_exhausted)
    QApplication.sendEvent(s.term, QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Escape,
                                             Qt.KeyboardModifier.NoModifier))
    assert pump(lambda: s not in dlg._sessions)


@pytest.mark.parametrize("cols", [24, 30, 40, 51, 52, 80, 200])
def test_error_card_rows_fit_the_terminal(app, cols):
    """A wrapped row would make clear_error() lift the wrong number of rows."""
    import re
    from ui import ssh_panel as sp
    card = sp._error_card("Brak połączenia z serwer-aplikacyjny-pacs.szpital.local",
                          "3 próby ponownego połączenia bez powodzenia.\n"
                          "Ostatni błąd: " + "x" * 120, "Sprawdź, czy VPN i sieć działają.",
                          cols)
    for row in card.split("\r\n"):
        assert len(re.sub(r"\x1b\[[0-9;]*m", "", row)) <= cols - 1, (cols, row)


def test_resize_while_the_card_is_shown_then_r(dialog):
    """The card and the banner are found by their text: a resize between
    printing and removing them must not erase the wrong rows."""
    from PyQt6.QtCore import QEvent, Qt
    from PyQt6.QtGui import QKeyEvent
    from PyQt6.QtWidgets import QApplication
    dlg, srv = dialog
    s = dlg._sessions[0]
    s.term.feed("marker-line-1\r\nmarker-line-2\r\n$ ")
    srv.refuse = True
    srv.drop()
    assert pump(lambda: s.reconnect_exhausted)
    dlg.resize(dlg.width() // 2, dlg.height() - 120)
    pump(lambda: False, timeout=0.3)
    srv.refuse = False
    QApplication.sendEvent(s.term, QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_R,
                                             Qt.KeyboardModifier.NoModifier, "r"))
    ok = pump(lambda: not s.reconnecting and s.worker._channel is not None
              and "Przerwa w połączeniu" in screen_text(s.term))
    text = screen_text(s.term)
    assert ok, (s.term.terminal_size(), s.reconnecting, s.reconnect_exhausted, text)
    assert "marker-line-2" in text
    assert "╭" not in text and "Próba" not in text
