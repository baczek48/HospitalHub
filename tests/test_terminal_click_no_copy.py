"""2026-10-16 (owner): a plain click in the terminal — to start typing —
must not select anything nor replace the clipboard; as in MobaXterm only a
drag selects (and copies)."""

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


@pytest.fixture
def term(app):
    from ui.ssh_panel import TerminalWidget
    t = TerminalWidget()
    t.resize(800, 300)
    t.show()
    t.feed("hello world\r\nsecond line\r\n")
    from PyQt6.QtTest import QTest
    QTest.qWait(80)                     # feed() parses on an 8 ms timer
    app.clipboard().setText("SCHOWEK")
    yield t
    t.hide()
    t.deleteLater()


def _pt(t, col, row):
    from PyQt6.QtCore import QPoint
    return QPoint(int((col + 0.5) * t._cw), int((row + 0.5) * t._ch))


def _drag_to(app, t, pos):
    from PyQt6.QtCore import QEvent, QPointF, Qt
    from PyQt6.QtGui import QMouseEvent
    p = QPointF(pos)
    app.sendEvent(t, QMouseEvent(QEvent.Type.MouseMove, p, t.mapToGlobal(p),
                                 Qt.MouseButton.NoButton, Qt.MouseButton.LeftButton,
                                 Qt.KeyboardModifier.NoModifier))


def test_a_click_selects_and_copies_nothing(app, term):
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest
    QTest.mouseClick(term, Qt.MouseButton.LeftButton, pos=_pt(term, 2, 0))
    app.processEvents()
    assert app.clipboard().text() == "SCHOWEK"
    assert term._sel_start is None and term._sel_end is None


def test_a_click_clears_an_old_selection(app, term):
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest
    term._sel_start, term._sel_end = (0, 0), (4, 0)
    QTest.mouseClick(term, Qt.MouseButton.LeftButton, pos=_pt(term, 8, 1))
    assert term._sel_start is None and term._sel_end is None


def test_a_drag_selects_and_copies(app, term):
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest
    QTest.mousePress(term, Qt.MouseButton.LeftButton, pos=_pt(term, 0, 0))
    for col in (2, 4):          # QTest.mouseMove carries no held button
        _drag_to(app, term, _pt(term, col, 0))
    QTest.mouseRelease(term, Qt.MouseButton.LeftButton, pos=_pt(term, 4, 0))
    app.processEvents()
    assert app.clipboard().text() == "hello"
