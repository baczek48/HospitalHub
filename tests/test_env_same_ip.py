"""2026-10-16 (owner): in the SSH window's Environment tab two machines with
the same IP were one card for the panel — clicking the first lit up the
other one further down.  Every machine is its own card now."""

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


def _click(ctrl=False):
    from PyQt6.QtCore import QEvent, QPointF, Qt
    from PyQt6.QtGui import QMouseEvent
    mod = Qt.KeyboardModifier.ControlModifier if ctrl else Qt.KeyboardModifier.NoModifier
    return QMouseEvent(QEvent.Type.MouseButtonPress, QPointF(5, 5), QPointF(5, 5),
                       Qt.MouseButton.LeftButton, Qt.MouseButton.LeftButton, mod)


def _env(app):
    import models
    from ui import ssh_panel as sp
    a = models.Machine(ip="10.0.60.222", name="srvAPP")
    b = models.Machine(ip="10.0.60.230", name="srvWin")
    c = models.Machine(ip="10.0.60.222", name="srvAPP-root2")
    h = models.Hospital(name="Śrem", machines=[a, b, c])
    env = sp._EnvironmentPanel(h, [h], initial_ip=c.ip, initial_machine=c)
    return env, sp, (a, b, c)


def _styles(env, sp, machines):
    return [env._cards[id(m)].styleSheet() for m in machines]


def test_each_machine_with_a_shared_ip_has_its_own_card(app):
    env, sp, (a, b, c) = _env(app)
    assert len(env._cards) == 3


def test_clicking_the_first_selects_the_first_only(app):
    env, sp, ms = _env(app)
    a, b, c = ms
    env._card_clicked(a, _click())
    st = _styles(env, sp, ms)
    assert st[0] == sp._EnvironmentPanel._STYLE_SELECTED
    assert st[2] != sp._EnvironmentPanel._STYLE_SELECTED
    env._card_clicked(c, _click())
    st = _styles(env, sp, ms)
    assert st[2] == sp._EnvironmentPanel._STYLE_SELECTED
    assert st[0] != sp._EnvironmentPanel._STYLE_SELECTED


def test_the_session_lights_up_the_machine_it_was_opened_for(app):
    env, sp, ms = _env(app)
    a, b, c = ms
    P = sp._EnvironmentPanel
    assert _styles(env, sp, ms) == [P._STYLE_IDLE, P._STYLE_IDLE, P._STYLE_ACTIVE]
    env.set_active(a.ip, a)
    assert _styles(env, sp, ms) == [P._STYLE_ACTIVE, P._STYLE_IDLE, P._STYLE_IDLE]
    env.set_active("10.0.60.222")            # a session typed by hand: first card
    assert _styles(env, sp, ms)[0] == P._STYLE_ACTIVE
    env.set_active("")
    assert _styles(env, sp, ms) == [P._STYLE_IDLE] * 3


def test_enter_opens_exactly_the_selected_machines(app):
    from PyQt6.QtCore import QEvent, Qt
    from PyQt6.QtGui import QKeyEvent
    env, sp, (a, b, c) = _env(app)
    opened = []
    env.open_machine.connect(opened.append)
    env._card_clicked(c, _click())
    env.keyPressEvent(QKeyEvent(QEvent.Type.KeyPress, Qt.Key.Key_Return,
                                Qt.KeyboardModifier.NoModifier))
    assert opened == [c]
