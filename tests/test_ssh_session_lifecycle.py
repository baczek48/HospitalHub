"""SSH session lifecycle against a real paramiko server (socketpair, no network).

UX audit 2026-10-16 (Etap 71):
  S-01  a dropped link must reach the auto-reconnect path, a normal ``exit``
        must not.
"""

import os
import sys
import time

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

pytest.importorskip("paramiko")
from ssh_fake_server import FakeServer  # noqa: E402


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture
def sp(app):
    from ui import ssh_panel
    return ssh_panel


@pytest.fixture
def server(tmp_path, sp, monkeypatch):
    srv = FakeServer(str(tmp_path))
    monkeypatch.setattr(sp, "_make_client", srv.make_client_patch())
    yield srv
    srv.drop()


def pump_until(cond, timeout=5.0):
    from PyQt6.QtWidgets import QApplication
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        QApplication.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return cond()


def start_worker(sp):
    w = sp._SshWorker("10.0.0.5", "u", "pw", 80, 24)
    got = {"connected": 0, "dropped": 0, "done": 0, "out": []}
    w.connected.connect(lambda: got.__setitem__("connected", got["connected"] + 1))
    w.dropped.connect(lambda: got.__setitem__("dropped", got["dropped"] + 1))
    w.done.connect(lambda: got.__setitem__("done", got["done"] + 1))
    w.output.connect(got["out"].append)
    w.start()
    assert pump_until(lambda: got["connected"] == 1)
    return w, got


@pytest.mark.parametrize("attempt", range(5))
def test_a_dropped_link_reaches_auto_reconnect(sp, server, attempt):
    w, got = start_worker(sp)
    server.drop()
    assert pump_until(lambda: got["done"] == 1)
    w.wait(2000)
    assert got["dropped"] == 1, "zerwane łącze sklasyfikowane jak zwykłe wyjście"


def test_exit_is_a_normal_end_not_a_drop(sp, server):
    w, got = start_worker(sp)
    w.send(b"exit\r")
    assert pump_until(lambda: got["done"] == 1)
    w.wait(2000)
    assert got["dropped"] == 0
