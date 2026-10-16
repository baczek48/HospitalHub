"""Closing the SSH window while work is in flight (UX audit 2026-10-16).

S-02  closing during a transfer or a listing crashed the whole process: the
      worker reported into the deleted window (QMessageBox on a destroyed
      parent, 0xC0000374).  Now the window asks first, cuts the workers'
      signals and retires the threads that are still running.
E-01  Escape closed the window with every session.
E-02  several live sessions close only after a question.

Real paramiko SSH/SFTP server in-process (socketpair), no network.
"""

import os
import sys
import time

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for _p in (_PARENT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

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


def pump(ms):
    from PyQt6.QtCore import QEvent
    from PyQt6.QtWidgets import QApplication
    end = time.monotonic() + ms / 1000
    while time.monotonic() < end:
        QApplication.processEvents()
        QApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
        time.sleep(0.005)


@pytest.fixture
def world(sp, tmp_path, monkeypatch):
    root = tmp_path / "srv"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "app.conf").write_bytes(b"key=value\n" * 20000)
    srv = FakeServer(str(root))
    monkeypatch.setattr(sp, "_make_client", srv.make_client_patch())
    monkeypatch.setattr(sp, "_SftpConnectWorker", _sftp_worker_class(sp, srv))
    warnings = []
    monkeypatch.setattr(sp.QMessageBox, "warning",
                        staticmethod(lambda *a, **k: warnings.append(a[1:3])))
    yield srv, root, warnings
    srv.drop()


def _sftp_worker_class(sp, srv):
    class W(sp._SftpConnectWorker):
        def run(self):
            try:
                client = srv.client()
                self.ready.emit(client.open_sftp(), client)
            except Exception as e:
                self.error.emit(str(e))
    return W


def open_dialog(sp):
    import models
    m = models.Machine(ip="10.0.0.7", name="t",
                       credentials=[models.Credential(login="u", password="pw")])
    dlg = sp.SshDialog(m)
    dlg.show()
    end = time.monotonic() + 8
    while time.monotonic() < end and dlg._sftp_panel._sftp is None:
        pump(50)
    assert dlg._sftp_panel._sftp is not None
    return dlg


def test_closing_during_an_upload_asks_and_never_reports_into_the_dead_window(
        sp, world, tmp_path, monkeypatch):
    srv, root, warnings = world
    srv.io_delay = 0.05
    dlg = open_dialog(sp)
    asked = []
    monkeypatch.setattr(sp.SshDialog, "_ask_close",
                        lambda self, text: asked.append(text) or True,
                        raising=False)
    local = tmp_path / "new.conf"
    local.write_bytes(b"key=NEW\n" * 60000)
    p = dlg._sftp_panel
    p._run_transfer('put', '/etc/app.conf', str(local), local.stat().st_size)
    pump(300)
    assert p.transfer_running()
    dlg.close()
    pump(2500)                         # the worker ends and reports (or not)
    assert asked and "niepełny" in asked[0]
    assert warnings == [], "nic nie trafia do zamkniętego okna"


def test_keeping_the_window_lets_the_upload_finish(sp, world, tmp_path,
                                                   monkeypatch):
    srv, root, warnings = world
    srv.io_delay = 0.02
    dlg = open_dialog(sp)
    monkeypatch.setattr(sp.SshDialog, "_ask_close", lambda self, text: False,
                        raising=False)
    local = tmp_path / "new.conf"
    data = b"key=NEW\n" * 30000
    local.write_bytes(data)
    p = dlg._sftp_panel
    p._run_transfer('put', '/etc/app.conf', str(local), len(data))
    pump(150)
    dlg.close()
    assert dlg.isVisible()
    end = time.monotonic() + 10
    while time.monotonic() < end and p.transfer_running():
        pump(50)
    assert (root / "etc" / "app.conf").read_bytes() == data
    dlg.close_without_asking()
    pump(300)


def test_closing_during_a_slow_listing_does_not_crash(sp, world, monkeypatch):
    srv, root, warnings = world
    dlg = open_dialog(sp)
    srv.list_delay = 1.5
    dlg._sftp_panel._list("/etc")
    pump(200)
    dlg.close()                        # nothing to ask: no transfer, 1 session
    pump(2500)
    assert warnings == []


def test_escape_does_not_close_the_window(sp, world):
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest
    dlg = open_dialog(sp)
    dlg._sftp_panel._table.setFocus()
    QTest.keyClick(dlg._sftp_panel._table, Qt.Key.Key_Escape)
    pump(100)
    assert dlg.isVisible()
    dlg.close_without_asking()
    pump(300)


def test_a_signal_of_a_retired_worker_reaches_nobody(sp):
    w = sp._TransferWorker(None, 'get', '/x', 'x')
    got = []
    w.error.connect(got.append)
    sp._unplug_and_retire([w])
    w.error.emit("late")
    assert got == []
