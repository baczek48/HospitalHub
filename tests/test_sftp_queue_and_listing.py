"""SFTP panel against a real paramiko server (UX audit 2026-10-16, Etap 71).

S-04  a name that is not UTF-8 no longer blocks the whole directory
S-05  a transfer requested during a queue joins it instead of wiping it
S-06  a dropped link ends the queue with ONE summary, in Polish
S-07  rename refuses "/", "." and ".."
      + a queued transfer keeps the connection it was queued on
"""

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
    srv, root, warnings = world
    (root / "dl").mkdir()
    for i in range(6):
        (root / "dl" / f"f{i}.log").write_bytes(b"x" * 200_000)
    d = open_dialog(sp)
    msgs = []
    d._sftp_panel.status_msg.connect(lambda t, e: msgs.append((e, t)))
    d.msgs = msgs
    yield d
    d.close_without_asking()
    pump(300)


def wait_idle(panel, timeout=15):
    end = time.monotonic() + timeout
    while time.monotonic() < end and (panel._transfer_busy() or panel._transfer_queue):
        pump(50)


def downloads(root, tmp_path, names):
    return [('get', f'/dl/{n}', str(tmp_path / n), 200_000) for n in names]


def test_s04_a_non_utf8_name_does_not_block_the_listing(sp, world, dlg):
    srv, root, warnings = world
    (root / "zażółć.txt").write_bytes(b"x")
    srv.extra_names = [b"ksi\xea\xbfka_cp1250.txt"]
    p = dlg._sftp_panel
    end = time.monotonic() + 5
    while time.monotonic() < end and p._listing_active:
        pump(50)                       # the listing at connect, if still on
    p._list("/")
    while time.monotonic() < end and p._listing_active:
        pump(50)
    names = [p._table.item(r, 0).data(0x0100)[0] for r in range(p._table.rowCount())
             if p._table.item(r, 0) is not None]
    assert "zażółć.txt" in names
    assert any("�" in n for n in names)
    assert any(not err and "UTF-8" in text for err, text in dlg.msgs)
    assert warnings == []


def test_s05_a_transfer_requested_mid_queue_joins_it(sp, world, dlg, tmp_path):
    srv, root, warnings = world
    srv.io_delay = 0.01
    p = dlg._sftp_panel
    p._enqueue_transfers(downloads(root, tmp_path, ["f0.log", "f1.log", "f2.log"]))
    pump(100)
    assert p._transfer_busy()
    p._run_transfer('get', '/dl/f3.log', str(tmp_path / "f3.log"), 200_000)
    wait_idle(p)
    got = sorted(f for f in os.listdir(tmp_path) if f.endswith(".log"))
    assert got == ["f0.log", "f1.log", "f2.log", "f3.log"]
    assert not [t for e, t in dlg.msgs if e]


def test_s06_a_dropped_link_ends_the_queue_with_one_summary(sp, world, dlg, tmp_path,
                                                            monkeypatch):
    srv, root, warnings = world
    srv.io_delay = 0.03
    p = dlg._sftp_panel
    # The session's own reconnect would bring a new connection; this test is
    # about the queue on the one that died.
    monkeypatch.setattr(sp.SshDialog, "_on_session_dropped", lambda self, s: None)
    p._enqueue_transfers(downloads(root, tmp_path, [f"f{i}.log" for i in range(6)]))
    pump(150)
    srv.drop()
    wait_idle(p)
    errors = [t for e, t in dlg.msgs if e]
    assert len(errors) == 1, errors
    assert "przerwane" in errors[0] and "Nie przesłano" in errors[0]
    assert "NoneType" not in errors[0]


def test_s07_rename_refuses_a_path(sp, world, dlg, monkeypatch):
    from PyQt6.QtWidgets import QLineEdit
    srv, root, warnings = world
    p = dlg._sftp_panel
    end = time.monotonic() + 5
    while time.monotonic() < end and p._path != "/etc":
        if not p._listing_active:
            p._list("/etc")
        pump(50)
    item = next(p._table.item(r, 0) for r in range(p._table.rowCount())
                if p._table.item(r, 0) and p._table.item(r, 0).data(0x0100)[0] == "app.conf")
    shown = []
    monkeypatch.setattr(sp.QMessageBox, "warning",
                        staticmethod(lambda *a, **k: shown.append(a[2])))
    for bad in ("../app.conf", "a/b.conf", ".."):
        p._rename_editor = QLineEdit(bad)
        p._rename_editor_data = dict(item=item, name="app.conf", is_dir=False, size=1)
        p._commit_rename()
        pump(200)
        assert (root / "etc" / "app.conf").exists()
    assert len(shown) == 3 and not (root / "app.conf").exists()


def test_a_queued_transfer_never_runs_on_another_connection(sp, world, dlg, tmp_path):
    srv, root, warnings = world
    srv.io_delay = 0.02
    p = dlg._sftp_panel
    a_sftp, a_client = p._sftp, p._ssh_client
    p._enqueue_transfers(downloads(root, tmp_path, ["f0.log", "f1.log", "f2.log"]))
    pump(80)
    other = srv.client()                       # the user switched to tab B
    p.switch_sftp(other.open_sftp(), other, "/")
    wait_idle(p)
    errors = [t for e, t in dlg.msgs if e]
    assert errors and "przełączono" in errors[0]
    assert not (tmp_path / "f2.log").exists()
    p.switch_sftp(a_sftp, a_client, "/")
