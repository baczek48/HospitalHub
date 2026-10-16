"""2026-10-16 (owner's request): whole folders go to SFTP, not only files —
by the "Wgraj → Folder…" menu and by dropping a folder from Explorer.
Against a real paramiko server on localhost (tests/ssh_fake_server.py)."""

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
    msgs = []
    d._sftp_panel.status_msg.connect(lambda t, e: msgs.append((e, t)))
    d.msgs = msgs
    yield d
    d.close_without_asking()
    pump(300)


def wait_done(panel, timeout=15):
    end = time.monotonic() + timeout
    pump(100)
    while time.monotonic() < end and (panel._transfer_busy() or panel._transfer_queue
                                      or any(w.isRunning() for w in panel._workers
                                             if hasattr(w, "isRunning"))):
        pump(50)
    pump(100)


def at(panel, path):
    end = time.monotonic() + 5
    while time.monotonic() < end and (panel._path != path or panel._listing_active):
        if not panel._listing_active and panel._path != path:
            panel._list(path)
        pump(50)


def tree(tmp_path):
    src = tmp_path / "raporty"
    (src / "2026" / "pazdziernik").mkdir(parents=True)
    (src / "pusty").mkdir()
    (src / "a.txt").write_bytes(b"A" * 10)
    (src / "2026" / "b.log").write_bytes(b"B" * 3000)
    (src / "2026" / "pazdziernik" / "zażółć.csv").write_bytes(b"C" * 5)
    return src


def test_a_folder_is_uploaded_with_its_structure(sp, world, dlg, tmp_path):
    srv, root, warnings = world
    p = dlg._sftp_panel
    at(p, "/")
    p._begin_uploads([str(tree(tmp_path))])
    wait_done(p)
    up = root / "raporty"
    assert (up / "a.txt").read_bytes() == b"A" * 10
    assert (up / "2026" / "b.log").read_bytes() == b"B" * 3000
    assert (up / "2026" / "pazdziernik" / "zażółć.csv").read_bytes() == b"C" * 5
    assert (up / "pusty").is_dir()
    assert not [t for e, t in dlg.msgs if e]


def test_an_existing_folder_is_merged_and_conflicts_asked_by_path(sp, world, dlg,
                                                                tmp_path, monkeypatch):
    srv, root, warnings = world
    (root / "raporty" / "2026").mkdir(parents=True)
    (root / "raporty" / "2026" / "b.log").write_bytes(b"old")
    (root / "raporty" / "stary.txt").write_bytes(b"keep")
    asked = []
    monkeypatch.setattr(sp.SftpPanel, "_ask_overwrite",
                        lambda self, paths: asked.append(
                            [self._shown_name(x) for x in paths]) or "skip")
    p = dlg._sftp_panel
    at(p, "/")
    p._begin_uploads([str(tree(tmp_path))])
    wait_done(p)
    assert asked == [["raporty/2026/b.log"]]
    assert (root / "raporty" / "2026" / "b.log").read_bytes() == b"old"
    assert (root / "raporty" / "stary.txt").read_bytes() == b"keep"
    assert (root / "raporty" / "a.txt").exists()


def test_a_file_where_a_folder_should_be_stops_the_upload(sp, world, dlg, tmp_path,
                                                          monkeypatch):
    srv, root, warnings = world
    (root / "raporty").write_bytes(b"to jest plik")
    shown = []
    monkeypatch.setattr(sp.QMessageBox, "warning",
                        staticmethod(lambda *a, **k: shown.append(a[2])))
    p = dlg._sftp_panel
    at(p, "/")
    p._begin_uploads([str(tree(tmp_path))])
    wait_done(p)
    assert shown and "folder" in shown[0]
    assert (root / "raporty").read_bytes() == b"to jest plik"


def test_a_big_folder_asks_first_and_no_sends_nothing(sp, world, dlg, tmp_path,
                                                     monkeypatch):
    from ui import utils
    srv, root, warnings = world
    monkeypatch.setattr(sp.SftpPanel, "_FOLDER_CONFIRM_FILES", 2)
    asked = []
    monkeypatch.setattr(utils, "confirm", lambda *a, **k: asked.append(a[2]) or False)
    p = dlg._sftp_panel
    at(p, "/")
    p._begin_uploads([str(tree(tmp_path))])
    wait_done(p)
    assert asked and "3 plików" in asked[0]
    assert not (root / "raporty").exists()


def test_a_huge_folder_is_refused(sp, world, dlg, tmp_path, monkeypatch):
    srv, root, warnings = world
    monkeypatch.setattr(sp.SftpPanel, "_FOLDER_MAX_FILES", 1)
    shown = []
    monkeypatch.setattr(sp.QMessageBox, "warning",
                        staticmethod(lambda *a, **k: shown.append(a[2])))
    p = dlg._sftp_panel
    at(p, "/")
    p._begin_uploads([str(tree(tmp_path))])
    assert shown and "ponad 1 plików" in shown[0]
    assert not (root / "raporty").exists()


def test_dropping_a_folder_from_explorer_uploads_it(sp, world, dlg, tmp_path,
                                                    monkeypatch):
    from types import SimpleNamespace
    from PyQt6.QtCore import QUrl
    srv, root, warnings = world
    p = dlg._sftp_panel
    at(p, "/")
    src = tree(tmp_path)
    got = []
    monkeypatch.setattr(p, "_begin_uploads", lambda paths: got.append(paths))
    ev = SimpleNamespace(mimeData=lambda: SimpleNamespace(
        urls=lambda: [QUrl.fromLocalFile(str(src))]))
    p.dropEvent(ev)
    assert got and os.path.normpath(got[0][0]) == os.path.normpath(str(src))


def test_the_upload_button_offers_files_and_a_folder(sp, world, dlg):
    menu = dlg._sftp_panel._btn_ul.menu()
    assert [a.text() for a in menu.actions()] == ["Pliki…", "Folder…"]
