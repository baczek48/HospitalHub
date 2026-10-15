"""Application-level resilience (2026-10-14, Etap 69, audit PHASE D/E).

* D-04 — the crash hook shows a dialog only on the GUI thread, never two at
  once, at most one per interval; ``threading`` deaths are logged.
* D-05 — no write to ``sys.stderr`` without a console (the built exe has none).
* E-03 — crash.log is bounded.
"""

import os
import sys
import threading
from types import SimpleNamespace

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture
def hook(app, monkeypatch, tmp_path):
    """A freshly installed hook writing to a temporary crash.log, with the
    dialog replaced by a recorder."""
    import main
    from PyQt6 import QtWidgets
    shown = []

    class Box:
        Icon = QtWidgets.QMessageBox.Icon

        def __init__(self, *a):
            pass

        def setWindowTitle(self, t):
            pass

        def setIcon(self, i):
            pass

        def setText(self, t):
            pass

        def setInformativeText(self, t):
            shown.append(t)

        def exec(self):
            if Box.reenter is not None:
                fn, Box.reenter = Box.reenter, None
                fn()

    Box.reenter = None
    monkeypatch.setattr(QtWidgets, "QMessageBox", Box)
    monkeypatch.setattr(main, "_crash_log_path", lambda: tmp_path / "crash.log")
    old_hook, old_thread_hook = sys.excepthook, threading.excepthook
    main._install_excepthook()
    yield SimpleNamespace(main=main, hook=sys.excepthook, shown=shown, Box=Box,
                          log=tmp_path / "crash.log")
    sys.excepthook, threading.excepthook = old_hook, old_thread_hook


def raise_into(hook_fn):
    try:
        raise ValueError("boom")
    except ValueError:
        hook_fn(*sys.exc_info())


def test_d04_on_the_gui_thread_one_dialog_and_a_log_entry(hook):
    raise_into(hook.hook)
    assert len(hook.shown) == 1
    assert "ValueError: boom" in hook.log.read_text(encoding="utf-8")


def test_d04_no_dialog_from_a_worker_thread(hook):
    t = threading.Thread(target=lambda: raise_into(hook.hook))
    t.start()
    t.join()
    assert hook.shown == [], "widget poza watkiem GUI"
    assert "ValueError: boom" in hook.log.read_text(encoding="utf-8")


def test_d04_no_second_dialog_while_one_is_open(hook):
    hook.Box.reenter = lambda: raise_into(hook.hook)
    raise_into(hook.hook)
    assert len(hook.shown) == 1
    assert hook.log.read_text(encoding="utf-8").count("\n=== ") == 2, "oba zalogowane"


def test_d04_at_most_one_dialog_per_interval(hook):
    raise_into(hook.hook)
    raise_into(hook.hook)
    assert len(hook.shown) == 1


def test_d04_a_dying_thread_is_logged(hook):
    def die():
        raise RuntimeError("watek autofill padl")
    t = threading.Thread(target=die, name="autofill")
    t.start()
    t.join()
    text = hook.log.read_text(encoding="utf-8")
    assert "watek autofill padl" in text and "autofill" in text


def test_d05_no_console_no_crash(hook, monkeypatch):
    monkeypatch.setattr(sys, "stderr", None)
    raise_into(hook.hook)
    src = open(hook.main.__file__, encoding="utf-8").read()
    assert "sys.stderr.write(\n" not in src
    body = src[src.index("if not self._ipc_server.listen("):]
    body = body[:body.index("newConnection.connect")]
    assert "sys.stderr.write" not in body


def test_e03_crash_log_is_bounded(hook):
    hook.log.write_bytes(b"x" * (hook.main._CRASH_LOG_MAX + 1000))
    raise_into(hook.hook)
    assert hook.log.stat().st_size < hook.main._CRASH_LOG_MAX


# ══════════════════════════════════════════════════════════════════════════
# D-01 / D-02 — running worker threads outlive a closed window safely
# ══════════════════════════════════════════════════════════════════════════

def test_d01_a_running_thread_survives_its_parent_and_is_released_after(app):
    from PyQt6.QtCore import QObject, QThread, pyqtSignal
    from ui.thread_retire import RETIRED, retire_thread

    gate = threading.Event()

    class Blocking(QThread):
        found = pyqtSignal()

        def run(self):
            gate.wait(5)

    parent = QObject()
    worker = Blocking(parent)
    reached = []
    worker.found.connect(lambda: reached.append(True))
    worker.start()
    assert worker.isRunning()

    assert retire_thread(worker, disconnect=(worker.found,)) is True
    assert worker in RETIRED and worker.parent() is None
    parent.deleteLater()
    app.processEvents()                       # the window goes; no qFatal
    worker.found.emit()
    assert reached == [], "sygnaly do zamknietego okna rozlaczone"

    gate.set()
    assert worker.wait(5000)
    for _ in range(20):
        app.processEvents()
        if worker not in RETIRED:
            break
    assert worker not in RETIRED


def test_d01_a_finished_thread_is_not_held(app):
    from PyQt6.QtCore import QThread
    from ui.thread_retire import RETIRED, retire_thread
    t = QThread()
    assert retire_thread(t) is False and t not in RETIRED
    assert retire_thread(None) is False


def test_d02_a_monitor_is_never_terminated(app, monkeypatch):
    from ui import vpn_panel
    calls = []

    class Old:
        twofa_detected = SimpleNamespace(disconnect=lambda: None)
        finished = SimpleNamespace(disconnect=lambda: None, connect=lambda f: None)

        def isRunning(self):
            return True

        def terminate(self):
            calls.append("terminate")

        def setParent(self, p):
            pass

    class New:
        def __init__(self, idx, process, parent):
            self.twofa_detected = SimpleNamespace(connect=lambda f: None)
            self.finished = SimpleNamespace(connect=lambda f: None)

        def start(self):
            calls.append("start")

    monkeypatch.setattr(vpn_panel, "VpnMonitorWorker", New)
    panel = vpn_panel.VpnPanel.__new__(vpn_panel.VpnPanel)
    panel.__dict__.update(_monitor_workers={0: Old()}, _on_2fa_detected=lambda i: None)
    vpn_panel.VpnPanel._start_monitor(panel, 0, object())
    assert "terminate" not in calls and calls == ["start"]


def test_d01_a_second_click_does_not_start_a_second_token_waiter():
    src = open(os.path.join(_PARENT, "ui", "detail_panel.py"), encoding="utf-8").read()
    body = src[src.index("class _TokenWindowWaiter(QThread):"):]
    body = body[:body.index("waiter.start()")]
    assert body.index("busy") < body.index("waiter = _TokenWindowWaiter(self)")


# ══════════════════════════════════════════════════════════════════════════
# E-01 — orphaned SFTP temp folders
# ══════════════════════════════════════════════════════════════════════════

def test_e01_folders_of_dead_processes_are_removed_live_ones_kept(tmp_path):
    import main
    tmp_path = tmp_path / "Temp"
    tmp_path.mkdir()
    for name in ("HospitalHubV2_111", "HospitalHubV2_222", "HospitalHubV2_x",
                 "HospitalHub_333", "other"):
        d = tmp_path / name
        d.mkdir()
        (d / "msg.hl7").write_text(r"MSH|^~\&|", encoding="utf-8")
    removed = main.cleanup_orphan_temp_dirs(str(tmp_path),
                                            pid_alive=lambda pid: pid == 222)
    assert [os.path.basename(p) for p in removed] == ["HospitalHubV2_111"]
    left = sorted(p.name for p in tmp_path.iterdir())
    assert left == ["HospitalHubV2_222", "HospitalHubV2_x", "HospitalHub_333", "other"]


def test_e01_an_unreadable_temp_root_is_harmless(tmp_path):
    import main
    assert main.cleanup_orphan_temp_dirs(str(tmp_path / "missing")) == []


def test_e01_the_own_process_is_alive():
    import main
    assert main._pid_alive(os.getpid()) is True


def test_e01_startup_runs_the_cleanup():
    src = open(os.path.join(_PARENT, "main.py"), encoding="utf-8").read()
    body = src[src.index("def main():"):]
    assert "cleanup_orphan_temp_dirs()" in body


def test_n4_retired_threads_get_a_bounded_wait_at_exit(app):
    from ui import thread_retire
    waited = []

    class T:
        def wait(self, ms):
            waited.append(ms)

    thread_retire.RETIRED.add(T())
    try:
        thread_retire.wait_for_retired(500)
    finally:
        thread_retire.RETIRED.clear()
    assert waited and all(0 < ms <= 500 for ms in waited)


def test_n1_a_nonexistent_pid_is_dead_and_the_own_one_alive():
    import main
    assert main._pid_alive(os.getpid()) is True
    assert main._pid_alive(0x7FFFFFF0) is False


def test_n2_each_status_probe_is_freed_when_done():
    src = open(os.path.join(_PARENT, "ui", "detail_panel.py"), encoding="utf-8").read()
    body = src[src.index("    def _poll_vpn_status(self):"):]
    body = body[:body.index("probe.start()")]
    assert "probe.finished.connect(probe.deleteLater)" in body
