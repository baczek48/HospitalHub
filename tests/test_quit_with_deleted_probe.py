"""2026-10-17 (owner's crash.log from another computer): with a VPN vault
window open the hospital panel's status probe runs, finishes and deletes
itself; closing the application then raised "wrapped C/C++ object of type
_VpnStatusProbe has been deleted" in cleanup — and the application did not
close, on every attempt."""

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


def test_cleanup_survives_a_probe_that_deleted_itself(app):
    from PyQt6 import sip
    from PyQt6.QtTest import QTest
    from ui import detail_panel as dp
    panel = dp.DetailPanel()
    probe = dp._VpnStatusProbe(("FortiClient", "", ""), "FortiClient", "", "", panel)
    probe.run = lambda: None
    probe.finished.connect(probe.deleteLater)
    panel._vpn_status_probe = probe
    probe.start()
    for _ in range(50):
        QTest.qWait(10)
        if sip.isdeleted(probe):
            break
    assert sip.isdeleted(probe)
    panel.cleanup()                     # raised RuntimeError before


def test_quit_all_closes_even_if_a_window_cleanup_fails(app, monkeypatch, tmp_path):
    import main
    quits = []

    class W:
        _unsaved = False

        def destroy_cleanup(self):
            raise RuntimeError("wrapped C/C++ object has been deleted")

    mgr = main.AppManager.__new__(main.AppManager)
    mgr._windows = [W()]
    mgr._trays = {}
    mgr._app = type("A", (), {"quit": lambda self: quits.append(1)})()
    monkeypatch.setattr(main.AppManager, "_close_all_ssh_dialogs", staticmethod(lambda: None))
    monkeypatch.setattr(main, "_crash_log_path", lambda: tmp_path / "crash.log")
    mgr._quit_all()
    assert quits == [1]
    assert "destroy_cleanup" in (tmp_path / "crash.log").read_text(encoding="utf-8")


def test_quit_all_takes_every_window_off_the_screen_first(app, monkeypatch, tmp_path):
    """2026-10-21: after "Zamknij wszystko" the VPN window sometimes stayed
    on top, frozen, through the clean-up — until its X was clicked."""
    import main
    from PyQt6.QtWidgets import QWidget
    vpn_window, other = QWidget(), QWidget()
    vpn_window.show()
    other.show()
    seen_at_cleanup = []

    def close_ssh():
        seen_at_cleanup.append((vpn_window.isVisible(), other.isVisible()))

    class W:
        _unsaved = False

        def destroy_cleanup(self):
            pass

    mgr = main.AppManager.__new__(main.AppManager)
    mgr._windows = [W()]
    mgr._trays = {}
    mgr._app = type("A", (), {"quit": lambda self: None})()
    monkeypatch.setattr(main.AppManager, "_close_all_ssh_dialogs", staticmethod(close_ssh))
    mgr._quit_all()
    assert seen_at_cleanup == [(False, False)]
    vpn_window.deleteLater()
    other.deleteLater()


def test_the_exit_has_a_watchdog():
    import inspect
    import main
    src = inspect.getsource(main.main)
    assert "threading.Timer(10.0" in src and "os._exit" in src
    assert src.index("_hide_all_windows") < src.index("_cleanup_sftp_temp()")
    # the watchdog never skips the removal of RDP credentials and a secret
    assert src.index("cleanup_pending_credentials()") < src.index("threading.Timer(")
    assert src.index("clear_secret_from_clipboard()") < src.index("threading.Timer(")
