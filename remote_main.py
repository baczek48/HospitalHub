# Copyright © 2026 Sebastian Bąk. All rights reserved.
"""HospitalHub Remote — HospitalHub for a hospital's own remote machine.

Portable: no installation, nothing written outside its folder except the
temporary files of SFTP and the SSH host keys of the Windows user.  The
settings and crash.log go to ``dane\\`` next to the exe, or to
%APPDATA%\\HospitalHubRemote when the folder is read-only.

One vault — the hospital exported from HospitalHub — opens in one window:
machines on the left, terminal on the right (ui/remote_window.py).
"""

import os
import sys


def _program_dir() -> str:
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def _writable(folder: str) -> bool:
    try:
        os.makedirs(folder, exist_ok=True)
        probe = os.path.join(folder, f".probe-{os.getpid()}")
        with open(probe, "w") as f:
            f.write("")
        os.remove(probe)
        return True
    except OSError:
        return False


def data_dir(program_dir: str) -> str:
    """``dane`` beside the program, else a folder of the Windows user."""
    portable = os.path.join(program_dir, "dane")
    if _writable(portable):
        return portable
    base = os.environ.get("APPDATA") or os.path.expanduser("~")
    return os.path.join(base, "HospitalHubRemote")


PROGRAM_DIR = _program_dir()
sys.path.insert(0, PROGRAM_DIR)

import main as hh  # noqa: E402  (excepthook, theme, shutdown)
from PyQt6.QtCore import Qt, QTimer  # noqa: E402
from PyQt6.QtNetwork import QLocalServer, QLocalSocket  # noqa: E402
from PyQt6.QtWidgets import QApplication  # noqa: E402


_IPC_CHANNEL = hh._ipc_channel_name().replace("HospitalHubV2_", "HospitalHubRemote_")


class RemoteApp:
    """Login → window; "Otwórz inny vault" goes round again; closing the
    window ends the program."""

    def __init__(self, app: QApplication):
        self._app = app
        self._window = None
        self._switching = False
        app.setQuitOnLastWindowClosed(False)
        self._ipc = QLocalServer()
        self._ipc.setSocketOptions(QLocalServer.SocketOption.UserAccessOption)
        self._ipc.removeServer(_IPC_CHANNEL)
        self._ipc.listen(_IPC_CHANNEL)
        self._ipc.newConnection.connect(self._on_ipc)

    def _on_ipc(self):
        conn = self._ipc.nextPendingConnection()
        if conn:
            conn.waitForReadyRead(500)
            conn.close()
        w = self._window
        if w is not None:
            if w.isMinimized():
                w.showMaximized() if w._was_maximized else w.showNormal()
            w.raise_()
            w.activateWindow()

    def login(self) -> None:
        from config import load_last_vault, save_last_vault
        from ui.remote_login import RemoteLoginDialog
        dlg = RemoteLoginDialog(PROGRAM_DIR, load_last_vault() or "")
        if not dlg.exec() or dlg.get_result() is None:
            self._app.quit()
            return
        path, password, hospitals, admin_hash, admin_salt = dlg.get_result()
        save_last_vault(path)
        from ui.remote_window import RemoteWindow
        w = RemoteWindow(path, password, hospitals, admin_hash, admin_salt)
        # The HospitalHub icon, not the SSH window's own (owner, 2026-10-28).
        w.setWindowIcon(hh.make_icon())
        w.switch_vault_requested.connect(self._switch_vault)
        w.destroyed.connect(self._on_window_gone)
        self._window = w
        w.showMaximized()

    def _switch_vault(self) -> None:
        w = self._window
        if w is None:
            return
        self._switching = True
        w.close()
        if w.isVisible():              # the user kept the window
            self._switching = False

    def _on_window_gone(self, *_):
        self._window = None
        if self._switching:
            self._switching = False
            QTimer.singleShot(0, self.login)
        else:
            self._app.quit()


def _activate_existing() -> bool:
    sock = QLocalSocket()
    sock.connectToServer(_IPC_CHANNEL)
    if sock.waitForConnected(1000):
        sock.write(b"activate")
        sock.waitForBytesWritten(1000)
        sock.disconnectFromServer()
        return True
    return False


def main():
    # Before anything reads the settings or writes crash.log: both follow
    # HH_DATA_DIR (config.app_data_dir, main._crash_log_path).
    os.environ.setdefault("HH_DATA_DIR", data_dir(PROGRAM_DIR))
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough)
    app = QApplication(sys.argv)
    app.setApplicationName("HospitalHub Remote")
    hh.install_polish_translations(app)
    hh.cleanup_orphan_temp_dirs()
    if _activate_existing():
        sys.exit(0)
    try:
        from config import load_theme
        from ui import theme as _theme
        chosen = load_theme()
    except Exception:
        chosen = "dark"
    if chosen != "dark":
        _theme.install(app, chosen)
    else:
        hh.apply_dark_theme(app)
    app.setWindowIcon(hh.make_icon())

    remote = RemoteApp(app)
    QTimer.singleShot(0, remote.login)
    hh.finish_and_exit(app.exec())


if __name__ == "__main__":
    main()
