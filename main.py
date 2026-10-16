# Copyright © 2026 Sebastian Bąk. All rights reserved.

import atexit
import shutil
import sys
import os
import tempfile
import traceback
from datetime import datetime
from pathlib import Path

# Ensure vault_app directory is on the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _crash_log_path() -> Path:
    base = os.environ.get("APPDATA") or str(Path.home())
    d = Path(base) / "HospitalHubV2"
    try:
        d.mkdir(parents=True, exist_ok=True)
    except Exception:
        pass
    return d / "crash.log"


#: crash.log is kept to its last ~256 KB once it passes this (E-03).
_CRASH_LOG_MAX = 512 * 1024
#: At most one error dialog per this many seconds (D-04).
_ERROR_DIALOG_INTERVAL_S = 10.0


def _append_crash_log(log_path: Path, text: str) -> None:
    """Append to crash.log, trimming it first when it has grown too big."""
    try:
        try:
            if log_path.stat().st_size > _CRASH_LOG_MAX:
                with open(log_path, "rb") as f:
                    f.seek(-_CRASH_LOG_MAX // 2, os.SEEK_END)
                    tail = f.read()
                with open(log_path, "wb") as f:
                    f.write(tail)
        except OSError:
            pass
        with open(log_path, "a", encoding="utf-8") as f:
            f.write(text)
    except Exception:
        pass


def _install_excepthook():
    """Replace PyQt6's default excepthook so an uncaught exception in a slot
    no longer aborts the process (PyQt6 ≥6.4 calls qFatal). We log the full
    traceback and show a dialog instead — so a single AttributeError in a UI
    handler can't kill the app while the user has unsaved data.

    2026-10-14 (D-04): the dialog only on the GUI thread (an exception in a
    QThread.run arrives here on the worker thread, where creating a widget is
    itself an error), never while one is already open (``exec`` runs a nested
    event loop — a timer raising every 2 s used to stack dialogs), and at most
    one per ``_ERROR_DIALOG_INTERVAL_S``.  Threads started with ``threading``
    are logged too (they died silently before)."""
    import threading
    import time as _time
    log_path = _crash_log_path()
    state = {"showing": False, "last": 0.0}

    def _log(exc_type, exc_value, exc_tb, where=""):
        text = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        _append_crash_log(
            log_path,
            f"\n=== {datetime.now().isoformat(timespec='seconds')}{where} ===\n{text}")
        try:
            from diagnostics import actionlog
            actionlog.exception_text(text, where)
        except Exception:
            pass
        try:
            if sys.stderr is not None:
                sys.stderr.write(text)
        except Exception:
            pass

    def _hook(exc_type, exc_value, exc_tb):
        if issubclass(exc_type, KeyboardInterrupt):
            sys.__excepthook__(exc_type, exc_value, exc_tb)
            return
        _log(exc_type, exc_value, exc_tb)
        try:
            from PyQt6.QtCore import QThread
            from PyQt6.QtWidgets import QApplication, QMessageBox
            app = QApplication.instance()
            if app is None or QThread.currentThread() is not app.thread():
                return
            now = _time.monotonic()
            if state["showing"] or now - state["last"] < _ERROR_DIALOG_INTERVAL_S:
                return
            state["showing"], state["last"] = True, now
            try:
                short = "".join(
                    traceback.format_exception_only(exc_type, exc_value)
                ).strip()
                box = QMessageBox()
                box.setWindowTitle("Błąd aplikacji")
                box.setIcon(QMessageBox.Icon.Warning)
                box.setText("Wystąpił nieoczekiwany błąd. Aplikacja kontynuuje pracę.")
                box.setInformativeText(f"{short}\n\nSzczegóły zapisano w:\n{log_path}")
                box.exec()
            finally:
                state["showing"] = False
        except Exception:
            pass

    def _thread_hook(args):
        if args.exc_type is SystemExit:
            return
        _log(args.exc_type, args.exc_value, args.exc_traceback,
             f" (wątek {getattr(args.thread, 'name', '?')})")

    sys.excepthook = _hook
    threading.excepthook = _thread_hook


_install_excepthook()


def _cleanup_sftp_temp():
    """Remove SFTP temp directory on exit (best-effort)."""
    tmp_dir = os.path.join(tempfile.gettempdir(),
                           f'HospitalHubV2_{os.getpid()}')
    if os.path.isdir(tmp_dir):
        shutil.rmtree(tmp_dir, ignore_errors=True)


atexit.register(_cleanup_sftp_temp)


def _pid_alive(pid: int) -> bool:
    """Is a process with this id running?  Unknown counts as yes (keep)."""
    if pid == os.getpid():
        return True
    try:
        import ctypes
        from ctypes import wintypes
        # use_last_error: the error code is captured right after the call,
        # not whenever Python gets round to asking (review 69/N1).
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.OpenProcess.restype = wintypes.HANDLE
        kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
        handle = kernel32.OpenProcess(0x1000, False, pid)   # QUERY_LIMITED_INFORMATION
        if not handle:
            # 87 = ERROR_INVALID_PARAMETER: no such process.  Anything else
            # (access denied…) means it exists.
            return ctypes.get_last_error() != 87
        try:
            code = ctypes.c_ulong()
            if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
                return True
            return code.value == 259                        # STILL_ACTIVE
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        return True


def cleanup_orphan_temp_dirs(tmp_root: str | None = None, pid_alive=_pid_alive) -> list:
    """Remove ``HospitalHubV2_<pid>`` folders left by processes that are gone.

    2026-10-14 (E-01): they hold plain copies of files opened from SFTP — on
    hospital servers possibly HL7 messages with patient data — and a crash or
    a killed process left them in %TEMP% for good.  Folders of live processes
    (another running instance, or a reused pid) are never touched.
    Returns the removed paths.  Never raises.
    """
    removed = []
    try:
        root = tmp_root or tempfile.gettempdir()
        for name in os.listdir(root):
            if not name.startswith("HospitalHubV2_"):
                continue
            suffix = name[len("HospitalHubV2_"):]
            if not suffix.isdigit():
                continue
            path = os.path.join(root, name)
            if not os.path.isdir(path) or pid_alive(int(suffix)):
                continue
            shutil.rmtree(path, ignore_errors=True)
            if not os.path.exists(path):
                removed.append(path)
    except Exception:
        pass
    return removed

from PyQt6.QtWidgets import QApplication, QSystemTrayIcon, QMenu, QMessageBox
from PyQt6.QtGui import (QPalette, QColor, QIcon, QPixmap, QPainter,
                          QPainterPath, QPen, QAction)
from PyQt6.QtCore import Qt, QRectF
from PyQt6.QtNetwork import QLocalServer, QLocalSocket

from ui.login_dialog import LoginDialog
from ui.main_window import MainWindow


def apply_dark_theme(app: QApplication):
    app.setStyle("Fusion")
    palette = QPalette()

    dark_bg = QColor(30, 30, 35)
    mid_bg = QColor(42, 42, 48)
    light_bg = QColor(55, 55, 62)
    highlight = QColor(0, 120, 215)
    text = QColor(220, 220, 220)
    dim_text = QColor(140, 140, 140)

    palette.setColor(QPalette.ColorRole.Window, dark_bg)
    palette.setColor(QPalette.ColorRole.WindowText, text)
    palette.setColor(QPalette.ColorRole.Base, mid_bg)
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor(36, 36, 42))
    palette.setColor(QPalette.ColorRole.ToolTipBase, light_bg)
    palette.setColor(QPalette.ColorRole.ToolTipText, text)
    palette.setColor(QPalette.ColorRole.Text, text)
    palette.setColor(QPalette.ColorRole.Button, light_bg)
    palette.setColor(QPalette.ColorRole.ButtonText, text)
    palette.setColor(QPalette.ColorRole.BrightText, QColor(255, 80, 80))
    palette.setColor(QPalette.ColorRole.Link, highlight)
    palette.setColor(QPalette.ColorRole.Highlight, highlight)
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor(255, 255, 255))
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor(110, 118, 129))
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.Text, dim_text)
    palette.setColor(QPalette.ColorGroup.Disabled, QPalette.ColorRole.ButtonText, dim_text)
    palette.setColor(QPalette.ColorRole.Mid, light_bg)
    palette.setColor(QPalette.ColorRole.Dark, QColor(20, 20, 24))

    app.setPalette(palette)


def make_icon() -> QIcon:
    """Draws a shield with a medical cross — used as the app icon."""
    size = 256
    px = QPixmap(size, size)
    px.fill(Qt.GlobalColor.transparent)

    p = QPainter(px)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)

    # Shield shape
    shield = QPainterPath()
    w, h = size, size
    shield.moveTo(w * 0.5, h * 0.05)
    shield.lineTo(w * 0.92, h * 0.22)
    shield.cubicTo(w * 0.92, h * 0.60, w * 0.72, h * 0.85, w * 0.50, h * 0.96)
    shield.cubicTo(w * 0.28, h * 0.85, w * 0.08, h * 0.60, w * 0.08, h * 0.22)
    shield.closeSubpath()

    # Fill shield — dark blue gradient feel via solid color
    p.fillPath(shield, QColor(18, 52, 96))

    # Shield border
    pen = QPen(QColor(41, 128, 215), size * 0.03)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.drawPath(shield)

    # Medical cross — white, centered
    cx, cy = w * 0.5, h * 0.50
    arm = w * 0.14
    thick = w * 0.10
    cross = QPainterPath()
    cross.addRoundedRect(QRectF(cx - thick / 2, cy - arm - thick / 2, thick, arm * 2 + thick), 4, 4)
    cross.addRoundedRect(QRectF(cx - arm - thick / 2, cy - thick / 2, arm * 2 + thick, thick), 4, 4)
    p.setPen(Qt.PenStyle.NoPen)
    p.fillPath(cross, QColor(235, 245, 255))

    p.end()
    return QIcon(px)


def make_vpn_icon() -> QIcon:
    """Draws a shield with a key symbol — used for VPN vault windows."""
    size = 256
    px = QPixmap(size, size)
    px.fill(Qt.GlobalColor.transparent)

    p = QPainter(px)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)

    # Shield shape (same as main icon)
    shield = QPainterPath()
    w, h = size, size
    shield.moveTo(w * 0.5, h * 0.05)
    shield.lineTo(w * 0.92, h * 0.22)
    shield.cubicTo(w * 0.92, h * 0.60, w * 0.72, h * 0.85, w * 0.50, h * 0.96)
    shield.cubicTo(w * 0.28, h * 0.85, w * 0.08, h * 0.60, w * 0.08, h * 0.22)
    shield.closeSubpath()

    # Fill shield — teal/green for VPN
    p.fillPath(shield, QColor(12, 60, 52))

    # Shield border — green
    pen = QPen(QColor(34, 180, 140), size * 0.03)
    pen.setJoinStyle(Qt.PenJoinStyle.RoundJoin)
    p.setPen(pen)
    p.drawPath(shield)

    # Lock body
    cx, cy = w * 0.5, h * 0.52
    lock_w, lock_h = w * 0.28, h * 0.20
    lock_body = QPainterPath()
    lock_body.addRoundedRect(QRectF(cx - lock_w / 2, cy, lock_w, lock_h), 6, 6)
    p.setPen(Qt.PenStyle.NoPen)
    p.fillPath(lock_body, QColor(220, 240, 235))

    # Lock shackle (arc)
    shackle_pen = QPen(QColor(220, 240, 235), size * 0.04)
    shackle_pen.setCapStyle(Qt.PenCapStyle.RoundCap)
    p.setPen(shackle_pen)
    shackle_r = w * 0.10
    p.drawArc(QRectF(cx - shackle_r, cy - shackle_r * 1.4, shackle_r * 2, shackle_r * 2),
              0 * 16, 180 * 16)

    # Keyhole
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(QColor(12, 60, 52))
    kh_r = size * 0.03
    p.drawEllipse(QRectF(cx - kh_r, cy + lock_h * 0.3 - kh_r, kh_r * 2, kh_r * 2))
    p.drawRect(QRectF(cx - kh_r * 0.5, cy + lock_h * 0.3, kh_r, lock_h * 0.35))

    p.end()
    return QIcon(px)


# ------------------------------------------------------------------ #
# Application Manager — manages tray icon and multiple windows        #
# ------------------------------------------------------------------ #

_TRAY_MENU_STYLE = (
    "QMenu { background:#1e1e23; border:1px solid #30363d; color:#c9d1d9; }"
    "QMenu::item { padding:5px 20px 5px 12px; }"
    "QMenu::item:selected { background:#1f6feb; color:#fff; }"
    "QMenu::separator { height:1px; background:#30363d; margin:2px 0; }"
)


class AppManager:
    """Singleton managing per-window tray icons and all open MainWindow instances."""

    def __init__(self, app: QApplication):
        self._app = app
        self._windows: list[MainWindow] = []
        self._trays: dict[MainWindow, QSystemTrayIcon] = {}
        self._default_icon = make_icon()
        self._vpn_icon = make_vpn_icon()

        # Don't quit when all windows are hidden
        app.setQuitOnLastWindowClosed(False)

        # IPC server — listens for "activate" from second instances
        self._ipc_server = QLocalServer()
        # Only this user may connect (C5-01): the pipe is otherwise reachable
        # by other sessions on a shared (RDS) server.
        self._ipc_server.setSocketOptions(
            QLocalServer.SocketOption.UserAccessOption)
        self._ipc_server.removeServer(_IPC_CHANNEL)
        if not self._ipc_server.listen(_IPC_CHANNEL):
            # Not fatal — the app works; a second start just opens a second
            # instance instead of raising this one.  Recorded for diagnosis —
            # in crash.log: the built exe has no console, sys.stderr is None
            # and writing to it raised at startup (D-05).
            _append_crash_log(
                _crash_log_path(),
                f"\n=== {datetime.now().isoformat(timespec='seconds')} ===\n"
                f"single-instance: listen failed: {self._ipc_server.errorString()}\n")
        self._ipc_server.newConnection.connect(self._on_ipc_connection)

    def icon_for_type(self, vault_type: str) -> QIcon:
        return self._vpn_icon if vault_type == "vpn" else self._default_icon

    def add_window(self, window: MainWindow):
        self._windows.append(window)
        window.open_vault_requested.connect(self._on_open_vault_requested)
        window.force_close_requested.connect(lambda w=window: self._force_close_window(w))

        # Create dedicated tray icon for this window
        icon = self.icon_for_type(window._vault_type)
        tray = QSystemTrayIcon(icon)
        tray.setToolTip(window.windowTitle())
        tray.activated.connect(lambda reason, w=window: self._on_tray_activated(reason, w))
        self._trays[window] = tray
        self._rebuild_tray_menu(window)
        tray.show()

        window.title_changed.connect(lambda w=window: self._on_title_changed(w))

    def remove_window(self, window: MainWindow):
        tray = self._trays.pop(window, None)
        if tray:
            tray.hide()
        if window in self._windows:
            self._windows.remove(window)
        if not self._windows:
            self._close_all_ssh_dialogs()
            self._app.quit()

    @staticmethod
    def _close_all_ssh_dialogs():
        """Close all open top-level SshDialog windows so their QThreads/sessions
        don't keep the process alive after the main windows are gone."""
        try:
            from ui.ssh_panel import SshDialog
        except Exception:
            return
        for dlg in list(SshDialog._alive):
            try:
                dlg.close_without_asking()
            except Exception:
                pass

    def _on_title_changed(self, window: MainWindow):
        tray = self._trays.get(window)
        if tray:
            tray.setToolTip(window.windowTitle())
            self._rebuild_tray_menu(window)

    def _rebuild_tray_menu(self, window: MainWindow):
        tray = self._trays.get(window)
        if not tray:
            return
        menu = QMenu()
        menu.setStyleSheet(_TRAY_MENU_STYLE)

        act_show = menu.addAction(f"Pokaż: {window.windowTitle().split('[')[0].strip()}")
        act_show.triggered.connect(lambda checked, w=window: self._show_window(w))
        menu.addSeparator()

        act_open = menu.addAction("Otwórz vault...")
        act_open.triggered.connect(self._on_open_vault_requested)
        menu.addSeparator()

        act_close = menu.addAction("Zamknij to okno")
        act_close.triggered.connect(lambda checked, w=window: self._force_close_window(w))

        act_quit = menu.addAction("Zamknij wszystko")
        act_quit.triggered.connect(self._quit_all)

        tray.setContextMenu(menu)

    def _show_window(self, window: MainWindow):
        window.show()
        window.raise_()
        window.activateWindow()

    def _on_ipc_connection(self):
        """Another instance asked us to activate — show all windows via Qt."""
        conn = self._ipc_server.nextPendingConnection()
        if conn:
            conn.waitForReadyRead(500)
            conn.close()
        for w in self._windows:
            self._show_window(w)

    def _on_tray_activated(self, reason, window: MainWindow):
        if reason == QSystemTrayIcon.ActivationReason.Trigger:
            if window.isVisible():
                window.hide()
            else:
                self._show_window(window)

    def _force_close_window(self, window: MainWindow):
        if window._unsaved:
            window.show()
            window.raise_()
            box = QMessageBox(window)
            box.setWindowTitle("Niezapisane zmiany")
            box.setText("Masz niezapisane zmiany. Zapisać przed zamknięciem?")
            box.setIcon(QMessageBox.Icon.Question)
            btn_yes = box.addButton("Tak", QMessageBox.ButtonRole.YesRole)
            btn_no = box.addButton("Nie", QMessageBox.ButtonRole.NoRole)
            box.addButton("Anuluj", QMessageBox.ButtonRole.RejectRole)
            box.exec()
            clicked = box.clickedButton()
            if clicked is btn_yes:
                if not window._save():
                    return  # save failed: keep the window and its changes (C4-01)
            elif clicked is btn_no:
                pass
            else:
                return  # Cancel
        # Its SSH windows go with it: they hold the vault's hospitals and
        # passwords (UX audit S-03).
        try:
            from ui.ssh_panel import SshDialog
            for dlg in SshDialog.windows_of(window):
                if not dlg.close_for_vault():
                    return       # a transfer kept its window: the vault stays (R-03)
        except Exception:
            pass
        self.remove_window(window)
        window.destroy_cleanup()
        window.deleteLater()

    def _quit_all(self):
        for w in list(self._windows):
            if w._unsaved:
                w.show()
                w.raise_()
                box = QMessageBox(w)
                box.setWindowTitle("Niezapisane zmiany")
                box.setText(f"'{w.windowTitle().split('[')[0].strip()}' ma niezapisane zmiany.\nZapisać?")
                box.setIcon(QMessageBox.Icon.Question)
                btn_yes = box.addButton("Tak", QMessageBox.ButtonRole.YesRole)
                btn_no = box.addButton("Nie", QMessageBox.ButtonRole.NoRole)
                box.addButton("Anuluj", QMessageBox.ButtonRole.RejectRole)
                box.exec()
                clicked = box.clickedButton()
                if clicked is btn_yes:
                    if not w._save():
                        return  # save failed: abort quit, nothing lost (C4-01)
                elif clicked is btn_no:
                    pass
                else:
                    return  # Cancel — abort quit
        self._close_all_ssh_dialogs()
        for w in self._windows:
            w.destroy_cleanup()
        for tray in self._trays.values():
            tray.hide()
        self._trays.clear()
        self._windows.clear()
        self._app.quit()

    def _on_open_vault_requested(self):
        login = LoginDialog()
        if not login.exec():
            return
        result = login.get_result()
        if not result:
            return
        vault_path, password, items, admin_hash, admin_salt = result[:5]
        vault_type = result[5] if len(result) > 5 else "global"

        # Check if this vault is already open
        # normcase: paths differing only in letter case are one file on
        # Windows, and the same vault must not open twice (C4-05).
        normed = os.path.normcase(os.path.normpath(vault_path))
        for w in self._windows:
            if os.path.normcase(os.path.normpath(w._vault_path)) == normed:
                self._show_window(w)
                return

        self._create_window(vault_path, password, items, admin_hash, admin_salt, vault_type)

    def _create_window(self, vault_path, password, items, admin_hash, admin_salt, vault_type):
        window = MainWindow(vault_path, password, items, admin_hash, admin_salt,
                            vault_type=vault_type)
        window.setWindowIcon(self.icon_for_type(vault_type))
        self.add_window(window)
        window.show()

    def run_initial_login(self):
        """Run the initial login dialog and open the first window."""
        login = LoginDialog()
        if not login.exec():
            sys.exit(0)

        result = login.get_result()
        vault_path, password, hospitals, admin_hash, admin_salt = result[:5]
        vault_type = result[5] if len(result) > 5 else "global"

        self._create_window(vault_path, password, hospitals, admin_hash, admin_salt, vault_type)


def _ipc_channel_name() -> str:
    """The single-instance channel, per Windows user (2026-10-14, C5-01).

    A machine-wide name made a second user on a shared (RDS) server reach the
    first user's instance: their start "found" a running app and quit, and
    the first user's windows popped up instead.
    """
    import hashlib
    user = os.environ.get("USERNAME") or os.environ.get("USER") or ""
    if not user:
        try:
            import getpass
            user = getpass.getuser()
        except Exception:
            user = "user"
    domain = os.environ.get("USERDOMAIN", "")
    # A hash of the full DOMAIN\user, not a lossy rewrite of it (D-05):
    # "Michał"/"Michal" or DOM1\jan/DOM2\jan must not share a channel —
    # the other user's pipe would make listen() fail.
    digest = hashlib.sha256(f"{domain}\\{user}".lower().encode("utf-8")).hexdigest()[:16]
    return f"HospitalHubV2_SingleInstance_{digest}"


_IPC_CHANNEL = _ipc_channel_name()


def _try_activate_existing() -> bool:
    """Send 'activate' message to the running instance via QLocalSocket.
    Returns True if the message was delivered (caller should exit)."""
    sock = QLocalSocket()
    sock.connectToServer(_IPC_CHANNEL)
    if sock.waitForConnected(1000):
        sock.write(b"activate")
        sock.waitForBytesWritten(1000)
        sock.disconnectFromServer()
        return True
    return False


def install_polish_translations(app) -> bool:
    """Qt's standard buttons and context menus in Polish ("Anuluj", "Tak",
    "Kopiuj"…) — they showed "Cancel" and "&Yes/&No" next to our own Polish
    buttons (UX audit V-09/E-16).  The .qm files ship with PyQt6 and are in
    the build.  Missing files leave English; never raises."""
    try:
        from PyQt6.QtCore import QLibraryInfo, QTranslator
        path = QLibraryInfo.path(QLibraryInfo.LibraryPath.TranslationsPath)
        loaded = False
        for name in ("qtbase_pl", "qt_pl"):
            tr = QTranslator(app)
            if tr.load(name, path):
                app.installTranslator(tr)
                loaded = True
        return loaded
    except Exception:
        return False


def main():
    # Must be set BEFORE QApplication() to take effect. PassThrough lets Qt
    # use the system's fractional DPI scaling (125% / 150% / 175%) verbatim
    # instead of rounding to the nearest integer (the Qt6 default). On
    # external monitors with fractional Windows scaling this stops Qt from
    # operating on an over-scaled coordinate space — without it each paint
    # in the terminal widget had to cover more logical pixels than the
    # screen actually has, which manifested as sluggish redraws.
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )
    app = QApplication(sys.argv)
    app.setApplicationName("HospitalHub")
    install_polish_translations(app)
    try:
        from config import load_vpn_log_enabled
        from diagnostics import actionlog
        if load_vpn_log_enabled():
            actionlog.set_enabled(True)
            actionlog.info("app", "Start aplikacji")
    except Exception:
        pass
    cleanup_orphan_temp_dirs()

    # Single-instance: try to activate a running instance via IPC
    if _try_activate_existing():
        sys.exit(0)

    app.setApplicationDisplayName("")
    # Theme: dark (default) keeps apply_dark_theme; the others install their
    # palette + the stylesheet remap (must run before any window is built).
    try:
        from config import load_theme
        from ui import theme as _theme
        _chosen = load_theme()
    except Exception:
        _chosen = "dark"
    if _chosen != "dark":
        _theme.install(app, _chosen)
    else:
        apply_dark_theme(app)
    app.setWindowIcon(make_icon())

    manager = AppManager(app)
    manager.run_initial_login()

    exit_code = app.exec()
    # Force-terminate: Qt threads or blocked I/O (paramiko/pysftp) can
    # keep the interpreter alive after app.quit(). Best-effort cleanup
    # already ran via tray/close handlers, so exit hard here.
    _cleanup_sftp_temp()
    try:
        from ui.thread_retire import wait_for_retired
        wait_for_retired(3000)
    except Exception:
        pass
    # os._exit skips the 30 s RDP credential timers and atexit: remove the
    # TERMSRV entries and a copied secret now (C2-04, C3-01).
    try:
        from ui import rdp
        rdp.cleanup_pending_credentials()
    except Exception:
        pass
    try:
        from ui.dialogs import clear_secret_from_clipboard
        clear_secret_from_clipboard()
    except Exception:
        pass
    os._exit(exit_code)


if __name__ == "__main__":
    main()
