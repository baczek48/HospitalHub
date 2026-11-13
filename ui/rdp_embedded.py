"""RDP inside HospitalHub: a session as a tab of the terminal window.

2026-11-13 (owner): "RDP should open inside, in the terminal window, so I can
switch Wsparcie Claude on for such a session — with a choice: a separate
window or the terminal".  The separate window stays :mod:`ui.rdp` (mstsc with
a signed .rdp file); this module hosts the same engine — the Remote Desktop
ActiveX control of Windows (``MsTscAx.MsTscAx.11``, mstscax.dll) — in a Qt
widget.

How it is hosted: no QAxContainer (its DLL does not load with the PyQt6 we
build with).  A native child window of class ``AtlAxWin`` (atl.dll, part of
every Windows) creates the control; ``AtlAxGetControl`` hands over its
IUnknown and comtypes talks to it through the type library of mstscax.dll
(``comtypes.gen.MSTSCLib``, named in the build's hidden imports).

What differs from mstsc:

* the credentials go straight to the control (``ClearTextPassword``) — no
  TERMSRV/<ip> entry in the Credential Manager and no .rdp file to sign;
* the drives chosen for the machine are redirected one by one through the
  control's drive collection, the same choice the .rdp file carries;
* the screen can be captured (:meth:`RdpView.capture`) — what "Wsparcie
  Claude" gets for an RDP tab.  Read only: nothing here sends a key or a
  click to the session on Claude's behalf.

comtypes and the control are loaded only when a tab is opened, so tests and
the rest of the application never touch them.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import re

from PyQt6.QtCore import QTimer, Qt, pyqtSignal
from PyQt6.QtGui import QGuiApplication, QImage
from PyQt6.QtWidgets import (
    QHBoxLayout, QLabel, QPushButton, QStackedWidget, QVBoxLayout, QWidget,
)

__all__ = ["RdpPane", "RdpView", "split_login", "drives_to_redirect",
           "disconnect_text", "is_blank", "PROG_ID"]

PROG_ID = "MsTscAx.MsTscAx.11"
_MSTSCAX = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                        "System32", "mstscax.dll")

#: The control's ``Connected`` property.
_NOT_CONNECTED, _CONNECTED, _CONNECTING = 0, 1, 2
#: Disconnect reasons that are a normal end, not an error: the user
#: disconnected here (1), logged off or disconnected on the server (2, 3).
_NORMAL_END = {1, 2, 3}
#: Smallest and largest desktop the control accepts.
_MIN_SIDE, _MAX_SIDE = 200, 8192
#: The window pause before a resized tab resizes the remote desktop.
_RESIZE_DEBOUNCE_MS = 400
#: PrintWindow: ask for the full content (DirectX/composited surfaces too).
_PW_RENDERFULLCONTENT = 2


# ══════════════════════════════════════════════════════════════════════════
# Pure helpers (tested without the control)
# ══════════════════════════════════════════════════════════════════════════

def split_login(login: str) -> tuple[str, str]:
    """``DOMAIN\\user`` → (``user``, ``DOMAIN``); anything else is the user
    name as written (``user@domain.local`` included), with no domain."""
    login = (login or "").strip()
    if "\\" in login:
        domain, _, user = login.partition("\\")
        if domain and user:
            return user, domain
    return login, ""


_DRIVE = re.compile(r"[A-Za-z]:")


def drives_to_redirect(chosen, available) -> list[str]:
    """The names in `available` (as the control lists them, e.g. ``C:\\``)
    whose letter the machine has chosen — the .rdp file's
    ``drivestoredirect``.  Entries that are not one letter and a colon are
    ignored, as in :func:`ui.rdp._valid_drives`."""
    letters = {d.strip().upper() for d in (chosen or [])
               if isinstance(d, str) and _DRIVE.fullmatch(d.strip())}
    return [name for name in available
            if isinstance(name, str) and name[:2].upper() in letters]


def disconnect_text(reason: int, description: str = "") -> str:
    """What the tab says after the session ended."""
    if reason in _NORMAL_END:
        return "Sesja RDP zakończona."
    description = (description or "").strip()
    if description:
        return f"Rozłączono: {description}"
    return f"Rozłączono (kod {reason})."


def is_blank(image: QImage) -> bool:
    """A capture with nothing on it (all one colour on a sample grid) — the
    control drew to a surface PrintWindow did not reach."""
    if image is None or image.isNull():
        return True
    w, h = image.width(), image.height()
    first = image.pixel(0, 0)
    for y in range(0, h, max(1, h // 24)):
        for x in range(0, w, max(1, w // 24)):
            if image.pixel(x, y) != first:
                return False
    return True


# ══════════════════════════════════════════════════════════════════════════
# Win32
# ══════════════════════════════════════════════════════════════════════════

_user32 = ctypes.WinDLL("user32", use_last_error=True)
_gdi32 = ctypes.WinDLL("gdi32")
_user32.CreateWindowExW.restype = wt.HWND
_user32.CreateWindowExW.argtypes = [
    wt.DWORD, wt.LPCWSTR, wt.LPCWSTR, wt.DWORD, ctypes.c_int, ctypes.c_int,
    ctypes.c_int, ctypes.c_int, wt.HWND, wt.HMENU, wt.HINSTANCE, wt.LPVOID]
_user32.MoveWindow.argtypes = [wt.HWND, ctypes.c_int, ctypes.c_int,
                               ctypes.c_int, ctypes.c_int, wt.BOOL]
_user32.DestroyWindow.argtypes = [wt.HWND]
_user32.IsWindow.argtypes = [wt.HWND]
_user32.PrintWindow.argtypes = [wt.HWND, wt.HDC, wt.UINT]
_user32.GetDC.restype = wt.HDC
_user32.GetDC.argtypes = [wt.HWND]
_user32.ReleaseDC.argtypes = [wt.HWND, wt.HDC]
_user32.SetFocus.argtypes = [wt.HWND]
_gdi32.CreateCompatibleDC.restype = wt.HDC
_gdi32.CreateCompatibleDC.argtypes = [wt.HDC]
_gdi32.CreateDIBSection.restype = wt.HBITMAP
_gdi32.CreateDIBSection.argtypes = [wt.HDC, ctypes.c_void_p, wt.UINT,
                                    ctypes.POINTER(ctypes.c_void_p), wt.HANDLE, wt.DWORD]
_gdi32.SelectObject.restype = wt.HGDIOBJ
_gdi32.SelectObject.argtypes = [wt.HDC, wt.HGDIOBJ]
_gdi32.DeleteObject.argtypes = [wt.HGDIOBJ]
_gdi32.DeleteDC.argtypes = [wt.HDC]

_WS_CHILD, _WS_VISIBLE, _WS_CLIPCHILDREN = 0x40000000, 0x10000000, 0x02000000


class _BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [("biSize", wt.DWORD), ("biWidth", wt.LONG), ("biHeight", wt.LONG),
                ("biPlanes", wt.WORD), ("biBitCount", wt.WORD),
                ("biCompression", wt.DWORD), ("biSizeImage", wt.DWORD),
                ("biXPelsPerMeter", wt.LONG), ("biYPelsPerMeter", wt.LONG),
                ("biClrUsed", wt.DWORD), ("biClrImportant", wt.DWORD)]


def _print_window(hwnd: int, width: int, height: int) -> QImage | None:
    """The window's content through PrintWindow into a 32-bit DIB."""
    if width <= 0 or height <= 0:
        return None
    header = _BITMAPINFOHEADER(ctypes.sizeof(_BITMAPINFOHEADER), width, -height,
                               1, 32, 0, 0, 0, 0, 0, 0)
    bits = ctypes.c_void_p()
    screen_dc = _user32.GetDC(None)
    mem_dc = _gdi32.CreateCompatibleDC(screen_dc)
    bitmap = _gdi32.CreateDIBSection(screen_dc, ctypes.byref(header), 0,
                                     ctypes.byref(bits), None, 0)
    try:
        if not bitmap or not bits.value:
            return None
        old = _gdi32.SelectObject(mem_dc, bitmap)
        ok = _user32.PrintWindow(wt.HWND(hwnd), mem_dc, _PW_RENDERFULLCONTENT)
        _gdi32.SelectObject(mem_dc, old)
        if not ok:
            return None
        raw = ctypes.string_at(bits.value, width * height * 4)
        return QImage(raw, width, height, width * 4, QImage.Format.Format_RGB32).copy()
    finally:
        if bitmap:
            _gdi32.DeleteObject(bitmap)
        _gdi32.DeleteDC(mem_dc)
        _user32.ReleaseDC(None, screen_dc)


def _load_typelib():
    """comtypes' wrapper of mstscax.dll (pre-generated in the build)."""
    try:
        import comtypes.gen.MSTSCLib as lib          # noqa: N813
        return lib
    except ImportError:
        import comtypes.client
        return comtypes.client.GetModule(_MSTSCAX)


def available() -> bool:
    """Can this computer host the control at all?"""
    return os.path.isfile(_MSTSCAX)


# ══════════════════════════════════════════════════════════════════════════
# The control
# ══════════════════════════════════════════════════════════════════════════

class RdpView(QWidget):
    """A native window holding one Remote Desktop control.

    Signals carry what the control reports: ``state_changed`` with
    ``"connecting"``, ``"connected"`` or ``"disconnected"``, and
    ``ended(text, normal)`` when a session ends.
    """

    state_changed = pyqtSignal(str)
    ended = pyqtSignal(str, bool)

    def __init__(self, host: str, port: int, login: str, password: str,
                 drives=(), parent=None):
        super().__init__(parent)
        # Our own HWND — the control's parent — kept for the widget's life:
        # moving the tab between the tab bar and the Multi-exec parking
        # changes only its parent window (measured 2026-11-13).
        self.setAttribute(Qt.WidgetAttribute.WA_NativeWindow, True)
        self.setAttribute(Qt.WidgetAttribute.WA_DontCreateNativeAncestors, True)
        self.setMinimumSize(_MIN_SIDE, _MIN_SIDE)
        self.setStyleSheet("background:#000;")
        self._host, self._port = host, port
        self._login, self._password = login, password
        self._drives = list(drives or [])
        self._ax_hwnd = 0
        self._lib = None
        self._client = None
        self._events = None
        self._state = "idle"
        self._closing = False
        self._smart = False
        self._refit_pending = False
        #: The desktop size asked for at the last connect (physical pixels).
        self.session_size: tuple[int, int] | None = None
        self._resize_timer = QTimer(self)
        self._resize_timer.setSingleShot(True)
        self._resize_timer.setInterval(_RESIZE_DEBOUNCE_MS)
        self._resize_timer.timeout.connect(self._apply_display_size)

    # -- creating the control ---------------------------------------------- #

    def _physical_size(self) -> tuple[int, int]:
        ratio = self.devicePixelRatioF() or 1.0
        w = int(round(self.width() * ratio))
        h = int(round(self.height() * ratio))
        return (max(_MIN_SIDE, min(_MAX_SIDE, w)) & ~1,
                max(_MIN_SIDE, min(_MAX_SIDE, h)))

    def _scale_factor(self) -> int:
        """Windows' own display scale (100, 125, 150 …) for the session."""
        ratio = self.devicePixelRatioF() or 1.0
        return max(100, min(500, int(round(ratio * 100))))

    def _create_control(self) -> None:
        import comtypes
        import comtypes.client
        lib = _load_typelib()
        atl = ctypes.WinDLL("atl.dll")
        atl.AtlAxWinInit()
        w, h = self._physical_size()
        self._ax_hwnd = _user32.CreateWindowExW(
            0, "AtlAxWin", PROG_ID, _WS_CHILD | _WS_VISIBLE | _WS_CLIPCHILDREN,
            0, 0, w, h, wt.HWND(int(self.winId())), None, None, None)
        if not self._ax_hwnd:
            raise OSError(f"AtlAxWin: {ctypes.get_last_error()}")
        unknown = ctypes.POINTER(comtypes.IUnknown)()
        hr = atl.AtlAxGetControl(wt.HWND(self._ax_hwnd), ctypes.byref(unknown))
        if hr != 0 or not unknown:
            raise OSError(f"AtlAxGetControl: {hr:#x}")
        self._lib = lib
        self._client = unknown.QueryInterface(lib.IMsRdpClient9)
        self._events = comtypes.client.GetEvents(
            self._client, _EventSink(self), interface=lib.IMsTscAxEvents)

    def _configure(self) -> None:
        c, lib = self._client, self._lib
        user, domain = split_login(self._login)
        c.Server = self._host
        if user:
            c.UserName = user
        if domain:
            c.Domain = domain
        w, h = self._physical_size()
        c.DesktopWidth, c.DesktopHeight = w, h
        self.session_size = (w, h)
        c.ColorDepth = 32
        adv = c.AdvancedSettings9
        adv.RDPPort = int(self._port)
        if self._password:
            adv.ClearTextPassword = self._password
        adv.EnableCredSspSupport = True          # NLA, as mstsc
        adv.AuthenticationLevel = 2              # warn on an unknown server cert
        adv.RedirectClipboard = True             # as the .rdp file of ui.rdp
        adv.RedirectPrinters = False
        adv.RedirectDrives = False
        adv.EnableAutoReconnect = True
        adv.GrabFocusOnConnect = True
        adv.SmartSizing = self._smart
        try:
            ext = self._client.QueryInterface(lib.IMsRdpExtendedSettings)
            ext.Property["DesktopScaleFactor"] = self._scale_factor()
            ext.Property["DeviceScaleFactor"] = 100
        except Exception:
            pass
        try:
            drives = self._client.QueryInterface(lib.IMsRdpClientNonScriptable3).DriveCollection
            names = [drives.DriveByIndex(i).Name for i in range(drives.DriveCount)]
            wanted = set(drives_to_redirect(self._drives, names))
            for i in range(drives.DriveCount):
                drive = drives.DriveByIndex(i)
                drive.RedirectionState = drive.Name in wanted
        except Exception:
            pass

    # -- public ------------------------------------------------------------- #

    def start(self) -> None:
        """Create the control (first time) and connect."""
        if self._closing:
            return
        if self._client is None:
            self._create_control()
        self._configure()
        self._set_state("connecting")
        self._client.Connect()

    def set_smart_sizing(self, on: bool) -> None:
        """Scale the remote picture to the tab (no reconnect) — for servers
        that cannot change their resolution during a session (XP/2003,
        2008; seen 2026-11-13 on a hospital server)."""
        self._smart = bool(on)
        if self._client is not None:
            try:
                self._client.AdvancedSettings9.SmartSizing = self._smart
            except Exception:
                pass

    def fits(self) -> bool:
        """Is the remote desktop already the size of the tab?"""
        return self.session_size == self._physical_size()

    def refit(self) -> bool:
        """Reconnect at the tab's current size.  The session on the server
        stays (its programs keep running); only the picture is renegotiated.
        False when there is nothing to do (the desktop is the tab's size)."""
        if self._client is None:
            return False
        if self.connected_state() == _NOT_CONNECTED:
            self.start()
            return True
        if self.fits():
            return False
        self._refit_pending = True
        self.disconnect_session()
        return True

    def _destroy_control(self) -> None:
        """A fresh control for the next connect: a used one may keep the
        desktop size of its first connection (owner 2026-11-13: "Dopasuj
        rozdzielczość" changed nothing on the server)."""
        self._events = None
        self._client = None
        if self._ax_hwnd and _user32.IsWindow(wt.HWND(self._ax_hwnd)):
            _user32.DestroyWindow(wt.HWND(self._ax_hwnd))
        self._ax_hwnd = 0

    def disconnect_session(self) -> None:
        if self._client is not None and self.connected_state() != _NOT_CONNECTED:
            try:
                self._client.Disconnect()
            except Exception:
                pass

    def connected_state(self) -> int:
        try:
            return int(self._client.Connected) if self._client is not None else 0
        except Exception:
            return 0

    def is_connected(self) -> bool:
        return self.connected_state() == _CONNECTED

    def shutdown(self) -> None:
        """End the session and destroy the control (the tab is closing)."""
        if self._closing:
            return
        self._closing = True
        self._resize_timer.stop()
        self.disconnect_session()
        self._events = None
        self._client = None
        self._password = ""
        if self._ax_hwnd and _user32.IsWindow(wt.HWND(self._ax_hwnd)):
            _user32.DestroyWindow(wt.HWND(self._ax_hwnd))
        self._ax_hwnd = 0

    def focus_session(self) -> None:
        if self._ax_hwnd:
            _user32.SetFocus(wt.HWND(self._ax_hwnd))

    def capture(self) -> QImage | None:
        """The remote screen as the tab shows it, or None.

        PrintWindow first (works when the tab is covered); where it comes
        back blank and the tab is on screen, the screen itself is grabbed."""
        if not self._ax_hwnd or not self.is_connected():
            return None
        w, h = self._physical_size()
        image = None
        try:
            image = _print_window(self._ax_hwnd, w, h)
        except Exception:
            image = None
        if (image is None or is_blank(image)) and self.isVisible():
            screen = self.screen() or QGuiApplication.primaryScreen()
            if screen is not None:
                top_left = self.mapToGlobal(self.rect().topLeft())
                local = screen.geometry()
                grabbed = screen.grabWindow(
                    0, top_left.x() - local.x(), top_left.y() - local.y(),
                    self.width(), self.height()).toImage()
                if not grabbed.isNull() and not is_blank(grabbed):
                    image = grabbed
        if image is None or is_blank(image):
            return None
        return image

    # -- size --------------------------------------------------------------- #

    def resizeEvent(self, event):
        super().resizeEvent(event)
        if self._ax_hwnd:
            ratio = self.devicePixelRatioF() or 1.0
            _user32.MoveWindow(wt.HWND(self._ax_hwnd), 0, 0,
                               int(round(self.width() * ratio)),
                               int(round(self.height() * ratio)), True)
            if self.is_connected():
                self._resize_timer.start()

    def _apply_display_size(self) -> None:
        """The remote desktop follows the tab's size (Windows 8.1 / 2012 R2
        and newer; older servers keep the size they started with)."""
        if not self.is_connected():
            return
        w, h = self._physical_size()
        try:
            self._client.UpdateSessionDisplaySettings(
                w, h, w, h, 0, self._scale_factor(), 100)
        except Exception:
            pass

    # -- events (UI thread: the control lives in it) ------------------------- #

    def _set_state(self, state: str) -> None:
        if state != self._state:
            self._state = state
            self.state_changed.emit(state)

    def _on_connected(self) -> None:
        self._set_state("connected")
        QTimer.singleShot(0, self._apply_display_size)

    def _on_disconnected(self, reason: int) -> None:
        if self._closing:
            return
        if self._refit_pending:
            # "Dopasuj rozdzielczość": straight back in at the new size,
            # on a new control (after this event has returned to it).
            self._refit_pending = False

            def again():
                self._destroy_control()
                self.start()
            QTimer.singleShot(300, again)
            return
        description = ""
        if reason not in _NORMAL_END:
            try:
                description = self._client.GetErrorDescription(
                    reason, int(self._client.ExtendedDisconnectReason))
            except Exception:
                description = ""
        self._set_state("disconnected")
        self.ended.emit(disconnect_text(reason, description), reason in _NORMAL_END)


class _EventSink:
    """IMsTscAxEvents → RdpView.  comtypes calls these on the UI thread."""

    def __init__(self, view: RdpView):
        self._view = view

    def OnConnecting(self, this=None, *args):            # noqa: N802
        self._view._set_state("connecting")

    def OnConnected(self, this=None, *args):             # noqa: N802
        self._view._on_connected()

    def OnLoginComplete(self, this=None, *args):         # noqa: N802
        self._view._on_connected()

    def OnDisconnected(self, this=None, reason=0, *args):   # noqa: N802
        self._view._on_disconnected(int(reason or 0))

    def OnRequestGoFullScreen(self, this=None, *args):   # noqa: N802
        pass                                             # the tab is the screen

    def OnConfirmClose(self, this=None, *args):          # noqa: N802
        return True


# ══════════════════════════════════════════════════════════════════════════
# The tab
# ══════════════════════════════════════════════════════════════════════════

_HEADER_STYLE = ("background:#0d1117;border-bottom:1px solid #21262d;")
_BTN_STYLE = (
    "QPushButton{background:#151b23;color:#c9d1d9;border:1px solid #30363d;"
    "border-radius:6px;padding:3px 10px;font-size:11px;}"
    "QPushButton:hover{background:#1c2433;border-color:#c084fc;}")


class RdpPane(QWidget):
    """One RDP tab: a thin status line over the session, and a message page
    with "Połącz ponownie" / "Zamknij kartę" once it has ended."""

    close_requested = pyqtSignal()
    state_changed = pyqtSignal(str)

    def __init__(self, machine, cred, label: str, parent=None):
        super().__init__(parent)
        from ui.rdp import _validate_ip, _validate_port, _valid_drives
        self.machine = machine
        self.label = label
        self.host = _validate_ip(machine.ip)
        self.port = _validate_port(getattr(machine, "rdp_port", "") or "3389")
        login = cred.login if cred else ""
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(0)

        header = QWidget()
        header.setFixedHeight(26)
        header.setStyleSheet(_HEADER_STYLE)
        hl = QHBoxLayout(header)
        hl.setContentsMargins(8, 0, 6, 0)
        badge = QLabel("RDP")
        badge.setStyleSheet("color:#c084fc;font-size:10px;font-weight:bold;")
        self._status = QLabel(f"Łączenie z {self.host}…")
        self._status.setStyleSheet("color:#8b949e;font-size:11px;")
        hl.addWidget(badge)
        hl.addSpacing(6)
        hl.addWidget(self._status, 1)
        self._btn_reconnect = QPushButton("Połącz ponownie")
        self._btn_reconnect.setStyleSheet(_BTN_STYLE)
        self._btn_reconnect.clicked.connect(self.reconnect)
        self._btn_reconnect.hide()
        self._btn_disconnect = QPushButton("Rozłącz")
        self._btn_disconnect.setStyleSheet(_BTN_STYLE)
        self._btn_disconnect.setToolTip("Zakończ sesję RDP (karta zostaje)")
        self._btn_disconnect.clicked.connect(self._disconnect)
        # 2026-11-13 (owner: "can the window be made smaller/bigger?"): new
        # servers follow the tab by themselves; for old ones, two ways.
        self._btn_scale = QPushButton("Skaluj")
        self._btn_scale.setCheckable(True)
        self._btn_scale.setStyleSheet(
            _BTN_STYLE + "QPushButton:checked{background:#7c3aed;color:#fff;"
            "border-color:#c084fc;}")
        self._btn_scale.setToolTip(
            "Obraz zdalny zmniejsza się i powiększa razem z kartą (bez "
            "rozłączania; tekst może być mniej ostry)")
        self._btn_scale.toggled.connect(lambda on: self.view.set_smart_sizing(on))
        self._btn_fit = QPushButton("Dopasuj rozdzielczość")
        self._btn_fit.setStyleSheet(_BTN_STYLE)
        self._btn_fit.setToolTip(
            "Połącz ponownie w rozmiarze karty — dla starszych serwerów, które "
            "nie zmieniają rozdzielczości same. Programy na serwerze działają dalej.")
        self._btn_fit.clicked.connect(self._refit)
        hl.addWidget(self._btn_scale)
        hl.addWidget(self._btn_fit)
        hl.addWidget(self._btn_reconnect)
        hl.addWidget(self._btn_disconnect)
        lay.addWidget(header)

        self._stack = QStackedWidget()
        self.view = RdpView(self.host, self.port, login,
                            cred.password if cred else "",
                            _valid_drives(getattr(machine, "rdp_drives", [])))
        self.view.state_changed.connect(self._on_state)
        self.view.ended.connect(self._on_ended)
        self._stack.addWidget(self.view)

        page = QWidget()
        page.setStyleSheet("background:#0d1117;")
        pl = QVBoxLayout(page)
        pl.addStretch()
        self._message = QLabel("")
        self._message.setWordWrap(True)
        self._message.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._message.setStyleSheet("color:#c9d1d9;font-size:13px;")
        pl.addWidget(self._message)
        row = QHBoxLayout()
        row.addStretch()
        again = QPushButton("Połącz ponownie")
        again.setStyleSheet(_BTN_STYLE)
        again.clicked.connect(self.reconnect)
        close = QPushButton("Zamknij kartę")
        close.setStyleSheet(_BTN_STYLE)
        close.clicked.connect(self.close_requested.emit)
        row.addWidget(again)
        row.addWidget(close)
        row.addStretch()
        pl.addLayout(row)
        pl.addStretch()
        self._stack.addWidget(page)
        lay.addWidget(self._stack, 1)
        self._started = False

    # The terminal tab's interface that the window calls on every tab.
    def set_multiexec_header(self, visible: bool) -> None:
        pass

    def showEvent(self, event):
        super().showEvent(event)
        if not self._started:
            self._started = True
            QTimer.singleShot(0, self._start)

    def _start(self) -> None:
        try:
            self.view.start()
        except Exception as exc:
            self._on_ended(f"Nie udało się uruchomić RDP w HospitalHub "
                           f"({type(exc).__name__}: {exc}). Użyj „Otwórz w osobnym "
                           "oknie”.", False)

    def reconnect(self) -> None:
        self._stack.setCurrentWidget(self.view)
        self._btn_reconnect.hide()
        self._btn_disconnect.show()
        self._start()

    def _disconnect(self) -> None:
        self.view.disconnect_session()

    def _refit(self) -> None:
        self._stack.setCurrentWidget(self.view)
        if self.view.fits():
            w, h = self.view.session_size
            self._status.setText(
                f"Pulpit zdalny ma już rozmiar karty ({w}×{h}). Zmień rozmiar okna "
                "lub panelu Claude, potem kliknij ponownie — albo włącz „Skaluj”.")
            self._status.setStyleSheet("color:#d29922;font-size:11px;")
            return
        self._status.setText(f"Dopasowuję rozdzielczość — łączenie z {self.host}…")
        self.view.refit()

    def _on_state(self, state: str) -> None:
        if state == "connecting":
            self._status.setText(f"Łączenie z {self.host}…")
            self._status.setStyleSheet("color:#8b949e;font-size:11px;")
        elif state == "connected":
            size = self.view.session_size
            self._status.setText(f"Połączono z {self.host}" + (
                f" · pulpit {size[0]}×{size[1]}" if size else ""))
            self._status.setStyleSheet("color:#3fb950;font-size:11px;")
            self.view.focus_session()
        self.state_changed.emit(state)

    def _on_ended(self, text: str, normal: bool) -> None:
        self._status.setText(text)
        self._status.setStyleSheet(
            f"color:{'#8b949e' if normal else '#f85149'};font-size:11px;")
        self._message.setText(text)
        self._stack.setCurrentIndex(1)
        self._btn_reconnect.show()
        self._btn_disconnect.hide()
        self.state_changed.emit("disconnected")

    def is_connected(self) -> bool:
        return self.view.is_connected()

    def capture(self) -> QImage | None:
        return self.view.capture()

    def shutdown(self) -> None:
        self.view.shutdown()
