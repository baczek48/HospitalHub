"""The VPN vault as a pane of the main window (2026-10-26, owner).

With both vaults open the VPN window stops being a window of its own: it
stands in a dock at the right of the main one — one window on the taskbar,
maximised together (the VPN pane keeps its width, the rest grows), restored
by Windows itself.  The pane is dragged by its title to the other side.

"Odepnij" on the pane's title makes it a window of its own again — its own
taskbar button, as before.  (Qt's floating dock was a tool window: no taskbar
button, and its buttons did not take clicks — owner, 2026-10-26.)  The window
goes back in when it is dropped with the cursor at the right or left edge of
the main window, or from Widok → "Przypnij do okna głównego".

The VPN ``MainWindow`` keeps working as before inside the dock — its menu,
its save, its tray icon.  Before the main window goes away the VPN one is
taken out again and becomes a window of its own.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QAction, QColor, QCursor, QPainter, QPen
from PyQt6.QtWidgets import (QApplication, QDockWidget, QHBoxLayout, QLabel,
                             QToolButton, QWidget)

from ui.window_layout import MAIN_SIZE, VPN_SIZE

_DOCK_ATTR = "_vpn_dock"            # on the VPN window: its dock while docked
#: px from the main window's side edge where a dropped VPN window docks
DROP_ZONE = 90
#: The cards of the VPN list need this width — narrower, their buttons
#: (edit, password) went past the pane's edge.
PANE_MIN_WIDTH = VPN_SIZE[0]
#: The VPN window's own minimum, back as a window (ui/main_window.py).
WINDOW_MIN_WIDTH = 360

_host_finder = [None]               # set by the app manager: () -> main window
_icon = [None]                      # the VPN window's icon, back when undocked


def set_host_finder(finder, vpn_icon=None) -> None:
    """`finder()` gives the main window a VPN one docks in, or None."""
    _host_finder[0] = finder
    _icon[0] = vpn_icon


def find_host():
    f = _host_finder[0]
    try:
        return f() if f is not None else None
    except RuntimeError:
        return None


def dock_of(vpn_window) -> QDockWidget | None:
    dock = vars(vpn_window).get(_DOCK_ATTR)
    try:
        if dock is not None:
            dock.objectName()       # deleted under us → RuntimeError
    except RuntimeError:
        return None
    return dock


def host_of(vpn_window):
    """The main window the VPN one is docked in, or None."""
    dock = dock_of(vpn_window)
    return dock.parentWidget() if dock is not None else None


def docked_in(main_window) -> list:
    """The VPN windows docked in `main_window`."""
    return [d.widget() for d in main_window.findChildren(QDockWidget)
            if d.objectName() == "vpnDock" and d.widget() is not None]


def _fit(window, w: int, h: int) -> None:
    screen = window.screen() or QApplication.primaryScreen()
    if screen is not None:
        a = screen.availableGeometry()
        w, h = min(w, a.width() - 16), min(h, a.height() - 16)
    window.resize(w, h)
    if screen is not None:
        a = screen.availableGeometry()
        fg = window.frameGeometry()
        x = min(max(fg.x(), a.x()), a.x() + a.width() - fg.width())
        y = min(max(fg.y(), a.y()), a.y() + a.height() - fg.height())
        window.move(x, y)


class _TitleBar(QWidget):
    """The pane's title: the vault's name, "Odepnij", and X (hide the pane)."""
    def __init__(self, dock_widget, vpn_window):
        super().__init__(dock_widget)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(8, 3, 4, 3)
        lay.setSpacing(4)
        self.label = QLabel(dock_widget.windowTitle())
        f = self.label.font()
        f.setBold(True)
        self.label.setFont(f)
        lay.addWidget(self.label, 1)
        self.btn_out = QToolButton()
        self.btn_out.setText("Odepnij")
        self.btn_out.setToolTip(
            "Osobne okno VPN (z własną ikoną na pasku zadań).\n"
            "Z powrotem: upuść je kursorem przy krawędzi okna głównego\n"
            "albo Widok → Przypnij do okna głównego.")
        self.btn_out.setAutoRaise(True)
        # After the click: the button is inside what the undock takes apart.
        self.btn_out.clicked.connect(lambda: QTimer.singleShot(
            0, lambda: undock(vpn_window, _icon[0], show=True)))
        lay.addWidget(self.btn_out)
        self.btn_hide = QToolButton()
        from ui.icons import set_icon
        set_icon(self.btn_hide, "close", "#8b949e", active="#f85149", size=12)
        set_icon(self.btn_out, "external", "#8b949e", active="#58a6ff", size=12)
        self.btn_out.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self.btn_hide.setToolTip("Schowaj panel VPN (ikona VPN w trayu go przywraca)")
        self.btn_hide.setAutoRaise(True)
        self.btn_hide.clicked.connect(dock_widget.hide)
        lay.addWidget(self.btn_hide)


def dock(main_window, vpn_window,
         area=Qt.DockWidgetArea.RightDockWidgetArea) -> QDockWidget:
    """Put `vpn_window` as a pane at the right (or `area`) of `main_window`."""
    existing = dock_of(vpn_window)
    if existing is not None:
        return existing
    width = max(PANE_MIN_WIDTH, VPN_SIZE[0])
    was_max = main_window.isMaximized()

    d = QDockWidget(vpn_window.windowTitle(), main_window)
    d.setObjectName("vpnDock")
    d.setAllowedAreas(Qt.DockWidgetArea.LeftDockWidgetArea
                      | Qt.DockWidgetArea.RightDockWidgetArea)
    # Movable between the sides; never floating (see the module doc).
    d.setFeatures(QDockWidget.DockWidgetFeature.DockWidgetMovable
                  | QDockWidget.DockWidgetFeature.DockWidgetClosable)
    d.setTitleBarWidget(_TitleBar(d, vpn_window))
    vpn_window.hide()
    vpn_window.setWindowFlags(Qt.WindowType.Widget)
    vpn_window.setMinimumWidth(PANE_MIN_WIDTH)
    d.setWidget(vpn_window)
    vpn_window.show()
    vpn_window.__dict__[_DOCK_ATTR] = d
    sync = lambda d=d, w=vpn_window: _sync_title(d, w)      # noqa: E731
    d.__dict__["_title_sync"] = sync
    vpn_window.title_changed.connect(sync)

    # The pane widens the window instead of taking the hospitals' room.
    if not was_max:
        _fit(main_window, MAIN_SIZE[0] + width, max(main_window.height(), VPN_SIZE[1]))
    main_window.addDockWidget(area, d)
    main_window.resizeDocks([d], [width], Qt.Orientation.Horizontal)
    _scope_shortcuts(main_window, main_window.centralWidget())
    _scope_shortcuts(vpn_window, vpn_window)
    d.show()
    return d


def _menu_shortcuts(window) -> list:
    out = []
    for act in window.menuBar().findChildren(QAction):
        if not act.shortcut().isEmpty() and act not in out:
            out.append(act)
    return out


def _scope_shortcuts(window, scope) -> None:
    """Both vaults have Ctrl+S, Ctrl+Shift+S and Ctrl+O; in one window the
    same key twice is ambiguous and neither fires.  Docked, each one's keys
    work where the focus is: in the hospitals for the main vault, in the
    pane for the VPN one.  `scope` None: the whole window again."""
    for act in _menu_shortcuts(window):
        old = vars(act).get("_scope")
        if old is not None:
            try:
                old.removeAction(act)
            except RuntimeError:
                pass
            act.__dict__.pop("_scope", None)
        if scope is None:
            act.setShortcutContext(Qt.ShortcutContext.WindowShortcut)
        else:
            scope.addAction(act)
            act.__dict__["_scope"] = scope
            act.setShortcutContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)


def _sync_title(d, vpn_window) -> None:
    try:
        d.setWindowTitle(vpn_window.windowTitle())
        bar = d.titleBarWidget()
        if isinstance(bar, _TitleBar):
            bar.label.setText(vpn_window.windowTitle())
    except RuntimeError:
        pass


def undock(vpn_window, icon=None, show: bool = False) -> bool:
    """Take `vpn_window` out of its dock: a window of its own again, where
    the pane stood.  False when it was not docked."""
    d = dock_of(vpn_window)
    if d is None:
        return False
    host = d.parentWidget()
    geo = d.geometry()
    origin = d.mapToGlobal(d.rect().topLeft()) if d.isVisible() else None
    vpn_window.__dict__.pop(_DOCK_ATTR, None)
    try:
        vpn_window.title_changed.disconnect(vars(d)["_title_sync"])
    except (KeyError, TypeError, RuntimeError):
        pass
    vpn_window.hide()
    vpn_window.setParent(None)
    vpn_window.setWindowFlags(Qt.WindowType.Window)
    vpn_window.setMinimumWidth(WINDOW_MIN_WIDTH)
    if icon is not None:
        vpn_window.setWindowIcon(icon)
    _scope_shortcuts(vpn_window, None)
    if host is not None:
        host.removeDockWidget(d)
        if len(docked_in(host)) == 0:
            _scope_shortcuts(host, None)
    d.deleteLater()
    vpn_window.resize(*VPN_SIZE)
    if origin is not None:
        vpn_window.move(origin)
    elif host is not None:
        hg = host.frameGeometry()
        vpn_window.move(hg.x() + hg.width() - geo.width(), hg.y())
    if show:
        vpn_window.show()
        vpn_window.raise_()
        vpn_window.activateWindow()
    return True


class _DropHint(QWidget):
    """The strip of the main window where a dragged VPN window would go —
    as Qt's own dock drag showed it."""
    def __init__(self, host):
        super().__init__(host)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setObjectName("vpnDropHint")

    def paintEvent(self, _event):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(31, 111, 235, 60))
        pen = QPen(QColor(31, 111, 235, 220))
        pen.setWidth(2)
        p.setPen(pen)
        p.drawRect(self.rect().adjusted(1, 1, -2, -2))
        p.end()


_hint = [None]              # the _DropHint shown now, if any


def drop_hint_rect(host, area):
    """Where the hint stands in `host`: the pane's width at that side, from
    under the menu bar to the bottom."""
    from PyQt6.QtCore import QRect
    top = host.menuBar().height() if host.menuBar() is not None else 0
    w = min(PANE_MIN_WIDTH, host.width() // 2)
    x = host.width() - w if area == Qt.DockWidgetArea.RightDockWidgetArea else 0
    return QRect(x, top, w, host.height() - top)


def drag_hover(vpn_window) -> None:
    """The VPN window is being dragged: light up the side of the main window
    it would go into if let go now, or nothing."""
    if dock_of(vpn_window) is not None:
        return
    host = find_host()
    area = drop_area(host, QCursor.pos())
    hint = _hint[0]
    try:
        if hint is not None and (area is None or hint.parentWidget() is not host):
            hint.hide()
            hint.deleteLater()
            _hint[0] = hint = None
    except RuntimeError:
        _hint[0] = hint = None
    if area is None:
        return
    if hint is None:
        hint = _hint[0] = _DropHint(host)
    hint.setGeometry(drop_hint_rect(host, area))
    hint.show()
    hint.raise_()
    hint.repaint()        # inside Windows' move loop: paint now


def drag_end() -> None:
    hint, _hint[0] = _hint[0], None
    if hint is not None:
        try:
            hint.hide()
            hint.deleteLater()
        except RuntimeError:
            pass


def drop_area(host, pos):
    """The dock area for a VPN window let go with the cursor at `pos`: near
    the right or left edge inside `host`'s frame, else None."""
    if host is None or not host.isVisible() or host.isMinimized():
        return None
    g = host.frameGeometry()
    if not g.contains(pos):
        return None
    if pos.x() >= g.x() + g.width() - DROP_ZONE:
        return Qt.DockWidgetArea.RightDockWidgetArea
    if pos.x() <= g.x() + DROP_ZONE:
        return Qt.DockWidgetArea.LeftDockWidgetArea
    return None


def redock_if_dropped(vpn_window) -> bool:
    """The VPN window was let go after a drag by its title: in the drop zone
    of the main window it goes back in there."""
    if dock_of(vpn_window) is not None:
        return False
    host = find_host()
    area = drop_area(host, QCursor.pos())
    if area is None:
        return False
    dock(host, vpn_window, area)
    show_pane(vpn_window)
    return True


def redock(vpn_window) -> bool:
    """Widok → "Przypnij do okna głównego"."""
    if dock_of(vpn_window) is not None:
        return False
    host = find_host()
    if host is None:
        return False
    dock(host, vpn_window)
    show_pane(vpn_window)
    return True


def show_pane(vpn_window) -> bool:
    """Bring the VPN pane up (its main window with it).  False when the VPN
    window is not docked."""
    d = dock_of(vpn_window)
    if d is None:
        return False
    host = d.parentWidget()
    if host is not None:
        if host.isMinimized():         # maximised stays maximised
            host.setWindowState(host.windowState() & ~Qt.WindowState.WindowMinimized)
        host.show()
        host.raise_()
        host.activateWindow()
    d.show()
    d.raise_()
    return True


def hide_pane(vpn_window) -> bool:
    d = dock_of(vpn_window)
    if d is None:
        return False
    d.hide()
    return True


def pane_visible(vpn_window) -> bool:
    d = dock_of(vpn_window)
    if d is None:
        return False
    host = d.parentWidget()
    return d.isVisible() and (host is None or (host.isVisible() and not host.isMinimized()))


def resize_pane(vpn_window, width: int) -> bool:
    """The VPN page asks for a width (edit page wider, list narrow again)."""
    d = dock_of(vpn_window)
    if d is None:
        return False
    d.parentWidget().resizeDocks([d], [max(width, PANE_MIN_WIDTH)],
                                 Qt.Orientation.Horizontal)
    return True
