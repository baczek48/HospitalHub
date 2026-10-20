"""Vector icons for buttons, tabs and menus.

Why: the UI used colour emoji (🔑 📁 🌐 ⚙ …) as icons.  Windows draws those as
small bitmaps with greyscale smoothing — at 100 % scaling on a 1080p monitor
a 12-pixel emoji is blurry, while a 4K TV at 200 % shows it sharp.  These
icons are SVG line drawings rendered for the exact pixel size and device
pixel ratio they are shown at, so they are equally sharp on every screen.

Usage::

    from ui.icons import icon
    btn.setIcon(icon("gear", "#6e9a6e"))      # colour follows the light theme

Drawings: 24×24 grid, 2-unit round strokes (own drawings in the common
"line icon" style).
"""

from __future__ import annotations

import math

from PyQt6.QtCore import QByteArray, QPoint, QRect, QRectF, QSize, Qt
from PyQt6.QtGui import QIcon, QIconEngine, QPainter, QPixmap
from PyQt6.QtSvg import QSvgRenderer


def _gear_path() -> str:
    """An 8-tooth gear outline, generated so the teeth are exactly even."""
    teeth, r_out, r_in = 8, 10.0, 7.6
    pts = []
    for i in range(teeth):
        a = 2 * math.pi * i / teeth
        half = math.pi / teeth
        for ang, r in ((a - half * 0.55, r_out), (a + half * 0.55, r_out),
                       (a + half * 1.0, r_in), (a + half * 1.45, r_in)):
            pts.append((12 + r * math.cos(ang), 12 + r * math.sin(ang)))
    d = "M" + " L".join(f"{x:.2f} {y:.2f}" for x, y in pts) + " Z"
    return f'<path d="{d}"/><circle cx="12" cy="12" r="3"/>'


_SHAPES: dict[str, str] = {
    "gear": _gear_path(),
    "lock": '<rect x="5" y="11" width="14" height="10" rx="2"/>'
            '<path d="M8 11V7a4 4 0 0 1 8 0v4"/>',
    "lock-open": '<rect x="5" y="11" width="14" height="10" rx="2"/>'
                 '<path d="M8 11V7a4 4 0 0 1 7.8-1.3"/>',
    "plus": '<path d="M12 5v14M5 12h14"/>',
    "minus": '<path d="M5 12h14"/>',
    "key": '<circle cx="7.5" cy="16.5" r="3.5"/>'
           '<path d="M10 14 20 4M15.5 8.5l3 3M18 6l2 2"/>',
    "connect": '<path d="M4 8h15M15 4l4 4-4 4M20 16H5M9 12l-4 4 4 4"/>',
    "monitor": '<rect x="3" y="4" width="18" height="12" rx="2"/>'
               '<path d="M8 20h8M12 16v4"/>',
    "globe": '<circle cx="12" cy="12" r="9"/><path d="M3 12h18"/>'
             '<path d="M12 3a14 14 0 0 1 0 18a14 14 0 0 1 0-18"/>',
    "user": '<circle cx="12" cy="8" r="4"/><path d="M4 20a8 8 0 0 1 16 0"/>',
    "copy": '<rect x="8" y="8" width="12" height="12" rx="2"/>'
            '<path d="M16 8V6a2 2 0 0 0-2-2H6a2 2 0 0 0-2 2v8a2 2 0 0 0 2 2h2"/>',
    "pencil": '<path d="M16.5 3.5a2.1 2.1 0 0 1 3 3L8 18l-4 1 1-4Z"/>'
              '<path d="M14.5 5.5l3 3"/>',
    "trash": '<path d="M4 7h16M10 11v6M14 11v6M6 7l1 13h10l1-13M9 7V4h6v3"/>',
    "upload": '<path d="M12 15V4M7 9l5-5 5 5M5 20h14"/>',
    "download": '<path d="M12 4v11M7 10l5 5 5-5M5 20h14"/>',
    "clipboard": '<rect x="8" y="3" width="8" height="4" rx="1"/>'
                 '<path d="M16 5h2a2 2 0 0 1 2 2v12a2 2 0 0 1-2 2H6a2 2 0 0 1-2-2'
                 'V7a2 2 0 0 1 2-2h2"/>',
    "file": '<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8Z"/>'
            '<path d="M14 3v5h5"/>',
    "folder": '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2'
              'H5a2 2 0 0 1-2-2Z"/>',
    "folder-plus": '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2'
                   'H5a2 2 0 0 1-2-2Z"/><path d="M12 10.5v5M9.5 13h5"/>',
    "folder-open": '<path d="M3 17V7a2 2 0 0 1 2-2h4l2 2h6a2 2 0 0 1 2 2v1"/>'
                   '<path d="M3 17l2.4-6.2A2 2 0 0 1 7.3 9.5H20a1 1 0 0 1 .95 1.3'
                   'l-2.2 6.6A2 2 0 0 1 16.8 19H5a2 2 0 0 1-2-2Z"/>',
    "home": '<path d="M3 11l9-8 9 8M5 9.5V20h5v-6h4v6h5V9.5"/>',
    "refresh": '<path d="M20 12a8 8 0 1 1-2.35-5.65M20 4v5h-5"/>',
    "up": '<path d="M12 19V5M6 11l6-6 6 6"/>',
    "chevron-down": '<path d="M6 9l6 6 6-6"/>',
    "close": '<path d="M6 6l12 12M18 6 6 18"/>',
    "grid": '<rect x="3" y="3" width="7" height="7" rx="1.5"/>'
            '<rect x="14" y="3" width="7" height="7" rx="1.5"/>'
            '<rect x="3" y="14" width="7" height="7" rx="1.5"/>'
            '<rect x="14" y="14" width="7" height="7" rx="1.5"/>',
    "more": '<circle cx="12" cy="5" r="1.3" fill="{c}"/>'
            '<circle cx="12" cy="12" r="1.3" fill="{c}"/>'
            '<circle cx="12" cy="19" r="1.3" fill="{c}"/>',
    "search": '<circle cx="11" cy="11" r="7"/><path d="M20 20l-4-4"/>',
    "eye": '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/>'
           '<circle cx="12" cy="12" r="3"/>',
    "external": '<path d="M7 17 17 7M9 7h8v8"/>',
    "database": '<ellipse cx="12" cy="5" rx="8" ry="3"/>'
                '<path d="M4 5v14c0 1.7 3.6 3 8 3s8-1.3 8-3V5"/>'
                '<path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/>',
    "check": '<path d="M5 12.5l4.5 4.5L19 7"/>',
    "play": '<path d="M7.5 5v14l11-7Z" fill="{c}" stroke-width="1.5"/>',
    "stop": '<rect x="6.5" y="6.5" width="11" height="11" rx="2" fill="{c}"'
            ' stroke-width="1"/>',
    "chat": '<path d="M4 5h16v11H9l-5 4Z"/><path d="M8 9.5h8M8 12.5h5"/>',
    "shield": '<path d="M12 3l8 3v6c0 4.5-3.4 8-8 9-4.6-1-8-4.5-8-9V6Z"/>'
              '<rect x="9" y="11" width="6" height="5" rx="1"/>'
              '<path d="M10.5 11V9.5a1.5 1.5 0 0 1 3 0V11"/>',
}

NAMES = frozenset(_SHAPES)


def svg(name: str, color: str, stroke: float = 2.0) -> bytes:
    body = _SHAPES[name].replace("{c}", color)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
            f'fill="none" stroke="{color}" stroke-width="{stroke}" '
            f'stroke-linecap="round" stroke-linejoin="round">{body}</svg>'
            ).encode("utf-8")


class _SvgEngine(QIconEngine):
    """Draws the SVG at whatever size and pixel ratio Qt asks for — never a
    scaled bitmap.  Disabled buttons get a dimmed copy; hovered ones the
    `active` colour when given."""

    def __init__(self, name: str, color: str, active: str | None,
                 disabled: str, on: str | None = None):
        super().__init__()
        self._name, self._color = name, color
        self._active, self._disabled, self._on = active, disabled, on
        # SVG bytes per colour.  Not QSvgRenderer objects: a renderer kept
        # here could be deleted on the C++ side under us ("wrapped C/C++
        # object has been deleted" inside a paint) — one is cheap to build.
        self._svgs: dict[str, bytes] = {}

    def _renderer(self, mode, state=None) -> QSvgRenderer:
        if mode == QIcon.Mode.Disabled:
            color = self._disabled
        elif state == QIcon.State.On and self._on:
            color = self._on
        elif mode == QIcon.Mode.Active and self._active:
            color = self._active
        else:
            color = self._color
        data = self._svgs.get(color)
        if data is None:
            data = self._svgs[color] = svg(self._name, color)
        return QSvgRenderer(QByteArray(data))

    def paint(self, painter: QPainter, rect: QRect, mode, state) -> None:
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        side = min(rect.width(), rect.height())
        target = QRectF(rect.x() + (rect.width() - side) / 2,
                        rect.y() + (rect.height() - side) / 2, side, side)
        self._renderer(mode, state).render(painter, target)
        painter.restore()

    def pixmap(self, size: QSize, mode, state) -> QPixmap:
        return self.scaledPixmap(size, mode, state, 1.0)

    def scaledPixmap(self, size: QSize, mode, state, scale: float) -> QPixmap:
        scale = scale or 1.0
        pm = QPixmap(max(1, round(size.width() * scale)),
                     max(1, round(size.height() * scale)))
        pm.fill(Qt.GlobalColor.transparent)
        p = QPainter(pm)
        self.paint(p, QRect(QPoint(0, 0), pm.size()), mode, state)
        p.end()
        pm.setDevicePixelRatio(scale)
        return pm

    def clone(self) -> "QIconEngine":
        return _SvgEngine(self._name, self._color, self._active, self._disabled,
                          self._on)


class _PainterEngine(_SvgEngine):
    """For icons drawn with QPainter on a `base`×`base` grid: the same
    drawing function runs scaled to the target pixels, so an icon designed
    for 16 px is drawn, not stretched, at 24 or 32 px."""

    def __init__(self, draw, base: int):
        QIconEngine.__init__(self)
        self._draw, self._base = draw, base

    def paint(self, painter: QPainter, rect: QRect, mode, state) -> None:
        painter.save()
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        side = min(rect.width(), rect.height())
        painter.translate(rect.x() + (rect.width() - side) / 2,
                          rect.y() + (rect.height() - side) / 2)
        painter.scale(side / self._base, side / self._base)
        if mode == QIcon.Mode.Disabled:
            painter.setOpacity(0.4)
        self._draw(painter, self._base)
        painter.restore()

    def clone(self) -> "QIconEngine":
        return _PainterEngine(self._draw, self._base)


def painter_icon(draw, base: int = 16) -> QIcon:
    """QIcon from a `draw(painter, size)` function written for `base` px."""
    return QIcon(_PainterEngine(draw, base))


_cache: dict[tuple, QIcon] = {}


def icon(name: str, color: str = "#c9d1d9", active: str | None = None,
         themed: bool = True, on: str | None = None) -> QIcon:
    """A crisp icon `name` in `color` (a dark-theme hex; mapped for the light
    theme unless themed=False, e.g. on the always-dark terminal).  `active`:
    colour under the mouse; `on`: colour of a checked button."""
    from ui import theme
    if themed:
        color = theme.paint(color)
        active = theme.paint(active) if active else None
        on = theme.paint(on) if on else None
    disabled = theme.paint("#484f58") if themed else "#484f58"
    key = (name, color, active, disabled, on)
    ic = _cache.get(key)
    if ic is None:
        if name not in _SHAPES:
            raise KeyError(f"unknown icon {name!r}")
        ic = QIcon(_SvgEngine(name, color, active, disabled, on))
        _cache[key] = ic
    return ic


def pixmap(name: str, color: str, size: int, widget=None,
           themed: bool = True) -> QPixmap:
    """For a QLabel: the icon at `size` logical px for the widget's screen."""
    ratio = widget.devicePixelRatioF() if widget is not None else 1.0
    return icon(name, color, themed=themed).pixmap(QSize(size, size), ratio)


def set_icon(button, name: str, color: str, active: str | None = None,
             size: int = 16, themed: bool = True, on: str | None = None):
    """Give a button (QPushButton/QToolButton) the icon; returns it."""
    button.setIcon(icon(name, color, active, themed=themed, on=on))
    button.setIconSize(QSize(size, size))
    return button


def _icon_label(name: str, color: str, size: int, themed: bool):
    from PyQt6.QtWidgets import QLabel

    class _L(QLabel):
        """Re-renders its pixmap when moved to a screen with another
        pixel ratio, so it stays sharp after dragging between monitors."""
        def __init__(self):
            super().__init__()
            self.setFixedSize(size, size)
            self._render()

        def _render(self):
            self.setPixmap(pixmap(name, color, size, self, themed))

        def changeEvent(self, ev):
            super().changeEvent(ev)
            from PyQt6.QtCore import QEvent
            kinds = {getattr(QEvent.Type, n, None)
                     for n in ("ScreenChangeInternal", "DevicePixelRatioChange")}
            if ev.type() in kinds:
                self._render()

        def showEvent(self, ev):
            super().showEvent(ev)
            self._render()

    return _L()


def icon_label(name: str, color: str, size: int = 14, themed: bool = True):
    """A QLabel showing just the icon, sharp on every screen."""
    return _icon_label(name, color, size, themed)


from PyQt6.QtWidgets import QFrame  # noqa: E402


class IconBadge(QFrame):
    """A rounded pill of "[icon] text" items separated by dots — the place
    where emoji used to sit inside the text of a QLabel.  `text()` returns
    the plain text (tests, accessibility)."""

    def __init__(self, color: str, frame_css: str, icon_px: int = 12,
                 parent=None):
        super().__init__(parent)
        from PyQt6.QtWidgets import QHBoxLayout
        self.setObjectName("IconBadge")
        self._color, self._icon_px = color, icon_px
        self.setStyleSheet(
            f"#IconBadge {{ {frame_css} }}"
            f"#IconBadge QLabel {{ color: {color}; font-size: 10px;"
            f" background: transparent; border: none; padding: 0; }}")
        self._lay = QHBoxLayout(self)
        self._lay.setContentsMargins(10, 3, 12, 3)
        self._lay.setSpacing(5)
        self._text = ""

    def set_items(self, items) -> None:
        """items: [(icon name or None, text), …]"""
        from PyQt6.QtWidgets import QLabel
        while self._lay.count():
            w = self._lay.takeAt(0).widget()
            if w is not None:
                # Hidden now: until deleteLater runs, a widget taken out of
                # the layout still paints at (0, 0) — a ghost icon.
                w.hide()
                w.deleteLater()
        parts = []
        for i, (name, text) in enumerate(items):
            if i:
                sep = QLabel("·")
                self._lay.addSpacing(4)
                self._lay.addWidget(sep)
                self._lay.addSpacing(4)
            if name:
                self._lay.addWidget(icon_label(name, self._color, self._icon_px))
            self._lay.addWidget(QLabel(text))
            parts.append(text)
        self._text = "   ·   ".join(parts)

    def text(self) -> str:
        return self._text
