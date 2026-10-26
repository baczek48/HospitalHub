import copy

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QToolButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QTextEdit, QGroupBox, QFrame, QScrollArea, QMessageBox, QApplication,
    QSplitter, QMenu, QDialog, QDialogButtonBox, QFileDialog, QLineEdit,
    QStyledItemDelegate, QStyle, QGraphicsColorizeEffect, QSizePolicy,
)
from PyQt6.QtCore import (Qt, pyqtSignal, QPoint, QTimer, QObject, QEvent,
                           QSize, QPropertyAnimation, QEasingCurve, QThread)
from PyQt6.QtGui import (QFont, QBrush, QColor, QIcon, QPixmap, QPainter,
                          QPainterPath, QPen, QPalette)


def _make_db_connect_icon(size: int = 24) -> QIcon:
    """3 stacked database discs with a green play triangle — SQL launcher icon.
    Drawn for the screen's pixel ratio, not as a fixed bitmap."""
    from ui.icons import painter_icon
    return painter_icon(_draw_db_connect, base=size)


def _draw_db_connect(p: QPainter, size: int) -> None:
    disc_color = QColor(58, 130, 200)      # steel blue
    rim_color  = QColor(80, 160, 230)
    play_color = QColor(50, 200, 80)       # green

    n = 3
    disc_h   = size * 0.13              # height of each ellipse rim
    disc_ry  = disc_h / 2
    disc_rx  = size * 0.38
    gap      = size * 0.155             # vertical gap between disc centres
    top_cy   = size * 0.22             # centre y of topmost disc
    cx       = size * 0.44

    # Draw discs bottom → top (so top disc paints over lower ones)
    for i in range(n - 1, -1, -1):
        cy = top_cy + i * gap
        # Cylinder body: filled rect between this disc and next
        if i < n - 1:
            next_cy = top_cy + (i + 1) * gap
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(disc_color)
            p.drawRect(
                int(cx - disc_rx), int(cy),
                int(disc_rx * 2),  int(next_cy - cy + 1),
            )
        # Top ellipse face
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(disc_color.lighter(130) if i == 0 else disc_color)
        p.drawEllipse(
            int(cx - disc_rx), int(cy - disc_ry),
            int(disc_rx * 2),   int(disc_ry * 2),
        )
        # Rim highlight
        p.setPen(QPen(rim_color, max(1, size * 0.03)))
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.drawEllipse(
            int(cx - disc_rx), int(cy - disc_ry),
            int(disc_rx * 2),   int(disc_ry * 2),
        )

    # Green play triangle — bottom-right corner
    ts  = size * 0.36          # triangle bounding box
    tx  = size - ts * 0.95     # left edge of triangle area
    ty  = size - ts * 0.95     # top edge
    tri = QPainterPath()
    tri.moveTo(tx,        ty)
    tri.lineTo(tx + ts,   ty + ts / 2)
    tri.lineTo(tx,        ty + ts)
    tri.closeSubpath()
    p.setPen(Qt.PenStyle.NoPen)
    p.setBrush(play_color)
    p.fillPath(tri, play_color)


class _HeaderMenuFilter(QObject):
    """Event filter that shows a context menu when the header is right-clicked.

    Parented to the header widget so Qt's object tree keeps it alive for as
    long as the header lives — no separate strong-reference bookkeeping needed.
    Using an event filter avoids the PyQt6/Windows segfault that occurs when
    customContextMenuRequested is handled via a Python signal-slot connection.
    """

    def __init__(self, header: QHeaderView, callback):
        super().__init__(header)   # header is Qt parent → lifetime tied
        self._callback = callback
        header.installEventFilter(self)

    def eventFilter(self, obj, event):
        if event.type() == QEvent.Type.ContextMenu:
            menu = QMenu(obj)
            act = menu.addAction("Zapisz szerokości kolumn")
            act.triggered.connect(self._callback)
            menu.exec(event.globalPos())
            return True          # event consumed
        return False


from ui.utils import EmptyHint  # noqa: E402 (needed before the class)


class _DraggableTable(EmptyHint, QTableWidget):
    """QTableWidget with reliable row drag-and-drop via custom dropEvent."""
    rows_reordered = pyqtSignal(int, int)  # from_row, to_row

    def __init__(self, rows, cols, parent=None):
        super().__init__(rows, cols, parent)
        self.setDragEnabled(True)
        self.setAcceptDrops(True)
        self.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)
        self.setDropIndicatorShown(True)
        self.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)

    def resizeEvent(self, event):
        super().resizeEvent(event)
        _fit_table_columns(self)

    def dropEvent(self, event):
        from_row = self.currentRow()
        idx = self.indexAt(event.position().toPoint())
        to_row = idx.row() if idx.isValid() else self.rowCount() - 1
        if from_row >= 0 and to_row >= 0 and from_row != to_row:
            self.rows_reordered.emit(from_row, to_row)
        event.ignore()  # block Qt's own item shuffling

import sys
import os
import weakref
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import models
import vpn_connect
from crypto import decrypt
from ui import theme
from ui.dialogs import HospitalDialog, MachineDialog, DatabaseDialog, _clipboard_copy
from ui.thread_retire import retire_thread
from ui.utils import ElidedLabel, EmptyHint, confirm, plural
from ui.style import FormStyled
from ui.ssh_panel import SshDialog
from ui.rdp import connect_rdp
from ui.icons import IconBadge, icon, set_icon
from ui.db_connect import launch_sqldeveloper
from config import (load_column_widths, save_column_widths,
                    load_personal_vpn_vault, save_personal_vpn_vault,
                    load_vpn_autofill_enabled,
                    load_ssh_start_maximized)

# Session-level VPN profile cache (loaded once per app session)
_vpn_session_profiles: list = []
_vpn_session_loaded: bool = False

# 2026-10-16 (owner's request): a VPN vault open in its own window lends its
# profiles to the VPN button of the hospital windows — no second unlock while
# it is open, and edits made there count at once.  Held weakly; when that
# window is closed for good the button falls back to the vault unlocked here
# (if any) or asks for one again.
_vpn_window_source = None            # weakref to the VpnPanel
_vpn_button_panels = weakref.WeakSet()


def share_vpn_window(panel) -> None:
    """`panel` (a VpnPanel) is open; None: the VPN window was closed."""
    global _vpn_window_source
    _vpn_window_source = weakref.ref(panel) if panel is not None else None
    vpn_profiles_changed()


def unshare_vpn_window(panel) -> None:
    """The window of `panel` closes — stop lending it if it is the one."""
    src = _vpn_window_source() if _vpn_window_source is not None else None
    if src is panel:
        share_vpn_window(None)


def amms_hospital_for(name: str):
    """(hospital, panel): the hospital of an open main vault named `name` —
    paired by name like the VPN button — and the panel of its window
    (2026-10-26: AMMS set once in the main vault shows on the VPN card)."""
    key = (name or "").strip().lower()
    if not key:
        return None, None
    for panel in list(_vpn_button_panels):
        try:
            hospitals = panel._all_hospitals
            if hospitals is None:
                hospitals = getattr(panel.window(), "_hospitals", None)
        except RuntimeError:         # widget already deleted
            continue
        for h in hospitals or []:
            if isinstance(h, models.Hospital) and h.name.strip().lower() == key:
                return h, panel
    return None, None


def amms_changed() -> None:
    """Refresh the AMMS buttons of every hospital window and the VPN window."""
    for p in list(_vpn_button_panels):
        try:
            p._update_amms_btn()
        except RuntimeError:
            pass
    src = _vpn_window_source() if _vpn_window_source is not None else None
    if src is not None:
        try:
            src.restyle_amms()
        except RuntimeError:
            pass


def vpn_profiles_changed() -> None:
    """Refresh the VPN button of every hospital window."""
    for p in list(_vpn_button_panels):
        try:
            p._vpn_last_status = None
            p._update_vpn_btn()
        except RuntimeError:         # widget already deleted
            pass


def _window_vpn_profiles():
    src = _vpn_window_source() if _vpn_window_source is not None else None
    if src is None:
        return None
    try:
        return list(src.get_profiles())
    except RuntimeError:
        return None


def _session_vpn_profiles() -> list:
    shared = _window_vpn_profiles()
    return shared if shared is not None else _vpn_session_profiles


def _vpn_available() -> bool:
    return _vpn_session_loaded or _window_vpn_profiles() is not None

# stretch_col: fills remaining space, pins Akcje to right edge
# akcje_col: always ResizeToContents, not saved
_MACHINES_STRETCH_COL = 2   # Opis
_MACHINES_AKCJE_COL = 3
_MACHINES_DEFAULTS = [120, 140, 180]   # widths for cols 0,1 (col 2 stretches)
_MACHINES_AKCJE_WIDTH = 204    # the buttons, packed (R2: was 322, spread)

_DB_STRETCH_COL = 4         # Notatka (ostatnia kolumna danych, jak Opis w maszynach)
_DB_AKCJE_COL = 5
_DB_DEFAULTS = [180, 60, 130, 80]      # widths for cols 0,1,2,3
_DB_AKCJE_WIDTH = 166


#: "Copied" flash of the login button: (background, border) per theme.  A
#: colorize effect was used before — it tints the pixels, which on the
#: near-white light-theme button left almost nothing to see.
_PULSE_DARK = ("#1f4d2b", "#3fb950")
_PULSE_LIGHT = ("#c6ecd0", "#2da44e")


def _pulse_copy_button(btn: QPushButton) -> None:
    """Green "copied" flash: background and border jump to green and fade
    back to the button's own colours.  Re-clicks restart it."""
    from PyQt6.QtCore import QVariantAnimation
    base_css = getattr(btn, "_pulse_base_css", None)
    if base_css is None:
        base_css = btn._pulse_base_css = btn.styleSheet()
    prev = getattr(btn, "_copy_pulse_anim", None)
    if prev is not None:
        prev.stop()

    light = theme.is_light()
    flash_bg, flash_bd = _PULSE_LIGHT if light else _PULSE_DARK
    rest_bg = QColor(theme.paint("#1e2733"))
    rest_bd = QColor(theme.paint("#30363d"))

    def mix(a: QColor, b: QColor, t: float) -> str:
        return QColor(round(a.red() + (b.red() - a.red()) * t),
                      round(a.green() + (b.green() - a.green()) * t),
                      round(a.blue() + (b.blue() - a.blue()) * t)).name()

    anim = QVariantAnimation(btn)
    anim.setDuration(650)
    anim.setStartValue(0.0)
    anim.setKeyValueAt(0.12, 1.0)    # quick rise
    anim.setKeyValueAt(0.40, 1.0)    # held so it is seen
    anim.setEndValue(0.0)            # fade back
    anim.setEasingCurve(QEasingCurve.Type.InOutQuad)

    def step(value):
        t = float(value)
        btn.setStyleSheet(
            base_css + "QPushButton { background: "
            f"{mix(rest_bg, QColor(flash_bg), t)}; border-color: "
            f"{mix(rest_bd, QColor(flash_bd), t)}; }}")

    anim.valueChanged.connect(step)
    anim.finished.connect(lambda: btn.setStyleSheet(base_css))
    anim.start()
    btn._copy_pulse_anim = anim


class _NoSelectionDelegate(QStyledItemDelegate):
    """Render cells as if never selected/focused. Selection still happens
    internally so drag-and-drop reorder keeps working — only the visual
    'whole row goes blue' from QPalette::Highlight is suppressed."""

    def initStyleOption(self, option, index):
        super().initStyleOption(option, index)
        option.state &= ~QStyle.StateFlag.State_Selected
        option.state &= ~QStyle.StateFlag.State_HasFocus


class _TruncationTooltipFilter(QObject):
    """Show a tooltip with full cell content only when the rendered text is
    actually being elided — i.e. the user can see ellipsis. We ask Qt for the
    elided form (same routine the delegate uses to draw) and compare; if the
    elided string differs from the source, the cell is cut off."""

    # Stylesheet "padding: 2px 4px" + the delegate's focus-frame text margin
    # (~3px each side). Subtracted from the cell rect to get the actual text
    # area the painter draws into.
    _PADDING = 14

    def __init__(self, table: QTableWidget):
        super().__init__(table)
        self._table = table
        table.viewport().installEventFilter(self)

    def eventFilter(self, obj, event):
        from PyQt6.QtWidgets import QToolTip
        if event.type() == QEvent.Type.ToolTip and obj is self._table.viewport():
            idx = self._table.indexAt(event.pos())
            if not idx.isValid():
                QToolTip.hideText()
                return True
            item = self._table.item(idx.row(), idx.column())
            if item is None or not item.text():
                QToolTip.hideText()
                return True
            text = item.text()
            rect = self._table.visualRect(idx)
            available = rect.width() - self._PADDING
            if available <= 0:
                QToolTip.hideText()
                return True
            fm = self._table.fontMetrics()
            longest = max(text.split('\n'), key=len) if '\n' in text else text
            if fm.elidedText(longest, Qt.TextElideMode.ElideRight, available) != longest:
                QToolTip.showText(event.globalPos(), text,
                                  self._table.viewport(), rect)
            else:
                QToolTip.hideText()
            return True
        return False


def _fit_table_columns(table) -> None:
    """Keep the actions column on screen (UX audit V-05).

    The data columns keep their own (or the user's) widths while they fit;
    when the table is narrower — a 1366×768 laptop at 125–150 % — they give
    way proportionally, down to 60 px each, instead of pushing Connect past
    the right edge behind a horizontal scroll bar."""
    spec = getattr(table, '_fit_spec', None)
    if not spec:
        return
    cols, base, akcje_col, stretch_col, hide_order = spec
    avail = table.viewport().width() - table.columnWidth(akcje_col)
    # Least important columns go first when even 60 px each will not fit
    # (their full text stays in the edit dialog and the row's tooltip).
    def plan(hidden):
        shown = [c for c in cols if c not in hidden]
        want = [base[cols.index(c)] for c in shown]
        room = avail - (0 if stretch_col in hidden else 90)
        if sum(want) > room:
            factor = max(room, 0) / max(1, sum(want))
            want = [max(60, int(w * factor)) for w in want]
        return shown, want, sum(want) <= room

    for k in range(len(hide_order) + 1):
        hidden = set(hide_order[:k])
        shown, want, fits = plan(hidden)
        if fits:
            break
    table._fitting = True
    try:
        for col in hide_order:
            table.setColumnHidden(col, col in hidden)
        for col, w in zip(shown, want):
            if table.columnWidth(col) != w:
                table.setColumnWidth(col, w)
    finally:
        table._fitting = False


def _setup_table_columns(
    table: QTableWidget,
    key: str,
    defaults: list,
    stretch_col: int,
    akcje_col: int,
    akcje_width: int = 220,
    hide_order: tuple = (),
):
    """Configure column resize modes and restore saved widths."""
    hh = table.horizontalHeader()
    saved = load_column_widths(key)

    skip = {stretch_col, akcje_col}

    # Build list of interactive column indices (all except stretch, akcje)
    interactive_cols = [
        i for i in range(table.columnCount()) if i not in skip
    ]
    widths = saved if (saved and len(saved) == len(interactive_cols)) else defaults

    hh.setMinimumSectionSize(60)
    for idx, col in enumerate(interactive_cols):
        hh.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
        table.setColumnWidth(col, widths[idx])

    # What the columns should be when there is room; a drag by the user
    # becomes the new wish, a fit-to-width squeeze does not (V-05).
    base = list(widths)
    table._fit_spec = (interactive_cols, base, akcje_col, stretch_col, tuple(hide_order))
    table._fitting = False

    def _remember(col, _old, new):
        if not table._fitting and col in interactive_cols:
            base[interactive_cols.index(col)] = new
    hh.sectionResized.connect(_remember)

    hh.setSectionResizeMode(stretch_col, QHeaderView.ResizeMode.Stretch)
    hh.setSectionResizeMode(akcje_col, QHeaderView.ResizeMode.Fixed)
    table.setColumnWidth(akcje_col, akcje_width)

    # Install an event filter that intercepts ContextMenu events on the header.
    # IMPORTANT: horizontalHeader() returns ephemeral Python wrappers — storing on
    # hh would lose the reference when that wrapper is GC'd.  Store on `table`
    # instead, which is a stable Python object held by the DetailPanel instance.
    table._header_ctx_menu_filter = _HeaderMenuFilter(
        hh,
        # The user's widths, not the ones squeezed to fit a narrow window or
        # the 0 of a hidden column (review 71, R-09).
        lambda: save_column_widths(key, list(table._fit_spec[1])),
    )
    table._truncation_tooltip_filter = _TruncationTooltipFilter(table)

    delegate = _NoSelectionDelegate(table)
    table.setItemDelegate(delegate)
    table._no_selection_delegate = delegate

    # Suppress the row-wide blue paint from QPalette.Highlight that QTableView
    # draws under cells without items (the "Akcje" cell-widget column). Only
    # this widget's palette is touched — QApplication palette stays intact, so
    # nothing else in the app changes colour.
    pal = table.palette()
    pal.setColor(QPalette.ColorRole.Highlight, QColor(0, 0, 0, 0))
    pal.setColor(QPalette.ColorRole.HighlightedText, QColor(theme.paint("#e6edf3")))
    table.setPalette(pal)


class _VpnStatusProbe(QThread):
    """One ``vpn_connect.get_status`` call, off the UI thread (D-07).

    The hospital window asked for the VPN status on the UI thread every 2 s —
    for FortiClient that is ``tasklist`` and ``netstat`` per tick when the
    tunnel is down, and up to a 5 s CLI timeout on EMS — and froze the window
    for that long.  Same call, same arguments, in a thread; the answer comes
    back with the profile key it was asked for.
    """

    result = pyqtSignal(object, object)          # key, status (or None)

    def __init__(self, key, provider, app_path, profile_name, parent=None,
                 sole=False):
        super().__init__(parent)
        self._key = key
        self._args = (provider, app_path, profile_name)
        self._sole = sole

    def run(self):
        try:
            from ui.vpn_panel import vpn_status
            status = vpn_status(*self._args, sole=self._sole)
        except Exception:
            status = None
        self.result.emit(self._key, status)


def _vpn_status_key(profile) -> tuple:
    return (profile.provider, profile.app_path, profile.profile_name)


def _sole_vpn_profile(profile) -> bool:
    """Is `profile` the only one of its provider among the loaded VPN
    profiles?  (A tunnel connected before HospitalHub started is then its,
    see ui.vpn_panel.vpn_status.)"""
    from ui.vpn_panel import sole_providers
    try:
        return profile.provider in sole_providers(_session_vpn_profiles())
    except Exception:
        return False


class _VpnUnlockDialog(FormStyled, QDialog):
    """Dialog to pick a personal VPN vault file and enter its password."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Twój VPN vault")
        self.setModal(True)
        self.setFixedWidth(380)
        self.setStyleSheet("background: #0d1117; color: #c9d1d9;")

        lay = QVBoxLayout(self)
        lay.setContentsMargins(20, 16, 20, 16)
        lay.setSpacing(10)

        title = QLabel("Wskaż osobisty VPN vault")
        title.setStyleSheet("color: #c9d1d9; font-size: 13px; font-weight: bold; background: transparent;")
        lay.addWidget(title)

        desc = QLabel("Plik zostanie zapamiętany — hasło tylko na czas sesji.")
        desc.setStyleSheet("color: #8b949e; font-size: 10px; background: transparent;")
        desc.setWordWrap(True)
        lay.addWidget(desc)

        # File path row
        path_row = QHBoxLayout()
        self._path_edit = QLineEdit()
        saved = load_personal_vpn_vault()
        if saved:
            self._path_edit.setText(saved)
        self._path_edit.setPlaceholderText("Ścieżka do pliku .vault...")
        self._path_edit.setStyleSheet(
            "QLineEdit { background: #21262d; border: 1px solid #30363d; border-radius: 4px;"
            " padding: 5px 8px; color: #c9d1d9; font-size: 11px; }"
            "QLineEdit:focus { border-color: #1f6feb; }"
        )
        path_row.addWidget(self._path_edit, 1)
        btn_browse = QPushButton("...")
        btn_browse.setFixedSize(28, 28)
        btn_browse.setStyleSheet(
            "QPushButton { background: #21262d; color: #c9d1d9; border: 1px solid #30363d;"
            " border-radius: 4px; font-weight: bold; }"
            "QPushButton:hover { background: #30363d; }"
        )
        btn_browse.clicked.connect(self._browse)
        path_row.addWidget(btn_browse)
        lay.addLayout(path_row)

        # Password
        lbl_pass = QLabel("Hasło do VPN vaulta")
        lbl_pass.setStyleSheet("color: #8b949e; font-size: 10px; background: transparent;")
        lay.addWidget(lbl_pass)
        self._pass_edit = QLineEdit()
        self._pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self._pass_edit.setPlaceholderText("Hasło...")
        self._pass_edit.setStyleSheet(
            "QLineEdit { background: #21262d; border: 1px solid #30363d; border-radius: 4px;"
            " padding: 5px 8px; color: #c9d1d9; font-size: 11px; }"
            "QLineEdit:focus { border-color: #1f6feb; }"
        )
        self._pass_edit.returnPressed.connect(self.accept)
        lay.addWidget(self._pass_edit)

        btns = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        btns.setStyleSheet(
            "QDialogButtonBox QPushButton { background: #21262d; color: #c9d1d9;"
            " border: 1px solid #30363d; border-radius: 4px; padding: 5px 16px; min-width: 70px; }"
            "QDialogButtonBox QPushButton:hover { background: #30363d; }"
            "QDialogButtonBox QPushButton[text='OK'] { background: #1f6feb; color: #fff; border-color: #1f6feb; }"
            "QDialogButtonBox QPushButton[text='OK']:hover { background: #388bfd; }"
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        lay.addWidget(btns)

        self._pass_edit.setFocus()

    def _browse(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Wybierz VPN vault", "",
            "Vault files (*.vault);;Wszystkie pliki (*)"
        )
        if path:
            self._path_edit.setText(path)

    def vault_path(self) -> str:
        return self._path_edit.text().strip()

    def password(self) -> str:
        return self._pass_edit.text()


_LOGIN_BTN_W = 90   # width of the login button in the Akcje column


class DetailPanel(QWidget):
    data_changed = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.current_hospital: models.Hospital = None
        self._all_hospitals: list = None
        self._admin_unlocked: bool = False
        self._setup_ui()

    def _setup_ui(self):
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        self._placeholder = QLabel("Wybierz szpital z listy lub dodaj nowy")
        self._placeholder.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._placeholder.setStyleSheet("color: #888; font-size: 14px;")
        outer.addWidget(self._placeholder)

        self._content = QWidget()
        content_layout = QVBoxLayout(self._content)
        content_layout.setContentsMargins(16, 12, 16, 12)
        content_layout.setSpacing(10)

        # Header
        header = QHBoxLayout()
        self._name_label = ElidedLabel()
        font = QFont()
        font.setPointSize(15)
        font.setBold(True)
        self._name_label.setFont(font)
        header.addWidget(self._name_label, 1)

        # Admin mode badge — visible only when unlocked
        self._admin_badge = IconBadge(
            "#8ae234", "background: #1a3a1a; border: 1px solid #2d5a1a;"
            " border-radius: 10px;")
        self._admin_badge.set_items([("lock-open", "TRYB ADMINA")])
        self._admin_badge.setVisible(False)
        header.addWidget(self._admin_badge)

        # Decorative stats badge — shows machine + DB count at a glance
        self._stats_badge = IconBadge(
            "#58a6ff", "background: #0d1117; border: 1px solid #21262d;"
            " border-radius: 10px;")
        header.addWidget(self._stats_badge)
        # The name gives way first; the badge keeps its full text (V-03).
        self._stats_badge.setSizePolicy(QSizePolicy.Policy.Minimum,
                                        QSizePolicy.Policy.Preferred)

        btn_quick_ssh = QToolButton()
        set_icon(btn_quick_ssh, "connect", "#58a6ff", active="#79c0ff")
        btn_quick_ssh.setFixedSize(26, 26)
        btn_quick_ssh.setToolTip("Szybkie połączenie SSH (dowolny host)")
        btn_quick_ssh.setStyleSheet(
            "QToolButton { background: transparent; border: 1px solid #1f4a70;"
            " border-radius: 5px; color: #58a6ff; font-size: 15px; font-weight: bold; }"
            "QToolButton:hover { background: #0f2535; border-color: #58a6ff; color: #79c0ff; }"
            "QToolButton:pressed { background: #1f6feb; color: #fff; }"
        )
        btn_quick_ssh.clicked.connect(self._quick_ssh)
        header.addWidget(btn_quick_ssh)

        btn_sqld = QToolButton()
        btn_sqld.setIcon(_make_db_connect_icon(26))
        btn_sqld.setIconSize(QSize(20, 20))
        btn_sqld.setFixedSize(26, 26)
        btn_sqld.setToolTip("Uruchom SQL Developer")
        btn_sqld.setStyleSheet(
            "QToolButton { background: transparent; border: 1px solid #30363d; border-radius: 5px; }"
            "QToolButton:hover { background: #21262d; border-color: #3a82c8; }"
            "QToolButton:pressed { background: #1a4a70; }"
        )
        btn_sqld.clicked.connect(lambda: launch_sqldeveloper(self))
        header.addWidget(btn_sqld)

        self._vpn_btn = QToolButton()
        self._vpn_btn.setText("VPN")
        self._vpn_btn.setFixedSize(38, 26)
        self._vpn_btn.setToolTip("Połącz przez VPN")
        self._vpn_btn.setStyleSheet(
            "QToolButton { background: transparent; border: 1px solid #30363d;"
            " border-radius: 5px; color: #8b949e; font-size: 10px; font-weight: bold; }"
            "QToolButton:hover { background: #21262d; border-color: #58a6ff; color: #58a6ff; }"
            "QToolButton:pressed { background: #1a3a5c; }"
        )
        self._vpn_btn.clicked.connect(self._on_vpn_btn_clicked)
        # 2026-10-20: a V2 connect from this button reports here, like a VPN
        # card's status line; hidden when nothing is going on.
        self._vpn_status_lbl = QLabel()
        self._vpn_status_lbl.setMaximumWidth(420)
        self._vpn_status_lbl.setVisible(False)
        self._vpn_header = header
        self._vpn_v2_controller = None
        header.addWidget(self._vpn_status_lbl)

        # 2026-10-26: AMMS of this hospital — left click signs in, right
        # click edits the URL and the account (kept in the hospital, in the
        # vault).
        self._amms_btn = QToolButton()
        self._amms_btn.setText("AMMS")
        self._amms_btn.setFixedSize(46, 26)
        self._amms_btn.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._amms_btn.customContextMenuRequested.connect(self._on_amms_menu)
        self._amms_btn.clicked.connect(self._on_amms_btn_clicked)
        self._amms_status_lbl = QLabel()
        self._amms_status_lbl.setMaximumWidth(420)
        self._amms_status_lbl.setVisible(False)
        self._amms_worker = None
        self._amms_hide_timer = QTimer(self)
        self._amms_hide_timer.setSingleShot(True)
        self._amms_hide_timer.timeout.connect(
            lambda: self._amms_status_lbl.setVisible(False))
        header.addWidget(self._amms_status_lbl)
        header.addWidget(self._amms_btn)
        header.addWidget(self._vpn_btn)

        # Poll VPN status every 2s to keep button state in sync
        self._vpn_last_status = None  # cache last known status to avoid flicker
        self._vpn_poll_timer = QTimer(self)
        self._vpn_poll_timer.setInterval(2000)
        self._vpn_poll_timer.timeout.connect(self._poll_vpn_status)
        self._vpn_poll_timer.start()
        _vpn_button_panels.add(self)

        content_layout.addLayout(header)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFrameShadow(QFrame.Shadow.Sunken)
        content_layout.addWidget(sep)

        # Splitter
        self._splitter = QSplitter(Qt.Orientation.Vertical)
        self._splitter.setChildrenCollapsible(False)

        # Top: machines
        machines_group = QGroupBox("Maszyny / Hosty")
        machines_group.setStyleSheet("""
            QGroupBox {
                color: #8b949e; font-size: 11px; font-weight: bold;
                border: 1px solid #30363d; border-radius: 6px;
                margin-top: 12px; padding-top: 6px; background: #0d1117;
            }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; }
        """)
        machines_layout = QVBoxLayout(machines_group)
        machines_layout.setContentsMargins(8, 8, 8, 8)
        machines_layout.setSpacing(6)

        self._machines_table = _DraggableTable(0, 4)
        self._machines_table.setTabKeyNavigation(False)   # E-12
        self._machines_table.setHorizontalHeaderLabels(["Adres IP", "Nazwa", "Opis", "Akcje"])
        self._machines_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._machines_table.verticalHeader().setVisible(False)
        self._machines_table.setAlternatingRowColors(True)
        self._machines_table.setStyleSheet("""
            QTableWidget {
                background: #161b22; alternate-background-color: #1c2128;
                color: #e6edf3; border: 1px solid #30363d; border-radius: 4px;
                gridline-color: transparent;
            }
            QTableWidget::item { padding: 2px 4px; }
            QTableWidget::item:selected { background: transparent; color: #e6edf3; }
            QTableWidget::item:focus   { background: transparent; outline: none; }
            QTableWidget { outline: 0; }
            QHeaderView::section {
                background: #21262d; color: #8b949e; border: none;
                border-bottom: 1px solid #30363d; padding: 4px 6px;
                font-weight: bold; font-size: 10px;
            }
        """)
        self._machines_table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._machines_table.cellClicked.connect(self._on_machine_cell_clicked)
        self._machines_table.rows_reordered.connect(self._on_machines_reordered)
        self._machines_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._machines_table.customContextMenuRequested.connect(
            lambda pos: self._on_table_menu(self._machines_table, 'machine', pos))
        _setup_table_columns(
            self._machines_table, "machines", _MACHINES_DEFAULTS,
            stretch_col=_MACHINES_STRETCH_COL, akcje_col=_MACHINES_AKCJE_COL,
            akcje_width=_MACHINES_AKCJE_WIDTH,
            hide_order=(2,),               # Opis
        )
        machines_layout.addWidget(self._machines_table)

        btn_add_machine = QPushButton("Dodaj maszynę")
        set_icon(btn_add_machine, "plus", "#8ae234", active="#a0de4a", size=14)
        btn_add_machine.setMaximumWidth(170)
        btn_add_machine.setStyleSheet(
            "QPushButton { background: #1a2a1a; color: #8ae234; border: 1px solid #2d5a1a;"
            " border-radius: 4px; padding: 4px 10px; font-size: 11px; }"
            "QPushButton:hover { background: #253d1a; color: #a0de4a; }"
        )
        btn_add_machine.clicked.connect(self._add_machine)
        machines_layout.addWidget(btn_add_machine)

        self._splitter.addWidget(machines_group)

        # Bottom: databases + notes
        bottom_scroll = QScrollArea()
        bottom_scroll.setWidgetResizable(True)
        bottom_scroll.setFrameShape(QFrame.Shape.NoFrame)
        bottom_widget = QWidget()
        bottom_layout = QVBoxLayout(bottom_widget)
        bottom_layout.setContentsMargins(0, 4, 0, 0)
        bottom_layout.setSpacing(10)

        db_group = QGroupBox("Bazy danych")
        db_group.setStyleSheet("""
            QGroupBox {
                color: #8b949e; font-size: 11px; font-weight: bold;
                border: 1px solid #30363d; border-radius: 6px;
                margin-top: 12px; padding-top: 6px; background: #0d1117;
            }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; }
        """)
        db_layout = QVBoxLayout(db_group)
        db_layout.setContentsMargins(8, 8, 8, 8)
        db_layout.setSpacing(6)

        self._db_table = _DraggableTable(0, 6)
        self._db_table.setTabKeyNavigation(False)         # E-12
        self._db_table.setHorizontalHeaderLabels(
            ["Host", "Port", "Nazwa bazy", "Typ", "Notatka", "Akcje"]
        )
        self._db_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self._db_table.verticalHeader().setVisible(False)
        self._db_table.setAlternatingRowColors(True)
        self._db_table.setStyleSheet("""
            QTableWidget {
                background: #161b22; alternate-background-color: #1c2128;
                color: #e6edf3; border: 1px solid #30363d; border-radius: 4px;
                gridline-color: transparent;
            }
            QTableWidget::item { padding: 2px 4px; }
            QTableWidget::item:selected { background: transparent; color: #e6edf3; }
            QTableWidget::item:focus   { background: transparent; outline: none; }
            QTableWidget { outline: 0; }
            QHeaderView::section {
                background: #21262d; color: #8b949e; border: none;
                border-bottom: 1px solid #30363d; padding: 4px 6px;
                font-weight: bold; font-size: 10px;
            }
        """)
        self._db_table.setFixedHeight(140)
        self._db_table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        self._db_table.cellClicked.connect(self._on_db_cell_clicked)
        self._db_table.rows_reordered.connect(self._on_db_reordered)
        self._db_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._db_table.customContextMenuRequested.connect(
            lambda pos: self._on_table_menu(self._db_table, 'database', pos))
        _setup_table_columns(
            self._db_table, "databases", _DB_DEFAULTS,
            stretch_col=_DB_STRETCH_COL, akcje_col=_DB_AKCJE_COL,
            akcje_width=_DB_AKCJE_WIDTH,
            hide_order=(4, 3, 1),          # Notatka, Typ, Port
        )
        db_layout.addWidget(self._db_table)

        btn_add_db = QPushButton("Dodaj bazę danych")
        set_icon(btn_add_db, "plus", "#8ae234", active="#a0de4a", size=14)
        btn_add_db.setMaximumWidth(190)
        btn_add_db.setStyleSheet(
            "QPushButton { background: #1a2a1a; color: #8ae234; border: 1px solid #2d5a1a;"
            " border-radius: 4px; padding: 4px 10px; font-size: 11px; }"
            "QPushButton:hover { background: #253d1a; color: #a0de4a; }"
        )
        btn_add_db.clicked.connect(self._add_database)
        db_layout.addWidget(btn_add_db)

        bottom_layout.addWidget(db_group)

        notes_group = QGroupBox("Notatki o środowisku")
        notes_group.setStyleSheet("""
            QGroupBox {
                color: #8b949e; font-size: 11px; font-weight: bold;
                border: 1px solid #30363d; border-radius: 6px;
                margin-top: 12px; padding-top: 6px; background: #0d1117;
            }
            QGroupBox::title { subcontrol-origin: margin; left: 10px; padding: 0 6px; }
        """)
        notes_layout = QVBoxLayout(notes_group)
        self._notes_edit = QTextEdit()
        self._notes_edit.setMaximumHeight(100)
        self._notes_edit.setPlaceholderText(
            "Dodatkowe informacje, specyfika środowiska, kontakty..."
        )
        self._notes_edit.textChanged.connect(self._on_notes_changed)
        notes_layout.addWidget(self._notes_edit)
        bottom_layout.addWidget(notes_group)
        bottom_layout.addStretch()

        bottom_scroll.setWidget(bottom_widget)
        self._splitter.addWidget(bottom_scroll)
        self._splitter.setSizes([320, 280])

        content_layout.addWidget(self._splitter)
        outer.addWidget(self._content)
        self._content.hide()

    # ------------------------------------------------------------------ #

    def resizeEvent(self, event):
        super().resizeEvent(event)
        # The hospital's name matters more than the counts: on a narrow
        # panel the badge goes and the name keeps its room (V-03).
        if hasattr(self, '_stats_badge'):
            self._stats_badge.setVisible(self.width() >= 760)

    def cleanup(self):
        """Stop timers and workers — call before discarding this panel."""
        if hasattr(self, '_vpn_poll_timer'):
            self._vpn_poll_timer.stop()
        # Both block without an event loop (a 20 s window search, a client's
        # stdout): quit() cannot stop them, and deleting this panel with them
        # still running aborted the process (D-01).  Hand them over instead.
        # A finished status probe deletes itself (deleteLater) while this
        # panel still holds it: reading its signal raised "wrapped C/C++
        # object … has been deleted" and stopped the application from
        # closing (2026-10-17).  Each is looked at only if still there.
        for attr, sig in (('_vpn_status_probe', 'result'),
                          ('_vpn_token_waiter', 'found'),
                          ('_vpn_monitor_worker', 'twofa_detected'),
                          ('_amms_worker', 'done')):
            thread = getattr(self, attr, None)
            if thread is None:
                continue
            try:
                signal = getattr(thread, sig, None)
            except RuntimeError:          # the C++ object is already gone
                continue
            retire_thread(thread, disconnect=(signal,) if signal is not None else ())

    # ------------------------------------------------------------------ #

    def set_admin_mode(self, unlocked: bool):
        self._admin_unlocked = unlocked
        self._admin_badge.setVisible(unlocked)
        self._refresh()

    def show_hospital(self, hospital: models.Hospital, all_hospitals: list):
        self.current_hospital = hospital
        self._all_hospitals = all_hospitals
        if hospital is None:
            self._placeholder.show()
            self._content.hide()
        else:
            self._placeholder.hide()
            self._content.show()
            self._refresh()

    def _refresh(self):
        h = self.current_hospital
        if not h:
            return
        self._name_label.setText(h.name)
        self._notes_edit.blockSignals(True)
        self._notes_edit.setPlainText(h.notes)
        self._notes_edit.blockSignals(False)
        self._refresh_machines()
        self._refresh_databases()
        self._update_vpn_btn()
        self._update_amms_btn()

    # ------------------------------------------------------------------ #
    # Cell click → copy                                                    #
    # ------------------------------------------------------------------ #

    def _flash_cell(self, table: QTableWidget, row: int, col: int) -> None:
        """Press-and-spring-back feedback. Cell briefly recesses: darker bg
        plus the text shrinks ~0.7pt; then the bg fades through a midpoint
        and the font springs back to its original size. Two-stage timing
        (~140 ms total) gives a soft physical-press feel rather than a flat
        on/off colour blink."""
        item = table.item(row, col)
        if not item:
            return

        if theme.is_light():
            # Warm-ivory press feedback: a gentle DARKER tint on press that
            # settles back to the row's real background (remap turns the dark
            # source hexes lighter, so we can't reuse them for a press recess).
            orig_bg = QColor("#f2f3f6") if row % 2 else QColor("#ffffff")
            pressed_bg = QColor("#dde0e6")
            half_bg = QColor("#eaecf0")
        else:
            orig_bg = QColor("#1c2128") if row % 2 else QColor("#161b22")
            pressed_bg = QColor("#0a0c10")
            half_bg = QColor("#13171c")  # mid-fade to soften the bg release

        base_font = item.font()
        if base_font.pointSize() <= 0 and base_font.pixelSize() <= 0:
            base_font = QFont(table.font())
        pressed_font = QFont(base_font)
        if base_font.pointSizeF() > 0:
            pressed_font.setPointSizeF(max(base_font.pointSizeF() - 0.7, 6.0))
        elif base_font.pixelSize() > 0:
            pressed_font.setPixelSize(max(base_font.pixelSize() - 1, 8))

        item.setBackground(QBrush(pressed_bg))
        item.setFont(pressed_font)

        def _half():
            try:
                item.setBackground(QBrush(half_bg))
            except RuntimeError:
                pass        # the table was refreshed meanwhile (E-24)

        QTimer.singleShot(70, _half)

        def _restore():
            try:
                item.setBackground(QBrush(orig_bg))
                item.setFont(base_font)
            except RuntimeError:
                pass

        QTimer.singleShot(140, _restore)

    def _on_machine_cell_clicked(self, row: int, col: int):
        self._machines_table.clearSelection()
        self._machines_table.setCurrentIndex(
            self._machines_table.model().index(-1, -1))
        if col == _MACHINES_AKCJE_COL:
            return
        item = self._machines_table.item(row, col)
        if item and item.text():
            self._flash_cell(self._machines_table, row, col)
            _clipboard_copy(item.text())

    def _on_db_cell_clicked(self, row: int, col: int):
        self._db_table.clearSelection()
        self._db_table.setCurrentIndex(
            self._db_table.model().index(-1, -1))
        if col == _DB_AKCJE_COL:
            return
        item = self._db_table.item(row, col)
        if item and item.text():
            self._flash_cell(self._db_table, row, col)
            _clipboard_copy(item.text())

    def _on_machines_reordered(self, from_row: int, to_row: int):
        if not self.current_hospital:
            return
        visible = self._visible_machines()
        if from_row >= len(visible) or to_row >= len(visible):
            return
        lst = self.current_hospital.machines
        real_from = lst.index(visible[from_row])
        real_to = lst.index(visible[to_row])
        lst.insert(real_to, lst.pop(real_from))
        self._refresh_machines()
        self.data_changed.emit()

    def _on_db_reordered(self, from_row: int, to_row: int):
        if not self.current_hospital:
            return
        visible = self._visible_databases()
        if from_row >= len(visible) or to_row >= len(visible):
            return
        lst = self.current_hospital.databases
        real_from = lst.index(visible[from_row])
        real_to = lst.index(visible[to_row])
        lst.insert(real_to, lst.pop(real_from))
        self._refresh_databases()
        self.data_changed.emit()

    # ------------------------------------------------------------------ #
    # Machines                                                             #
    # ------------------------------------------------------------------ #

    def _update_badge(self):
        if not self.current_hospital:
            return
        m  = len(self._visible_machines())
        db = len(self._visible_databases())
        hidden_m = sum(1 for x in self.current_hospital.machines if x.admin_only)
        hidden_d = sum(1 for x in self.current_hospital.databases if x.admin_only)
        hidden = hidden_m + hidden_d
        items = [("monitor", plural(m, 'maszyna', 'maszyny', 'maszyn')),
                 ("database", plural(db, 'baza', 'bazy', 'baz'))]
        if hidden and not self._admin_unlocked:
            items.append(("lock", plural(hidden, "ukryta pozycja",
                                         "ukryte pozycje", "ukrytych pozycji")))
        self._stats_badge.set_items(items)

    def _visible_machines(self) -> list[models.Machine]:
        if not self.current_hospital:
            return []
        if self._admin_unlocked:
            return self.current_hospital.machines
        return [m for m in self.current_hospital.machines if not m.admin_only]

    def _visible_databases(self) -> list[models.Database]:
        if not self.current_hospital:
            return []
        if self._admin_unlocked:
            return self.current_hospital.databases
        return [d for d in self.current_hospital.databases if not d.admin_only]

    def _refresh_machines(self):
        self._machines_table.setRowCount(0)
        visible = self._visible_machines()
        h = self.current_hospital
        hidden = h is not None and len(h.machines) > len(visible)
        self._machines_table.empty_hint = (
            "Maszyny tego szpitala są ukryte — odblokuj tryb admina." if hidden
            else "Brak maszyn — dodaj pierwszą przyciskiem „+ Dodaj maszynę”.")
        self._machines_table.viewport().update()
        for i, machine in enumerate(visible):
            self._machines_table.insertRow(i)

            ip_item = QTableWidgetItem(machine.ip)
            # Darker, stronger blue on the white light-theme card (the steel blue
            # was too faint); keep the brighter blue on the dark theme.
            ip_color = QColor("#0a4db0") if theme.is_light() else QColor(0, 120, 215)
            ip_item.setForeground(QBrush(ip_color))
            self._machines_table.setItem(i, 0, ip_item)

            for col, text in [(1, machine.name), (2, machine.description)]:
                item = QTableWidgetItem(text)
                if machine.admin_only:
                    item.setForeground(QBrush(QColor(theme.paint("#c084fc"))))
                self._machines_table.setItem(i, col, item)

            self._machines_table.setCellWidget(i, _MACHINES_AKCJE_COL, self._machine_actions(machine))

            self._machines_table.setRowHeight(i, 36)
        self._update_badge()

    # ── row menu: every account, login and password (UX audit E-08/E-09) ──

    _MENU_QSS = (
        "QMenu { background:#161b22; border:1px solid #30363d; color:#c9d1d9; }"
        "QMenu::item { padding:5px 20px 5px 12px; }"
        "QMenu::item:selected { background:#1f6feb; color:#fff; }"
        "QMenu::item:disabled { color:#6e7681; }"
        "QMenu::separator { height:1px; background:#30363d; margin:3px 0; }"
    )

    def _attach_row_menu(self, widget, item, kind: str) -> None:
        widget.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        widget.customContextMenuRequested.connect(
            lambda pos, w=widget, it=item, k=kind:
                self._row_menu(it, k).exec(w.mapToGlobal(pos)))

    def _row_menu(self, item, kind: str) -> QMenu:
        """The same actions as the row's buttons, plus what had no button:
        the login, the other accounts, connecting as one of them."""
        menu = QMenu(self)
        menu.setStyleSheet(self._MENU_QSS)
        creds = self._visible_credentials(item.credentials)
        if kind == 'machine':
            ctype = getattr(item, 'connection_type', 'SSH')
            if ctype == 'WWW':
                menu.addAction(icon("globe", "#c9d1d9"), "Otwórz w przeglądarce",
                               lambda m=item: self._open_www(m))
            elif ctype == 'RDP':
                menu.addAction("Połącz (RDP)",
                               lambda m=item: connect_rdp(m, self, self._admin_unlocked))
            else:
                menu.addAction(icon("connect", "#c9d1d9"), "Połącz (SSH + SFTP)",
                               lambda m=item: self._open_ssh(m))
            if len(creds) > 1 and ctype in ('SSH', 'RDP'):
                sub = menu.addMenu("Połącz jako")
                sub.setStyleSheet(self._MENU_QSS)
                for c in creds:
                    sub.addAction(c.login or "(bez loginu)",
                                  lambda m=item, c=c: self._connect_as(m, c))
            menu.addSeparator()
        if not creds:
            act = menu.addAction("Brak poświadczeń")
            act.setEnabled(False)
        for c in creds:
            label = c.login or "(bez loginu)"
            if c.admin_only:
                label += "  (admin)"
            menu.addAction(icon("user", "#c9d1d9"), f"Kopiuj login: {label}",
                           lambda c=c: _clipboard_copy(c.login))
            menu.addAction(icon("key", "#c9d1d9"), f"Kopiuj hasło: {label}",
                           lambda c=c: _clipboard_copy(c.password))
        menu.addSeparator()
        if kind == 'machine':
            menu.addAction(icon("copy", "#c9d1d9"), "Duplikuj",
                           lambda m=item: self._duplicate_machine(m))
            menu.addAction(icon("gear", "#c9d1d9"), "Edytuj maszynę…",
                           lambda m=item: self._edit_machine(m))
            menu.addAction("Usuń maszynę…", lambda m=item: self._delete_machine(m))
        else:
            menu.addAction(icon("gear", "#c9d1d9"), "Edytuj bazę…",
                           lambda d=item: self._edit_database(d))
            menu.addAction("Usuń bazę…", lambda d=item: self._delete_database(d))
        return menu

    def _connect_as(self, machine, cred) -> None:
        """Connect with `cred` instead of the first account (E-09)."""
        import copy
        m = copy.copy(machine)
        m.credentials = [cred] + [c for c in machine.credentials if c is not cred]
        if getattr(machine, 'connection_type', 'SSH') == 'RDP':
            connect_rdp(m, self, self._admin_unlocked)
        else:
            self._open_ssh(m)

    def _on_table_menu(self, table, kind: str, pos) -> None:
        row = table.indexAt(pos).row()
        items = (self._visible_machines() if kind == 'machine'
                 else self._visible_databases())
        if 0 <= row < len(items):
            self._row_menu(items[row], kind).exec(table.viewport().mapToGlobal(pos))

    def _visible_credentials(self, creds: list) -> list:
        if self._admin_unlocked:
            return creds
        return [c for c in creds if not c.admin_only]

    def _machine_actions(self, machine: models.Machine) -> QWidget:
        w = QWidget()
        row = QHBoxLayout(w)
        row.setContentsMargins(4, 2, 4, 2)
        row.setSpacing(3)

        vis_creds = self._visible_credentials(machine.credentials)
        first_cred = vis_creds[0] if vis_creds else None
        login_text = (first_cred.login[:10] + "…" if first_cred and len(first_cred.login) > 10
                      else (first_cred.login if first_cred else "—"))

        _cred_btn_style = (
            "QPushButton { background: #1e2733; color: #8b949e; border: 1px solid #30363d;"
            " border-radius: 4px; padding: 2px 4px; font-size: 10px; }"
            "QPushButton:hover { background: #263040; color: #c9d1d9; }"
            "QPushButton:disabled { color: #444; background: #161b22; border-color: #21262d; }"
        )

        btn_login = QPushButton(login_text)
        if first_cred:
            set_icon(btn_login, "key", "#d29922", size=12)
        btn_login.setEnabled(first_cred is not None)
        btn_login.setFixedHeight(28)
        # Fixed, not maximum: a short login (or "—") made the button narrower
        # and pushed the action buttons out of line row by row.
        btn_login.setFixedWidth(_LOGIN_BTN_W)
        btn_login.setToolTip(
            f"Kliknij: kopiuj hasło ({first_cred.login})\n"
            "Prawy klik: login, inne konta, połącz jako…" if first_cred
            else "Brak poświadczeń"
        )
        self._attach_row_menu(btn_login, machine, 'machine')
        btn_login.setStyleSheet(_cred_btn_style)
        if first_cred:
            btn_login.clicked.connect(
                lambda _, c=first_cred, b=btn_login: (
                    _clipboard_copy(c.password), _pulse_copy_button(b)
                )
            )
        row.addWidget(btn_login)

        if machine.connection_type == "RDP":
            btn_connect = QPushButton("RDP")
            btn_connect.setFixedSize(34, 28)
            btn_connect.setToolTip(
                f"Połącz przez Remote Desktop (port {machine.rdp_port or '3389'})"
            )
            btn_connect.setStyleSheet(
                "QPushButton { background: #2a1a35; color: #c084fc; border: 1px solid #6b3fa0;"
                " border-radius: 4px; font-size: 11px; font-weight: bold; padding: 0; }"
                "QPushButton:hover { background: #7c3aed; color: #fff; border-color: #c084fc; }"
            )
            btn_connect.clicked.connect(
                lambda _, m=machine: connect_rdp(m, self, self._admin_unlocked))
        elif machine.connection_type == "WWW":
            btn_connect = QPushButton()
            set_icon(btn_connect, "globe", "#3fb950", active="#7ee787")
            btn_connect.setFixedSize(34, 28)
            btn_connect.setToolTip(
                f"Otwórz w przeglądarce: {machine.www_url or machine.ip}"
            )
            btn_connect.setStyleSheet(
                "QPushButton { background: #1a2a1a; color: #3fb950; border: 1px solid #2d5a2d;"
                " border-radius: 4px; font-size: 15px; padding: 0; }"
                "QPushButton:hover { background: #2d5a2d; color: #7ee787; border-color: #3fb950; }"
            )
            btn_connect.clicked.connect(lambda _, m=machine: self._open_www(m))
        else:
            btn_connect = QPushButton()
            set_icon(btn_connect, "connect", "#58a6ff", active="#ffffff")
            btn_connect.setFixedSize(34, 28)
            btn_connect.setToolTip("Połącz — otwórz terminal SSH i przeglądarkę SFTP")
            btn_connect.setStyleSheet(
                "QPushButton { background: #0f2535; color: #58a6ff; border: 1px solid #1f4a70;"
                " border-radius: 4px; font-size: 15px; padding: 0; }"
                "QPushButton:hover { background: #1f6feb; color: #fff; border-color: #58a6ff; }"
            )
            btn_connect.clicked.connect(lambda _, m=machine: self._open_ssh(m))
        row.addWidget(btn_connect)

        btn_edit = QPushButton()
        set_icon(btn_edit, "gear", "#6e9a6e", active="#8ae234", size=15)
        btn_edit.setFixedSize(28, 28)
        btn_edit.setToolTip("Edytuj maszynę")
        btn_edit.setStyleSheet(
            "QPushButton { background: #1a2a1a; color: #6e9a6e; border: 1px solid #2d4d2d;"
            " border-radius: 4px; font-size: 14px; padding: 0; }"
            "QPushButton:hover { background: #2a3d2a; color: #8ae234; }"
        )
        btn_edit.clicked.connect(lambda _, m=machine: self._edit_machine(m))
        row.addWidget(btn_edit)

        btn_del = QPushButton()
        set_icon(btn_del, "trash", "#c0392b", active="#e74c3c", size=14)
        btn_del.setFixedSize(28, 28)
        btn_del.setToolTip("Usuń maszynę")
        btn_del.setStyleSheet(
            "QPushButton { background: #2a1515; color: #c0392b; border: 1px solid #5a2020;"
            " border-radius: 4px; font-size: 18px; font-weight: bold; padding: 0; }"
            "QPushButton:hover { background: #3d1a1a; color: #e74c3c; }"
        )
        btn_del.clicked.connect(lambda _, m=machine: self._delete_machine(m))
        row.addWidget(btn_del)
        row.addStretch()

        return w

    # ------------------------------------------------------------------ #
    # Databases                                                            #
    # ------------------------------------------------------------------ #

    def _refresh_databases(self):
        self._db_table.setRowCount(0)
        visible = self._visible_databases()
        h = self.current_hospital
        hidden = h is not None and len(h.databases) > len(visible)
        self._db_table.empty_hint = (
            "Bazy tego szpitala są ukryte — odblokuj tryb admina." if hidden
            else "Brak baz danych — dodaj pierwszą przyciskiem „+ Dodaj bazę danych”.")
        self._db_table.viewport().update()
        for i, db in enumerate(visible):
            self._db_table.insertRow(i)
            texts = [db.host, db.port, db.name, db.db_type, db.note]
            for col, text in enumerate(texts):
                item = QTableWidgetItem(text)
                if db.admin_only:
                    item.setForeground(QBrush(QColor(theme.paint("#c084fc"))))
                self._db_table.setItem(i, col, item)
            self._db_table.setCellWidget(i, _DB_AKCJE_COL, self._db_actions(db))

            self._db_table.setRowHeight(i, 36)
        self._update_badge()

    def _db_actions(self, db: models.Database) -> QWidget:
        w = QWidget()
        row = QHBoxLayout(w)
        row.setContentsMargins(4, 2, 4, 2)
        row.setSpacing(3)

        vis_creds = self._visible_credentials(db.credentials)
        first_db_cred = vis_creds[0] if vis_creds else None
        db_login_text = (first_db_cred.login[:10] + "…"
                         if first_db_cred and len(first_db_cred.login) > 10
                         else (first_db_cred.login if first_db_cred else "—"))

        _cred_btn_style = (
            "QPushButton { background: #1e2733; color: #8b949e; border: 1px solid #30363d;"
            " border-radius: 4px; padding: 2px 4px; font-size: 10px; }"
            "QPushButton:hover { background: #263040; color: #c9d1d9; }"
            "QPushButton:disabled { color: #444; background: #161b22; border-color: #21262d; }"
        )

        btn_login = QPushButton(db_login_text)
        if first_db_cred:
            set_icon(btn_login, "key", "#d29922", size=12)
        btn_login.setEnabled(first_db_cred is not None)
        btn_login.setFixedHeight(28)
        # Fixed, not maximum: a short login (or "—") made the button narrower
        # and pushed the action buttons out of line row by row.
        btn_login.setFixedWidth(_LOGIN_BTN_W)
        btn_login.setToolTip(
            f"Kliknij: kopiuj hasło ({first_db_cred.login})\n"
            "Prawy klik: login i inne konta" if first_db_cred
            else "Brak poświadczeń"
        )
        self._attach_row_menu(btn_login, db, 'database')
        btn_login.setStyleSheet(_cred_btn_style)
        if first_db_cred:
            btn_login.clicked.connect(
                lambda _, c=first_db_cred, b=btn_login: (
                    _clipboard_copy(c.password), _pulse_copy_button(b)
                )
            )
        row.addWidget(btn_login)

        btn_edit = QPushButton()
        set_icon(btn_edit, "gear", "#6e9a6e", active="#8ae234", size=15)
        btn_edit.setFixedSize(28, 28)
        btn_edit.setToolTip("Edytuj bazę danych")
        btn_edit.setStyleSheet(
            "QPushButton { background: #1a2a1a; color: #6e9a6e; border: 1px solid #2d4d2d;"
            " border-radius: 4px; font-size: 14px; padding: 0; }"
            "QPushButton:hover { background: #2a3d2a; color: #8ae234; }"
        )
        btn_edit.clicked.connect(lambda _, d=db: self._edit_database(d))
        row.addWidget(btn_edit)

        btn_del = QPushButton()
        set_icon(btn_del, "trash", "#c0392b", active="#e74c3c", size=14)
        btn_del.setFixedSize(28, 28)
        btn_del.setToolTip("Usuń bazę danych")
        btn_del.setStyleSheet(
            "QPushButton { background: #2a1515; color: #c0392b; border: 1px solid #5a2020;"
            " border-radius: 4px; font-size: 18px; font-weight: bold; padding: 0; }"
            "QPushButton:hover { background: #3d1a1a; color: #e74c3c; }"
        )
        btn_del.clicked.connect(lambda _, d=db: self._delete_database(d))
        row.addWidget(btn_del)
        row.addStretch()

        return w

    # ------------------------------------------------------------------ #
    # Hospital actions (rename / delete handled by MainWindow context menu) #
    # ------------------------------------------------------------------ #

    def rename_hospital(self):
        """Called externally (MainWindow right-click menu)."""
        if not self.current_hospital:
            return
        dlg = HospitalDialog(self, self.current_hospital.name)
        if dlg.exec():
            self.current_hospital.name = dlg.get_name()
            self.data_changed.emit()
            self._refresh()

    def delete_hospital(self):
        """Called externally (MainWindow right-click menu)."""
        if not self.current_hospital or self._all_hospitals is None:
            return
        h = self.current_hospital
        creds = (sum(len(m.credentials) for m in h.machines)
                 + sum(len(d.credentials) for d in h.databases))
        if confirm(
            self,
            "Usuń szpital",
            f"Usunąć szpital '{h.name}'?\n\n"
            f"Zostaną usunięte: "
            f"{plural(len(h.machines), 'maszyna', 'maszyny', 'maszyn')}, "
            f"{plural(len(h.databases), 'baza', 'bazy', 'baz')} i "
            f"{plural(creds, 'poświadczenie', 'poświadczenia', 'poświadczeń')}.",
            yes="Usuń szpital", no="Anuluj",
        ):
            self._all_hospitals.remove(self.current_hospital)
            self.current_hospital = None
            self.data_changed.emit()
            self.show_hospital(None, None)

    def _on_notes_changed(self):
        if self.current_hospital:
            self.current_hospital.notes = self._notes_edit.toPlainText()
            self.data_changed.emit()

    # ------------------------------------------------------------------ #
    # Machine actions                                                      #
    # ------------------------------------------------------------------ #

    def _quick_ssh(self):
        from ui.ssh_panel import _AddSessionDialog
        dlg = _AddSessionDialog(parent=self)
        if not dlg.exec():
            return
        ip, login, password, port = dlg.get_values()
        cred = models.Credential(login=login, password=password)
        machine = models.Machine(ip=ip, name="", description="", credentials=[cred])
        machine._ssh_port = port
        ssh_dlg = SshDialog(machine, hospital=self.current_hospital,
                            all_hospitals=self._all_hospitals,
                            admin_unlocked=self._admin_unlocked, parent=self)
        if load_ssh_start_maximized():
            ssh_dlg.showMaximized()
        else:
            ssh_dlg.show()

    def _open_ssh(self, machine: models.Machine):
        # Another machine of the same hospital joins the SSH window already
        # open for it as a new tab, not a window of its own.
        open_dlg = SshDialog.window_for(self.window(), self.current_hospital)
        if open_dlg is not None:
            open_dlg.open_machine(machine)
            return
        dlg = SshDialog(machine, hospital=self.current_hospital,
                        all_hospitals=self._all_hospitals,
                        admin_unlocked=self._admin_unlocked, parent=self)
        if load_ssh_start_maximized():
            dlg.showMaximized()
        else:
            dlg.show()

    def _open_www(self, machine: models.Machine):
        from PyQt6.QtGui import QDesktopServices
        from PyQt6.QtCore import QUrl
        url = machine.www_url or f"https://{machine.ip}"
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        QDesktopServices.openUrl(QUrl(url))

    def _add_machine(self):
        if not self.current_hospital:
            return
        dlg = MachineDialog(self, admin_mode=self._admin_unlocked)
        if dlg.exec():
            self.current_hospital.machines.append(dlg.get_machine())
            self.data_changed.emit()
            self._refresh_machines()

    def _edit_machine(self, machine: models.Machine):
        dlg = MachineDialog(self, machine, admin_mode=self._admin_unlocked)
        if dlg.exec():
            updated = dlg.get_machine()
            # Replace the whole object instead of copying field-by-field.
            # The dialog deep-copies the machine and preserves its id, so
            # the list element keeps the same identity for the vault, and
            # we can never again silently drop a field (this was the
            # www_url-not-persisted bug for WWW machines).
            machines = self.current_hospital.machines
            try:
                idx = machines.index(machine)
            except ValueError:
                idx = -1
            if idx >= 0:
                machines[idx] = updated
            self.data_changed.emit()
            self._refresh_machines()

    def _delete_machine(self, machine: models.Machine):
        if confirm(
            self,
            "Usuń maszynę",
            f"Usunąć maszynę '{machine.ip}'?\n"
            "Poświadczenia tej maszyny zostaną usunięte.",
        ):
            self.current_hospital.machines.remove(machine)
            self.data_changed.emit()
            self._refresh_machines()

    def _duplicate_machine(self, machine: models.Machine):
        dup = copy.deepcopy(machine)
        dup.id = str(models.uuid.uuid4())
        for c in dup.credentials:
            c.id = str(models.uuid.uuid4())
        dlg = MachineDialog(self, machine=dup, admin_mode=self._admin_unlocked)
        if dlg.exec():
            idx = self.current_hospital.machines.index(machine)
            self.current_hospital.machines.insert(idx + 1, dlg.get_machine())
            self.data_changed.emit()
            self._refresh_machines()

    def _on_machine_context_menu(self, pos):
        item = self._machines_table.itemAt(pos)
        if not item:
            return
        row = item.row()
        visible = self._visible_machines()
        if row < 0 or row >= len(visible):
            return
        machine = visible[row]

        menu = QMenu(self)
        menu.addAction(icon("copy", "#c9d1d9"), "Duplikuj",
                       lambda: self._duplicate_machine(machine))
        menu.exec(self._machines_table.viewport().mapToGlobal(pos))

    # ------------------------------------------------------------------ #
    # Database actions                                                     #
    # ------------------------------------------------------------------ #

    def _add_database(self):
        if not self.current_hospital:
            return
        dlg = DatabaseDialog(self, admin_mode=self._admin_unlocked)
        if dlg.exec():
            self.current_hospital.databases.append(dlg.get_database())
            self.data_changed.emit()
            self._refresh_databases()

    def _edit_database(self, db: models.Database):
        dlg = DatabaseDialog(self, db, admin_mode=self._admin_unlocked)
        if dlg.exec():
            updated = dlg.get_database()
            db.host = updated.host
            db.port = updated.port
            db.name = updated.name
            db.db_type = updated.db_type
            db.credentials = updated.credentials
            db.note = updated.note
            db.admin_only = updated.admin_only
            self.data_changed.emit()
            self._refresh_databases()

    def _delete_database(self, db: models.Database):
        if confirm(
            self,
            "Usuń bazę danych",
            f"Usunąć bazę '{db.name}' na hoście '{db.host}'?",
        ):
            self.current_hospital.databases.remove(db)
            self.data_changed.emit()
            self._refresh_databases()

    # ------------------------------------------------------------------ #
    # VPN integration                                                      #
    # ------------------------------------------------------------------ #

    # ------------------------------------------------------------------ #
    # AMMS                                                                 #
    # ------------------------------------------------------------------ #

    _AMMS_STYLE = (
        "QToolButton {{ background: transparent; border: 1px solid {border};"
        " border-radius: 5px; color: {color}; font-size: 10px; font-weight: bold; }}"
        "QToolButton:hover {{ background: #21262d; border-color: #58a6ff; color: #58a6ff; }}"
        "QToolButton:pressed {{ background: #1a3a5c; }}"
    )

    def _update_amms_btn(self):
        h = self.current_hospital
        if self._amms_worker is not None:
            self._amms_btn.setStyleSheet(self._AMMS_STYLE.format(
                border="#1f6feb", color="#58a6ff"))
            self._amms_btn.setToolTip("AMMS: logowanie w toku…")
        elif h and h.amms_url:
            self._amms_btn.setStyleSheet(self._AMMS_STYLE.format(
                border="#30363d", color="#8b949e"))
            who = f" jako {h.amms_login}" if h.amms_login else ""
            self._amms_btn.setToolTip(
                f"Otwórz AMMS i zaloguj{who}: {h.amms_url}"
                "\nPrawy przycisk: edycja")
        else:
            self._amms_btn.setStyleSheet(self._AMMS_STYLE.format(
                border="#21262d", color="#484f58"))
            self._amms_btn.setToolTip(
                "AMMS nie skonfigurowany — kliknij albo prawy przycisk → Edytuj")

    def _on_amms_menu(self, pos):
        h = self.current_hospital
        if not h:
            return
        menu = QMenu(self)
        menu.addAction("Edytuj AMMS…", self._edit_amms)
        if h.amms_password:
            # Same copy as a machine's password: kept out of the Win+V
            # history, cleared after 15 s.
            menu.addAction("Kopiuj hasło", lambda: _clipboard_copy(h.amms_password))
        if h.amms_url:
            menu.addAction("Otwórz bez logowania",
                           lambda: self._start_amms(with_login=False))
        menu.exec(self._amms_btn.mapToGlobal(pos))

    def _edit_amms(self):
        h = self.current_hospital
        if not h:
            return
        from ui.amms import AmmsDialog
        dlg = AmmsDialog(self, h)
        if dlg.exec():
            values = dlg.values()
            if values != (h.amms_url, h.amms_login, h.amms_password):
                h.amms_url, h.amms_login, h.amms_password = values
                self.data_changed.emit()
            amms_changed()

    def _on_amms_btn_clicked(self):
        h = self.current_hospital
        if not h:
            return
        if not h.amms_url:
            self._edit_amms()
            return
        self._start_amms(with_login=True)

    def _start_amms(self, with_login: bool):
        h = self.current_hospital
        if not h or not h.amms_url or self._amms_worker is not None:
            return
        from ui.amms import AmmsWorker
        login = h.amms_login if with_login else ""
        password = h.amms_password if with_login else ""
        worker = AmmsWorker(h.amms_url, login, password, parent=self)
        worker.progress.connect(lambda text: self._show_amms_status(text, "#58a6ff"))
        worker.done.connect(self._on_amms_done)
        worker.finished.connect(worker.deleteLater)
        self._amms_worker = worker
        self._update_amms_btn()
        worker.start()

    def _show_amms_status(self, text: str, color: str, hide_after_ms: int = 0):
        self._amms_hide_timer.stop()
        self._amms_status_lbl.setText(text)
        self._amms_status_lbl.setStyleSheet(f"color: {color}; font-size: 11px;")
        self._amms_status_lbl.setToolTip(text)
        self._amms_status_lbl.setVisible(True)
        if hide_after_ms:
            self._amms_hide_timer.start(hide_after_ms)

    def _on_amms_done(self, outcome: str, detail: str):
        from ui.amms import outcome_text
        self._amms_worker = None
        text, color = outcome_text(outcome)
        if outcome == "rejected" and detail:
            text = f"{text}: {detail}"
        self._show_amms_status(text, color, hide_after_ms=10000)
        if detail:
            self._amms_status_lbl.setToolTip(detail)
        self._update_amms_btn()

    def _vpn_profile_for_current(self):
        """Return matching VPN profile for current hospital (by name, case-insensitive), or None."""
        profiles = _session_vpn_profiles()
        if not self.current_hospital or not profiles:
            return None
        name = self.current_hospital.name.strip().lower()
        for p in profiles:
            if p.name.strip().lower() == name:
                return p
        return None

    def _poll_vpn_status(self):
        """Periodically refresh VPN button to reflect real connection state.

        In a thread (D-07); skipped while the window is hidden in the tray —
        nobody sees the button — and while the previous probe still runs."""
        if not _vpn_available():
            return
        if not self.isVisible():
            return
        profile = self._vpn_profile_for_current()
        if not profile:
            return
        probe = getattr(self, '_vpn_status_probe', None)
        try:
            if probe is not None and probe.isRunning():
                return
        except RuntimeError:
            pass
        probe = _VpnStatusProbe(_vpn_status_key(profile), profile.provider,
                                profile.app_path, profile.profile_name, self,
                                sole=_sole_vpn_profile(profile))
        probe.result.connect(self._on_vpn_status)
        # One probe every 2 s: each must be freed when done (review 69/N2).
        probe.finished.connect(probe.deleteLater)
        self._vpn_status_probe = probe
        probe.start()

    def _on_vpn_status(self, key, status):
        if status is None:
            return  # query failed — keep previous state, don't flicker
        profile = self._vpn_profile_for_current()
        if not profile or _vpn_status_key(profile) != key:
            return  # the hospital changed while the probe ran
        if (key, status) != self._vpn_last_status:
            self._vpn_last_status = (key, status)
            self._update_vpn_btn(status)

    def _update_vpn_btn(self, status=None):
        """Update VPN button colour based on matching profile connection status.

        `status` comes from the status probe.  Without it the last answer for
        *this* profile is used and a fresh probe is asked for — the UI thread
        no longer queries the VPN client itself (D-07)."""
        profile = self._vpn_profile_for_current()
        if not _vpn_available():
            # Not loaded yet — neutral grey
            self._vpn_btn.setStyleSheet(
                "QToolButton { background: transparent; border: 1px solid #30363d;"
                " border-radius: 5px; color: #8b949e; font-size: 10px; font-weight: bold; }"
                "QToolButton:hover { background: #21262d; border-color: #58a6ff; color: #58a6ff; }"
            )
            self._vpn_btn.setToolTip("Połącz przez VPN (wskaż swój VPN vault przy pierwszym kliknięciu)")
            return
        if not profile:
            self._vpn_btn.setStyleSheet(
                "QToolButton { background: transparent; border: 1px solid #21262d;"
                " border-radius: 5px; color: #484f58; font-size: 10px; font-weight: bold; }"
                "QToolButton:hover { background: #161b22; border-color: #30363d; color: #6e7681; }"
            )
            self._vpn_btn.setToolTip("Brak profilu VPN dla tego szpitala")
            return
        # Profile found — status from the probe, or the last one for it
        if status is None:
            cached = self._vpn_last_status
            key = _vpn_status_key(profile)
            status = cached[1] if isinstance(cached, tuple) and cached[0] == key else None
            QTimer.singleShot(0, self._poll_vpn_status)
        if status == "Connected":
            self._vpn_btn.setStyleSheet(
                "QToolButton { background: rgba(35,134,54,0.15); border: 1px solid #238636;"
                " border-radius: 5px; color: #3fb950; font-size: 10px; font-weight: bold; }"
                "QToolButton:hover { background: rgba(35,134,54,0.25); border-color: #2ea043; }"
            )
            self._vpn_btn.setToolTip(f"VPN połączono: {profile.name}  ·  kliknij aby rozłączyć")
        elif status and "Connecting" in status:
            self._vpn_btn.setStyleSheet(
                "QToolButton { background: rgba(210,153,34,0.15); border: 1px solid #d29922;"
                " border-radius: 5px; color: #d29922; font-size: 10px; font-weight: bold; }"
                "QToolButton:hover { background: rgba(210,153,34,0.25); }"
            )
            self._vpn_btn.setToolTip(f"VPN łączy: {profile.name}...")
        else:
            self._vpn_btn.setStyleSheet(
                "QToolButton { background: transparent; border: 1px solid #30363d;"
                " border-radius: 5px; color: #8b949e; font-size: 10px; font-weight: bold; }"
                "QToolButton:hover { background: #21262d; border-color: #238636; color: #3fb950; }"
            )
            self._vpn_btn.setToolTip(f"Połącz VPN: {profile.name}  ({profile.provider})")

    def _load_vpn_vault(self) -> bool:
        """Show unlock dialog, load VPN profiles into session cache. Returns True on success."""
        global _vpn_session_profiles, _vpn_session_loaded
        dlg = _VpnUnlockDialog(self)
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return False
        vault_path = dlg.vault_path()
        password = dlg.password()
        if not vault_path or not os.path.exists(vault_path):
            QMessageBox.warning(self, "VPN vault", "Nie znaleziono pliku vault.")
            return False
        try:
            with open(vault_path, "rb") as f:
                raw = f.read()
            data = decrypt(raw, password)
            profiles = models.vpn_from_dict(data)
        except Exception as e:
            QMessageBox.critical(self, "VPN vault", f"Nie można otworzyć vaulta:\n{e}")
            return False
        save_personal_vpn_vault(vault_path)
        _vpn_session_profiles = profiles
        _vpn_session_loaded = True
        return True

    def _on_vpn_btn_clicked(self):
        if not _vpn_available():
            if not self._load_vpn_vault():
                return
            self._update_vpn_btn()
            return  # only load vault, don't auto-connect

        profile = self._vpn_profile_for_current()
        if not profile:
            QMessageBox.information(
                self, "VPN",
                f"Brak profilu VPN o nazwie \"{self.current_hospital.name}\".\n"
                "Dodaj profil w sekcji VPN z taką samą nazwą jak szpital."
            )
            return

        # Toggle: disconnect if connected, connect if not
        from ui import vpn_panel as _vp
        status = _vp.vpn_status(profile.provider, profile.app_path, profile.profile_name,
                                sole=_sole_vpn_profile(profile))
        if status == "Connected":
            vpn_connect.disconnect(profile.provider, profile.server, profile.app_path, profile.profile_name)
            self._update_vpn_btn()
            return

        # FortiClient, Stormshield, Barracuda: the same V2 connect as the VPN
        # card (2026-10-20, owner: "po co to rozbijać").  Everything else, and
        # every disarmed provider, keeps the legacy path below.
        autofill = load_vpn_autofill_enabled()
        from ui import vpn_panel as _vp
        if profile.provider and profile.provider not in models.VPN_PROVIDERS_BUILTIN:
            # A custom provider (AnyDesk…): open the program, say what happened.
            _vp.open_custom_program(self, profile, self._vpn_status_lbl, autofill)
            QTimer.singleShot(20000, lambda: self._vpn_status_lbl.setVisible(False))
            return
        if _vp.select_connect_route(profile.provider) != _vp.ROUTE_LEGACY:
            self._connect_vpn_v2(profile, autofill)
            return

        # Connect first (without token — FortiClient will show Token field in GUI)
        ok, msg, process = vpn_connect.connect_monitored(
            profile.provider, profile.server, profile.port,
            profile.login, profile.password,
            profile.group, profile.domain,
            _vp.resolve_client_path(profile), profile.profile_name, "",
            autofill=autofill,
        )
        if not ok:
            QMessageBox.warning(self, "VPN", msg)
            return

        self._update_vpn_btn()

        # 2FA handling is automation — skip entirely when user opted out of autofill.
        if not autofill:
            return

        # If 2FA required — wait for FortiClient Token window, ask user, fill in
        if profile.requires_2fa and profile.provider == "FortiClient":
            from PyQt6.QtCore import QThread
            from ui.vpn_panel import TwoFactorDialog

            class _TokenWindowWaiter(QThread):
                """Wait for FortiClient token window in background thread."""
                from PyQt6.QtCore import pyqtSignal as Signal
                found = Signal()

                def run(self):
                    # _find_forti_auth_window zwraca KROTKĘ (hwnd, edits,
                    # buttons) — rozpakowanie jest konieczne, bo sama krotka
                    # jest zawsze prawdziwa (także „(None, [], [])”), więc
                    # „if hwnd:” na nierozpakowanym wyniku otwierałoby okno
                    # kodu 2FA nawet wtedy, gdy okno FortiClienta się nie
                    # pojawiło.
                    hwnd, _edits, _buttons = vpn_connect._find_forti_auth_window(
                        timeout=20.0)
                    if hwnd:
                        self.found.emit()

            def _on_token_window_found():
                dlg = TwoFactorDialog(profile.name, self)
                if dlg.exec() == QDialog.DialogCode.Accepted:
                    ok2, msg2 = vpn_connect.fill_forticlient_token(dlg.code())
                    if not ok2:
                        QMessageBox.warning(self, "VPN Token", msg2)
                self._update_vpn_btn()

            running = getattr(self, '_vpn_token_waiter', None)
            try:
                busy = running is not None and running.isRunning()
            except RuntimeError:
                busy = False
            if busy:
                # Already waiting for this token window: a second waiter
                # would open a second 2FA dialog (D-01).
                return
            waiter = _TokenWindowWaiter(self)
            waiter.found.connect(_on_token_window_found)
            waiter.start()
            self._vpn_token_waiter = waiter  # keep reference

        # Auto-detect 2FA via stdout if process available (non-GUI fallback)
        elif process is not None and not profile.requires_2fa:
            from ui.vpn_panel import VpnMonitorWorker, TwoFactorDialog
            old = getattr(self, '_vpn_monitor_worker', None)
            if old is not None:
                # Replaced while still reading the previous client's output:
                # hand it over rather than leave it a running child (69/N5).
                retire_thread(old, disconnect=(old.twofa_detected,))
            worker = VpnMonitorWorker(0, process, self)
            worker.twofa_detected.connect(lambda _: self._handle_auto_2fa(worker, profile))
            worker.start()
            self._vpn_monitor_worker = worker  # keep reference

    def _connect_vpn_v2(self, profile, autofill: bool) -> None:
        """Run the V2 connect the VPN card runs, reporting next to the button.

        The same pieces as ``VpnPanel._connect_card_v2``: the request and the
        session from the bridge, the controller with its Cancel button, the
        session recorded for the status poll, and the missing-profile
        explanation.  One connect at a time from this window.
        """
        from ui import vpn_panel as _vp
        running = self._vpn_v2_controller
        if running is not None and getattr(running, "active", False):
            return
        app_path = _vp.resolve_client_path(profile)
        _vp._record_legacy_session(profile)
        lbl = self._vpn_status_lbl
        try:
            request = _vp.build_request(profile, app_path=app_path,
                                        autofill=autofill)
            session = _vp.PanelConnectSession(request)
            controller = _vp.V2ConnectController(
                session, lbl, prompt_parent=self, client=profile.provider)
            self._vpn_v2_controller = controller
            controller.finished.connect(
                lambda outcome, p=profile, c=controller:
                    self._on_vpn_v2_finished(p, outcome, c))
            header = self._vpn_header
            header.insertWidget(header.indexOf(self._vpn_btn), controller.prompt)
            lbl.setVisible(True)
            self._update_vpn_btn("Connecting")
            controller.start()
        except Exception as exc:
            _vp._vlog("error", "Połącz (V2, okno szpitala) — błąd uruchomienia",
                      profile, error=f"{type(exc).__name__}: {exc}")
            lbl.setText("Błąd połączenia V2")
            lbl.setVisible(True)
            self._vpn_v2_controller = None
            self._update_vpn_btn()

    def _on_vpn_v2_finished(self, profile, outcome, controller) -> None:
        from ui import vpn_panel as _vp
        started = bool(getattr(outcome, "started", False))
        _vp._vlog("info" if started else "warn", "Połącz (V2, okno szpitala) — wynik",
                  profile, started=started,
                  state=str(getattr(outcome, "state", "") or ""),
                  reason_code=str(getattr(outcome, "code", "") or ""),
                  error_code=str(getattr(outcome, "error_code", "") or ""))
        if str(getattr(outcome, "reason", "") or "") in _vp._TUNNEL_MISSING_REASONS:
            _vp.explain_missing_tunnel(self, profile)
        if started:
            vpn_connect.invalidate_adapter_cache()
        self._vpn_last_status = None
        QTimer.singleShot(2000, self._update_vpn_btn)
        # The sentence stays readable for a while, then the line goes away.
        QTimer.singleShot(20000, lambda c=controller: self._hide_vpn_v2_status(c))

    def _hide_vpn_v2_status(self, controller) -> None:
        try:
            if self._vpn_v2_controller is controller:
                self._vpn_status_lbl.setVisible(False)
                self._vpn_v2_controller = None
        except RuntimeError:
            pass

    def _handle_auto_2fa(self, worker, profile):
        from ui.vpn_panel import TwoFactorDialog
        dlg = TwoFactorDialog(profile.name, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            worker.send_token(dlg.code())
