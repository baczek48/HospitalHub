import copy

from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QToolButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QTextEdit, QGroupBox, QFrame, QScrollArea, QMessageBox, QApplication,
    QSplitter, QMenu, QDialog, QDialogButtonBox, QFileDialog, QLineEdit,
)
from PyQt6.QtCore import Qt, pyqtSignal, QPoint, QTimer, QObject, QEvent, QSize
from PyQt6.QtGui import QFont, QBrush, QColor, QIcon, QPixmap, QPainter, QPainterPath, QPen


def _make_db_connect_icon(size: int = 24) -> QIcon:
    """3 stacked database discs with a green play triangle — SQL launcher icon."""
    px = QPixmap(size, size)
    px.fill(Qt.GlobalColor.transparent)
    p = QPainter(px)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)

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

    p.end()
    return QIcon(px)


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


class _DraggableTable(QTableWidget):
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

    def dropEvent(self, event):
        from_row = self.currentRow()
        idx = self.indexAt(event.position().toPoint())
        to_row = idx.row() if idx.isValid() else self.rowCount() - 1
        if from_row >= 0 and to_row >= 0 and from_row != to_row:
            self.rows_reordered.emit(from_row, to_row)
        event.ignore()  # block Qt's own item shuffling

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import models
import vpn_connect
from crypto import decrypt
from ui.dialogs import HospitalDialog, MachineDialog, DatabaseDialog, _clipboard_copy
from ui.utils import confirm
from ui.ssh_panel import SshDialog
from ui.rdp import connect_rdp
from ui.db_connect import launch_sqldeveloper
from config import (load_column_widths, save_column_widths,
                    load_personal_vpn_vault, save_personal_vpn_vault,
                    load_vpn_autofill_enabled,
                    load_ssh_start_maximized)

# Session-level VPN profile cache (loaded once per app session)
_vpn_session_profiles: list = []
_vpn_session_loaded: bool = False

# stretch_col: fills remaining space, pins Akcje to right edge
# akcje_col: always ResizeToContents, not saved
_MACHINES_STRETCH_COL = 2   # Opis
_MACHINES_AKCJE_COL = 3
_MACHINES_DEFAULTS = [120, 140, 180]   # widths for cols 0,1 (col 2 stretches)
_MACHINES_AKCJE_WIDTH = 322

_DB_STRETCH_COL = 4         # Notatka (ostatnia kolumna danych, jak Opis w maszynach)
_DB_AKCJE_COL = 5
_DB_DEFAULTS = [180, 60, 130, 80]      # widths for cols 0,1,2,3
_DB_AKCJE_WIDTH = 252


def _setup_table_columns(
    table: QTableWidget,
    key: str,
    defaults: list,
    stretch_col: int,
    akcje_col: int,
    akcje_width: int = 220,
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

    hh.setMinimumSectionSize(80)
    for idx, col in enumerate(interactive_cols):
        hh.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
        table.setColumnWidth(col, widths[idx])

    hh.setSectionResizeMode(stretch_col, QHeaderView.ResizeMode.Stretch)
    hh.setSectionResizeMode(akcje_col, QHeaderView.ResizeMode.Fixed)
    table.setColumnWidth(akcje_col, akcje_width)

    # Install an event filter that intercepts ContextMenu events on the header.
    # IMPORTANT: horizontalHeader() returns ephemeral Python wrappers — storing on
    # hh would lose the reference when that wrapper is GC'd.  Store on `table`
    # instead, which is a stable Python object held by the DetailPanel instance.
    table._header_ctx_menu_filter = _HeaderMenuFilter(
        hh,
        lambda: save_column_widths(key, [table.columnWidth(c) for c in interactive_cols]),
    )


class _VpnUnlockDialog(QDialog):
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
        self._name_label = QLabel()
        font = QFont()
        font.setPointSize(15)
        font.setBold(True)
        self._name_label.setFont(font)
        header.addWidget(self._name_label)
        header.addStretch()

        # Admin mode badge — visible only when unlocked
        self._admin_badge = QLabel("🔓 TRYB ADMINA")
        self._admin_badge.setStyleSheet(
            "color: #8ae234; font-size: 10px; font-weight: bold;"
            " background: #1a3a1a; border: 1px solid #2d5a1a; border-radius: 10px;"
            " padding: 3px 12px; letter-spacing: 0.5px;"
        )
        self._admin_badge.setVisible(False)
        header.addWidget(self._admin_badge)

        # Decorative stats badge — shows machine + DB count at a glance
        self._stats_badge = QLabel()
        self._stats_badge.setStyleSheet(
            "color: #58a6ff; font-size: 10px;"
            " background: #0d1117; border: 1px solid #21262d; border-radius: 10px;"
            " padding: 3px 12px; letter-spacing: 0.5px;"
        )
        header.addWidget(self._stats_badge)

        btn_quick_ssh = QToolButton()
        btn_quick_ssh.setText("⇆")
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
        header.addWidget(self._vpn_btn)

        # Poll VPN status every 2s to keep button state in sync
        self._vpn_last_status = None  # cache last known status to avoid flicker
        self._vpn_poll_timer = QTimer(self)
        self._vpn_poll_timer.setInterval(2000)
        self._vpn_poll_timer.timeout.connect(self._poll_vpn_status)
        self._vpn_poll_timer.start()

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
        self._machines_table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._machines_table.customContextMenuRequested.connect(self._on_machine_context_menu)
        self._machines_table.cellClicked.connect(self._on_machine_cell_clicked)
        self._machines_table.rows_reordered.connect(self._on_machines_reordered)
        _setup_table_columns(
            self._machines_table, "machines", _MACHINES_DEFAULTS,
            stretch_col=_MACHINES_STRETCH_COL, akcje_col=_MACHINES_AKCJE_COL,
            akcje_width=_MACHINES_AKCJE_WIDTH,
        )
        machines_layout.addWidget(self._machines_table)

        btn_add_machine = QPushButton("＋  Dodaj maszynę")
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
        _setup_table_columns(
            self._db_table, "databases", _DB_DEFAULTS,
            stretch_col=_DB_STRETCH_COL, akcje_col=_DB_AKCJE_COL,
            akcje_width=_DB_AKCJE_WIDTH,
        )
        db_layout.addWidget(self._db_table)

        btn_add_db = QPushButton("＋  Dodaj bazę danych")
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

    def cleanup(self):
        """Stop timers and workers — call before discarding this panel."""
        if hasattr(self, '_vpn_poll_timer'):
            self._vpn_poll_timer.stop()
        for attr in ('_vpn_token_waiter', '_vpn_monitor_worker'):
            w = getattr(self, attr, None)
            if w and hasattr(w, 'quit'):
                w.quit()
                w.wait(500)

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

    # ------------------------------------------------------------------ #
    # Cell click → copy                                                    #
    # ------------------------------------------------------------------ #

    def _flash_cell(self, table: QTableWidget, row: int, col: int) -> None:
        """Brief press-feedback: dim the cell for 130 ms, then restore."""
        item = table.item(row, col)
        if not item:
            return
        item.setBackground(QBrush(QColor("#1e3a52")))
        orig = QColor("#1c2128") if row % 2 else QColor("#161b22")
        QTimer.singleShot(60, lambda: item.setBackground(QBrush(orig)))

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
        ms  = 'maszyna' if m  == 1 else 'maszyny' if 2 <= m  <= 4 else 'maszyn'
        dbs = 'baza'    if db == 1 else 'bazy'    if 2 <= db <= 4 else 'baz'
        hidden_m = sum(1 for x in self.current_hospital.machines if x.admin_only)
        hidden_d = sum(1 for x in self.current_hospital.databases if x.admin_only)
        hidden = hidden_m + hidden_d
        suffix = ""
        if hidden and not self._admin_unlocked:
            suffix = f"   ·   🔒 {hidden} ukrytych"
        self._stats_badge.setText(f"🖥  {m} {ms}   ·   🗄  {db} {dbs}{suffix}")

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
        for i, machine in enumerate(visible):
            self._machines_table.insertRow(i)

            ip_item = QTableWidgetItem(machine.ip)
            ip_item.setToolTip("Kliknij aby skopiować")
            ip_item.setForeground(self._machines_table.palette().highlight().color())
            self._machines_table.setItem(i, 0, ip_item)

            for col, text in [(1, machine.name), (2, machine.description)]:
                item = QTableWidgetItem(text)
                item.setToolTip("Kliknij aby skopiować")
                if machine.admin_only:
                    item.setForeground(QBrush(QColor("#c084fc")))
                self._machines_table.setItem(i, col, item)

            self._machines_table.setCellWidget(i, _MACHINES_AKCJE_COL, self._machine_actions(machine))

            self._machines_table.setRowHeight(i, 36)
        self._update_badge()

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
        btn_login.setEnabled(first_cred is not None)
        btn_login.setFixedHeight(28)
        btn_login.setMaximumWidth(90)
        btn_login.setToolTip(
            f"Kopiuj hasło: {first_cred.login}" if first_cred
            else "Brak poświadczeń"
        )
        btn_login.setStyleSheet(_cred_btn_style)
        if first_cred:
            btn_login.clicked.connect(
                lambda _, c=first_cred: _clipboard_copy(c.password)
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
            btn_connect = QPushButton("🌐")
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
            btn_connect = QPushButton("⇆")
            btn_connect.setFixedSize(34, 28)
            btn_connect.setToolTip("Połącz — otwórz terminal SSH i przeglądarkę SFTP")
            btn_connect.setStyleSheet(
                "QPushButton { background: #0f2535; color: #58a6ff; border: 1px solid #1f4a70;"
                " border-radius: 4px; font-size: 15px; padding: 0; }"
                "QPushButton:hover { background: #1f6feb; color: #fff; border-color: #58a6ff; }"
            )
            btn_connect.clicked.connect(lambda _, m=machine: self._open_ssh(m))
        row.addWidget(btn_connect)

        btn_edit = QPushButton("⚙")
        btn_edit.setFixedSize(28, 28)
        btn_edit.setToolTip("Edytuj maszynę")
        btn_edit.setStyleSheet(
            "QPushButton { background: #1a2a1a; color: #6e9a6e; border: 1px solid #2d4d2d;"
            " border-radius: 4px; font-size: 14px; padding: 0; }"
            "QPushButton:hover { background: #2a3d2a; color: #8ae234; }"
        )
        btn_edit.clicked.connect(lambda _, m=machine: self._edit_machine(m))
        row.addWidget(btn_edit)

        btn_del = QPushButton("−")
        btn_del.setFixedSize(28, 28)
        btn_del.setToolTip("Usuń maszynę")
        btn_del.setStyleSheet(
            "QPushButton { background: #2a1515; color: #c0392b; border: 1px solid #5a2020;"
            " border-radius: 4px; font-size: 18px; font-weight: bold; padding: 0; }"
            "QPushButton:hover { background: #3d1a1a; color: #e74c3c; }"
        )
        btn_del.clicked.connect(lambda _, m=machine: self._delete_machine(m))
        row.addWidget(btn_del)

        return w

    # ------------------------------------------------------------------ #
    # Databases                                                            #
    # ------------------------------------------------------------------ #

    def _refresh_databases(self):
        self._db_table.setRowCount(0)
        visible = self._visible_databases()
        for i, db in enumerate(visible):
            self._db_table.insertRow(i)
            texts = [db.host, db.port, db.name, db.db_type, db.note]
            for col, text in enumerate(texts):
                item = QTableWidgetItem(text)
                item.setToolTip("Kliknij aby skopiować")
                if db.admin_only:
                    item.setForeground(QBrush(QColor("#c084fc")))
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
        btn_login.setEnabled(first_db_cred is not None)
        btn_login.setFixedHeight(28)
        btn_login.setMaximumWidth(90)
        btn_login.setToolTip(
            f"Kopiuj hasło: {first_db_cred.login}" if first_db_cred
            else "Brak poświadczeń"
        )
        btn_login.setStyleSheet(_cred_btn_style)
        if first_db_cred:
            btn_login.clicked.connect(
                lambda _, c=first_db_cred: _clipboard_copy(c.password)
            )
        row.addWidget(btn_login)

        btn_edit = QPushButton("⚙")
        btn_edit.setFixedSize(28, 28)
        btn_edit.setToolTip("Edytuj bazę danych")
        btn_edit.setStyleSheet(
            "QPushButton { background: #1a2a1a; color: #6e9a6e; border: 1px solid #2d4d2d;"
            " border-radius: 4px; font-size: 14px; padding: 0; }"
            "QPushButton:hover { background: #2a3d2a; color: #8ae234; }"
        )
        btn_edit.clicked.connect(lambda _, d=db: self._edit_database(d))
        row.addWidget(btn_edit)

        btn_del = QPushButton("−")
        btn_del.setFixedSize(28, 28)
        btn_del.setToolTip("Usuń bazę danych")
        btn_del.setStyleSheet(
            "QPushButton { background: #2a1515; color: #c0392b; border: 1px solid #5a2020;"
            " border-radius: 4px; font-size: 18px; font-weight: bold; padding: 0; }"
            "QPushButton:hover { background: #3d1a1a; color: #e74c3c; }"
        )
        btn_del.clicked.connect(lambda _, d=db: self._delete_database(d))
        row.addWidget(btn_del)

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
        if confirm(
            self,
            "Usuń szpital",
            f"Usunąć szpital '{self.current_hospital.name}'?\n"
            "Wszystkie maszyny, bazy i poświadczenia zostaną usunięte.",
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
            machine.ip = updated.ip
            machine.name = updated.name
            machine.description = updated.description
            machine.credentials = updated.credentials
            machine.connection_type = updated.connection_type
            machine.rdp_port = updated.rdp_port
            machine.rdp_drives = updated.rdp_drives
            machine.admin_only = updated.admin_only
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
        menu.addAction("📑  Duplikuj", lambda: self._duplicate_machine(machine))
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

    def _vpn_profile_for_current(self):
        """Return matching VPN profile for current hospital (by name, case-insensitive), or None."""
        if not self.current_hospital or not _vpn_session_profiles:
            return None
        name = self.current_hospital.name.strip().lower()
        for p in _vpn_session_profiles:
            if p.name.strip().lower() == name:
                return p
        return None

    def _poll_vpn_status(self):
        """Periodically refresh VPN button to reflect real connection state."""
        if not _vpn_session_loaded:
            return
        profile = self._vpn_profile_for_current()
        if not profile:
            return
        status = vpn_connect.get_status(profile.provider, profile.app_path, profile.profile_name)
        if status is None:
            return  # query failed — keep previous state, don't flicker
        if status != self._vpn_last_status:
            self._vpn_last_status = status
            self._update_vpn_btn()

    def _update_vpn_btn(self):
        """Update VPN button colour based on matching profile connection status."""
        profile = self._vpn_profile_for_current()
        if not _vpn_session_loaded:
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
        # Profile found — check live status
        status = vpn_connect.get_status(profile.provider, profile.app_path, profile.profile_name)
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
        global _vpn_session_loaded
        if not _vpn_session_loaded:
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
        status = vpn_connect.get_status(profile.provider, profile.app_path, profile.profile_name)
        if status == "Connected":
            vpn_connect.disconnect(profile.provider, profile.server, profile.app_path, profile.profile_name)
            self._update_vpn_btn()
            return

        # Connect first (without token — FortiClient will show Token field in GUI)
        autofill = load_vpn_autofill_enabled()
        ok, msg, process = vpn_connect.connect_monitored(
            profile.provider, profile.server, profile.port,
            profile.login, profile.password,
            profile.group, profile.domain,
            profile.app_path, profile.profile_name, "",
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
                    hwnd = vpn_connect._find_forticlient_token_window(timeout=20.0)
                    if hwnd:
                        self.found.emit()

            def _on_token_window_found():
                dlg = TwoFactorDialog(profile.name, self)
                if dlg.exec() == QDialog.DialogCode.Accepted:
                    ok2, msg2 = vpn_connect.fill_forticlient_token(dlg.code())
                    if not ok2:
                        QMessageBox.warning(self, "VPN Token", msg2)
                self._update_vpn_btn()

            waiter = _TokenWindowWaiter(self)
            waiter.found.connect(_on_token_window_found)
            waiter.start()
            self._vpn_token_waiter = waiter  # keep reference

        # Auto-detect 2FA via stdout if process available (non-GUI fallback)
        elif process is not None and not profile.requires_2fa:
            from ui.vpn_panel import VpnMonitorWorker, TwoFactorDialog
            worker = VpnMonitorWorker(0, process, self)
            worker.twofa_detected.connect(lambda _: self._handle_auto_2fa(worker, profile))
            worker.start()
            self._vpn_monitor_worker = worker  # keep reference

    def _handle_auto_2fa(self, worker, profile):
        from ui.vpn_panel import TwoFactorDialog
        dlg = TwoFactorDialog(profile.name, self)
        if dlg.exec() == QDialog.DialogCode.Accepted:
            worker.send_token(dlg.code())
