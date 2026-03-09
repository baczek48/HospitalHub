from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton,
    QTableWidget, QTableWidgetItem, QHeaderView, QAbstractItemView,
    QTextEdit, QGroupBox, QFrame, QScrollArea, QMessageBox, QApplication,
    QSplitter, QMenu,
)
from PyQt6.QtCore import Qt, pyqtSignal, QPoint, QTimer, QObject, QEvent
from PyQt6.QtGui import QFont, QBrush, QColor


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
from ui.dialogs import HospitalDialog, MachineDialog, DatabaseDialog, _clipboard_copy
from ui.utils import confirm
from ui.ssh_panel import SshDialog
from ui.rdp import connect_rdp
from ui.db_connect import connect_db
from config import load_column_widths, save_column_widths

# stretch_col: fills remaining space, pins Akcje to right edge
# akcje_col: always ResizeToContents, not saved
_MACHINES_STRETCH_COL = 2   # Opis
_MACHINES_AKCJE_COL = 3
_MACHINES_DEFAULTS = [120, 140, 180]   # widths for cols 0,1 (col 2 stretches)
_MACHINES_AKCJE_WIDTH = 290

_DB_STRETCH_COL = 4         # Notatka (ostatnia kolumna danych, jak Opis w maszynach)
_DB_AKCJE_COL = 5
_DB_DEFAULTS = [180, 60, 130, 80]      # widths for cols 0,1,2,3
_DB_AKCJE_WIDTH = 260


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

    # Build list of interactive column indices (all except stretch and akcje)
    interactive_cols = [
        i for i in range(table.columnCount()) if i != stretch_col and i != akcje_col
    ]
    widths = saved if (saved and len(saved) == len(interactive_cols)) else defaults

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


class DetailPanel(QWidget):
    data_changed = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.current_hospital: models.Hospital = None
        self._all_hospitals: list = None
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

        # Decorative stats badge — shows machine + DB count at a glance
        self._stats_badge = QLabel()
        self._stats_badge.setStyleSheet(
            "color: #58a6ff; font-size: 10px;"
            " background: #0d1117; border: 1px solid #21262d; border-radius: 10px;"
            " padding: 3px 12px; letter-spacing: 0.5px;"
        )
        header.addWidget(self._stats_badge)

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
        self._machines_table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
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
        self._db_table.setSelectionMode(QAbstractItemView.SelectionMode.NoSelection)
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
        self._fit_columns(self._machines_table, [0, 1], _MACHINES_AKCJE_COL)
        self._fit_columns(self._db_table, [0, 1, 2, 3], _DB_AKCJE_COL)

    def _fit_columns(self, table: QTableWidget, interactive_cols: list, akcje_col: int):
        """Scale interactive columns proportionally so they never overflow the viewport."""
        vp_width = table.viewport().width()
        if vp_width <= 0:
            return
        akcje_w = table.columnWidth(akcje_col)
        min_stretch = 30  # keep at least a sliver for the stretch column
        available = vp_width - akcje_w - min_stretch
        if available <= 0:
            return
        total = sum(table.columnWidth(c) for c in interactive_cols)
        if total > available:
            scale = available / total
            for col in interactive_cols:
                new_w = max(28, int(table.columnWidth(col) * scale))
                table.setColumnWidth(col, new_w)

    # ------------------------------------------------------------------ #

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
        if col == 3:
            return
        item = self._machines_table.item(row, col)
        if item and item.text():
            self._flash_cell(self._machines_table, row, col)
            QApplication.clipboard().setText(item.text())

    def _on_db_cell_clicked(self, row: int, col: int):
        self._db_table.clearSelection()
        self._db_table.setCurrentIndex(
            self._db_table.model().index(-1, -1))
        if col == _DB_AKCJE_COL:
            return
        item = self._db_table.item(row, col)
        if item and item.text():
            self._flash_cell(self._db_table, row, col)
            QApplication.clipboard().setText(item.text())

    def _on_machines_reordered(self, from_row: int, to_row: int):
        if not self.current_hospital:
            return
        lst = self.current_hospital.machines
        lst.insert(to_row, lst.pop(from_row))
        self._refresh_machines()
        self.data_changed.emit()

    def _on_db_reordered(self, from_row: int, to_row: int):
        if not self.current_hospital:
            return
        lst = self.current_hospital.databases
        lst.insert(to_row, lst.pop(from_row))
        self._refresh_databases()
        self.data_changed.emit()

    # ------------------------------------------------------------------ #
    # Machines                                                             #
    # ------------------------------------------------------------------ #

    def _update_badge(self):
        if not self.current_hospital:
            return
        h = self.current_hospital
        m  = len(h.machines)
        db = len(h.databases)
        ms  = 'maszyna' if m  == 1 else 'maszyny' if 2 <= m  <= 4 else 'maszyn'
        dbs = 'baza'    if db == 1 else 'bazy'    if 2 <= db <= 4 else 'baz'
        self._stats_badge.setText(f"🖥  {m} {ms}   ·   🗄  {db} {dbs}")

    def _refresh_machines(self):
        self._machines_table.setRowCount(0)
        for i, machine in enumerate(self.current_hospital.machines):
            self._machines_table.insertRow(i)

            ip_item = QTableWidgetItem(machine.ip)
            ip_item.setToolTip("Kliknij aby skopiować")
            ip_item.setForeground(self._machines_table.palette().highlight().color())
            self._machines_table.setItem(i, 0, ip_item)

            for col, text in [(1, machine.name), (2, machine.description)]:
                item = QTableWidgetItem(text)
                item.setToolTip("Kliknij aby skopiować")
                self._machines_table.setItem(i, col, item)

            self._machines_table.setCellWidget(i, 3, self._machine_actions(machine))
            self._machines_table.setRowHeight(i, 36)
        self._update_badge()

    def _machine_actions(self, machine: models.Machine) -> QWidget:
        w = QWidget()
        row = QHBoxLayout(w)
        row.setContentsMargins(4, 2, 4, 2)
        row.setSpacing(3)

        first_cred = machine.credentials[0] if machine.credentials else None
        login_text = (first_cred.login[:10] + "…" if first_cred and len(first_cred.login) > 10
                      else (first_cred.login if first_cred else "—"))
        btn_copy = QPushButton(login_text)
        btn_copy.setEnabled(first_cred is not None)
        btn_copy.setFixedHeight(28)
        btn_copy.setMaximumWidth(90)
        btn_copy.setToolTip(
            f"Kopiuj hasło użytkownika: {first_cred.login}" if first_cred
            else "Brak poświadczeń"
        )
        btn_copy.setStyleSheet(
            "QPushButton { background: #1e2733; color: #8b949e; border: 1px solid #30363d;"
            " border-radius: 4px; padding: 2px 4px; font-size: 10px; }"
            "QPushButton:hover { background: #263040; color: #c9d1d9; }"
            "QPushButton:disabled { color: #444; background: #161b22; border-color: #21262d; }"
        )
        if first_cred:
            btn_copy.clicked.connect(
                lambda _, c=first_cred: _clipboard_copy(c.password)
            )
        row.addWidget(btn_copy)

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
            btn_connect.clicked.connect(lambda _, m=machine: connect_rdp(m, self))
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
        for i, db in enumerate(self.current_hospital.databases):
            self._db_table.insertRow(i)
            for col, text in enumerate([db.host, db.port, db.name, db.db_type, db.note]):
                item = QTableWidgetItem(text)
                item.setToolTip("Kliknij aby skopiować")
                self._db_table.setItem(i, col, item)
            self._db_table.setCellWidget(i, _DB_AKCJE_COL, self._db_actions(db))
            self._db_table.setRowHeight(i, 36)
        self._update_badge()

    def _db_actions(self, db: models.Database) -> QWidget:
        w = QWidget()
        row = QHBoxLayout(w)
        row.setContentsMargins(4, 2, 4, 2)
        row.setSpacing(3)

        first_db_cred = db.credentials[0] if db.credentials else None
        db_login_text = (first_db_cred.login[:10] + "…"
                         if first_db_cred and len(first_db_cred.login) > 10
                         else (first_db_cred.login if first_db_cred else "—"))
        btn_copy = QPushButton(db_login_text)
        btn_copy.setEnabled(first_db_cred is not None)
        btn_copy.setFixedHeight(28)
        btn_copy.setMaximumWidth(90)
        btn_copy.setToolTip(
            f"Kopiuj hasło użytkownika: {first_db_cred.login}" if first_db_cred
            else "Brak poświadczeń"
        )
        btn_copy.setStyleSheet(
            "QPushButton { background: #1e2733; color: #8b949e; border: 1px solid #30363d;"
            " border-radius: 4px; padding: 2px 4px; font-size: 10px; }"
            "QPushButton:hover { background: #263040; color: #c9d1d9; }"
            "QPushButton:disabled { color: #444; background: #161b22; border-color: #21262d; }"
        )
        if first_db_cred:
            btn_copy.clicked.connect(
                lambda _, c=first_db_cred: _clipboard_copy(c.password)
            )
        row.addWidget(btn_copy)

        btn_sql = QPushButton("SQL")
        btn_sql.setFixedSize(38, 28)
        btn_sql.setToolTip("Połącz — otwórz SQL Developer z danymi tej bazy")
        btn_sql.setStyleSheet(
            "QPushButton { background: #1a1a0a; color: #f0a500; border: 1px solid #7a5200;"
            " border-radius: 4px; font-size: 10px; font-weight: bold; padding: 0; }"
            "QPushButton:hover { background: #c47d00; color: #fff; border-color: #f0a500; }"
        )
        btn_sql.clicked.connect(lambda _, d=db: connect_db(d, self))
        row.addWidget(btn_sql)

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

    def _open_ssh(self, machine: models.Machine):
        dlg = SshDialog(machine, hospital=self.current_hospital, parent=self)
        dlg.show()

    def _add_machine(self):
        if not self.current_hospital:
            return
        dlg = MachineDialog(self)
        if dlg.exec():
            self.current_hospital.machines.append(dlg.get_machine())
            self.data_changed.emit()
            self._refresh_machines()

    def _edit_machine(self, machine: models.Machine):
        dlg = MachineDialog(self, machine)
        if dlg.exec():
            updated = dlg.get_machine()
            machine.ip = updated.ip
            machine.name = updated.name
            machine.description = updated.description
            machine.credentials = updated.credentials
            machine.connection_type = updated.connection_type
            machine.rdp_port = updated.rdp_port
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

    # ------------------------------------------------------------------ #
    # Database actions                                                     #
    # ------------------------------------------------------------------ #

    def _add_database(self):
        if not self.current_hospital:
            return
        dlg = DatabaseDialog(self)
        if dlg.exec():
            self.current_hospital.databases.append(dlg.get_database())
            self.data_changed.emit()
            self._refresh_databases()

    def _edit_database(self, db: models.Database):
        dlg = DatabaseDialog(self, db)
        if dlg.exec():
            updated = dlg.get_database()
            db.host = updated.host
            db.port = updated.port
            db.name = updated.name
            db.db_type = updated.db_type
            db.credentials = updated.credentials
            db.note = updated.note
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
