"""The "Rejestr HL7" window of HospitalHub Portable (owner, 2026-11-19): the
packages of one AMMS order, as the old wymdMonitor showed them — time,
direction, type, sender → receivers, status, SI or WymD, the
acknowledgement — with the message itself split into segments and fields.

Search by the order (``ID_OBIEKTU``) or by one package (``GIDK_PACZKI``,
its order is found first).  The patient search (PESEL / MIP) comes later.
Read only: hl7_registry runs SELECTs in a read-only transaction.

The database is one of the hospital's databases in the vault (host, port,
service name, the first visible login); the choice is kept in
``Hospital.si["hl7_db"]``.
"""

from __future__ import annotations

import datetime as _dt

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QFont, QKeySequence, QShortcut, QTextOption
from PyQt6.QtWidgets import (
    QApplication, QComboBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit,
    QMenu, QPlainTextEdit, QPushButton, QSplitter, QTabWidget, QTreeWidget,
    QTreeWidgetItem, QVBoxLayout, QWidget,
)

import hl7_fields
import hl7_parser
import hl7_registry as hr

__all__ = ["Hl7RegistryWindow"]

_QSS = (
    "QWidget#hl7Root { background:#0f1117; }"
    "QLabel { color:#c9d1d9; }"
    "QLineEdit, QComboBox { background:#14161e; border:1px solid #2a2d3a;"
    " border-radius:6px; padding:4px 6px; color:#c9d1d9; }"
    "QLineEdit:focus, QComboBox:focus { border-color:#4a5adf; }"
    "QPushButton { background:#1a2040; color:#a5b4ff; border:1px solid #3a4070;"
    " border-radius:6px; padding:5px 12px; }"
    "QPushButton:hover { background:#4a5adf; color:#fff; }"
    "QPushButton:disabled { color:#5a5f72; }"
    "QPlainTextEdit { background:#0d1117; border:1px solid #2a2d3a;"
    " border-radius:6px; color:#c9d1d9; }"
    "QTabWidget::pane { border:none; }"
    "QTabBar::tab { background:#14161e; color:#8b949e; padding:5px 12px;"
    " border:1px solid #2a2d3a; border-bottom:none; border-top-left-radius:6px;"
    " border-top-right-radius:6px; }"
    "QTabBar::tab:selected { background:#1a1d28; color:#e1e4eb; }"
    "QMenu { background:#1a1d28; color:#e1e4eb; border:1px solid #2a2d3a; }"
    "QMenu::item:selected { background:#4a5adf; }"
)

# Owner, 2026-11-19: GIDK first, the time 4th — and which time it is: a
# package has four (DT_GENER, DT_WYSLANIA, DT_ODBIORU, DT_PRZETW).
# The owner's own arrangement (2026-11-19 screenshot): what fits a narrow
# list first, the times and the rest further right.
COLUMNS = ["GIDK", "Kier.", "Status", "Typ", "Wygenerowana", "Wysłana",
           "Odebrana", "Przetworzona", "Nadawca → odbiorca", "Kanał", "Obiekt",
           "Potwierdzenie"]
COL = {name: i for i, name in enumerate(COLUMNS)}
_TIME_TIPS = {
    "Wygenerowana": "DT_GENER — kiedy paczka powstała",
    "Wysłana": "DT_WYSLANIA — kiedy wyszła do odbiorcy",
    "Odebrana": "DT_ODBIORU — kiedy przyszła do AMMS",
    "Przetworzona": "DT_PRZETW — kiedy AMMS ją przetworzył",
}

_STATUS_COLOR = {"B": "#f85149", "N": "#d29922", "W": "#3fb950",
                 "P": "#3fb950", "O": "#58a6ff"}


def fmt_time(v) -> str:
    if isinstance(v, _dt.datetime):
        return v.strftime("%d.%m %H:%M:%S")
    return "" if v is None else str(v)


def ack_text(p: hr.Package) -> str:
    if p.acks:
        a = p.acks[0]
        return f"ACK {fmt_time(a.dt_gener)}" + (f" (+{len(p.acks) - 1})"
                                                  if len(p.acks) > 1 else "")
    bits = [b for b in (p.ack_status, p.ack_code) if b]
    return " ".join(bits) if bits else "—"


def db_label(d) -> str:
    """``10.20.30.40:1521 · SID amms01 · Oracle`` — not the whole JDBC URL."""
    t = hr.parse_target(d.host, d.port, d.name)
    if t["descriptor"]:
        where = "deskryptor TNS"
    else:
        where = f"{t['host']}:{t['port']} · " + (f"SID {t['sid']}" if t["sid"]
                                                 else t["service"])
    return where + (f" · {d.db_type}" if d.db_type else "")


class _Job(QThread):
    """One database job off the UI thread."""
    result = pyqtSignal(object)
    failed = pyqtSignal(str)

    def __init__(self, fn):
        super().__init__()
        self._fn = fn

    def run(self):
        try:
            self.result.emit(self._fn())
        except Exception as e:  # noqa: BLE001 — shown to the user
            self.failed.emit(str(e) or type(e).__name__)


class Hl7RegistryWindow(QWidget):
    data_changed = pyqtSignal()

    def __init__(self, hospital=None, admin_unlocked: bool = False,
                 parent=None, connect_fn=None):
        super().__init__(parent, Qt.WindowType.Window)
        self.setObjectName("hl7Root")
        self.setWindowTitle("Rejestr HL7")
        self.setAttribute(Qt.WidgetAttribute.WA_StyledBackground, True)
        self.setStyleSheet(_QSS)
        self.resize(1400, 800)
        self._hospital = None
        self._admin_unlocked = admin_unlocked
        self._connect_fn = connect_fn or hr.connect
        self._conn = None
        self._conn_key = None
        self._job: _Job | None = None
        self._packages: list = []
        self._content: dict[str, dict] = {}
        self._loading = False

        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        row = QHBoxLayout()
        row.addWidget(QLabel("Baza AMMS:"))
        self._db = QComboBox()
        self._db.setMinimumWidth(260)
        self._db.currentIndexChanged.connect(self._db_changed)
        row.addWidget(self._db)
        row.addSpacing(12)
        self._mode = QComboBox()
        self._mode.addItem("Zlecenie (ID_OBIEKTU)", "order")
        self._mode.addItem("Paczka (GIDK_PACZKI)", "package")
        row.addWidget(self._mode)
        self._value = QLineEdit()
        self._value.setPlaceholderText("np. 76764524")
        self._value.setClearButtonEnabled(True)
        self._value.returnPressed.connect(self.search)
        row.addWidget(self._value, 1)
        self._search_btn = QPushButton("Szukaj")
        self._search_btn.clicked.connect(self.search)
        row.addWidget(self._search_btn)
        root.addLayout(row)

        self._info = QLabel("Wpisz ID zlecenia i Enter. Tylko odczyt "
                            "(SELECT w transakcji read only).")
        self._info.setStyleSheet("color:#8b949e;")
        root.addWidget(self._info)

        split = QSplitter(Qt.Orientation.Horizontal)
        split.setChildrenCollapsible(False)

        self._tree = QTreeWidget()
        self._tree.setColumnCount(len(COLUMNS))
        self._tree.setHeaderLabels(COLUMNS)
        self._tree.setUniformRowHeights(True)
        self._tree.setAlternatingRowColors(False)
        h = self._tree.header()
        h.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for i, w in enumerate((135, 75, 55, 75, 105, 105, 105, 105, 165,
                               50, 70, 110)):
            self._tree.setColumnWidth(i, w)
        hdr = self._tree.headerItem()
        for name, tip in _TIME_TIPS.items():
            hdr.setToolTip(COL[name], tip)
        self._tree.header().setSectionsMovable(True)
        self._tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._tree.customContextMenuRequested.connect(self._menu)
        self._tree.currentItemChanged.connect(self._show_current)
        split.addWidget(self._tree)

        right = QWidget()
        rl = QVBoxLayout(right)
        rl.setContentsMargins(0, 0, 0, 0)
        rl.setSpacing(6)
        self._head = QLabel("")
        self._head.setWordWrap(True)
        self._head.setTextInteractionFlags(
            Qt.TextInteractionFlag.TextSelectableByMouse)
        rl.addWidget(self._head)
        self._tabs = QTabWidget()
        self._segs = QTreeWidget()
        self._segs.setColumnCount(3)
        self._segs.setHeaderLabels(["Pole", "Nazwa", "Wartość"])
        self._segs.setColumnWidth(0, 105)
        self._segs.setColumnWidth(1, 190)
        # Copying (owner, 2026-11-19): Ctrl+C / double click = the value;
        # the menu also gives "PID.3 = 98265" and the whole segment.
        self._segs.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._segs.customContextMenuRequested.connect(self._segs_menu)
        self._segs.itemDoubleClicked.connect(
            lambda it, _c: self._copy_text(self._seg_value(it)))
        QShortcut(QKeySequence.StandardKey.Copy, self._segs,
                  activated=lambda: self._copy_text(
                      self._seg_value(self._segs.currentItem())),
                  context=Qt.ShortcutContext.WidgetShortcut)
        self._raw = QPlainTextEdit()
        self._raw.setReadOnly(True)
        # Wrapped to the window (owner, 2026-11-19); HL7 lines have no spaces
        # to break at, so anywhere — at a word boundary when there is one.
        self._raw.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        self._raw.setWordWrapMode(QTextOption.WrapMode.WrapAtWordBoundaryOrAnywhere)
        f = QFont("Consolas")
        f.setStyleHint(QFont.StyleHint.Monospace)
        f.setPointSize(9)
        self._raw.setFont(f)
        # The raw message first and shown at once (owner, 2026-11-19).
        self._tabs.addTab(self._raw, "Surowa treść")
        self._tabs.addTab(self._segs, "Segmenty")
        self._tabs.setCurrentWidget(self._raw)
        rl.addWidget(self._tabs, 1)
        btns = QHBoxLayout()
        self._copy_btn = QPushButton("Kopiuj treść")
        self._copy_btn.clicked.connect(self._copy_content)
        btns.addWidget(self._copy_btn)
        self._ack_btn = QPushButton("Pokaż ACK")
        self._ack_btn.clicked.connect(lambda: self.show_ack(self._current_package()))
        btns.addWidget(self._ack_btn)
        btns.addStretch(1)
        rl.addLayout(btns)
        split.addWidget(right)
        # A narrow list (GIDK, Kier., Status, Typ) and the message wide.
        split.setStretchFactor(0, 0)
        split.setStretchFactor(1, 1)
        split.setSizes([380, 1020])
        root.addWidget(split, 1)

        QShortcut(QKeySequence("Ctrl+F"), self, activated=self._value.setFocus)

        if hospital is not None:
            self.set_hospital(hospital)
        self._update_buttons()

    # ── Settings ──────────────────────────────────────────────────────────

    def _databases(self) -> list:
        h = self._hospital
        if h is None:
            return []
        dbs = [d for d in h.databases
               if self._admin_unlocked or not d.admin_only]
        # Oracle first: AMMS lives there.
        return sorted(dbs, key=lambda d: (d.db_type != "Oracle",))

    def set_hospital(self, hospital) -> None:
        self._hospital = hospital
        self._close_conn()
        self._fill_dbs()

    def set_admin_mode(self, unlocked: bool) -> None:
        self._admin_unlocked = unlocked
        self._fill_dbs()

    def _fill_dbs(self) -> None:
        si = getattr(self._hospital, "si", None) or {}
        wanted = si.get("hl7_db") or self._db.currentData() or ""
        self._loading = True
        self._db.clear()
        for d in self._databases():
            label = db_label(d)
            self._db.addItem(label, d.id)
        if self._db.count() == 0:
            self._db.addItem("— brak baz w vaulcie (dodaj w Maszyny) —", "")
        i = self._db.findData(wanted) if wanted else -1
        self._db.setCurrentIndex(i if i >= 0 else 0)
        self._loading = False
        self._update_buttons()

    def current_db(self):
        did = self._db.currentData()
        for d in self._databases():
            if d.id == did:
                return d
        return None

    def _db_changed(self, *_):
        if self._loading:
            return
        self._close_conn()
        h = self._hospital
        did = self._db.currentData() or ""
        if h is not None and did:
            si = dict(getattr(h, "si", None) or {})
            if si.get("hl7_db") != did:
                si["hl7_db"] = did
                h.si = si
                self.data_changed.emit()
        self._update_buttons()

    # ── Connection ────────────────────────────────────────────────────────

    def _close_conn(self) -> None:
        c, self._conn, self._conn_key = self._conn, None, None
        if c is not None:
            try:
                c.close()
            except Exception:
                pass

    def _connection(self):
        """Called in the job thread: the open connection or a new one."""
        d = self.current_db()
        if d is None:
            raise RuntimeError("Wybierz bazę AMMS.")
        creds = [c for c in d.credentials
                 if self._admin_unlocked or not c.admin_only]
        if not creds or not creds[0].login:
            raise RuntimeError("Baza nie ma w vaulcie loginu — dodaj go w "
                               "zakładce Maszyny.")
        key = (d.id, d.host, d.port, d.name, creds[0].login)
        if self._conn is not None and self._conn_key == key:
            return self._conn
        self._close_conn()
        self._conn = self._connect_fn(d.host, d.port or 1521, d.name,
                                      creds[0].login, creds[0].password)
        self._conn_key = key
        return self._conn

    def _run(self, fn, on_result, busy_text: str | None) -> None:
        if self._job is not None:
            return
        if busy_text:
            self._info.setText(busy_text)
        job = _Job(fn)
        job.result.connect(on_result)
        job.failed.connect(self._failed)
        job.finished.connect(self._job_done)
        self._job = job
        self._update_buttons()
        job.start()

    def _job_done(self) -> None:
        j, self._job = self._job, None
        if j is not None:
            j.deleteLater()
        self._update_buttons()
        # The package chosen while another job ran: its content now.
        p = self._current_package()
        if (p is not None and p.gidk not in self._content
                and self._raw.toPlainText() == "Wczytywanie treści…"):
            self._show_package(p)

    def _failed(self, msg: str) -> None:
        if "ORA-" in msg or "DPY-" in msg:
            # A broken connection is not reused.
            self._close_conn()
        self._info.setText(f"Błąd: {msg}")

    def busy(self) -> bool:
        return self._job is not None

    def _update_buttons(self) -> None:
        idle = self._job is None
        self._search_btn.setEnabled(idle and self.current_db() is not None)
        p = self._current_package()
        self._copy_btn.setEnabled(idle and p is not None)
        self._ack_btn.setEnabled(p is not None and not p.is_ack)

    # ── Search ────────────────────────────────────────────────────────────

    def search(self) -> None:
        value = self._value.text().strip()
        if not value or self._job is not None:
            return
        mode = self._mode.currentData()
        self._run(lambda: hr.find_chain(self._connection(), mode, value),
                  self._found, f"Szukam {value}…")

    def _found(self, result) -> None:
        order_id, pkgs = result
        self._packages = pkgs
        self._content.clear()
        self._fill_tree()
        if not pkgs:
            self._info.setText("Nic nie znaleziono." if not order_id else
                               f"Zlecenie {order_id}: brak paczek.")
            return
        acks = sum(len(p.acks) for p in pkgs)
        bad = sum(1 for p in pkgs if p.status.upper() == "B")
        self._info.setText(
            f"Zlecenie {order_id}: paczek {len(pkgs)}, ACK {acks}"
            + (f", błędnych {bad}" if bad else "")
            + (f" — pokazano pierwsze {hr.MAX_ROWS}"
               if len(pkgs) >= hr.MAX_ROWS else ""))
        self._tree.setCurrentItem(self._tree.topLevelItem(0))

    def _item(self, p: hr.Package) -> QTreeWidgetItem:
        if p.outgoing is True:
            arrow = "→ wych."
        elif p.outgoing is False:
            arrow = "← przych."
        else:
            arrow = ""
        who = p.sender + (f" → {p.receivers}" if p.receivers else "")
        obj = "/".join(p.kinds)
        values = {
            "GIDK": p.gidk, "Kier.": arrow, "Typ": p.msg_type,
            "Wygenerowana": fmt_time(p.dt_gener),
            "Wysłana": fmt_time(p.dt_sent),
            "Odebrana": fmt_time(p.dt_received),
            "Przetworzona": fmt_time(p.dt_processed),
            "Nadawca → odbiorca": who, "Status": p.status,
            "Kanał": "SI" if p.via_si else (p.via or "WymD"),
            "Obiekt": obj, "Potwierdzenie": ack_text(p)}
        it = QTreeWidgetItem([values[c] for c in COLUMNS])
        it.setData(0, Qt.ItemDataRole.UserRole, p)
        st = COL["Status"]
        if p.is_ack:
            for c in range(len(COLUMNS)):
                it.setForeground(c, QBrush(QColor("#8b949e")))
        color = _STATUS_COLOR.get(p.status.upper())
        if color:
            it.setForeground(st, QBrush(QColor(color)))
        # The letter only (owner: "my to będziemy rozpoznawać"), the word in
        # the bubble.
        it.setTextAlignment(st, Qt.AlignmentFlag.AlignCenter)
        it.setToolTip(st, hr.status_words(p))
        for name in _TIME_TIPS:
            it.setToolTip(COL[name], _TIME_TIPS[name])
        tip = [f"GIDK: {p.gidk}",
               f"Wygenerowana: {fmt_time(p.dt_gener)}",
               f"Wysłana: {fmt_time(p.dt_sent)}",
               f"Odebrana: {fmt_time(p.dt_received)}",
               f"Przetworzona: {fmt_time(p.dt_processed)}"]
        if p.ack_info:
            tip.append(f"Potwierdzenie: {p.ack_info}")
        it.setToolTip(0, "\n".join(tip))
        return it

    def _fill_tree(self) -> None:
        self._tree.clear()
        for p in self._packages:
            it = self._item(p)
            for a in p.acks:
                it.addChild(self._item(a))
            self._tree.addTopLevelItem(it)
            # Closed under its package; the arrow (or "Pokaż ACK") opens it
            # (owner, 2026-11-19).
            it.setExpanded(False)
        self._show_package(None)

    # ── One package ───────────────────────────────────────────────────────

    def _current_package(self):
        it = self._tree.currentItem()
        return it.data(0, Qt.ItemDataRole.UserRole) if it else None

    def _show_current(self, *_):
        self._show_package(self._current_package())
        self._update_buttons()

    def _show_package(self, p) -> None:
        self._segs.clear()
        self._raw.clear()
        if p is None:
            self._head.setText("")
            return
        lines = [f"<b>{p.msg_type or 'paczka'}</b> &nbsp; {p.gidk}"
                 f" &nbsp; <span style='color:#8b949e'>{hr.status_words(p)}</span>",
                 "<span style='color:#8b949e'>wygen. "
                 f"{fmt_time(p.dt_gener)} · wysł. {fmt_time(p.dt_sent) or '—'}"
                 f" · odebr. {fmt_time(p.dt_received) or '—'} · przetw. "
                 f"{fmt_time(p.dt_processed) or '—'}</span>"]
        if p.ack_for:
            lines.append(f"<span style='color:#8b949e'>potwierdza paczkę "
                         f"{p.ack_for}</span>")
        self._head.setText("<br>".join(lines))
        got = self._content.get(p.gidk)
        if got is not None:
            self._show_content(p.gidk, got)
            return
        self._raw.setPlainText("Wczytywanie treści…")
        gidk = p.gidk
        self._run(lambda: (gidk, hr.fetch_content(self._connection(), gidk)),
                  self._content_loaded, None)

    def _content_loaded(self, result) -> None:
        gidk, content = result
        self._content[gidk] = content
        p = self._current_package()
        if p is not None and p.gidk == gidk:
            self._show_content(gidk, content)
        elif p is not None and p.gidk not in self._content:
            self._show_package(p)

    def _show_content(self, gidk: str, c: dict) -> None:
        text = c.get("text", "")
        if not c.get("found"):
            self._raw.setPlainText("Brak paczki w bazie.")
            return
        if not text:
            where = c.get("file") or c.get("external_file")
            self._raw.setPlainText("Pusta treść w bazie"
                                   + (f" — plik: {c.get('folder', '')}/{where}"
                                      if where else "."))
            return
        shown = text.replace("\r\n", "\n").replace("\r", "\n")
        if c.get("url_decoded"):
            # AMMS stores TRESC URL-encoded (%0D between segments): shown
            # decoded, the "Kopiuj treść" copies the decoded message too.
            self._raw.setToolTip("W bazie treść jest zakodowana (%0D, %C5%82…) "
                                 "— pokazano zdekodowaną")
        if c.get("compression"):
            shown = (f"[R_KOMPR_TRESCI = {c['compression']}: treść może być "
                     f"skompresowana]\n\n") + shown
        self._raw.setPlainText(shown)
        self._fill_segments(text)

    def _fill_segments(self, text: str) -> None:
        self._segs.clear()
        msg = hl7_parser.parse(text)
        for seg in msg.segments:
            top = QTreeWidgetItem([seg.name, hl7_fields.get_segment_name(seg.name),
                                   ""])
            top.setToolTip(1, hl7_fields.get_segment_description(seg.name))
            f = top.font(0)
            f.setBold(True)
            top.setFont(0, f)
            for fld in seg.fields:
                if not fld.raw or (seg.name == "MSH" and fld.index <= 2):
                    continue
                info = hl7_fields.get_field_info(seg.name, fld.index)
                ch = QTreeWidgetItem([f"{seg.name}.{fld.index}",
                                      info[0] if info else "", fld.raw])
                if info:
                    ch.setToolTip(1, info[1])
                ch.setToolTip(2, fld.raw)
                top.addChild(ch)
            # The whole segment line, for "Kopiuj cały segment".
            top.setData(0, Qt.ItemDataRole.UserRole, seg.raw)
            self._segs.addTopLevelItem(top)
            top.setExpanded(True)

    # ── Copying from "Segmenty" ───────────────────────────────────────────

    @staticmethod
    def _seg_value(it) -> str:
        """A field row → its value; a segment row → the whole segment."""
        if it is None:
            return ""
        if it.parent() is None:
            return it.data(0, Qt.ItemDataRole.UserRole) or ""
        return it.text(2)

    def _copy_text(self, text: str) -> None:
        if not text:
            return
        QApplication.clipboard().setText(text)
        shown = text if len(text) <= 60 else text[:57] + "…"
        self._info.setText(f"Skopiowano: {shown}")

    def _segs_menu(self, pos) -> None:
        it = self._segs.itemAt(pos)
        if it is None:
            return
        self._segs.setCurrentItem(it)
        menu = QMenu(self)
        if it.parent() is not None:
            menu.addAction("Kopiuj wartość",
                           lambda: self._copy_text(it.text(2)))
            menu.addAction(f"Kopiuj „{it.text(0)} = …”",
                           lambda: self._copy_text(f"{it.text(0)} = {it.text(2)}"))
            seg = it.parent()
        else:
            seg = it
        menu.addAction(f"Kopiuj cały segment {seg.text(0)}",
                       lambda: self._copy_text(self._seg_value(seg)))
        menu.exec(self._segs.viewport().mapToGlobal(pos))

    # ── Actions ───────────────────────────────────────────────────────────

    def show_ack(self, p) -> None:
        if p is None:
            return
        if p.acks:
            for i in range(self._tree.topLevelItemCount()):
                it = self._tree.topLevelItem(i)
                if it.data(0, Qt.ItemDataRole.UserRole) is p:
                    it.setExpanded(True)
                    self._tree.setCurrentItem(it.child(0))
                    return
        bits = [b for b in (p.ack_status, p.ack_code, p.ack_info) if b]
        self._info.setText(f"Paczka {p.gidk}: brak ACK w rejestrze"
                           + (f" — potwierdzenie obiektu: {' '.join(bits)}"
                              if bits else "."))

    def _copy_content(self) -> None:
        p = self._current_package()
        c = self._content.get(p.gidk) if p else None
        if c and c.get("text"):
            QApplication.clipboard().setText(c["text"].replace("\r", "\n"))
            self._info.setText(f"Treść paczki {p.gidk} skopiowana.")

    def _menu(self, pos) -> None:
        it = self._tree.itemAt(pos)
        p = it.data(0, Qt.ItemDataRole.UserRole) if it else None
        if p is None:
            return
        self._tree.setCurrentItem(it)
        menu = QMenu(self)
        if not p.is_ack:
            menu.addAction("Pokaż ACK", lambda: self.show_ack(p))
        menu.addAction("Kopiuj treść", self._copy_content)
        menu.addAction("Kopiuj GIDK",
                       lambda: QApplication.clipboard().setText(p.gidk))
        menu.exec(self._tree.viewport().mapToGlobal(pos))

    def closeEvent(self, event):
        j = self._job
        if j is not None:
            j.wait(3000)
        self._close_conn()
        super().closeEvent(event)
