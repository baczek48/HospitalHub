"""The machine list of HospitalHub Remote (2026-10-28, owner).

HospitalHub Remote runs on a hospital's own remote machine and opens the
vault exported for that one hospital.  Its window is the SSH window; this
panel takes the place of the "Środowisko" tab there: every machine and
database of the hospital, connected from the list, edited from its menu.

It speaks to the SSH window the way ``_EnvironmentPanel`` does —
``open_machine`` / ``open_machine_cred`` out, ``set_active`` /
``set_admin_mode`` in — and adds ``data_changed`` for the window to save.
RDP, WWW and databases are launched from here; SSH goes to the window.
"""

from __future__ import annotations

import copy

from PyQt6.QtCore import QPoint, QSize, Qt, QTimer, QUrl, pyqtSignal
from PyQt6.QtGui import (
    QColor, QCursor, QDesktopServices, QFont, QFontMetrics, QGuiApplication,
    QPainter,
)
from PyQt6.QtWidgets import (
    QDialog, QDialogButtonBox, QFrame, QHBoxLayout, QLabel, QLineEdit, QMenu,
    QPlainTextEdit, QPushButton, QScrollArea, QToolButton, QVBoxLayout,
    QWidget,
)

import models
from ui import theme
from ui.dialogs import DatabaseDialog, MachineDialog, _clipboard_copy
from ui.icons import icon, set_icon
from ui.utils import confirm

__all__ = ["RemoteMachinesPanel", "machine_matches", "database_matches",
           "www_url"]


_MENU_QSS = (
    "QMenu{background:#1a1d28;color:#e1e4eb;border:1px solid #2a2d3a;"
    "border-radius:10px;padding:6px;}"
    "QMenu::item{padding:6px 18px;border-radius:6px;}"
    "QMenu::item:selected{background:#4a5adf;color:#fff;}"
    "QMenu::item:disabled{color:#5a5f72;}"
    "QMenu::separator{height:1px;background:#2a2d3a;margin:4px 10px;}"
)

_CARD_IDLE = (
    "QFrame#machineCard { background:#1a1d28; border:1px solid #2a2d3a;"
    " border-radius:10px; border-left:3px solid #2a2d3a; }"
    "QFrame#machineCard:hover { background:#1e2233; border-color:#3a3f55;"
    " border-left:3px solid #4a5adf; }"
    "QLabel { border:none; background:transparent; }"
)
_CARD_ACTIVE = (
    "QFrame#machineCard { background:#1c2240; border:1px solid #4a5adf;"
    " border-radius:10px; border-left:3px solid #6382ff; }"
    "QLabel { border:none; background:transparent; }"
)
_CARD_SELECTED = (
    "QFrame#machineCard { background:#1a2830; border:1px solid #2a8a6a;"
    " border-radius:10px; border-left:3px solid #40c090; }"
    "QLabel { border:none; background:transparent; }"
)

#: The badge on a card: text, colour, background, border, hover background.
_BADGES = {
    "SSH": ("SSH", "#6382ff", "#1a2040", "#3a4070", "#4a5adf"),
    "RDP": ("RDP", "#c084fc", "#2a1a40", "#5a3a8a", "#7c3aed"),
    "WWW": ("WWW", "#3fb950", "#1a2a1a", "#2d5a2d", "#2ea043"),
    "DB":  ("DB",  "#e2b340", "#2a2515", "#c9a227", "#d29922"),
}

_BTN_QSS = (
    "QPushButton, QToolButton {{ background:{bg}; color:{fg};"
    " border:1px solid {border}; border-radius:6px; padding:5px 10px;"
    " font-size:11px; }}"
    "QPushButton:hover, QToolButton:hover {{ background:{hover}; color:#fff; }}"
    "QToolButton::menu-indicator {{ width:0; height:0; }}"
)


def machine_matches(machine, text: str) -> bool:
    """Does the search `text` (lower case) find `machine`?"""
    if not text:
        return True
    fields = (machine.ip, machine.name, machine.description, machine.www_url)
    return any(text in (f or "").lower() for f in fields)


def database_matches(db, text: str) -> bool:
    if not text:
        return True
    fields = (db.host, db.name, db.db_type, db.note)
    return any(text in (f or "").lower() for f in fields)


def www_url(machine) -> str:
    """The address a WWW machine opens: its URL, else https://<ip>."""
    url = (machine.www_url or "").strip() or f"https://{machine.ip}"
    if not url.lower().startswith(("http://", "https://")):
        url = "https://" + url
    return url


class _CardLine(QWidget):
    """"IP  name" on one line that fits the card: the name gives way first,
    then the address, each ending in "…" — a long JDBC address pushed the
    connect buttons out of the panel (owner, 2026-10-28)."""

    def __init__(self, main: str, sub: str, main_color: str, sub_color: str,
                 parent=None):
        super().__init__(parent)
        self.main, self.sub = main, sub
        self._main_color, self._sub_color = main_color, sub_color
        font = self.font()
        font.setPointSizeF(max(7.5, font.pointSizeF() - 0.5))
        self.setFont(font)
        self._bold = QFont(font)
        self._bold.setBold(True)

    def _parts(self, width: int) -> tuple[str, str]:
        fm_b, fm = QFontMetrics(self._bold), QFontMetrics(self.font())
        gap = "  " if self.sub else ""
        main_w = fm_b.horizontalAdvance(self.main)
        if main_w >= width:
            return fm_b.elidedText(self.main, Qt.TextElideMode.ElideRight, width), ""
        rest = width - main_w - fm.horizontalAdvance(gap)
        sub = fm.elidedText(self.sub, Qt.TextElideMode.ElideRight, max(rest, 0))
        return self.main, (gap + sub) if sub else ""

    def shown_text(self, width: int | None = None) -> str:
        main, sub = self._parts(self.width() if width is None else width)
        return main + sub

    def sizeHint(self) -> QSize:
        fm_b, fm = QFontMetrics(self._bold), QFontMetrics(self.font())
        w = fm_b.horizontalAdvance(self.main) + fm.horizontalAdvance(
            ("  " + self.sub) if self.sub else "")
        return QSize(w, max(fm_b.height(), fm.height()) + 2)

    def minimumSizeHint(self) -> QSize:
        return QSize(30, self.sizeHint().height())

    def paintEvent(self, _event):
        main, sub = self._parts(self.width())
        p = QPainter(self)
        fm_b = QFontMetrics(self._bold)
        y = (self.height() + fm_b.ascent() - fm_b.descent()) // 2
        p.setFont(self._bold)
        p.setPen(QColor(self._main_color))
        p.drawText(0, y, main)
        if sub:
            p.setFont(self.font())
            p.setPen(QColor(self._sub_color))
            p.drawText(fm_b.horizontalAdvance(main), y, sub)
        p.end()


class _HoverTip(QLabel):
    """The description of the card under the cursor: shown at once, moving
    with the cursor, gone when it leaves the card (owner, 2026-10-28) — the
    standard tooltip came late and stood still."""

    OFFSET = QPoint(16, 18)

    def __init__(self, parent=None):
        super().__init__(parent, Qt.WindowType.ToolTip
                         | Qt.WindowType.FramelessWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setTextFormat(Qt.TextFormat.RichText)
        self.setWordWrap(True)
        self.setMaximumWidth(420)
        self.setStyleSheet(
            "QLabel { background:#1a1d28; color:#e1e4eb; border:1px solid #3a3f55;"
            " border-radius:8px; padding:8px 10px; font-size:11px; }")

    def show_text(self, html: str, at: QPoint) -> None:
        self.setText(html)
        self.adjustSize()
        self.follow(at)
        self.show()
        self.raise_()

    def follow(self, at: QPoint) -> None:
        pos = at + self.OFFSET
        screen = QGuiApplication.screenAt(at)
        if screen is not None:
            area = screen.availableGeometry()
            if pos.x() + self.width() > area.right():
                pos.setX(at.x() - self.width() - 8)
            if pos.y() + self.height() > area.bottom():
                pos.setY(at.y() - self.height() - 8)
            pos.setX(max(pos.x(), area.left()))
            pos.setY(max(pos.y(), area.top()))
        self.move(pos)


class _NotesDialog(QDialog):
    """The hospital's notes, as in the hospital view of HospitalHub."""

    def __init__(self, parent, hospital_name: str, text: str):
        super().__init__(parent)
        self.setWindowTitle(f"Notatki — {hospital_name}" if hospital_name
                            else "Notatki")
        self.resize(560, 420)
        lay = QVBoxLayout(self)
        self._edit = QPlainTextEdit(text)
        self._edit.setStyleSheet(
            "QPlainTextEdit { background:#0d1117; color:#c9d1d9;"
            " border:1px solid #30363d; border-radius:6px; padding:6px; }")
        lay.addWidget(self._edit, 1)
        box = QDialogButtonBox(QDialogButtonBox.StandardButton.Save
                               | QDialogButtonBox.StandardButton.Cancel)
        box.button(QDialogButtonBox.StandardButton.Save).setText("Zapisz")
        box.button(QDialogButtonBox.StandardButton.Cancel).setText("Anuluj")
        box.accepted.connect(self.accept)
        box.rejected.connect(self.reject)
        lay.addWidget(box)

    def text(self) -> str:
        return self._edit.toPlainText()


class RemoteMachinesPanel(QWidget):
    """Machines and databases of one hospital, for HospitalHub Remote."""

    open_machine = pyqtSignal(object)               # SSH, first visible login
    open_machine_cred = pyqtSignal(object, object)  # SSH as this login
    data_changed = pyqtSignal()                     # an edit: save the vault
    hospital_changed = pyqtSignal(object)           # another hospital chosen
    admin_clicked = pyqtSignal()
    notice = pyqtSignal(str)                        # a line for the status bar

    def __init__(self, hospitals: list, admin_unlocked: bool = False,
                 has_admin: bool = False, parent=None):
        super().__init__(parent)
        self._hospitals = hospitals
        self._hospital = hospitals[0] if hospitals else None
        self._admin_unlocked = admin_unlocked
        self._has_admin = has_admin
        # Keyed by the item itself (id): two machines may share an IP.
        self._cards: dict[int, QFrame] = {}
        self._items: dict[int, object] = {}
        self._kinds: dict[int, str] = {}
        self._order: list[int] = []
        self._active_key: int | None = None
        self._selected: set[int] = set()
        self._amms_worker = None
        self._tips: dict[int, str] = {}
        self._tip_key: int | None = None
        self._tip = _HoverTip(self)
        self._tip_timer = QTimer(self)
        self._tip_timer.setInterval(30)
        self._tip_timer.timeout.connect(self._follow_tip)

        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(8)

        # Header: the hospital (a menu when the vault holds several) + AMMS.
        head = QHBoxLayout()
        head.setSpacing(6)
        self._hospital_btn = QPushButton()
        # Never takes the keyboard focus: as the first widget of the window
        # it wore the blue focus frame for no reason (owner, 2026-10-28).
        self._hospital_btn.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._hospital_btn.setStyleSheet(
            "QPushButton { background:#1a1d28; color:#e1e4eb; border:1px solid #2a2d3a;"
            " border-radius:10px; padding:8px 12px; font-size:13px; font-weight:bold;"
            " text-align:left; }"
            "QPushButton:hover { border-color:#4a5adf; background:#1e2233; }")
        self._hospital_btn.clicked.connect(self._show_hospital_menu)
        head.addWidget(self._hospital_btn, 1)

        self._amms_btn = QToolButton()
        self._amms_btn.setText("AMMS")
        self._amms_btn.setFixedHeight(34)
        self._amms_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._amms_btn.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._amms_btn.customContextMenuRequested.connect(self._on_amms_menu)
        self._amms_btn.clicked.connect(self._on_amms_clicked)
        head.addWidget(self._amms_btn)
        root.addLayout(head)

        self._search = QLineEdit()
        self._search.setPlaceholderText("Szukaj: IP, nazwa, opis…")
        self._search.setClearButtonEnabled(True)
        self._search.setStyleSheet(
            "QLineEdit { background:#14161e; border:1px solid #2a2d3a;"
            " border-radius:8px; padding:5px 8px; color:#c9d1d9; }"
            "QLineEdit:focus { border-color:#4a5adf; }")
        self._search.textChanged.connect(lambda _t: self._rebuild())
        self._search.returnPressed.connect(self._search_enter)
        root.addWidget(self._search)

        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setFrameShape(QFrame.Shape.NoFrame)
        self._scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._scroll.setStyleSheet(
            "QScrollArea { background:transparent; border:none; }"
            "QScrollBar:vertical { background:#14161e; width:6px; border:none;"
            " border-radius:3px; margin:2px; }"
            "QScrollBar::handle:vertical { background:#2a2d3a; border-radius:3px;"
            " min-height:20px; }"
            "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height:0; }")
        root.addWidget(self._scroll, 1)

        self._amms_status = QLabel()
        self._amms_status.setWordWrap(True)
        self._amms_status.setVisible(False)
        root.addWidget(self._amms_status)
        self._amms_hide = QTimer(self)
        self._amms_hide.setSingleShot(True)
        self._amms_hide.timeout.connect(lambda: self._amms_status.setVisible(False))

        # Footer: add, notes, admin.
        foot = QHBoxLayout()
        foot.setSpacing(6)
        self._add_btn = QToolButton()
        self._add_btn.setText("Dodaj")
        set_icon(self._add_btn, "plus", "#3fb950", size=14)
        self._add_btn.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)
        self._add_btn.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self._add_btn.setStyleSheet(_BTN_QSS.format(
            bg="#0d1f0d", fg="#3fb950", border="#1b3d1b", hover="#2d5a2d"))
        add_menu = QMenu(self._add_btn)
        add_menu.setStyleSheet(_MENU_QSS)
        add_menu.addAction("Maszynę (SSH / RDP / WWW)…", self._add_machine)
        add_menu.addAction("Bazę danych…", self._add_database)
        self._add_btn.setMenu(add_menu)
        foot.addWidget(self._add_btn)

        self._notes_btn = QPushButton("Notatki")
        self._notes_btn.setStyleSheet(_BTN_QSS.format(
            bg="#151b23", fg="#8b949e", border="#21262d", hover="#30363d"))
        self._notes_btn.clicked.connect(self._edit_notes)
        foot.addWidget(self._notes_btn)
        foot.addStretch()

        self._admin_btn = QPushButton("Admin")
        self._admin_btn.clicked.connect(self.admin_clicked.emit)
        foot.addWidget(self._admin_btn)
        root.addLayout(foot)

        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self._show_header()
        self._show_admin_state()
        self._rebuild()

    # ── What the SSH window calls ─────────────────────────────────────────

    def current_hospital(self):
        return self._hospital

    def set_admin_mode(self, unlocked: bool) -> None:
        if unlocked == self._admin_unlocked:
            return
        self._admin_unlocked = unlocked
        self._show_admin_state()
        self._rebuild()

    def set_has_admin(self, has_admin: bool) -> None:
        self._has_admin = has_admin
        self._show_admin_state()

    def set_active(self, ip: str, machine=None) -> None:
        """Light up the card of the session on screen."""
        key = None
        if machine is not None and id(machine) in self._cards:
            key = id(machine)
        elif ip:
            key = next((k for k in self._order if self._kinds[k] == "machine"
                        and self._items[k].ip == ip), None)
        if key == self._active_key:
            return
        old, self._active_key = self._active_key, key
        for k in (old, key):
            if k is not None:
                self._style_card(k)

    # ── Header, admin ─────────────────────────────────────────────────────

    def _show_header(self) -> None:
        h = self._hospital
        name = (h.name or "(bez nazwy)") if h else "—"
        several = len(self._hospitals) > 1
        self._hospital_btn.setText(f"  {name}")
        if several:
            set_icon(self._hospital_btn, "chevron-down", "#8a90a4", size=14)
        # One hospital: a heading, nothing to click or hover.
        self._hospital_btn.setCursor(Qt.CursorShape.PointingHandCursor if several
                                     else Qt.CursorShape.ArrowCursor)
        hover = ("QPushButton:hover { border-color:#4a5adf; background:#1e2233; }"
                 if several else "")
        self._hospital_btn.setStyleSheet(
            "QPushButton { background:#1a1d28; color:#e1e4eb; border:1px solid #2a2d3a;"
            " border-radius:10px; padding:8px 12px; font-size:13px; font-weight:bold;"
            " text-align:left; }" + hover)
        self._hospital_btn.setToolTip(
            "Wybierz szpital z tego vaulta" if several else name)
        self._show_amms()

    def _show_hospital_menu(self) -> None:
        if len(self._hospitals) < 2:
            return
        menu = QMenu(self)
        menu.setStyleSheet(_MENU_QSS)
        for h in self._hospitals:
            act = menu.addAction(h.name or "(bez nazwy)")
            act.setEnabled(h is not self._hospital)
            act.triggered.connect(lambda _=False, _h=h: self._choose_hospital(_h))
        menu.exec(self._hospital_btn.mapToGlobal(
            self._hospital_btn.rect().bottomLeft()))

    def _choose_hospital(self, hospital) -> None:
        self._hospital = hospital
        self._active_key = None
        self._selected.clear()
        self._show_header()
        self._rebuild()
        self.hospital_changed.emit(hospital)

    def _show_admin_state(self) -> None:
        self._admin_btn.setVisible(self._has_admin)
        if self._admin_unlocked:
            set_icon(self._admin_btn, "lock-open", "#8ae234", size=14)
            self._admin_btn.setToolTip("Tryb admina odblokowany — kliknij, aby zablokować")
            self._admin_btn.setStyleSheet(_BTN_QSS.format(
                bg="#1a3a1a", fg="#8ae234", border="#2d5a1a", hover="#2a4d2a"))
        else:
            set_icon(self._admin_btn, "lock", "#c084fc", size=14)
            self._admin_btn.setToolTip("Pokaż maszyny i loginy admina")
            self._admin_btn.setStyleSheet(_BTN_QSS.format(
                bg="#2a1a35", fg="#c084fc", border="#6b3fa0", hover="#3d2550"))

    def _visible(self, items: list) -> list:
        return items if self._admin_unlocked else [
            i for i in items if not i.admin_only]

    def _creds(self, item) -> list:
        return self._visible(list(item.credentials))

    # ── The list ──────────────────────────────────────────────────────────

    def _rebuild(self) -> None:
        self._hide_tip()
        self._cards.clear()
        self._tips.clear()
        self._items.clear()
        self._kinds.clear()
        self._order = []
        self._selected.clear()
        old_active = self._active_key
        self._active_key = None

        container = QWidget()
        container.setStyleSheet("background:transparent;")
        lay = QVBoxLayout(container)
        lay.setContentsMargins(0, 0, 2, 0)
        lay.setSpacing(2)

        h = self._hospital
        text = self._search.text().strip().lower()
        machines = [m for m in self._visible(h.machines if h else [])
                    if machine_matches(m, text)]
        databases = [d for d in self._visible(h.databases if h else [])
                     if database_matches(d, text)]

        if machines:
            lay.addWidget(self._section("MASZYNY"))
            for m in machines:
                lay.addWidget(self._card(m, "machine"))
        if databases:
            lay.addWidget(self._section("BAZY DANYCH"))
            for d in databases:
                lay.addWidget(self._card(d, "database"))
        if not machines and not databases:
            if text:
                msg = f"Brak wyników dla „{self._search.text().strip()}”."
            elif h is not None and (h.machines or h.databases):
                msg = "Wszystko w tym szpitalu jest dla admina — odblokuj Admin."
            else:
                msg = "Brak maszyn — dodaj pierwszą przyciskiem „Dodaj”."
            empty = QLabel(msg)
            empty.setWordWrap(True)
            empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
            empty.setStyleSheet("color:#5a5f72; font-size:11px; padding:16px;")
            lay.addWidget(empty)
        lay.addStretch()
        self._scroll.setWidget(container)

        if old_active in self._cards:
            self._active_key = old_active
            self._style_card(old_active)

    @staticmethod
    def _section(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet("color:#5a5f72; font-size:9px; font-weight:bold;"
                          " letter-spacing:2px; padding:6px 4px 4px 4px;")
        return lbl

    def _card(self, item, kind: str) -> QFrame:
        key = id(item)
        card = QFrame()
        card.setObjectName("machineCard")
        card.setCursor(Qt.CursorShape.PointingHandCursor)
        card.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._cards[key] = card
        self._items[key] = item
        self._kinds[key] = kind
        self._order.append(key)

        row = QHBoxLayout(card)
        row.setContentsMargins(10, 4, 8, 4)
        row.setSpacing(6)

        if theme.is_light():
            main_c, sub_c = "#0a4db0", "#525861"
        else:
            main_c, sub_c = "#b0c0ff", "#8a90a4"
        admin_c = "#c084fc"
        if kind == "machine":
            ctype = item.connection_type or "SSH"
            main = item.ip or (item.www_url if ctype == "WWW" else "") or "—"
            sub = item.name
            badge = ctype if ctype in _BADGES else "SSH"
            tip = item.description or ""
        else:
            main = item.host or "—"
            if item.port:
                main += f":{item.port}"
            sub = " ".join(p for p in (item.name, item.db_type) if p)
            badge = "DB"
            tip = item.note or ""
        colour = admin_c if item.admin_only else main_c
        row.addWidget(_CardLine(main, sub, colour, sub_c), 1)

        text, fg, bg, border, hover = _BADGES[badge]
        btn = QPushButton(text)
        btn.setFixedSize(38, 18)
        btn.setStyleSheet(
            f"QPushButton {{ background:{bg}; color:{fg}; border:1px solid {border};"
            " border-radius:6px; font-size:9px; font-weight:bold; padding:0; }"
            f"QPushButton:hover {{ background:{hover}; color:#fff; border-color:{hover}; }}")
        btn.setToolTip(self._connect_tip(item, kind))
        btn.clicked.connect(lambda _=False, i=item, k=kind: self._connect(i, k))
        row.addWidget(btn)

        if tip.strip():
            # What runs there (services on Tomcat…): the hover bubble, at
            # once and following the cursor (owner, 2026-10-28).
            self._tips[key] = self._tip_html(main, sub, tip.strip())
            card.enterEvent = lambda e, k=key: self._show_tip(k)
            card.leaveEvent = lambda e: self._hide_tip()
        card.mousePressEvent = lambda e, k=key: self._clicked(k, e)
        card.mouseDoubleClickEvent = lambda e, k=key: self._double_clicked(k, e)
        card.customContextMenuRequested.connect(
            lambda pos, k=key, c=card: self._menu(k).exec(c.mapToGlobal(pos)))
        self._style_card(key)
        return card

    def _connect_tip(self, item, kind: str) -> str:
        if kind == "database":
            return "Uruchom SQL Developer, hasło do schowka"
        ctype = item.connection_type or "SSH"
        if ctype == "RDP":
            return f"Pulpit zdalny ({item.ip}:{item.rdp_port or '3389'})"
        if ctype == "WWW":
            return f"Otwórz w przeglądarce: {www_url(item)}"
        return f"Terminal SSH + pliki SFTP: {item.ip}"

    def _style_card(self, key: int) -> None:
        card = self._cards.get(key)
        if card is None:
            return
        if key in self._selected:
            card.setStyleSheet(_CARD_SELECTED)
        elif key == self._active_key:
            card.setStyleSheet(_CARD_ACTIVE)
        else:
            card.setStyleSheet(_CARD_IDLE)

    # ── The hover bubble ─────────────────────────────────────────────────

    @staticmethod
    def _tip_html(main: str, sub: str, text: str) -> str:
        head_c, sub_c = (("#0a4db0", "#525861") if theme.is_light()
                         else ("#b0c0ff", "#8a90a4"))
        head = f"<b style='color:{head_c};'>{_esc(main)}</b>"
        if sub:
            head += f"<span style='color:{sub_c};'>&nbsp;&nbsp;{_esc(sub)}</span>"
        body = _esc(text).replace("\n", "<br>")
        return f"{head}<br>{body}"

    def _show_tip(self, key: int) -> None:
        html = self._tips.get(key)
        if html is None:
            return
        self._tip_key = key
        self._tip.show_text(html, QCursor.pos())
        self._tip_timer.start()

    def _follow_tip(self) -> None:
        card = self._cards.get(self._tip_key)
        pos = QCursor.pos()
        if (card is None or not card.isVisible()
                or not self.window().isActiveWindow()
                or not card.rect().contains(card.mapFromGlobal(pos))):
            self._hide_tip()
            return
        self._tip.follow(pos)

    def _hide_tip(self) -> None:
        self._tip_key = None
        self._tip_timer.stop()
        self._tip.hide()

    def hideEvent(self, event):
        self._hide_tip()
        super().hideEvent(event)

    def _clicked(self, key: int, event) -> None:
        self._hide_tip()
        if event.button() != Qt.MouseButton.LeftButton:
            return
        # One click selects; Ctrl+click adds to the selection.  Connecting is
        # a double click or Enter (as in the SSH window, UX audit E-04).
        if not event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            for k in list(self._selected):
                if k != key:
                    self._selected.discard(k)
                    self._style_card(k)
        if key in self._selected:
            self._selected.discard(key)
        else:
            self._selected.add(key)
        self._style_card(key)
        self.setFocus()

    def _double_clicked(self, key: int, event) -> None:
        self._hide_tip()
        if event.button() != Qt.MouseButton.LeftButton:
            return
        for k in list(self._selected):
            self._selected.discard(k)
            self._style_card(k)
        self._connect(self._items[key], self._kinds[key])

    def keyPressEvent(self, event):
        if event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and self._selected:
            keys = [k for k in self._order if k in self._selected]
            self._selected.clear()
            for k in keys:
                self._style_card(k)
                self._connect(self._items[k], self._kinds[k])
            return
        super().keyPressEvent(event)

    def _search_enter(self) -> None:
        """Enter in the search box: the only result connects, several are
        selected for a look first."""
        if len(self._order) == 1:
            k = self._order[0]
            self._connect(self._items[k], self._kinds[k])
        elif self._order:
            self._selected = {self._order[0]}
            self._style_card(self._order[0])
            self.setFocus()

    # ── Connecting ────────────────────────────────────────────────────────

    def _connect(self, item, kind: str, cred=None) -> None:
        if kind == "database":
            from ui.db_connect import connect_db
            if cred is not None:
                item = copy.copy(item)
                item.credentials = [cred]
            connect_db(item, self, self._admin_unlocked)
            return
        ctype = item.connection_type or "SSH"
        if ctype == "WWW":
            QDesktopServices.openUrl(QUrl(www_url(item)))
        elif ctype == "RDP":
            from ui.rdp import connect_rdp
            if cred is not None:
                m = copy.copy(item)
                m.credentials = [cred] + [c for c in item.credentials if c is not cred]
                item = m
            connect_rdp(item, self, self._admin_unlocked)
        elif cred is not None:
            self.open_machine_cred.emit(item, cred)
        else:
            self.open_machine.emit(item)

    def _menu(self, key: int) -> QMenu:
        item, kind = self._items[key], self._kinds[key]
        menu = QMenu(self)
        menu.setStyleSheet(_MENU_QSS)
        creds = self._creds(item)
        ctype = item.connection_type if kind == "machine" else "DB"
        label = {"SSH": "Połącz (SSH + SFTP)", "RDP": "Połącz (RDP)",
                 "WWW": "Otwórz w przeglądarce",
                 "DB": "SQL Developer + hasło do schowka"}.get(ctype, "Połącz")
        menu.addAction(icon("connect", "#c9d1d9"), label,
                       lambda: self._connect(item, kind))
        if len(creds) > 1 and ctype in ("SSH", "RDP", "DB"):
            sub = menu.addMenu("Połącz jako")
            sub.setStyleSheet(_MENU_QSS)
            for c in creds:
                sub.addAction(_cred_label(c),
                              lambda c=c: self._connect(item, kind, c))
        menu.addSeparator()
        if not creds:
            menu.addAction("Brak loginów").setEnabled(False)
        for c in creds:
            text = _cred_label(c)
            menu.addAction(icon("user", "#c9d1d9"), f"Kopiuj login: {text}",
                           lambda c=c: _clipboard_copy(c.login))
            menu.addAction(icon("key", "#c9d1d9"), f"Kopiuj hasło: {text}",
                           lambda c=c: _clipboard_copy(c.password))
        if kind == "machine" and item.ip:
            menu.addAction(icon("copy", "#c9d1d9"), "Kopiuj IP",
                           lambda: _clipboard_copy(item.ip))
        menu.addSeparator()
        if kind == "machine":
            menu.addAction(icon("gear", "#c9d1d9"), "Edytuj maszynę…",
                           lambda: self._edit_machine(item))
            menu.addAction(icon("copy", "#c9d1d9"), "Duplikuj…",
                           lambda: self._duplicate_machine(item))
            menu.addAction(icon("trash", "#f85149"), "Usuń maszynę…",
                           lambda: self._delete(item, kind))
        else:
            menu.addAction(icon("gear", "#c9d1d9"), "Edytuj bazę…",
                           lambda: self._edit_database(item))
            menu.addAction(icon("trash", "#f85149"), "Usuń bazę…",
                           lambda: self._delete(item, kind))
        return menu

    # ── Editing ───────────────────────────────────────────────────────────

    def _changed(self) -> None:
        self._rebuild()
        self.data_changed.emit()

    def _add_machine(self) -> None:
        if self._hospital is None:
            return
        dlg = MachineDialog(self, admin_mode=self._admin_unlocked)
        if dlg.exec():
            self._hospital.machines.append(dlg.get_machine())
            self._changed()

    def _edit_machine(self, machine) -> None:
        dlg = MachineDialog(self, machine, admin_mode=self._admin_unlocked)
        if dlg.exec():
            # The dialog edits a deep copy with the same id: the copy takes
            # the original's place in the list (as in the hospital view).
            machines = self._hospital.machines
            if machine in machines:
                machines[machines.index(machine)] = dlg.get_machine()
            self._changed()

    def _duplicate_machine(self, machine) -> None:
        dup = copy.deepcopy(machine)
        dup.id = str(models.uuid.uuid4())
        for c in dup.credentials:
            c.id = str(models.uuid.uuid4())
        dlg = MachineDialog(self, machine=dup, admin_mode=self._admin_unlocked)
        if dlg.exec():
            machines = self._hospital.machines
            at = machines.index(machine) + 1 if machine in machines else len(machines)
            machines.insert(at, dlg.get_machine())
            self._changed()

    def _add_database(self) -> None:
        if self._hospital is None:
            return
        dlg = DatabaseDialog(self, admin_mode=self._admin_unlocked)
        if dlg.exec():
            self._hospital.databases.append(dlg.get_database())
            self._changed()

    def _edit_database(self, db) -> None:
        dlg = DatabaseDialog(self, db, admin_mode=self._admin_unlocked)
        if dlg.exec():
            dbs = self._hospital.databases
            if db in dbs:
                dbs[dbs.index(db)] = dlg.get_database()
            self._changed()

    def _delete(self, item, kind: str) -> None:
        if kind == "machine":
            what = f"maszynę '{item.name or item.ip}' ({item.ip})"
            items = self._hospital.machines
        else:
            what = f"bazę '{item.name}' na '{item.host}'"
            items = self._hospital.databases
        if confirm(self, "Usuń", f"Usunąć {what}?\nJej loginy też zostaną usunięte.",
                   yes="Usuń", no="Anuluj"):
            if item in items:
                items.remove(item)
            self._changed()

    def _edit_notes(self) -> None:
        h = self._hospital
        if h is None:
            return
        dlg = _NotesDialog(self, h.name, h.notes)
        if dlg.exec() and dlg.text() != h.notes:
            h.notes = dlg.text()
            self.data_changed.emit()

    # ── AMMS ──────────────────────────────────────────────────────────────

    _AMMS_QSS = (
        "QToolButton {{ background:#1a1d28; border:1px solid {border};"
        " border-radius:10px; color:{color}; font-size:10px; font-weight:bold;"
        " padding:0 10px; }}"
        "QToolButton:hover {{ border-color:#58a6ff; color:#58a6ff; }}")

    def _show_amms(self) -> None:
        h = self._hospital
        if self._amms_worker is not None:
            self._amms_btn.setStyleSheet(self._AMMS_QSS.format(
                border="#1f6feb", color="#58a6ff"))
            self._amms_btn.setToolTip("AMMS: logowanie w toku…")
        elif h is not None and h.amms_url:
            self._amms_btn.setStyleSheet(self._AMMS_QSS.format(
                border="#30363d", color="#8b949e"))
            who = f" jako {h.amms_login}" if h.amms_login else ""
            self._amms_btn.setToolTip(f"Otwórz AMMS i zaloguj{who}: {h.amms_url}"
                                      "\nPrawy przycisk: edycja")
        else:
            self._amms_btn.setStyleSheet(self._AMMS_QSS.format(
                border="#21262d", color="#484f58"))
            self._amms_btn.setToolTip("AMMS nie skonfigurowany — kliknij, aby ustawić")

    def _on_amms_clicked(self) -> None:
        h = self._hospital
        if h is None:
            return
        if not h.amms_url:
            self._edit_amms()
        else:
            self._start_amms(with_login=True)

    def _on_amms_menu(self, pos) -> None:
        h = self._hospital
        if h is None:
            return
        menu = QMenu(self)
        menu.setStyleSheet(_MENU_QSS)
        menu.addAction("Edytuj AMMS…", self._edit_amms)
        if h.amms_password:
            menu.addAction("Kopiuj hasło", lambda: _clipboard_copy(h.amms_password))
        if h.amms_url:
            menu.addAction("Otwórz bez logowania",
                           lambda: self._start_amms(with_login=False))
        menu.exec(self._amms_btn.mapToGlobal(pos))

    def _edit_amms(self) -> None:
        h = self._hospital
        from ui.amms import AmmsDialog
        dlg = AmmsDialog(self, h)
        if dlg.exec():
            values = dlg.values()
            if values != (h.amms_url, h.amms_login, h.amms_password):
                h.amms_url, h.amms_login, h.amms_password = values
                self.data_changed.emit()
            self._show_amms()

    def _start_amms(self, with_login: bool) -> None:
        h = self._hospital
        if h is None or not h.amms_url or self._amms_worker is not None:
            return
        from ui.amms import AmmsWorker
        worker = AmmsWorker(h.amms_url, h.amms_login if with_login else "",
                            h.amms_password if with_login else "", parent=self)
        worker.progress.connect(lambda text: self._amms_line(text, "#58a6ff"))
        worker.done.connect(self._on_amms_done)
        worker.finished.connect(worker.deleteLater)
        self._amms_worker = worker
        self._show_amms()
        worker.start()

    def _amms_line(self, text: str, color: str, hide_after_ms: int = 0) -> None:
        self._amms_hide.stop()
        self._amms_status.setText(text)
        self._amms_status.setStyleSheet(f"color:{color}; font-size:11px;")
        self._amms_status.setVisible(True)
        if hide_after_ms:
            self._amms_hide.start(hide_after_ms)

    def _on_amms_done(self, outcome: str, detail: str) -> None:
        from ui.amms import outcome_text
        self._amms_worker = None
        text, color = outcome_text(outcome)
        if outcome == "rejected" and detail:
            text = f"{text}: {detail}"
        self._amms_line(text, color, hide_after_ms=10000)
        self._show_amms()


def _cred_label(c) -> str:
    text = c.login or "(bez loginu)"
    if c.note:
        text += f"  ({c.note})"
    if c.admin_only:
        text += "  (admin)"
    return text


def _esc(text: str) -> str:
    return (str(text).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;"))
