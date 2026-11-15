"""The "Aktualizacja" tab of HospitalHub Portable (2026-11-15, owner).

The upgrade of a hospital done from one place:

* the machines of the upgrade in a list whose order is the order of the
  tabs — "Otwórz karty po kolei" opens an SSH tab for each one not open yet;
* groups (AMMS / WildFly, Platforma / Tomcat, Zdarzenia medyczne, Balancer…)
  with their machines and editable command buttons — a click types the
  command into the terminal of every machine of the group at once, so each
  terminal shows what is going on, and the result comes back here per
  machine (✓ kod 0 / ✗ kod N).

The plan is data of the hospital (``Hospital.upgrade``, see upgrade_plan);
every edit emits ``data_changed`` and the window saves the vault.  Typing
into the terminals is the window's job (``run_requested`` /
``interrupt_requested``); it reports back with ``set_status``.
"""

from __future__ import annotations

import time

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QAbstractItemView, QCheckBox, QDialog, QDialogButtonBox, QFrame,
    QGridLayout, QHBoxLayout, QInputDialog, QLabel, QLineEdit, QListWidget,
    QListWidgetItem, QMenu, QPlainTextEdit, QPushButton, QScrollArea,
    QSizePolicy, QToolButton, QVBoxLayout, QWidget,
)

import upgrade_plan as up
from ui.hd_download import HdDownloadBox
from ui.icons import set_icon
from ui.utils import confirm

__all__ = ["UpgradePanel", "CommandDialog", "MachinePickDialog"]


_MENU_QSS = (
    "QMenu{background:#1a1d28;color:#e1e4eb;border:1px solid #2a2d3a;"
    "border-radius:10px;padding:6px;}"
    "QMenu::item{padding:6px 18px;border-radius:6px;}"
    "QMenu::item:selected{background:#4a5adf;color:#fff;}"
    "QMenu::item:disabled{color:#5a5f72;}"
    "QMenu::separator{height:1px;background:#2a2d3a;margin:4px 10px;}"
)

_BTN_QSS = (
    "QPushButton, QToolButton {{ background:{bg}; color:{fg};"
    " border:1px solid {border}; border-radius:6px; padding:5px 8px;"
    " font-size:11px; }}"
    "QPushButton:hover, QToolButton:hover {{ background:{hover}; color:#fff; }}"
    "QPushButton:disabled {{ color:#5a5f72; }}"
    "QToolButton::menu-indicator {{ width:0; height:0; }}"
)

_CMD_QSS = _BTN_QSS.format(bg="#1a2040", fg="#a5b4ff", border="#3a4070",
                           hover="#4a5adf")
_CMD_DANGER_QSS = _BTN_QSS.format(bg="#2a1a1a", fg="#ff9b8f", border="#5a2d2d",
                                  hover="#b33a3a")
_GREEN_QSS = _BTN_QSS.format(bg="#0d1f0d", fg="#3fb950", border="#1b3d1b",
                             hover="#2d5a2d")
_GREY_QSS = _BTN_QSS.format(bg="#151b23", fg="#8b949e", border="#21262d",
                            hover="#30363d")

_BOX_QSS = (
    "QFrame#upgradeBox { background:#1a1d28; border:1px solid #2a2d3a;"
    " border-radius:10px; }"
    "QLabel { border:none; background:transparent; }"
)

_FIELD_QSS = (
    "QLineEdit, QPlainTextEdit { background:#14161e; border:1px solid #2a2d3a;"
    " border-radius:6px; padding:4px 6px; color:#c9d1d9; }"
    "QLineEdit:focus, QPlainTextEdit:focus { border-color:#4a5adf; }"
)

#: state → (mark, colour) of a machine's last result in a group.
STATES = {
    "run":  ("▶", "#58a6ff"),
    "ok":   ("✓", "#3fb950"),
    "fail": ("✗", "#f85149"),
    "miss": ("–", "#d29922"),
    "stop": ("■", "#d29922"),
}


def machine_label(m) -> str:
    return m.ip + (f"  {m.name}" if m.name else "")


def _shrinkable(w):
    """A button may be narrower than its text: the panel is narrow and its
    width is the user's (the splitter) — never pushed out of it."""
    w.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
    w.setMinimumWidth(40)
    return w


def _esc(text: str) -> str:
    return (text or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


# ── Dialogs ──────────────────────────────────────────────────────────────

class CommandDialog(QDialog):
    """Edit one command button."""

    def __init__(self, parent, cmd: dict, group: dict):
        super().__init__(parent)
        self.setWindowTitle("Komenda")
        self.setMinimumWidth(560)
        self.setStyleSheet(_FIELD_QSS)
        lay = QVBoxLayout(self)

        lay.addWidget(QLabel("Nazwa przycisku:"))
        self.label = QLineEdit(cmd.get("label", ""))
        lay.addWidget(self.label)

        lay.addWidget(QLabel("Komendy (każda w osobnej linii — wykonywane po "
                             "kolei, błąd przerywa resztę):"))
        self.text = QPlainTextEdit(cmd.get("text", ""))
        mono = QFont("Consolas")
        mono.setStyleHint(QFont.StyleHint.Monospace)
        self.text.setFont(mono)
        self.text.setMinimumHeight(140)
        lay.addWidget(self.text)

        hint = QLabel("{WERSJA} — wersja wpisana u góry zakładki, "
                      "{DATA} — dzisiejsza data (RRRRMMDD). Linie z # są pomijane.")
        hint.setWordWrap(True)
        hint.setStyleSheet("color:#8b949e; font-size:10px;")
        lay.addWidget(hint)

        self.confirm = QCheckBox("Pytaj przed wykonaniem")
        self.confirm.setChecked(bool(cmd.get("confirm")))
        lay.addWidget(self.confirm)

        pattern = (group.get("process") or "").strip()
        self.stopped = QCheckBox(
            f"Wymaga zatrzymanej usługi grupy (proces: {pattern})" if pattern
            else "Wymaga zatrzymanej usługi grupy (ustaw proces w grupie)")
        self.stopped.setToolTip(
            "Przed komendą sprawdzany jest proces tej grupy (pgrep -f). "
            "Gdy działa — nic się nie wykona.\nSprawdzany jest tylko proces "
            "tej usługi, nie każda java: WildFly i Tomcat mogą stać na "
            "jednej maszynie.")
        self.stopped.setChecked(bool(cmd.get("requires_stopped")))
        lay.addWidget(self.stopped)

        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                              | QDialogButtonBox.StandardButton.Cancel)
        bb.button(QDialogButtonBox.StandardButton.Ok).setText("Zapisz")
        bb.button(QDialogButtonBox.StandardButton.Cancel).setText("Anuluj")
        bb.accepted.connect(self._accept)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def _accept(self):
        if not self.label.text().strip() or not self.text.toPlainText().strip():
            self.label.setFocus()
            return
        self.accept()

    def values(self) -> dict:
        return {"label": self.label.text().strip(),
                "text": self.text.toPlainText().rstrip(),
                "confirm": self.confirm.isChecked(),
                "requires_stopped": self.stopped.isChecked()}


class MachinePickDialog(QDialog):
    """Tick machines from a list (in the list's order)."""

    def __init__(self, parent, title: str, machines: list, chosen: set,
                 extra: QWidget | None = None):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(380)
        self.setStyleSheet(_FIELD_QSS)
        lay = QVBoxLayout(self)
        if extra is not None:
            lay.addWidget(extra)
        self._boxes = []
        for m in machines:
            cb = QCheckBox(machine_label(m))
            cb.setChecked(m.id in chosen)
            if m.description:
                cb.setToolTip(m.description)
            self._boxes.append((cb, m))
            lay.addWidget(cb)
        if not machines:
            lay.addWidget(QLabel("Brak maszyn SSH w tym szpitalu."))
        bb = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                              | QDialogButtonBox.StandardButton.Cancel)
        bb.button(QDialogButtonBox.StandardButton.Ok).setText("Zapisz")
        bb.button(QDialogButtonBox.StandardButton.Cancel).setText("Anuluj")
        bb.accepted.connect(self.accept)
        bb.rejected.connect(self.reject)
        lay.addWidget(bb)

    def chosen_ids(self) -> list:
        return [m.id for cb, m in self._boxes if cb.isChecked()]


# ── The panel ────────────────────────────────────────────────────────────

class UpgradePanel(QWidget):
    data_changed = pyqtSignal()
    #: machines to open, in order (only those without a tab — the window checks)
    open_requested = pyqtSignal(list)
    #: (group, command, machines in plan order)
    run_requested = pyqtSignal(dict, dict, list)
    #: (group, machines) — Ctrl+C in their terminals
    interrupt_requested = pyqtSignal(dict, list)

    def __init__(self, hospital=None, admin_unlocked: bool = False, parent=None):
        super().__init__(parent)
        self._hospital = None
        self._plan: dict = up.default_plan()
        self._admin_unlocked = admin_unlocked
        #: (group id, machine id) → (state, text, HH:MM:SS)
        self._status: dict[tuple, tuple] = {}
        self._status_labels: dict[str, QLabel] = {}
        self._select_row = -1

        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        row = QHBoxLayout()
        lbl = QLabel("Wersja:")
        lbl.setStyleSheet("color:#c9d1d9; font-size:11px;")
        row.addWidget(lbl)
        self._version = QLineEdit()
        self._version.setPlaceholderText("np. 6.10.01.83")
        self._version.setStyleSheet(_FIELD_QSS)
        self._version.setToolTip("Wstawiana do komend w miejsce {WERSJA}")
        self._version.editingFinished.connect(self._version_edited)
        row.addWidget(self._version, 1)
        self._day = QLabel()
        self._day.setStyleSheet("color:#8b949e; font-size:10px;")
        self._day.setToolTip("{DATA} w komendach")
        row.addWidget(self._day)
        root.addLayout(row)

        # Outside the scrolled plan: a rebuild never drops a running download.
        self.hd_box = HdDownloadBox(lambda: self._plan.get("hd") or up.default_hd())
        self.hd_box.settings_changed.connect(self._hd_settings)
        self.hd_box.version_found.connect(self._hd_version)
        root.addWidget(self.hd_box)

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

        if hospital is not None:
            self.set_hospital(hospital)

    # ── What the window calls ─────────────────────────────────────────────

    @property
    def plan(self) -> dict:
        return self._plan

    def version(self) -> str:
        return self._version.text().strip()

    def set_hospital(self, hospital) -> None:
        self._hospital = hospital
        self._plan = up.normalize_plan(getattr(hospital, "upgrade", None))
        self._status.clear()
        self._version.setText(self._plan.get("version", ""))
        if not self.hd_box.busy():
            self.hd_box.show_idle()
        self._rebuild()

    def refresh(self) -> None:
        """The hospital's machines changed (edited in "Maszyny")."""
        self._rebuild()

    def set_admin_mode(self, unlocked: bool) -> None:
        self._admin_unlocked = unlocked
        self._rebuild()

    def set_status(self, group_id: str, machine_id: str, state: str,
                   text: str = "") -> None:
        self._status[(group_id, machine_id)] = (state, text,
                                                time.strftime("%H:%M:%S"))
        self._show_status(group_id)

    def machines_of(self, group: dict) -> list:
        """The group's machines in the order of the upgrade list."""
        ids = set(group.get("machines", []))
        ordered = [m for m in self._order_machines() if m.id in ids]
        rest = [m for m in self._ssh_machines()
                if m.id in ids and m not in ordered]
        return ordered + rest

    # ── Data ──────────────────────────────────────────────────────────────

    def _ssh_machines(self) -> list:
        h = self._hospital
        if h is None:
            return []
        return [m for m in h.machines
                if getattr(m, "connection_type", "SSH") == "SSH"
                and (self._admin_unlocked or not m.admin_only)]

    def _order_machines(self) -> list:
        return up.plan_machines(self._plan, self._ssh_machines())

    def _commit(self, rebuild: bool = True) -> None:
        if self._hospital is not None:
            self._hospital.upgrade = up.copy_plan(self._plan)
        if rebuild:
            # Later: the edit may come from a signal of a widget the
            # rebuild deletes (the drag of the list).
            QTimer.singleShot(0, self._rebuild)
        self.data_changed.emit()

    def _hd_settings(self, values: dict) -> None:
        self._plan["hd"] = up.normalize_hd(values)
        self._commit(rebuild=False)

    def _hd_version(self, version: str) -> None:
        """The newest version on hd.asseco.pl goes into {WERSJA}."""
        if version and version != self._plan.get("version"):
            self._version.setText(version)
            self._plan["version"] = version
            self._commit(rebuild=False)

    def _version_edited(self) -> None:
        v = self._version.text().strip()
        if v != self._plan.get("version", ""):
            self._plan["version"] = v
            self._commit(rebuild=False)

    # ── Building ──────────────────────────────────────────────────────────

    def _rebuild(self) -> None:
        self._day.setText(f"data: {up.today_stamp()}")
        self._status_labels.clear()
        box = QWidget()
        box.setStyleSheet("background:transparent;")
        lay = QVBoxLayout(box)
        lay.setContentsMargins(0, 0, 4, 0)
        lay.setSpacing(8)
        lay.addWidget(self._order_box())
        for g in self._plan["groups"]:
            lay.addWidget(self._group_box(g))
        add = _shrinkable(QPushButton("Dodaj grupę"))
        set_icon(add, "plus", "#3fb950", size=13)
        add.setStyleSheet(_GREEN_QSS)
        add.clicked.connect(self._add_group)
        lay.addWidget(add)
        lay.addStretch()
        self._scroll.setWidget(box)
        for g in self._plan["groups"]:
            self._show_status(g["id"])

    @staticmethod
    def _section(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet("color:#8b949e; font-size:9px; font-weight:bold;"
                          " letter-spacing:2px;")
        return lbl

    def _order_box(self) -> QFrame:
        frame = QFrame()
        frame.setObjectName("upgradeBox")
        frame.setStyleSheet(_BOX_QSS)
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(6)
        lay.addWidget(self._section("KOLEJNOŚĆ KART"))

        machines = self._order_machines()
        self._list = QListWidget()
        self._list.setDragDropMode(QAbstractItemView.DragDropMode.InternalMove)
        self._list.setDefaultDropAction(Qt.DropAction.MoveAction)
        self._list.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._list.setTextElideMode(Qt.TextElideMode.ElideRight)
        self._list.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
        self._list.setStyleSheet(
            "QListWidget { background:#14161e; border:1px solid #2a2d3a;"
            " border-radius:6px; color:#c9d1d9; font-size:11px; }"
            "QListWidget::item { padding:3px 4px; }"
            "QListWidget::item:selected { background:#1c2240; color:#fff; }")
        groups_of = {}
        for g in self._plan["groups"]:
            for mid in g.get("machines", []):
                groups_of.setdefault(mid, []).append(g["name"].split(" (")[0])
        for i, m in enumerate(machines, 1):
            tags = groups_of.get(m.id, [])
            item = QListWidgetItem(f"{i}. {machine_label(m)}"
                                   + (f"   [{', '.join(tags)}]" if tags else ""))
            item.setData(Qt.ItemDataRole.UserRole, m.id)
            if m.description:
                item.setToolTip(m.description)
            self._list.addItem(item)
        self._list.setFixedHeight(min(240, 12 + 20 * max(1, len(machines))))
        self._list.model().rowsMoved.connect(lambda *_a: self._order_dragged())
        if 0 <= self._select_row < len(machines):
            self._list.setCurrentRow(self._select_row)
        self._select_row = -1
        lay.addWidget(self._list)
        if not machines:
            empty = QLabel("Dodaj maszyny aktualizacji — ich kolejność to "
                           "kolejność otwierania kart.")
            empty.setWordWrap(True)
            empty.setStyleSheet("color:#5a5f72; font-size:10px;")
            lay.addWidget(empty)

        row = QHBoxLayout()
        row.setSpacing(4)
        open_btn = QPushButton("Otwórz karty po kolei")
        set_icon(open_btn, "connect", "#3fb950", size=13)
        open_btn.setStyleSheet(_GREEN_QSS)
        open_btn.setEnabled(bool(machines))
        open_btn.setToolTip("Otwiera kartę SSH każdej maszyny z listy, "
                            "w tej kolejności (już otwarte są pomijane)")
        open_btn.clicked.connect(lambda: self.open_requested.emit(self._order_machines()))
        row.addWidget(_shrinkable(open_btn), 1)
        for name, tip, step in (("up", "W górę", -1), ("chevron-down", "W dół", 1)):
            b = QToolButton()
            set_icon(b, name, "#8b949e", size=13)
            b.setToolTip(tip)
            b.setStyleSheet(_GREY_QSS)
            b.clicked.connect(lambda _c=False, s=step: self._move_selected(s))
            row.addWidget(b)
        pick = QToolButton()
        set_icon(pick, "pencil", "#8b949e", size=13)
        pick.setStyleSheet(_GREY_QSS)
        pick.setToolTip("Wybierz maszyny aktualizacji")
        pick.clicked.connect(self._pick_order)
        row.addWidget(pick)
        lay.addLayout(row)
        return frame

    def _group_box(self, g: dict) -> QFrame:
        frame = QFrame()
        frame.setObjectName("upgradeBox")
        frame.setStyleSheet(_BOX_QSS)
        lay = QVBoxLayout(frame)
        lay.setContentsMargins(8, 8, 8, 8)
        lay.setSpacing(6)

        head = QHBoxLayout()
        title = QLabel(_esc(g["name"]))
        title.setStyleSheet("color:#e1e4eb; font-size:12px; font-weight:bold;")
        title.setWordWrap(True)
        title.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        head.addWidget(title, 1)
        more = QToolButton()
        set_icon(more, "more", "#8b949e", size=14)
        more.setStyleSheet(_GREY_QSS)
        more.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        menu = QMenu(more)
        menu.setStyleSheet(_MENU_QSS)
        menu.addAction("Maszyny grupy…", lambda gg=g: self._pick_group_machines(gg))
        menu.addAction("Dodaj komendę…", lambda gg=g: self._add_command(gg))
        menu.addAction("Nazwa i proces usługi…", lambda gg=g: self._edit_group(gg))
        menu.addSeparator()
        menu.addAction("Usuń grupę", lambda gg=g: self._delete_group(gg))
        more.setMenu(menu)
        head.addWidget(more)
        lay.addLayout(head)

        ms = self.machines_of(g)
        who = QLabel(", ".join(m.ip for m in ms) if ms
                     else "brak maszyn — ⋯ → Maszyny grupy…")
        who.setWordWrap(True)
        who.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        who.setStyleSheet("color:#8b949e; font-size:10px;" if ms
                          else "color:#d29922; font-size:10px;")
        if g.get("process"):
            who.setToolTip(f"Proces usługi: {g['process']}")
        lay.addWidget(who)

        grid = QGridLayout()
        grid.setSpacing(4)
        cmds = g.get("commands", [])
        for i, c in enumerate(cmds):
            b = _shrinkable(QPushButton(c["label"]))
            b.setStyleSheet(_CMD_DANGER_QSS if c.get("confirm") else _CMD_QSS)
            b.setToolTip(_esc(c["text"]).replace("\n", "<br>")
                         + "<br><i>prawy klik — edycja</i>")
            b.setEnabled(bool(ms))
            b.clicked.connect(lambda _c=False, gg=g, cc=c:
                              self.run_requested.emit(gg, cc, self.machines_of(gg)))
            b.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            b.customContextMenuRequested.connect(
                lambda _p, gg=g, cc=c, bb=b: self._command_menu(gg, cc, bb))
            grid.addWidget(b, i // 2, i % 2)
        lay.addLayout(grid)

        row = QHBoxLayout()
        row.setSpacing(4)
        stop = QPushButton("Ctrl+C")
        set_icon(stop, "stop", "#d29922", size=12)
        stop.setStyleSheet(_GREY_QSS)
        stop.setToolTip("Przerwij to, co działa w terminalach tej grupy "
                        "(np. tail -f po starcie)")
        stop.setEnabled(bool(ms))
        _shrinkable(stop)
        stop.clicked.connect(lambda _c=False, gg=g:
                             self.interrupt_requested.emit(gg, self.machines_of(gg)))
        row.addWidget(stop)
        add = QPushButton("+ komenda")
        add.setStyleSheet(_GREY_QSS)
        add.clicked.connect(lambda _c=False, gg=g: self._add_command(gg))
        row.addWidget(_shrinkable(add))
        lay.addLayout(row)

        status = QLabel()
        status.setWordWrap(True)
        status.setTextFormat(Qt.TextFormat.RichText)
        status.setStyleSheet("font-size:10px;")
        status.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Preferred)
        status.setVisible(False)
        self._status_labels[g["id"]] = status
        lay.addWidget(status)
        return frame

    def _show_status(self, group_id: str) -> None:
        lbl = self._status_labels.get(group_id)
        group = next((g for g in self._plan["groups"] if g["id"] == group_id), None)
        if lbl is None or group is None:
            return
        rows = []
        for m in self.machines_of(group):
            st = self._status.get((group_id, m.id))
            if st is None:
                continue
            state, text, at = st
            mark, color = STATES.get(state, ("·", "#8b949e"))
            rows.append(f"<span style='color:{color}'>{mark}</span> "
                        f"<span style='color:#c9d1d9'>{_esc(m.ip)}</span> "
                        f"<span style='color:#8b949e'>{_esc(text)} · {at}</span>")
        lbl.setText("<br>".join(rows))
        lbl.setVisible(bool(rows))

    # ── Order ─────────────────────────────────────────────────────────────

    def _order_dragged(self) -> None:
        ids = [self._list.item(i).data(Qt.ItemDataRole.UserRole)
               for i in range(self._list.count())]
        self._set_order(ids)

    def _set_order(self, shown_ids: list) -> None:
        # Hidden (admin-only) machines keep their places at the end.
        hidden = [i for i in self._plan["order"] if i not in shown_ids]
        self._plan["order"] = list(shown_ids) + hidden
        self._commit()

    def _move_selected(self, step: int) -> None:
        row = self._list.currentRow()
        ids = [self._list.item(i).data(Qt.ItemDataRole.UserRole)
               for i in range(self._list.count())]
        to = row + step
        if row < 0 or not 0 <= to < len(ids):
            return
        ids[row], ids[to] = ids[to], ids[row]
        self._select_row = to
        self._set_order(ids)

    def _pick_order(self) -> None:
        all_m = self._ssh_machines()
        current = [m.id for m in self._order_machines()]
        shown = (self._order_machines()
                 + [m for m in all_m if m.id not in current])
        dlg = MachinePickDialog(self, "Maszyny aktualizacji", shown, set(current))
        if not dlg.exec():
            return
        chosen = dlg.chosen_ids()
        keep = [i for i in current if i in chosen]
        self._set_order(keep + [i for i in chosen if i not in keep])

    # ── Groups and commands ───────────────────────────────────────────────

    def _pick_group_machines(self, g: dict) -> None:
        all_m = self._ssh_machines()
        order_ids = [m.id for m in self._order_machines()]
        shown = (self._order_machines()
                 + [m for m in all_m if m.id not in order_ids])
        dlg = MachinePickDialog(self, f"Maszyny — {g['name']}", shown,
                                set(g.get("machines", [])))
        if not dlg.exec():
            return
        visible = {m.id for m in all_m}
        hidden = [i for i in g.get("machines", []) if i not in visible]
        g["machines"] = dlg.chosen_ids() + hidden
        # A machine of a group is a machine of the upgrade.
        for mid in g["machines"]:
            if mid in visible and mid not in self._plan["order"]:
                self._plan["order"].append(mid)
        self._commit()

    def _edit_group(self, g: dict) -> None:
        name, ok = QInputDialog.getText(self, "Grupa", "Nazwa grupy:",
                                        text=g["name"])
        if not ok or not name.strip():
            return
        proc, ok = QInputDialog.getText(
            self, "Grupa",
            "Proces usługi (wzorzec pgrep -f), np. java.*WildflyAMMS\n"
            "Puste — bez sprawdzania „wymaga zatrzymanej usługi”:",
            text=g.get("process", ""))
        if not ok:
            return
        g["name"], g["process"] = name.strip(), proc.strip()
        self._commit()

    def _add_group(self) -> None:
        name, ok = QInputDialog.getText(self, "Nowa grupa", "Nazwa grupy:")
        if not ok or not name.strip():
            return
        self._plan["groups"].append({"id": up.new_id(), "name": name.strip(),
                                     "process": "", "machines": [],
                                     "commands": []})
        self._commit()

    def _delete_group(self, g: dict) -> None:
        if not confirm(self, "Usuń grupę",
                       f"Usunąć grupę „{g['name']}” razem z jej komendami?"):
            return
        self._plan["groups"] = [x for x in self._plan["groups"] if x is not g]
        self._commit()

    def _add_command(self, g: dict) -> None:
        dlg = CommandDialog(self, {"label": "", "text": ""}, g)
        if not dlg.exec():
            return
        g["commands"].append({"id": up.new_id(), **dlg.values()})
        self._commit()

    def _command_menu(self, g: dict, c: dict, button) -> None:
        menu = QMenu(self)
        menu.setStyleSheet(_MENU_QSS)
        cmds = g["commands"]
        i = cmds.index(c)
        menu.addAction("Edytuj…", lambda: self._edit_command(g, c))
        a = menu.addAction("Przesuń wcześniej", lambda: self._move_command(g, c, -1))
        a.setEnabled(i > 0)
        a = menu.addAction("Przesuń dalej", lambda: self._move_command(g, c, 1))
        a.setEnabled(i < len(cmds) - 1)
        menu.addSeparator()
        menu.addAction("Usuń", lambda: self._delete_command(g, c))
        menu.exec(button.mapToGlobal(button.rect().bottomLeft()))

    def _edit_command(self, g: dict, c: dict) -> None:
        dlg = CommandDialog(self, c, g)
        if dlg.exec():
            c.update(dlg.values())
            self._commit()

    def _move_command(self, g: dict, c: dict, step: int) -> None:
        cmds = g["commands"]
        i = cmds.index(c)
        j = i + step
        if 0 <= j < len(cmds):
            cmds[i], cmds[j] = cmds[j], cmds[i]
            self._commit()

    def _delete_command(self, g: dict, c: dict) -> None:
        if confirm(self, "Usuń komendę", f"Usunąć przycisk „{c['label']}”?"):
            g["commands"] = [x for x in g["commands"] if x is not c]
            self._commit()
