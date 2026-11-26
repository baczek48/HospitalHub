"""„Scal zmiany z innego vaulta…” — the differences, ticked or not.

Hospital → item (hospital data, a machine, a login…) → its fields; new and
deleted items are rows of their own.  Ticked = take it from the imported
vault; unticked = this vault stays as it is.  The ticks start at
:mod:`vault_merge`'s proposals.  The pane under the list shows the selected
row in full — both values side by side (and the joined text), what its
status means and what the tick does.  Passwords are masked until „Pokaż
hasła”.  Admin items hidden while admin is locked are only counted — they
come over as in the imported file.
"""

from __future__ import annotations

import json

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QBrush, QColor, QFont
from PyQt6.QtWidgets import (
    QCheckBox, QDialog, QHBoxLayout, QHeaderView, QLabel, QPlainTextEdit, QPushButton,
    QSplitter, QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

import vault_merge as vm
import vault_sync as vs

MASK = "••••••"
EMPTY = "(puste)"
_KEY_ROLE = Qt.ItemDataRole.UserRole
_STATUS_COLOURS = {
    vm.NEW: "#3fb950", vm.FILLED: "#3fb950", vm.UPDATE: "#3fb950", vm.EXTENDED: "#3fb950",
    vm.JOINED: "#58a6ff", vm.CONFLICT: "#d29922", vm.REMOVED_THERE: "#f85149",
    vm.REMOVED_HERE: "#8b949e", vm.DECLINED: "#8b949e",
    vm.OLDER: "#8b949e", vm.EMPTY_THERE: "#8b949e",
}
_STATUS_ORDER = (vm.NEW, vm.FILLED, vm.UPDATE, vm.EXTENDED, vm.JOINED, vm.CONFLICT,
                 vm.REMOVED_THERE, vm.REMOVED_HERE, vm.DECLINED)
_GREY = QColor("#8b949e")


def plural(n: int, one: str, few: str, many: str) -> str:
    if n == 1:
        return one
    if n % 10 in (2, 3, 4) and n % 100 not in (12, 13, 14):
        return few
    return many


def _short(value, secret: bool, show_secrets: bool, limit: int = 60) -> str:
    if isinstance(value, bool):
        return "tak" if value else "nie"
    if isinstance(value, (dict, list)):
        if not value:
            return EMPTY
        if isinstance(value, list) and all(isinstance(v, str) for v in value):
            return ", ".join(value)
        return "(ustawienia — zob. szczegóły)"
    text = str(value or "")
    if not text.strip():
        return EMPTY
    if secret and not show_secrets:
        return MASK
    lines = text.splitlines()
    first = lines[0] if lines else text
    more = len(lines) > 1 or len(first) > limit
    return first[:limit] + (" …" if more else "")


def _full(value, secret: bool, show_secrets: bool) -> str:
    if isinstance(value, bool):
        return "tak" if value else "nie"
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, indent=2) if value else EMPTY
    if secret and not show_secrets and value:
        return MASK
    return str(value) if str(value or "").strip() else EMPTY


def _item_summary(item: dict, kind: str, show_secrets: bool) -> str:
    """A whole item (new or deleted) as readable lines, children included."""
    out = []

    def walk(d, k, indent):
        pad = "    " * indent
        out.append(pad + vm.item_label(vs.Node(k, str(d.get("id")), d, None, "", False)))
        for name in vs.SPEC[k]["fields"]:
            value = d.get(name)
            if (k, name) in vs.LOCAL_FIELDS or vm._empty(value) or name == "name":
                continue
            if isinstance(value, bool) and not value:
                continue
            text = _full(value, name in vs.SECRET_FIELDS, show_secrets)
            text = text.replace("\n", "\n" + pad + "      ")
            out.append(f"{pad}  {vm.FIELD_LABELS.get(name, name)}: {text}")
        for child_key, child_kind in vs.SPEC[k]["children"]:
            for c in d.get(child_key) or []:
                walk(c, child_kind, indent + 1)

    walk(item, kind, 0)
    return "\n".join(out)


class _Pane(QWidget):
    """One read-only box with a title — "Twój vault", "Importowany vault"…"""

    def __init__(self, title: str):
        super().__init__()
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(2)
        self.title = QLabel(title)
        self.title.setStyleSheet("color: #8b949e; font-size: 11px;")
        self.text = QPlainTextEdit()
        self.text.setReadOnly(True)
        lay.addWidget(self.title)
        lay.addWidget(self.text)


class VaultMergeDialog(QDialog):
    """`replan(show_admin)` builds the plan again after admin is unlocked;
    `unlock()` asks for the admin password and returns True when unlocked."""

    def __init__(self, parent, source_name: str, plan: vm.Plan, *, replan=None,
                 unlock=None):
        super().__init__(parent)
        self.plan = plan
        self.chosen: set = set()
        self._replan = replan
        self._unlock = unlock
        self._filling = False
        self.setWindowTitle("Scal zmiany z innego vaulta")
        self.resize(1040, 720)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 12)
        lay.setSpacing(6)
        head = QLabel(f"Porównanie Twojego vaulta z importowanym: <b>{source_name}</b>")
        lay.addWidget(head)
        legend = QLabel("<b>Zaznaczone</b> = przejmij z importowanego vaulta. "
                        "<b>Niezaznaczone</b> = zostaje tak, jak jest w Twoim vaulcie. "
                        "Kliknij wiersz, aby zobaczyć szczegóły.")
        legend.setWordWrap(True)
        lay.addWidget(legend)
        self._summary = QLabel()
        self._summary.setWordWrap(True)
        lay.addWidget(self._summary)
        self._quiet = QLabel()
        self._quiet.setWordWrap(True)
        self._quiet.setStyleSheet("color: #8b949e;")
        lay.addWidget(self._quiet)

        admin_row = QHBoxLayout()
        self._admin_note = QLabel()
        self._admin_note.setWordWrap(True)
        self._admin_note.setStyleSheet("color: #c084fc;")
        self._admin_btn = QPushButton("Odblokuj admina, aby je zobaczyć…")
        self._admin_btn.clicked.connect(self._on_unlock)
        admin_row.addWidget(self._admin_note, 1)
        admin_row.addWidget(self._admin_btn)
        lay.addLayout(admin_row)

        opts = QHBoxLayout()
        self._show_secrets = QCheckBox("Pokaż hasła")
        self._show_secrets.toggled.connect(lambda _on: self._fill(keep_ticks=True))
        self._only_conflicts = QCheckBox("Tylko do decyzji (różne wartości i usunięcia)")
        self._only_conflicts.toggled.connect(lambda _on: self._fill(keep_ticks=True))
        skipped = sum(1 for c in plan.visible if c.skipped)
        self._show_skipped = QCheckBox(f"Pokaż pominięte ({skipped})")
        self._show_skipped.setToolTip(
            "Wartości starsze w importowanym vaulcie i pola puste w importowanym — "
            "zostają Twoje; zaznacz wiersz, jeśli jednak chcesz importowaną")
        self._show_skipped.setEnabled(bool(skipped))
        self._show_skipped.toggled.connect(lambda _on: self._fill(keep_ticks=True))
        expand = QPushButton("Rozwiń wszystko")
        expand.clicked.connect(lambda: self._tree.expandAll())
        collapse = QPushButton("Zwiń do szpitali")
        collapse.clicked.connect(lambda: self._tree.collapseAll())
        opts.addWidget(self._show_secrets)
        opts.addWidget(self._only_conflicts)
        opts.addWidget(self._show_skipped)
        opts.addStretch(1)
        opts.addWidget(expand)
        opts.addWidget(collapse)
        lay.addLayout(opts)

        self._tree = QTreeWidget()
        self._tree.setColumnCount(4)
        self._tree.setHeaderLabels(["Element / pole", "Zmiana", "Twój vault",
                                    "Importowany vault"])
        self._tree.setUniformRowHeights(True)
        self._tree.setAlternatingRowColors(True)
        header = self._tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col, width in ((1, 150), (2, 230), (3, 230)):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
            header.resizeSection(col, width)
        header.setStretchLastSection(False)
        self._tree.itemChanged.connect(self._on_item_changed)
        self._tree.currentItemChanged.connect(lambda cur, _prev: self._show_details(cur))

        details = QWidget()
        dl = QVBoxLayout(details)
        dl.setContentsMargins(0, 4, 0, 0)
        dl.setSpacing(4)
        self._detail_head = QLabel()
        self._detail_head.setWordWrap(True)
        self._detail_head.setTextFormat(Qt.TextFormat.RichText)
        dl.addWidget(self._detail_head)
        boxes = QHBoxLayout()
        self._mine_pane = _Pane("Twój vault")
        self._theirs_pane = _Pane("Importowany vault")
        self._joined_pane = _Pane("Po scaleniu (jeśli zaznaczone)")
        for pane in (self._mine_pane, self._theirs_pane, self._joined_pane):
            boxes.addWidget(pane)
        dl.addLayout(boxes, 1)

        split = QSplitter(Qt.Orientation.Vertical)
        split.addWidget(self._tree)
        split.addWidget(details)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 1)
        split.setSizes([430, 170])
        lay.addWidget(split, 1)

        buttons = QHBoxLayout()
        take_all = QPushButton("Przyjmij wszystko z importowanego")
        take_all.setToolTip("Zaznacza każdą zmianę na liście, także usunięcia")
        take_all.clicked.connect(lambda: self._tick_all(True))
        none = QPushButton("Odznacz wszystko")
        none.setToolTip("Nic nie zostanie przejęte — Twój vault bez zmian")
        none.clicked.connect(lambda: self._tick_all(False))
        defaults = QPushButton("Domyślne")
        defaults.setToolTip("Zaznaczenia zaproponowane przez HospitalHub")
        defaults.clicked.connect(self._defaults)
        self._ok = QPushButton()
        self._ok.setDefault(True)
        self._ok.clicked.connect(self._accept)
        cancel = QPushButton("Anuluj")
        cancel.clicked.connect(self.reject)
        buttons.addWidget(take_all)
        buttons.addWidget(none)
        buttons.addWidget(defaults)
        buttons.addStretch(1)
        buttons.addWidget(self._ok)
        buttons.addWidget(cancel)
        lay.addLayout(buttons)

        self._by_key = {}
        self._expanded: set = set()          # nodes the user opened; start closed
        self._ticks = {c.key: c.default for c in plan.visible}
        self._fill()

    # -- content --------------------------------------------------------- #

    def _cells(self, ch: vm.Change):
        """(text, mine, theirs) of a row."""
        show = self._show_secrets.isChecked()
        if ch.action == "field":
            return (vm.FIELD_LABELS.get(ch.field, ch.field),
                    _short(ch.mine, ch.secret, show), _short(ch.theirs, ch.secret, show))
        extra = f" (+{ch.count - 1} w środku)" if ch.count > 1 else ""
        title = ch.title or ch.label
        if ch.action == "add":
            name = "Cały szpital" if ch.kind == "hospital" else title
            return name + extra, "—", "jest"
        return title + extra, "jest", "—"

    def _row(self, ch: vm.Change) -> QTreeWidgetItem:
        text, mine, theirs = self._cells(ch)
        if ch.admin and ch.action != "field":
            text = "[admin] " + text
        row = QTreeWidgetItem([text, vm.STATUS_LABELS[ch.status], mine, theirs])
        row.setData(0, _KEY_ROLE, ch.key)
        row.setFlags(row.flags() | Qt.ItemFlag.ItemIsUserCheckable)
        row.setForeground(1, QBrush(QColor(_STATUS_COLOURS[ch.status])))
        for col, value in ((2, mine), (3, theirs)):
            if value in (EMPTY, "—"):
                row.setForeground(col, QBrush(_GREY))
        return row

    def _node_key(self, item) -> str | None:
        return item.data(0, _KEY_ROLE + 1) if item is not None else None

    def _remember_expanded(self):
        if self._tree.topLevelItemCount() == 0:
            return
        self._expanded = set()

        def walk(item):
            for i in range(item.childCount()):
                child = item.child(i)
                if child.isExpanded() and self._node_key(child):
                    self._expanded.add(self._node_key(child))
                walk(child)
        walk(self._tree.invisibleRootItem())

    def _fill(self, keep_ticks: bool = False):
        if keep_ticks:
            self._collect()
        self._remember_expanded()
        current = self._tree.currentItem()
        current_key = current.data(0, _KEY_ROLE) if current else None
        self._filling = True
        self._tree.blockSignals(True)
        self._tree.clear()
        self._by_key = {}
        only = self._only_conflicts.isChecked()
        show_skipped = self._show_skipped.isChecked()
        bold = QFont()
        bold.setBold(True)
        nodes: dict[tuple, QTreeWidgetItem] = {}
        counts: dict[str, int] = {}

        def node(key: tuple, label: str, parent, admin: bool):
            item = nodes.get(key)
            if item is None:
                item = QTreeWidgetItem([("[admin] " if admin else "") + label, "", "", ""])
                item.setData(0, _KEY_ROLE + 1, "/".join(key))
                item.setFlags(item.flags() | Qt.ItemFlag.ItemIsAutoTristate
                              | Qt.ItemFlag.ItemIsUserCheckable)
                if parent is None:
                    item.setFont(0, bold)
                    self._tree.addTopLevelItem(item)
                else:
                    parent.addChild(item)
                nodes[key] = item
            return item

        for ch in self.plan.visible:
            if ch.skipped and not show_skipped:
                continue
            if only and ch.status not in (vm.CONFLICT, vm.REMOVED_THERE):
                continue
            parent = node((ch.group,), ch.group, None, False)
            if not ch.skipped:
                counts[ch.group] = counts.get(ch.group, 0) + 1
            key = (ch.group,)
            # One node per machine / login on the way: each machine once,
            # its logins under it (2026-11-25, owner).
            for item_id, label in ch.path:
                key += (item_id,)
                parent = node(key, label, parent, ch.admin)
            if ch.action == "field" and not ch.path:
                parent = node(key + ("__hospital__",), "Dane szpitala", parent, False)
            row = self._row(ch)
            parent.addChild(row)
            # After addChild: the item's and the hospital's ticks follow.
            row.setCheckState(0, Qt.CheckState.Checked if self._ticks.get(ch.key)
                              else Qt.CheckState.Unchecked)
            self._by_key[ch.key] = (row, ch)
        for i in range(self._tree.topLevelItemCount()):
            group = self._tree.topLevelItem(i)
            n = counts.get(group.text(0), 0)
            group.setText(1, f"{n} {plural(n, 'zmiana', 'zmiany', 'zmian')}" if n
                          else "tylko pominięte")
            group.setForeground(1, QBrush(_GREY))
        for item in nodes.values():
            item.setExpanded(self._node_key(item) in self._expanded)
        self._tree.blockSignals(False)
        self._filling = False
        if current_key in self._by_key:
            row = self._by_key[current_key][0]
            parent = row.parent()
            while parent is not None:
                parent.setExpanded(True)
                parent = parent.parent()
            self._tree.setCurrentItem(row)
        else:
            self._show_details(None)
        self._update_texts()

    def _collect(self):
        for key, (row, _ch) in self._by_key.items():
            self._ticks[key] = row.checkState(0) == Qt.CheckState.Checked

    def _on_item_changed(self, item, column):
        if self._filling or column != 0:
            return
        self._collect()
        self._update_texts()

    # -- details --------------------------------------------------------- #

    def _show_details(self, row):
        key = row.data(0, _KEY_ROLE) if row is not None else None
        entry = self._by_key.get(key)
        if entry is None:
            self._detail_head.setText("<span style='color:#8b949e'>Kliknij wiersz z "
                                      "checkboxem, aby zobaczyć obie wartości.</span>")
            for pane in (self._mine_pane, self._theirs_pane):
                pane.text.setPlainText("")
            self._joined_pane.hide()
            return
        ch = entry[1]
        show = self._show_secrets.isChecked()
        colour = _STATUS_COLOURS[ch.status]
        where = ch.label if ch.action != "field" else (
            f"{ch.label} › {vm.FIELD_LABELS.get(ch.field, ch.field)}")
        self._detail_head.setText(
            f"<b>{ch.group}</b> › {where} — <span style='color:{colour}'>"
            f"{vm.STATUS_LABELS[ch.status]}</span><br>{vm.STATUS_HELP[ch.status]}")
        if ch.action == "field":
            self._mine_pane.text.setPlainText(_full(ch.mine, ch.secret, show))
            self._theirs_pane.text.setPlainText(_full(ch.theirs, ch.secret, show))
            joined = ch.status == vm.JOINED
            self._joined_pane.setVisible(joined)
            if joined:
                self._joined_pane.text.setPlainText(_full(ch.proposed, ch.secret, show))
        elif ch.action == "add":
            self._mine_pane.text.setPlainText("(brak)")
            self._theirs_pane.text.setPlainText(_item_summary(ch.theirs, ch.kind, show))
            self._joined_pane.hide()
        else:
            self._mine_pane.text.setPlainText(_item_summary(ch.mine, ch.kind, show))
            self._theirs_pane.text.setPlainText("(usunięty)")
            self._joined_pane.hide()

    def _update_texts(self):
        visible = [c for c in self.plan.visible if not c.skipped]
        counts = {}
        for ch in visible:
            counts[ch.status] = counts.get(ch.status, 0) + 1
        parts = [f"{vm.STATUS_LABELS[s]}: {counts[s]}" for s in _STATUS_ORDER
                 if counts.get(s)]
        self._summary.setText("Na liście — " + " · ".join(parts) if parts
                              else "Brak różnic do wyboru.")
        quiet = []
        if self.plan.older_there:
            quiet.append(f"starsze wartości w importowanym (zostają Twoje): "
                         f"{self.plan.older_there}")
        if self.plan.empty_there:
            quiet.append(f"pola puste w importowanym (zostają Twoje): "
                         f"{self.plan.empty_there}")
        if self.plan.only_here:
            quiet.append(f"elementy tylko w Twoim vaulcie (zostają): {self.plan.only_here}")
        if quiet and (self.plan.older_there or self.plan.empty_there):
            quiet[-1] += " — szczegóły: „Pokaż pominięte”"
        self._quiet.setText("Pominięte: " + " · ".join(quiet) if quiet else "")
        self._quiet.setVisible(bool(quiet))
        hidden = self.plan.hidden
        if hidden:
            taken = sum(1 for c in hidden if c.auto)
            left = len(hidden) - taken
            note = (f"Elementy admina: {taken} "
                    f"{plural(taken, 'zmiana zostanie przejęta', 'zmiany zostaną przejęte', 'zmian zostanie przejętych')}"
                    f" z importowanego vaulta bez podglądu")
            note += (f"; usunięcia z importowanego vaulta pominięte ({left}) — bez hasła "
                     f"admina nic nie jest usuwane." if left else ".")
            self._admin_note.setText(note)
        self._admin_note.setVisible(bool(hidden))
        self._admin_btn.setVisible(bool(hidden) and self._unlock is not None)
        ticked = sum(1 for c in self.plan.visible if self._ticks.get(c.key))
        self._ok.setText(f"Scal zaznaczone ({ticked})" if visible else "Scal")

    # -- actions --------------------------------------------------------- #

    def _tick_all(self, on: bool):
        self._collect()
        for ch in self.plan.visible:
            self._ticks[ch.key] = on
        self._fill()

    def _defaults(self):
        self._ticks = {c.key: c.default for c in self.plan.visible}
        self._fill()

    def _on_unlock(self):
        if self._unlock is None or not self._unlock():
            return
        self._collect()
        old = dict(self._ticks)
        self.plan = self._replan(True)
        self._ticks = {c.key: old.get(c.key, c.default) for c in self.plan.visible}
        self._fill()

    def _accept(self):
        self._collect()
        self.chosen = {k for k, on in self._ticks.items() if on}
        self.accept()
