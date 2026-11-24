"""„Scal zmiany z innego vaulta…” — the differences, ticked or not.

One row per difference, grouped by hospital (VPN: one group).  Ticked =
apply it; the ticks start at :mod:`vault_merge`'s proposals.  Passwords are
masked until „Pokaż hasła”.  Admin items hidden while admin is locked are
only counted — they come over as in the colleague's file.
"""

from __future__ import annotations

import json

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QBrush, QColor, QFont
from PyQt6.QtWidgets import (
    QCheckBox, QDialog, QHBoxLayout, QHeaderView, QLabel, QPushButton, QTreeWidget,
    QTreeWidgetItem, QVBoxLayout,
)

import vault_merge as vm

MASK = "••••••"
_KEY_ROLE = Qt.ItemDataRole.UserRole
_STATUS_COLOURS = {
    vm.NEW: "#3fb950", vm.UPDATE: "#3fb950", vm.JOINED: "#58a6ff",
    vm.CONFLICT: "#d29922", vm.REMOVED_THERE: "#f85149",
    vm.REMOVED_HERE: "#8b949e", vm.DECLINED: "#8b949e",
}


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
            return "(puste)"
        return "lista: " + ", ".join(map(str, value)) if isinstance(value, list) \
            and all(isinstance(v, str) for v in value) else "(ustawienia — zob. podpowiedź)"
    text = str(value or "")
    if not text:
        return "(puste)"
    if secret and not show_secrets:
        return MASK
    first = text.splitlines()[0] if text.splitlines() else text
    more = len(text.splitlines()) > 1 or len(first) > limit
    return (first[:limit] + (" …" if more else ""))


def _full(value, secret: bool, show_secrets: bool) -> str:
    if isinstance(value, (dict, list)):
        return json.dumps(value, ensure_ascii=False, indent=2)
    if secret and not show_secrets and value:
        return MASK
    return str(value if value not in (None, "") else "(puste)")


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
        self.setWindowTitle("Scal zmiany z innego vaulta")
        self.resize(980, 620)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 14, 16, 12)
        lay.setSpacing(8)
        head = QLabel(f"Porównanie Twojego vaulta z: <b>{source_name}</b>")
        lay.addWidget(head)
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
        self._only_conflicts = QCheckBox("Tylko do decyzji (różnice i usunięcia)")
        self._only_conflicts.toggled.connect(lambda _on: self._fill(keep_ticks=True))
        opts.addWidget(self._show_secrets)
        opts.addWidget(self._only_conflicts)
        opts.addStretch(1)
        lay.addLayout(opts)

        self._tree = QTreeWidget()
        self._tree.setColumnCount(4)
        self._tree.setHeaderLabels(["Element / pole", "Zmiana", "U Ciebie", "U kolegi"])
        self._tree.setUniformRowHeights(True)
        self._tree.setAlternatingRowColors(True)
        header = self._tree.header()
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        for col, width in ((1, 150), (2, 210), (3, 210)):
            header.setSectionResizeMode(col, QHeaderView.ResizeMode.Interactive)
            header.resizeSection(col, width)
        header.setStretchLastSection(False)
        self._tree.itemChanged.connect(self._on_item_changed)
        lay.addWidget(self._tree, 1)

        buttons = QHBoxLayout()
        take_all = QPushButton("Przyjmij wszystko od kolegi")
        take_all.setToolTip("Zaznacza każdą zmianę na liście, także usunięcia")
        take_all.clicked.connect(lambda: self._tick_all(True))
        defaults = QPushButton("Domyślne")
        defaults.setToolTip("Zaznaczenia zaproponowane przez HospitalHub")
        defaults.clicked.connect(self._defaults)
        self._ok = QPushButton()
        self._ok.setDefault(True)
        self._ok.clicked.connect(self._accept)
        cancel = QPushButton("Anuluj")
        cancel.clicked.connect(self.reject)
        buttons.addWidget(take_all)
        buttons.addWidget(defaults)
        buttons.addStretch(1)
        buttons.addWidget(self._ok)
        buttons.addWidget(cancel)
        lay.addLayout(buttons)

        self._ticks = {c.key: c.default for c in plan.visible}
        self._fill()

    # -- content --------------------------------------------------------- #

    def _texts(self, ch: vm.Change):
        show = self._show_secrets.isChecked()
        name = ch.label
        if ch.action == "field":
            name = f"{ch.label} › {vm.FIELD_LABELS.get(ch.field, ch.field)}"
            mine = _short(ch.mine, ch.secret, show)
            theirs = _short(ch.theirs, ch.secret, show)
            tip = (f"U Ciebie:\n{_full(ch.mine, ch.secret, show)}\n\n"
                   + ("Po połączeniu:\n" + _full(ch.proposed, ch.secret, show) + "\n\n"
                      if ch.status == vm.JOINED else "")
                   + f"U kolegi:\n{_full(ch.theirs, ch.secret, show)}")
        elif ch.action == "add":
            extra = f" (+{ch.count - 1} w środku)" if ch.count > 1 else ""
            if ch.kind == "hospital":
                name = "Cały szpital"
            name += extra
            mine, theirs = "—", "jest"
            tip = "Zaznaczone: zostanie dodane do Twojego vaulta."
        else:
            extra = f" (+{ch.count - 1} w środku)" if ch.count > 1 else ""
            name += extra
            mine, theirs = "jest", "—"
            tip = "Zaznaczone: zostanie usunięte z Twojego vaulta."
        if ch.admin:
            name = "[admin] " + name
        return name, vm.STATUS_LABELS[ch.status], mine, theirs, tip

    def _fill(self, keep_ticks: bool = False):
        if keep_ticks:
            self._collect()
        self._tree.blockSignals(True)
        self._tree.clear()
        only = self._only_conflicts.isChecked()
        groups: dict[str, QTreeWidgetItem] = {}
        bold = QFont()
        bold.setBold(True)
        for ch in self.plan.visible:
            if only and ch.status not in (vm.CONFLICT, vm.REMOVED_THERE):
                continue
            group = groups.get(ch.group)
            if group is None:
                group = QTreeWidgetItem([ch.group, "", "", ""])
                group.setFont(0, bold)
                group.setFlags(group.flags() | Qt.ItemFlag.ItemIsAutoTristate
                               | Qt.ItemFlag.ItemIsUserCheckable)
                self._tree.addTopLevelItem(group)
                groups[ch.group] = group
            name, status, mine, theirs, tip = self._texts(ch)
            row = QTreeWidgetItem([name, status, mine, theirs])
            row.setData(0, _KEY_ROLE, ch.key)
            row.setFlags(row.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            row.setForeground(1, QBrush(QColor(_STATUS_COLOURS[ch.status])))
            for col in range(4):
                row.setToolTip(col, tip)
            group.addChild(row)
            # After addChild: the group's tick follows its rows.
            row.setCheckState(0, Qt.CheckState.Checked if self._ticks.get(ch.key)
                              else Qt.CheckState.Unchecked)
        self._tree.expandAll()
        self._tree.blockSignals(False)
        self._update_texts()

    def _collect(self):
        root = self._tree.invisibleRootItem()
        for i in range(root.childCount()):
            group = root.child(i)
            for j in range(group.childCount()):
                row = group.child(j)
                self._ticks[row.data(0, _KEY_ROLE)] = (
                    row.checkState(0) == Qt.CheckState.Checked)

    def _on_item_changed(self, item, column):
        if column == 0 and item.data(0, _KEY_ROLE):
            self._ticks[item.data(0, _KEY_ROLE)] = (
                item.checkState(0) == Qt.CheckState.Checked)
            self._update_texts()

    def _update_texts(self):
        visible = self.plan.visible
        counts = {}
        for ch in visible:
            counts[ch.status] = counts.get(ch.status, 0) + 1
        order = (vm.NEW, vm.UPDATE, vm.JOINED, vm.CONFLICT, vm.REMOVED_THERE,
                 vm.REMOVED_HERE, vm.DECLINED)
        parts = [f"{vm.STATUS_LABELS[s]}: {counts[s]}" for s in order if counts.get(s)]
        self._summary.setText(" · ".join(parts) if parts else "Brak różnic do wyboru.")
        quiet = []
        if self.plan.older_there:
            quiet.append(f"starsze dane u kolegi (pominięte, zostają Twoje): "
                         f"{self.plan.older_there}")
        if self.plan.only_here:
            quiet.append(f"Twoje elementy, których kolega nie ma (zostają): "
                         f"{self.plan.only_here}")
        self._quiet.setText(" · ".join(quiet).capitalize() if quiet else "")
        self._quiet.setVisible(bool(quiet))
        hidden = self.plan.hidden
        if hidden:
            taken = sum(1 for c in hidden if c.auto)
            left = len(hidden) - taken
            note = (f"Elementy admina: {taken} "
                    f"{plural(taken, 'zmiana zostanie przejęta', 'zmiany zostaną przejęte', 'zmian zostanie przejętych')}"
                    f" z pliku kolegi bez podglądu")
            note += (f"; usunięcia u kolegi pominięte ({left}) — bez hasła admina nic nie "
                     f"jest usuwane." if left else ".")
            self._admin_note.setText(note)
        self._admin_note.setVisible(bool(hidden))
        self._admin_btn.setVisible(bool(hidden) and self._unlock is not None)
        ticked = sum(1 for c in visible if self._ticks.get(c.key))
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
