"""The "SI" tab of HospitalHub Portable (owner, 2026-11-19): the Serwer
Integracji modules on one hospital machine.

* the machine and the modules' folder (``/opt/asseco``) are kept with the
  hospital in the vault (``Hospital.si``);
* "Odśwież" lists the modules (one folder each, ``old`` skipped) with the
  version from their env files and their containers' state;
* Uruchom / Zatrzymaj / Restart / Pobierz obrazy run ``docker compose`` in
  the ticked modules' folders, in the start order of the Asseco guide (stop
  backwards), and show the output here with ✓ / ✗ per module;
* "Logi" shows the last lines of one module; "Na żywo" opens one terminal
  tab per ticked module (or brings it back) and follows its logs there —
  and after Uruchom / Restart the same happens by itself (owner, 2026-11-19:
  "żebym widział na bieżąco co się dzieje"), unless switched off.

Each run is its own SSH connection with one exec channel (``si_docker``
builds the scripts); the session tabs are not touched.
"""

from __future__ import annotations

import shlex
import time

from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QFont
from PyQt6.QtWidgets import (
    QCheckBox, QComboBox, QHBoxLayout, QHeaderView, QLabel, QLineEdit, QPlainTextEdit,
    QPushButton, QSizePolicy, QSplitter, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)

import si_docker as sd
from ui.icons import set_icon
from ui.utils import confirm

__all__ = ["SiPanel", "SiWorker"]


_BTN_QSS = (
    "QPushButton {{ background:{bg}; color:{fg}; border:1px solid {border};"
    " border-radius:6px; padding:5px 8px; font-size:11px; }}"
    "QPushButton:hover {{ background:{hover}; color:#fff; }}"
    "QPushButton:disabled {{ color:#5a5f72; }}"
)
_CMD_QSS = _BTN_QSS.format(bg="#1a2040", fg="#a5b4ff", border="#3a4070",
                           hover="#4a5adf")
_DANGER_QSS = _BTN_QSS.format(bg="#2a1a1a", fg="#ff9b8f", border="#5a2d2d",
                              hover="#b33a3a")
_GREEN_QSS = _BTN_QSS.format(bg="#0d1f0d", fg="#3fb950", border="#1b3d1b",
                             hover="#2d5a2d")
_GREY_QSS = _BTN_QSS.format(bg="#151b23", fg="#8b949e", border="#21262d",
                            hover="#30363d")
_FIELD_QSS = (
    "QLineEdit, QComboBox { background:#14161e; border:1px solid #2a2d3a;"
    " border-radius:6px; padding:4px 6px; color:#c9d1d9; }"
    "QLineEdit:focus, QComboBox:focus { border-color:#4a5adf; }"
)
# Rows, header, scroll bars: the Portable list look (ui/list_style.py).
_TREE_QSS = (
    "QTreeWidget { font-size:11px; }"
    # Our own box: the native one vanished on a selected row in the light
    # theme (owner, 2026-11-19).  Ticked = filled blue, on any background.
    "QTreeWidget::indicator { width:12px; height:12px; border-radius:3px;"
    " border:1px solid #8b949e; background:#14161e; }"
    "QTreeWidget::indicator:checked { background:#4a5adf;"
    " border:1px solid #a5b4ff; }"
    "QHeaderView::section { font-size:10px; padding:4px 6px; }"
)
_OUT_QSS = (
    "QPlainTextEdit { background:#0d1117; border:1px solid #2a2d3a;"
    " border-radius:6px; color:#c9d1d9; padding:4px; }"
)

#: module state → (mark, colour, words)
STATE_LOOK = {
    "ok":   ("●", "#3fb950", "działa"),
    "warn": ("●", "#d29922", "uwaga"),
    "down": ("●", "#f85149", "zatrzymany"),
    "none": ("○", "#8b949e", "brak kontenerów"),
}
PRIV_WORDS = {
    "root": "root",
    "docker": "grupa docker",
    "sudo-n": "sudo (bez hasła)",
    "sudo-pw": "sudo (hasło z vaulta)",
}


def _shrinkable(w):
    w.setSizePolicy(QSizePolicy.Policy.Ignored, QSizePolicy.Policy.Fixed)
    w.setMinimumWidth(40)
    return w


def machine_port(machine) -> tuple[str, int]:
    """``host`` or ``host:port`` from the machine's address."""
    ip = (getattr(machine, "ip", "") or "").strip()
    if ip.count(":") == 1:
        host, _, port = ip.partition(":")
        if port.isdigit():
            return host, int(port)
    return ip, 22


def machine_credential(machine, admin_unlocked: bool):
    """The credential a session tab would use: the first visible one."""
    creds = [c for c in getattr(machine, "credentials", []) or []
             if admin_unlocked or not c.admin_only]
    return creds[0] if creds else None


class SiWorker(QThread):
    """One SSH connection: find the rights, run the script, stream the
    output.  ``kind`` is ``scan`` or an action of ``si_docker.ACTIONS``."""

    line = pyqtSignal(str)
    #: (privilege mode, the whole output, exit code)
    done = pyqtSignal(str, str, int)
    failed = pyqtSignal(str)

    def __init__(self, host, port, user, password, root, kind,
                 names=None, tail=300, client_factory=None):
        super().__init__()
        self._host, self._port = host, port
        self._user, self._pw = user, password
        self._root, self._kind = root, kind
        self._names = list(names or [])
        self._tail = tail
        self._factory = client_factory
        self._chan = None
        self._cancel = False

    def cancel(self) -> None:
        self._cancel = True
        ch = self._chan
        if ch is not None:
            try:
                ch.close()
            except Exception:
                pass

    def _client(self):
        if self._factory is not None:
            return self._factory(self._host, self._user, self._pw, self._port)
        from ui.ssh_panel import _make_client
        return _make_client(self._host, self._user, self._pw, self._port)

    @staticmethod
    def _exec_simple(client, cmd: str) -> str:
        _, out, _ = client.exec_command(cmd, timeout=15)
        return out.read().decode("utf-8", errors="replace")

    def run(self):
        client = None
        try:
            client = self._client()
            mode = sd.parse_privilege(self._exec_simple(client, sd.privilege_probe()))
            if mode == "sudo-pw" and not self._pw:
                self.failed.emit("Użytkownik nie jest rootem, a sudo wymaga "
                                 "hasła — brak hasła w vaulcie.")
                return
            if self._kind == "scan":
                script = sd.scan_script(self._root)
            else:
                script = sd.action_script(self._root, self._names, self._kind,
                                          tail=self._tail)
            chan = client.get_transport().open_session()
            self._chan = chan
            chan.set_combine_stderr(True)
            chan.exec_command(sd.wrap(script, mode))
            if mode == "sudo-pw":
                chan.sendall((self._pw + "\n").encode("utf-8"))
            chan.shutdown_write()
            buf = b""
            chunks = []
            stream = self._kind != "scan"
            while True:
                data = chan.recv(65536)
                if not data:
                    break
                chunks.append(data)
                if stream:
                    buf += data
                    *lines, buf = buf.split(b"\n")
                    for ln in lines:
                        self.line.emit(ln.decode("utf-8", errors="replace")
                                       .rstrip("\r"))
            if stream and buf:
                self.line.emit(buf.decode("utf-8", errors="replace").rstrip("\r"))
            code = chan.recv_exit_status()
            if self._cancel:
                self.failed.emit("Przerwano.")
                return
            text = b"".join(chunks).decode("utf-8", errors="replace")
            self.done.emit(mode, text, code)
        except Exception as e:  # noqa: BLE001 — shown to the user
            if self._cancel:
                self.failed.emit("Przerwano.")
            else:
                msg = str(e) or type(e).__name__
                self.failed.emit(f"Błąd połączenia z {self._host}: {msg}")
        finally:
            self._chan = None
            if client is not None:
                try:
                    client.close()
                except Exception:
                    pass


class SiPanel(QWidget):
    data_changed = pyqtSignal()
    #: (machine, [(module, command), …]) — one terminal tab per module
    #: following its logs (the window opens or reuses the tabs)
    follow_requested = pyqtSignal(object, list)
    #: "Rejestr paczek HL7…" — the window opens it
    hl7_requested = pyqtSignal()

    def __init__(self, hospital=None, admin_unlocked: bool = False,
                 parent=None, client_factory=None):
        super().__init__(parent)
        self._hospital = None
        self._admin_unlocked = admin_unlocked
        self._factory = client_factory
        self._worker: SiWorker | None = None
        self._modules: list = []
        self._other: list = []
        self._mode = ""
        self._results: dict[str, int] = {}
        self._loading = False
        self._last_names: list = []
        self._rescan = False

        root = QVBoxLayout(self)
        root.setContentsMargins(8, 8, 8, 8)
        root.setSpacing(6)

        row = QHBoxLayout()
        row.addWidget(self._small("Maszyna:"))
        self._machine = QComboBox()
        self._machine.setStyleSheet(_FIELD_QSS)
        self._machine.setSizePolicy(QSizePolicy.Policy.Ignored,
                                    QSizePolicy.Policy.Fixed)
        self._machine.currentIndexChanged.connect(self._machine_changed)
        row.addWidget(self._machine, 1)
        root.addLayout(row)

        row = QHBoxLayout()
        row.addWidget(self._small("Folder:"))
        self._root = QLineEdit(sd.DEFAULT_ROOT)
        self._root.setStyleSheet(_FIELD_QSS)
        self._root.setToolTip("Katalog z modułami Serwera Integracji "
                              "(jeden podkatalog na moduł; „old” pomijany)")
        self._root.editingFinished.connect(self._root_edited)
        row.addWidget(self._root, 1)
        self._refresh_btn = QPushButton("Odśwież")
        self._refresh_btn.setStyleSheet(_GREY_QSS)
        set_icon(self._refresh_btn, "refresh", "#8b949e", size=14)
        self._refresh_btn.clicked.connect(self.scan)
        row.addWidget(self._refresh_btn)
        root.addLayout(row)

        self._info = QLabel("Wybierz maszynę z Serwerem Integracji i kliknij Odśwież.")
        self._info.setWordWrap(True)
        self._info.setStyleSheet("color:#8b949e; font-size:10px;")
        root.addWidget(self._info)

        split = QSplitter(Qt.Orientation.Vertical)
        split.setChildrenCollapsible(False)

        self._tree = QTreeWidget()
        self._tree.setColumnCount(3)
        self._tree.setHeaderLabels(["Moduł", "Wersja", "Stan"])
        self._tree.setStyleSheet(_TREE_QSS)
        self._tree.setRootIsDecorated(True)
        self._tree.setUniformRowHeights(True)
        h = self._tree.header()
        h.setStretchLastSection(True)
        h.setSectionResizeMode(0, QHeaderView.ResizeMode.Interactive)
        self._tree.setColumnWidth(0, 165)
        self._tree.setColumnWidth(1, 70)
        self._tree.itemChanged.connect(self._item_checked)
        self._tree.currentItemChanged.connect(lambda *_: self._update_buttons())
        split.addWidget(self._tree)

        self._out = QPlainTextEdit()
        self._out.setReadOnly(True)
        self._out.setMaximumBlockCount(6000)
        self._out.setStyleSheet(_OUT_QSS)
        f = QFont("Consolas")
        f.setStyleHint(QFont.StyleHint.Monospace)
        f.setPointSize(9)
        self._out.setFont(f)
        self._out.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        split.addWidget(self._out)
        split.setSizes([300, 200])
        root.addWidget(split, 1)

        row = QHBoxLayout()
        row.setSpacing(4)
        self._all_btn = QPushButton("Zaznacz wszystkie")
        self._all_btn.setStyleSheet(_GREY_QSS)
        self._all_btn.clicked.connect(self._toggle_all)
        row.addWidget(self._all_btn)
        self._picked = QLabel("")
        self._picked.setStyleSheet("color:#8b949e; font-size:10px;")
        row.addWidget(self._picked, 1)
        root.addLayout(row)

        grid1 = QHBoxLayout()
        grid1.setSpacing(4)
        self._btn_start = self._action_btn("Uruchom", "play", "#3fb950",
                                           _GREEN_QSS, "start")
        self._btn_stop = self._action_btn("Zatrzymaj", "stop", "#ff9b8f",
                                          _DANGER_QSS, "stop")
        self._btn_restart = self._action_btn("Restart", "refresh", "#ff9b8f",
                                             _DANGER_QSS, "restart")
        for b in (self._btn_start, self._btn_stop, self._btn_restart):
            grid1.addWidget(b)
        root.addLayout(grid1)

        # Before an upgrade: stop + a copy of the folders in old/ (owner's
        # order, 2026-11-19); the new files go in by hand, then Odśwież →
        # Pobierz → Uruchom.
        self._btn_archive = self._action_btn(
            "Zatrzymaj i zarchiwizuj (przed aktualizacją)", "stop", "#ff9b8f",
            _DANGER_QSS, "stop_archive")
        self._btn_archive.setToolTip(
            "Zatrzymuje zaznaczone moduły i kopiuje ich foldery do "
            "/opt/old/<moduł>_<data-godzina>. Potem wgraj nowe pliki z Kreatora "
            "i kliknij Odśwież → Pobierz → Uruchom.")
        root.addWidget(self._btn_archive)

        grid2 = QHBoxLayout()
        grid2.setSpacing(4)
        self._btn_pull = self._action_btn("Pobierz", "download",
                                          "#a5b4ff", _CMD_QSS, "pull")
        self._btn_pull.setToolTip("Pobierz obrazy z rejestru (docker compose "
                                  "pull) — moduły działają dalej")
        self._btn_logs = self._action_btn("Logi", "file", "#a5b4ff",
                                          _CMD_QSS, "logs")
        self._btn_follow = _shrinkable(QPushButton("Na żywo"))
        self._btn_follow.setStyleSheet(_CMD_QSS)
        set_icon(self._btn_follow, "eye", "#a5b4ff", size=14)
        self._btn_follow.setToolTip("Każdy zaznaczony moduł w osobnej karcie "
                                    "terminala: docker compose logs -f "
                                    "--tail=100 (karta już otwarta: Ctrl+C "
                                    "i tail od nowa)")
        self._btn_follow.clicked.connect(self._follow)
        self._btn_cancel = _shrinkable(QPushButton("Przerwij"))
        self._btn_cancel.setStyleSheet(_GREY_QSS)
        self._btn_cancel.clicked.connect(self._cancel)
        for b in (self._btn_pull, self._btn_logs, self._btn_follow,
                  self._btn_cancel):
            grid2.addWidget(b)
        root.addLayout(grid2)

        self._auto_follow = QCheckBox("Po Uruchom / Restart pokaż logi w terminalu")
        self._auto_follow.setChecked(True)
        self._auto_follow.setStyleSheet("color:#c9d1d9; font-size:11px;")
        self._auto_follow.setToolTip(
            "Po udanym uruchomieniu lub restarcie każdy moduł dostaje swoją "
            "kartę terminala z logami na żywo")
        self._auto_follow.toggled.connect(lambda _=False: self._store())
        root.addWidget(self._auto_follow)

        self._hl7_btn = QPushButton("Rejestr paczek HL7…")
        self._hl7_btn.setStyleSheet(_CMD_QSS)
        set_icon(self._hl7_btn, "search", "#a5b4ff", size=14)
        self._hl7_btn.setToolTip("Paczki zlecenia z bazy AMMS, ze statusami "
                                 "i ACK (Ctrl+Shift+H)")
        self._hl7_btn.clicked.connect(self.hl7_requested.emit)
        root.addWidget(self._hl7_btn)

        if hospital is not None:
            self.set_hospital(hospital)
        self._update_buttons()

    # ── Building blocks ───────────────────────────────────────────────────

    @staticmethod
    def _small(text: str) -> QLabel:
        lbl = QLabel(text)
        lbl.setStyleSheet("color:#c9d1d9; font-size:11px;")
        return lbl

    def _action_btn(self, text, icon_name, color, qss, action) -> QPushButton:
        b = _shrinkable(QPushButton(text))
        b.setStyleSheet(qss)
        set_icon(b, icon_name, color, size=14)
        b.clicked.connect(lambda _=False, a=action: self.run_action(a))
        return b

    # ── What the window calls ─────────────────────────────────────────────

    def set_hospital(self, hospital) -> None:
        self._hospital = hospital
        self._modules, self._other, self._mode = [], [], ""
        self._results.clear()
        si = getattr(hospital, "si", None) or {}
        self._root.setText(si.get("root") or sd.DEFAULT_ROOT)
        self._loading = True
        self._auto_follow.setChecked(si.get("follow_after", True) is not False)
        self._loading = False
        self._fill_machines(si.get("machine", ""))
        self._fill_tree()
        self._info.setText("Wybierz maszynę z Serwerem Integracji i kliknij Odśwież.")

    def refresh(self) -> None:
        """The hospital's machines changed (edited in "Maszyny")."""
        keep = self._machine.currentData()
        self._fill_machines(keep or "")

    def set_admin_mode(self, unlocked: bool) -> None:
        self._admin_unlocked = unlocked
        self.refresh()

    def busy(self) -> bool:
        return self._worker is not None

    def shutdown(self) -> None:
        w = self._worker
        if w is not None:
            w.cancel()
            w.wait(3000)

    # ── Settings ──────────────────────────────────────────────────────────

    def _ssh_machines(self) -> list:
        h = self._hospital
        if h is None:
            return []
        return [m for m in h.machines
                if getattr(m, "connection_type", "SSH") == "SSH"
                and (self._admin_unlocked or not m.admin_only)]

    def _fill_machines(self, wanted: str) -> None:
        self._loading = True
        self._machine.clear()
        self._machine.addItem("— wybierz maszynę —", "")
        for m in self._ssh_machines():
            label = m.ip + (f"  ({m.name})" if m.name else "")
            self._machine.addItem(label, m.id)
        i = self._machine.findData(wanted) if wanted else 0
        self._machine.setCurrentIndex(max(i, 0))
        self._loading = False
        self._update_buttons()

    def current_machine(self):
        mid = self._machine.currentData()
        for m in self._ssh_machines():
            if m.id == mid:
                return m
        return None

    def root(self) -> str:
        return self._root.text().strip().rstrip("/") or sd.DEFAULT_ROOT

    def _store(self) -> None:
        if self._hospital is None or self._loading:
            return
        old = dict(getattr(self._hospital, "si", None) or {})
        # Other keys (the HL7 register's database) stay as they are.
        si = {k: v for k, v in old.items()
              if k not in ("machine", "root", "follow_after")}
        machine = self._machine.currentData() or ""
        if machine:
            si["machine"] = machine
        if self.root() != sd.DEFAULT_ROOT or machine:
            si["root"] = self.root()
        if not self._auto_follow.isChecked():
            si["follow_after"] = False
        if old != si:
            self._hospital.si = si
            self.data_changed.emit()

    def _machine_changed(self, *_):
        if self._loading:
            return
        self._modules, self._other = [], []
        self._fill_tree()
        self._store()
        self._update_buttons()

    def _root_edited(self):
        self._store()

    # ── Tree ──────────────────────────────────────────────────────────────

    def _fill_tree(self) -> None:
        checked = set(self.checked_names())
        self._tree.blockSignals(True)
        self._tree.clear()
        for m in self._modules:
            st = sd.module_state(m)
            mark, color, words = STATE_LOOK[st]
            it = QTreeWidgetItem([m.name, m.version_text(), f"{mark} {words}"])
            it.setData(0, Qt.ItemDataRole.UserRole, m.name)
            it.setFlags(it.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            it.setCheckState(0, Qt.CheckState.Checked if m.name in checked
                             else Qt.CheckState.Unchecked)
            it.setForeground(2, QBrush(QColor(color)))
            code = self._results.get(m.name)
            if code is not None:
                it.setText(0, f"{m.name}  {'✓' if code == 0 else '✗'}")
                it.setForeground(0, QBrush(QColor("#3fb950" if code == 0
                                                  else "#f85149")))
            tip = [f"Folder: {self.root()}/{m.name}",
                   f"Projekt: {m.project}"]
            tip += [f"{k}={v}" for k, v in m.versions.items()]
            it.setToolTip(0, "\n".join(tip))
            for c in m.containers:
                ch = QTreeWidgetItem([c.name, c.tag, c.status or c.state])
                ch.setToolTip(0, c.image)
                if c.finished_ok:
                    ch.setToolTip(2, "Jednorazowe zadanie startowe — "
                                     "zakończone poprawnie (kod 0)")
                ch.setForeground(2, QBrush(QColor(
                    "#8b949e" if c.finished_ok
                    else "#f85149" if c.state != "running"
                    else "#d29922" if c.healthy is False else "#8b949e")))
                it.addChild(ch)
            self._tree.addTopLevelItem(it)
        if self._other:
            it = QTreeWidgetItem([f"Inne kontenery ({len(self._other)})", "", ""])
            it.setToolTip(0, "Kontenery spoza folderu modułów — tylko podgląd")
            it.setForeground(0, QBrush(QColor("#8b949e")))
            for c in self._other:
                ch = QTreeWidgetItem([c.name, c.tag, c.status or c.state])
                ch.setToolTip(0, f"{c.image}\n{c.workdir or 'bez folderu compose'}")
                it.addChild(ch)
            self._tree.addTopLevelItem(it)
        self._tree.blockSignals(False)
        self._update_buttons()

    def checked_names(self) -> list:
        out = []
        for i in range(self._tree.topLevelItemCount()):
            it = self._tree.topLevelItem(i)
            name = it.data(0, Qt.ItemDataRole.UserRole)
            if name and it.checkState(0) == Qt.CheckState.Checked:
                out.append(name)
        return out

    def _current_module(self) -> str:
        it = self._tree.currentItem()
        while it is not None and it.parent() is not None:
            it = it.parent()
        return (it.data(0, Qt.ItemDataRole.UserRole) or "") if it else ""

    def target_names(self) -> list:
        """The ticked modules, else the one the cursor is on."""
        names = self.checked_names()
        if names:
            return names
        cur = self._current_module()
        return [cur] if cur else []

    def _item_checked(self, *_):
        self._update_buttons()

    def _toggle_all(self):
        names = [m.name for m in self._modules]
        on = len(self.checked_names()) < len(names)
        self._tree.blockSignals(True)
        for i in range(self._tree.topLevelItemCount()):
            it = self._tree.topLevelItem(i)
            if it.data(0, Qt.ItemDataRole.UserRole):
                it.setCheckState(0, Qt.CheckState.Checked if on
                                 else Qt.CheckState.Unchecked)
        self._tree.blockSignals(False)
        self._update_buttons()

    def _update_buttons(self) -> None:
        running = self._worker is not None
        has_machine = self.current_machine() is not None
        targets = self.target_names()
        n = len(self.checked_names())
        self._picked.setText(f"zaznaczone: {n}" if n else
                             (f"kursor: {targets[0]}" if targets else ""))
        self._all_btn.setText("Odznacz wszystkie"
                              if self._modules and n == len(self._modules)
                              else "Zaznacz wszystkie")
        self._all_btn.setEnabled(bool(self._modules) and not running)
        self._refresh_btn.setEnabled(has_machine and not running)
        for b in (self._btn_start, self._btn_stop, self._btn_restart,
                  self._btn_pull, self._btn_archive):
            b.setEnabled(has_machine and not running and bool(targets))
        single = len(targets) == 1
        self._btn_logs.setEnabled(has_machine and not running and single)
        self._btn_follow.setEnabled(has_machine and bool(targets))
        self._btn_cancel.setEnabled(running)

    # ── Running ───────────────────────────────────────────────────────────

    def _say(self, text: str) -> None:
        self._out.appendPlainText(text)

    def _start_worker(self, kind: str, names=None) -> bool:
        m = self.current_machine()
        if m is None or self._worker is not None:
            return False
        cred = machine_credential(m, self._admin_unlocked)
        if cred is None or not cred.login:
            self._info.setText("Ta maszyna nie ma w vaulcie loginu — dodaj go "
                               "w zakładce Maszyny.")
            return False
        host, port = machine_port(m)
        w = SiWorker(host, port, cred.login, cred.password, self.root(), kind,
                     names=names, client_factory=self._factory)
        w.line.connect(self._on_line)
        w.done.connect(lambda mode, text, code, k=kind: self._on_done(k, mode, text, code))
        w.failed.connect(self._on_failed)
        w.finished.connect(self._on_finished)
        self._worker = w
        self._update_buttons()
        w.start()
        return True

    def scan(self) -> None:
        if self._start_worker("scan"):
            self._info.setText("Odczyt modułów…")

    def run_action(self, action: str) -> None:
        names = self.target_names()
        if not names or self._worker is not None:
            return
        if action == "logs":
            names = names[:1]
        label = sd.ACTIONS[action][0]
        ordered = (sd.stop_order(names) if action == "stop"
                   else sd.start_order(names))
        if action == "stop_archive":
            m = self.current_machine()
            where = (m.name or m.ip) if m else ""
            listing = "\n".join(
                f"  {i}. {self.root()}/{n}  →  {sd.ARCHIVE_ROOT}/{n}_<data-godzina>"
                for i, n in enumerate(ordered, 1))
            if not confirm(self, label,
                           f"Na {where}: zatrzymanie i kopia folderów do "
                           f"{sd.ARCHIVE_ROOT}/ — w tej "
                           f"kolejności:\n\n{listing}\n\nModuły przestaną "
                           "obsługiwać komunikaty do czasu uruchomienia "
                           "nowych.", yes="Zatrzymaj i zarchiwizuj",
                           no="Anuluj"):
                return
        elif action in ("stop", "restart"):
            m = self.current_machine()
            where = (m.name or m.ip) if m else ""
            listing = "\n".join(f"  {i}. {n}" for i, n in enumerate(ordered, 1))
            if not confirm(self, label,
                           f"{label} na {where} — w tej kolejności:\n\n{listing}"
                           "\n\nModuły przestaną obsługiwać komunikaty do czasu "
                           "ponownego uruchomienia." if action == "stop" else
                           f"{label} na {where} — w tej kolejności:\n\n{listing}",
                           yes=label, no="Anuluj"):
                return
        self._results = {k: v for k, v in self._results.items() if k not in names}
        self._last_names = list(ordered)
        self._say(f"\n── {label}: {', '.join(ordered)}  "
                  f"[{time.strftime('%H:%M:%S')}] ──")
        self._start_worker(action, ordered)

    def _on_line(self, text: str) -> None:
        mk = sd.parse_action_markers(text)
        if mk is None:
            self._say(text)
        elif mk[0] == "begin":
            self._say(f"▶ {mk[1]}")
        else:
            _, name, code = mk
            self._results[name] = code
            if name.endswith(sd.ARCHIVE_SUFFIX):
                mod = name[:-len(sd.ARCHIVE_SUFFIX)]
                self._say(f"{'✓' if code == 0 else '✗'} {mod}: "
                          + ("zarchiwizowany" if code == 0 else
                             "archiwum już istnieje (ta sama minuta)"
                             if code == 3 else f"kopia nieudana, kod {code}"))
            elif code == sd.RUNNING_UNHEALTHY:
                self._say(f"⚠ {name}: działa, ale unhealthy — następne moduły "
                          "uruchomione")
            elif code == sd.SKIPPED:
                self._say(f"– {name}: pominięty (wcześniejszy moduł bazowy "
                          "nie wstał)")
            elif code in sd.WAIT_CODES:
                self._say(f"✗ {name}: {sd.WAIT_CODES[code]} — dalsze moduły "
                          "nie zostaną uruchomione")
            else:
                self._say(f"{'✓' if code == 0 else '✗'} {name}: "
                          f"{'OK' if code == 0 else f'kod {code}'}")

    def _on_done(self, kind: str, mode: str, text: str, code: int) -> None:
        self._mode = mode
        priv = PRIV_WORDS.get(mode, mode)
        if kind == "scan":
            if code != 0 and "@@SI-" not in text:
                self._info.setText(f"Odczyt nieudany ({priv}, kod {code}).")
                self._say(text.strip()[-2000:])
                return
            self._modules, self._other = sd.parse_scan(text, self.root())
            self._fill_tree()
            down = sum(1 for m in self._modules
                       if sd.module_state(m) in ("down", "warn"))
            self._info.setText(
                f"{priv} · modułów: {len(self._modules)}"
                + (f" · uwaga: {down}" if down else "")
                + f" · odczyt {time.strftime('%H:%M:%S')}")
            if not self._modules:
                self._say(f"Brak modułów w {self.root()} "
                          "(podkatalogi z docker-compose.yml).")
            return
        warned = [n for n, c in self._results.items()
                  if c == sd.RUNNING_UNHEALTHY]
        failed = [n for n, c in self._results.items()
                  if c not in (0, sd.RUNNING_UNHEALTHY)]
        if kind in ("start", "restart") and self._auto_follow.isChecked():
            # Up — healthy or not: its logs are just what to look at.
            ok = [n for n in self._last_names
                  if self._results.get(n) in (0, sd.RUNNING_UNHEALTHY)]
            if ok:
                self.follow(ok)
        summary = []
        if failed:
            summary.append(f"błędy: {', '.join(failed)}")
        if warned:
            summary.append(f"uwaga (unhealthy): {', '.join(warned)}")
        self._say(f"── koniec ({priv}): "
                  + ("; ".join(summary) if summary else "wszystko OK") + " ──")
        if kind == "stop_archive" and not failed:
            self._say("Teraz wgraj nowe pliki z Kreatora do "
                      f"{self.root()}/<moduł>/ (nadpisz), potem: Odśwież → "
                      "Pobierz → Uruchom.")
        if kind != "logs":
            # The state after the action: one more read of the modules.
            self._rescan = True

    def _on_failed(self, msg: str) -> None:
        self._info.setText(msg)
        self._say(msg)

    def _on_finished(self) -> None:
        w = self._worker
        self._worker = None
        if w is not None:
            w.deleteLater()
        if getattr(self, "_rescan", False):
            self._rescan = False
            self._fill_tree()
            self.scan()
        self._update_buttons()

    def _cancel(self) -> None:
        if self._worker is not None:
            self._worker.cancel()

    def follow_command(self, name: str) -> str:
        """What a module's terminal tab runs: its logs, followed."""
        path = shlex.quote(f"{self.root()}/{name}")
        sudo = "" if self._mode in ("root", "docker", "") else "sudo "
        return f"cd {path} && {sudo}docker compose logs -f --tail=100"

    def follow(self, names: list) -> None:
        m = self.current_machine()
        if m is None or not names:
            return
        self.follow_requested.emit(
            m, [(n, self.follow_command(n)) for n in sd.start_order(names)])

    def _follow(self) -> None:
        self.follow(self.target_names())
