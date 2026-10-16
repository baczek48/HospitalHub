import os
import sys

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QListWidget, QListWidgetItem, QLineEdit, QPushButton, QLabel,
    QSplitter, QMessageBox, QFileDialog, QMenu,
)
from PyQt6.QtCore import Qt, QTimer, QEvent, pyqtSignal
from PyQt6.QtGui import QFont, QKeySequence, QShortcut, QActionGroup

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crypto import encrypt, hash_admin_password, verify_admin_password
import models
from vault_io import discard_backup, write_vault_atomic
from config import (save_last_vault,
                    load_ssh_start_maximized, save_ssh_start_maximized,
                    load_hospital_sort_order, save_hospital_sort_order,
                    load_theme, save_theme)
from ui.detail_panel import DetailPanel
from ui.vpn_panel import VpnPanel
from ui.dialogs import (
    HospitalDialog, ChangePasswordDialog,
    AdminSetupDialog, AdminUnlockDialog,
)
from ui.utils import confirm

_ADMIN_LOCK_TIMEOUT_MS = 5 * 60 * 1000  # auto-lock after 5 minutes


def encrypt_off_ui_thread(data: dict, password: str) -> bytes:
    """``encrypt`` on a worker thread, the caller waiting in a local loop.

    2026-10-14 (D-06, AUDYT P1): Argon2id (t=3, 64 MiB) ran on the UI thread
    at every Ctrl+S — a frozen window, "Not responding" on slow machines.
    argon2-cffi releases the GIL, so a thread really runs in parallel.  The
    local loop repaints but excludes user input: nothing can be clicked or
    typed (another Ctrl+S, a close) while the vault is being written.
    Exceptions from ``encrypt`` reach the caller unchanged.
    """
    from PyQt6.QtCore import QEventLoop, QThread
    from PyQt6.QtWidgets import QApplication
    if QApplication.instance() is None:
        return encrypt(data, password)
    outcome = {}

    class _Encrypt(QThread):
        def run(self):
            try:
                outcome["content"] = encrypt(data, password)
            except BaseException as exc:          # handed back below
                outcome["error"] = exc

    worker = _Encrypt()
    loop = QEventLoop()
    worker.finished.connect(loop.quit)
    worker.start()
    if not worker.isFinished():
        loop.exec(QEventLoop.ProcessEventsFlag.ExcludeUserInputEvents)
    worker.wait()
    if "error" in outcome:
        raise outcome["error"]
    return outcome["content"]


class MainWindow(QMainWindow):
    open_vault_requested = pyqtSignal()
    force_close_requested = pyqtSignal()
    title_changed = pyqtSignal()

    def __init__(self, vault_path: str, password: str, hospitals: list,
                 admin_hash: str = "", admin_salt: str = "",
                 vault_type: str = "global"):
        super().__init__()
        self._vault_path = vault_path
        self._password = password
        self._hospitals = hospitals
        self._admin_hash = admin_hash
        self._admin_salt = admin_salt
        self._admin_unlocked = False
        self._unsaved = False
        self._vault_type = vault_type
        self._relogin = False
        self._really_close = False
        self._detail_panel = None
        self._hospital_list = None
        self._search_edit = None
        self._admin_btn = None
        self._vpn_panel = None
        self._sort_order = load_hospital_sort_order()
        self._sort_actions = {}

        self._admin_lock_timer = QTimer(self)
        self._admin_lock_timer.setSingleShot(True)
        self._admin_lock_timer.setInterval(_ADMIN_LOCK_TIMEOUT_MS)
        self._admin_lock_timer.timeout.connect(self._lock_admin)

        self._setup_ui()
        self._setup_menu()
        if self._vault_type != "vpn":
            self._refresh_hospital_list()
        self._update_title()

    # ------------------------------------------------------------------ #
    # UI setup                                                             #
    # ------------------------------------------------------------------ #

    def _setup_ui(self):
        self.setMinimumSize(700, 450)
        self.resize(1050, 680)

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout(central)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        if self._vault_type == "vpn":
            self.setMinimumSize(360, 300)
            self.resize(420, 700)
            self._vpn_panel = VpnPanel(self._hospitals)
            self._vpn_panel.data_changed.connect(self._on_data_changed)
            main_layout.addWidget(self._vpn_panel)
            return

        # Modern slim scrollbars for the whole main vault (replaces the chunky
        # default Fusion ones — the "Windows 98" look). Cascades to every child:
        # machines/DB tables, hospital list, notes — vertical and horizontal
        # alike (up to ~5 at once). Themed via the light-mode remap (handle
        # #30363d -> border grey). Arrow step-buttons removed.
        central.setStyleSheet("""
            QScrollBar:vertical { background: transparent; width: 10px; margin: 0; }
            QScrollBar::handle:vertical { background: #30363d; border-radius: 5px; min-height: 28px; }
            QScrollBar::handle:vertical:hover { background: #484f58; }
            QScrollBar:horizontal { background: transparent; height: 10px; margin: 0; }
            QScrollBar::handle:horizontal { background: #30363d; border-radius: 5px; min-width: 28px; }
            QScrollBar::handle:horizontal:hover { background: #484f58; }
            QScrollBar::add-line, QScrollBar::sub-line { width: 0; height: 0; background: none; border: none; }
            QScrollBar::add-page, QScrollBar::sub-page { background: none; }
        """)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter)

        # ---- Left panel ----
        left = QWidget()
        left.setObjectName("leftPanel")
        left.setMinimumWidth(190)
        left.setMaximumWidth(300)
        left.setStyleSheet(
            "#leftPanel { background: #161b22; border-right: 1px solid #21262d; }")
        left_layout = QVBoxLayout(left)
        left_layout.setContentsMargins(10, 12, 10, 10)
        left_layout.setSpacing(8)

        lbl = QLabel("Szpitale")
        font = QFont()
        font.setBold(True)
        font.setPointSize(11)
        lbl.setFont(font)
        lbl.setStyleSheet("color: #c9d1d9; letter-spacing: 0.5px;")
        left_layout.addWidget(lbl)

        self._search_edit = QLineEdit()
        self._search_edit.setPlaceholderText("Szukaj...")
        self._search_edit.setClearButtonEnabled(True)
        self._search_edit.setStyleSheet(
            "QLineEdit { background: #21262d; border: 1px solid #30363d; border-radius: 5px;"
            " padding: 5px 8px; color: #c9d1d9; }"
            "QLineEdit:focus { border-color: #1f6feb; }"
        )
        self._search_edit.textChanged.connect(self._on_search_changed)
        self._search_edit.setPlaceholderText("Szukaj: szpital, IP, maszyna, baza…")
        self._search_edit.returnPressed.connect(self._search_go_to_list)
        self._search_edit.installEventFilter(self)
        left_layout.addWidget(self._search_edit)

        self._hospital_list = QListWidget()
        self._hospital_list.setStyleSheet("""
            QListWidget {
                background: #0d1117; border: 1px solid #30363d;
                border-radius: 6px; padding: 2px; color: #c9d1d9;
            }
            QListWidget::item { padding: 8px 10px; border-radius: 4px; }
            QListWidget::item:selected { background: #1f6feb; color: #fff; }
            QListWidget::item:hover:!selected { background: #21262d; }
        """)
        # Long names end in "…" with a tooltip, no sideways scrolling (V-04).
        self._hospital_list.setTextElideMode(Qt.TextElideMode.ElideRight)
        self._hospital_list.setHorizontalScrollBarPolicy(
            Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self._hospital_list.currentRowChanged.connect(self._on_hospital_selected)
        self._hospital_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._hospital_list.customContextMenuRequested.connect(self._on_hospital_context_menu)
        left_layout.addWidget(self._hospital_list)

        btn_add = QPushButton("＋  Dodaj szpital")
        btn_add.setStyleSheet(
            "QPushButton { background: #1a2a3a; color: #58a6ff; border: 1px solid #1f4a70;"
            " border-radius: 5px; padding: 6px 10px; }"
            "QPushButton:hover { background: #1f6feb; color: #fff; }"
        )
        btn_add.clicked.connect(self._add_hospital)
        left_layout.addWidget(btn_add)

        # ---- Admin lock/unlock button ----
        self._admin_btn = QPushButton("🔒  Admin")
        self._admin_btn.setStyleSheet(
            "QPushButton { background: #2a1a35; color: #c084fc; border: 1px solid #6b3fa0;"
            " border-radius: 5px; padding: 6px 10px; font-weight: bold; }"
            "QPushButton:hover { background: #3d2550; color: #d4a0ff; }"
        )
        self._admin_btn.clicked.connect(self._toggle_admin)
        left_layout.addWidget(self._admin_btn)

        splitter.addWidget(left)

        # ---- Right panel ----
        self._detail_panel = DetailPanel()
        self._detail_panel.data_changed.connect(self._on_data_changed)
        splitter.addWidget(self._detail_panel)

        splitter.setStretchFactor(0, 0)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([230, 820])

    def _setup_menu(self):
        menu = self.menuBar()

        file_menu = menu.addMenu("Plik")

        act_save = file_menu.addAction("Zapisz")
        act_save.setShortcut(QKeySequence("Ctrl+S"))
        act_save.triggered.connect(self._save)

        act_save_as = file_menu.addAction("Zapisz jako / Eksportuj")
        act_save_as.setShortcut(QKeySequence("Ctrl+Shift+S"))
        act_save_as.triggered.connect(self._save_as)

        file_menu.addSeparator()

        act_open_vault = file_menu.addAction("Otwórz vault...")
        act_open_vault.setShortcut(QKeySequence("Ctrl+O"))
        act_open_vault.triggered.connect(lambda: self.open_vault_requested.emit())

        file_menu.addSeparator()

        act_change_pass = file_menu.addAction("Zmień hasło główne...")
        act_change_pass.triggered.connect(self._change_password)

        if self._vault_type != "vpn":
            act_admin_pass = file_menu.addAction("Ustaw / zmień hasło admina...")
            act_admin_pass.triggered.connect(self._setup_admin_password)

        file_menu.addSeparator()

        act_ssh_max = file_menu.addAction("Otwieraj terminal SSH zmaksymalizowany")
        act_ssh_max.setCheckable(True)
        act_ssh_max.setChecked(load_ssh_start_maximized())
        act_ssh_max.toggled.connect(save_ssh_start_maximized)

        file_menu.addSeparator()

        act_close = file_menu.addAction("Zamknij okno")
        act_close.triggered.connect(self._close_to_tray)

        act_exit = file_menu.addAction("Zamknij całkowicie")
        act_exit.triggered.connect(self._force_close)

        view_menu = menu.addMenu("Widok")
        act_light = view_menu.addAction("Jasny motyw")
        act_light.setCheckable(True)
        act_light.setChecked(load_theme() == "light")
        act_light.toggled.connect(self._toggle_theme)

        if self._vault_type == "vpn" and self._vpn_panel:
            sort_menu = menu.addMenu("Sortuj")
            act_sort_name = sort_menu.addAction("Wg nazwy (A-Z)")
            act_sort_name.triggered.connect(lambda: self._vpn_panel._sort_profiles("name"))
            act_sort_prov = sort_menu.addAction("Wg providera")
            act_sort_prov.triggered.connect(lambda: self._vpn_panel._sort_profiles("provider"))
        elif self._vault_type != "vpn":
            sort_menu = menu.addMenu("Sortuj")
            group = QActionGroup(self)
            group.setExclusive(True)

            options = [
                ("none", "Bez sortowania (kolejność z vaulta)"),
                ("asc", "Wg nazwy (A-Z)"),
                ("desc", "Wg nazwy (Z-A)"),
            ]
            for key, label in options:
                act = sort_menu.addAction(label)
                act.setCheckable(True)
                act.setChecked(self._sort_order == key)
                group.addAction(act)
                act.triggered.connect(lambda _checked, k=key: self._set_sort_order(k))
                self._sort_actions[key] = act

    def _close_to_tray(self):
        """Hide window to system tray."""
        self.hide()

    def _force_close(self):
        """Close this window permanently (AppManager handles save prompt)."""
        self.force_close_requested.emit()

    # ------------------------------------------------------------------ #
    # Title management                                                     #
    # ------------------------------------------------------------------ #

    def _update_title(self):
        mark = "  [niezapisane]" if self._unsaved else ""
        type_labels = {"private": "PRIVATE", "vpn": "VPN"}
        type_str = type_labels.get(self._vault_type, "")
        parts = ["HospitalHub"]
        if type_str:
            parts.append(type_str)
        self.setWindowTitle("  ·  ".join(parts) + mark)
        self.title_changed.emit()

    # ------------------------------------------------------------------ #
    # Hospital list                                                        #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _search_hit(h, text: str) -> str:
        """Why `h` matches `text` ("" = it does not).  Hospital name, and —
        tickets name a server, not a hospital — machine IP / name /
        description and database host / name (UX audit E-10)."""
        if text in h.name.lower():
            return "name"
        for m in h.machines:
            if (text in (m.ip or "").lower() or text in (m.name or "").lower()
                    or text in (m.description or "").lower()):
                return f"maszyna: {m.name or m.ip} ({m.ip})"
        for d in h.databases:
            if text in (d.host or "").lower() or text in (d.name or "").lower():
                return f"baza: {d.name} ({d.host})"
        return ""

    def _filtered_hospitals(self) -> list:
        text = self._search_edit.text().strip().lower()
        result = [h for h in self._hospitals
                  if not text or self._search_hit(h, text)]
        if self._sort_order == "asc":
            result.sort(key=lambda h: h.name.casefold())
        elif self._sort_order == "desc":
            result.sort(key=lambda h: h.name.casefold(), reverse=True)
        return result

    def _refresh_hospital_list(self):
        current_id = (
            self._detail_panel.current_hospital.id
            if self._detail_panel.current_hospital
            else None
        )

        filtered = self._filtered_hospitals()
        # A hospital hidden by the filter comes back selected when the
        # filter is cleared (E-10).
        if current_id:
            self._remembered_id = current_id
        elif getattr(self, '_remembered_id', None):
            current_id = self._remembered_id

        text = self._search_edit.text().strip().lower()
        wanted = [(h.name, self._search_hit(h, text) if text else "")
                  for h in filtered]
        same = (self._hospital_list.count() == len(wanted) and all(
            self._hospital_list.item(i).text() == name
            and self._hospital_list.item(i).data(Qt.ItemDataRole.UserRole) == hit
            for i, (name, hit) in enumerate(wanted)))
        if not same:
            # Rebuilt only when names, order or matches changed — not on
            # every character typed in the notes (E-26).
            self._hospital_list.blockSignals(True)
            self._hospital_list.clear()
            for name, hit in wanted:
                item = QListWidgetItem(name)
                item.setData(Qt.ItemDataRole.UserRole, hit)
                tip = name if hit in ("", "name") else f"{name}\n{hit}"
                item.setToolTip(tip)
                self._hospital_list.addItem(item)
            self._hospital_list.blockSignals(False)

        # Restore selection — block signals so show_hospital isn't called again
        # (prevents notes cursor from resetting while the user is typing)
        found = False
        if current_id:
            for i, h in enumerate(filtered):
                if h.id == current_id:
                    self._hospital_list.blockSignals(True)
                    self._hospital_list.setCurrentRow(i)
                    self._hospital_list.blockSignals(False)
                    found = True
                    break

        if not found and self._detail_panel.current_hospital is not None:
            self._detail_panel.show_hospital(None, None)
        if found:
            self._remembered_id = None
            if self._detail_panel.current_hospital is not h:
                # Brought back from before the filter: show it too.
                self._detail_panel.show_hospital(h, self._hospitals)

    def _on_search_changed(self, _text: str):
        self._refresh_hospital_list()

    def _search_go_to_list(self):
        """Enter / ↓ in the search box: first result selected, focus on the
        list (E-10)."""
        if self._hospital_list.count():
            if self._hospital_list.currentRow() < 0:
                self._hospital_list.setCurrentRow(0)
            self._hospital_list.setFocus()

    def eventFilter(self, obj, event):
        if (obj is self._search_edit and event.type() == QEvent.Type.KeyPress
                and event.key() == Qt.Key.Key_Down):
            self._search_go_to_list()
            return True
        return super().eventFilter(obj, event)

    def _set_sort_order(self, order: str):
        if order == self._sort_order:
            return
        self._sort_order = order
        save_hospital_sort_order(order)
        act = self._sort_actions.get(order)
        if act and not act.isChecked():
            act.setChecked(True)
        self._refresh_hospital_list()

    def _on_hospital_selected(self, row: int):
        if row < 0:
            return
        filtered = self._filtered_hospitals()
        if row < len(filtered):
            self._detail_panel.show_hospital(filtered[row], self._hospitals)

    def _on_data_changed(self):
        self._unsaved = True
        self._update_title()
        if self._vault_type != "vpn":
            self._refresh_hospital_list()

    def _on_hospital_context_menu(self, pos):
        idx = self._hospital_list.indexAt(pos).row()
        filtered = self._filtered_hospitals()
        if idx < 0 or idx >= len(filtered):
            return
        hospital = filtered[idx]

        # Select the clicked row so user sees what they right-clicked
        self._hospital_list.setCurrentRow(idx)

        menu = QMenu(self)
        menu.setStyleSheet(
            "QMenu { background:#161b22; border:1px solid #30363d; color:#c9d1d9; }"
            "QMenu::item { padding:5px 20px 5px 12px; }"
            "QMenu::item:selected { background:#1f6feb; color:#fff; }"
            "QMenu::separator { height:1px; background:#30363d; margin:2px 0; }"
        )
        act_rename = menu.addAction("✏  Zmień nazwę")
        menu.addSeparator()
        act_delete = menu.addAction("🗑  Usuń szpital")
        act_delete.setToolTip(f"Usuwa '{hospital.name}' wraz z maszynami i bazami")

        chosen = menu.exec(self._hospital_list.viewport().mapToGlobal(pos))
        if chosen is act_rename:
            self._detail_panel.rename_hospital()
        elif chosen is act_delete:
            self._detail_panel.delete_hospital()

    # ------------------------------------------------------------------ #
    # Hospital management                                                  #
    # ------------------------------------------------------------------ #

    def _add_hospital(self):
        dlg = HospitalDialog(self)
        if dlg.exec():
            name = dlg.get_name()
            key = name.strip().casefold()
            if any(h.name.strip().casefold() == key for h in self._hospitals):
                # Two hospitals with one name are easy to mix up — machines
                # and passwords end up in the wrong one, and the VPN button
                # matches profiles by name (UX audit E-06).
                if not confirm(self, "Szpital już istnieje",
                               f"Szpital o nazwie '{name}' już jest w vaulcie.\n"
                               "Dodać drugi o tej samej nazwie?",
                               yes="Dodaj mimo to", no="Anuluj"):
                    return
            hospital = models.Hospital(name=name)
            self._hospitals.append(hospital)
            self._unsaved = True
            self._update_title()
            if self._search_edit.text():
                self._search_edit.clear()      # the new one must be visible
            self._refresh_hospital_list()
            # Select the new hospital — by object, not by name (E-06).
            filtered = self._filtered_hospitals()
            for i, h in enumerate(filtered):
                if h is hospital:
                    self._hospital_list.setCurrentRow(i)
                    break

    # ------------------------------------------------------------------ #
    # Save / export                                                        #
    # ------------------------------------------------------------------ #

    def _save(self) -> bool:
        # The result matters to whoever closes the window after saving: a save
        # that failed must not be followed by a close (C4-01).
        return self._do_save(self._vault_path)

    def _save_as(self):
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Zapisz vault jako",
            os.path.dirname(self._vault_path) if self._vault_path else "",
            "Vault files (*.vault);;Wszystkie pliki (*)",
        )
        if path:
            if not path.endswith(".vault"):
                path += ".vault"
            if self._do_save(path):
                self._vault_path = path
                save_last_vault(path)
                self._update_title()

    def _do_save(self, path: str) -> bool:
        # A save already running (nested event loop below): refuse, do not
        # start a second one over the same file (D-06).
        if getattr(self, "_saving", False):
            return False
        self._saving = True
        try:
            return self._do_save_now(path)
        finally:
            self._saving = False

    def _do_save_now(self, path: str) -> bool:
        try:
            if self._vault_type == "vpn":
                data = models.vpn_to_dict(self._hospitals)
            else:
                data = models.to_dict(self._hospitals)
            if self._admin_hash:
                data["admin_hash"] = self._admin_hash
                data["admin_salt"] = self._admin_salt
            content = encrypt_off_ui_thread(data, self._password)
            # Atomic write (temp file + fsync + replace), the previous file kept
            # as <vault>.bak, replace retried while AV/sync holds the file.
            write_vault_atomic(path, content)
            self._unsaved = False
            self._update_title()
            return True
        except Exception as e:
            QMessageBox.critical(self, "Błąd zapisu", f"Nie można zapisać pliku:\n{e}")
            return False

    # ------------------------------------------------------------------ #
    # Password change                                                      #
    # ------------------------------------------------------------------ #

    def _change_password(self):
        dlg = ChangePasswordDialog(self)
        if not dlg.exec():
            return

        old_pass, new_pass = dlg.get_passwords()
        if old_pass != self._password:
            QMessageBox.critical(self, "Błąd", "Nieprawidłowe bieżące hasło.")
            return

        previous = self._password
        self._password = new_pass
        if self._vault_path and os.path.exists(self._vault_path):
            if self._do_save(self._vault_path):
                # The backup that save just made is the vault under the OLD
                # password — the one the user may be changing because it
                # leaked.  It must not stay next to the vault (review 65/1).
                discard_backup(self._vault_path)
                QMessageBox.information(
                    self, "Sukces", "Hasło zostało zmienione i vault zapisany."
                )
            else:
                # The file still opens with the old password; keeping the new
                # one in memory would encrypt the next Ctrl+S with a password
                # the user believes was never set (C4-04).
                self._password = previous
        else:
            self._unsaved = True
            self._update_title()
            QMessageBox.information(
                self,
                "Sukces",
                "Hasło zostało zmienione. Pamiętaj o zapisaniu vault (Ctrl+S).",
            )

    # ------------------------------------------------------------------ #
    # Admin mode                                                           #
    # ------------------------------------------------------------------ #

    def _toggle_admin(self):
        if self._admin_unlocked:
            self._lock_admin()
        else:
            self._unlock_admin()

    def _toggle_theme(self, light: bool):
        save_theme("light" if light else "dark")
        QMessageBox.information(
            self, "Motyw",
            "Motyw zostanie zastosowany po ponownym uruchomieniu aplikacji.\n"
            "Terminal SSH pozostaje w ciemnych odcieniach.",
        )

    def _unlock_admin(self):
        if not self._admin_hash:
            QMessageBox.information(
                self, "Brak hasła admina",
                "Hasło admina nie zostało ustawione.\n"
                "Ustaw je w menu: Plik → Ustaw / zmień hasło admina."
            )
            return
        dlg = AdminUnlockDialog(self, verify=lambda pw: verify_admin_password(
            pw, self._admin_hash, self._admin_salt))
        if not dlg.exec():
            return
        if not verify_admin_password(dlg.get_password(), self._admin_hash, self._admin_salt):
            QMessageBox.critical(self, "Błąd", "Nieprawidłowe hasło admina.")
            return
        self._admin_unlocked = True
        self._admin_btn.setText("🔓  Admin")
        self._admin_btn.setStyleSheet(
            "QPushButton { background: #1a3a1a; color: #8ae234; border: 1px solid #2d5a1a;"
            " border-radius: 5px; padding: 6px 10px; font-weight: bold; }"
            "QPushButton:hover { background: #2a4d2a; color: #a0de4a; }"
        )
        if self._detail_panel:
            self._detail_panel.set_admin_mode(True)
        self._admin_to_ssh_windows(True)
        # Admin stays unlocked for the whole session — no auto-lock timer.
        # The user re-locks manually by clicking the 🔓 Admin button.

    def _lock_admin(self):
        self._admin_unlocked = False
        self._admin_lock_timer.stop()
        if self._admin_btn:
            self._admin_btn.setText("🔒  Admin")
            self._admin_btn.setStyleSheet(
                "QPushButton { background: #2a1a35; color: #c084fc; border: 1px solid #6b3fa0;"
                " border-radius: 5px; padding: 6px 10px; font-weight: bold; }"
                "QPushButton:hover { background: #3d2550; color: #d4a0ff; }"
            )
        if self._detail_panel:
            self._detail_panel.set_admin_mode(False)
        self._admin_to_ssh_windows(False)

    def _admin_to_ssh_windows(self, unlocked: bool) -> None:
        """This vault's SSH windows follow its admin lock (UX audit S-03)."""
        try:
            from ui.ssh_panel import SshDialog
        except Exception:
            return
        for dlg in SshDialog.windows_of(self):
            try:
                dlg.set_admin_mode(unlocked)
            except RuntimeError:
                pass

    def _setup_admin_password(self):
        has_existing = bool(self._admin_hash)
        dlg = AdminSetupDialog(self, is_change=has_existing)
        if not dlg.exec():
            return
        if has_existing:
            old = dlg.get_old_password()
            if not verify_admin_password(old, self._admin_hash, self._admin_salt):
                QMessageBox.critical(self, "Błąd", "Nieprawidłowe bieżące hasło admina.")
                return
        new_pass = dlg.get_password()
        self._admin_hash, self._admin_salt = hash_admin_password(new_pass)
        self._unsaved = True
        self._update_title()
        QMessageBox.information(self, "Sukces", "Hasło admina zostało ustawione.")

    # ------------------------------------------------------------------ #
    # Close                                                                #
    # ------------------------------------------------------------------ #

    def closeEvent(self, event):
        # X button → hide to tray (not close)
        event.ignore()
        self.hide()

    def destroy_cleanup(self):
        """Stop all background timers/workers before final destruction."""
        self._admin_lock_timer.stop()
        if self._vpn_panel and hasattr(self._vpn_panel, 'cleanup'):
            self._vpn_panel.cleanup()
        if self._detail_panel and hasattr(self._detail_panel, 'cleanup'):
            self._detail_panel.cleanup()
