import os
import sys
import tempfile

from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QHBoxLayout, QVBoxLayout,
    QListWidget, QLineEdit, QPushButton, QLabel,
    QSplitter, QMessageBox, QFileDialog, QMenu,
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont, QKeySequence, QShortcut

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from crypto import encrypt, hash_admin_password, verify_admin_password
import models
from config import (save_last_vault,
                    load_ssh_start_maximized, save_ssh_start_maximized)
from ui.detail_panel import DetailPanel
from ui.vpn_panel import VpnPanel
from ui.dialogs import (
    HospitalDialog, ChangePasswordDialog,
    AdminSetupDialog, AdminUnlockDialog,
)

_ADMIN_LOCK_TIMEOUT_MS = 5 * 60 * 1000  # auto-lock after 5 minutes


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
            self.resize(420, 400)
            self._vpn_panel = VpnPanel(self._hospitals)
            self._vpn_panel.data_changed.connect(self._on_data_changed)
            main_layout.addWidget(self._vpn_panel)
            return

        splitter = QSplitter(Qt.Orientation.Horizontal)
        main_layout.addWidget(splitter)

        # ---- Left panel ----
        left = QWidget()
        left.setMinimumWidth(190)
        left.setMaximumWidth(300)
        left.setStyleSheet("background: #161b22; border-right: 1px solid #21262d;")
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

        if self._vault_type == "vpn" and self._vpn_panel:
            sort_menu = menu.addMenu("Sortuj")
            act_sort_name = sort_menu.addAction("Wg nazwy (A-Z)")
            act_sort_name.triggered.connect(lambda: self._vpn_panel._sort_profiles("name"))
            act_sort_prov = sort_menu.addAction("Wg providera")
            act_sort_prov.triggered.connect(lambda: self._vpn_panel._sort_profiles("provider"))

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

    def _filtered_hospitals(self) -> list:
        text = self._search_edit.text().lower()
        return [h for h in self._hospitals if text in h.name.lower()]

    def _refresh_hospital_list(self):
        current_id = (
            self._detail_panel.current_hospital.id
            if self._detail_panel.current_hospital
            else None
        )

        filtered = self._filtered_hospitals()

        self._hospital_list.blockSignals(True)
        self._hospital_list.clear()
        for h in filtered:
            self._hospital_list.addItem(h.name)
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

        if not found and current_id:
            self._detail_panel.show_hospital(None, None)

    def _on_search_changed(self, _text: str):
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
            hospital = models.Hospital(name=dlg.get_name())
            self._hospitals.append(hospital)
            self._unsaved = True
            self._update_title()
            self._refresh_hospital_list()
            # Select the new hospital
            for i in range(self._hospital_list.count()):
                if self._hospital_list.item(i).text() == hospital.name:
                    self._hospital_list.setCurrentRow(i)
                    break

    # ------------------------------------------------------------------ #
    # Save / export                                                        #
    # ------------------------------------------------------------------ #

    def _save(self):
        self._do_save(self._vault_path)

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
        try:
            if self._vault_type == "vpn":
                data = models.vpn_to_dict(self._hospitals)
            else:
                data = models.to_dict(self._hospitals)
            if self._admin_hash:
                data["admin_hash"] = self._admin_hash
                data["admin_salt"] = self._admin_salt
            content = encrypt(data, self._password)
            # Atomic write: encrypt to temp file in same dir, then rename.
            # If the process crashes mid-write, the original vault is untouched.
            dir_name = os.path.dirname(os.path.abspath(path))
            fd, tmp_path = tempfile.mkstemp(dir=dir_name, suffix=".tmp")
            try:
                with os.fdopen(fd, "wb") as f:
                    f.write(content)
                    f.flush()
                    os.fsync(f.fileno())
                os.replace(tmp_path, path)  # atomic on same filesystem
            except Exception:
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass
                raise
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

        self._password = new_pass
        if self._vault_path and os.path.exists(self._vault_path):
            if self._do_save(self._vault_path):
                QMessageBox.information(
                    self, "Sukces", "Hasło zostało zmienione i vault zapisany."
                )
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

    def _unlock_admin(self):
        if not self._admin_hash:
            QMessageBox.information(
                self, "Brak hasła admina",
                "Hasło admina nie zostało ustawione.\n"
                "Ustaw je w menu: Plik → Ustaw / zmień hasło admina."
            )
            return
        dlg = AdminUnlockDialog(self)
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
        self._admin_lock_timer.start()

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
