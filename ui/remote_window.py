"""The window of HospitalHub Remote (2026-10-28, owner).

One window for work on a hospital's own remote machine: the machines of the
vault on the left ("Maszyny"), the terminal tabs on the right, and the SFTP
files of the session on screen in the "Pliki" tab — it is the SSH window of
HospitalHub with the vault's machine list in place of its Environment tab.

There is no hospital overview, no VPN and no tray.  Every edit is saved to
the vault at once; before a save the file on disk is compared with the one
opened, so a vault another person changed meanwhile is not overwritten
without a question.
"""

from __future__ import annotations

import os

from PyQt6.QtCore import pyqtSignal
from PyQt6.QtGui import QActionGroup
from PyQt6.QtWidgets import QMenuBar, QMessageBox

import models
from crypto import hash_admin_password, verify_admin_password
from ui import theme
from ui.dialogs import AdminSetupDialog, AdminUnlockDialog, ChangePasswordDialog
from ui.icons import icon
from ui.remote_panel import RemoteMachinesPanel
from ui.ssh_panel import SshDialog
from vault_io import discard_backup, write_vault_atomic

__all__ = ["RemoteWindow", "APP_TITLE", "file_stamp"]

APP_TITLE = "HospitalHub Portable"


def file_stamp(path: str):
    """(mtime_ns, size) of the vault file, None when it cannot be read."""
    try:
        st = os.stat(path)
        return (st.st_mtime_ns, st.st_size)
    except OSError:
        return None


class RemoteWindow(SshDialog):
    #: "Plik → Otwórz inny vault…": the window closes and the login returns.
    switch_vault_requested = pyqtSignal()

    def __init__(self, vault_path: str, password: str, hospitals: list,
                 admin_hash: str = "", admin_salt: str = ""):
        if not hospitals:
            hospitals.append(models.Hospital(name="Szpital"))
        self._vault_path = vault_path
        self._password = password
        self._vault_hospitals = hospitals
        self._admin_hash = admin_hash
        self._admin_salt = admin_salt
        self._stamp = file_stamp(vault_path)
        super().__init__(None, hospital=hospitals[0], all_hospitals=hospitals,
                         admin_unlocked=False)

        # "Maszyny" first and on screen; "Pliki" takes over on a connect.
        tabs = self._left_tabs
        at = tabs.indexOf(self._env_panel)
        tabs.setTabText(at, "Maszyny")
        tabs.setTabIcon(at, icon("monitor", "#58a6ff"))
        tabs.tabBar().moveTab(at, 0)
        tabs.setCurrentWidget(self._env_panel)
        self._main_splitter.setSizes([300, 900])

        # Wsparcie Claude sends the terminal's screen out of the hospital's
        # network and needs Claude Code on the machine: not here.
        self._btn_claude.hide()

        self._env_panel.data_changed.connect(self._save)
        self._env_panel.hospital_changed.connect(self._on_hospital_changed)
        self._env_panel.admin_clicked.connect(self._toggle_admin)
        self._env_panel.notice.connect(self._notice)
        self._setup_menu()
        self._update_window_title()

    # ── SshDialog hooks ───────────────────────────────────────────────────

    def _make_env_panel(self):
        return RemoteMachinesPanel(self._vault_hospitals,
                                   admin_unlocked=self._admin_unlocked,
                                   has_admin=bool(self._admin_hash))

    def _update_window_title(self) -> None:
        parts = [APP_TITLE]
        name = getattr(self._hospital, "name", "") if self._hospital else ""
        if name:
            parts.append(name)
        s = self._active_session()
        if s is not None and getattr(s, "is_rdp", False):
            parts.append(f"RDP {s.pane.host}")
        elif s is not None:
            w = s.worker
            parts.append(f"{w._user}@{w._host}" if w._user else w._host)
        self.setWindowTitle("  ·  ".join(parts))

    def _on_tab_changed(self, idx: int):
        super()._on_tab_changed(idx)
        # The last session closed: back to the machine list.
        if not self._sessions:
            self._left_tabs.setCurrentWidget(self._env_panel)

    # ── Menu ──────────────────────────────────────────────────────────────

    def _setup_menu(self) -> None:
        bar = QMenuBar(self)
        file_menu = bar.addMenu("Plik")
        file_menu.addAction("Otwórz inny vault…", self.switch_vault_requested.emit)
        file_menu.addSeparator()
        file_menu.addAction("Zmień hasło vaulta…", self._change_password)
        file_menu.addAction("Ustaw / zmień hasło admina…", self._setup_admin_password)
        file_menu.addSeparator()
        file_menu.addAction("Zamknij", self.close)

        view_menu = bar.addMenu("Widok")
        theme_menu = view_menu.addMenu("Motyw")
        group = QActionGroup(self)
        group.setExclusive(True)
        from config import load_theme
        chosen = load_theme()
        for tid, (label, _pal, _light) in theme.THEMES.items():
            act = theme_menu.addAction(label)
            act.setCheckable(True)
            act.setChecked(tid == chosen)
            act.setData(tid)
            group.addAction(act)
        group.triggered.connect(lambda a: self._choose_theme(a.data()))
        self.layout().setMenuBar(bar)
        self._menu_bar = bar

    def _choose_theme(self, tid: str) -> None:
        from config import load_theme, save_theme
        if tid == load_theme():
            return
        save_theme(tid)
        QMessageBox.information(
            self, "Motyw",
            "Motyw zostanie zastosowany po ponownym uruchomieniu programu.\n"
            "Terminal pozostaje w ciemnych odcieniach.")

    # ── Hospital, admin ───────────────────────────────────────────────────

    def _on_hospital_changed(self, hospital) -> None:
        self._hospital = hospital
        self._update_window_title()

    def _toggle_admin(self) -> None:
        if self._admin_unlocked:
            self.set_admin_mode(False)
            return
        if not self._admin_hash:
            return
        dlg = AdminUnlockDialog(self, verify=lambda pw: verify_admin_password(
            pw, self._admin_hash, self._admin_salt))
        if not dlg.exec():
            return
        if not verify_admin_password(dlg.get_password(), self._admin_hash,
                                     self._admin_salt):
            QMessageBox.critical(self, "Błąd", "Nieprawidłowe hasło admina.")
            return
        self.set_admin_mode(True)

    def _setup_admin_password(self) -> None:
        had = bool(self._admin_hash)
        dlg = AdminSetupDialog(self, is_change=had)
        if not dlg.exec():
            return
        if had and not verify_admin_password(dlg.get_old_password(),
                                             self._admin_hash, self._admin_salt):
            QMessageBox.critical(self, "Błąd", "Nieprawidłowe bieżące hasło admina.")
            return
        old = (self._admin_hash, self._admin_salt)
        self._admin_hash, self._admin_salt = hash_admin_password(dlg.get_password())
        if not self._save():
            self._admin_hash, self._admin_salt = old
            return
        self._env_panel.set_has_admin(True)
        QMessageBox.information(self, "Admin", "Hasło admina zostało ustawione.")

    def _change_password(self) -> None:
        dlg = ChangePasswordDialog(self)
        if not dlg.exec():
            return
        old_pass, new_pass = dlg.get_passwords()
        if old_pass != self._password:
            QMessageBox.critical(self, "Błąd", "Nieprawidłowe bieżące hasło.")
            return
        previous, self._password = self._password, new_pass
        if not self._save():
            self._password = previous
            return
        # The .bak the save left is the vault under the old password.
        discard_backup(self._vault_path)
        QMessageBox.information(self, "Hasło", "Hasło zostało zmienione i vault zapisany.")

    # ── Saving ────────────────────────────────────────────────────────────

    def _save(self) -> bool:
        """Write the vault now.  False when it was not written."""
        if getattr(self, "_saving", False):
            return False
        now = file_stamp(self._vault_path)
        if self._stamp is not None and now != self._stamp:
            box = QMessageBox(
                QMessageBox.Icon.Warning, "Vault zmieniony na dysku",
                "Plik vaulta zmienił się od otwarcia — może ktoś inny pracuje "
                "na nim w tej chwili.\n\nZapisanie go teraz zastąpi tamte "
                "zmiany Twoimi.", parent=self)
            write = box.addButton("Zapisz mimo to", QMessageBox.ButtonRole.DestructiveRole)
            keep = box.addButton("Nie zapisuj", QMessageBox.ButtonRole.RejectRole)
            box.setDefaultButton(keep)
            box.setEscapeButton(keep)
            box.exec()
            if box.clickedButton() is not write:
                self._notice("Zmiana NIE zapisana — vault zmieniony na dysku. "
                             "Otwórz go ponownie (Plik → Otwórz inny vault).")
                return False
        self._saving = True
        try:
            from ui.main_window import encrypt_off_ui_thread
            data = models.to_dict(self._vault_hospitals)
            if self._admin_hash:
                data["admin_hash"] = self._admin_hash
                data["admin_salt"] = self._admin_salt
            content = encrypt_off_ui_thread(data, self._password)
            write_vault_atomic(self._vault_path, content)
        except Exception as e:
            QMessageBox.critical(self, "Błąd zapisu",
                                 f"Nie można zapisać vaulta:\n{e}")
            return False
        finally:
            self._saving = False
        self._stamp = file_stamp(self._vault_path)
        self._notice("Zapisano vault")
        return True
