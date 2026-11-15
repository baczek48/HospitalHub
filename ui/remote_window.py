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

from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QActionGroup
from PyQt6.QtWidgets import QMenuBar, QMessageBox

import models
import upgrade_plan as up
from crypto import hash_admin_password, verify_admin_password
from ui import theme
from ui.dialogs import AdminSetupDialog, AdminUnlockDialog, ChangePasswordDialog
from ui.icons import icon
from ui.remote_panel import RemoteMachinesPanel
from ui.ssh_panel import SshDialog
from ui.upgrade_panel import UpgradePanel
from ui.utils import confirm
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
        #: id(session) → the upgrade command waited for in that terminal:
        #: {"re", "gid", "mid", "label", "buf"} (see _upgrade_output).
        self._upgrade_wait: dict[int, dict] = {}
        super().__init__(None, hospital=hospitals[0], all_hospitals=hospitals,
                         admin_unlocked=False)

        # "Maszyny" first and on screen; "Pliki" takes over on a connect.
        tabs = self._left_tabs
        at = tabs.indexOf(self._env_panel)
        tabs.setTabText(at, "Maszyny")
        tabs.setTabIcon(at, icon("monitor", "#58a6ff"))
        tabs.tabBar().moveTab(at, 0)
        tabs.setCurrentWidget(self._env_panel)
        self._main_splitter.setSizes([320, 880])
        # Three tabs in a narrow panel: shortened, never behind arrows.
        tabs.tabBar().setUsesScrollButtons(False)
        tabs.tabBar().setElideMode(Qt.TextElideMode.ElideRight)

        # "Aktualizacja" (2026-11-15): the upgrade plan of the hospital.
        self._upgrade_panel = UpgradePanel(self._env_panel.current_hospital(),
                                           admin_unlocked=False)
        tabs.addTab(self._upgrade_panel, icon("refresh", "#d29922"),
                    "Aktualizacja")
        self._upgrade_panel.data_changed.connect(self._save)
        self._upgrade_panel.open_requested.connect(self._open_upgrade_tabs)
        self._upgrade_panel.run_requested.connect(self._run_upgrade_command)
        self._upgrade_panel.interrupt_requested.connect(self._interrupt_upgrade)
        self._env_panel.data_changed.connect(self._upgrade_panel.refresh)

        # Wsparcie Claude sends the terminal's screen out of the hospital's
        # network and needs Claude Code on the machine: not here.
        self._btn_claude.hide()
        # "Wątki" are saved Claude conversations — nothing to go back to here.
        self._btn_threads.hide()

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

    def closeEvent(self, event):
        box = self._upgrade_panel.hd_box
        if (box.busy() and not getattr(self, "_close_confirmed", False)
                and not confirm(
                self, "Pobieranie",
                "Trwa pobieranie z hd.asseco.pl. Przerwać je i zamknąć okno?",
                yes="Przerwij i zamknij", no="Wróć")):
            event.ignore()
            return
        super().closeEvent(event)
        if event.isAccepted():
            box.shutdown()

    def _connect_worker(self, worker, term, pane, ip, user, is_first,
                        session=None):
        super()._connect_worker(worker, term, pane, ip, user, is_first, session)
        if session is not None:
            worker.output.connect(
                lambda text, s=session: self._upgrade_output(s, text))

    def _teardown_session(self, s):
        self._upgrade_wait.pop(id(s), None)
        super()._teardown_session(s)

    # ── Aktualizacja ──────────────────────────────────────────────────────

    def _session_for(self, machine):
        """The open SSH tab of a vault machine (the first one), or None."""
        for s in self._sessions:
            if (not s.is_rdp and s.machine is not None
                    and s.machine.id == machine.id):
                return s
        return None

    @staticmethod
    def _session_ready(s) -> bool:
        w = s.worker
        return (w is not None and getattr(w, "_channel", None) is not None
                and not s.reconnecting)

    def _open_upgrade_tabs(self, machines: list) -> None:
        opened = 0
        for m in machines:
            if self._session_for(m) is None:
                self._open_extra_machine(m)
                opened += 1
        self._left_tabs.setCurrentWidget(self._upgrade_panel)
        self._notice(f"Otwarto karty: {opened}" if opened
                     else "Wszystkie karty z listy są już otwarte")

    def _run_upgrade_command(self, group: dict, cmd: dict, machines: list) -> None:
        panel = self._upgrade_panel
        version = panel.version()
        if "{WERSJA}" in cmd.get("text", "") and not version:
            QMessageBox.warning(self, "Aktualizacja",
                                "Komenda używa {WERSJA} — wpisz najpierw wersję "
                                "u góry zakładki Aktualizacja.")
            return
        ready, missing, busy = [], [], []
        for m in machines:
            s = self._session_for(m)
            if s is None or not self._session_ready(s):
                missing.append(m)
            else:
                ready.append((m, s))
                if id(s) in self._upgrade_wait:
                    busy.append(m)
        if not ready:
            QMessageBox.information(
                self, "Aktualizacja",
                "Żadna maszyna grupy nie ma połączonej karty.\n"
                "Użyj „Otwórz karty po kolei” i poczekaj na połączenie.")
            return
        if cmd.get("confirm") or busy or missing:
            shown = up.expand(cmd.get("text", ""), version)
            text = (f"„{cmd['label']}” — {group['name']}\n\nNa maszynach:\n"
                    + "\n".join(f"   {m.ip}  {m.name}" for m, _s in ready)
                    + f"\n\nKomendy:\n{shown}")
            if cmd.get("requires_stopped") and group.get("process"):
                text += (f"\n\n(najpierw sprawdzenie, że proces "
                         f"„{group['process']}” nie działa)")
            if missing:
                text += ("\n\nPOMINIĘTE — brak połączonej karty:\n"
                         + "\n".join(f"   {m.ip}  {m.name}" for m in missing))
            if busy:
                text += ("\n\nPoprzednia komenda jeszcze trwa na:\n"
                         + "\n".join(f"   {m.ip}" for m in busy)
                         + "\nzostanie przerwana (Ctrl+C).")
            box = QMessageBox(QMessageBox.Icon.Question, "Aktualizacja", text,
                              parent=self)
            go = box.addButton("Wykonaj", QMessageBox.ButtonRole.AcceptRole)
            no = box.addButton("Anuluj", QMessageBox.ButtonRole.RejectRole)
            box.setDefaultButton(no)
            box.setEscapeButton(no)
            box.exec()
            if box.clickedButton() is not go:
                return
        for m in missing:
            panel.set_status(group["id"], m.id, "miss",
                             f"{cmd['label']}: brak połączonej karty")
        for m, s in ready:
            token = up.new_id()[:8]
            data = (up.build_line(cmd, group, version, token) + "\r").encode("utf-8")
            interrupted = id(s) in self._upgrade_wait
            if interrupted:
                self._send_one(s, b"\x03", True)
            self._upgrade_wait[id(s)] = {
                "re": up.marker_re(token), "gid": group["id"], "mid": m.id,
                "label": cmd["label"], "buf": ""}
            if interrupted:
                QTimer.singleShot(400, lambda s=s, d=data: s.worker.send(d))
            else:
                s.worker.send(data)
            panel.set_status(group["id"], m.id, "run", f"{cmd['label']}: trwa…")
        n = len(ready)
        self._notice(f"„{cmd['label']}” wysłane na {n} "
                     f"{'maszynę' if n == 1 else 'maszyny'}")

    def _upgrade_output(self, s, text: str) -> None:
        w = self._upgrade_wait.get(id(s))
        if w is None:
            return
        w["buf"] = (w["buf"] + text)[-1500:]
        found = w["re"].search(up.strip_ansi(w["buf"]))
        if not found:
            return
        del self._upgrade_wait[id(s)]
        code = int(found.group(1))
        self._upgrade_panel.set_status(
            w["gid"], w["mid"], "ok" if code == 0 else "fail",
            f"{w['label']}: kod {code}")

    def _interrupt_upgrade(self, group: dict, machines: list) -> None:
        n = 0
        for m in machines:
            s = self._session_for(m)
            if s is None or not self._session_ready(s):
                continue
            self._send_one(s, b"\x03", True)
            n += 1
            w = self._upgrade_wait.pop(id(s), None)
            if w is not None:
                self._upgrade_panel.set_status(
                    w["gid"], w["mid"], "stop", f"{w['label']}: przerwano (Ctrl+C)")
        self._notice(f"Ctrl+C wysłane na {n} "
                     f"{'maszynę' if n == 1 else 'maszyny'}")

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
        self._upgrade_panel.set_hospital(hospital)
        self._update_window_title()

    def set_admin_mode(self, unlocked: bool) -> None:
        super().set_admin_mode(unlocked)
        if hasattr(self, "_upgrade_panel"):
            self._upgrade_panel.set_admin_mode(unlocked)

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
