"""2026-10-28 (owner): HospitalHub Remote — the version for a hospital's own
remote machine.  One window: the machines of the exported vault on the left,
the terminal on the right, SFTP in the "Pliki" tab.  Edits are saved at once,
never over a vault file that changed on disk meanwhile without a question."""

import os
import sys
import time

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for _p in (_PARENT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

pytest.importorskip("paramiko")

import models  # noqa: E402
import vault_export  # noqa: E402
from crypto import decrypt, encrypt, hash_admin_password  # noqa: E402


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def pump(ms):
    from PyQt6.QtCore import QEvent
    from PyQt6.QtWidgets import QApplication
    end = time.monotonic() + ms / 1000
    while time.monotonic() < end:
        QApplication.processEvents()
        QApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete.value)
        time.sleep(0.005)


def _hospital():
    cred = models.Credential(login="user", password="pw")
    root = models.Credential(login="root", password="rpw", admin_only=True)
    return models.Hospital(
        name="Szpital Betanin",
        machines=[
            models.Machine(ip="10.0.0.1", name="srvAPP", credentials=[cred, root]),
            models.Machine(ip="10.0.0.2", name="srvWin", connection_type="RDP",
                           credentials=[models.Credential(login="adm", password="x")]),
            models.Machine(ip="10.0.0.3", name="portal", connection_type="WWW",
                           www_url="pam.szpital-x.example"),
            models.Machine(ip="10.0.0.9", name="ukryta", admin_only=True),
        ],
        databases=[models.Database(host="10.0.0.5", port="1521", name="AMMS",
                                   db_type="Oracle")],
        notes="notatka")


@pytest.fixture
def vault(tmp_path):
    """A vault exported the way HospitalHub does it, with an admin password."""
    ah, salt = hash_admin_password("adm1")
    data = vault_export.export_hospital_data(_hospital(), include_admin=True,
                                             admin_hash=ah, admin_salt=salt)
    path = tmp_path / "Szpital Betanin.vault"
    path.write_bytes(encrypt(data, "haslo"))
    return str(path), ah, salt


@pytest.fixture
def window(app, vault):
    from ui.remote_window import RemoteWindow
    path, ah, salt = vault
    data = decrypt(open(path, "rb").read(), "haslo")
    w = RemoteWindow(path, "haslo", models.from_dict(data), ah, salt)
    w.show()
    pump(100)
    yield w
    w.close_without_asking()
    pump(200)


def _texts(panel):
    return [panel._items[k] for k in panel._order]


# ── Pure helpers ─────────────────────────────────────────────────────────

def test_candidate_vaults_last_first_then_the_folder_without_duplicates(tmp_path):
    from ui.remote_login import candidate_vaults
    for name in ("b.vault", "A.vault", "x.txt"):
        (tmp_path / name).write_bytes(b"")
    last = str(tmp_path / "b.vault")
    got = [os.path.basename(p) for p in candidate_vaults(str(tmp_path), last)]
    assert got == ["b.vault", "A.vault"]
    assert candidate_vaults(str(tmp_path / "none"), str(tmp_path / "gone.vault")) == []


def test_search_and_www_address():
    from ui.remote_panel import database_matches, machine_matches, www_url
    m = models.Machine(ip="10.1.2.3", name="srvDB", description="Oracle prod")
    assert machine_matches(m, "") and machine_matches(m, "oracle")
    assert machine_matches(m, "10.1.2") and not machine_matches(m, "srvapp")
    assert database_matches(models.Database(host="h", name="AMMS"), "amms")
    assert www_url(models.Machine(ip="10.0.0.3")) == "https://10.0.0.3"
    assert www_url(models.Machine(www_url="pam.x.example")) == "https://pam.x.example"
    assert www_url(models.Machine(www_url="http://a")) == "http://a"


def test_data_dir_is_beside_the_program_or_the_users_folder(tmp_path, monkeypatch):
    import remote_main
    assert remote_main.data_dir(str(tmp_path)) == str(tmp_path / "dane")
    monkeypatch.setattr(remote_main, "_writable", lambda _f: False)
    monkeypatch.setenv("APPDATA", str(tmp_path / "ad"))
    assert remote_main.data_dir(str(tmp_path)) == str(tmp_path / "ad" / "HospitalHubRemote")


def test_config_follows_hh_data_dir(tmp_path, monkeypatch):
    import config
    monkeypatch.setenv("HH_DATA_DIR", str(tmp_path / "dane"))
    assert config._config_path() == tmp_path / "dane" / "config.json"
    monkeypatch.delenv("HH_DATA_DIR")
    monkeypatch.setenv("APPDATA", str(tmp_path / "ad"))
    assert config._config_path() == tmp_path / "ad" / "HospitalHubV2" / "config.json"


# ── The window ───────────────────────────────────────────────────────────

def test_the_window_opens_on_its_machine_list(window):
    tabs = window._left_tabs
    assert tabs.tabText(0) == "Maszyny" and tabs.widget(0) is window._env_panel
    assert tabs.currentWidget() is window._env_panel
    assert tabs.tabText(1) == "Pliki"
    assert window._sessions == []                  # nothing connects by itself
    assert window.windowTitle() == "HospitalHub Portable  ·  Szpital Betanin"
    assert window._btn_claude.isHidden()


def test_the_list_holds_every_type_and_hides_admin_items(window):
    panel = window._env_panel
    items = _texts(panel)
    assert [getattr(i, "name", "") for i in items] == [
        "srvAPP", "srvWin", "portal", "AMMS"]
    assert not panel._admin_btn.isHidden()
    window.set_admin_mode(True)
    assert "ukryta" in [getattr(i, "name", "") for i in _texts(panel)]
    window.set_admin_mode(False)
    assert "ukryta" not in [getattr(i, "name", "") for i in _texts(panel)]


def test_search_filters_the_list(window):
    panel = window._env_panel
    panel._search.setText("oracle")
    assert [i.name for i in _texts(panel)] == ["AMMS"]
    panel._search.setText("brak-takiej")
    assert _texts(panel) == []
    panel._search.clear()
    assert len(_texts(panel)) == 4


def test_ssh_goes_to_the_window_and_the_other_types_launch_here(window, monkeypatch):
    from ui import db_connect, rdp, remote_panel
    panel = window._env_panel
    opened, rdps, urls, dbs = [], [], [], []
    monkeypatch.setattr(window, "_open_extra_machine", opened.append)
    panel.open_machine.disconnect()
    panel.open_machine.connect(window._open_extra_machine)
    monkeypatch.setattr(rdp, "connect_rdp", lambda m, *a: rdps.append(m.ip))
    monkeypatch.setattr(db_connect, "connect_db", lambda d, *a: dbs.append(d.name))
    monkeypatch.setattr(remote_panel.QDesktopServices, "openUrl",
                        staticmethod(lambda u: urls.append(u.toString())))
    for item in _texts(panel):
        kind = panel._kinds[id(item)]
        panel._connect(item, kind)
    assert [m.ip for m in opened] == ["10.0.0.1"]
    assert rdps == ["10.0.0.2"] and dbs == ["AMMS"]
    assert urls == ["https://pam.szpital-x.example"]


def test_the_admin_login_is_offered_only_when_unlocked(window):
    panel = window._env_panel
    srv = _texts(panel)[0]

    def labels():
        menu = panel._menu(id(srv))
        return [a.text() for a in menu.actions()]
    assert not any("root" in t for t in labels())
    window.set_admin_mode(True)
    srv = _texts(panel)[0]
    assert any("root" in t for t in labels())


def test_an_edit_is_saved_to_the_vault_at_once(window, vault):
    path = vault[0]
    h = window._env_panel.current_hospital()
    h.machines.append(models.Machine(ip="10.0.0.7", name="nowa"))
    window._env_panel._changed()
    data = decrypt(open(path, "rb").read(), "haslo")
    (saved,) = models.from_dict(data)
    assert "nowa" in [m.name for m in saved.machines]
    assert "ukryta" in [m.name for m in saved.machines]  # admin items stay
    assert data["admin_hash"] == vault[1]
    assert [i.name for i in _texts(window._env_panel)][-2:] == ["nowa", "AMMS"]


def test_a_vault_changed_on_disk_is_not_overwritten_without_a_question(
        window, vault, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox
    path = vault[0]
    other = encrypt(models.to_dict([models.Hospital(name="cudzy")]), "haslo")
    with open(path, "wb") as f:
        f.write(other)
    os.utime(path, ns=(1, 1))
    asked = []

    def refuse(box):
        asked.append(box.text())
        return 0
    monkeypatch.setattr(QMessageBox, "exec", refuse)
    assert window._save() is False
    assert asked and "zmienił się" in asked[0]
    assert open(path, "rb").read() == other          # untouched

    def overwrite(box):
        for b in box.buttons():
            if b.text() == "Zapisz mimo to":
                b.click()
        return 0
    monkeypatch.setattr(QMessageBox, "exec", overwrite)
    assert window._save() is True
    (saved,) = models.from_dict(decrypt(open(path, "rb").read(), "haslo"))
    assert saved.name == "Szpital Betanin"
    # Saved: the next save does not ask again.
    asked.clear()
    monkeypatch.setattr(QMessageBox, "exec", refuse)
    assert window._save() is True and asked == []


def test_closing_the_last_session_returns_to_the_machines(window):
    window._left_tabs.setCurrentWidget(window._sftp_panel)
    window._on_tab_changed(-1)
    assert window._left_tabs.currentWidget() is window._env_panel


def test_a_vault_without_hospitals_opens_with_an_empty_one(app, tmp_path):
    from ui.remote_window import RemoteWindow
    path = tmp_path / "pusty.vault"
    path.write_bytes(encrypt(models.to_dict([]), "p"))
    hospitals = []
    w = RemoteWindow(str(path), "p", hospitals)
    try:
        assert len(hospitals) == 1 and w._env_panel._admin_btn.isHidden()
        assert _texts(w._env_panel) == []
    finally:
        w.close_without_asking()
        pump(100)


# ── Login ────────────────────────────────────────────────────────────────

def _wait(cond, seconds=10):
    end = time.monotonic() + seconds
    while not cond() and time.monotonic() < end:
        pump(50)


def test_login_opens_the_exported_vault_and_refuses_a_wrong_password(app, vault):
    from ui.remote_login import RemoteLoginDialog
    path = vault[0]
    dlg = RemoteLoginDialog(os.path.dirname(path))
    assert dlg._combo.currentData() == path
    dlg._pass.setText("zle")
    dlg._open()
    _wait(lambda: not dlg._error.isHidden())
    # The error under the field, not a message box; the field is emptied.
    assert dlg._error.text() and dlg.get_result() is None
    assert dlg._pass.text() == "" and dlg._open_btn.isEnabled()
    dlg._pass.setText("haslo")
    dlg._open()
    _wait(lambda: dlg.get_result() is not None)
    got = dlg.get_result()
    assert got[0] == path and got[2][0].name == "Szpital Betanin" and got[3] == vault[1]


def test_login_refuses_a_vpn_vault(app, tmp_path):
    from ui.remote_login import RemoteLoginDialog
    path = tmp_path / "vpn.vault"
    path.write_bytes(encrypt(models.vpn_to_dict([models.VpnProfile(name="x")]), "p"))
    dlg = RemoteLoginDialog(str(tmp_path))
    dlg._pass.setText("p")
    dlg._open()
    _wait(lambda: not dlg._error.isHidden())
    assert "VPN" in dlg._error.text() and dlg.get_result() is None


def test_the_login_is_logo_name_password_and_open(app, vault, tmp_path):
    from PyQt6.QtWidgets import QPushButton
    from ui.remote_login import APP_NAME, RemoteLoginDialog
    dlg = RemoteLoginDialog(str(tmp_path / "elsewhere"), last=vault[0])
    dlg.show()
    pump(50)
    assert dlg.windowTitle() == APP_NAME == "HospitalHub Portable"
    assert dlg._remembered_lbl.text() == "Szpital Betanin"   # no ".vault"
    visible = [b.text() for b in dlg.findChildren(QPushButton) if b.isVisible()]
    assert visible == ["Zmień", "Otwórz"]                   # no "Zamknij"
    assert dlg._error.isHidden()
    dlg._open()                                            # no password
    assert dlg._error.text() == "Podaj hasło." and not dlg._error.isHidden()
    dlg._pass.setText("x")
    dlg._pass.textEdited.emit("x")
    assert dlg._error.isHidden()
    dlg.close()


# ── The hospital heading (owner, 2026-10-28) ────────────────────────────

def test_the_hospital_heading_never_takes_the_focus(window):
    from PyQt6.QtCore import Qt
    btn = window._env_panel._hospital_btn
    assert btn.focusPolicy() == Qt.FocusPolicy.NoFocus
    # One hospital: nothing to choose, so no hover and no hand cursor.
    assert ":hover" not in btn.styleSheet()
    assert btn.cursor().shape() == Qt.CursorShape.ArrowCursor


def test_several_hospitals_keep_a_menu_button(app):
    from PyQt6.QtCore import Qt
    from ui.remote_panel import RemoteMachinesPanel
    panel = RemoteMachinesPanel([models.Hospital(name="A"), models.Hospital(name="B")])
    btn = panel._hospital_btn
    assert ":hover" in btn.styleSheet()
    assert btn.cursor().shape() == Qt.CursorShape.PointingHandCursor
    assert btn.focusPolicy() == Qt.FocusPolicy.NoFocus


# ── Cards: one line that fits, the description in a hover bubble ─────────
# (owner, 2026-10-28: descriptions on the cards pushed the buttons out of the
# panel; the bubble shows at once and follows the cursor)

def _desc_panel():
    from ui.remote_panel import RemoteMachinesPanel
    h = models.Hospital(name="X", machines=[
        models.Machine(ip="10.0.0.1", name="srvPi1",
                       description="Tomcat: eRejestracja\nHL7 bridge"),
        models.Machine(ip="10.0.0.2", name="bez"),
    ], databases=[models.Database(
        host="jdbc:oracle:thin:@10.0.0.20:1521:szpital", port="1521",
        name="Szpital", note="+DATA/SZPITAL/DATAFILE/")])
    return RemoteMachinesPanel([h]), h


def test_a_long_address_never_pushes_the_buttons_out(app):
    from PyQt6.QtWidgets import QPushButton
    from ui.remote_panel import _CardLine
    panel, h = _desc_panel()
    panel.resize(300, 600)
    panel.show()
    pump(100)
    viewport = panel._scroll.viewport()
    for key in panel._order:
        btn = panel._cards[key].findChild(QPushButton)
        right = btn.mapTo(viewport, btn.rect().topRight()).x()
        assert right <= viewport.width(), panel._items[key]
    line = panel._cards[id(h.databases[0])].findChild(_CardLine)
    assert line.shown_text().endswith("…")
    short = panel._cards[id(h.machines[1])].findChild(_CardLine)
    assert short.shown_text() == "10.0.0.2  bez"
    panel.close()


def test_descriptions_are_in_the_bubble_not_on_the_cards(app, monkeypatch):
    from PyQt6.QtCore import QPoint
    from PyQt6.QtWidgets import QLabel
    from ui import remote_panel
    panel, h = _desc_panel()
    panel.resize(300, 600)
    panel.show()
    pump(50)
    srv, bare, db = h.machines[0], h.machines[1], h.databases[0]
    assert set(panel._tips) == {id(srv), id(db)}
    card = panel._cards[id(srv)]
    assert not card.findChildren(QLabel)            # nothing but the line + button
    monkeypatch.setattr(panel.window(), "isActiveWindow", lambda: True)
    where = {"pos": card.mapToGlobal(card.rect().center())}
    monkeypatch.setattr(remote_panel.QCursor, "pos",
                        staticmethod(lambda: QPoint(where["pos"])))
    card.enterEvent(None)
    tip = panel._tip
    assert tip.isVisible()
    assert "Tomcat: eRejestracja<br>HL7 bridge" in tip.text() and "srvPi1" in tip.text()
    first = tip.pos()
    # It follows the cursor while it stays on the card.
    where["pos"] = where["pos"] + QPoint(6, 0)
    panel._follow_tip()
    assert tip.isVisible() and tip.pos() != first
    # Off the card: gone.
    where["pos"] = card.mapToGlobal(card.rect().bottomRight()) + QPoint(60, 60)
    panel._follow_tip()
    assert not tip.isVisible()
    # A card without a description shows nothing.
    panel._show_tip(id(bare))
    assert not tip.isVisible()
    panel.close()


def test_a_click_or_a_rebuild_hides_the_bubble(app):
    from PyQt6.QtCore import Qt
    panel, h = _desc_panel()
    panel.show()
    pump(50)
    key = id(h.machines[0])

    class _Right:
        def button(self):
            return Qt.MouseButton.RightButton

    panel._show_tip(key)
    assert panel._tip.isVisible()
    panel._clicked(key, _Right())
    assert not panel._tip.isVisible()
    panel._show_tip(key)
    panel._search.setText("srv")                    # the list is rebuilt
    assert not panel._tip.isVisible()
    panel.close()


# ── Login: the remembered vault, and Enter (owner, 2026-10-28) ──────────

def test_a_remembered_vault_asks_for_the_password_only(app, vault, tmp_path):
    from ui.remote_login import RemoteLoginDialog
    path = vault[0]
    dlg = RemoteLoginDialog(str(tmp_path / "elsewhere"), last=path)
    dlg.show()
    pump(50)
    assert dlg._remembered_row.isVisible() and not dlg._file_row.isVisible()
    assert dlg._remembered_lbl.text() == "Szpital Betanin"
    assert dlg._combo.currentData() == path
    dlg._show_file_row()
    assert dlg._file_row.isVisible() and not dlg._remembered_row.isVisible()
    dlg.close()


def test_without_a_remembered_vault_the_file_row_shows(app, vault):
    from ui.remote_login import RemoteLoginDialog
    dlg = RemoteLoginDialog(os.path.dirname(vault[0]), last="C:/nie/ma/takiego.vault")
    dlg.show()
    pump(50)
    assert dlg._file_row.isVisible() and not dlg._remembered_row.isVisible()
    dlg.close()


def test_enter_in_the_password_opens_and_never_closes(app, vault):
    from PyQt6.QtCore import Qt
    from PyQt6.QtTest import QTest
    from PyQt6.QtWidgets import QDialog
    from ui.remote_login import RemoteLoginDialog
    dlg = RemoteLoginDialog(os.path.dirname(vault[0]), last=vault[0])
    finished = []
    dlg.finished.connect(finished.append)
    dlg.show()
    pump(50)
    dlg._pass.setText("haslo")
    QTest.keyClick(dlg._pass, Qt.Key.Key_Return)
    QTest.keyClick(dlg._pass, Qt.Key.Key_Return)   # a second Enter while busy
    end = time.monotonic() + 10
    while not finished and time.monotonic() < end:
        pump(50)
    assert finished == [QDialog.DialogCode.Accepted.value]
    assert dlg.get_result()[0] == vault[0]
