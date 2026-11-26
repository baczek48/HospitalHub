"""2026-11-24: „Scal zmiany z innego vaulta…” in the window — the history
saved with the vault, a colleague's file merged, the dialog's ticks.
Made-up data only (TEST-NET, .example)."""

import copy
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for _p in (_PARENT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import models  # noqa: E402
import vault_merge as vm  # noqa: E402
import vault_sync as vs  # noqa: E402
from crypto import decrypt, encrypt  # noqa: E402
from test_vault_merge import base_vault, machine  # noqa: E402

PW = "haslo-zespolu"


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture
def quiet(monkeypatch):
    from PyQt6.QtWidgets import QMessageBox
    shown = []
    for name in ("information", "critical", "warning"):
        monkeypatch.setattr(QMessageBox, name,
                            staticmethod(lambda *a, **k: shown.append(a[2] if len(a) > 2 else "")))
    return shown


def write(path, data, password=PW):
    with open(path, "wb") as f:
        f.write(encrypt(data, password))


def read(path, password=PW):
    with open(path, "rb") as f:
        return decrypt(f.read(), password)


def open_window(path, data=None, vault_type="global"):
    from ui import main_window as mw
    data = data if data is not None else read(path)
    vs.note_loaded(path, data)
    items = (models.vpn_from_dict(data) if vault_type == "vpn" else models.from_dict(data))
    return mw.MainWindow(path, PW, items, data.get("admin_hash", ""),
                         data.get("admin_salt", ""), vault_type=vault_type)


def accept_defaults(monkeypatch, pick=None):
    from ui.vault_merge_dialog import VaultMergeDialog

    def fake_exec(self):
        self.chosen = ({c.key for c in self.plan.visible if c.default}
                       if pick is None else pick(self.plan))
        return True
    monkeypatch.setattr(VaultMergeDialog, "exec", fake_exec)


def test_saving_writes_the_history_into_the_vault(app, tmp_path, quiet):
    path = str(tmp_path / "moj.vault")
    write(path, base_vault())
    w = open_window(path)
    try:
        w._hospitals[0].machines[0].credentials[0].password = "nowe"
        assert w._save()
        data = read(path)
        assert data["sync"]["seen"]["c1.password"] == [vs.value_hash("stare")]
        # A second save without changes keeps it.
        assert w._save() and read(path)["sync"]["seen"]["c1.password"]
    finally:
        w._unsaved = False


def test_merge_from_a_colleagues_file(app, tmp_path, monkeypatch, quiet):
    mine_path, theirs_path = str(tmp_path / "moj.vault"), str(tmp_path / "kolegi.vault")
    common = base_vault()
    write(mine_path, common)
    theirs = copy.deepcopy(common)
    theirs["hospitals"][1]["machines"].append(
        {"id": "m-new", "ip": "198.51.100.7", "name": "srvPACS", "credentials": []})
    machine(theirs, "h1")["notes"] += "\nNowy numer: 999"
    write(theirs_path, theirs)
    w = open_window(mine_path)
    m1 = w._hospitals[0].machines[0]
    try:
        accept_defaults(monkeypatch)
        w._merge_from_vault(theirs_path)
        assert w._unsaved
        assert w._hospitals[0].machines[0] is m1, "otwarte panele trzymają te obiekty"
        assert [m.name for m in w._hospitals[1].machines] == ["srvPACS"]
        assert w._hospitals[0].notes.endswith("Nowy numer: 999")
        assert "Zapisz vault" in quiet[-1]
        assert w._save()
        saved = read(mine_path)
        assert [m["id"] for m in saved["hospitals"][1]["machines"]] == ["m-new"]
        assert "sync" in saved
    finally:
        w._unsaved = False


def test_a_vault_under_another_password_asks_for_it(app, tmp_path, monkeypatch, quiet):
    from PyQt6.QtWidgets import QInputDialog
    mine_path, theirs_path = str(tmp_path / "moj.vault"), str(tmp_path / "kolegi.vault")
    write(mine_path, base_vault())
    theirs = base_vault()
    machine(theirs, "c1")["password"] = "kolegi"
    write(theirs_path, theirs, password="inne-haslo")
    asked = []
    monkeypatch.setattr(QInputDialog, "getText",
                        staticmethod(lambda *a, **k: asked.append(a[2]) or ("inne-haslo", True)))
    accept_defaults(monkeypatch, pick=lambda plan: {"f:c1:password"})
    w = open_window(mine_path)
    try:
        w._merge_from_vault(theirs_path)
        assert asked and "innym hasłem" in asked[0]
        assert w._hospitals[0].machines[0].credentials[0].password == "kolegi"
    finally:
        w._unsaved = False


def test_nothing_new_is_said_and_nothing_changes(app, tmp_path, quiet):
    mine_path, theirs_path = str(tmp_path / "moj.vault"), str(tmp_path / "kolegi.vault")
    write(mine_path, base_vault())
    write(theirs_path, base_vault())
    w = open_window(mine_path)
    try:
        w._merge_from_vault(theirs_path)
        assert not w._unsaved and "Nie ma nic nowego" in quiet[-1]
    finally:
        w._unsaved = False


def test_a_vpn_vault_is_refused_in_a_hospital_vault(app, tmp_path, quiet):
    mine_path, theirs_path = str(tmp_path / "moj.vault"), str(tmp_path / "vpn.vault")
    write(mine_path, base_vault())
    write(theirs_path, {"vpn_profiles": [{"id": "p1", "name": "Alfa"}]})
    w = open_window(mine_path)
    try:
        w._merge_from_vault(theirs_path)
        assert not w._unsaved and "VPN" in quiet[-1]
    finally:
        w._unsaved = False


def test_vpn_window_merges_profiles(app, tmp_path, monkeypatch, quiet):
    from ui import detail_panel as dp
    from ui import vpn_panel
    monkeypatch.setattr(dp, "_vpn_session_profiles", [])
    monkeypatch.setattr(dp, "_vpn_session_loaded", False)
    monkeypatch.setattr(dp, "_vpn_window_source", None)
    monkeypatch.setattr(vpn_panel.VpnPanel, "_poll_status", lambda self: None)
    monkeypatch.setattr(dp.DetailPanel, "_poll_vpn_status", lambda self: None)
    mine_path, theirs_path = str(tmp_path / "vpn.vault"), str(tmp_path / "vpn-kolegi.vault")
    write(mine_path, {"vpn_profiles": [{"id": "p1", "name": "Alfa", "server": "a.example"}]})
    write(theirs_path, {"vpn_profiles": [{"id": "p1", "name": "Alfa", "server": "a.example"},
                                          {"id": "p2", "name": "Beta", "server": "b.example"}]})
    accept_defaults(monkeypatch)
    w = open_window(mine_path, vault_type="vpn")
    try:
        w._merge_from_vault(theirs_path)
        assert [p.name for p in w._hospitals] == ["Alfa", "Beta"]
        assert w._vpn_panel._profiles is w._hospitals
    finally:
        w._unsaved = False
        w.destroy_cleanup()


def test_file_menu_offers_the_merge(app, tmp_path, quiet):
    path = str(tmp_path / "moj.vault")
    write(path, base_vault())
    w = open_window(path)
    try:
        plik = next(a.menu() for a in w.menuBar().actions() if a.text() == "Plik")
        assert "Scal zmiany z innego vaulta…" in [a.text() for a in plik.actions()]
    finally:
        w._unsaved = False


# ── the dialog ─────────────────────────────────────────────────────────────

def a_plan(show_admin=False):
    common = base_vault()
    theirs = copy.deepcopy(common)
    machine(theirs, "c1")["password"] = "kolegi"                   # conflict
    theirs["hospitals"].append({"id": "h3", "name": "Szpital Gamma", "notes": "",
                                "machines": [], "databases": []})  # new
    machine(theirs, "c2")["password"] = "admin-kolegi"             # admin
    return vm.plan(common, theirs, show_admin=show_admin)


def rows(dlg):
    """The rows with a decision (leaves), in tree order."""
    out = []

    def walk(item):
        for i in range(item.childCount()):
            child = item.child(i)
            if child.childCount():
                walk(child)
            else:
                out.append(child)
    walk(dlg._tree.invisibleRootItem())
    return out


def all_texts(dlg):
    out = []

    def walk(item):
        for i in range(item.childCount()):
            out.append(item.child(i).text(0))
            walk(item.child(i))
    walk(dlg._tree.invisibleRootItem())
    return out


def test_dialog_lists_masks_and_ticks(app):
    from PyQt6.QtCore import Qt
    from ui.vault_merge_dialog import MASK, VaultMergeDialog
    dlg = VaultMergeDialog(None, "kolegi.vault", a_plan())
    texts = {r.text(0): r for r in rows(dlg)}
    pw = next(r for t, r in texts.items() if t.endswith("Hasło"))
    assert pw.text(2) == MASK and pw.text(3) == MASK
    assert pw.checkState(0) == Qt.CheckState.Unchecked            # conflict: mine
    new = next(r for t, r in texts.items() if t == "Cały szpital")
    assert new.parent().text(0) == "Szpital Gamma"
    assert new.checkState(0) == Qt.CheckState.Checked
    assert dlg._admin_note.isVisibleTo(dlg) and "1 zmiana zostanie" in dlg._admin_note.text()
    dlg._show_secrets.setChecked(True)
    pw = next(r for r in rows(dlg) if r.text(0).endswith("Hasło"))
    assert pw.text(2) == "stare" and pw.text(3) == "kolegi"
    dlg._only_conflicts.setChecked(True)
    assert [r.text(1) for r in rows(dlg)] == ["różne wartości"]
    dlg._only_conflicts.setChecked(False)
    dlg._tick_all(True)
    dlg._accept()
    assert dlg.chosen == {"f:c1:password", "a:h3"}


def test_dialog_unlocks_admin_and_shows_admin_rows(app):
    from ui.vault_merge_dialog import VaultMergeDialog
    dlg = VaultMergeDialog(None, "kolegi.vault", a_plan(),
                           replan=lambda show: a_plan(show), unlock=lambda: True)
    assert not any("[admin]" in t for t in all_texts(dlg))
    dlg._on_unlock()
    assert any("[admin]" in t for t in all_texts(dlg))
    assert not dlg._admin_note.isVisibleTo(dlg)


def test_dialog_groups_fields_under_their_item_and_explains_the_row(app):
    from ui.vault_merge_dialog import VaultMergeDialog
    common = base_vault()
    theirs = copy.deepcopy(common)
    h = theirs["hospitals"][0]
    h["amms_url"], h["amms_login"], h["amms_password"] = (
        "https://amms.alfa.example/", "OPERATOR", "x")
    dlg = VaultMergeDialog(None, "importowany.vault", vm.plan(common, theirs, show_admin=True))
    group = dlg._tree.topLevelItem(0)
    assert group.text(0) == "Szpital Alfa" and group.text(1) == "3 zmiany"
    item = group.child(0)
    assert item.text(0) == "Dane szpitala"
    assert [item.child(i).text(0) for i in range(3)] == [
        "AMMS – adres", "AMMS – login", "AMMS – hasło"]
    assert {item.child(i).text(1) for i in range(3)} == {"uzupełnienie"}
    dlg._tree.setCurrentItem(item.child(0))
    assert "pole jest puste" in dlg._detail_head.text()
    assert dlg._theirs_pane.text.toPlainText() == "https://amms.alfa.example/"
    assert dlg._mine_pane.text.toPlainText() == "(puste)"


def test_one_machine_once_with_its_logins_under_it_and_closed_at_start(app):
    """Owner, 2026-11-25: two rows starting with the same machine read like
    two machines; and the list should start closed."""
    from ui.vault_merge_dialog import VaultMergeDialog
    mine = base_vault()
    theirs = copy.deepcopy(mine)
    machine(theirs, "c1")["login"] = "ALFA\platforma"
    machine(theirs, "m1")["credentials"].append(
        {"id": "c-new", "login": "DIN046\Admin", "password": "x"})
    dlg = VaultMergeDialog(None, "importowany.vault", vm.plan(mine, theirs, show_admin=True))
    group = dlg._tree.topLevelItem(0)
    assert dlg._tree.topLevelItemCount() == 1 and not group.isExpanded()
    assert group.childCount() == 1
    srv = group.child(0)
    assert srv.text(0) == "Maszyna srvAPP (192.0.2.10)"
    assert [srv.child(i).text(0) for i in range(srv.childCount())] == [
        "Login root", "Login DIN046\Admin"]
    assert srv.child(0).child(0).text(0) == "Login"
    assert srv.child(1).text(1) == "nowy element"


def test_skipped_rows_only_on_request(app):
    from ui.vault_merge_dialog import VaultMergeDialog
    mine = base_vault()
    mine["hospitals"][0]["amms_login"] = "OPERATOR"           # empty in the import
    theirs = base_vault()
    theirs["hospitals"].append({"id": "h3", "name": "Szpital Gamma", "machines": [],
                                "databases": []})
    dlg = VaultMergeDialog(None, "importowany.vault", vm.plan(mine, theirs, show_admin=True))
    assert [r.text(1) for r in rows(dlg)] == ["nowy element"]
    assert dlg._show_skipped.text() == "Pokaż pominięte (1)"
    assert "Pokaż pominięte" in dlg._quiet.text()
    dlg._show_skipped.setChecked(True)
    assert sorted(r.text(1) for r in rows(dlg)) == ["nowy element", "puste w importowanym"]
    assert dlg._ok.text() == "Scal zaznaczone (1)"
