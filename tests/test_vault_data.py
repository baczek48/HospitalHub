"""Vault data integrity (2026-10-14, Etap 65): crypto, models, saving, config.

Until this file nothing tested the code that holds the user's data.  The
audit of that code (C2–C6) found ways to lose it: a failed save followed by a
close (C4-01), a vault opened as the wrong type and saved empty (C4-02), a new
vault created over an existing one (C4-03), a password change that stuck in
memory after its save failed (C4-04), no backup and a single-shot replace
(C4-05), a damaged config.json stopping the login dialog (C4-07).

Everything runs on temporary files; Argon2 is made cheap for speed, and the
production parameters are pinned by a test of their own.  APPDATA is a fresh
temporary directory for every test (conftest).
"""

import base64
import json
import os
import sys
from types import SimpleNamespace

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import config  # noqa: E402
import crypto  # noqa: E402
import models  # noqa: E402
import vault_io  # noqa: E402


@pytest.fixture
def cheap_argon(monkeypatch):
    """Argon2 parameters are module globals read at call time."""
    monkeypatch.setattr(crypto, "ARGON2_TIME_COST", 1)
    monkeypatch.setattr(crypto, "ARGON2_MEMORY_COST", 8)
    monkeypatch.setattr(crypto, "ARGON2_PARALLELISM", 1)


# ══════════════════════════════════════════════════════════════════════════
# 1. crypto
# ══════════════════════════════════════════════════════════════════════════

def test_1_production_parameters_and_format_are_pinned():
    assert (crypto.ARGON2_TIME_COST, crypto.ARGON2_MEMORY_COST,
            crypto.ARGON2_PARALLELISM) == (3, 65536, 4)
    assert crypto._MAGIC == b"HHUB" and crypto._BIN_VERSION == 2
    assert crypto._HEADER_SIZE == 33


def test_2_round_trip_keeps_polish_text(cheap_argon):
    data = {"hospitals": [{"name": "Szpital Zażółć Gęślą", "notes": "ąćęłńóśźż"}]}
    blob = crypto.encrypt(data, "hasło-główne")
    assert blob[:4] == b"HHUB"
    assert crypto.decrypt(blob, "hasło-główne") == data


def test_3_wrong_password_is_a_value_error(cheap_argon):
    blob = crypto.encrypt({"hospitals": []}, "dobre-haslo")
    with pytest.raises(ValueError):
        crypto.decrypt(blob, "zle-haslo")


@pytest.mark.parametrize("offset", [5, 21, 33, -1])   # salt, nonce, ciphertext, tag
def test_4_any_flipped_byte_is_refused(cheap_argon, offset):
    blob = bytearray(crypto.encrypt({"hospitals": []}, "haslo1234"))
    blob[offset] ^= 0x01
    with pytest.raises(ValueError):
        crypto.decrypt(bytes(blob), "haslo1234")


def test_5_two_saves_never_reuse_salt_or_nonce(cheap_argon):
    a = crypto.encrypt({"hospitals": []}, "haslo1234")
    b = crypto.encrypt({"hospitals": []}, "haslo1234")
    assert a[5:33] != b[5:33]


def test_6_reencrypt_changes_the_password(cheap_argon):
    blob = crypto.encrypt({"vpn_profiles": []}, "stare-haslo")
    new = crypto.reencrypt(blob, "stare-haslo", "nowe-haslo")
    assert crypto.decrypt(new, "nowe-haslo") == {"vpn_profiles": []}
    with pytest.raises(ValueError):
        crypto.decrypt(new, "stare-haslo")


def test_7_admin_password_round_trip_and_damaged_hash(cheap_argon):
    h, s = crypto.hash_admin_password("admin-pass")
    assert crypto.verify_admin_password("admin-pass", h, s)
    assert not crypto.verify_admin_password("other", h, s)
    # A damaged stored hash or salt is a "no", never an exception (C4-07).
    for bad_h, bad_s in (("%%%", s), (h, "%%%"), ("", s), (h, ""),
                         (base64.b64encode(b"short").decode(), s)):
        assert crypto.verify_admin_password("admin-pass", bad_h, bad_s) is False


# ══════════════════════════════════════════════════════════════════════════
# 2. models
# ══════════════════════════════════════════════════════════════════════════

def test_8_hospital_round_trip_is_lossless():
    data = {"hospitals": [{
        "id": "h1", "name": "Szpital A", "notes": "n", "www_url": "https://x",
        "admin_only": True,
        "machines": [{"id": "m1", "name": "srv", "ip": "10.0.0.1",
                      "rdp_drives": ["C:"], "admin_only": False}],
    }]}
    once = models.to_dict(models.from_dict(data))
    twice = models.to_dict(models.from_dict(once))
    assert once == twice
    assert once["hospitals"][0]["name"] == "Szpital A"


def test_9_vpn_round_trip_is_lossless():
    profiles = models.vpn_from_dict({"vpn_profiles": [{
        "id": "v1", "name": "VPN A", "provider": "FortiClient", "server": "s",
        "port": "443", "login": "l", "password": "p", "profile_name": "SZPITAL-A",
        "requires_2fa": True}]})
    assert models.vpn_from_dict(models.vpn_to_dict(profiles)) == profiles
    assert profiles[0].profile_name == "SZPITAL-A"


def test_10_full_cycle_models_encrypt_decrypt_models(cheap_argon):
    hospitals = models.from_dict({"hospitals": [{"id": "h1", "name": "A"}]})
    blob = crypto.encrypt(models.to_dict(hospitals), "haslo1234")
    assert models.from_dict(crypto.decrypt(blob, "haslo1234")) == hospitals


# ══════════════════════════════════════════════════════════════════════════
# 3. vault_io — saving and the type check
# ══════════════════════════════════════════════════════════════════════════

def test_11_write_replaces_and_keeps_a_backup(tmp_path):
    path = tmp_path / "x.vault"
    path.write_bytes(b"OLD")
    vault_io.write_vault_atomic(str(path), b"NEW")
    assert path.read_bytes() == b"NEW"
    assert (tmp_path / "x.vault.bak").read_bytes() == b"OLD"
    assert not list(tmp_path.glob("*.tmp"))


def test_12_first_write_has_nothing_to_back_up(tmp_path):
    path = tmp_path / "new.vault"
    vault_io.write_vault_atomic(str(path), b"DATA")
    assert path.read_bytes() == b"DATA"
    assert not (tmp_path / "new.vault.bak").exists()


def test_13_a_failed_replace_leaves_the_original_and_no_temp(tmp_path, monkeypatch):
    path = tmp_path / "x.vault"
    path.write_bytes(b"ORIGINAL")

    def boom(src, dst):
        raise OSError("disk full")
    monkeypatch.setattr(vault_io.os, "replace", boom)
    with pytest.raises(OSError):
        vault_io.write_vault_atomic(str(path), b"NEW")
    assert path.read_bytes() == b"ORIGINAL"
    assert not list(tmp_path.glob("*.tmp"))


def test_14_replace_is_retried_while_the_file_is_held(tmp_path, monkeypatch):
    """Antivirus or OneDrive holding the file for a moment is not a failed save."""
    path = tmp_path / "x.vault"
    path.write_bytes(b"OLD")
    real = os.replace
    calls = []

    def held_twice(src, dst):
        calls.append(1)
        if len(calls) <= 2:
            raise PermissionError("in use")
        return real(src, dst)
    monkeypatch.setattr(vault_io.os, "replace", held_twice)
    vault_io.write_vault_atomic(str(path), b"NEW", sleep=lambda s: None)
    assert path.read_bytes() == b"NEW" and len(calls) == 3


def test_15_a_file_held_for_good_fails_the_save_cleanly(tmp_path, monkeypatch):
    path = tmp_path / "x.vault"
    path.write_bytes(b"OLD")

    def held(src, dst):
        raise PermissionError("in use")
    monkeypatch.setattr(vault_io.os, "replace", held)
    with pytest.raises(PermissionError):
        vault_io.write_vault_atomic(str(path), b"NEW", sleep=lambda s: None)
    assert path.read_bytes() == b"OLD"
    assert not list(tmp_path.glob("*.tmp"))


def test_16_a_backup_that_cannot_be_made_does_not_stop_the_save(tmp_path, monkeypatch):
    path = tmp_path / "x.vault"
    path.write_bytes(b"OLD")

    def no_copy(*a, **k):
        raise OSError("no space for a backup")
    monkeypatch.setattr(vault_io.shutil, "copy2", no_copy)
    vault_io.write_vault_atomic(str(path), b"NEW")
    assert path.read_bytes() == b"NEW"


@pytest.mark.parametrize("data,vtype,refused", [
    ({"vpn_profiles": [1]}, "global", True),
    ({"vpn_profiles": [1]}, "private", True),
    ({"hospitals": [1]}, "vpn", True),
    ({"hospitals": []}, "global", False),
    ({"vpn_profiles": []}, "vpn", False),
    ({}, "vpn", False),                       # neither key: accepted as before
    ({"hospitals": [], "vpn_profiles": []}, "vpn", False),
    ([], "global", True),
])
def test_17_the_vault_type_must_not_contradict_the_file(data, vtype, refused):
    """C4-02: a VPN vault opened as "Ogólny" read as an empty list, and the
    first save wrote that empty list over the profiles."""
    assert (vault_io.vault_kind_error(data, vtype) is not None) is refused


# ══════════════════════════════════════════════════════════════════════════
# 4. config.py
# ══════════════════════════════════════════════════════════════════════════

def config_file():
    return config._config_path()


def test_18_the_tests_never_touch_the_real_appdata():
    assert "AppData" in str(config_file()) and os.environ["APPDATA"] in str(config_file())
    assert "Roaming" not in str(config_file())


@pytest.mark.parametrize("content", [b"{not json", b"\xff\xfe\x00garbage",
                                     b"[1, 2, 3]", b"\"text\"", b"null"])
def test_19_a_damaged_config_reads_as_no_settings(content):
    config_file().write_bytes(content)
    assert config._load_all() == {}
    assert config.load_vault_list() == []
    assert config.load_active_vault_index() == 0
    assert config.load_theme() == "dark"


@pytest.mark.parametrize("index", [-1, "3", None, 2.5])
def test_20_a_bad_active_vault_index_falls_back_to_zero(index):
    config_file().write_text(json.dumps({"active_vault_index": index}), encoding="utf-8")
    assert config.load_active_vault_index() == 0


def test_21_malformed_vault_list_entries_are_dropped(tmp_path):
    real = tmp_path / "v.vault"
    real.write_bytes(b"x")
    config_file().write_text(json.dumps({"vault_list": [
        {"path": str(real), "type": "global"}, "not-a-dict", {"path": None},
        {"type": "vpn"}]}), encoding="utf-8")
    assert [v["path"] for v in config.load_vault_list()] == [str(real)]


def test_22_saving_settings_leaves_no_temp_file_and_round_trips():
    config.save_theme("light")
    config.save_hospital_sort_order("asc")
    assert config.load_theme() == "light"
    assert config.load_hospital_sort_order() == "asc"
    assert not list(config_file().parent.glob("*.tmp"))


def test_23_register_vault_keeps_one_vault_per_type(tmp_path):
    a, b = tmp_path / "a.vault", tmp_path / "b.vault"
    a.write_bytes(b"x")
    b.write_bytes(b"x")
    config.register_vault(str(a), "global")
    config.register_vault(str(b), "global")
    assert [os.path.basename(v["path"]) for v in config.load_vault_list()] == ["b.vault"]


# ══════════════════════════════════════════════════════════════════════════
# 5. The window code around saving (regressions)
# ══════════════════════════════════════════════════════════════════════════

class _Box:
    """Stands in for QMessageBox: records, answers with a chosen button."""

    answer = "Tak"
    shown = []

    from PyQt6.QtWidgets import QMessageBox as _Real
    Icon, ButtonRole = _Real.Icon, _Real.ButtonRole
    del _Real

    def __init__(self, *a, **k):
        self._buttons = {}

    def setWindowTitle(self, *a):
        pass

    def setText(self, *a):
        pass

    def setIcon(self, *a):
        pass

    def addButton(self, text, role):
        btn = object()
        self._buttons[text] = btn
        return btn

    def exec(self):
        pass

    def clickedButton(self):
        return self._buttons.get(_Box.answer)

    @staticmethod
    def critical(*a, **k):
        _Box.shown.append(("critical", a[1] if len(a) > 1 else ""))

    @staticmethod
    def warning(*a, **k):
        _Box.shown.append(("warning", a[1] if len(a) > 1 else ""))

    @staticmethod
    def information(*a, **k):
        _Box.shown.append(("information", a[1] if len(a) > 1 else ""))


class _Window:
    def __init__(self, save_ok):
        self._unsaved = True
        self._save_ok = save_ok
        self.destroyed = False
        self.closed_with_cleanup = False

    def show(self):
        pass

    def raise_(self):
        pass

    def windowTitle(self):
        return "Vault [*]"

    def _save(self):
        return self._save_ok

    def destroy_cleanup(self):
        self.closed_with_cleanup = True

    def deleteLater(self):
        self.destroyed = True


@pytest.fixture
def app_manager(monkeypatch):
    import main
    monkeypatch.setattr(main, "QMessageBox", _Box)
    _Box.answer, _Box.shown = "Tak", []
    removed = []
    quit_called = []
    manager = SimpleNamespace(
        remove_window=removed.append, _windows=[], _trays={},
        _close_all_ssh_dialogs=lambda: None,
        _app=SimpleNamespace(quit=lambda: quit_called.append(True)))
    return main, manager, removed, quit_called


def test_24_a_failed_save_on_close_keeps_the_window(app_manager):
    """C4-01: "Zamknij" → "Tak, zapisz" → the save fails → the window and its
    changes stay; before, the window was destroyed and the changes lost."""
    main, manager, removed, _ = app_manager
    window = _Window(save_ok=False)
    main.AppManager._force_close_window(manager, window)
    assert removed == [] and not window.destroyed


def test_25_a_successful_save_on_close_closes(app_manager):
    main, manager, removed, _ = app_manager
    window = _Window(save_ok=True)
    main.AppManager._force_close_window(manager, window)
    assert removed == [window] and window.destroyed


def test_26_a_failed_save_on_quit_aborts_the_quit(app_manager):
    main, manager, _, quit_called = app_manager
    ok, bad = _Window(save_ok=True), _Window(save_ok=False)
    manager._windows = [ok, bad]
    main.AppManager._quit_all(manager)
    assert quit_called == [] and not bad.closed_with_cleanup


def test_27_a_failed_save_after_a_password_change_restores_the_old_one(
        monkeypatch, tmp_path):
    """C4-04: the file still opens with the old password, so the old one must
    stay in memory — the next Ctrl+S would otherwise lock the user out."""
    import ui.main_window as mw

    class Dlg:
        def __init__(self, parent):
            pass

        def exec(self):
            return True

        def get_passwords(self):
            return "stare-haslo", "nowe-haslo"

    monkeypatch.setattr(mw, "ChangePasswordDialog", Dlg)
    monkeypatch.setattr(mw, "QMessageBox", _Box)
    vault = tmp_path / "x.vault"
    vault.write_bytes(b"x")
    window = SimpleNamespace(_password="stare-haslo", _vault_path=str(vault),
                             _do_save=lambda path: False, _unsaved=False,
                             _update_title=lambda: None)
    mw.MainWindow._change_password(window)
    assert window._password == "stare-haslo"

    window._do_save = lambda path: True
    mw.MainWindow._change_password(window)
    assert window._password == "nowe-haslo"


def test_28_creating_a_vault_never_replaces_an_existing_file(monkeypatch, tmp_path):
    """C4-03: an empty vault written over a real one had no way back."""
    import ui.login_dialog as ld
    monkeypatch.setattr(ld, "QMessageBox", _Box)
    _Box.shown = []
    existing = tmp_path / "real.vault"
    existing.write_bytes(b"REAL DATA")

    def text(value):
        return SimpleNamespace(text=lambda: value)

    dialog = SimpleNamespace(
        _path_edit=text(str(existing)), _pass_edit=text("haslo12345"),
        _pass_confirm=text("haslo12345"), _vault_type="global",
        _result=None, accept=lambda: None)
    ld._CreateVaultDialog._create(dialog)
    assert existing.read_bytes() == b"REAL DATA"
    assert dialog._result is None
    assert _Box.shown and _Box.shown[-1][0] == "warning"


def test_29_creating_a_new_vault_still_works(monkeypatch, tmp_path, cheap_argon):
    import ui.login_dialog as ld
    monkeypatch.setattr(ld, "QMessageBox", _Box)
    target = tmp_path / "new.vault"

    def text(value):
        return SimpleNamespace(text=lambda: value)

    accepted = []
    dialog = SimpleNamespace(
        _path_edit=text(str(target)), _pass_edit=text("haslo12345"),
        _pass_confirm=text("haslo12345"), _vault_type="vpn",
        _result=None, accept=lambda: accepted.append(True))
    ld._CreateVaultDialog._create(dialog)
    assert accepted and crypto.decrypt(target.read_bytes(), "haslo12345") == {
        "vpn_profiles": []}


def test_30_the_save_path_goes_through_the_atomic_writer():
    import ui.main_window as mw
    src = open(mw.__file__, encoding="utf-8").read()
    body = src[src.index("def _do_save"):src.index("def _change_password")]
    assert "write_vault_atomic(path, content)" in body
    assert "open(" not in body, "zapis tylko przez vault_io"


def test_31_a_password_change_removes_the_old_passwords_backup(monkeypatch, tmp_path):
    """Review 65/1: the backup a save makes is the file under the OLD password —
    the one being changed, perhaps because it leaked.  It must not stay."""
    import ui.main_window as mw

    class Dlg:
        def __init__(self, parent):
            pass

        def exec(self):
            return True

        def get_passwords(self):
            return "stare-haslo", "nowe-haslo"

    monkeypatch.setattr(mw, "ChangePasswordDialog", Dlg)
    monkeypatch.setattr(mw, "QMessageBox", _Box)
    vault = tmp_path / "x.vault"
    vault.write_bytes(b"OLD-PASSWORD-FILE")

    def save(path):
        vault_io.write_vault_atomic(path, b"NEW-PASSWORD-FILE")
        return True

    window = SimpleNamespace(_password="stare-haslo", _vault_path=str(vault),
                             _do_save=save, _unsaved=False,
                             _update_title=lambda: None)
    mw.MainWindow._change_password(window)
    assert vault.read_bytes() == b"NEW-PASSWORD-FILE"
    assert not (tmp_path / "x.vault.bak").exists()


def test_32_discarding_a_missing_backup_is_harmless(tmp_path):
    vault_io.discard_backup(str(tmp_path / "nothing.vault"))


# ══════════════════════════════════════════════════════════════════════════
# C5-01 — single-instance channel
# ══════════════════════════════════════════════════════════════════════════

def channel_for(monkeypatch, user, domain=""):
    import main
    monkeypatch.setenv("USERNAME", user)
    monkeypatch.setenv("USERDOMAIN", domain)
    return main._ipc_channel_name()


def test_33_the_single_instance_channel_is_per_user(monkeypatch):
    name = channel_for(monkeypatch, "jkowalski", "SZPITAL")
    assert name.startswith("HospitalHubV2_SingleInstance_")
    assert len(name.rsplit("_", 1)[1]) == 16
    assert name == channel_for(monkeypatch, "jkowalski", "SZPITAL"), "stabilna"


@pytest.mark.parametrize("a,b", [
    (("a", ""), ("b", "")),
    (("Michał", ""), ("Michal", "")),            # D-05: no lossy rewrite
    (("jan", "DOM1"), ("jan", "DOM2")),
])
def test_34_two_users_never_share_the_channel(monkeypatch, a, b):
    assert channel_for(monkeypatch, *a) != channel_for(monkeypatch, *b)


def test_35_the_server_is_restricted_to_the_user_and_checks_listen():
    src = open(os.path.join(_PARENT, "main.py"), encoding="utf-8").read()
    body = src[src.index("self._ipc_server = QLocalServer()"):]
    body = body[:body.index("newConnection.connect")]
    assert "UserAccessOption" in body
    assert body.index("setSocketOptions") < body.index(".listen(")
    assert "if not self._ipc_server.listen(" in body


# ══════════════════════════════════════════════════════════════════════════
# D-06 — Argon2 off the UI thread
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def qapp():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def test_36_encryption_runs_off_the_ui_thread(qapp, monkeypatch):
    import threading
    import ui.main_window as mw
    seen = []

    def fake_encrypt(data, password):
        seen.append(threading.get_ident())
        return b"CIPHERTEXT"
    monkeypatch.setattr(mw, "encrypt", fake_encrypt)
    assert mw.encrypt_off_ui_thread({"hospitals": []}, "x") == b"CIPHERTEXT"
    assert seen and seen[0] != threading.get_ident()


def test_37_an_encryption_error_reaches_the_caller(qapp, monkeypatch):
    import ui.main_window as mw

    def broken(data, password):
        raise ValueError("argon2 failed")
    monkeypatch.setattr(mw, "encrypt", broken)
    with pytest.raises(ValueError, match="argon2 failed"):
        mw.encrypt_off_ui_thread({}, "x")


def test_38_a_save_during_a_save_is_refused(qapp):
    import ui.main_window as mw
    calls = []
    window = SimpleNamespace(_saving=True,
                             _do_save_now=lambda path: calls.append(path) or True)
    assert mw.MainWindow._do_save(window, "x.vault") is False and calls == []
    window._saving = False
    assert mw.MainWindow._do_save(window, "x.vault") is True
    assert window._saving is False, "flaga zdjęta po zapisie"
