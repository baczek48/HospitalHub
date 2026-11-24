"""2026-11-24 (owner): an „Info” drop-down with the version of HH, the author
(Sebastian Bąk) and the release date — plus what helps with a support call:
system, rights, folders, one button that copies it all."""

import ast
import importlib
import os
import shutil
import subprocess
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for _p in (_PARENT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture
def built(monkeypatch):
    """app_version as a build with a number sees it."""
    import types
    info = types.ModuleType("_build_info")
    info.VERSION = "2.0.52"
    info.RELEASE_DATE = "2026-11-24"
    monkeypatch.setitem(sys.modules, "_build_info", info)
    import app_version
    importlib.reload(app_version)
    yield app_version
    monkeypatch.delitem(sys.modules, "_build_info")
    importlib.reload(app_version)


def test_from_source_the_version_is_dev():
    import app_version
    if os.path.exists(os.path.join(_PARENT, "_build_info.py")):
        pytest.skip("a build left _build_info.py behind")
    importlib.reload(app_version)
    assert app_version.VERSION == "dev" and app_version.version_label() == "dev"


def test_rows_name_version_author_and_date(built):
    from ui import about_dialog
    rows = dict(about_dialog.info_rows("V2"))
    assert rows["Program"] == "HospitalHub V2"
    assert rows["Wersja"] == "v2.0.52"
    assert rows["Data wydania"] == "24.11.2026"
    assert rows["Autor"] == "Sebastian Bąk"
    assert "Sebastian Bąk" in rows["Licencja"]
    assert rows["Strona"].startswith("https://github.com/")
    for key in ("System", "Uprawnienia", "Środowisko", "Folder danych", "Logi"):
        assert rows[key], key


def test_copy_puts_every_row_on_the_clipboard(app, built):
    from PyQt6.QtGui import QGuiApplication
    from ui.about_dialog import AboutDialog
    dlg = AboutDialog("Portable")
    dlg._copy.click()
    text = QGuiApplication.clipboard().text()
    assert "Wersja: v2.0.52" in text and "Autor: Sebastian Bąk" in text
    assert "Program: HospitalHub Portable" in text
    dlg.close()


def test_main_window_has_the_info_menu(app, tmp_path, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox
    from ui import main_window as mw
    monkeypatch.setattr(QMessageBox, "information", lambda *a, **k: None)
    w = mw.MainWindow(str(tmp_path / "v.vault"), "pw", [])
    try:
        titles = [a.text() for a in w.menuBar().actions()]
        assert titles[-1] == "Info"
        info = w.menuBar().actions()[-1].menu()
        labels = [a.text() for a in info.actions() if not a.isSeparator()]
        assert labels[:2] == ["O programie HospitalHub…", "Sprawdź aktualizacje…"]
        assert not any("folder" in t.lower() for t in labels), "foldery tylko w O programie"
    finally:
        w._unsaved = False


def test_portable_window_adds_the_same_menu():
    tree = ast.parse(open(os.path.join(_PARENT, "ui", "remote_window.py"),
                          encoding="utf-8").read())
    calls = [n for n in ast.walk(tree) if isinstance(n, ast.Call)
             and isinstance(n.func, ast.Name) and n.func.id == "add_info_menu"]
    assert len(calls) == 1 and calls[0].args[2].value == "Portable"
    assert [k.arg for k in calls[0].keywords] == ["own_vault"]


def test_build_script_writes_the_number_and_todays_date(tmp_path):
    from datetime import date
    script = tmp_path / "write_build_info.py"
    shutil.copy(os.path.join(_PARENT, "write_build_info.py"), script)
    subprocess.run([sys.executable, str(script), "2.0.60"], check=True,
                   capture_output=True)
    ns = {}
    exec((tmp_path / "_build_info.py").read_text(encoding="utf-8"), ns)
    assert ns["VERSION"] == "2.0.60"
    assert ns["RELEASE_DATE"] == date.today().isoformat()


def test_both_builds_pass_one_number_to_the_exe_and_the_installer():
    v2 = open(os.path.join(_PARENT, "build_v2.bat"), encoding="utf-8").read()
    remote = open(os.path.join(_PARENT, "build_remote.bat"), encoding="utf-8").read()
    for bat in (v2, remote):
        assert 'write_build_info.py "%VER%"' in bat
        assert "del /q _build_info.py" in bat
    assert "/DMyAppVersion=%VER%" in v2
    ignore = open(os.path.join(_PARENT, ".gitignore"), encoding="utf-8").read()
    assert "_build_info.py" in ignore


def test_menu_lists_the_registered_vaults(tmp_path, monkeypatch):
    import config
    from ui import about_dialog
    main_v = tmp_path / "main.vault"
    vpn_v = tmp_path / "vpn.vault"
    main_v.write_bytes(b"x")
    vpn_v.write_bytes(b"x")
    monkeypatch.setattr(config, "load_vault_list", lambda: [
        {"type": "vpn", "path": str(vpn_v)}, {"type": "global", "path": str(main_v)}])
    assert about_dialog.vault_entries() == [
        ("Pokaż vault główny (main.vault)", str(main_v)),
        ("Pokaż vault VPN (vpn.vault)", str(vpn_v))]
    assert about_dialog.vault_entries(str(vpn_v)) == [("Pokaż vault (vpn.vault)", str(vpn_v))]
    assert about_dialog.vault_entries(str(tmp_path / "brak.vault")) == []


def test_about_window_keeps_the_folders(built):
    from ui import about_dialog
    keys = [k for k, _ in about_dialog.info_rows("V2")]
    assert "Folder danych" in keys and "Logi" in keys


def test_exe_properties_carry_the_author_and_the_copyright(built):
    import exe_version_info
    importlib.reload(exe_version_info)
    info = exe_version_info.version_info("HospitalHub", "HospitalHubV2", "HospitalHub.exe")
    strings = {s.name: s.val for s in info.kids[0].kids[0].kids}
    assert strings["CompanyName"] == "Sebastian Bąk"
    assert strings["LegalCopyright"].startswith("© 2026 Sebastian Bąk")
    assert strings["ProductVersion"] == "2.0.52"
    assert info.ffi.fileVersionMS >> 16 == 2 and info.ffi.fileVersionLS >> 16 == 52
    iss = open(os.path.join(_PARENT, "HospitalHubV2.iss"), encoding="utf-8-sig").read()
    assert "VersionInfoCopyright=" in iss and "AppCopyright=" in iss
