"""2026-11-24 (owner): check for an update and install it from the app —
Info → „Sprawdź aktualizacje…".  Nothing here touches the network: GitHub
is a fake opener."""

import hashlib
import io
import json
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for _p in (_PARENT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import updater  # noqa: E402

PAYLOAD = b"MZ" + b"x" * 300_000
SHA = hashlib.sha256(PAYLOAD).hexdigest()


@pytest.fixture
def dl(tmp_path):
    d = tmp_path / "dl"
    d.mkdir()
    return d


def api_json(tag="v2.0.4", digest=f"sha256:{SHA}", size=len(PAYLOAD)):
    return {
        "tag_name": tag, "html_url": f"https://github.com/baczek48/HospitalHub/releases/tag/{tag}",
        "published_at": "2026-11-30T10:00:00Z", "body": "### Zmiany\n- poprawki",
        "assets": [
            {"name": f"HospitalHub-Setup-{tag[1:]}.exe", "size": size, "digest": digest,
             "browser_download_url": "https://example.invalid/setup.exe"},
            {"name": f"HospitalHubPortable-{tag[1:]}.zip", "size": 10, "digest": "sha256:00",
             "browser_download_url": "https://example.invalid/p.zip"},
        ]}


class Opener:
    def __init__(self, routes):
        self.routes = routes
        self.seen = []

    def __call__(self, url, accept):
        self.seen.append((url, accept))
        body = self.routes[url]
        if isinstance(body, Exception):
            raise body
        return io.BytesIO(body)


def test_compare_versions():
    assert updater.compare("2.0.4", "2.0.3") == 1
    assert updater.compare("v2.0.3", "2.0.3") == 0
    assert updater.compare("2.0.3", "2.0.52") == -1, "wewnętrzny numer nie dostaje 'aktualizacji'"
    assert updater.compare("2.1", "2.0.9") == 1
    assert updater.compare("2.0.3", "dev") is None
    assert updater.compare("nightly", "2.0.3") is None


def test_latest_release_is_read_from_the_api():
    op = Opener({updater.API_LATEST: json.dumps(api_json()).encode()})
    rel = updater.fetch_latest(opener=op)
    assert rel.version == "2.0.4" and rel.published == "2026-11-30"
    assert rel.asset_for("V2").name == "HospitalHub-Setup-2.0.4.exe"
    assert rel.asset_for("V2").sha256 == SHA
    assert rel.asset_for("Portable").name.endswith(".zip")
    assert op.seen == [(updater.API_LATEST, "application/vnd.github+json")]


def test_no_network_is_a_readable_error():
    op = Opener({updater.API_LATEST: OSError("offline")})
    with pytest.raises(updater.UpdateError, match="GitHub"):
        updater.fetch_latest(opener=op)


def test_download_keeps_only_a_verified_file(dl):
    asset = updater.release_from_json(api_json()).asset_for("V2")
    op = Opener({asset.url: PAYLOAD})
    seen = []
    path = updater.download(asset, str(dl), progress=lambda d, t: seen.append(d),
                            opener=op)
    assert open(path, "rb").read() == PAYLOAD and seen[-1] == len(PAYLOAD)
    assert os.listdir(dl) == [asset.name]


@pytest.mark.parametrize("payload", [PAYLOAD[:-1] + b"y", PAYLOAD[:1000]],
                         ids=["changed", "short"])
def test_a_file_that_does_not_match_is_deleted(dl, payload):
    asset = updater.release_from_json(api_json()).asset_for("V2")
    with pytest.raises(updater.UpdateError, match="SHA-256"):
        updater.download(asset, str(dl), opener=Opener({asset.url: payload}))
    assert os.listdir(dl) == []


def test_without_a_published_checksum_nothing_is_downloaded(dl):
    asset = updater.release_from_json(api_json(digest=None)).asset_for("V2")
    op = Opener({})
    with pytest.raises(updater.UpdateError, match="SHA-256"):
        updater.download(asset, str(dl), opener=op)
    assert op.seen == []


def test_cancel_stops_and_cleans_up(dl):
    asset = updater.release_from_json(api_json()).asset_for("V2")
    with pytest.raises(updater.UpdateError, match="przerwane"):
        updater.download(asset, str(dl), cancelled=lambda: True,
                         opener=Opener({asset.url: PAYLOAD}))
    assert os.listdir(dl) == []


def test_installer_starts_only_after_this_process_ends():
    cmd = updater.installer_after_exit_command(r"C:\Temp\O'Brien\HospitalHub-Setup-2.0.4.exe", 4321)
    script = cmd[-1]
    assert cmd[0] == "powershell.exe" and "-NoProfile" in cmd
    assert script.index("Wait-Process -Id 4321") < script.index("Start-Process")
    assert "'C:\\Temp\\O''Brien\\HospitalHub-Setup-2.0.4.exe'" in script
    assert "/SILENT" in script and "/HHUPDATE=1" in script


def test_installer_starts_the_app_again_after_an_update():
    iss = open(os.path.join(_PARENT, "HospitalHubV2.iss"), encoding="utf-8-sig").read()
    assert "Check: IsHHUpdate" in iss
    assert "ExpandConstant('{param:HHUPDATE|0}') = '1'" in iss


# ── the dialog ─────────────────────────────────────────────────────────────

@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture
def version(monkeypatch):
    import app_version

    def set_(v):
        monkeypatch.setattr(app_version, "VERSION", v)
    return set_


@pytest.mark.parametrize("current,expect,action", [
    ("2.0.3", "Dostępna nowa wersja: v2.0.4", True),
    ("2.0.4", "Masz najnowszą wersję", False),
    ("2.0.52", "jest nowsza", False),
    ("dev", "Najnowsze wydanie na GitHubie: v2.0.4", False),
])
def test_dialog_states(app, version, current, expect, action):
    from ui.update_dialog import UpdateDialog
    version(current)
    dlg = UpdateDialog("V2", check=False)
    dlg.show_result(updater.release_from_json(api_json()))
    assert expect in dlg._status.text()
    assert dlg._action.isVisibleTo(dlg) is action
    if action:
        assert dlg._action.text().startswith("Pobierz i zainstaluj")
    dlg.close()


def test_portable_downloads_the_zip(app, version):
    from ui.update_dialog import UpdateDialog
    version("2.0.3")
    dlg = UpdateDialog("Portable", check=False)
    dlg.show_result(updater.release_from_json(api_json()))
    assert dlg._action.text().startswith("Pobierz zip")
    dlg.close()


def test_install_hands_over_only_when_the_app_really_quits(app, monkeypatch):
    from PyQt6.QtWidgets import QMessageBox
    from ui import update_dialog
    started = []
    monkeypatch.setattr(updater, "start_installer_after_exit",
                        lambda path, pid=None: started.append(path))
    monkeypatch.setattr(QMessageBox, "exec", lambda self: None)
    monkeypatch.setattr(QMessageBox, "clickedButton",
                        lambda self: self.buttons()[0])  # "Zainstaluj"

    calls = []

    def quit_all(before_quit):
        calls.append(1)
        return before_quit()

    update_dialog.set_quit_all_hook(quit_all)
    try:
        dlg = update_dialog.UpdateDialog("V2", check=False)
        assert dlg.install(r"C:\x\setup.exe") is True
        assert started == [r"C:\x\setup.exe"] and calls == [1]

        # The user cancels at "unsaved changes": nothing is started.
        started.clear()
        update_dialog.set_quit_all_hook(lambda before_quit: False)
        dlg = update_dialog.UpdateDialog("V2", check=False)
        assert dlg.install(r"C:\x\setup.exe") is False and started == []
    finally:
        update_dialog.set_quit_all_hook(None)


def test_quit_all_calls_the_hand_over_after_the_questions(app, monkeypatch, tmp_path):
    import main
    from PyQt6.QtWidgets import QApplication
    mgr = main.AppManager.__new__(main.AppManager)
    mgr._app = QApplication.instance()
    mgr._windows, mgr._trays = [], {}
    monkeypatch.setattr(mgr._app, "quit", lambda: None)
    monkeypatch.setattr(main, "_settle_claude_threads", lambda final=False: None)
    monkeypatch.setattr(main.AppManager, "_hide_all_windows", lambda self: None)
    monkeypatch.setattr(main.AppManager, "_close_all_ssh_dialogs", lambda self: None)
    assert mgr._quit_all(lambda: False) is False, "nieudane przekazanie = nie zamykaj"
    assert mgr._quit_all(lambda: True) is True
    assert mgr._quit_all() is True


def test_the_window_shows_only_what_changed():
    notes = "\n".join([
        "Instalator aktualizuje HospitalHub w miejscu.", "",
        "**Z wersji 2.0.4: Info …**", "",
        "### Pliki", "- `HospitalHub-Setup-2.0.5.exe`", "",
        "### Zmiany względem 2.0.4", "", "**Scalanie**", "- punkt",
        "#### Szczegóły", "- głębiej", "",
        "### Instalacja", "Zamknij HospitalHub."])
    out = updater.changes_only(notes)
    assert out.startswith("### Zmiany względem 2.0.4")
    assert "punkt" in out and "głębiej" in out
    assert "Instalator" not in out and "Pliki" not in out and "Instalacja" not in out
    assert updater.changes_only("bez nagłówków") == "bez nagłówków"


def test_the_update_folder_keeps_only_the_newest_installer(tmp_path, monkeypatch):
    folder = tmp_path / "HospitalHubUpdate"
    folder.mkdir()
    (folder / "HospitalHub-Setup-2.0.4.exe").write_bytes(b"old")
    (folder / "HospitalHub-Setup-2.0.5.exe.part").write_bytes(b"half")
    monkeypatch.setattr(updater, "download_dir", lambda: str(folder))
    asset = updater.release_from_json(api_json()).asset_for("V2")
    path = updater.download(asset, opener=Opener({asset.url: PAYLOAD}))
    assert os.listdir(folder) == [asset.name] and path == str(folder / asset.name)


def test_a_local_test_build_number_compares_between_releases():
    import exe_version_info
    assert updater.parse_version("2.0.5_1") == (2, 0, 5, 1)
    assert updater.compare("2.0.6", "2.0.5_1") == 1, "2.0.6 ma się zaproponować"
    assert updater.compare("2.0.5", "2.0.5_1") == -1
    assert exe_version_info._numbers("2.0.5_1") == (2, 0, 5, 1)
    iss = open(os.path.join(os.path.dirname(updater.__file__), "HospitalHubV2.iss"),
               encoding="utf-8-sig").read()
    assert 'VersionInfoVersion={#StringChange(MyAppVersion, "_", ".")}' in iss
