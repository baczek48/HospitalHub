"""Opt-in readable VPN log (2026-10-16): off by default, no secrets, rotation,
switch in ⚙ Ustawienia VPN, included in the diagnostics ZIP."""

import os
import sys
import zipfile

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.dirname(_HERE), _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)


@pytest.fixture(autouse=True)
def _fresh_log():
    from diagnostics import actionlog
    actionlog.reset_for_tests()
    yield
    actionlog.reset_for_tests()


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def _profile(**kw):
    import models
    base = dict(name="Szpital Zielona Góra", provider="FortiClient",
                server="vpn.szpital.example.invalid", login="jkowalski",
                password="Tajne#Haslo-2026", profile_name="ZG")
    base.update(kw)
    return models.VpnProfile(**base)


def test_off_by_default_writes_nothing():
    from diagnostics import actionlog
    actionlog.info("vpn", "coś")
    assert not actionlog.log_path().exists()


def test_line_has_profile_but_no_password_login_or_server():
    from diagnostics import actionlog
    actionlog.set_enabled(True)
    actionlog.register_secrets(["Tajne#Haslo-2026", "jkowalski"])
    actionlog.error("vpn", "Połącz — wynik", profile="Szpital Zielona Góra",
                    provider="FortiClient", server="vpn.szpital.example.invalid",
                    message="Błąd logowania jkowalski / Tajne#Haslo-2026")
    text = actionlog.read_text()
    assert "Szpital Zielona Góra" in text and "FortiClient" in text
    assert "Tajne#Haslo-2026" not in text
    assert "jkowalski" not in text
    assert "vpn.szpital.example.invalid" not in text
    assert "BŁĄD" in text


def test_secret_looking_line_is_dropped():
    from diagnostics import actionlog
    actionlog.set_enabled(True)
    actionlog.info("vpn", "token", message="password=Xy7Kq9Lm2Np4Rs8T")    # field: redactor
    actionlog.info("vpn", "odpowiedź password=Ab3Cd5Ef7Gh9Jk2L")          # text: last scan
    text = actionlog.read_text()
    assert "Xy7Kq9Lm2Np4Rs8T" not in text and "Ab3Cd5Ef7Gh9Jk2L" not in text
    assert "<blocked:looks-like-secret>" in text
    assert "wpis pominięty" in text


def test_rotation_keeps_bounded_files(monkeypatch):
    from diagnostics import actionlog
    monkeypatch.setattr(actionlog, "MAX_BYTES", 2000)
    actionlog.set_enabled(True)
    for i in range(400):
        actionlog.info("vpn", f"wpis {i:04d} " + "x" * 40)
    files = actionlog.log_files()
    assert 2 <= len(files) <= 4
    assert all(f.stat().st_size <= 2200 for f in files)
    assert "wpis 0399" in actionlog.log_path().read_text(encoding="utf-8")


def test_finished_trace_lands_in_the_log():
    from diagnostics import actionlog, TraceRecorder
    actionlog.set_enabled(True)
    rec = TraceRecorder("vpn.connect", meta={"provider": "FortiClient"})
    rec.add_step("forti.launch", status="fail", error_code="LAUNCH_FAILED",
                 message="nie znaleziono pliku")
    rec.finish("fail", error_code="LAUNCH_FAILED")
    text = actionlog.read_text()
    assert "vpn.connect" in text and "forti.launch: fail [LAUNCH_FAILED]" in text


def test_uncaught_exception_is_logged_once_enabled():
    from diagnostics import actionlog
    actionlog.exception_text("Traceback…\nValueError: x")
    assert not actionlog.log_path().exists()
    actionlog.set_enabled(True)
    actionlog.exception_text("Traceback…\nValueError: x", " (wątek w1)")
    assert "ValueError: x" in actionlog.read_text()


def test_panel_logs_connect_and_disconnect(app, monkeypatch):
    import vpn_connect
    from diagnostics import actionlog
    from ui import vpn_panel
    monkeypatch.setattr(vpn_panel.VpnPanel, "_poll_status", lambda self: None)
    monkeypatch.setattr(vpn_connect, "connect_monitored",
                        lambda *a, **k: (False, "Nie znaleziono FortiClient", None))
    monkeypatch.setattr(vpn_connect, "disconnect", lambda *a, **k: (True, "Rozłączono"))
    monkeypatch.setattr(vpn_panel, "load_vpn_autofill_enabled", lambda: False)
    actionlog.set_enabled(True)
    p = _profile()
    panel = vpn_panel.VpnPanel([p])
    try:
        panel._connect_card(0)
        panel._disconnect_card(0)
    finally:
        panel.cleanup()
    text = actionlog.read_text()
    assert "Połącz — kliknięto" in text
    assert "Połącz — wynik" in text and "Nie znaleziono FortiClient" in text
    assert "Rozłącz — wynik" in text
    assert "Tajne#Haslo-2026" not in text and "jkowalski" not in text


def test_settings_switch_persists_and_enables(app, monkeypatch):
    import config
    from diagnostics import actionlog
    from ui import vpn_panel
    monkeypatch.setattr(vpn_panel.VpnPanel, "_poll_status", lambda self: None)
    monkeypatch.setattr(vpn_panel.vpn_connect, "is_forticlient_installed", lambda: False)
    panel = vpn_panel.VpnPanel([_profile()])

    def fake_exec(dlg):
        dlg._log_cb.setChecked(True)
        return True
    monkeypatch.setattr(vpn_panel.VpnSettingsDialog, "exec", fake_exec)
    try:
        panel._open_vpn_settings()
    finally:
        panel.cleanup()
    assert config.load_vpn_log_enabled() is True
    assert actionlog.is_enabled()
    assert "Logowanie włączone" in actionlog.read_text()


def test_export_zip_contains_the_log(tmp_path):
    import diagnostics
    from diagnostics import actionlog
    actionlog.set_enabled(True)
    actionlog.info("vpn", "Połącz — kliknięto", profile="Szpital A", provider="FortiClient")
    result = diagnostics.export(dest_dir=tmp_path, sections=[])
    with zipfile.ZipFile(result.path) as zf:
        assert "Połącz — kliknięto" in zf.read("vpn_log.txt").decode("utf-8")
