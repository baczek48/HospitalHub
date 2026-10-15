"""D-07 (2026-10-14): the hospital window's VPN button never queries the VPN
client on the UI thread."""

import os
import sys
from types import SimpleNamespace

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture
def dp(app, monkeypatch):
    from ui import detail_panel
    def forbidden(*a, **k):
        raise AssertionError("get_status w watku GUI")
    monkeypatch.setattr(detail_panel.vpn_connect, "get_status", forbidden)
    monkeypatch.setattr(detail_panel, "_vpn_session_loaded", True)
    monkeypatch.setattr(detail_panel.QTimer, "singleShot",
                        staticmethod(lambda ms, fn: None))
    return detail_panel


def profile(name="SZPITAL-A"):
    return SimpleNamespace(provider="FortiClient", app_path="", profile_name=name,
                           name=name)


def panel(dp, prof, visible=True, last=None):
    styles = []
    btn = SimpleNamespace(setStyleSheet=styles.append, setToolTip=lambda t: None)
    p = SimpleNamespace(_vpn_btn=btn, _vpn_last_status=last,
                        _vpn_profile_for_current=lambda: prof,
                        isVisible=lambda: visible, styles=styles)
    p._update_vpn_btn = lambda status=None: dp.DetailPanel._update_vpn_btn(p, status)
    p._poll_vpn_status = lambda: None
    return p


def test_d07_the_button_update_uses_the_cache_not_the_client(dp):
    prof = profile()
    p = panel(dp, prof, last=(dp._vpn_status_key(prof), "Connected"))
    dp.DetailPanel._update_vpn_btn(p)          # would raise if it queried
    assert "rgba(35,134,54" in p.styles[-1], "zielony z bufora"


def test_d07_a_cached_status_of_another_profile_is_not_shown(dp):
    other = profile("INNY")
    p = panel(dp, profile(), last=(dp._vpn_status_key(other), "Connected"))
    dp.DetailPanel._update_vpn_btn(p)
    assert "rgba(35,134,54" not in p.styles[-1]


def test_d07_a_late_answer_for_the_previous_hospital_is_ignored(dp):
    p = panel(dp, profile("B"))
    dp.DetailPanel._on_vpn_status(p, dp._vpn_status_key(profile("A")), "Connected")
    assert p._vpn_last_status is None and p.styles == []


def test_d07_a_matching_answer_updates_the_button(dp):
    prof = profile()
    p = panel(dp, prof)
    dp.DetailPanel._on_vpn_status(p, dp._vpn_status_key(prof), "Connected")
    assert p._vpn_last_status == (dp._vpn_status_key(prof), "Connected")
    assert "rgba(35,134,54" in p.styles[-1]


def test_d07_no_polling_while_the_window_is_hidden(dp, monkeypatch):
    started = []
    monkeypatch.setattr(dp, "_VpnStatusProbe",
                        lambda *a, **k: started.append(True))
    p = panel(dp, profile(), visible=False)
    dp.DetailPanel._poll_vpn_status(p)
    assert started == []


def test_d07_the_probe_runs_the_same_call_in_its_thread(dp, app, monkeypatch):
    calls = []
    monkeypatch.setattr(dp.vpn_connect, "get_status",
                        lambda *a: calls.append(a) or "Connected")
    got = []
    probe = dp._VpnStatusProbe(("k",), "FortiClient", "C:/x", "SZPITAL-A")
    probe.result.connect(lambda k, s: got.append((k, s)))
    probe.start()
    assert probe.wait(5000)
    app.processEvents()
    assert calls == [("FortiClient", "C:/x", "SZPITAL-A")]
    assert got == [(("k",), "Connected")]
