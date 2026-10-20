"""2026-10-20 (owner): the hospital window's VPN button takes the V2 route.

"Po co to rozbijać" — the button now asks the same gate as a VPN card
(``ui.vpn_panel.select_connect_route``) and, for an armed provider, runs the
same session and controller, reporting in a status line next to it.  Every
other provider keeps the legacy connect.  Fakes only.
"""

import os
import sys
from types import SimpleNamespace

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from PyQt6.QtWidgets import (  # noqa: E402
    QApplication, QHBoxLayout, QLabel, QToolButton, QWidget,
)

import models  # noqa: E402
import vpn_connect  # noqa: E402
from ui import detail_panel as dp  # noqa: E402
from ui import vpn_panel as vp  # noqa: E402
from tests.test_vpn_connect_card_wiring import FakeController, FakeSession  # noqa: E402


@pytest.fixture(scope="module")
def app():
    return QApplication.instance() or QApplication([])


@pytest.fixture(autouse=True)
def reset():
    FakeSession.instances.clear()
    FakeController.instances.clear()


class Host(QWidget):
    """The pieces of DetailPanel the VPN button touches, on a real widget."""

    _on_vpn_btn_clicked = dp.DetailPanel._on_vpn_btn_clicked
    _connect_vpn_v2 = dp.DetailPanel._connect_vpn_v2
    _on_vpn_v2_finished = dp.DetailPanel._on_vpn_v2_finished
    _hide_vpn_v2_status = dp.DetailPanel._hide_vpn_v2_status

    def __init__(self, profile):
        super().__init__()
        self._profile = profile
        self._vpn_header = QHBoxLayout(self)
        self._vpn_status_lbl = QLabel()
        self._vpn_btn = QToolButton()
        self._vpn_header.addWidget(self._vpn_status_lbl)
        self._vpn_header.addWidget(self._vpn_btn)
        self._vpn_v2_controller = None
        self._vpn_last_status = None
        self.button_states = []
        self.current_hospital = SimpleNamespace(name=profile.name)

    def _vpn_profile_for_current(self):
        return self._profile

    def _update_vpn_btn(self, status=None):
        self.button_states.append(status)


def profile(provider="FortiClient"):
    return models.VpnProfile(name="Wieluń", provider=provider, server="vpn.x",
                             port="443", login="jkowalski", password="Secret1",
                             app_path=r"C:\x\client.exe", profile_name="WIELUN")


@pytest.fixture
def wired(monkeypatch):
    calls = []
    monkeypatch.setattr(vp, "PanelConnectSession", FakeSession)
    monkeypatch.setattr(vp, "V2ConnectController", FakeController)
    monkeypatch.setattr(dp, "_vpn_available", lambda: True)
    monkeypatch.setattr(dp, "load_vpn_autofill_enabled", lambda: True)
    monkeypatch.setattr(vpn_connect, "get_status", lambda *a, **k: "Disconnected")
    monkeypatch.setattr(vpn_connect, "connect_monitored",
                        lambda *a, **k: calls.append(a) or (True, "ok", None))
    monkeypatch.setattr(vpn_connect, "_last_connected", {})
    monkeypatch.setattr(vpn_connect, "_last_connected_meta", {})
    monkeypatch.setattr(dp, "QTimer", SimpleNamespace(singleShot=lambda ms, fn: None))
    return calls


@pytest.mark.parametrize("provider", ["FortiClient", "Stormshield", "Barracuda"])
def test_an_armed_provider_runs_the_v2_session_not_the_legacy(app, wired,
                                                              monkeypatch, provider):
    monkeypatch.setattr(vp, "select_connect_route",
                        lambda name: "v2" if name == provider else vp.ROUTE_LEGACY)
    host = Host(profile(provider))
    host._on_vpn_btn_clicked()
    assert wired == [], "zadnego starego connect_monitored"
    assert len(FakeSession.instances) == 1
    assert FakeSession.instances[0].request.provider_id == provider.lower()
    controller = FakeController.instances[0]
    assert controller.started and controller.client == provider
    assert controller.label is host._vpn_status_lbl
    assert host._vpn_status_lbl.isVisibleTo(host)
    if provider != "Barracuda":       # Barracuda: adapter only (2026-10-20)
        assert vpn_connect._last_connected[provider], "status wie, ktory profil"
    assert "Connecting" in host.button_states


def test_another_provider_keeps_the_legacy_connect(app, wired, monkeypatch):
    monkeypatch.setattr(vp, "select_connect_route", lambda name: vp.ROUTE_LEGACY)
    host = Host(profile("SonicWall NetExtender"))
    host._on_vpn_btn_clicked()
    assert len(wired) == 1 and FakeSession.instances == []


def test_a_second_click_while_connecting_starts_nothing(app, wired, monkeypatch):
    monkeypatch.setattr(vp, "select_connect_route", lambda name: "v2")
    host = Host(profile())
    host._on_vpn_btn_clicked()
    FakeController.instances[0].active = True
    host._on_vpn_btn_clicked()
    assert len(FakeSession.instances) == 1


def test_a_missing_forticlient_profile_is_explained(app, wired, monkeypatch):
    from vpn.panel_bridge import PanelConnectOutcome, PanelOutcome
    monkeypatch.setattr(vp, "select_connect_route", lambda name: "v2")
    shown = []
    monkeypatch.setattr(vp, "explain_missing_tunnel",
                        lambda parent, p: shown.append(p.profile_name))
    host = Host(profile())
    host._on_vpn_btn_clicked()
    FakeController.instances[0].finished.emit(PanelConnectOutcome(
        code=PanelOutcome.AUTOFILL_BLOCKED, reason="requested-tunnel-not-configured"))
    assert shown == ["WIELUN"]


# ══════════════════════════════════════════════════════════════════════════
# 2026-10-20: a custom provider ("Anydesk") only has to open its program
# ══════════════════════════════════════════════════════════════════════════

def test_a_custom_provider_without_a_path_finds_its_start_menu_shortcut(
        tmp_path, monkeypatch):
    menu = tmp_path / "ProgramData" / "Microsoft" / "Windows" / "Start Menu" / "Programs"
    (menu / "AnyDesk").mkdir(parents=True)
    (menu / "AnyDesk" / "AnyDesk.lnk").write_bytes(b"x")
    (menu / "AnyDesk" / "Uninstall AnyDesk.lnk").write_bytes(b"x")
    for var in ("APPDATA", "PUBLIC", "USERPROFILE", "PROGRAMFILES(X86)",
                "PROGRAMFILES", "LOCALAPPDATA"):
        monkeypatch.setenv(var, str(tmp_path / "nothing"))
    monkeypatch.setenv("PROGRAMDATA", str(tmp_path / "ProgramData"))
    monkeypatch.setattr(vp, "load_vpn_provider_paths", lambda: {})
    card = models.VpnProfile(name="Lubań", provider="Anydesk", app_path="")
    assert vp.resolve_client_path(card).endswith(r"AnyDesk\AnyDesk.lnk")


def test_a_custom_provider_finds_program_files_exe(tmp_path, monkeypatch):
    pf = tmp_path / "PF86" / "AnyDesk"
    pf.mkdir(parents=True)
    (pf / "AnyDesk.exe").write_bytes(b"x")
    for var in ("PROGRAMDATA", "APPDATA", "PUBLIC", "USERPROFILE",
                "PROGRAMFILES", "LOCALAPPDATA"):
        monkeypatch.setenv(var, str(tmp_path / "nothing"))
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path / "PF86"))
    monkeypatch.setattr(vp, "load_vpn_provider_paths", lambda: {})
    card = models.VpnProfile(name="Lubań", provider="Anydesk", app_path="")
    # Windows paths ignore case; the folder is looked up by the provider name.
    assert vp.resolve_client_path(card).lower().endswith(r"anydesk\anydesk.exe")


def test_a_configured_path_and_builtin_providers_are_left_alone(monkeypatch):
    monkeypatch.setattr(vp, "load_vpn_provider_paths", lambda: {"Anydesk": r"D:\a.exe"})
    monkeypatch.setattr(vp, "_find_program",
                        lambda name: (_ for _ in ()).throw(AssertionError(name)))
    assert vp.resolve_client_path(models.VpnProfile(
        name="x", provider="Anydesk", app_path="")) == r"D:\a.exe"
    monkeypatch.setattr(vp, "load_vpn_provider_paths", lambda: {})
    assert vp.resolve_client_path(models.VpnProfile(
        name="x", provider="FortiClient", app_path="")) == ""


# ══════════════════════════════════════════════════════════════════════════
# 2026-10-20: Barracuda's idle adapter is Up with 169.254.1.10
# ══════════════════════════════════════════════════════════════════════════

def _adapter(ips, up=True, name="barracuda virtual adapter (vpn)"):
    return {"description": name, "friendly_name": "barracuda vpn",
            "ipv4_addresses": list(ips), "oper_status_up": up}


@pytest.mark.parametrize("adapters,expected", [
    ([_adapter(["169.254.1.10"], up=True)], "Disconnected"),   # owner's laptop, idle
    ([_adapter([], up=True)], "Disconnected"),
    ([_adapter([], up=False)], "Disconnected"),
    ([_adapter(["10.20.30.40"], up=True)], "Connected"),
    ([_adapter(["169.254.1.10", "10.20.30.40"])], "Connected"),
    ([{"description": "intel ethernet", "friendly_name": "ethernet",
       "ipv4_addresses": ["192.168.1.5"], "oper_status_up": True}], "Disconnected"),
])
def test_barracuda_is_connected_only_with_a_real_tunnel_address(monkeypatch,
                                                                adapters, expected):
    monkeypatch.setattr(vpn_connect, "_get_adapters", lambda: adapters)
    monkeypatch.setattr(vpn_connect, "get_status",
                        lambda *a, **k: (_ for _ in ()).throw(AssertionError("legacy")))
    assert vp.vpn_status("Barracuda", "", "MCX") == expected


def test_without_an_adapter_list_the_legacy_answers(monkeypatch):
    monkeypatch.setattr(vpn_connect, "_get_adapters", lambda: [])
    monkeypatch.setattr(vpn_connect, "get_status", lambda *a, **k: "Connected")
    assert vp.vpn_status("Barracuda", "", "MCX") == "Connected"


def test_other_providers_keep_the_legacy_status(monkeypatch):
    seen = []
    monkeypatch.setattr(vpn_connect, "get_status",
                        lambda *a, **k: seen.append(a) or "Connected")
    assert vp.vpn_status("FortiClient", "x", "WIELUN", "s") == "Connected"
    assert seen == [("FortiClient", "x", "WIELUN", "s")]
