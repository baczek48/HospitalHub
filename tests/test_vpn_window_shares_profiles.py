"""2026-10-16 (owner's request): a VPN vault open in its own window makes the
VPN button of the hospital window usable at once — no separate unlock; edits
there count immediately; closing that window for good takes it back."""

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.dirname(_HERE), _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture
def dp(monkeypatch):
    from ui import detail_panel as dp
    from ui import vpn_panel
    monkeypatch.setattr(dp, "_vpn_session_profiles", [])
    monkeypatch.setattr(dp, "_vpn_session_loaded", False)
    monkeypatch.setattr(dp, "_vpn_window_source", None)
    monkeypatch.setattr(vpn_panel.VpnPanel, "_poll_status", lambda self: None)
    monkeypatch.setattr(dp.DetailPanel, "_poll_vpn_status", lambda self: None)
    return dp


def _windows(tmp_path, hospital_name="Sanok", profile_name="Sanok"):
    import models
    from ui.main_window import MainWindow
    h = models.Hospital(name=hospital_name)
    hosp_win = MainWindow(str(tmp_path / "h.vault"), "pw", [h])
    vpn_win = MainWindow(str(tmp_path / "v.vault"), "pw",
                         [models.VpnProfile(name=profile_name, provider="FortiClient")],
                         vault_type="vpn")
    hosp_win._detail_panel.show_hospital(h, [h])
    return hosp_win, vpn_win


def _close(*wins):
    for w in wins:
        w._unsaved = False
        w.destroy_cleanup()


def test_open_vpn_window_makes_the_button_ready_without_unlock(app, dp, tmp_path,
                                                               monkeypatch):
    monkeypatch.setattr(dp._VpnUnlockDialog, "exec",
                        lambda self: pytest.fail("asked to unlock the VPN vault"))
    hw, vw = _windows(tmp_path)
    try:
        panel = hw._detail_panel
        assert dp._vpn_available()
        assert panel._vpn_profile_for_current().name == "Sanok"
        assert "Połącz VPN: Sanok" in panel._vpn_btn.toolTip()
    finally:
        _close(hw, vw)


def test_a_profile_added_in_the_vpn_window_counts_at_once(app, dp, tmp_path):
    import models
    hw, vw = _windows(tmp_path, hospital_name="Żary", profile_name="Sanok")
    try:
        panel = hw._detail_panel
        assert panel._vpn_profile_for_current() is None
        assert "Brak profilu VPN" in panel._vpn_btn.toolTip()
        vw._vpn_panel.get_profiles().append(models.VpnProfile(name="Żary"))
        vw._vpn_panel.data_changed.emit()
        assert panel._vpn_profile_for_current().name == "Żary"
        assert "Połącz VPN: Żary" in panel._vpn_btn.toolTip()
    finally:
        _close(hw, vw)


def test_closing_the_vpn_window_takes_the_profiles_back(app, dp, tmp_path):
    hw, vw = _windows(tmp_path)
    try:
        _close(vw)
        assert not dp._vpn_available()
        assert hw._detail_panel._vpn_profile_for_current() is None
        assert "wskaż swój VPN vault" in hw._detail_panel._vpn_btn.toolTip()
    finally:
        _close(hw)


def test_hiding_the_vpn_window_to_the_tray_keeps_sharing(app, dp, tmp_path):
    hw, vw = _windows(tmp_path)
    try:
        vw.show()
        vw.close()                      # X = hide to tray, the vault stays open
        assert dp._vpn_available()
    finally:
        _close(hw, vw)


def test_a_vault_unlocked_by_hand_stays_after_the_window_closes(app, dp, tmp_path,
                                                                monkeypatch):
    import models
    monkeypatch.setattr(dp, "_vpn_session_profiles", [models.VpnProfile(name="Sanok")])
    monkeypatch.setattr(dp, "_vpn_session_loaded", True)
    hw, vw = _windows(tmp_path, profile_name="Inny")
    try:
        assert hw._detail_panel._vpn_profile_for_current() is None   # window wins
        _close(vw)
        assert hw._detail_panel._vpn_profile_for_current().name == "Sanok"
    finally:
        _close(hw)
