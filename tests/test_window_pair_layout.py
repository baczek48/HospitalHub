"""2026-10-26 (owner): the main vault and the VPN vault open side by side —
the main one on the left, the VPN one right next to it, the same top and
height, the pair centred on the screen."""

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from ui.window_layout import (Frame, Rect, pair_layout, MAIN_SIZE, VPN_SIZE,  # noqa: E402
                              GAP, MAIN_MIN_WIDTH)

FRAME = Frame(1, 31, 1, 1)                     # a Windows 11 title bar at 100 %


def _right(r, f):
    return r.x + f.left + r.w + f.right


def _bottom(r, f):
    return r.y + f.top + r.h + f.bottom


def test_1_side_by_side_same_top_same_bottom_gap_between():
    area = Rect(0, 0, 1536, 816)               # 1920x1080 at 125 %, taskbar off
    main, vpn = pair_layout(area, FRAME, FRAME)
    assert (main.w, vpn.w) == (MAIN_SIZE[0], VPN_SIZE[0])
    assert main.y == vpn.y
    assert _bottom(main, FRAME) == _bottom(vpn, FRAME)
    assert vpn.x == _right(main, FRAME) + GAP
    left_space = main.x - area.x
    right_space = area.x + area.w - _right(vpn, FRAME)
    assert abs(left_space - right_space) <= 1      # centred


def test_2_height_fits_the_screen_with_margins():
    area = Rect(0, 0, 1366, 728)               # a small laptop
    main, vpn = pair_layout(area, FRAME, FRAME)
    assert main.y >= area.y and _bottom(main, FRAME) <= area.y + area.h
    assert main.h < MAIN_SIZE[1]


def test_3_narrow_screen_shrinks_the_main_window_first():
    area = Rect(0, 0, 1280, 984)
    main, vpn = pair_layout(area, FRAME, FRAME)
    assert vpn.w == VPN_SIZE[0]
    assert MAIN_MIN_WIDTH <= main.w < MAIN_SIZE[0]
    assert _right(vpn, FRAME) <= area.x + area.w


def test_4_different_title_bars_still_share_the_bottom_edge():
    other = Frame(1, 40, 1, 1)
    main, vpn = pair_layout(Rect(0, 0, 1920, 1040), FRAME, other)
    assert _bottom(main, FRAME) == _bottom(vpn, other)


def test_5_second_screen_offsets_are_kept():
    area = Rect(1920, 0, 1920, 1040)
    main, vpn = pair_layout(area, FRAME, FRAME)
    assert main.x >= 1920 and _right(vpn, FRAME) <= 3840


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def test_6_vpn_list_returns_to_the_size_it_had_before_editing(app, monkeypatch):
    import models
    from PyQt6.QtWidgets import QMainWindow
    from ui import vpn_panel as vp
    monkeypatch.setattr(vp.VpnPanel, "_poll_status", lambda self: None)
    win = QMainWindow()
    panel = vp.VpnPanel([models.VpnProfile(name="P", provider="FortiClient")])
    win.setCentralWidget(panel)
    win.resize(430, 690)
    win.show()
    try:
        panel._enter_edit(0)
        assert (win.width(), win.height()) != (430, 690)
        panel._exit_edit()
        assert (win.width(), win.height()) == (430, 690)
    finally:
        panel.cleanup()
        win.close()
