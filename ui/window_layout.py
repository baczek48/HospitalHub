"""The main vault and the VPN vault side by side (2026-10-26, owner).

When both windows are open, the main one stands on the left and the VPN one
right next to it: the same top, the same height, the pair centred on the
screen.  Sizes are client sizes; positions are of the frames, as ``move()``
takes them.
"""

from __future__ import annotations

from dataclasses import dataclass

MAIN_SIZE = (1050, 720)
VPN_SIZE = (420, 720)
GAP = 6                  # px between the two frames
MARGIN = 16              # px kept free above and below the pair
MAIN_MIN_WIDTH = 700


@dataclass(frozen=True)
class Rect:
    x: int
    y: int
    w: int
    h: int


@dataclass(frozen=True)
class Frame:
    """Frame thickness around a window's client area."""
    left: int = 0
    top: int = 0
    right: int = 0
    bottom: int = 0


def pair_layout(area: Rect, main_frame: Frame, vpn_frame: Frame,
                main_size=MAIN_SIZE, vpn_size=VPN_SIZE, gap: int = GAP,
                margin: int = MARGIN) -> tuple[Rect, Rect]:
    """(main, vpn): frame position (x, y) and client size (w, h) of each."""
    def frame_w(f, w):
        return f.left + w + f.right

    def frame_h(f, h):
        return f.top + h + f.bottom

    vpn_w = vpn_size[0]
    main_w = main_size[0]
    spare = area.w - (frame_w(main_frame, main_w) + gap + frame_w(vpn_frame, vpn_w))
    if spare < 0:                             # a narrow screen: the main one gives way
        main_w = max(MAIN_MIN_WIDTH, main_w + spare)

    tallest_frame = max(main_frame.top + main_frame.bottom,
                        vpn_frame.top + vpn_frame.bottom)
    height = min(max(main_size[1], vpn_size[1]), area.h - 2 * margin - tallest_frame)
    # Both frames end at the same bottom edge even when their title bars differ.
    main_h = height
    vpn_h = height + (main_frame.top + main_frame.bottom) - (vpn_frame.top + vpn_frame.bottom)

    total_w = frame_w(main_frame, main_w) + gap + frame_w(vpn_frame, vpn_w)
    left = area.x + max(0, (area.w - total_w) // 2)
    top = area.y + max(0, (area.h - frame_h(main_frame, main_h)) // 2)
    main = Rect(left, top, main_w, main_h)
    vpn = Rect(left + frame_w(main_frame, main_w) + gap, top, vpn_w, vpn_h)
    return main, vpn


def _frame_of(window) -> Frame:
    fg, g = window.frameGeometry(), window.geometry()
    return Frame(g.x() - fg.x(), g.y() - fg.y(),
                 fg.right() - g.right(), fg.bottom() - g.bottom())


def arrange_pair(main_window, vpn_window) -> bool:
    """Put the two windows side by side; False when it was left alone (one
    of them maximised, minimised or hidden)."""
    for w in (main_window, vpn_window):
        if not w.isVisible() or w.isMaximized() or w.isMinimized() or w.isFullScreen():
            return False
    screen = main_window.screen()
    if screen is None:
        return False
    a = screen.availableGeometry()
    main, vpn = pair_layout(Rect(a.x(), a.y(), a.width(), a.height()),
                            _frame_of(main_window), _frame_of(vpn_window))
    main_window.resize(main.w, main.h)
    main_window.move(main.x, main.y)
    vpn_window.resize(vpn.w, vpn.h)
    vpn_window.move(vpn.x, vpn.y)
    return True
