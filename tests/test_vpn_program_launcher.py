"""2026-10-20: a custom provider's program opened, and only reported when its
window really came up.  Fakes only."""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from vpn.providers import program_launcher as pl  # noqa: E402

EXE = r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe"
LNK = r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\AnyDesk.lnk"


class Launch:
    def __init__(self):
        self.opened = []

    def shell_open(self, path):
        self.opened.append(path)
        return True


class Desktop:
    """Windows appear after `after` polls; `image` owns the second one."""

    def __init__(self, image="AnyDesk.exe", after=2):
        self.polls, self.after, self.image = 0, after, image
        self.raised = []

    def visible_top_windows(self):
        self.polls += 1
        return [0x10, 0x20] if self.polls > self.after else [0x10]

    def window_pid(self, hwnd):
        return hwnd

    def process_image_path(self, pid):
        if pid == 0x10:
            return r"C:\Windows\explorer.exe"
        return "C:\\x\\" + self.image

    def is_iconic(self, hwnd):
        return False

    def restore_window(self, hwnd):
        pass

    def set_foreground_window(self, hwnd):
        self.raised.append(hwnd)
        return True


class Clock:
    def __init__(self):
        self.slept = 0.0

    def sleep(self, s):
        self.slept += s


def run(path=EXE, files=(EXE, LNK), target=EXE, desktop=None):
    desktop = desktop or Desktop()
    launch, clock = Launch(), Clock()
    result = pl.open_program(path, launch=launch, messages=desktop,
                             window_api=desktop, clock=clock,
                             resolve=lambda p: target, is_file=lambda p: p in files)
    return result, launch, desktop, clock


def test_the_window_is_waited_for_and_brought_forward():
    result, launch, desktop, _ = run()
    assert result.ok and result.reason == "window-shown"
    assert desktop.raised == [0x20], "tylko okno AnyDesk, nie explorer"
    assert launch.opened == [EXE]


def test_a_shortcut_is_opened_as_a_shortcut_when_its_target_exists():
    result, launch, _, _ = run(path=LNK)
    assert result.ok and launch.opened == [LNK]


def test_a_shortcut_to_a_missing_file_starts_nothing():
    result, launch, _, _ = run(path=LNK, files=(LNK,))
    assert result.reason == "shortcut-target-missing" and launch.opened == []


def test_a_missing_program_starts_nothing():
    result, launch, _, _ = run(files=())
    assert result.reason == "program-missing" and launch.opened == []


def test_no_window_is_reported_as_such_not_as_success():
    result, _, desktop, clock = run(desktop=Desktop(image="Other.exe"))
    assert not result.ok and result.reason == "no-window"
    assert clock.slept >= pl.WINDOW_WAIT_S and desktop.raised == []


class TrayDesktop(Desktop):
    """Already running in the tray: only its tray icon shows the window."""

    def __init__(self):
        super().__init__(after=10**6)
        self.clicked = []

    def tray_icon_windows(self):
        return [0x30, 0x40]

    def process_image_path(self, pid):
        if pid == 0x30:
            return "C:\\Other\\Other.exe"
        return super().process_image_path(pid)

    def post_tray_double_click(self, hwnd):
        self.clicked.append(hwnd)
        self.after = 0                      # the window comes up


def test_a_program_in_the_tray_is_shown_by_its_own_tray_icon():
    desktop = TrayDesktop()
    result, _, _, clock = run(desktop=desktop)
    assert result.ok and desktop.clicked == [0x40], "tylko ikona tego programu"
    assert clock.slept >= pl.TRAY_AFTER_S
