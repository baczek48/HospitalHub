"""Open a custom provider's program and confirm that its window came up.

2026-10-20 (owner): an "Anydesk" card only has to open AnyDesk.  Without a
path, a shortcut found by name was handed to ``os.startfile`` and the legacy
reported "Uruchomiono" whether or not anything opened — the owner saw the
sentence and no AnyDesk.  This module says what really happened:

* a ``.lnk`` must point at a file that exists (resolved through the shell's
  own shortcut object), otherwise nothing is started;
* the program is started by the desktop shell, like a double-click
  (:func:`launch_system.desktop_shell_execute`), falling back to a detached
  start with the user's environment;
* success means a visible window of that program appeared within a few
  seconds; it is then brought to the front (HospitalHub is the foreground
  program at the click).  No window — the result says so.

No credential passes through here: a program is opened, nothing is typed.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

__all__ = ["ProgramOpen", "open_program", "shortcut_target", "WINDOW_WAIT_S"]

#: How long the program's window may take to appear.
WINDOW_WAIT_S = 8.0
_POLL_S = 0.25
#: After this long without a window, the program's tray icon is tried once
#: (a program already running in the tray ignores a second start — measured
#: with Hillstone and Stormshield).
TRAY_AFTER_S = 3.0


@dataclass(frozen=True)
class ProgramOpen:
    ok: bool
    #: ``window-shown`` | ``program-missing`` | ``shortcut-target-missing`` |
    #: ``launch-failed`` | ``no-window``
    reason: str
    image_name: str = ""


def shortcut_target(path: str) -> str:
    """The file a ``.lnk`` points at, or ``""`` when it cannot be read."""
    try:
        import pythoncom
        import win32com.client
        pythoncom.CoInitialize()
        try:
            link = win32com.client.Dispatch("WScript.Shell").CreateShortcut(path)
            return str(link.TargetPath or "")
        finally:
            link = None
            pythoncom.CoUninitialize()
    except Exception:
        return ""


def open_program(path: str, *, launch=None, messages=None, window_api=None,
                 clock=None, resolve=shortcut_target,
                 is_file=os.path.isfile) -> ProgramOpen:
    """Start `path` (an executable or a shortcut) and wait for its window."""
    if not path:
        return ProgramOpen(False, "program-missing")
    target = path
    if path.lower().endswith(".lnk"):
        if not is_file(path):
            return ProgramOpen(False, "program-missing")
        target = resolve(path)
        if not target or not is_file(target):
            return ProgramOpen(False, "shortcut-target-missing")
    elif not is_file(path):
        return ProgramOpen(False, "program-missing")
    image = os.path.basename(target).lower()

    if launch is None:
        from .launch_system import WindowsLaunchSystem
        launch = WindowsLaunchSystem()
    try:
        from .launch_system import desktop_shell_execute
        started = bool(launch.shell_open(path)) if hasattr(launch, "shell_open") \
            else desktop_shell_execute(path, os.path.dirname(target))
    except Exception:
        started = False
    if not started:
        try:
            launch.spawn_detached(target, os.path.dirname(target))
        except Exception:
            return ProgramOpen(False, "launch-failed", image)

    if messages is None:
        from .window_message_system import Win32WindowMessageSystem
        messages = Win32WindowMessageSystem()
    if window_api is None:
        from secure_window import Win32WindowApi
        window_api = Win32WindowApi()
    if clock is None:
        import time as clock

    waited = 0.0
    tray_tried = False
    while True:
        hwnd = _window_of(image, messages, window_api)
        if hwnd is not None:
            try:
                if window_api.is_iconic(hwnd) is True:
                    window_api.restore_window(hwnd)
                window_api.set_foreground_window(hwnd)
            except Exception:
                pass
            return ProgramOpen(True, "window-shown", image)
        if waited >= WINDOW_WAIT_S:
            return ProgramOpen(False, "no-window", image)
        if not tray_tried and waited >= TRAY_AFTER_S:
            tray_tried = True
            _click_tray_icon(image, messages, window_api)
        clock.sleep(_POLL_S)
        waited += _POLL_S


def _click_tray_icon(image: str, messages, window_api) -> bool:
    """The Qt tray double-click, on an icon window owned by this program."""
    try:
        icons = messages.tray_icon_windows()
    except Exception:
        return False
    for hwnd in icons:
        try:
            pid = window_api.window_pid(hwnd)
            path = window_api.process_image_path(pid) if pid else None
            if path and os.path.basename(path).lower() == image:
                messages.post_tray_double_click(hwnd)
                return True
        except Exception:
            continue
    return False


def _window_of(image: str, messages, window_api):
    for hwnd in messages.visible_top_windows():
        try:
            pid = window_api.window_pid(hwnd)
            path = window_api.process_image_path(pid) if pid else None
        except Exception:
            continue
        if path and os.path.basename(path).lower() == image:
            return hwnd
    return None
