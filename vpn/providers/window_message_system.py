"""Window-message seam for the FortiClient authentication window.

The EMS edition authenticates in a WinForms window whose fields are real child
controls, so the legacy fills them with ``WM_SETTEXT`` and presses Connect with
``BM_CLICK`` instead of synthesising keystrokes.  This module is the only place
in ``vpn/`` allowed to touch those messages — the counterpart of
:mod:`vpn.providers.input_system` for the keyboard.

Why a seam at all: a token sent with ``WM_SETTEXT`` reaches whatever control
handle it is given, with no focus and no user-visible trace.  Isolating the
three primitives (enumerate, set text, click) behind an injectable object means
the whole 2FA sequence can be tested without a real window, and it keeps the
decision of *whether* to send — which belongs to
:class:`~vpn.providers.secure_target.VerifiedWindow` — out of the code that can
actually send.

``win32gui`` / ``win32con`` are imported lazily inside the methods, so
importing the package (which registers providers) pulls in nothing heavy and
the module imports fine on a machine without pywin32.

Parity: the control classification below is the legacy
``_find_forti_auth_window._enum_child`` test, unchanged — WinForms or plain
``Edit`` / ``Button`` classes only.  Order matters: the legacy takes the *last*
edit as the token field, so enumeration must preserve the Win32 Z-order.
"""

from __future__ import annotations

from dataclasses import dataclass

#: Qt5's tray callback message and the mouse event it carries (legacy
#: ``_activate_qt_tray_icon``; measured working on the owner's machines).
_QT_TRAY_CALLBACK = 0x8000 + 101
_WM_LBUTTONDBLCLK = 0x0203

__all__ = ["WindowControl", "WindowMessageSystem", "Win32WindowMessageSystem",
           "EDIT", "BUTTON", "is_connect_button"]

EDIT = "edit"
BUTTON = "button"


@dataclass(frozen=True)
class WindowControl:
    """One child control of an authentication window.

    ``text`` is a caption written by the client ("Connect", "Cancel") — it is
    used to find the submit button and is never a field value: the seam reads
    captions, never the contents of an edit control.
    """

    hwnd: object
    kind: str
    text: str = ""


def is_connect_button(text: str) -> bool:
    """The legacy submit-button test: ``"onnect" in text and "Cancel" not in text``.

    Case-insensitive on purpose in the legacy too ("onnect" matches both
    "Connect" and "connect"), and Cancel wins — a window with a single
    "Connect/Cancel" caption is not pressed.
    """
    return "onnect" in (text or "") and "Cancel" not in (text or "")


class WindowMessageSystem:
    """Enumerate child controls and send them window messages.

    It knows nothing about trust: every method takes a handle it is given and
    acts on it.  That is exactly why callers must reach it only from inside a
    confirmed :class:`~vpn.providers.secure_target.VerifiedWindow` guard.
    """

    def enumerate_controls(self, hwnd) -> list[WindowControl]:
        """Child Edit/Button controls, in Win32 enumeration order."""
        raise NotImplementedError

    def set_control_text(self, hwnd, text: str) -> None:
        """``WM_SETTEXT`` — the only way a secret leaves this process here."""
        raise NotImplementedError

    def click_button(self, hwnd) -> None:
        """``BM_CLICK`` — carries no secret."""
        raise NotImplementedError

    def sleep(self, seconds: float) -> None:
        raise NotImplementedError

    def tray_icon_windows(self) -> list:
        """Qt's hidden tray-icon message windows (class contains
        ``TrayIcon``), of every process.  The caller verifies the owner."""
        return []

    def post_tray_double_click(self, hwnd) -> None:
        """What a double-click on the tray icon sends Qt (WM_APP+101 with
        WM_LBUTTONDBLCLK) — the legacy ``_activate_qt_tray_icon``."""
        raise NotImplementedError


class Win32WindowMessageSystem(WindowMessageSystem):
    """The real thing.  Not exercised by the test suite (see the module doc)."""

    def enumerate_controls(self, hwnd) -> list[WindowControl]:
        import win32gui

        found: list[WindowControl] = []

        def _cb(child, _):
            try:
                cls = win32gui.GetClassName(child)
                text = win32gui.GetWindowText(child)
            except Exception:
                return True
            upper = cls.upper()
            winforms = "WindowsForms" in cls
            if "EDIT" in upper and (winforms or cls == "Edit"):
                found.append(WindowControl(child, EDIT, text))
            elif "BUTTON" in upper and (winforms or cls == "Button"):
                found.append(WindowControl(child, BUTTON, text))
            return True

        try:
            win32gui.EnumChildWindows(hwnd, _cb, None)
        except Exception:
            return []
        return found

    def set_control_text(self, hwnd, text: str) -> None:
        import win32con
        import win32gui
        win32gui.SendMessage(hwnd, win32con.WM_SETTEXT, 0, text)

    def click_button(self, hwnd) -> None:
        import win32con
        import win32gui
        win32gui.SendMessage(hwnd, win32con.BM_CLICK, 0, 0)

    def sleep(self, seconds: float) -> None:
        import time
        time.sleep(seconds)

    def tray_icon_windows(self) -> list:
        import win32gui
        found: list = []

        def _cb(hwnd, _):
            try:
                if "TrayIcon" in win32gui.GetClassName(hwnd):
                    found.append(hwnd)
            except Exception:
                pass
            return True

        try:
            win32gui.EnumWindows(_cb, None)
        except Exception:
            pass
        return found

    def post_tray_double_click(self, hwnd) -> None:
        import win32gui
        win32gui.PostMessage(hwnd, _QT_TRAY_CALLBACK, 0, _WM_LBUTTONDBLCLK)
