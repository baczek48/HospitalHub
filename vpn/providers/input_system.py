"""Keyboard and clipboard seam for FortiClient autofill.

The only part of the migrated autofill allowed to synthesise input, isolated
exactly like :mod:`vpn.providers.launch_system` so the whole autofill sequence
can be driven by a fake in tests — no real ``SendInput``, no real clipboard.

The Win32 implementation mirrors the primitives the legacy ``vpn_connect`` uses
(``SendInput`` unicode/vk events, ``win32clipboard``).  It is a *separate* copy
on purpose: the legacy module stays frozen this stage, and ``vpn/`` must not
import it.  The duplication is a deliberate, temporary cost — it goes away when
the legacy autofill is removed in a later stage — and it introduces no second
security path: every secret still flows through the Stage-13 guard.

``ctypes`` / ``win32clipboard`` are imported lazily inside the methods, so
importing the package (which registers providers) pulls in nothing heavy.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["InputSystem", "Win32InputSystem", "FocusedControl",
           "UIA_COMBOBOX_CONTROL_TYPE",
           "VK_TAB", "VK_SHIFT", "VK_RETURN", "VK_CONTROL", "VK_SPACE",
           "VK_DELETE"]

VK_TAB = 0x09
#: Stormshield tabs *backwards* through its form (Stage 40 measured it),
#: and no migrated path needed a modifier other than Ctrl until now.
VK_SHIFT = 0x10
VK_RETURN = 0x0D
VK_CONTROL = 0x11
VK_SPACE = 0x20
VK_DELETE = 0x2E

#: UIA_ComboBoxControlTypeId.  The only control type whose value
#: :meth:`InputSystem.focused_control` is willing to read.
UIA_COMBOBOX_CONTROL_TYPE = 50003
_UIA_VALUE_PATTERN_ID = 10002
_UIA_SELECTION_PATTERN_ID = 10001

_KEYEVENTF_KEYUP = 0x0002


@dataclass(frozen=True)
class FocusedControl:
    """What has the keyboard focus right now (Stage 60).

    ``value`` is filled **only for a combo box** — the displayed selection,
    e.g. a FortiClient VPN profile name.  For any other control it stays
    ``None``, so asking "where is the caret" can never read a login or a
    password back out of a text field.
    """

    found: bool
    process_id: int | None = None
    control_type: int | None = None
    value: str | None = None
    reason: str = ""

    @property
    def is_combo(self) -> bool:
        return self.found and self.control_type == UIA_COMBOBOX_CONTROL_TYPE

_KEYEVENTF_UNICODE = 0x0004


class InputSystem:
    """Keystrokes, clipboard and waiting.  Tests substitute a recorder.

    It knows nothing about windows or focus — the caller only reaches it from
    inside a confirmed :class:`~vpn.providers.secure_target.VerifiedWindow`
    guard, so an :class:`InputSystem` on its own can never target a window.
    """

    def press_key(self, vk: int) -> None:
        raise NotImplementedError

    def press_combo(self, modifier_vk: int, key: int) -> None:
        raise NotImplementedError

    def type_text(self, text: str) -> None:
        raise NotImplementedError

    def copy_to_clipboard(self, text: str) -> bool:
        raise NotImplementedError

    def read_clipboard(self) -> str | None:
        raise NotImplementedError

    def sleep(self, seconds: float) -> None:
        raise NotImplementedError

    def focused_control(self) -> FocusedControl:
        """Read-only: the control that would receive the next keystroke.

        The default answers "unknown", which every caller treats as a refusal
        — an input system that cannot say where focus is cannot confirm a
        profile choice either (Stage 60).
        """
        return FocusedControl(found=False, reason="unsupported")


class Win32InputSystem(InputSystem):
    """The real desktop, via ``SendInput`` and ``win32clipboard``."""

    def _send(self, vk: int = 0, scan: int = 0, flags: int = 0) -> None:
        import ctypes
        from ctypes import wintypes

        class _MOUSEINPUT(ctypes.Structure):
            _fields_ = [("dx", ctypes.c_long), ("dy", ctypes.c_long),
                        ("mouseData", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                        ("time", wintypes.DWORD),
                        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]

        class _KEYBDINPUT(ctypes.Structure):
            _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD),
                        ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD),
                        ("dwExtraInfo", ctypes.POINTER(ctypes.c_ulong))]

        class _HARDWAREINPUT(ctypes.Structure):
            _fields_ = [("uMsg", wintypes.DWORD), ("wParamL", wintypes.WORD),
                        ("wParamH", wintypes.WORD)]

        class _INPUT(ctypes.Structure):
            class _U(ctypes.Union):
                _fields_ = [("mi", _MOUSEINPUT), ("ki", _KEYBDINPUT),
                            ("hi", _HARDWAREINPUT)]
            _fields_ = [("type", wintypes.DWORD), ("u", _U)]

        inp = _INPUT(type=1)                      # INPUT_KEYBOARD
        inp.u.ki.wVk = vk
        inp.u.ki.wScan = scan
        inp.u.ki.dwFlags = flags
        ctypes.windll.user32.SendInput(1, ctypes.byref(inp), ctypes.sizeof(_INPUT))

    def press_key(self, vk: int) -> None:
        import time
        self._send(vk=vk)
        time.sleep(0.03)
        self._send(vk=vk, flags=_KEYEVENTF_KEYUP)
        time.sleep(0.05)

    def press_combo(self, modifier_vk: int, key: int) -> None:
        import time
        self._send(vk=modifier_vk)
        time.sleep(0.02)
        self._send(vk=key)
        time.sleep(0.02)
        self._send(vk=key, flags=_KEYEVENTF_KEYUP)
        time.sleep(0.02)
        self._send(vk=modifier_vk, flags=_KEYEVENTF_KEYUP)
        time.sleep(0.05)

    def type_text(self, text: str) -> None:
        import time
        for ch in text:
            code = ord(ch)
            self._send(scan=code, flags=_KEYEVENTF_UNICODE)
            self._send(scan=code, flags=_KEYEVENTF_UNICODE | _KEYEVENTF_KEYUP)
            time.sleep(0.01)

    #: Registered clipboard formats that keep this content out of the
    #: Windows clipboard history (Win+V), out of cloud clipboard sync and away
    #: from clipboard monitors (2026-10-14, C3-01 for the V2 fill): a password
    #: pasted by the autofill must not stay in the history after the
    #: clipboard is restored.  DWORD 0 for the two "Can…" formats; for the
    #: first one its presence is what counts.
    _PRIVATE_FORMATS = ("ExcludeClipboardContentFromMonitorProcessing",
                        "CanIncludeInClipboardHistory",
                        "CanUploadToCloudClipboard")

    def copy_to_clipboard(self, text: str) -> bool:
        try:
            import win32clipboard
            win32clipboard.OpenClipboard()
            try:
                win32clipboard.EmptyClipboard()
                win32clipboard.SetClipboardText(text)
                for name in self._PRIVATE_FORMATS:
                    try:
                        fmt = win32clipboard.RegisterClipboardFormat(name)
                        win32clipboard.SetClipboardData(fmt, b"\x00\x00\x00\x00")
                    except Exception:
                        pass        # the text is set; the marks are extra
            finally:
                win32clipboard.CloseClipboard()
            return True
        except Exception:
            return False

    def read_clipboard(self) -> str | None:
        try:
            import win32clipboard
            win32clipboard.OpenClipboard()
            try:
                data = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
            except Exception:
                data = None
            win32clipboard.CloseClipboard()
            return data
        except Exception:
            return None

    def sleep(self, seconds: float) -> None:
        import time
        time.sleep(seconds)

    def focused_control(self) -> FocusedControl:
        """UI Automation's focused element: owner pid, type, combo value.

        Not a source of truth for the FortiClient profile: on 7.4.3 the
        Electron form is invisible to UI Automation (Stage 61), and the
        profile is read through MSAA instead (``forticlient_profile``).

        ``comtypes`` is imported here, lazily, like the other seams.  Any
        failure is an answer of "unknown", never an exception, and never a
        guess.
        """
        try:
            import comtypes.client
            comtypes.client.GetModule("UIAutomationCore.dll")
            from comtypes.gen.UIAutomationClient import (
                CUIAutomation, IUIAutomation, IUIAutomationSelectionPattern,
                IUIAutomationValuePattern,
            )
            uia = comtypes.client.CreateObject(CUIAutomation,
                                               interface=IUIAutomation)
            el = uia.GetFocusedElement()
        except Exception as exc:
            return FocusedControl(found=False,
                                  reason=f"uia-error:{type(exc).__name__}")
        if not el:
            return FocusedControl(found=False, reason="no-focus")
        try:
            pid = int(el.CurrentProcessId)
            ctrl = int(el.CurrentControlType)
        except Exception as exc:
            return FocusedControl(found=False,
                                  reason=f"uia-error:{type(exc).__name__}")
        if ctrl != UIA_COMBOBOX_CONTROL_TYPE:
            return FocusedControl(found=True, process_id=pid, control_type=ctrl)
        value = None
        try:
            pattern = el.GetCurrentPattern(_UIA_VALUE_PATTERN_ID)
            if pattern:
                value = pattern.QueryInterface(
                    IUIAutomationValuePattern).CurrentValue or None
        except Exception:
            value = None
        if value is None:
            # A combo that does not expose a value may still expose which
            # item is selected.
            try:
                pattern = el.GetCurrentPattern(_UIA_SELECTION_PATTERN_ID)
                if pattern:
                    sel = pattern.QueryInterface(
                        IUIAutomationSelectionPattern).GetCurrentSelection()
                    if sel and sel.Length > 0:
                        value = sel.GetElement(0).CurrentName or None
            except Exception:
                value = None
        return FocusedControl(found=True, process_id=pid, control_type=ctrl,
                              value=value)
