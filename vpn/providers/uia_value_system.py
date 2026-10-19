"""UI Automation value seam — the third way a secret reaches a client field.

Two seams already carry credentials into a window: :mod:`input_system`
(``SendInput`` keystrokes, for windows with no queryable controls) and
:mod:`window_message_system` (``WM_SETTEXT`` into native Win32 child controls).
A modern **WPF** client has neither — it renders its own controls inside a
single ``HwndWrapper`` HWND, so ``EnumChildWindows`` finds nothing and
``WM_SETTEXT`` has no target, while blind ``SendInput`` was measured to be
unreliable (the first keystroke after ``AttachThreadInput`` is dropped and the
field mapping drifts).

UI Automation is the answer WPF itself provides: every control has a stable
``AutomationId`` and, when editable, a **ValuePattern** whose ``SetValue`` sets
the field's text deterministically — no focus race, no tab counting, no lost
keystroke.  This seam wraps exactly that, and nothing else: find one element by
``AutomationId`` inside one window, and set its value.

Security — the same contract as the other two seams
---------------------------------------------------
This object decides nothing about trust.  It is reached only from inside a
confirmed :class:`~vpn.providers.secure_target.VerifiedWindow` guard, and every
:meth:`set_value` is additionally handed the ``expected_pid`` of that verified
window: the element it is about to write to must belong to that process, or the
value is refused before it is sent.  So a secret goes to a WPF field only when
the window is verified (HWND → PID → trusted image), in front and not minimised
(the guard), **and** the specific element is owned by that same verified
process.  It never raises, focuses, clicks or presses a key, and it carries no
title matching — the element is addressed by ``AutomationId`` within an already
verified HWND.

``comtypes`` is imported lazily inside the methods, so importing the package
(which registers providers) pulls in nothing, and a machine without it still
imports ``vpn`` fine — the seam only needs it when actually driving a live
window, and the tests use a fake.
"""

from __future__ import annotations

from dataclasses import dataclass

__all__ = ["UiaValueSystem", "Win32UiaValueSystem", "UiaField", "UiaSetOutcome",
           "AUTOMATION_ID_PROPERTY_ID", "VALUE_PATTERN_ID",
           "VALUE_IS_READONLY_PROPERTY_ID", "TREESCOPE_DESCENDANTS"]

#: Numeric UIA constants — used directly so the seam does not depend on a
#: generated constant module, only on the (lazily generated) interfaces.
AUTOMATION_ID_PROPERTY_ID = 30011
VALUE_PATTERN_ID = 10002
VALUE_IS_READONLY_PROPERTY_ID = 30046
TREESCOPE_DESCENDANTS = 4
IS_PASSWORD_PROPERTY_ID = 30019


@dataclass(frozen=True)
class UiaField:
    """What a read-only lookup of one element found.  No value, ever."""

    found: bool
    process_id: int | None = None
    read_only: bool | None = None
    control_type: int | None = None
    supports_value: bool = False


@dataclass(frozen=True)
class UiaSetOutcome:
    """What setting one element's value achieved.  Codes only, never the value."""

    found: bool
    performed: bool = False
    reason: str = ""
    process_id: int | None = None

    @property
    def ok(self) -> bool:
        return self.performed

    def __repr__(self) -> str:      # never the value
        return (f"<UiaSetOutcome found={self.found} performed={self.performed} "
                f"reason={self.reason!r}>")


class UiaValueSystem:
    """Find an element by ``AutomationId`` in a window, and set its value.

    It knows nothing about trust: the caller supplies the verified window's
    handle and pid, and reaches this only from inside a guard.
    """

    def find(self, hwnd, automation_id: str) -> UiaField:
        """Read-only: describe the element (pid, editability), or not-found."""
        raise NotImplementedError

    def set_value(self, hwnd, automation_id: str, value: str, *,
                  expected_pid: int) -> UiaSetOutcome:
        """Set the element's value — only if it is owned by ``expected_pid``.

        The value lives only in this call's arguments; it is never returned,
        logged or stored.
        """
        raise NotImplementedError

    def value_matches(self, hwnd, automation_id: str, expected: str, *,
                      expected_pid: int):
        """Does the element now hold `expected`?  ``None`` when it cannot be
        read (a password field never exposes its text).  Nothing is returned
        but the answer; the element's text is compared here and dropped."""
        return None

    def focus(self, hwnd, automation_id: str, *,
              expected_pid: int) -> UiaSetOutcome:
        """Give the element the keyboard focus — only if it is owned by
        ``expected_pid`` — and confirm that it has it.

        2026-10-19: ``SetValue`` fills a Qt field without Qt's ``textEdited``
        signal, so Stormshield kept its "Log in" button disabled.  Typing is
        what the clients react to; this is how the typing finds its field by
        identity instead of by counting Tab presses.  Carries no value.
        """
        raise NotImplementedError


class Win32UiaValueSystem(UiaValueSystem):
    """The real thing, over the Windows UI Automation COM API (``comtypes``).

    Not exercised by the test suite (the tests use a fake); it runs only against
    a live window.
    """

    def _element(self, hwnd, automation_id: str):
        import comtypes
        import comtypes.client
        from .msaa_system import ensure_com_apartment
        ensure_com_apartment(comtypes)          # a fresh worker thread (L3)
        mod = comtypes.client.GetModule("UIAutomationCore.dll")
        from comtypes.gen.UIAutomationClient import CUIAutomation, IUIAutomation
        uia = comtypes.client.CreateObject(CUIAutomation, interface=IUIAutomation)
        root = uia.ElementFromHandle(hwnd)
        cond = uia.CreatePropertyCondition(AUTOMATION_ID_PROPERTY_ID, automation_id)
        return root.FindFirst(TREESCOPE_DESCENDANTS, cond), mod

    def find(self, hwnd, automation_id: str) -> UiaField:
        try:
            el, _mod = self._element(hwnd, automation_id)
        except Exception:
            return UiaField(found=False)
        if not el:
            return UiaField(found=False)
        try:
            read_only = bool(el.GetCurrentPropertyValue(VALUE_IS_READONLY_PROPERTY_ID))
        except Exception:
            read_only = None
        try:
            supports = bool(el.GetCurrentPattern(VALUE_PATTERN_ID))
        except Exception:
            supports = False
        try:
            ctrl = int(el.CurrentControlType)
        except Exception:
            ctrl = None
        return UiaField(found=True, process_id=int(el.CurrentProcessId),
                        read_only=read_only, control_type=ctrl,
                        supports_value=supports)

    def set_value(self, hwnd, automation_id: str, value: str, *,
                  expected_pid: int) -> UiaSetOutcome:
        try:
            el, _mod = self._element(hwnd, automation_id)
        except Exception as exc:
            return UiaSetOutcome(False, reason=f"uia-error:{type(exc).__name__}")
        if not el:
            return UiaSetOutcome(False, reason="not-found")
        try:
            pid = int(el.CurrentProcessId)
        except Exception as exc:
            return UiaSetOutcome(True, reason=f"pid-error:{type(exc).__name__}")
        if pid != expected_pid:
            # The element is not owned by the verified window's process — the
            # exact refusal the whole seam exists to make possible.
            return UiaSetOutcome(True, reason="pid-mismatch", process_id=pid)
        try:
            from comtypes.gen.UIAutomationClient import IUIAutomationValuePattern
            pattern = el.GetCurrentPattern(VALUE_PATTERN_ID)
            if not pattern:
                return UiaSetOutcome(True, reason="no-value-pattern", process_id=pid)
            vp = pattern.QueryInterface(IUIAutomationValuePattern)
            if vp.CurrentIsReadOnly:
                return UiaSetOutcome(True, reason="read-only", process_id=pid)
            vp.SetValue(value)
        except Exception as exc:
            return UiaSetOutcome(True, reason=f"set-error:{type(exc).__name__}",
                                 process_id=pid)
        return UiaSetOutcome(True, performed=True, reason="set", process_id=pid)

    def focus(self, hwnd, automation_id: str, *,
              expected_pid: int) -> UiaSetOutcome:
        try:
            el, _mod = self._element(hwnd, automation_id)
        except Exception as exc:
            return UiaSetOutcome(False, reason=f"uia-error:{type(exc).__name__}")
        if not el:
            return UiaSetOutcome(False, reason="not-found")
        try:
            pid = int(el.CurrentProcessId)
        except Exception as exc:
            return UiaSetOutcome(True, reason=f"pid-error:{type(exc).__name__}")
        if pid != expected_pid:
            return UiaSetOutcome(True, reason="pid-mismatch", process_id=pid)
        try:
            el.SetFocus()
        except Exception as exc:
            return UiaSetOutcome(True, reason=f"focus-error:{type(exc).__name__}",
                                 process_id=pid)
        try:
            again, _mod = self._element(hwnd, automation_id)
            focused = bool(again and again.CurrentHasKeyboardFocus)
        except Exception:
            focused = False
        if not focused:
            return UiaSetOutcome(True, reason="focus-not-taken", process_id=pid)
        return UiaSetOutcome(True, performed=True, reason="focused", process_id=pid)

    def value_matches(self, hwnd, automation_id: str, expected: str, *,
                      expected_pid: int):
        try:
            el, _mod = self._element(hwnd, automation_id)
            if not el or int(el.CurrentProcessId) != expected_pid:
                return None
            if el.GetCurrentPropertyValue(IS_PASSWORD_PROPERTY_ID):
                return None
            from comtypes.gen.UIAutomationClient import IUIAutomationValuePattern
            pattern = el.GetCurrentPattern(VALUE_PATTERN_ID)
            if not pattern:
                return None
            return (pattern.QueryInterface(IUIAutomationValuePattern).CurrentValue
                    or "") == expected
        except Exception:
            return None
