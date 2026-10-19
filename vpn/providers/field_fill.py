"""Fill a client's form field by field: focus by AutomationId, then type.

2026-10-19 (owner's field test).  Two ways of filling had been migrated and
neither was right on the owner's clients:

* **Tab counting** (Stormshield): the sequence assumed the cursor started in
  Password.  On a real client it started in Firewall address — the password was
  typed into a plain-text field, on screen.
* **UIA ``SetValue``** (Barracuda, measured fine there): on Stormshield's Qt
  form the values arrived but Qt never saw an edit, so "Log in" stayed disabled.

What works on both, measured live: ask UI Automation to put the keyboard focus
on the field with a given ``AutomationId`` (and confirm it has it), select what
is there, and type — exactly what a person does, without guessing where the
cursor is.  Every step runs inside :meth:`VerifiedWindow.run_guarded`, so the
window is re-confirmed (verified owner, in front, not minimised) before the
focus, before the select-all and before the typing; the focus call also refuses
an element owned by another process.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..types import AutofillResult, AutofillStatus, ErrorCode
from .input_system import VK_RETURN

#: Moves the caret to the end of the field; edits nothing.
VK_END = 0x23

__all__ = ["Field", "FillOutcome", "fill_fields", "submit", "fill_form",
           "NO_TARGET_REASONS"]


#: Pauses the client needs between steps.  ``_SETTLE_S``: a window that has
#: just been brought to the front drops the first keystrokes (measured
#: 2026-10-19: the login typed first was lost, the same text typed a moment
#: later arrived).
_SETTLE_S = 0.5
_AFTER_FOCUS_S = 0.15
_AFTER_CLEAR_S = 0.05
_AFTER_TYPE_S = 0.2
#: One more attempt for a field whose text can be read back and is wrong.
_RETRIES = 1
#: After the profile changed, the form re-lays itself out.
_PROFILE_SETTLE_S = 0.4


@dataclass(frozen=True)
class Field:
    """One field to fill.  ``value`` is never printed."""

    phase: str
    automation_id: str
    value: str
    #: Which credential flag this field sets on success, if any.
    marks: str | None = None

    def __repr__(self) -> str:
        return f"<Field {self.phase} {self.automation_id}>"


@dataclass(frozen=True)
class FillOutcome:
    ok: bool
    #: The phase that stopped the fill, when it stopped.
    blocked_at: str | None = None
    reason: str | None = None
    entered: tuple[str, ...] = ()


def fill_fields(win, uia, keys, fields, *, cancelled=lambda: False) -> FillOutcome:
    """Fill `fields` in order; stop at the first refusal.  Never raises for a
    refusal -- a seam that raises propagates to the caller's ``except``.

    Per field: focus by AutomationId (confirmed), clear through UI Automation
    (Ctrl+A does not select in Stormshield's password box: the new password was
    appended to the old one), type, and -- where the text can be read back --
    check it and try once more.
    """
    entered: list[str] = []
    keys.sleep(_SETTLE_S)
    for field in fields:
        if not field.value:
            continue
        for attempt in range(_RETRIES + 1):
            if cancelled():
                return FillOutcome(False, field.phase, "cancelled", tuple(entered))
            focused = win.run_guarded(
                field.phase + "-focus",
                lambda f=field: uia.focus(win.hwnd, f.automation_id,
                                          expected_pid=win.pid))
            if not focused.performed:
                return FillOutcome(False, field.phase, focused.reason, tuple(entered))
            outcome = focused.value
            if outcome is None or not getattr(outcome, "ok", False):
                return FillOutcome(False, field.phase,
                                   getattr(outcome, "reason", "focus-failed"),
                                   tuple(entered))
            keys.sleep(_AFTER_FOCUS_S)
            if cancelled():
                return FillOutcome(False, field.phase, "cancelled", tuple(entered))
            cleared = win.run_guarded(
                field.phase + "-clear",
                lambda f=field: uia.set_value(win.hwnd, f.automation_id, "",
                                              expected_pid=win.pid))
            if not cleared.performed:
                return FillOutcome(False, field.phase, cleared.reason, tuple(entered))
            keys.sleep(_AFTER_CLEAR_S)

            def type_it(f=field):
                keys.type_text(f.value)
                # One real key press after the text.  Unicode text input does
                # not make WPF re-evaluate its commands: Barracuda kept
                # "Connect" disabled until a real key arrived (measured; the
                # legacy's double Enter was this).  End only moves the caret.
                keys.press_key(VK_END)
                keys.sleep(_AFTER_TYPE_S)

            typed = win.run_guarded(field.phase, type_it)
            if not typed.performed:
                return FillOutcome(False, field.phase, typed.reason, tuple(entered))
            check = uia.value_matches(win.hwnd, field.automation_id, field.value,
                                      expected_pid=win.pid)
            if check is not False:
                break                   # matches, or cannot be read (password)
        else:
            return FillOutcome(False, field.phase, "value-not-taken", tuple(entered))
        if field.marks:
            entered.append(field.marks)
    return FillOutcome(True, entered=tuple(entered))


def submit(win, uia, keys, automation_id: str) -> FillOutcome:
    """Enter in the field `automation_id` (the password) — the client's own
    default action, as the legacy did.  Guarded like every other step."""
    focused = win.run_guarded(
        "submit-focus",
        lambda: uia.focus(win.hwnd, automation_id, expected_pid=win.pid))
    if not focused.performed:
        return FillOutcome(False, "submit", focused.reason)
    outcome = focused.value
    if outcome is None or not getattr(outcome, "ok", False):
        return FillOutcome(False, "submit", getattr(outcome, "reason", "focus-failed"))
    pressed = win.run_guarded("submit", lambda: keys.press_key(VK_RETURN))
    if not pressed.performed:
        return FillOutcome(False, "submit", pressed.reason)
    return FillOutcome(True)


#: Reasons that mean "no trusted window", as opposed to "found one, could not
#: use it" -- the split every autofill reports.
NO_TARGET_REASONS = ("no-verified-target", "no-window", "no-process",
                     "image-unavailable", "untrusted-image",
                     "control-not-owned-by-target")


class _Trace:
    def __init__(self, trace):
        self._t = trace

    def ok(self, name, **data):
        if self._t is not None:
            self._t.ok(name, **data)

    def fail(self, name, **data):
        if self._t is not None:
            self._t.fail(name, **data)


def fill_form(provider_id: str, target, uia, keys, fields, *, submit_field=None,
              cancellation=None, trace=None, select_profile=None) -> AutofillResult:
    """Acquire the verified client window, fill `fields`, optionally press Enter
    in `submit_field`; an :class:`AutofillResult` either way.

    ``submit_field=None`` leaves the submit to the person (the second factor
    still has to be typed); ``metadata["submitted"]`` says which happened.
    """
    tr = _Trace(trace)
    tr.ok("vpn.autofill", event="autofill-start", automation_mode="uia_focus_type")

    def cancelled() -> bool:
        return cancellation is not None and bool(cancellation.cancelled)

    found = target.first_verified_candidate()
    if found is None:
        tr.fail("vpn.autofill", event="autofill-failure", reason="no-verified-target",
                error_code="target-window-untrusted")
        return AutofillResult(
            provider_id=provider_id, success=False, status=AutofillStatus.NO_TARGET,
            blocked_at="acquire", error_code=ErrorCode.CLIENT_NOT_FOUND.value,
            metadata={"reason_code": "no-verified-target"})
    acquired = target.acquire(found[0])
    if not hasattr(acquired, "run_guarded"):
        reason = getattr(acquired, "reason", "no-verified-target")
        no_target = reason in NO_TARGET_REASONS
        tr.fail("vpn.autofill", event="autofill-failure", reason=reason,
                error_code=("target-window-untrusted" if no_target
                            else "focus-failed"))
        return AutofillResult(
            provider_id=provider_id, success=False,
            status=AutofillStatus.NO_TARGET if no_target else AutofillStatus.NO_FOCUS,
            blocked_at="acquire",
            error_code=(ErrorCode.CLIENT_NOT_FOUND.value if no_target
                        else ErrorCode.FOCUS_FAILED.value),
            metadata={"reason_code": reason})
    tr.ok("vpn.autofill", event="target-acquired", image_name=acquired.image_name,
          pid=acquired.pid)

    entered: tuple[str, ...] = ()
    with acquired as win:
        try:
            if select_profile is not None:
                if cancelled():
                    return _stopped(provider_id, tr, FillOutcome(
                        False, "profile", "cancelled"))
                chosen = win.run_guarded(
                    "profile", lambda: uia.select_list_item(
                        win.hwnd, select_profile, expected_pid=win.pid))
                result = chosen.value
                if not chosen.performed:
                    return _stopped(provider_id, tr, FillOutcome(
                        False, "profile", chosen.reason))
                if result is None or not getattr(result, "ok", False):
                    return _stopped(provider_id, tr, FillOutcome(
                        False, "profile", getattr(result, "reason", "profile-failed")))
                tr.ok("vpn.autofill", event="profile-step", method="uia_select",
                      verified=True)
                keys.sleep(_PROFILE_SETTLE_S)
            outcome = fill_fields(win, uia, keys, fields, cancelled=cancelled)
            entered = outcome.entered
            if not outcome.ok:
                return _stopped(provider_id, tr, outcome)
            for flag in entered:
                tr.ok("vpn.autofill", event=f"{flag}-step", method="uia_focus_type",
                      entered=True)
            submitted = False
            if submit_field is not None and not cancelled():
                pressed = submit(win, uia, keys, submit_field)
                if not pressed.ok:
                    return _stopped(provider_id, tr, FillOutcome(
                        False, "submit", pressed.reason, entered))
                submitted = True
            tr.ok("vpn.autofill", event="autofill-success",
                  login_entered="login" in entered,
                  password_entered="password" in entered, submitted=submitted)
            return AutofillResult(
                provider_id=provider_id, success=True, status=AutofillStatus.DONE,
                login_entered="login" in entered,
                password_entered="password" in entered,
                metadata={"requires_user_action": not submitted,
                          "submitted": submitted,
                          # the card says "filled — finish in the client"
                          "filled_only": not submitted})
        except Exception as exc:                       # a seam misbehaved
            tr.fail("vpn.autofill", event="autofill-failure",
                    error_code="automation-failed", reason=type(exc).__name__)
            return AutofillResult(
                provider_id=provider_id, success=False, status=AutofillStatus.FAILED,
                login_entered="login" in entered,
                password_entered="password" in entered,
                error_code=ErrorCode.AUTOMATION_FAILED.value,
                metadata={"reason_code": type(exc).__name__})


def _stopped(provider_id, tr, outcome: FillOutcome) -> AutofillResult:
    if outcome.reason == "cancelled":
        tr.fail("vpn.autofill", event="autofill-cancelled",
                blocked_at=outcome.blocked_at, error_code=ErrorCode.CANCELLED.value)
        return AutofillResult(
            provider_id=provider_id, success=False, status=AutofillStatus.CANCELLED,
            login_entered="login" in outcome.entered,
            password_entered="password" in outcome.entered,
            blocked_at=outcome.blocked_at, error_code=ErrorCode.CANCELLED.value,
            metadata={"reason_code": "cancelled"})
    tr.fail("vpn.autofill", event="secret-input-blocked", blocked_at=outcome.blocked_at,
            reason=outcome.reason, error_code=ErrorCode.SECRET_INPUT_BLOCKED.value)
    return AutofillResult(
        provider_id=provider_id, success=False, status=AutofillStatus.BLOCKED,
        login_entered="login" in outcome.entered,
        password_entered="password" in outcome.entered,
        blocked_at=outcome.blocked_at, error_code=ErrorCode.SECRET_INPUT_BLOCKED.value,
        metadata={"reason_code": outcome.reason})
