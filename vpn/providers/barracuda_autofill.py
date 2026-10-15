"""Barracuda autofill — login + password into the WPF client, by AutomationId.

Measured live (Stage 50B/50C), not guessed.  The Barracuda Network Access
Client login window is **WPF** (``HwndWrapper[nacvpn.exe;;<guid>]``) with zero
native child controls, so ``WM_SETTEXT`` has nothing to write to and blind
``SendInput`` was measured to be unreliable.  What the window *does* expose is a
stable UI Automation tree:

======================  =======================  ==========================
field                   ``AutomationId``         handled here
======================  =======================  ==========================
User Name               ``TextBoxUser``          yes  — login
User Password           ``PasswordBoxUser``      yes  — password
OTP (hidden until MFA)  ``PasswordBoxOTP``       **no** — a separate contract
Certificate password    ``PasswordBoxCert``      **no**
profile combo ("MCX")   (none)                   **no** — already selected
Connect                 (button)                 **no** — never pressed here
======================  =======================  ==========================

So this fills exactly two fields, through :class:`UiaValueSystem.set_value`
addressed by ``AutomationId``, and stops — the same shape as the Stormshield
autofill (fill and stop, the user clicks Connect), with the mechanism swapped
from keystrokes to UI Automation.

Security — identical guarantees to the other providers
------------------------------------------------------
Every ``set_value`` runs inside :meth:`VerifiedWindow.run_guarded`, which
re-confirms before it runs anything that the pinned window is owned by the
trusted process, is in front and is not minimised.  The seam is *additionally*
handed the verified window's pid and refuses any element not owned by it.
Cancellation is checked before every field.  There is no Enter, no click on
Connect, no clipboard, no keystroke, no window raised or focused: the fields are
set by value, and the person reads what was filled and clicks Connect.

The token/OTP and certificate fields are deliberately untouched: a second factor
is its own contract, and a field existing in the tree is not a licence to fill
it.
"""

from __future__ import annotations

from ..types import AutofillResult, AutofillStatus, ErrorCode, VpnRequest
from .secure_target import SecureWindowTarget, VerifiedWindow
from .uia_value_system import UiaValueSystem, Win32UiaValueSystem

__all__ = ["autofill_login_password", "PHASES", "PHASE_LOGIN", "PHASE_PASSWORD",
           "AID_USER", "AID_PASSWORD", "REASON_CANCELLED"]

#: The measured AutomationIds of the two credential fields.
AID_USER = "TextBoxUser"
AID_PASSWORD = "PasswordBoxUser"

PHASE_LOGIN = "login"
PHASE_PASSWORD = "password"
PHASES = (PHASE_LOGIN, PHASE_PASSWORD)

#: Reason a guard reports when the caller called the fill off.
REASON_CANCELLED = "cancelled"

#: Reasons that mean "no trusted window", as opposed to "found one, could not
#: use it" — same split as the other autofills.
_NO_TARGET_REASONS = ("no-verified-target", "no-window", "no-process",
                      "image-unavailable", "untrusted-image",
                      "control-not-owned-by-target")


class _Trace:
    """Null-safe wrapper — the caller may pass a diagnostics trace or None."""

    def __init__(self, trace):
        self._t = trace

    def ok(self, name, **data):
        if self._t is not None:
            self._t.ok(name, **data)

    def fail(self, name, **data):
        if self._t is not None:
            self._t.fail(name, **data)


def autofill_login_password(
        provider, request: VpnRequest, *,
        target: SecureWindowTarget | None = None,
        uia: UiaValueSystem | None = None,
        cancellation=None, trace=None) -> AutofillResult:
    """Fill User Name and User Password by AutomationId, then stop.

    `target` defaults to the provider's :meth:`secure_window_target`
    (``require_visible=True, raise_window=False``); `uia` to the real
    UI Automation seam.  Both are injected in tests.
    """
    tr = _Trace(trace)
    uia = uia if uia is not None else Win32UiaValueSystem()
    target = target if target is not None else provider.secure_window_target()
    pid = provider.id
    login, password = request.login, request.password

    tr.ok("vpn.autofill", event="autofill-start", automation_mode="uia_value")

    # Locate first so we have the hwnd the seam must address, then acquire it —
    # the same window, verified, taken with the strict foreground contract.
    found = target.first_verified_candidate()
    if found is None:
        tr.fail("vpn.autofill", event="autofill-failure", reason="no-verified-target",
                error_code="target-window-untrusted")
        return AutofillResult(
            provider_id=pid, success=False, status=AutofillStatus.NO_TARGET,
            blocked_at="acquire", error_code=ErrorCode.CLIENT_NOT_FOUND.value,
            metadata={"reason_code": "no-verified-target"})
    hwnd, _owner = found

    acquired = target.acquire(hwnd)
    if not isinstance(acquired, VerifiedWindow):
        reason = getattr(acquired, "reason", "no-verified-target")
        no_target = reason in _NO_TARGET_REASONS
        status = AutofillStatus.NO_TARGET if no_target else AutofillStatus.NO_FOCUS
        tr.fail("vpn.autofill", event="autofill-failure", reason=reason,
                error_code=("target-window-untrusted" if no_target
                            else "focus-failed"))
        return AutofillResult(
            provider_id=pid, success=False, status=status, blocked_at="acquire",
            error_code=(ErrorCode.CLIENT_NOT_FOUND.value if no_target
                        else ErrorCode.FOCUS_FAILED.value),
            metadata={"reason_code": reason})

    tr.ok("vpn.autofill", event="target-acquired", image_name=acquired.image_name,
          pid=acquired.pid)

    state = {"login": False, "password": False}

    def cancelled() -> bool:
        return cancellation is not None and bool(cancellation.cancelled)

    def set_field(win: VerifiedWindow, phase: str, automation_id: str,
                  value: str) -> tuple[bool, str]:
        """Guarded ``set_value``: the guard re-confirms the window, the seam
        re-confirms the element's owner, before the value is set."""
        if cancelled():
            return False, REASON_CANCELLED
        result = win.run_guarded(
            phase,
            lambda: uia.set_value(win._hwnd, automation_id, value,
                                  expected_pid=win.pid))
        if not result.performed:
            return False, result.reason        # guard refused (foreground/owner)
        outcome = result.value
        if outcome is None or not getattr(outcome, "ok", False):
            return False, getattr(outcome, "reason", "set-failed")
        return True, "set"

    with acquired as win:
        try:
            if login:
                ok, reason = set_field(win, PHASE_LOGIN, AID_USER, login)
                if not ok:
                    return _stop(pid, state, tr, PHASE_LOGIN, reason)
                state["login"] = True
                tr.ok("vpn.autofill", event="login-step", field="username",
                      method="uia_value", entered=True)

            if password:
                ok, reason = set_field(win, PHASE_PASSWORD, AID_PASSWORD, password)
                if not ok:
                    return _stop(pid, state, tr, PHASE_PASSWORD, reason)
                state["password"] = True
                tr.ok("vpn.autofill", event="password-step", field="password",
                      method="uia_value", entered=True)

            # --- and stop, deliberately ------------------------------------ #
            # No Enter, no Connect click, no OTP/cert.  The user reads what was
            # filled and clicks Connect themselves.
            tr.ok("vpn.autofill", event="autofill-success",
                  login_entered=state["login"], password_entered=state["password"],
                  submitted=False)
            return AutofillResult(
                provider_id=pid, success=True, status=AutofillStatus.DONE,
                login_entered=state["login"], password_entered=state["password"],
                metadata={"requires_user_action": True, "submitted": False})
        except Exception as exc:                       # a seam misbehaved
            tr.fail("vpn.autofill", event="autofill-failure",
                    error_code="automation-failed", reason=type(exc).__name__)
            return AutofillResult(
                provider_id=pid, success=False, status=AutofillStatus.FAILED,
                login_entered=state["login"], password_entered=state["password"],
                error_code=ErrorCode.AUTOMATION_FAILED.value,
                metadata={"reason_code": type(exc).__name__})


def _stop(pid: str, state: dict, tr: _Trace, blocked_at: str,
          reason: str) -> AutofillResult:
    """A guard refused, the owner check refused, or the caller cancelled.

    Cancellation is not a security block, so it carries its own status/code.
    """
    if reason == REASON_CANCELLED:
        tr.ok("vpn.autofill", event="autofill-cancelled", blocked_at=blocked_at)
        return AutofillResult(
            provider_id=pid, success=False, status=AutofillStatus.CANCELLED,
            login_entered=state["login"], password_entered=state["password"],
            blocked_at=blocked_at, error_code=ErrorCode.CANCELLED.value,
            metadata={"reason_code": REASON_CANCELLED})
    tr.fail("vpn.autofill", event="secret-input-blocked", blocked_at=blocked_at,
            reason=reason, error_code=ErrorCode.SECRET_INPUT_BLOCKED.value)
    return AutofillResult(
        provider_id=pid, success=False, status=AutofillStatus.BLOCKED,
        login_entered=state["login"], password_entered=state["password"],
        blocked_at=blocked_at, error_code=ErrorCode.SECRET_INPUT_BLOCKED.value,
        metadata={"reason_code": reason})
