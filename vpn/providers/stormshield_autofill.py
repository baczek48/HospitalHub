"""Stormshield autofill — three fields, entered backwards, never submitted.

The shape is FortiClient's: acquire a verified window, then put every single
operation through :meth:`VerifiedWindow.run_guarded`, which re-reads the
desktop before it runs anything.  The *sequence* is nothing like FortiClient's,
and copying it would have been wrong in two separate ways.

Why backwards
-------------
Stage 40 measured the real client.  The cursor starts on **Password**, and two
``Shift+Tab`` presses walk back through **Login** to **Firewall address** —
confirmed three ways: by probing the live form, by the screenshots of it, and
by the legacy's own comment.  Walking *forward* was measured and did **not**
reproduce the reverse order, so this module never tabs forward.

That choice has a second benefit, which is the real reason to prefer it.  The
client grows an **OTP** field when "Use multifactor authentication" is ticked,
and it appears *after* Password.  Anything tabbing forward from the address
field lands one field off as soon as a user enables MFA; walking backwards from
Password is identical in both layouts.  The legacy sequence has this bug.

Why nothing is submitted
------------------------
The legacy does not press Enter here and neither does this: the user clicks
**Log in** themselves.  That is not a failure and is not reported as one —
``AutofillStatus.DONE`` with ``requires_user_action`` in the metadata says the
fields are filled and the connection has not been attempted.

Not here on purpose
-------------------
No OTP automation: the field exists, but filling a second factor is a separate
decision with its own contract, and a capability is not declared because a
screenshot has a text box in it.  No Enter, no click, no window being raised,
restored or activated — by the time this module runs, the user has already put
the client in front, and the guards check that they still have.
"""

from __future__ import annotations

from ..types import AutofillResult, AutofillStatus, ErrorCode, VpnRequest
from .input_system import (
    VK_CONTROL, VK_SHIFT, VK_TAB, InputSystem, Win32InputSystem,
)
from .secure_target import SecureWindowTarget, VerifiedWindow

__all__ = ["autofill_login_password", "PHASES", "PHASE_PASSWORD",
           "PHASE_TO_LOGIN", "PHASE_LOGIN", "PHASE_TO_ADDRESS",
           "PHASE_ADDRESS"]

#: Long enough for a Qt form to settle after the window is activated.  The
#: legacy waits 1.5 s here; the same number, for the same reason.
_RENDER_WAIT_S = 1.5
_AFTER_TYPE_S = 0.15
_AFTER_TAB_S = 0.25
_SELECT_ALL_S = 0.05

PHASE_PASSWORD = "password-type"
PHASE_TO_LOGIN = "shift-tab-to-login"
PHASE_LOGIN = "login-type"
PHASE_TO_ADDRESS = "shift-tab-to-address"
PHASE_ADDRESS = "address-type"

#: In order.  Two of them carry a credential; all five are guarded, because
#: every one of them types into a window this process does not own.
PHASES = (PHASE_PASSWORD, PHASE_TO_LOGIN, PHASE_LOGIN, PHASE_TO_ADDRESS,
          PHASE_ADDRESS)

#: Reasons that mean "no trusted window", as opposed to "found one, could not
#: use it".  Same split as the FortiClient autofill so a caller can tell a
#: retryable situation from a refusal.
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


def server_address(request: VpnRequest) -> str:
    """``host:port`` when a port is configured, else the host alone."""
    server = (request.server or "").strip()
    port = str(request.port or "").strip()
    return f"{server}:{port}" if server and port else server


def autofill_login_password(
        provider, request: VpnRequest, *,
        target: SecureWindowTarget | None = None,
        input_system: InputSystem | None = None,
        trace=None) -> AutofillResult:
    """Fill the Stormshield form, backwards from Password, and stop.

    `target` defaults to the provider's :meth:`secure_window_target`, which is
    configured ``require_visible=True, raise_window=False`` — so the window has
    to be in front and visible already, and nothing here will put it there.
    """
    tr = _Trace(trace)
    inp = input_system if input_system is not None else Win32InputSystem()
    target = target if target is not None else provider.secure_window_target()
    pid = provider.id
    login, password = request.login, request.password
    address = server_address(request)

    tr.ok("vpn.autofill", event="autofill-start", automation_mode="tab_sequence")

    acquired = target.acquire_any()
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

    def guard(win: VerifiedWindow, phase: str, operation) -> tuple[bool, str]:
        """Re-confirm the target, then run the operation — or run nothing.

        The secret lives in the closure and never passes through the guard's
        own signature; what the guard decides is only *whether* to call it.
        """
        result = win.run_guarded(phase, operation)
        return result.performed, result.reason

    with acquired as win:
        try:
            # --- Password: where the cursor already is (Stage 40) ---------- #
            # No Ctrl+A first: the field was measured empty, and selecting all
            # in a password box would be a keystroke that buys nothing.
            def enter_password():
                inp.sleep(_RENDER_WAIT_S)
                if password:
                    inp.type_text(password)
                    inp.sleep(_AFTER_TYPE_S)

            performed, reason = guard(win, PHASE_PASSWORD, enter_password)
            if not performed:
                return _stop(pid, state, tr, PHASE_PASSWORD, reason)
            if password:
                state["password"] = True
                tr.ok("vpn.autofill", event="password-step", field="password",
                      method="type", entered=True)

            # --- back to Login --------------------------------------------- #
            performed, reason = guard(win, PHASE_TO_LOGIN, lambda: (
                inp.press_combo(VK_SHIFT, VK_TAB), inp.sleep(_AFTER_TAB_S)))
            if not performed:
                return _stop(pid, state, tr, PHASE_TO_LOGIN, reason)

            def enter_login():
                inp.press_combo(VK_CONTROL, ord("A"))
                inp.sleep(_SELECT_ALL_S)
                inp.type_text(login)
                inp.sleep(_AFTER_TYPE_S)

            if login:
                performed, reason = guard(win, PHASE_LOGIN, enter_login)
                if not performed:
                    return _stop(pid, state, tr, PHASE_LOGIN, reason)
                state["login"] = True
                tr.ok("vpn.autofill", event="login-step", field="username",
                      method="type", entered=True)

            # --- back to Firewall address ---------------------------------- #
            performed, reason = guard(win, PHASE_TO_ADDRESS, lambda: (
                inp.press_combo(VK_SHIFT, VK_TAB), inp.sleep(_AFTER_TAB_S)))
            if not performed:
                return _stop(pid, state, tr, PHASE_TO_ADDRESS, reason)

            def enter_address():
                inp.press_combo(VK_CONTROL, ord("A"))
                inp.sleep(_SELECT_ALL_S)
                inp.type_text(address)
                inp.sleep(_AFTER_TYPE_S)

            if address:
                performed, reason = guard(win, PHASE_ADDRESS, enter_address)
                if not performed:
                    return _stop(pid, state, tr, PHASE_ADDRESS, reason)
                tr.ok("vpn.autofill", event="address-step", field="server",
                      method="type", entered=True)

            # --- and stop, deliberately ------------------------------------ #
            # No Enter.  The user reads what was filled in and clicks Log in.
            tr.ok("vpn.autofill", event="autofill-success",
                  login_entered=state["login"],
                  password_entered=state["password"], submitted=False)
            return AutofillResult(
                provider_id=pid, success=True, status=AutofillStatus.DONE,
                login_entered=state["login"],
                password_entered=state["password"],
                metadata={"requires_user_action": True, "submitted": False})
        except Exception as exc:                       # a seam misbehaved
            tr.fail("vpn.autofill", event="autofill-failure",
                    error_code="automation-failed", reason=type(exc).__name__)
            return AutofillResult(
                provider_id=pid, success=False, status=AutofillStatus.FAILED,
                login_entered=state["login"],
                password_entered=state["password"],
                error_code=ErrorCode.AUTOMATION_FAILED.value,
                metadata={"reason_code": type(exc).__name__})


def _stop(pid: str, state: dict, tr: _Trace, blocked_at: str,
          reason: str) -> AutofillResult:
    """A guard refused: report where, and never what was being carried."""
    tr.fail("vpn.autofill", event="secret-input-blocked", blocked_at=blocked_at,
            reason=reason, error_code=ErrorCode.SECRET_INPUT_BLOCKED.value)
    return AutofillResult(
        provider_id=pid, success=False, status=AutofillStatus.BLOCKED,
        login_entered=state["login"], password_entered=state["password"],
        blocked_at=blocked_at, error_code=ErrorCode.SECRET_INPUT_BLOCKED.value,
        metadata={"reason_code": reason})
