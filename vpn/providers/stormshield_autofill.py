"""Stormshield autofill — three fields, each focused by identity, never submitted.

The shape is FortiClient's: acquire a verified window, then put every single
operation through :meth:`VerifiedWindow.run_guarded`, which re-reads the
desktop before it runs anything.

2026-10-19 — why the Shift+Tab sequence is gone
-----------------------------------------------
Stage 40 measured the cursor starting on **Password** and walked backwards from
there.  On the live client today it started on **Firewall address**: the
password was typed into the address field, in plain text, on screen.  Counting
keys from wherever the cursor happens to be cannot be made safe.  The form's
fields carry AutomationIds (Qt's ``objectName``: ``Connexion.addressEdit``,
``Connexion.loginEdit``, ``Connexion.passwordEdit``), so each field is now
focused by identity through UI Automation, the focus is confirmed, and only
then is anything typed (:mod:`vpn.providers.field_fill`).  Typing rather than
``SetValue``: with ``SetValue`` the values arrived but Qt kept "Log in"
disabled.  The OTP field that MFA adds is never touched.

Why nothing is submitted
------------------------
The legacy does not press Enter here and neither does this: the user clicks
**Log in** themselves.  ``AutofillStatus.DONE`` with ``requires_user_action``
in the metadata says the fields are filled and the connection has not been
attempted.

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


#: AutomationIds of the form, read from the live client's UI Automation tree
#: (Qt exposes ``objectName``) on 2026-10-19.
AID_ADDRESS = "Connexion.addressEdit"
AID_LOGIN = "Connexion.loginEdit"
AID_PASSWORD = "Connexion.passwordEdit"


def autofill_login_password(
        provider, request: VpnRequest, *,
        target: SecureWindowTarget | None = None,
        input_system: InputSystem | None = None,
        trace=None, uia=None, cancellation=None) -> AutofillResult:
    """Fill Firewall address, Login and Password, each by its AutomationId,
    and stop (the person clicks Log in, as with the legacy).

    2026-10-19: the Shift+Tab sequence below this module's history assumed the
    cursor started in Password; on the live client it started in Firewall
    address and the password was typed there, in plain text.  Now every field
    is focused by identity and confirmed before a single key is sent.
    """
    from .field_fill import Field, fill_form
    from .uia_value_system import Win32UiaValueSystem

    keys = input_system if input_system is not None else Win32InputSystem()
    uia = uia if uia is not None else Win32UiaValueSystem()
    target = target if target is not None else provider.secure_window_target()
    fields = (Field(PHASE_ADDRESS, AID_ADDRESS, server_address(request)),
              Field(PHASE_LOGIN, AID_LOGIN, request.login or "", "login"),
              Field(PHASE_PASSWORD, AID_PASSWORD, request.password or "", "password"))
    return fill_form(provider.id, target, uia, keys, fields, submit_field=None,
                     cancellation=cancellation, trace=trace)


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
