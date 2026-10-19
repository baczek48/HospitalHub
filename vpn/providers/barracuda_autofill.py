"""Barracuda autofill — login + password into the WPF client, by AutomationId.

The Barracuda Network Access Client login window is **WPF**
(``HwndWrapper[nacvpn.exe;;<guid>]``) with zero native child controls, so
``WM_SETTEXT`` has nothing to write to.  What the window *does* expose is a
stable UI Automation tree (measured live, Stage 50B/50C):

======================  =======================  ==========================
field                   ``AutomationId``         handled here
======================  =======================  ==========================
User Name               ``TextBoxUser``          yes  — login
User Password           ``PasswordBoxUser``      yes  — password
OTP (hidden until MFA)  ``PasswordBoxOTP``       **no** — a separate contract
Certificate password    ``PasswordBoxCert``      **no**
profile combo ("MCX")   (none)                   **no** — already selected
======================  =======================  ==========================

2026-10-20 (owner's laptop): the client showed its "Default" profile — a
certificate form with no User Name — while the card was "MCX".  The card's
profile is now chosen in the client's list first (by the text of the item,
exactly; :meth:`UiaValueSystem.select_list_item`) and confirmed, and only
then is anything typed.

2026-10-19 (owner's field test): each field is focused by its AutomationId,
the focus confirmed, and the value typed (:mod:`vpn.providers.field_fill`);
then Enter in the password field submits — what the legacy's keystrokes did,
without its click at 40 % of the window height.  A profile with a second factor
is filled and left for the person to finish.

Security — identical guarantees to the other providers
------------------------------------------------------
Every step runs inside :meth:`VerifiedWindow.run_guarded`, which re-confirms
that the pinned window is owned by the trusted process, is in front and is not
minimised; the focus call additionally refuses any element not owned by that
process.  Cancellation is checked before every field.
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
        cancellation=None, trace=None, input_system=None) -> AutofillResult:
    """Fill User Name and User Password, then press Enter in the password —
    unless the profile has a second factor, which the person types first.

    2026-10-19: focus by AutomationId + typing (:mod:`field_fill`) instead of
    ``SetValue`` — the same mechanism as Stormshield, and what the legacy's
    keystrokes amounted to, without its click at 40 % of the window height.
    The submit restores what the legacy did (Enter), which the owner relies on.
    """
    from .field_fill import Field, fill_form
    from .input_system import Win32InputSystem

    uia = uia if uia is not None else Win32UiaValueSystem()
    keys = input_system if input_system is not None else Win32InputSystem()
    target = target if target is not None else provider.secure_window_target()
    fields = (Field(PHASE_LOGIN, AID_USER, request.login or "", "login"),
              Field(PHASE_PASSWORD, AID_PASSWORD, request.password or "", "password"))
    second_factor = bool(request.requires_2fa or request.token)
    profile = (request.profile_name or "").strip()
    return fill_form(provider.id, target, uia, keys, fields,
                     submit_field=None if second_factor or not request.password
                     else AID_PASSWORD,
                     cancellation=cancellation, trace=trace,
                     select_profile=profile or None)
