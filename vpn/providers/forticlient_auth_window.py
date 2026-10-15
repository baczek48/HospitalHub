"""FortiClient EMS authentication window — login + password, behind the guards.

Stage 48.  The migrated counterpart of legacy ``_fill_forti_auth_window``
(vpn_connect.py), the one route Stage 15 left behind on purpose: it moved the
*token* out of this window (``forticlient_2fa.submit_token_to_window``) and
recorded the *credentials* fill as "not migrated" so a second, unreviewed path
to a password would not be invented under time pressure.  This is that path,
built now on exactly the infrastructure the token path already uses.

Which window is this
--------------------
There is only one FortiClient authentication window, and both secrets go to the
same one — the EMS/ZTNA edition's WinForms dialog whose title carries both
"FortiClient" and "Authentication".  It is *not* the main FortiClient GUI (that
is Electron, has no native controls, and is filled by keystrokes —
``forticlient_autofill``).  The difference between the two secrets is only
*which edit control*:

* **credentials** (here): ``edits[0]`` = login, ``edits[1]`` = password, and
  a window needs at least two edit controls to be one — the legacy
  ``len(edits) >= 2`` / ``< 2`` test.
* **token** (``forticlient_2fa``): ``edits[-1]`` = token, and a window needs at
  least three, or it is the credentials window, not the token one.

So this module and the 2FA one share the *locating and verifying* of the
window — :func:`~vpn.providers.forticlient_2fa._locate_auth_window`, the same
title candidates, owner verification and control enumeration — and differ only
in which fields they write.  Nothing is duplicated.

Security — identical to the token path (Stage 15)
-------------------------------------------------
* The window is located through :class:`SecureWindowTarget` (HWND → PID →
  process image inside a trusted FortiClient directory); this module never
  accepts a raw handle from its caller.
* Focus is acquired (``require_visible`` on the target refuses a minimised
  window), then **every** ``WM_SETTEXT`` runs inside
  :meth:`VerifiedWindow.run_guarded` with the login field, the password field
  and every button listed as the operation's controls — so foreground, owner
  and per-control ownership are re-confirmed in the same breath as each send.
* Fail-closed: any doubt and the next secret is not sent, Connect is not
  pressed, and the result says where it stopped.  Login is sent before
  password, so a target lost between them leaves the password in this process.
* Cancellation is honoured before **every** send — before the login, between
  the login and the password, and before Connect — through the same
  :class:`CancellationToken` the activation gate and the keystroke autofill use.

No clipboard.  ``WM_SETTEXT`` delivers the value straight to the control, so
unlike the keystroke autofill this path never touches the clipboard and has
nothing to restore.  The secrets live only in the guard callbacks' closures and
never reach a guard argument, a result, a trace or an exception.
"""

from __future__ import annotations

from ..types import ErrorCode
from .forticlient_2fa import _UNTRUSTED_REASONS, _locate_auth_window
from .secure_target import SecureWindowTarget, VerifiedWindow
from .window_message_system import (
    BUTTON, EDIT, Win32WindowMessageSystem, WindowMessageSystem,
    is_connect_button,
)

__all__ = ["submit_credentials_to_window", "AuthWindowFillResult",
           "MIN_CREDENTIAL_EDITS", "AUTH_WINDOW_CREDENTIAL_TIMEOUT_S", "PHASES",
           "REASON_CANCELLED"]

#: ``_find_forti_auth_window`` returns the window only with two or more edit
#: controls; ``_fill_forti_auth_window`` refuses below that (``len(edits) < 2``).
MIN_CREDENTIAL_EDITS = 2

#: ``_fill_forti_auth_window(..., timeout=3.0)`` — the credentials call's own
#: poll budget, distinct from the token call's 15 s.  The connect flow overrides
#: it with the fast ``AUTH_WINDOW_TIMEOUT_S`` (0.1 s) instant check.
AUTH_WINDOW_CREDENTIAL_TIMEOUT_S = 3.0

#: Reason a guard reports when the caller called the fill off (Stage 47/48).
REASON_CANCELLED = "cancelled"

# Phases — the value of ``AuthWindowFillResult.blocked_at``.
PHASE_LOCATE = "locate"
PHASE_ACQUIRE = "acquire"
PHASE_CONTROLS = "controls"
PHASE_LOGIN = "login"
PHASE_PASSWORD = "password"
PHASE_CONNECT_CLICK = "connect-click"
PHASES = (PHASE_LOCATE, PHASE_ACQUIRE, PHASE_CONTROLS, PHASE_LOGIN,
          PHASE_PASSWORD, PHASE_CONNECT_CLICK)


class _Trace:
    """Null-safe wrapper: the caller may pass a diagnostics trace or None."""

    def __init__(self, trace):
        self._t = trace

    def ok(self, name, **data):
        if self._t is not None:
            self._t.ok(name, **data)

    def fail(self, name, **data):
        if self._t is not None:
            self._t.fail(name, **data)


class AuthWindowFillResult:
    """What filling the EMS credentials window achieved.  Codes, never secrets.

    Deliberately richer than the legacy ``(ok, message)`` and than the flow's
    :class:`~vpn.providers.forticlient_connect.AuthWindowFill`, so the runtime
    can translate one into the other and lose nothing on the way:

    * ``located`` — a verified credentials window was found at all;
    * ``login_sent`` / ``password_sent`` — whether each field received its value
      (so the flow knows a mid-fill stop is not "no window");
    * ``submitted`` — Connect was pressed for the user;
    * ``blocked`` — a guard refused; ``cancelled`` — the caller called it off;
    * ``blocked_at`` / ``error_code`` / ``reason`` — where and why it stopped.
    """

    __slots__ = ("located", "login_sent", "password_sent", "submitted",
                 "manual_submit_required", "blocked", "cancelled",
                 "blocked_at", "error_code", "reason")

    def __init__(self, *, located=False, login_sent=False, password_sent=False,
                 submitted=False, manual_submit_required=False, blocked=False,
                 cancelled=False, blocked_at=None, error_code=None, reason=None):
        self.located = located
        self.login_sent = login_sent
        self.password_sent = password_sent
        self.submitted = submitted
        self.manual_submit_required = manual_submit_required
        self.blocked = blocked
        self.cancelled = cancelled
        self.blocked_at = blocked_at
        self.error_code = error_code
        self.reason = reason

    @property
    def ok(self) -> bool:
        """Both fields entered and nothing refused — Connect may or may not have
        been pressed (that carries no secret)."""
        return (self.login_sent and self.password_sent
                and not self.blocked and not self.cancelled)

    @property
    def any_secret_sent(self) -> bool:
        return self.login_sent or self.password_sent

    def __repr__(self) -> str:      # never a secret
        return (f"<AuthWindowFillResult located={self.located} "
                f"login_sent={self.login_sent} password_sent={self.password_sent} "
                f"submitted={self.submitted} blocked={self.blocked} "
                f"cancelled={self.cancelled} at={self.blocked_at!r}>")


def submit_credentials_to_window(
        provider, request, *,
        target: SecureWindowTarget | None = None,
        message_system: WindowMessageSystem | None = None,
        api=None, cancellation=None,
        timeout: float = AUTH_WINDOW_CREDENTIAL_TIMEOUT_S,
        trace=None) -> AuthWindowFillResult:
    """Put login and password into the EMS authentication window, press Connect.

    `target` defaults to the provider's :meth:`auth_window_target`,
    `message_system` to the real Win32 one; both are injected in tests.  The
    caller never passes a window handle — locating the window is this function's
    job precisely so that it goes through the verified contract.
    """
    tr = _Trace(trace)
    msg = (message_system if message_system is not None
           else Win32WindowMessageSystem())
    target = (target if target is not None
              else provider.auth_credentials_target(api=api))
    login, password = request.login, request.password

    def cancelled() -> bool:
        return cancellation is not None and bool(cancellation.cancelled)

    tr.ok("vpn.auth_window", event="credentials-fill-start",
          automation_mode="wm_settext")

    # Called off before anything is located: nothing runs.
    if cancelled():
        tr.ok("vpn.auth_window", event="credentials-cancelled", blocked_at=PHASE_LOCATE)
        return AuthWindowFillResult(cancelled=True, blocked_at=PHASE_LOCATE,
                                    error_code=ErrorCode.CANCELLED.value,
                                    reason=REASON_CANCELLED)

    try:
        located = _locate_auth_window(target, msg, timeout)
    except Exception as exc:
        tr.fail("vpn.auth_window", event="credentials-fill-failure",
                blocked_at=PHASE_LOCATE, reason=type(exc).__name__,
                error_code=ErrorCode.OTP_WINDOW_NOT_FOUND.value)
        return AuthWindowFillResult(blocked_at=PHASE_LOCATE,
                                    error_code=ErrorCode.AUTOMATION_FAILED.value,
                                    reason=type(exc).__name__)
    if located is None:
        # No verified credentials window on screen: the flow falls through to
        # the other routes, exactly as the legacy does on a (False, "").
        tr.ok("vpn.auth_window", event="credentials-window-not-found")
        return AuthWindowFillResult(located=False)

    hwnd, controls = located
    edits = [c for c in controls if c.kind == EDIT]
    buttons = [c for c in controls if c.kind == BUTTON]
    if len(edits) < MIN_CREDENTIAL_EDITS:
        # Fewer than two fields: not the credentials window.  Treated as "not
        # this route" so the flow moves on — the legacy returns (False, "").
        tr.ok("vpn.auth_window", event="credentials-window-not-found",
              control_count=len(edits))
        return AuthWindowFillResult(located=False, reason="too-few-edit-controls")

    tr.ok("vpn.auth_window", event="EMS-credentials-window-found",
          control_count=len(edits))

    acquired = target.acquire(hwnd)
    if not isinstance(acquired, VerifiedWindow):
        reason = getattr(acquired, "reason", "no-verified-target")
        untrusted = reason in _UNTRUSTED_REASONS
        code = (ErrorCode.TARGET_WINDOW_UNTRUSTED if untrusted
                else ErrorCode.FOCUS_FAILED)
        tr.fail("vpn.auth_window", event="credentials-blocked",
                blocked_at=PHASE_ACQUIRE, reason=reason, error_code=code.value)
        # Nothing was sent, so the flow may still try the other routes.
        return AuthWindowFillResult(located=False, blocked=True,
                                    blocked_at=PHASE_ACQUIRE,
                                    error_code=code.value, reason=reason)

    login_field, password_field = edits[0], edits[1]
    guarded = [login_field.hwnd, password_field.hwnd] + [b.hwnd for b in buttons]

    with acquired as win:
        try:
            # Legacy rule, kept: one foreign Edit/Button anywhere condemns the
            # whole window, not just that control.
            owned = win.controls_owned([c.hwnd for c in controls])
            if not owned.ok:
                tr.fail("vpn.auth_window", event="credentials-blocked",
                        blocked_at=PHASE_CONTROLS, reason=owned.reason,
                        error_code=ErrorCode.SECRET_INPUT_BLOCKED.value)
                return AuthWindowFillResult(
                    located=False, blocked=True, blocked_at=PHASE_CONTROLS,
                    error_code=ErrorCode.SECRET_INPUT_BLOCKED.value,
                    reason=owned.reason)

            tr.ok("vpn.auth_window", event="EMS-credentials-verified",
                  image_name=win.image_name, pid=win.pid)

            # --- login ------------------------------------------------------ #
            if cancelled():
                return _cancel(tr, PHASE_LOGIN, located=True)
            sent = win.run_guarded(
                PHASE_LOGIN,
                lambda: msg.set_control_text(login_field.hwnd, login),
                controls=guarded)
            if not sent.performed:
                return _blocked(tr, PHASE_LOGIN, sent.reason, located=True)
            tr.ok("vpn.auth_window", event="credentials-login-sent",
                  field="username", method="wm_settext", entered=True)

            # --- password (login already went out; a stop now keeps it home) - #
            if cancelled():
                return _cancel(tr, PHASE_PASSWORD, located=True, login_sent=True)
            sent = win.run_guarded(
                PHASE_PASSWORD,
                lambda: msg.set_control_text(password_field.hwnd, password),
                controls=guarded)
            if not sent.performed:
                return _blocked(tr, PHASE_PASSWORD, sent.reason, located=True,
                                login_sent=True)
            tr.ok("vpn.auth_window", event="credentials-password-sent",
                  field="password", method="wm_settext", entered=True)

            # --- Connect (carries no secret) -------------------------------- #
            button = next((b for b in buttons if is_connect_button(b.text)), None)
            if button is None:
                tr.ok("vpn.auth_window", event="manual-submit-required",
                      submitted=False,
                      error_code=ErrorCode.CONNECT_BUTTON_NOT_FOUND.value)
                return AuthWindowFillResult(
                    located=True, login_sent=True, password_sent=True,
                    manual_submit_required=True,
                    error_code=ErrorCode.CONNECT_BUTTON_NOT_FOUND.value)

            if cancelled():
                # Both fields are filled; the user asked us not to submit.
                return _cancel(tr, PHASE_CONNECT_CLICK, located=True,
                               login_sent=True, password_sent=True)

            clicked = win.run_guarded(PHASE_CONNECT_CLICK,
                                      lambda: msg.click_button(button.hwnd))
            if not clicked.performed:
                # The fields are in; only the click was refused.  Not a secret
                # failure — the user can press Connect themselves.
                tr.ok("vpn.auth_window", event="manual-submit-required",
                      submitted=False, reason=clicked.reason)
                return AuthWindowFillResult(
                    located=True, login_sent=True, password_sent=True,
                    manual_submit_required=True, reason=clicked.reason)

            tr.ok("vpn.auth_window", event="credentials-submitted",
                  method="bm_click", submitted=True)
            return AuthWindowFillResult(located=True, login_sent=True,
                                        password_sent=True, submitted=True)
        except Exception as exc:                       # a seam misbehaved
            tr.fail("vpn.auth_window", event="credentials-fill-failure",
                    blocked_at=PHASE_PASSWORD, reason=type(exc).__name__,
                    error_code=ErrorCode.AUTOMATION_FAILED.value)
            return AuthWindowFillResult(
                located=True, blocked=True, blocked_at=PHASE_PASSWORD,
                error_code=ErrorCode.AUTOMATION_FAILED.value,
                reason=type(exc).__name__)


def _blocked(tr, blocked_at, reason, *, located, login_sent=False
             ) -> AuthWindowFillResult:
    """A guard refused: no further secret, no Connect."""
    tr.fail("vpn.auth_window", event="credentials-blocked", blocked_at=blocked_at,
            reason=reason, error_code=ErrorCode.SECRET_INPUT_BLOCKED.value)
    return AuthWindowFillResult(
        located=located, login_sent=login_sent, blocked=True,
        blocked_at=blocked_at, error_code=ErrorCode.SECRET_INPUT_BLOCKED.value,
        reason=reason)


def _cancel(tr, blocked_at, *, located, login_sent=False, password_sent=False
            ) -> AuthWindowFillResult:
    """The caller called it off: no further secret, no Connect, no failure."""
    tr.ok("vpn.auth_window", event="credentials-cancelled", blocked_at=blocked_at)
    return AuthWindowFillResult(
        located=located, login_sent=login_sent, password_sent=password_sent,
        cancelled=True, blocked_at=blocked_at,
        error_code=ErrorCode.CANCELLED.value, reason=REASON_CANCELLED)
