"""FortiClient second factor — the token paths, migrated behind the guards.

What the legacy actually does (vpn_connect.py + the two UI panels), and what of
it lives here:

===========================  ==================================  ============
legacy                       mechanism                           migrated here
===========================  ==================================  ============
``fill_forticlient_token``   EMS auth window, ``WM_SETTEXT`` +   yes
                             ``BM_CLICK`` on Connect
``is_2fa_prompt`` +          monitored CLI: stdout asks, the     yes
``VpnMonitorWorker``         token goes to stdin
``connect_monitored(token)`` ``FortiVPN.exe --token <value>``    no — that is
                                                                 a launch
                                                                 argument
``requires_2fa`` + autofill  the user types it into the client   yes (as a
off                                                               refusal)
===========================  ==================================  ============

Two things the legacy has that are *not* 2FA and are not here: the tab-sequence
autofill (login + password only — it never types a token, Stage 14) and the EMS
credential fill ``_fill_forti_auth_window`` (same window, but login + password,
and part of connect).

Security
--------
A token is a credential and is treated exactly like the password in Stage 14.

* **Window path** — the window is located through
  :class:`~vpn.providers.secure_target.SecureWindowTarget` (HWND → PID →
  process image inside a trusted FortiClient directory), focus is taken, and
  the ``WM_SETTEXT`` runs inside :meth:`VerifiedWindow.run_guarded` with the
  target control *and* every button listed, so foreground, owner and control
  ownership are all re-confirmed in the instruction before the send.  There is
  no path from a bare HWND to a ``WM_SETTEXT``: this module never accepts a
  window handle from its caller.
* **Process path** — before a token is written to a pipe, the process on the
  other end must be a FortiClient executable from a trusted install directory.

Fail-closed everywhere: any doubt and the token is not sent, Connect is not
pressed, and the result says where it stopped.  The token lives only in the
callback closures; it never reaches a guard, a result, a trace or an exception.

Deliberate differences from the legacy (see :data:`TWO_FACTOR_CAVEATS`)
----------------------------------------------------------------------
The legacy fills the token field without taking focus — ``WM_SETTEXT`` does not
need it — and never checks which process owns the pipe it writes to.  Both are
tightened here because Stage 15 requires a confirmed foreground and a verified
target before every secret.  The cost is that this path can refuse in a
situation where the legacy would have typed; nothing else changes, and nothing
here runs in production.
"""

from __future__ import annotations

import re

from secure_window import Win32WindowApi, WindowApi, is_inside

from ..types import (
    ErrorCode, TwoFactorMode, TwoFactorResult, TwoFactorStatus, VpnRequest,
)
from .secure_target import SecureWindowTarget, VerifiedWindow
from .window_message_system import (
    BUTTON, EDIT, Win32WindowMessageSystem, WindowMessageSystem,
    is_connect_button,
)

__all__ = [
    "supply_token", "submit_token_to_window", "submit_token_to_process",
    "two_factor_mode", "is_two_factor_prompt", "watch_for_challenge",
    "ChallengeWatch", "TOKEN_WINDOW_TIMEOUT_S", "MIN_TOKEN_EDITS",
    "TWO_FACTOR_CAVEATS", "PHASES",
]

#: ``fill_forticlient_token(timeout=15.0)`` and the 0.5 s poll of
#: ``_find_forti_auth_window``.  Unchanged.
TOKEN_WINDOW_TIMEOUT_S = 15.0
WINDOW_POLL_INTERVAL_S = 0.5

#: The legacy reads the token field as ``edits[-1]`` and demands at least three
#: edit controls (username, password, token); with two it is the credentials
#: window, not the token one.
MIN_TOKEN_EDITS = 3

#: How many lines of a monitored process' stdout are read while waiting for a
#: challenge before giving up.  The legacy worker reads until the process ends;
#: a bound is needed here because nothing else stops the loop.
MAX_CHALLENGE_LINES = 2000

# Phases — the value of ``TwoFactorResult.blocked_at``.
PHASE_LOCATE = "locate"
PHASE_ACQUIRE = "acquire"
PHASE_CONTROLS = "controls"
PHASE_SUBMIT = "submit"
PHASE_CONNECT_CLICK = "connect-click"
PHASE_PROCESS = "process"
PHASES = (PHASE_LOCATE, PHASE_ACQUIRE, PHASE_CONTROLS, PHASE_SUBMIT,
          PHASE_CONNECT_CLICK, PHASE_PROCESS)

#: Reasons :meth:`SecureWindowTarget.acquire` gives when the window itself is
#: wrong, as opposed to focus not being obtainable.
_UNTRUSTED_REASONS = ("no-verified-target", "no-window", "no-process",
                      "image-unavailable", "untrusted-image",
                      "control-not-owned-by-target")

#: Differences from the legacy, recorded rather than argued about; the tests
#: pin them so they cannot drift into production unnoticed.
TWO_FACTOR_CAVEATS: tuple[tuple[str, str], ...] = (
    ("window-focus-required",
     "legacy wpisuje token przez WM_SETTEXT bez fokusu (WM_SETTEXT go nie "
     "wymaga); tutaj okno musi być na wierzchu i potwierdzone przed wysyłką — "
     "ta ścieżka może odmówić tam, gdzie legacy wpisywał"),
    ("process-image-verified",
     "legacy pisze token na stdin procesu, który dostał z UI, bez sprawdzenia "
     "czyj to proces; tutaj obraz procesu musi leżeć w zaufanym katalogu "
     "FortiClienta"),
    ("no-token-acceptance-signal",
     "ani legacy, ani ta warstwa nie dowiadują się, czy token został przyjęty "
     "— sukces znaczy 'przekazano'; dlatego TwoFactorStatus.REJECTED jest "
     "zarezerwowany i nie jest dziś zwracany przez żadną ścieżkę"),
    ("stdout-line-not-kept",
     "legacy przekazuje linię stdout do UI tylko jako sygnał; tutaj linia jest "
     "klasyfikowana i porzucana — klient potrafi wypisać w niej dane, którymi "
     "go uruchomiono"),
    ("cli-token-is-a-launch-argument",
     "connect_monitored(--token) podaje token w wierszu poleceń przy starcie "
     "procesu; to należy do launch/connect, nie do tej warstwy (i oba panele "
     "UI przekazują pusty token — LEGACY_BEHAVIOR 'token-never-passed')"),
    ("write-errors-surface",
     "legacy VpnMonitorWorker.send_token połyka wyjątek zapisu na stdin i UI "
     "myśli, że token poszedł; tutaj to wynik FAILED"),
)

# The legacy prompt vocabulary (vpn_connect.py:76).  Copied, not imported:
# ``vpn/`` must not depend on the legacy module.  A test asserts the two
# patterns stay character-for-character identical.
_2FA_PATTERNS = re.compile(
    r"(enter.*token|enter.*code|two.?factor|2fa|otp|one.?time|"
    r"authentication code|verification code|token:|passcode|"
    r"sms.*code|email.*code|push.*notification|approve.*request)",
    re.IGNORECASE,
)


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


# --------------------------------------------------------------------------- #
# Planning                                                                     #
# --------------------------------------------------------------------------- #

def two_factor_mode(request: VpnRequest, *, route: str | None = None,
                    monitor_available: bool = False,
                    trace=None) -> TwoFactorMode:
    """How a second factor could be supplied after this connect.

    Thin wrapper over the Stage-11 :func:`plan_two_factor` so that callers of
    this module do not need both; the decision itself is not restated here.

    The four modes cover every path the application has.  ``--token`` on the
    CLI is not a fifth: it hands the token over at process start, and the
    monitor is still armed afterwards (the legacy says so explicitly —
    "in case the provider ignores --token and still prompts via stdout"), so
    that connect is ``PROCESS_STDOUT`` like any other monitored one.
    """
    from .forticlient_connect import plan_two_factor

    mode = plan_two_factor(route=route, monitor_available=monitor_available,
                           autofill=bool(request.autofill),
                           requires_2fa=bool(request.requires_2fa))
    _Trace(trace).ok("vpn.2fa", event="two-factor-mode", mode=mode.value)
    return mode


def supply_token(provider, request: VpnRequest, *,
                 mode: TwoFactorMode | None = None, channel=None,
                 target: SecureWindowTarget | None = None,
                 message_system: WindowMessageSystem | None = None,
                 api: WindowApi | None = None,
                 trace=None) -> TwoFactorResult:
    """One entry per connect: do whatever this connect's mode allows.

    `mode` defaults to :func:`two_factor_mode` for the request.  Two of the
    four modes are answers rather than actions, and that is the point — a
    connect must be able to *not* automate a second factor:

    * ``NONE`` — nothing to do (``NOT_REQUIRED``);
    * ``IN_CLIENT`` — the user authenticates in the client themselves
      (``MANUAL_REQUIRED``); nothing is sent, nothing is "repaired";
    * ``AUTH_WINDOW`` — :func:`submit_token_to_window`;
    * ``PROCESS_STDOUT`` — :func:`submit_token_to_process`, needing `channel`.
    """
    tr = _Trace(trace)
    resolved = mode if mode is not None else two_factor_mode(request, trace=trace)

    if resolved is TwoFactorMode.NONE:
        return _result(provider.id, TwoFactorStatus.NOT_REQUIRED, resolved)

    if resolved is TwoFactorMode.IN_CLIENT:
        tr.ok("vpn.2fa", event="manual-auth-required", mode=resolved.value,
              automation_mode="manual")
        return _result(provider.id, TwoFactorStatus.MANUAL_REQUIRED, resolved,
                       error_code=ErrorCode.MANUAL_ACTION_REQUIRED.value)

    if resolved is TwoFactorMode.PROCESS_STDOUT:
        if channel is None:
            tr.ok("vpn.2fa", event="manual-auth-required", mode=resolved.value)
            return _result(provider.id, TwoFactorStatus.MANUAL_REQUIRED, resolved,
                           error_code=ErrorCode.MANUAL_ACTION_REQUIRED.value,
                           reason="no-channel")
        return submit_token_to_process(provider, request, channel, api=api,
                                       trace=trace)

    return submit_token_to_window(provider, request, target=target,
                                  message_system=message_system, api=api,
                                  trace=trace)


# --------------------------------------------------------------------------- #
# EMS authentication window                                                    #
# --------------------------------------------------------------------------- #

def submit_token_to_window(
        provider, request: VpnRequest, *,
        target: SecureWindowTarget | None = None,
        message_system: WindowMessageSystem | None = None,
        api: WindowApi | None = None,
        timeout: float = TOKEN_WINDOW_TIMEOUT_S,
        trace=None) -> TwoFactorResult:
    """Put the token into the EMS authentication window and press Connect.

    `target` defaults to the provider's :meth:`auth_window_target`,
    `message_system` to the real Win32 one; both are injected in tests.  The
    caller never passes a window handle — locating the window is this
    function's job precisely so that it goes through the verified contract.
    """
    tr = _Trace(trace)
    pid = provider.id
    msg = message_system if message_system is not None else Win32WindowMessageSystem()
    target = (target if target is not None
              else provider.auth_window_target(api=api))
    token = request.token

    tr.ok("vpn.2fa", event="two-factor-detected", mode=TwoFactorMode.AUTH_WINDOW.value,
          field="token", automation_mode="wm_settext")

    if not token:
        # Nothing to send: the caller has to obtain one (the UI asks the user).
        tr.ok("vpn.2fa", event="manual-auth-required", reason="no-token",
              mode=TwoFactorMode.AUTH_WINDOW.value)
        return _result(pid, TwoFactorStatus.TOKEN_REQUIRED, TwoFactorMode.AUTH_WINDOW,
                       reason="no-token")

    try:
        located = _locate_auth_window(target, msg, timeout)
    except Exception as exc:
        return _failed(pid, tr, TwoFactorMode.AUTH_WINDOW, PHASE_LOCATE,
                       ErrorCode.OTP_WINDOW_NOT_FOUND, type(exc).__name__)
    if located is None:
        tr.fail("vpn.2fa", event="token-submit-failure", window_found=False,
                timeout_ms=int(timeout * 1000),
                error_code=ErrorCode.OTP_WINDOW_NOT_FOUND.value)
        return _result(pid, TwoFactorStatus.FAILED, TwoFactorMode.AUTH_WINDOW,
                       error_code=ErrorCode.OTP_WINDOW_NOT_FOUND.value,
                       blocked_at=PHASE_LOCATE, reason="no-window")

    hwnd, controls = located
    edits = [c for c in controls if c.kind == EDIT]
    buttons = [c for c in controls if c.kind == BUTTON]
    tr.ok("vpn.2fa", event="EMS-window-found", window_found=True,
          control_count=len(edits), timeout_ms=int(timeout * 1000))

    acquired = target.acquire(hwnd)
    if not isinstance(acquired, VerifiedWindow):
        reason = getattr(acquired, "reason", "no-verified-target")
        untrusted = reason in _UNTRUSTED_REASONS
        code = (ErrorCode.TARGET_WINDOW_UNTRUSTED if untrusted
                else ErrorCode.FOCUS_FAILED)
        tr.fail("vpn.2fa", event="token-submit-blocked", blocked_at=PHASE_ACQUIRE,
                reason=reason, error_code=code.value)
        return _result(pid, TwoFactorStatus.BLOCKED, TwoFactorMode.AUTH_WINDOW,
                       error_code=code.value, blocked_at=PHASE_ACQUIRE,
                       reason=reason)

    with acquired as win:
        try:
            # Legacy rule, kept: one foreign Edit/Button anywhere in the window
            # condemns the whole window, not just that control.
            owned = win.controls_owned([c.hwnd for c in controls])
            if not owned.ok:
                return _blocked(pid, tr, PHASE_CONTROLS, owned.reason)

            if len(edits) < MIN_TOKEN_EDITS:
                tr.fail("vpn.2fa", event="token-submit-failure",
                        control_count=len(edits),
                        error_code=ErrorCode.OTP_FIELD_NOT_FOUND.value)
                return _result(pid, TwoFactorStatus.FAILED,
                               TwoFactorMode.AUTH_WINDOW,
                               error_code=ErrorCode.OTP_FIELD_NOT_FOUND.value,
                               blocked_at=PHASE_CONTROLS,
                               reason="too-few-edit-controls")

            token_field = edits[-1]
            guarded = [token_field.hwnd] + [b.hwnd for b in buttons]
            tr.ok("vpn.2fa", event="EMS-target-verified",
                  image_name=win.image_name, pid=win.pid)
            tr.ok("vpn.2fa", event="token-submit-start", field="token",
                  method="wm_settext")

            sent = win.run_guarded(
                PHASE_SUBMIT,
                lambda: msg.set_control_text(token_field.hwnd, token),
                controls=guarded)
            if not sent.performed:
                return _blocked(pid, tr, PHASE_SUBMIT, sent.reason)

            tr.ok("vpn.2fa", event="token-submit-success", field="token",
                  method="wm_settext", entered=True)

            # Connect carries no secret (see the Stage-15 brief), so a refusal
            # here is not a security failure: the token is in, the user clicks.
            button = next((b for b in buttons if is_connect_button(b.text)), None)
            if button is None:
                tr.ok("vpn.2fa", event="manual-auth-required", submitted=False,
                      error_code=ErrorCode.CONNECT_BUTTON_NOT_FOUND.value)
                return _result(pid, TwoFactorStatus.SUBMITTED,
                               TwoFactorMode.AUTH_WINDOW, submitted=True,
                               manual_submit_required=True,
                               error_code=ErrorCode.CONNECT_BUTTON_NOT_FOUND.value)

            clicked = win.run_guarded(PHASE_CONNECT_CLICK,
                                      lambda: msg.click_button(button.hwnd))
            if not clicked.performed:
                tr.ok("vpn.2fa", event="manual-auth-required", submitted=False,
                      reason=clicked.reason)
                return _result(pid, TwoFactorStatus.SUBMITTED,
                               TwoFactorMode.AUTH_WINDOW, submitted=True,
                               manual_submit_required=True,
                               reason=clicked.reason)

            tr.ok("vpn.2fa", event="token-submit-success", phase="submit",
                  method="bm_click", submitted=True)
            return _result(pid, TwoFactorStatus.SUBMITTED,
                           TwoFactorMode.AUTH_WINDOW, submitted=True)
        except Exception as exc:                       # a seam misbehaved
            return _failed(pid, tr, TwoFactorMode.AUTH_WINDOW, PHASE_SUBMIT,
                           ErrorCode.AUTOMATION_FAILED, type(exc).__name__)


def _locate_auth_window(target: SecureWindowTarget, msg: WindowMessageSystem,
                        timeout: float):
    """Poll for a verified auth window; return ``(hwnd, controls)`` or None.

    Mirrors ``_find_forti_auth_window``: title candidates, owner verification,
    child enumeration, 0.5 s between rounds, and only windows with enough edit
    controls count as found.  Finding is not sending — nothing here can deliver
    a secret, which is why it may work on a plain handle.
    """
    attempts = max(1, round(timeout / WINDOW_POLL_INTERVAL_S))
    for attempt in range(attempts):
        found = target.first_verified_candidate()
        if found is not None:
            hwnd, _owner = found
            controls = list(msg.enumerate_controls(hwnd))
            if sum(1 for c in controls if c.kind == EDIT) >= 2:
                return hwnd, controls
        if attempt + 1 < attempts:
            msg.sleep(WINDOW_POLL_INTERVAL_S)
    return None


# --------------------------------------------------------------------------- #
# Monitored CLI process                                                        #
# --------------------------------------------------------------------------- #

def is_two_factor_prompt(line: str) -> bool:
    """Does this stdout line ask for a second factor?  (legacy ``is_2fa_prompt``)"""
    return bool(_2FA_PATTERNS.search(line or ""))


class ChallengeWatch:
    """Result of watching a process' stdout for a challenge.

    Carries no line content on purpose — only whether a challenge appeared and
    how far into the stream it was.
    """

    __slots__ = ("detected", "lines_read", "ended", "stopped")

    def __init__(self, detected: bool, lines_read: int, ended: bool,
                 stopped: bool = False):
        self.detected = detected
        self.lines_read = lines_read
        self.ended = ended        # the stream closed before a challenge
        self.stopped = stopped    # `should_stop` asked us to give up (Stage 50)

    def __repr__(self) -> str:    # never a line, never a token
        return (f"<ChallengeWatch detected={self.detected} "
                f"lines_read={self.lines_read} ended={self.ended} "
                f"stopped={self.stopped}>")


def watch_for_challenge(channel, *, max_lines: int = MAX_CHALLENGE_LINES,
                        should_stop=None, trace=None) -> ChallengeWatch:
    """Read stdout until it asks for a token, the stream ends, or the bound.

    The line that matched is classified and dropped — never returned, traced
    or logged: the client echoes its own command line on some editions, and
    that command line can contain the password it was started with.

    ``should_stop`` (Stage 50) is an optional predicate checked **before every
    read**, so a caller that has been cancelled can end the watch between lines
    without a token ever being asked for or answered.  It is a reading, not a
    write: it cannot cause anything to be sent.  A read already blocked in the
    OS is only unblocked by the process itself (a line, or EOF) — that limit is
    the pipe's, not this function's, and is documented for the CLI worker.
    """
    tr = _Trace(trace)
    read = 0
    while read < max_lines:
        if should_stop is not None and should_stop():
            return ChallengeWatch(False, read, False, stopped=True)
        try:
            line = channel.read_line()
        except Exception as exc:
            tr.fail("vpn.2fa", event="token-submit-failure", reason=type(exc).__name__,
                    error_code=ErrorCode.CLI_FAILED.value)
            return ChallengeWatch(False, read, True)
        if line is None:
            return ChallengeWatch(False, read, True)
        read += 1
        if is_two_factor_prompt(line):
            tr.ok("vpn.2fa", event="two-factor-detected",
                  mode=TwoFactorMode.PROCESS_STDOUT.value, line_index=read)
            return ChallengeWatch(True, read, False)
    return ChallengeWatch(False, read, False)


def submit_token_to_process(provider, request: VpnRequest, channel, *,
                            api: WindowApi | None = None,
                            trace=None) -> TwoFactorResult:
    """Answer a monitored client's stdout challenge on its stdin.

    The pipe has no window to confirm, so the check is on the other end of it:
    the process must be a FortiClient executable installed in one of this
    provider's trusted directories.  Anything else — an unknown pid, an
    unreadable image, an image outside those directories — and the token stays
    in this process.
    """
    tr = _Trace(trace)
    pid = provider.id
    token = request.token

    tr.ok("vpn.2fa", event="two-factor-detected",
          mode=TwoFactorMode.PROCESS_STDOUT.value, field="token",
          automation_mode="cli")

    if not token:
        tr.ok("vpn.2fa", event="manual-auth-required", reason="no-token",
              mode=TwoFactorMode.PROCESS_STDOUT.value)
        return _result(pid, TwoFactorStatus.TOKEN_REQUIRED,
                       TwoFactorMode.PROCESS_STDOUT, reason="no-token")

    window_api = api if api is not None else Win32WindowApi()
    trusted = provider.trusted_window_dirs()
    ok, reason = _process_is_trusted(getattr(channel, "pid", None), trusted,
                                     window_api)
    if not ok:
        tr.fail("vpn.2fa", event="token-submit-blocked", blocked_at=PHASE_PROCESS,
                reason=reason, error_code=ErrorCode.SECRET_INPUT_BLOCKED.value)
        return _result(pid, TwoFactorStatus.BLOCKED, TwoFactorMode.PROCESS_STDOUT,
                       error_code=ErrorCode.SECRET_INPUT_BLOCKED.value,
                       blocked_at=PHASE_PROCESS, reason=reason)

    tr.ok("vpn.2fa", event="token-submit-start", field="token", method="stdin")
    try:
        channel.write_line(token)
    except Exception as exc:
        tr.fail("vpn.2fa", event="token-submit-failure", reason=type(exc).__name__,
                error_code=ErrorCode.CLI_FAILED.value)
        return _result(pid, TwoFactorStatus.FAILED, TwoFactorMode.PROCESS_STDOUT,
                       error_code=ErrorCode.CLI_FAILED.value,
                       blocked_at=PHASE_PROCESS, reason=type(exc).__name__)

    tr.ok("vpn.2fa", event="token-submit-success", field="token", method="stdin",
          entered=True, submitted=True)
    return _result(pid, TwoFactorStatus.SUBMITTED, TwoFactorMode.PROCESS_STDOUT,
                   submitted=True)


def _process_is_trusted(process_pid, trusted_dirs, api: WindowApi
                        ) -> tuple[bool, str]:
    """Same rule as a window's owner, applied to the far end of a pipe.

    Reuses ``secure_window.is_inside`` — the project has one definition of
    "this image is a trusted FortiClient", and this is not a second one.
    """
    if not isinstance(process_pid, int) or isinstance(process_pid, bool) \
            or process_pid <= 0:
        return False, "no-process"
    try:
        image = api.process_image_path(process_pid)
    except Exception:
        image = None
    if not isinstance(image, str) or not image:
        return False, "image-unavailable"
    if not any(is_inside(image, directory) for directory in trusted_dirs):
        return False, "untrusted-image"
    return True, "verified"


# --------------------------------------------------------------------------- #
# Results                                                                      #
# --------------------------------------------------------------------------- #

def _result(provider_id: str, status: TwoFactorStatus, mode: TwoFactorMode,
            *, submitted: bool = False, manual_submit_required: bool = False,
            error_code: str | None = None, blocked_at: str | None = None,
            reason: str | None = None) -> TwoFactorResult:
    success = status in (TwoFactorStatus.SUBMITTED, TwoFactorStatus.NOT_REQUIRED)
    return TwoFactorResult(
        provider_id=provider_id, success=success, status=status, mode=mode,
        submitted=submitted, manual_submit_required=manual_submit_required,
        error_code=error_code, blocked_at=blocked_at,
        metadata={"reason_code": reason} if reason else {})


def _blocked(provider_id, tr, blocked_at, reason) -> TwoFactorResult:
    """A guard refused: no token, no Connect click."""
    tr.fail("vpn.2fa", event="token-submit-blocked", blocked_at=blocked_at,
            reason=reason, error_code=ErrorCode.SECRET_INPUT_BLOCKED.value)
    return _result(provider_id, TwoFactorStatus.BLOCKED,
                   TwoFactorMode.AUTH_WINDOW,
                   error_code=ErrorCode.SECRET_INPUT_BLOCKED.value,
                   blocked_at=blocked_at, reason=reason)


def _failed(provider_id, tr, mode, blocked_at, code: ErrorCode,
            reason: str) -> TwoFactorResult:
    tr.fail("vpn.2fa", event="token-submit-failure", blocked_at=blocked_at,
            reason=reason, error_code=code.value)
    return _result(provider_id, TwoFactorStatus.FAILED, mode,
                   error_code=code.value, blocked_at=blocked_at, reason=reason)
