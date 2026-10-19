"""FortiClient autofill — login + password, migrated behind the Stage-13 guard.

The migrated counterpart of legacy ``_autofill_forticlient``, limited on
purpose to entering the **username and password** into the FortiClient main
window and submitting.  Not here: the 2FA token, the EMS auth window, the CLI,
status and connect orchestration — later stages.

Every keystroke, paste and — crucially — every write of a secret to the
clipboard happens *inside* :meth:`VerifiedWindow.run_guarded`, so it is
preceded by a fresh confirmation that the verified FortiClient window is still
in the foreground and still owned by the same process.  There is no path that
finds a window and types into it without that guard: this function never
receives a raw HWND, only a :class:`SecureWindowTarget`.

Fail-closed: the moment a confirmation fails (focus lost, foreground changed,
owner changed, window released) no further secret is sent, Enter is not
pressed, the clipboard is restored, and an :class:`AutofillResult` says where
it stopped.  The secrets themselves live only in the callbacks' closures and
never pass through the guard, the result, or a trace.
"""

from __future__ import annotations

from ..types import AutofillResult, AutofillStatus, ErrorCode, VpnRequest
from . import forticlient_profile as fprof
from .input_system import (
    VK_CONTROL, VK_DELETE, VK_RETURN, VK_SHIFT, VK_SPACE, VK_TAB, InputSystem,
    Win32InputSystem,
)
from .secure_target import SecureWindowTarget, VerifiedWindow
from .msaa_system import ROLE_SYSTEM_COMBOBOX, ROLE_SYSTEM_TEXT

__all__ = ["autofill_login_password", "PHASES"]

# Pauses driven through InputSystem.sleep, which a test records without
# waiting.  Most came verbatim from the legacy sequence; the ones Stage 45
# changed say why, because each was waiting for something that has already
# happened by the time the V2 path runs.
#
#: The legacy path called SW_RESTORE and then had to wait for Electron to draw
#: the frame.  The V2 path never restores: the activation gate does not release
#: until the *user* has brought the window forward, so it is on screen and
#: painted before the first keystroke is even considered.  What is left is a
#: courtesy margin, not a render wait.
_RENDER_WAIT_S = 0.2
_AFTER_TAB_S = 0.3
_AFTER_TYPE_S = 0.3
#: Space drops the VPN Name list open; the legacy waited this long (Stage 60).
_AFTER_OPEN_S = 0.5
#: Enter commits the list's choice and closes it before the combo is read back.
_AFTER_SELECT_S = 0.4
#: Reading the combo back through MSAA after Enter: how often, and how far
#: apart, before "not that profile" becomes the answer.  The confirmation needs
#: two readings in a row (Stage 63), so four attempts leave room for one that
#: is still settling.
_PROFILE_READ_ATTEMPTS = 4
_PROFILE_READ_POLL_S = 0.1
_PROFILE_CONFIRM_READINGS = 2
_TO_USERNAME_S = 0.3
#: After *our own* SetClipboardData.  That call is synchronous and local, and
#: the target application is not involved — there is nothing to wait for.
_AFTER_CLIP_SET_S = 0.02
#: After Ctrl+A, before Ctrl+C: this one is a real wait, for the renderer to
#: apply the selection.
_SELECT_ALL_S = 0.15
_AFTER_DELETE_S = 0.15
_AFTER_COPY_S = 0.1
#: Ctrl+C is answered by polling rather than by sleeping a fixed time: the
#: clipboard is emptied first, so any content at all is the answer arriving.
#: A copy that produces nothing — an empty field, a password box — has no
#: signal to give and costs the whole deadline, which is why the deadline is
#: short and the poll is fine-grained.
_COPY_DEADLINE_S = 0.25
_COPY_POLL_S = 0.025
_AFTER_PASTE_LOGIN_S = 0.4
_TO_PASSWORD_S = 0.4
#: The same as the login's.  The legacy sequence waited half as long again
#: here, which is the sort of margin that gets added once and never questioned:
#: a password box commits a paste no more slowly than any other field, and
#: _BEFORE_SUBMIT_S still stands between this and Enter.
_AFTER_PASTE_PASSWORD_S = 0.4
_BEFORE_SUBMIT_S = 0.4
#: Only the clipboard restore waits behind this, and FortiClient has read the
#: fields long before — it is not reading the clipboard at all.
_AFTER_SUBMIT_S = 0.5

# Guard purposes / trace phases.
PHASE_NAVIGATION = "navigation"
#: Walking the tab stops until a text field answers (Stage 43).
PHASE_LOCATE = "locate-field"
#: Setting the VPN Name combo, proving it shows the requested profile, and
#: walking back to the username field after.
PHASE_PROFILE = "profile"
PHASE_LOGIN_CLEAR = "login-clear"
#: Is the caret in a text box at all?  Asked after the clear, so the field is
#: empty and nothing of the user's is read (Stage 42).
PHASE_LOGIN_PROBE = "login-probe"
PHASE_LOGIN_CLIPBOARD = "login-clipboard"
PHASE_LOGIN_PASTE = "login-paste"
#: Did the login actually land in the field?  If not, stop before the password.
PHASE_LOGIN_VERIFY = "login-verify"
PHASE_PASSWORD_CLEAR = "password-clear"
PHASE_PASSWORD_PROBE = "password-probe"
PHASE_PASSWORD_CLIPBOARD = "password-clipboard"
PHASE_PASSWORD_PASTE = "password-paste"
PHASE_SUBMIT = "submit"
PHASES = (PHASE_NAVIGATION, PHASE_LOCATE, PHASE_PROFILE, PHASE_LOGIN_CLEAR,
          PHASE_LOGIN_PROBE,
          PHASE_LOGIN_CLIPBOARD, PHASE_LOGIN_PASTE, PHASE_LOGIN_VERIFY,
          PHASE_PASSWORD_CLEAR, PHASE_PASSWORD_PROBE,
          PHASE_PASSWORD_CLIPBOARD, PHASE_PASSWORD_PASTE, PHASE_SUBMIT)

#: How many tab stops to walk while looking for the username field.  The form
#: is: profile combo, hamburger, username, password, Connect — so a handful
#: past that is plenty, and a budget means a client whose layout changed ends
#: the attempt instead of tabbing through the whole application.
MAX_TAB_STOPS = 8

#: Above this many characters, Ctrl+A grabbed the document rather than a field
#: — the signature of a caret that is not in a text box at all.  Measured in
#: Stage 18 on the real client and reused unchanged.
PAGE_SELECTION_CHARS = 60


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


#: Reason a guard reports when the caller called the fill off (Stage 47).
REASON_CANCELLED = "cancelled"


def autofill_login_password(
        provider, request: VpnRequest, *,
        target: SecureWindowTarget | None = None,
        input_system: InputSystem | None = None,
        trace=None, cancellation=None, msaa=None,
        tunnels=None) -> AutofillResult:
    """Enter login and password into a verified FortiClient window.

    `target` defaults to the provider's :meth:`secure_window_target`;
    `input_system` to the real Win32 one.  Both are injected in tests.

    `cancellation` (Stage 47) is checked before every guarded operation: a
    token that is set part-way through stops the sequence at its next step,
    exactly like a guard refusal — no further secret, no Enter, clipboard
    restored — but the outcome says CANCELLED rather than BLOCKED.  The check
    is *before* the operation, so a Cancel that lands between the login and the
    password, or just before Enter, is honoured before that keystroke.

    `msaa` (an :class:`~.msaa_system.MsaaSystem`) and `tunnels` (a
    :class:`~.forticlient_profile.TunnelCatalog`) serve the profile step only
    (Stage 63); they default to the real MSAA reader and the provider's
    registry, and neither is touched when the request names no profile.
    """
    tr = _Trace(trace)
    inp = input_system if input_system is not None else Win32InputSystem()
    target = target if target is not None else provider.secure_window_target()
    login, password = request.login, request.password
    pid = provider.id

    tr.ok("vpn.autofill", event="autofill-start", automation_mode="tab_sequence")

    acquired = target.acquire_any()
    if not isinstance(acquired, VerifiedWindow):
        # No trusted window, or focus refused.  Distinguish the two so a future
        # connect() can retry vs. abort.
        reason = getattr(acquired, "reason", "no-verified-target")
        no_target = reason in ("no-verified-target", "no-window", "no-process",
                               "image-unavailable", "untrusted-image",
                               "control-not-owned-by-target")
        status = AutofillStatus.NO_TARGET if no_target else AutofillStatus.NO_FOCUS
        tr.fail("vpn.autofill", event="autofill-failure", reason=reason,
                error_code="target-window-untrusted" if no_target else "focus-failed")
        return AutofillResult(
            provider_id=pid, success=False, status=status, blocked_at="acquire",
            error_code=(ErrorCode.CLIENT_NOT_FOUND.value if no_target
                        else ErrorCode.FOCUS_FAILED.value),
            metadata={"reason_code": reason})

    tr.ok("vpn.autofill", event="target-acquired", image_name=acquired.image_name,
          pid=acquired.pid)

    state = {"login": False, "password": False, "prev_clip": None,
             "clip_dirty": False, "profile_already_selected": False}

    def cancelled() -> bool:
        return cancellation is not None and bool(cancellation.cancelled)

    def guard(win: VerifiedWindow, phase: str, op) -> tuple[bool, str]:
        # Checked before the guard runs the operation: a Cancel that has
        # arrived means the next keystroke, paste or clipboard write does not
        # happen.  Reported as its own reason so `_stop` can tell it apart from
        # a lost-focus refusal and return CANCELLED, not BLOCKED.
        if cancelled():
            return False, REASON_CANCELLED
        result = win.run_guarded(phase, op)
        return result.performed, result.reason

    with acquired as win:
        try:
            profile = request.profile_name
            check_profile = None
            reader = None
            #: Without a profile name the step may only *confirm*, never change.
            may_change = True
            if not profile:
                # 2026-10-14 (L1, decision G5 pending): with no name the target
                # is unknown, and the legacy typed the credentials into whatever
                # profile was showing — one hospital's login at another's
                # gateway, and Enter.  Only one case is unambiguous: exactly one
                # tunnel configured, and MSAA shows that one.
                if tunnels is None:
                    tunnels = provider.configured_tunnels()
                profile = fprof.sole_tunnel(tunnels)
                if not profile:
                    return _stop(pid, state, inp, tr, PHASE_PROFILE,
                                 REASON_PROFILE_UNSPECIFIED)
                may_change = False
            if profile:
                # Before the first key (Stage 63): a name that could never be
                # confirmed is refused here, not after type-ahead has had a
                # chance to pick something merely similar.
                if tunnels is None:
                    tunnels = provider.configured_tunnels()
                ready = fprof.requested_profile_selectable(profile, tunnels)
                if not ready.matched:
                    return _stop(pid, state, inp, tr, PHASE_PROFILE, ready.reason)
                if msaa is None:
                    from .msaa_system import Win32MsaaSystem
                    msaa = Win32MsaaSystem()
                reader = _ProfileReader(target, msaa, win, profile, tunnels)
                check_profile = reader.still_selected

            # --- navigation (no secret): render wait, profile, tabs --------- #
            def navigate():
                # No keystroke here any more.  The old sequence opened with a
                # blind Tab, which was right when the window had just been shown
                # from the tray and wrong once the user clicked it to satisfy
                # the activation gate — it could step straight *past* the
                # username field.  Finding the field is `_locate_text_field`'s
                # job, and it probes before it tabs.
                inp.sleep(_RENDER_WAIT_S)
                # Remember the user's clipboard before we hijack it (not a secret).
                state["prev_clip"] = inp.read_clipboard()

            performed, reason = guard(win, PHASE_NAVIGATION, navigate)
            if not performed:
                return _stop(pid, state, inp, tr, PHASE_NAVIGATION, reason)

            # 2026-10-19: with MSAA's focus available the fields are reached
            # by name (combo, Username, Password) — no Tab counting from
            # wherever the window put the caret.  Without it, the old search.
            focus = (getattr(msaa, "focus_element", None)
                     if msaa is not None else None)
            if focus is None:
                # Where the caret ends up depends on how the window came
                # forward.  Rather than assume, walk to the field.
                found, reason = _locate_text_field(win, inp, guard, state)
                if not found:
                    return _stop(pid, state, inp, tr, PHASE_LOCATE, reason)

            # --- profile (no secret) ---------------------------------------- #
            if profile:
                chosen, reason = _select_profile(
                    win, inp, guard, profile, state, reader,
                    may_change=may_change, focus=focus)
                if not chosen:
                    return _stop(pid, state, inp, tr, PHASE_PROFILE, reason)
                tr.ok("vpn.autofill", event="profile-step",
                      field="vpn-name", method="open_type_commit",
                      verified=True,
                      already_selected=state["profile_already_selected"])

            if focus is not None:
                moved, reason = _focus_field(win, guard, focus, ROLE_SYSTEM_TEXT,
                                             FIELD_USERNAME, PHASE_LOCATE)
                if not moved:
                    return _stop(pid, state, inp, tr, PHASE_LOCATE, reason)

            # --- login ------------------------------------------------------ #
            # An empty login leaves the field alone, as the legacy does
            # (vpn_connect.py `if login:`): whatever FortiClient saved for this
            # connection stays.  Clearing it and pasting nothing wiped a saved
            # username and submitted an empty form (Stage 59, live).
            read_value = (getattr(msaa, "field_value", None)
                          if focus is not None else None)
            if login and read_value is not None:
                blocked, reason = _fill_field_by_name(
                    win, inp, guard, read_value, FIELD_USERNAME, login, state,
                    PHASE_LOGIN_CLIPBOARD, PHASE_LOGIN_PASTE, PHASE_LOGIN_VERIFY,
                    masked=False, precheck=check_profile)
                if blocked:
                    return _stop(pid, state, inp, tr, blocked, reason)
                state["login"] = True
                tr.ok("vpn.autofill", event="login-step", field="username",
                      method="clipboard_paste", entered=True)
            elif login:
                blocked, reason = _fill_field(
                    win, inp, guard, login, PHASE_LOGIN_CLEAR, PHASE_LOGIN_PROBE,
                    PHASE_LOGIN_CLIPBOARD, PHASE_LOGIN_PASTE,
                    _AFTER_PASTE_LOGIN_S, state,
                    verify_phase=PHASE_LOGIN_VERIFY, precheck=check_profile)
                if blocked:
                    return _stop(pid, state, inp, tr, blocked, reason)
                state["login"] = True
                tr.ok("vpn.autofill", event="login-step", field="username",
                      method="clipboard_paste", entered=True)

            # From username to password: by name, or the old Tab.
            if focus is not None:
                moved, reason = _focus_field(win, guard, focus, ROLE_SYSTEM_TEXT,
                                             FIELD_PASSWORD,
                                             PHASE_PASSWORD_CLEAR + "-focus")
                if not moved:
                    return _stop(pid, state, inp, tr, PHASE_PASSWORD_CLEAR, reason)
                # The focus is confirmed; no fixed wait for the caret to move.
                inp.sleep(_AFTER_MSAA_FOCUS_S)
            else:
                performed, reason = guard(win, PHASE_PASSWORD_CLEAR + "-tab",
                                          lambda: (inp.press_key(VK_TAB),
                                                   inp.sleep(_TO_PASSWORD_S)))
                if not performed:
                    return _stop(pid, state, inp, tr, PHASE_PASSWORD_CLEAR, reason)

            # --- password --------------------------------------------------- #
            # No verify for the password: a password box refuses to be copied
            # from, so reading it back proves nothing.  The login's verify
            # already established that the caret walks the fields as expected.
            # Empty password: field left alone, same as the login above.
            if password and read_value is not None:
                blocked, reason = _fill_field_by_name(
                    win, inp, guard, read_value, FIELD_PASSWORD, password, state,
                    PHASE_PASSWORD_CLIPBOARD, PHASE_PASSWORD_PASTE,
                    PHASE_PASSWORD_PASTE + "-verify", masked=True,
                    precheck=check_profile)
                if blocked:
                    return _stop(pid, state, inp, tr, blocked, reason)
                state["password"] = True
                tr.ok("vpn.autofill", event="password-step", field="password",
                      method="clipboard_paste", entered=True)
            elif password:
                blocked, reason = _fill_field(
                    win, inp, guard, password, PHASE_PASSWORD_CLEAR,
                    PHASE_PASSWORD_PROBE, PHASE_PASSWORD_CLIPBOARD,
                    PHASE_PASSWORD_PASTE, _AFTER_PASTE_PASSWORD_S, state,
                    precheck=check_profile)
                if blocked:
                    return _stop(pid, state, inp, tr, blocked, reason)
                state["password"] = True
                tr.ok("vpn.autofill", event="password-step", field="password",
                      method="clipboard_paste", entered=True)

            # --- submit ----------------------------------------------------- #
            # Enter is a guarded operation like any other, so the same
            # cancellation check stands between the filled form and the
            # attempt to connect: a Cancel here leaves the fields typed but
            # never presses Enter.  With a profile, the combo is read once
            # more in the same step — still that profile, closed, not focused —
            # so a choice changed after the confirmation never connects.
            refused = {"reason": ""}

            def submit():
                inp.sleep(_BEFORE_SUBMIT_S)
                if check_profile is not None:
                    refused["reason"] = check_profile()
                    if refused["reason"]:
                        return
                inp.press_key(VK_RETURN)

            performed, reason = guard(win, PHASE_SUBMIT, submit)
            if not performed:
                return _stop(pid, state, inp, tr, PHASE_SUBMIT, reason)
            if refused["reason"]:
                return _stop(pid, state, inp, tr, PHASE_SUBMIT, refused["reason"])

            # Restore the user's clipboard only after submit.
            inp.sleep(_AFTER_SUBMIT_S)
            _restore_clipboard(inp, state)
            tr.ok("vpn.autofill", event="autofill-success",
                  login_entered=state["login"], password_entered=state["password"])
            return AutofillResult(
                provider_id=pid, success=True, status=AutofillStatus.DONE,
                login_entered=state["login"], password_entered=state["password"])
        except Exception as exc:                       # a seam misbehaved
            _restore_clipboard(inp, state)
            tr.fail("vpn.autofill", event="autofill-failure",
                    error_code="automation-failed", reason=type(exc).__name__)
            return AutofillResult(
                provider_id=pid, success=False, status=AutofillStatus.FAILED,
                login_entered=state["login"], password_entered=state["password"],
                error_code=ErrorCode.AUTOMATION_FAILED.value,
                metadata={"reason_code": type(exc).__name__})


def _read_selection(inp) -> str:
    """Ctrl+A, Ctrl+C, and whatever the clipboard received.  Never printed.

    Used only to answer structural questions — "is this a text box", "did the
    paste land" — and the value is compared or measured, never logged.

    The clipboard is emptied first, and that is not tidiness.  ``Ctrl+C`` with
    an empty selection copies *nothing*, leaving whatever was there before —
    so without this the probe reads the operator's old clipboard and an empty
    field looks like a page selection, while a paste that silently failed looks
    like a paste that worked, because the value being compared against is still
    sitting there.  Both were observed live.
    """
    inp.copy_to_clipboard("")
    inp.sleep(_AFTER_CLIP_SET_S)
    inp.press_combo(VK_CONTROL, ord("A"))
    inp.sleep(_SELECT_ALL_S)
    inp.press_combo(VK_CONTROL, ord("C"))
    return _await_copy(inp)


def _await_copy(inp) -> str:
    """Wait for Ctrl+C to produce something, and no longer than it takes.

    The emptied clipboard doubles as a sentinel: the moment it holds anything,
    the copy has landed and there is nothing further to wait for.  A fixed
    sleep here was 0.2 s every time, and this sequence reads the selection ten
    times over — so most of that was spent waiting after the answer had already
    arrived.
    """
    waited = 0.0
    while True:
        try:
            value = inp.read_clipboard() or ""
        except Exception:
            return ""
        if value:
            return value
        if waited >= _COPY_DEADLINE_S:
            return ""                    # genuinely nothing: an empty field
        inp.sleep(_COPY_POLL_S)
        waited += _COPY_POLL_S


def _locate_text_field(win, inp, guard, state_holder) -> tuple[bool, str]:
    """Tab until the caret sits in a text field.  Returns ``(found, reason)``.

    Asked *before* anything is cleared, so unlike the Stage-42 probe this one
    can meet a field that still holds the user's data.  It therefore looks at
    one thing only — whether the selection is short enough to be a field rather
    than the whole document — and never at what the selection says.  That is
    the same question, and the same threshold, the Stage-18 tab-order tool used
    on this client.

    Every step is guarded: a Tab is a keystroke into somebody else's window.
    """
    for _ in range(MAX_TAB_STOPS):
        found = {"ok": False}

        def probe():
            # Ctrl+C overwrites the operator's clipboard, so the read dirties
            # it and the restore at the end has to know.
            state_holder["clip_dirty"] = True
            found["ok"] = _caret_is_in_a_text_box(inp)

        performed, reason = guard(win, PHASE_LOCATE, probe)
        if not performed:
            return False, reason
        if found["ok"]:
            return True, reason

        performed, reason = guard(win, PHASE_LOCATE, lambda: (
            inp.press_key(VK_TAB), inp.sleep(_TO_USERNAME_S)))
        if not performed:
            return False, reason
    return False, "no-text-field-found"


#: MSAA names of the two credential fields (FortiClient VPN 7.4.3, measured
#: 2026-10-19).
FIELD_USERNAME = "Username"
FIELD_PASSWORD = "Password"


def _focus_field(win, guard, focus, role, name, phase) -> tuple[bool, str]:
    """Guarded MSAA focus on one named element of the verified window."""
    outcome = {"ok": False, "reason": ""}

    def operation():
        result = focus(win.hwnd, role, name)
        outcome["ok"] = bool(getattr(result, "ok", False))
        outcome["reason"] = getattr(result, "reason", "focus-failed")

    performed, reason = guard(win, phase, operation)
    if not performed:
        return False, reason
    if not outcome["ok"]:
        return False, outcome["reason"] or "focus-failed"
    return True, reason


def _select_profile(win, inp, guard, profile: str, state,
                    reader: "_ProfileReader", *,
                    may_change: bool = True, focus=None) -> tuple[bool, str]:
    """Choose the VPN profile, prove FortiClient shows it, come back to Username.

    The form reads: VPN Name combo, the hamburger beside it, Username,
    Password, Connect.  So from the username field two Shift+Tabs reach the
    combo — going forwards from wherever the window starts would have to
    guess, and a guess one short lands on the hamburger, whose menu offers to
    delete the connection.

    Stage 60 decided every key here by asking UI Automation what had the
    focus; Stage 61 measured that FortiClient 7.4.3 shows UI Automation none of
    its form, so that question always ended in a refusal.  Stage 63 asks MSAA
    instead — the ``VPN Name`` combo of *this* verified window, through
    :mod:`forticlient_profile` — and every key is decided by a reading taken in
    the same guarded step, after which the window is confirmed once more
    before the key goes (:meth:`_ProfileReader.act`):

    1. Read first, before any key.  Showing the profile already, closed: done,
       not a single key sent.  Showing another configured tunnel: change it.
       Anything else (unknown format, foreign window, unreadable): refuse.
    2. Shift+Tab twice; Space only if the combo is now *focused* and closed.
    3. The name only if the list is open (``EXPANDED``); Enter only if it is
       still open — an Enter that could reach a field, or Connect, never goes.
    4. Afterwards the combo must show exactly the profile, closed, in two
       readings in a row.  Sending the keys proves nothing; this does.

    Any refusal returns ``(False, reason)`` and the caller stops: no login, no
    password, no Enter.  Changing the profile does not clear the credential
    fields, so all of this runs before them.  A Cancel after the committing
    Enter leaves the profile changed and nothing typed — a state the user can
    see and nothing was sent in.
    """
    first = {"reason": "", "selected": False}

    def look():
        first["reason"], first["selected"] = reader.initial()

    performed, reason = guard(win, PHASE_PROFILE, look)
    if not performed:
        return False, reason
    if first["reason"]:
        return False, first["reason"]
    state["profile_already_selected"] = first["selected"]
    if first["selected"]:
        # Nothing was moved, so the caret is still where the field search
        # left it — in the username field.
        return True, reason
    if not may_change:
        # No name was asked for: the sole tunnel is only accepted as already
        # showing, never chosen on the user's behalf.
        return False, REASON_PROFILE_UNSPECIFIED

    if focus is not None:
        # Straight to the combo by name (2026-10-19) — the hamburger, whose
        # menu can delete the connection, is never stepped on.
        moved, reason = _focus_field(win, guard, focus, ROLE_SYSTEM_COMBOBOX,
                                     fprof.PROFILE_CONTROL_NAME, PHASE_PROFILE)
        if not moved:
            return False, reason
        inp.sleep(_AFTER_TAB_S)
    else:
        for step in ("back-1", "back-2"):
            performed, reason = guard(win, PHASE_PROFILE, lambda: (
                inp.press_combo(VK_SHIFT, VK_TAB), inp.sleep(_AFTER_TAB_S)))
            if not performed:
                return False, reason

    for need, press in (
            (reader.ready_to_open, lambda: (inp.press_key(VK_SPACE),
                                            inp.sleep(_AFTER_OPEN_S))),
            (reader.list_open, lambda: (inp.type_text(profile),
                                        inp.sleep(_AFTER_TYPE_S))),
            (reader.list_open, lambda: (inp.press_key(VK_RETURN),
                                        inp.sleep(_AFTER_SELECT_S)))):
        performed, reason = guard(win, PHASE_PROFILE, reader.act(need, press))
        if not performed:
            return False, reason
        if reader.refusal:
            return False, reader.refusal

    confirmed, reason = _confirm_profile(win, inp, guard, reader)
    if not confirmed:
        return False, reason
    if focus is not None:
        return True, reason             # the caller focuses Username by name

    # Back to where the login expects to be: combo -> hamburger -> username.
    for step in ("forward-1", "forward-2"):
        performed, reason = guard(win, PHASE_PROFILE, lambda: (
            inp.press_key(VK_TAB), inp.sleep(_AFTER_TAB_S)))
        if not performed:
            return False, reason

    landed = {"ok": False}

    def confirm():
        state["clip_dirty"] = True
        landed["ok"] = _caret_is_in_a_text_box(inp)

    performed, reason = guard(win, PHASE_PROFILE, confirm)
    if not performed:
        return False, reason
    if landed["ok"]:
        return True, reason
    # The measurement did not hold on this machine — search rather than insist.
    return _locate_text_field(win, inp, guard, state)


#: Reasons the profile step refuses with, beyond the reader's own
#: (:mod:`forticlient_profile`).  Codes only — the profile name names a
#: hospital and does not go into a result or a trace.
REASON_PROFILE_NOT_CONFIRMED = "profile-not-confirmed"
#: The request names no profile and the target is not unambiguous (L1).
REASON_PROFILE_UNSPECIFIED = "profile-not-specified"
#: The combo is not focused where Space would have to reach it.
REASON_PROFILE_NOT_FOCUSED = "profile-control-not-focused"
#: The list is not open where the name or the committing Enter would go.
REASON_PROFILE_LIST_CLOSED = "profile-list-not-open"
#: The combo is open, or focused, where it must be closed and left.
REASON_PROFILE_STATE = "profile-control-state-unexpected"
#: The reading did not come back for the verified window and process.
REASON_PROFILE_WINDOW_CHANGED = "profile-window-changed"
#: The display is in a form the step does not change from — anything but
#: "another configured tunnel under a measured label".
REASON_PROFILE_UNCHANGEABLE = "profile-display-not-changeable"


class _ProfileReader:
    """Every decision of the profile step, each from a fresh MSAA reading.

    Holds no secret.  Reads only *this* verified window (``win.hwnd``) and
    accepts a reading only when it comes back for that window and that
    process — :func:`forticlient_profile.read_profile_control` re-verifies the
    owner, but against the trusted image, not against ``win.pid``.
    """

    def __init__(self, target, msaa, win, profile, tunnels):
        self._target, self._msaa, self._win = target, msaa, win
        self._profile, self._tunnels = profile, tunnels
        #: Why the last :meth:`act` withheld its key, or ``""``.
        self.refusal = ""

    def read(self):
        """``(reading, match, refusal)`` — `refusal` is ``""`` when usable."""
        reading = fprof.read_profile_control(self._target, self._msaa,
                                             hwnd=self._win.hwnd)
        if not reading.ok:
            return reading, None, reading.reason
        if (reading.hwnd != self._win.hwnd or self._win.pid is None
                or reading.pid != self._win.pid):
            return reading, None, REASON_PROFILE_WINDOW_CHANGED
        return reading, fprof.match_profile(reading.value, self._profile,
                                            self._tunnels), ""

    def initial(self) -> tuple[str, bool]:
        """Before any key: ``(refusal, already_selected)``."""
        reading, match, refusal = self.read()
        if refusal:
            return refusal, False
        if match.matched:
            if reading.collapsed and not reading.expanded:
                return "", True
            return REASON_PROFILE_STATE, False
        if match.reason != fprof.REASON_MISMATCH:
            # Not "another tunnel of a measured kind" — an unknown label, a
            # name not in the registry, an ambiguous one: do not touch it.
            return REASON_PROFILE_UNCHANGEABLE, False
        if reading.expanded or not reading.collapsed:
            # Someone has the list open: a Shift+Tab there could commit the
            # highlighted item on its way out.
            return REASON_PROFILE_STATE, False
        return "", False

    def ready_to_open(self, reading, match) -> str:
        if not reading.focused:
            return REASON_PROFILE_NOT_FOCUSED
        if reading.expanded or not reading.collapsed:
            return REASON_PROFILE_STATE
        return ""

    def list_open(self, reading, match) -> str:
        return "" if reading.expanded else REASON_PROFILE_LIST_CLOSED

    def settled(self, reading, match) -> str:
        if not match.matched:
            return REASON_PROFILE_NOT_CONFIRMED
        if reading.expanded or not reading.collapsed:
            return REASON_PROFILE_STATE
        return ""

    def still_selected(self) -> str:
        """Before a credential reaches the clipboard and before the final
        Enter: the profile still shows, closed, and nobody is in the combo."""
        reading, match, refusal = self.read()
        if refusal:
            return refusal
        refusal = self.settled(reading, match)
        if refusal:
            return refusal
        if reading.focused:
            return REASON_PROFILE_STATE
        return self._reconfirm()

    def act(self, need, press):
        """An operation for the guard: read, decide, confirm the window, key.

        The reading and the key are one operation, so a key is never
        justified by a reading taken in another step; and the window is
        confirmed again between the two, because a walk of the accessibility
        tree is not instant and the guard's own check came before it.
        """
        def operation():
            self.refusal = ""
            reading, match, refusal = self.read()
            if not refusal:
                refusal = need(reading, match)
            if not refusal:
                refusal = self._reconfirm()
            if refusal:
                self.refusal = refusal
                return
            press()
        return operation

    def _reconfirm(self) -> str:
        check = self._win.confirm()
        return "" if check.ok else check.reason


def _confirm_profile(win, inp, guard, reader) -> tuple[bool, str]:
    """After Enter: the profile, closed, in two readings in a row.

    Accessibility trees update lazily and a list takes a moment to close,
    hence the short poll; a single reading could also catch a value shown
    before the choice was committed, hence two.
    """
    last = {"refusal": REASON_PROFILE_NOT_CONFIRMED}
    good = 0
    for attempt in range(_PROFILE_READ_ATTEMPTS):
        def read(attempt=attempt):
            if attempt:
                inp.sleep(_PROFILE_READ_POLL_S)
            reading, match, refusal = reader.read()
            last["refusal"] = refusal or reader.settled(reading, match)

        performed, reason = guard(win, PHASE_PROFILE, read)
        if not performed:
            return False, reason
        if last["refusal"]:
            good = 0
            continue
        good += 1
        if good >= _PROFILE_CONFIRM_READINGS:
            return True, reason
    return False, last["refusal"]


def _caret_is_in_a_text_box(inp) -> bool:
    """Is the caret somewhere a paste would actually go?

    Asked immediately after the field was cleared, so an ordinary text box
    answers with an empty string and nothing of the user's is read.  A caret
    resting on the page body answers with the whole document — which is what a
    live run produced when three Tabs landed on the profile-list hamburger
    instead of the username field, and is exactly the case this refuses.

    A password box that declines to be copied also answers empty, and that is
    correct: empty means "nothing here objects to a paste".
    """
    return len(_read_selection(inp)) < PAGE_SELECTION_CHARS


def _field_now_contains(inp, expected: str) -> bool:
    """Did `expected` actually land in the field?  Compared, never logged.

    Only meaningful for a field that can be copied from.  A password box
    refuses, so this is asked about the login alone — and that is enough,
    because the login is pasted first: if it did not land, the caret is not
    where the sequence thinks it is, and the password must not follow.
    """
    return _read_selection(inp) == expected


def _fill_field(win, inp, guard, secret, clear_phase, probe_phase,
                clipboard_phase, paste_phase, after_paste_s, state,
                verify_phase=None, precheck=None) -> tuple[str | None, str]:
    """Clear, prove the caret is in a field, then clipboard and paste.

    The order is the whole point.  The secret reaches the system clipboard only
    after `probe_phase` has established that the caret sits in a text box —
    before Stage 42 it went there first and stayed there even when the paste had
    nowhere to land.  `verify_phase`, when given, reads the field back
    afterwards and refuses to continue if the paste did not arrive.

    An empty `secret` touches nothing — not even the clear — so the value
    FortiClient saved for the connection stays, as in the legacy (Stage 60).

    `precheck`, when given, is asked inside the clipboard step, before the
    secret is written: a non-empty answer is a refusal and the secret never
    reaches the clipboard (Stage 63 — the profile still shows).

    Returns ``(phase where it was blocked, why)``, or ``(None, reason)``.
    """
    if not secret:
        return None, "empty-skipped"
    performed, reason = guard(win, clear_phase, lambda: (
        inp.press_combo(VK_CONTROL, ord("A")), inp.sleep(_SELECT_ALL_S),
        inp.press_key(VK_DELETE), inp.sleep(_AFTER_DELETE_S)))
    if not performed:
        return clear_phase, reason

    # Probe *before* the secret exists outside this process.
    in_field = {"ok": False}

    def probe():
        # Ctrl+C overwrites the operator's clipboard whatever it finds, so the
        # read counts as dirtying it — otherwise a refusal here would walk away
        # leaving their clipboard replaced by a copy of the page.
        state["clip_dirty"] = True
        in_field["ok"] = _caret_is_in_a_text_box(inp)

    performed, reason = guard(win, probe_phase, probe)
    if not performed:
        return probe_phase, reason
    if not in_field["ok"]:
        return probe_phase, "caret-not-in-text-field"

    refused = {"reason": ""}

    def put_on_clipboard():
        if precheck is not None:
            refused["reason"] = precheck()
            if refused["reason"]:
                return
        inp.copy_to_clipboard(secret)
        state["clip_dirty"] = True
        inp.sleep(_AFTER_COPY_S)

    performed, reason = guard(win, clipboard_phase, put_on_clipboard)
    if not performed:
        return clipboard_phase, reason
    if refused["reason"]:
        return clipboard_phase, refused["reason"]

    def paste():
        # Asked again here: the clipboard step and this one are separate
        # guarded operations, and the profile could change in between.
        if precheck is not None:
            refused["reason"] = precheck()
            if refused["reason"]:
                return
        inp.press_combo(VK_CONTROL, ord("V"))
        inp.sleep(after_paste_s)

    performed, reason = guard(win, paste_phase, paste)
    if not performed:
        return paste_phase, reason
    if refused["reason"]:
        return paste_phase, refused["reason"]

    if verify_phase is not None:
        landed = {"ok": False}

        def verify():
            state["clip_dirty"] = True            # same reason as the probe
            landed["ok"] = _field_now_contains(inp, secret)

        performed, reason = guard(win, verify_phase, verify)
        if not performed:
            return verify_phase, reason
        if not landed["ok"]:
            # The paste went somewhere the read-back cannot see — typically a
            # password box the caret was resting in.  Take it out again, so a
            # login does not sit in the password field waiting for someone to
            # press Connect (2026-10-14, L13).  Guarded like any keystroke; if
            # the guard refuses, nothing more is sent either way.
            guard(win, verify_phase, lambda: (
                inp.press_combo(VK_CONTROL, ord("A")), inp.sleep(_SELECT_ALL_S),
                inp.press_key(VK_DELETE), inp.sleep(_AFTER_DELETE_S)))
            return verify_phase, "paste-did-not-land"
    return None, reason


#: The longest a paste may take to show in the field (MSAA read-back), and how
#: often to look.  Measured 2026-10-19: the fixed 0.4 s waits plus the
#: clipboard read-backs made ~2 s between the login and the password.
_PASTE_LANDS_WITHIN_S = 1.5
_PASTE_POLL_S = 0.025
_AFTER_MSAA_FOCUS_S = 0.05
#: What FortiClient's password field shows per character (measured).
_MASK_CHARS = frozenset("•●*")


def _fill_field_by_name(win, inp, guard, read_value, name, secret, state,
                        clipboard_phase, paste_phase, verify_phase, *,
                        masked: bool, precheck=None) -> tuple[str | None, str]:
    """Paste `secret` into the field `name`, whose focus MSAA has confirmed,
    and wait exactly until MSAA shows it there.

    No probe of the caret (the focus was confirmed by name) and no separate
    clear (Ctrl+A then Ctrl+V replaces the selection).  The read-back is MSAA's
    value: the text for Username, the mask for Password — compared by length
    and never readable.  Until it shows, nothing moves on: the password field
    is not focused while the login could still be on its way.
    """
    if not secret:
        return None, "empty-skipped"
    refused = {"reason": ""}

    def put_on_clipboard():
        if precheck is not None:
            refused["reason"] = precheck()
            if refused["reason"]:
                return
        inp.copy_to_clipboard(secret)
        state["clip_dirty"] = True
        inp.sleep(_AFTER_CLIP_SET_S)

    performed, reason = guard(win, clipboard_phase, put_on_clipboard)
    if not performed:
        return clipboard_phase, reason
    if refused["reason"]:
        return clipboard_phase, refused["reason"]

    def paste():
        if precheck is not None:
            refused["reason"] = precheck()
            if refused["reason"]:
                return
        inp.press_combo(VK_CONTROL, ord("A"))
        inp.press_combo(VK_CONTROL, ord("V"))

    performed, reason = guard(win, paste_phase, paste)
    if not performed:
        return paste_phase, reason
    if refused["reason"]:
        return paste_phase, refused["reason"]

    def landed(value) -> bool:
        if not isinstance(value, str):
            return False
        if masked:
            return len(value) == len(secret) and set(value) <= _MASK_CHARS
        return value == secret

    seen = {"ok": False}

    def verify():
        waited = 0.0
        while True:
            if landed(read_value(win.hwnd, ROLE_SYSTEM_TEXT, name)):
                seen["ok"] = True
                return
            if waited >= _PASTE_LANDS_WITHIN_S:
                return
            inp.sleep(_PASTE_POLL_S)
            waited += _PASTE_POLL_S

    performed, reason = guard(win, verify_phase, verify)
    if not performed:
        return verify_phase, reason
    if not seen["ok"]:
        # Take it out again rather than leave a value where it did not belong.
        guard(win, verify_phase, lambda: (
            inp.press_combo(VK_CONTROL, ord("A")), inp.sleep(_SELECT_ALL_S),
            inp.press_key(VK_DELETE), inp.sleep(_AFTER_DELETE_S)))
        return verify_phase, "paste-did-not-land"
    return None, reason


def _restore_clipboard(inp, state) -> None:
    if not state["clip_dirty"]:
        return
    try:
        inp.copy_to_clipboard(state["prev_clip"] if state["prev_clip"] is not None
                              else "")
    except Exception:
        pass
    state["clip_dirty"] = False


def _stop(pid, state, inp, tr, blocked_at, reason) -> AutofillResult:
    """A guard refused: no more secrets, no Enter, clipboard restored.

    A cancellation stops the sequence the same way — nothing further is sent
    and the clipboard is put back — but it is not a security block, so it
    carries its own status and code (Stage 47).
    """
    _restore_clipboard(inp, state)
    if reason == REASON_CANCELLED:
        tr.ok("vpn.autofill", event="autofill-cancelled", blocked_at=blocked_at)
        return AutofillResult(
            provider_id=pid, success=False, status=AutofillStatus.CANCELLED,
            login_entered=state["login"], password_entered=state["password"],
            blocked_at=blocked_at, error_code=ErrorCode.CANCELLED.value,
            metadata={"reason_code": REASON_CANCELLED})
    tr.fail("vpn.autofill", event="secret-input-blocked", blocked_at=blocked_at,
            reason=reason, error_code="secret-input-blocked")
    return AutofillResult(
        provider_id=pid, success=False, status=AutofillStatus.BLOCKED,
        login_entered=state["login"], password_entered=state["password"],
        blocked_at=blocked_at, error_code=ErrorCode.SECRET_INPUT_BLOCKED.value,
        metadata={"reason_code": reason})
