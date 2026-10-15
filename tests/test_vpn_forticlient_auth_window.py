"""Stage 48: the migrated FortiClient EMS credentials fill (login + password).

Proves the negative — login and password leave the application only into a
confirmed, focused, trusted, visible FortiClient authentication window, and only
one field at a time behind a fresh confirmation — and that the happy path fills
both fields in order and presses Connect.  Everything is a seam: a fake desktop
(:class:`WindowApi`) that owns the child controls, a fake
:class:`WindowMessageSystem` that records every ``WM_SETTEXT`` / ``BM_CLICK``, a
recording trace.  No real window, message, process or FortiClient.

Same window as the token path (Stage 15); the difference is only which fields
are written and that credentials use ``require_visible`` + ``raise_window=False``
(the main-window contract), so a minimised or background dialog is refused
rather than raised.
"""

import ast
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from vpn import ErrorCode, VpnRequest  # noqa: E402
from vpn.providers import FortiClientProvider  # noqa: E402
from vpn.providers import forticlient_auth_window as aw  # noqa: E402
from vpn.providers.activation_gate import CancellationToken  # noqa: E402
from vpn.providers.forticlient_auth_window import (  # noqa: E402
    submit_credentials_to_window,
)
from vpn.providers.window_message_system import (  # noqa: E402
    BUTTON, EDIT, WindowControl,
)
from tests.test_vpn_forticlient_detect import FakeEnvironment  # noqa: E402
from tests.test_vpn_forticlient_2fa import (  # noqa: E402
    AUTH_HWND, B_CANCEL, B_CONNECT, CONTROLS, E_PASS, E_TOKEN, E_USER,
    FakeMessages, RecTrace, auth_desktop, auth_windows, fg_lost_after,
)
from tests.test_vpn_secure_target import (  # noqa: E402
    EVIL_EXE, EVIL_PID, FORTI_DIR, FORTI_GUI, FORTI_PID, OTHER, FakeDesktop,
    ListFinder,
)

LOGIN, PASSWORD = "jkowalski", "SuperSecret123"
SECRETS = (LOGIN, PASSWORD)


def provider():
    return FortiClientProvider(FakeEnvironment(files=[FORTI_GUI], dirs=[FORTI_DIR]))


def run_creds(*, desktop=None, messages=None, hwnds=(AUTH_HWND,),
              cancellation=None, trace=None, login=LOGIN, password=PASSWORD,
              timeout=0.1):
    desktop = desktop if desktop is not None else auth_desktop()
    msg = messages if messages is not None else FakeMessages()
    tr = trace if trace is not None else RecTrace()
    prov = provider()
    target = prov.auth_credentials_target(api=desktop, finder=ListFinder(hwnds))
    request = VpnRequest(provider_id="forticlient", login=login, password=password)
    result = submit_credentials_to_window(
        prov, request, target=target, message_system=msg, api=desktop,
        cancellation=cancellation, timeout=timeout, trace=tr)
    return result, msg.events, tr


def sets(events):
    return [(hwnd, text) for kind, hwnd, text in
            [e for e in events if e[0] == "set_text"]]


def clicks(events):
    return [hwnd for kind, hwnd in [e for e in events if e[0] == "click"]]


def secret_sets(events):
    return [text for _hwnd, text in sets(events) if text in SECRETS]


# --------------------------------------------------------------------------- #
# Desktops that change under the fill's feet                                   #
# --------------------------------------------------------------------------- #

class OwnerFlipDesktop(FakeDesktop):
    """Owner verifies at locate time, then the process image turns hostile.

    Models a PID/image change between finding the window and acquiring it: the
    first image read (locate's owner check) is genuine, the next (acquire's
    re-verification) is an EVIL look-alike.
    """

    def __init__(self, flip_after=1, **kwargs):
        super().__init__(**kwargs)
        self._reads = 0
        self._flip_after = flip_after

    def process_image_path(self, pid):
        self._reads += 1
        if self._reads > self._flip_after and pid == FORTI_PID:
            return EVIL_EXE
        return super().process_image_path(pid)


class MessagesThatDisturb(FakeMessages):
    """Records sends, and runs a hook the instant a chosen field is written.

    The hook fires *after* the field is recorded, so it models something
    happening between two sends — the exact gap the guards defend.
    """

    def __init__(self, *, on_login=None, on_password=None, **kwargs):
        super().__init__(**kwargs)
        self._on_login = on_login
        self._on_password = on_password

    def set_control_text(self, hwnd, text):
        super().set_control_text(hwnd, text)
        if hwnd == E_USER and self._on_login is not None:
            self._on_login()
        elif hwnd == E_PASS and self._on_password is not None:
            self._on_password()


# ══════════════════════════════════════════════════════════════════════════
# 1. Happy path
# ══════════════════════════════════════════════════════════════════════════

def test_1_login_and_password_are_filled_in_order_and_connect_is_pressed():
    result, events, tr = run_creds()

    assert result.ok and result.located
    assert result.login_sent and result.password_sent and result.submitted
    assert not result.blocked and not result.cancelled
    assert sets(events) == [(E_USER, LOGIN), (E_PASS, PASSWORD)], \
        "login do pierwszego pola, hasło do drugiego, w tej kolejności"
    assert clicks(events) == [B_CONNECT]
    for expected in ("credentials-fill-start", "EMS-credentials-window-found",
                     "EMS-credentials-verified", "credentials-login-sent",
                     "credentials-password-sent", "credentials-submitted"):
        assert expected in tr.events(), expected


def test_1b_no_connect_button_leaves_the_submit_to_the_user():
    msg = MessagesThatDisturb(controls=[c for c in CONTROLS if c.hwnd != B_CONNECT])
    result, events, _ = run_creds(messages=msg)
    assert result.login_sent and result.password_sent
    assert not result.submitted and result.manual_submit_required
    assert result.error_code == ErrorCode.CONNECT_BUTTON_NOT_FOUND.value
    assert clicks(events) == []


def test_1c_the_fill_never_touches_the_clipboard():
    """WM_SETTEXT delivers straight to the control — no clipboard, nothing to
    restore.  Structural: no clipboard primitive is *named in the code* (the
    docstring may mention the word to explain the absence)."""
    tree = ast.parse(open(aw.__file__, encoding="utf-8").read())
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    for banned in ("copy_to_clipboard", "read_clipboard", "clipboard",
                   "OpenClipboard", "SetClipboardText"):
        assert banned not in names, banned


# ══════════════════════════════════════════════════════════════════════════
# 2. No auth window on screen
# ══════════════════════════════════════════════════════════════════════════

def test_2_no_auth_window_sends_nothing_and_falls_through():
    result, events, _ = run_creds(hwnds=())          # nothing for the finder
    assert not result.located and not result.blocked and not result.cancelled
    assert not result.any_secret_sent
    assert sets(events) == [] and clicks(events) == []


def test_2b_a_window_with_one_edit_is_not_the_credentials_window():
    # A single edit control fails the locate step's own ``>= 2`` test (the
    # legacy ``len(edits) >= 2``), so no window is located and nothing is sent.
    msg = FakeMessages(controls=[WindowControl(E_USER, EDIT, ""),
                                 WindowControl(B_CONNECT, BUTTON, "Connect")])
    result, events, _ = run_creds(messages=msg)
    assert not result.located and not result.any_secret_sent
    assert secret_sets(events) == []


# ══════════════════════════════════════════════════════════════════════════
# 3–6. The window or its controls cannot be trusted
# ══════════════════════════════════════════════════════════════════════════

def test_3_an_unverified_hwnd_is_never_a_candidate():
    # window_pid 0 → owner unverifiable → the finder yields nothing verified.
    desktop = auth_desktop(windows=auth_windows(pid=0))
    result, events, _ = run_creds(desktop=desktop)
    assert not result.located and not result.any_secret_sent
    assert sets(events) == [] and clicks(events) == []


def test_4_a_pid_change_before_acquire_blocks_before_any_secret():
    desktop = OwnerFlipDesktop(flip_after=1, windows=auth_windows(),
                               foreground=lambda n: AUTH_HWND)
    result, events, tr = run_creds(desktop=desktop)
    assert result.blocked and result.blocked_at == aw.PHASE_ACQUIRE
    assert not result.any_secret_sent
    assert sets(events) == [] and clicks(events) == []
    assert result.error_code == ErrorCode.TARGET_WINDOW_UNTRUSTED.value


def test_5_an_executable_outside_a_trusted_dir_gets_nothing():
    desktop = auth_desktop(images={FORTI_PID: r"C:\Users\Public\FortiClient.exe",
                                   EVIL_PID: EVIL_EXE})
    result, events, _ = run_creds(desktop=desktop)
    assert not result.located and not result.any_secret_sent
    assert sets(events) == []


def test_6_a_control_owned_by_another_process_condemns_the_window():
    windows = auth_windows()
    windows[B_CANCEL] = (EVIL_PID, 55, AUTH_HWND)     # a foreign button
    result, events, _ = run_creds(desktop=auth_desktop(windows=windows))
    assert result.blocked and result.blocked_at == aw.PHASE_CONTROLS
    assert not result.any_secret_sent
    assert sets(events) == [] and clicks(events) == []


def test_6b_a_control_reparented_to_another_window_blocks_the_fill():
    windows = auth_windows()
    windows[E_PASS] = (FORTI_PID, 55, OTHER)          # same process, other root
    result, events, _ = run_creds(desktop=auth_desktop(windows=windows))
    assert result.blocked and not result.any_secret_sent


# ══════════════════════════════════════════════════════════════════════════
# 7. Foreground/target lost between the login and the password
# ══════════════════════════════════════════════════════════════════════════

def test_7_target_lost_after_login_keeps_the_password_home():
    desktop = auth_desktop()

    def lose_foreground():
        desktop._foreground = lambda n: OTHER          # somebody else in front

    msg = MessagesThatDisturb(on_login=lose_foreground)
    result, events, tr = run_creds(desktop=desktop, messages=msg)

    assert result.login_sent, "login zdążył wyjść przed utratą okna"
    assert not result.password_sent and result.blocked
    assert result.blocked_at == aw.PHASE_PASSWORD
    assert sets(events) == [(E_USER, LOGIN)], "hasło nie zostało wysłane"
    assert clicks(events) == [], "Connect nie jest klikany po zablokowaniu"
    assert PASSWORD not in [t for _h, t in sets(events)]


def test_7b_owner_change_after_login_blocks_the_password():
    desktop = auth_desktop()

    def steal_owner():
        desktop.images[FORTI_PID] = EVIL_EXE

    msg = MessagesThatDisturb(on_login=steal_owner)
    result, events, _ = run_creds(desktop=desktop, messages=msg)
    assert result.login_sent and not result.password_sent and result.blocked
    assert secret_sets(events) == [LOGIN]
    assert clicks(events) == []


# ══════════════════════════════════════════════════════════════════════════
# 8. Minimised window is refused (require_visible + raise_window=False)
# ══════════════════════════════════════════════════════════════════════════

def test_8_a_minimised_auth_window_gets_no_credentials():
    desktop = auth_desktop(iconic=True)
    result, events, _ = run_creds(desktop=desktop)
    assert result.blocked and result.blocked_at == aw.PHASE_ACQUIRE
    assert not result.any_secret_sent
    assert sets(events) == [] and clicks(events) == []


def test_8b_the_credentials_target_is_strict_about_visibility():
    """It uses the main-window contract, not the token path's."""
    prov = provider()
    target = prov.auth_credentials_target(api=FakeDesktop())
    assert target._require_visible is True
    assert target._raise_window is False
    # The token path is left exactly as it was.
    token_target = prov.auth_window_target(api=FakeDesktop())
    assert token_target._require_visible is False
    assert token_target._raise_window is True


# ══════════════════════════════════════════════════════════════════════════
# 9–11. Cancellation before the login, between login and password, before Connect
# ══════════════════════════════════════════════════════════════════════════

def test_9_cancel_before_the_login_sends_nothing():
    token = CancellationToken()
    token.cancel()
    result, events, tr = run_creds(cancellation=token)
    assert result.cancelled and result.blocked_at == aw.PHASE_LOCATE
    assert result.error_code == ErrorCode.CANCELLED.value
    assert not result.any_secret_sent
    assert sets(events) == [] and clicks(events) == []


def test_10_cancel_between_login_and_password_keeps_the_password_home():
    token = CancellationToken()
    msg = MessagesThatDisturb(on_login=token.cancel)
    result, events, _ = run_creds(cancellation=token, messages=msg)

    assert result.cancelled and result.blocked_at == aw.PHASE_PASSWORD
    assert result.login_sent and not result.password_sent
    assert secret_sets(events) == [LOGIN]
    assert clicks(events) == []


def test_11_cancel_before_connect_fills_both_but_does_not_submit():
    token = CancellationToken()
    msg = MessagesThatDisturb(on_password=token.cancel)
    result, events, _ = run_creds(cancellation=token, messages=msg)

    assert result.cancelled and result.blocked_at == aw.PHASE_CONNECT_CLICK
    assert result.login_sent and result.password_sent
    assert not result.submitted
    assert clicks(events) == [], "Connect nie jest klikany po anulowaniu"


# ══════════════════════════════════════════════════════════════════════════
# 12. No secret in the trace or the result
# ══════════════════════════════════════════════════════════════════════════

def test_12_no_secret_reaches_the_trace_or_the_result():
    tr = RecTrace()
    result, _events, tr = run_creds(trace=tr)
    blob = repr(tr.steps) + repr(result)
    for secret in SECRETS:
        assert secret not in blob, secret


def test_12b_blocked_and_cancelled_paths_also_keep_secrets_out():
    for kwargs in (dict(cancellation=_cancelled_token()),
                   dict(desktop=auth_desktop(iconic=True))):
        tr = RecTrace()
        result, _events, tr = run_creds(trace=tr, **kwargs)
        blob = repr(tr.steps) + repr(result)
        for secret in SECRETS:
            assert secret not in blob, (kwargs, secret)


def _cancelled_token():
    token = CancellationToken()
    token.cancel()
    return token


# ══════════════════════════════════════════════════════════════════════════
# 13. No Connect (the WM_SETTEXT equivalent of "no Enter") after any block
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("scenario", [
    "minimised", "foreign-control", "pid-change", "login-then-loss",
    "cancel-before-login", "cancel-between", "cancel-before-connect",
])
def test_13_no_connect_click_after_any_block(scenario):
    token = None
    desktop = None
    messages = None

    if scenario == "minimised":
        desktop = auth_desktop(iconic=True)
    elif scenario == "foreign-control":
        windows = auth_windows()
        windows[B_CANCEL] = (EVIL_PID, 55, AUTH_HWND)
        desktop = auth_desktop(windows=windows)
    elif scenario == "pid-change":
        desktop = OwnerFlipDesktop(flip_after=1, windows=auth_windows(),
                                   foreground=lambda n: AUTH_HWND)
    elif scenario == "login-then-loss":
        desktop = auth_desktop()
        messages = MessagesThatDisturb(
            on_login=lambda: setattr(desktop, "_foreground", lambda n: OTHER))
    elif scenario == "cancel-before-login":
        token = _cancelled_token()
    elif scenario == "cancel-between":
        token = CancellationToken()
        messages = MessagesThatDisturb(on_login=token.cancel)
    elif scenario == "cancel-before-connect":
        token = CancellationToken()
        messages = MessagesThatDisturb(on_password=token.cancel)

    result, events, _ = run_creds(desktop=desktop, messages=messages,
                                  cancellation=token)
    assert clicks(events) == [], (scenario, events)
    assert result.submitted is False


# ══════════════════════════════════════════════════════════════════════════
# Structure: every send is inside a guard; nothing bypasses run_guarded
# ══════════════════════════════════════════════════════════════════════════

def test_the_sends_happen_only_inside_run_guarded():
    tree = ast.parse(open(aw.__file__, encoding="utf-8").read())
    sending = {"set_control_text", "click_button"}

    class Visitor(ast.NodeVisitor):
        def __init__(self):
            self.guarded, self.bare = [], []
            self._depth = 0

        def visit_Lambda(self, node):
            self._depth += 1
            self.generic_visit(node)
            self._depth -= 1

        def visit_Call(self, node):
            func = node.func
            if isinstance(func, ast.Attribute) and func.attr in sending:
                (self.guarded if self._depth else self.bare).append(func.attr)
            self.generic_visit(node)

    visitor = Visitor()
    visitor.visit(tree)
    assert visitor.bare == [], f"wysyłka poza guardem: {visitor.bare}"
    assert set(visitor.guarded) == sending


def test_the_guarded_send_lists_the_controls_it_touches():
    source = open(aw.__file__, encoding="utf-8").read()
    assert "controls=guarded" in source
    assert "guarded = [login_field.hwnd, password_field.hwnd]" in source


def test_the_module_does_not_import_win32_or_the_legacy():
    tree = ast.parse(open(aw.__file__, encoding="utf-8").read())
    modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)
               and n.level == 0}
    modules |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import)
                for a in n.names}
    for forbidden in ("ctypes", "win32gui", "win32con", "subprocess",
                      "vpn_connect"):
        assert not any(m and m.split(".")[0] == forbidden for m in modules), forbidden
