"""Stage 15: the migrated FortiClient second factor (EMS window + CLI stdin).

Proves the negative — a token leaves the application only into a confirmed,
focused, trusted FortiClient authentication window, or into the stdin of a
verified FortiClient process — and that the happy paths still fill the field
and press Connect.

Everything is a seam: a fake desktop (:class:`WindowApi`) that also owns the
child controls, a fake :class:`WindowMessageSystem` that records every
``WM_SETTEXT`` / ``BM_CLICK``, a fake process channel, a recording trace.  No
real window, message, process, pipe or FortiClient.
"""

import ast
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import vpn  # noqa: E402
import vpn_connect  # noqa: E402
from vpn import TwoFactorMode, TwoFactorStatus, VpnRequest  # noqa: E402
from vpn.providers import FortiClientProvider  # noqa: E402
from vpn.providers import forticlient_2fa as f2  # noqa: E402
from vpn.providers.window_message_system import (  # noqa: E402
    BUTTON, EDIT, WindowControl, WindowMessageSystem, is_connect_button,
)
from tests.test_vpn_forticlient_detect import FakeEnvironment  # noqa: E402
from tests.test_vpn_secure_target import (  # noqa: E402
    EVIL_EXE, EVIL_PID, FORTI_DIR, FORTI_GUI, FORTI_PID, OTHER, FakeDesktop,
    ListFinder,
)

TOKEN = "845217"
LOGIN, PASSWORD = "jkowalski", "SuperSecret123"
SECRETS = (TOKEN, LOGIN, PASSWORD)

AUTH_HWND = 0x3003
E_USER, E_PASS, E_TOKEN = 0x3101, 0x3102, 0x3103
B_CONNECT, B_CANCEL = 0x3201, 0x3202
CONTROL_HWNDS = (E_USER, E_PASS, E_TOKEN, B_CONNECT, B_CANCEL)

CONTROLS = [
    WindowControl(E_USER, EDIT, ""),
    WindowControl(E_PASS, EDIT, ""),
    WindowControl(E_TOKEN, EDIT, ""),
    WindowControl(B_CONNECT, BUTTON, "Connect"),
    WindowControl(B_CANCEL, BUTTON, "Cancel"),
]


def auth_windows(pid=FORTI_PID, root=AUTH_HWND, controls=CONTROL_HWNDS):
    """Desktop map: the auth window plus its child controls, all one process."""
    windows = {AUTH_HWND: (pid, 55, AUTH_HWND), OTHER: (EVIL_PID, 99, OTHER)}
    for control in controls:
        windows[control] = (pid, 55, root)
    return windows


def auth_desktop(**kwargs):
    kwargs.setdefault("windows", auth_windows())
    kwargs.setdefault("foreground", lambda n: AUTH_HWND)
    return FakeDesktop(**kwargs)


def fg_lost_after(n):
    """Foreground is the auth window for the first `n` checks, then not."""
    return lambda k: AUTH_HWND if k <= n else OTHER


class FakeMessages(WindowMessageSystem):
    """Records what would have been sent; sends nothing."""

    def __init__(self, controls=None, raise_on_set=False):
        self.controls = list(controls if controls is not None else CONTROLS)
        self.events = []
        self.raise_on_set = raise_on_set

    def enumerate_controls(self, hwnd):
        self.events.append(("enumerate", hwnd))
        return list(self.controls)

    def set_control_text(self, hwnd, text):
        if self.raise_on_set:
            raise OSError("SendMessage failed")
        self.events.append(("set_text", hwnd, text))

    def click_button(self, hwnd):
        self.events.append(("click", hwnd))

    def sleep(self, seconds):
        self.events.append(("sleep", seconds))


class FakeChannel:
    def __init__(self, pid=FORTI_PID, lines=(), raise_on_write=False):
        self.pid = pid
        self._lines = list(lines)
        self.written = []
        self.raise_on_write = raise_on_write

    def read_line(self):
        return self._lines.pop(0) if self._lines else None

    def write_line(self, text):
        if self.raise_on_write:
            raise BrokenPipeError("pipe closed")
        self.written.append(text)


class RecTrace:
    def __init__(self):
        self.steps = []

    def _add(self, name, status, **data):
        self.steps.append({"step": name, "status": status, **data})

    def ok(self, name, **data):
        self._add(name, "ok", **data)

    def warn(self, name, message=None, **data):
        self._add(name, "warn", **data)

    def fail(self, name, error_code=None, **data):
        self._add(name, "fail", error_code=error_code, **data)

    def events(self):
        return [s.get("event") for s in self.steps]


def provider():
    return FortiClientProvider(FakeEnvironment(files=[FORTI_GUI], dirs=[FORTI_DIR]))


def request(token=TOKEN, **kwargs):
    kwargs.setdefault("requires_2fa", True)
    return VpnRequest(provider_id="forticlient", login=LOGIN, password=PASSWORD,
                      token=token, **kwargs)


def run_window(*, desktop=None, messages=None, token=TOKEN, hwnds=(AUTH_HWND,),
               trace=None, **req):
    desktop = desktop if desktop is not None else auth_desktop()
    msg = messages if messages is not None else FakeMessages()
    tr = trace if trace is not None else RecTrace()
    prov = provider()
    target = prov.auth_window_target(api=desktop, finder=ListFinder(hwnds))
    result = prov.supply_two_factor(request(token, **req),
                                    mode=TwoFactorMode.AUTH_WINDOW,
                                    target=target, message_system=msg, trace=tr)
    return result, msg.events, tr


def sent_tokens(events):
    return [text for kind, _hwnd, text in
            [e for e in events if e[0] == "set_text"]]


def clicks(events):
    return [hwnd for kind, hwnd in [e for e in events if e[0] == "click"]]


# ══════════════════════════════════════════════════════════════════════════
# 1. No second factor → nothing happens
# ══════════════════════════════════════════════════════════════════════════

def test_1_no_two_factor_means_no_operation():
    msg = FakeMessages()
    result = provider().supply_two_factor(
        VpnRequest(provider_id="forticlient", requires_2fa=False, token=""),
        message_system=msg, target=object())
    assert result.status is TwoFactorStatus.NOT_REQUIRED
    assert result.success and result.mode is TwoFactorMode.NONE
    assert result.submitted is False
    assert msg.events == [], "nic nie dotknęło okna"


def test_1b_mode_is_derived_from_the_request_when_not_given():
    prov = provider()
    assert prov.two_factor_mode(VpnRequest(provider_id="forticlient")) \
        is TwoFactorMode.NONE
    assert prov.two_factor_mode(request()) is TwoFactorMode.AUTH_WINDOW
    assert prov.two_factor_mode(request(autofill=False)) is TwoFactorMode.IN_CLIENT
    assert prov.two_factor_mode(request(), route="cli_monitored",
                                monitor_available=True) \
        is TwoFactorMode.PROCESS_STDOUT


# ══════════════════════════════════════════════════════════════════════════
# 2 + 14. The EMS window happy path
# ══════════════════════════════════════════════════════════════════════════

def test_2_verified_window_receives_the_token_and_connect_is_pressed():
    result, events, tr = run_window()
    assert result.status is TwoFactorStatus.SUBMITTED and result.success
    assert result.submitted and not result.manual_submit_required
    assert sent_tokens(events) == [TOKEN]
    assert [e for e in events if e[0] == "set_text"][0][1] == E_TOKEN, \
        "token idzie do OSTATNIEGO pola Edit, jak w legacy"
    assert clicks(events) == [B_CONNECT]
    for expected in ("two-factor-detected", "EMS-window-found",
                     "EMS-target-verified", "token-submit-start",
                     "token-submit-success"):
        assert expected in tr.events(), expected


def test_14_token_field_and_button_choice_match_the_legacy():
    """Legacy: edits[-1] is the token field; the button is 'onnect' not Cancel."""
    legacy = _legacy_source("fill_forticlient_token")
    assert "edits[-1][0]" in legacy
    assert '"onnect" in btn_text and "Cancel" not in btn_text' in legacy
    assert is_connect_button("Connect") and is_connect_button("connect")
    assert not is_connect_button("Cancel") and not is_connect_button("Close")
    # ...and the same minimum number of edit controls guards the same field.
    assert "len(edits) < 3" in legacy and f2.MIN_TOKEN_EDITS == 3


def test_14b_window_timeout_is_unchanged():
    assert f2.TOKEN_WINDOW_TIMEOUT_S == 15.0
    assert "timeout: float = 15.0" in _legacy_source("fill_forticlient_token")
    assert f2.WINDOW_POLL_INTERVAL_S == 0.5
    assert "time.sleep(0.5)" in _legacy_source("_find_forti_auth_window")


def test_2b_too_few_edit_controls_sends_nothing():
    msg = FakeMessages(controls=[WindowControl(E_USER, EDIT, ""),
                                 WindowControl(E_PASS, EDIT, ""),
                                 WindowControl(B_CONNECT, BUTTON, "Connect")])
    result, events, _ = run_window(messages=msg)
    assert result.status is TwoFactorStatus.FAILED
    assert result.error_code == "otp-field-not-found"
    assert sent_tokens(events) == [] and clicks(events) == []


def test_2c_no_connect_button_leaves_the_submit_to_the_user():
    msg = FakeMessages(controls=[c for c in CONTROLS if c.hwnd != B_CONNECT])
    result, events, _ = run_window(messages=msg)
    assert result.status is TwoFactorStatus.SUBMITTED and result.submitted
    assert result.manual_submit_required is True
    assert result.error_code == "connect-button-not-found"
    assert sent_tokens(events) == [TOKEN] and clicks(events) == []


# ══════════════════════════════════════════════════════════════════════════
# 3–7. Everything that must stop the token
# ══════════════════════════════════════════════════════════════════════════

def test_3_foreign_process_window_gets_no_token():
    desktop = auth_desktop(images={FORTI_PID: EVIL_EXE, EVIL_PID: EVIL_EXE})
    result, events, _ = run_window(desktop=desktop)
    assert result.status is TwoFactorStatus.FAILED
    assert result.error_code == "otp-window-not-found"
    assert sent_tokens(events) == [] and clicks(events) == []


def test_3b_a_window_of_another_process_is_never_a_candidate():
    result, events, _ = run_window(hwnds=(OTHER,))
    assert result.status is TwoFactorStatus.FAILED
    assert sent_tokens(events) == []


@pytest.mark.parametrize("pid", [0, -1, None, "4100"])
def test_4_bad_pid_gets_no_token(pid):
    desktop = auth_desktop(windows=auth_windows(pid=pid))
    result, events, _ = run_window(desktop=desktop)
    assert result.status is TwoFactorStatus.FAILED
    assert sent_tokens(events) == []


def test_5_owner_change_before_the_send_blocks_the_token():
    desktop = auth_desktop()
    original = desktop._foreground

    def swap_owner(n):
        # The submit guard re-confirms on check 2; by then the window belongs
        # to somebody else.
        if n == 2:
            desktop.images[FORTI_PID] = EVIL_EXE
        return original(n)

    desktop._foreground = swap_owner
    result, events, tr = run_window(desktop=desktop)
    assert result.status is TwoFactorStatus.BLOCKED
    assert result.blocked_at == "submit"
    assert sent_tokens(events) == [] and clicks(events) == []
    assert "token-submit-blocked" in tr.events()


def test_6_foreground_lost_before_the_send_blocks_the_token():
    result, events, tr = run_window(desktop=auth_desktop(foreground=fg_lost_after(1)))
    assert result.status is TwoFactorStatus.BLOCKED
    assert result.blocked_at == "submit"
    assert sent_tokens(events) == [] and clicks(events) == []


def test_6b_focus_never_acquired_blocks_before_anything_is_read():
    result, events, _ = run_window(desktop=auth_desktop(foreground=fg_lost_after(0)))
    assert result.status is TwoFactorStatus.BLOCKED
    assert result.blocked_at == "acquire"
    assert sent_tokens(events) == []


def test_6c_foreground_lost_after_the_token_stops_the_connect_click():
    result, events, _ = run_window(desktop=auth_desktop(foreground=fg_lost_after(2)))
    assert result.status is TwoFactorStatus.SUBMITTED
    assert result.manual_submit_required is True
    assert sent_tokens(events) == [TOKEN]
    assert clicks(events) == [], "Connect nie jest klikany po utracie okna"


def test_7_a_control_that_changes_hands_blocks_the_token():
    desktop = auth_desktop()
    original = desktop._foreground

    def swap_control(n):
        if n == 2:                       # right before the WM_SETTEXT
            desktop.windows[E_TOKEN] = (EVIL_PID, 55, AUTH_HWND)
        return original(n)

    desktop._foreground = swap_control
    result, events, _ = run_window(desktop=desktop)
    assert result.status is TwoFactorStatus.BLOCKED
    assert result.blocked_at == "submit"
    assert sent_tokens(events) == []


def test_7b_a_foreign_control_anywhere_condemns_the_whole_window():
    """Legacy rule: one Edit/Button of another process and the window is out."""
    windows = auth_windows()
    windows[B_CANCEL] = (EVIL_PID, 55, AUTH_HWND)
    result, events, _ = run_window(desktop=auth_desktop(windows=windows))
    assert result.status is TwoFactorStatus.BLOCKED
    assert result.blocked_at == "controls"
    assert sent_tokens(events) == []
    legacy = _legacy_source("_find_forti_auth_window")
    assert "control-not-owned-by-target" in legacy


def test_7c_a_control_reparented_to_another_window_blocks_the_token():
    windows = auth_windows()
    windows[E_TOKEN] = (FORTI_PID, 55, OTHER)      # same process, other window
    result, events, _ = run_window(desktop=auth_desktop(windows=windows))
    assert result.status is TwoFactorStatus.BLOCKED
    assert sent_tokens(events) == []


# ══════════════════════════════════════════════════════════════════════════
# 8. Revalidation immediately before WM_SETTEXT
# ══════════════════════════════════════════════════════════════════════════

def test_8_the_target_is_reconfirmed_in_the_same_breath_as_the_send():
    desktop = auth_desktop()
    run_window(desktop=desktop)
    # acquire + submit guard + click guard — each re-reads the foreground.
    assert desktop.fg_checks == 3


def test_8b_the_send_happens_only_inside_run_guarded():
    """Structurally: no call to the message seam outside a guard callback."""
    tree = ast.parse(open(f2.__file__, encoding="utf-8").read())
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


def test_8c_guarded_send_lists_the_controls_it_is_about_to_touch():
    """The submit guard re-checks control ownership, not just the window."""
    source = open(f2.__file__, encoding="utf-8").read()
    assert "controls=guarded" in source
    assert "guarded = [token_field.hwnd] + [b.hwnd for b in buttons]" in source


# ══════════════════════════════════════════════════════════════════════════
# 9 + 10. No window, manual authentication
# ══════════════════════════════════════════════════════════════════════════

def test_9_no_window_is_a_safe_result_not_an_exception():
    result, events, tr = run_window(hwnds=())
    assert result.status is TwoFactorStatus.FAILED
    assert result.error_code == "otp-window-not-found"
    assert result.blocked_at == "locate"
    assert result.success is False and sent_tokens(events) == []
    assert "token-submit-failure" in tr.events()


def test_9b_the_window_is_polled_for_the_legacy_timeout():
    msg = FakeMessages()
    run_window(messages=msg, hwnds=())
    sleeps = [s for kind, s in [e for e in msg.events if e[0] == "sleep"]]
    assert len(sleeps) == 29 and set(sleeps) == {0.5}, "15 s co 0.5 s"


def test_10_manual_authentication_sends_nothing():
    msg = FakeMessages()
    result = provider().supply_two_factor(request(autofill=False),
                                          message_system=msg, target=object())
    assert result.status is TwoFactorStatus.MANUAL_REQUIRED
    assert result.mode is TwoFactorMode.IN_CLIENT
    assert result.submitted is False and result.success is False
    assert result.error_code == "manual-action-required"
    assert msg.events == []


def test_10b_without_a_token_nothing_is_sent_and_the_caller_is_told():
    result, events, tr = run_window(token="")
    assert result.status is TwoFactorStatus.TOKEN_REQUIRED
    assert result.submitted is False and events == []
    assert "manual-auth-required" in tr.events()


def test_10c_a_stdout_mode_without_a_channel_is_manual_not_a_crash():
    result = provider().supply_two_factor(request(),
                                          mode=TwoFactorMode.PROCESS_STDOUT)
    assert result.status is TwoFactorStatus.MANUAL_REQUIRED
    assert result.metadata["reason_code"] == "no-channel"


# ══════════════════════════════════════════════════════════════════════════
# 11. The monitored CLI path
# ══════════════════════════════════════════════════════════════════════════

def test_11_cli_challenge_is_detected_and_answered_on_stdin():
    channel = FakeChannel(lines=["Connecting...\n", "Please enter your token:\n"])
    tr = RecTrace()
    watch = f2.watch_for_challenge(channel, trace=tr)
    assert watch.detected and watch.lines_read == 2 and not watch.ended

    result = provider().supply_two_factor(
        request(), mode=TwoFactorMode.PROCESS_STDOUT, channel=channel,
        api=auth_desktop(), trace=tr)
    assert result.status is TwoFactorStatus.SUBMITTED and result.success
    assert result.mode is TwoFactorMode.PROCESS_STDOUT and result.submitted
    assert channel.written == [TOKEN]
    assert "two-factor-detected" in tr.events()
    assert "token-submit-success" in tr.events()


def test_11b_prompt_vocabulary_is_identical_to_the_legacy():
    assert f2._2FA_PATTERNS.pattern == vpn_connect._2FA_PATTERNS.pattern
    assert f2._2FA_PATTERNS.flags == vpn_connect._2FA_PATTERNS.flags
    for line in ("Please enter your token:", "2FA code required",
                 "Enter verification code", "approve the request on your phone"):
        assert f2.is_two_factor_prompt(line) is vpn_connect.is_2fa_prompt(line)
    assert not f2.is_two_factor_prompt("Connecting to gateway")


def test_11c_stdout_that_never_asks_ends_without_a_challenge():
    watch = f2.watch_for_challenge(FakeChannel(lines=["a\n", "b\n"]))
    assert not watch.detected and watch.ended and watch.lines_read == 2


def test_11d_an_unverified_process_gets_no_token():
    desktop = auth_desktop(images={FORTI_PID: EVIL_EXE})
    channel = FakeChannel(pid=FORTI_PID)
    result = provider().supply_two_factor(
        request(), mode=TwoFactorMode.PROCESS_STDOUT, channel=channel,
        api=desktop)
    assert result.status is TwoFactorStatus.BLOCKED
    assert result.blocked_at == "process"
    assert result.metadata["reason_code"] == "untrusted-image"
    assert channel.written == []


@pytest.mark.parametrize("pid,reason", [
    (None, "no-process"), (0, "no-process"), (-5, "no-process"),
    (True, "no-process"), (9999, "image-unavailable"),
])
def test_11e_a_process_that_cannot_be_verified_gets_no_token(pid, reason):
    channel = FakeChannel(pid=pid)
    result = provider().supply_two_factor(
        request(), mode=TwoFactorMode.PROCESS_STDOUT, channel=channel,
        api=auth_desktop())
    assert result.status is TwoFactorStatus.BLOCKED
    assert result.metadata["reason_code"] == reason
    assert channel.written == []


def test_11f_a_failed_write_is_reported_not_swallowed():
    channel = FakeChannel(raise_on_write=True)
    result = provider().supply_two_factor(
        request(), mode=TwoFactorMode.PROCESS_STDOUT, channel=channel,
        api=auth_desktop())
    assert result.status is TwoFactorStatus.FAILED
    assert result.error_code == "cli-failed"
    assert result.submitted is False
    assert result.metadata["reason_code"] == "BrokenPipeError"


# ══════════════════════════════════════════════════════════════════════════
# 12 + 13. The token never escapes
# ══════════════════════════════════════════════════════════════════════════

def test_12_no_secret_reaches_the_trace():
    scenarios = [
        dict(),                                                  # success
        dict(desktop=auth_desktop(images={FORTI_PID: EVIL_EXE})),
        dict(desktop=auth_desktop(foreground=fg_lost_after(1))),
        dict(hwnds=()),
        dict(token=""),
    ]
    for kwargs in scenarios:
        _result, _events, tr = run_window(**kwargs)
        blob = str(tr.steps)
        for secret in SECRETS:
            assert secret not in blob, (secret, kwargs)


def test_12b_the_process_path_keeps_the_token_out_of_the_trace():
    tr = RecTrace()
    provider().supply_two_factor(request(), mode=TwoFactorMode.PROCESS_STDOUT,
                                channel=FakeChannel(), api=auth_desktop(), trace=tr)
    f2.watch_for_challenge(FakeChannel(lines=[f"Enter token: {TOKEN}\n"]), trace=tr)
    blob = str(tr.steps)
    for secret in SECRETS:
        assert secret not in blob, secret


def test_12c_the_challenge_line_itself_is_never_kept():
    watch = f2.watch_for_challenge(
        FakeChannel(lines=[f"Enter code (user {LOGIN} pass {PASSWORD}):\n"]))
    assert watch.detected
    blob = repr(watch) + str(getattr(watch, "__dict__", {}))
    for secret in SECRETS:
        assert secret not in blob
    assert not hasattr(watch, "line"), "linia stdout nie jest przechowywana"


def test_13_no_result_carries_a_token():
    results = [
        run_window()[0],
        run_window(desktop=auth_desktop(foreground=fg_lost_after(1)))[0],
        run_window(hwnds=())[0],
        run_window(token="")[0],
        provider().supply_two_factor(request(autofill=False)),
        provider().supply_two_factor(request(), mode=TwoFactorMode.PROCESS_STDOUT,
                                     channel=FakeChannel(), api=auth_desktop()),
    ]
    for result in results:
        blob = f"{result!r} {result.to_trace_data()} {result.metadata}"
        for secret in SECRETS:
            assert secret not in blob, (secret, result.status)


def test_13b_a_result_refuses_to_carry_a_credential_at_all():
    from vpn import SecretInResultError, TwoFactorResult
    with pytest.raises(SecretInResultError):
        TwoFactorResult(provider_id="forticlient", metadata={"token": TOKEN})


# ══════════════════════════════════════════════════════════════════════════
# Seam failures, bare handles, isolation
# ══════════════════════════════════════════════════════════════════════════

def test_a_raising_message_seam_ends_the_attempt_without_a_click():
    result, events, tr = run_window(messages=FakeMessages(raise_on_set=True))
    assert result.status is TwoFactorStatus.FAILED
    assert result.error_code == "automation-failed"
    assert result.metadata["reason_code"] == "OSError"
    assert clicks(events) == [], "Connect nie leci po nieudanym wpisaniu"


def test_a2_a_raising_enumeration_is_a_controlled_failure():
    class Boom(FakeMessages):
        def enumerate_controls(self, hwnd):
            raise OSError("EnumChildWindows failed")

    result, _events, _tr = run_window(messages=Boom())
    assert result.status is TwoFactorStatus.FAILED
    assert result.blocked_at == "locate"
    assert result.metadata["reason_code"] == "OSError"


def test_a3_a_raising_read_ends_the_watch_without_a_challenge():
    class Boom(FakeChannel):
        def read_line(self):
            raise OSError("pipe broken")

    watch = f2.watch_for_challenge(Boom())
    assert not watch.detected and watch.ended


def test_two_factor_never_takes_a_window_handle_from_its_caller():
    import inspect
    for function in (f2.submit_token_to_window, f2.supply_token):
        params = set(inspect.signature(function).parameters)
        assert not ({"hwnd", "handle", "window"} & params), function.__name__
    # ...and the only way in is a SecureWindowTarget.
    result = provider().supply_two_factor(request(), mode=TwoFactorMode.AUTH_WINDOW,
                                          target=_TargetWithoutCandidates(),
                                          message_system=FakeMessages())
    assert result.status is TwoFactorStatus.FAILED


class _TargetWithoutCandidates:
    def first_verified_candidate(self):
        return None

    def acquire(self, hwnd):                     # pragma: no cover - never called
        raise AssertionError("nie wolno przejmować okna bez kandydata")


def test_the_auth_window_target_is_not_the_main_window_target():
    prov = provider()
    main = prov.secure_window_target(api=auth_desktop())
    auth = prov.auth_window_target(api=auth_desktop())
    assert main._finder._must_contain == ("FortiClient",)
    assert main._finder._must_not_contain == "Authentication"
    assert auth._finder._must_contain == ("FortiClient", "Authentication")
    assert auth._finder._must_not_contain is None
    # ...and it is the legacy's own title filter, word for word.
    legacy = _legacy_source("_find_forti_auth_window")
    assert '"FortiClient" in title and "Authentication" in title' in legacy


def test_the_two_factor_module_reaches_for_no_win32_of_its_own():
    tree = ast.parse(open(f2.__file__, encoding="utf-8").read())
    modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    modules |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import)
                for a in n.names}
    assert "vpn_connect" not in modules
    assert not any(m and m.split(".")[0] in ("win32gui", "win32con", "ctypes",
                                             "subprocess")
                   for m in modules), modules
    # ...and it names none of the machinery either — prose in the docstring
    # explains it, the code never touches it.
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)} | {
        n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    for banned in ("WM_SETTEXT", "BM_CLICK", "SendMessage", "EnumChildWindows"):
        assert banned not in names, banned


def test_win32_seams_are_the_only_message_or_process_modules_in_vpn():
    """win32gui lives in the window-message seam alone."""
    vpn_dir = os.path.join(_PARENT, "vpn")
    importers = set()
    for root, _dirs, files in os.walk(vpn_dir):
        for name in files:
            if not name.endswith(".py"):
                continue
            path = os.path.join(root, name)
            tree = ast.parse(open(path, encoding="utf-8").read())
            for node in ast.walk(tree):
                mods = ([a.name for a in node.names] if isinstance(node, ast.Import)
                        else [node.module] if isinstance(node, ast.ImportFrom)
                        and node.level == 0 and node.module else [])
                if any(m.split(".")[0] in ("win32gui", "win32con") for m in mods):
                    importers.add(os.path.relpath(path, _PARENT))
    assert importers == {os.path.join("vpn", "providers",
                                      "window_message_system.py")}


def test_caveats_are_named_and_not_silently_dropped():
    names = {name for name, _ in f2.TWO_FACTOR_CAVEATS}
    assert {"window-focus-required", "process-image-verified",
            "no-token-acceptance-signal", "cli-token-is-a-launch-argument"} <= names
    for _name, description in f2.TWO_FACTOR_CAVEATS:
        assert len(description) > 40


def test_rejected_is_reserved_because_nothing_confirms_a_token():
    """No migrated path can honestly say a token was refused — so none does."""
    tree = ast.parse(open(f2.__file__, encoding="utf-8").read())
    used = {n.attr for n in ast.walk(tree)
            if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
            and n.value.id == "TwoFactorStatus"}
    assert "REJECTED" not in used, used
    assert TwoFactorStatus.REJECTED.value == "rejected"


# ══════════════════════════════════════════════════════════════════════════
# Production still runs the legacy
# ══════════════════════════════════════════════════════════════════════════

def _legacy_source(name):
    source = open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read()
    tree = ast.parse(source)
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == name:
            return ast.get_source_segment(source, node)
    raise AssertionError(f"brak {name} w vpn_connect.py")


def test_legacy_two_factor_is_untouched_and_still_the_one_in_use():
    legacy = open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read()
    assert "def fill_forticlient_token(" in legacy
    assert "def is_2fa_prompt(" in legacy
    assert "def _find_forti_auth_window(" in legacy
    # Nothing outside vpn/ and the tests even names the new path.
    for root, dirs, files in os.walk(_PARENT):
        dirs[:] = [d for d in dirs
                   if d not in ("vpn", "tests", "smoke", "__pycache__",
                                ".pytest_cache")]
        for name in files:
            if not name.endswith(".py"):
                continue
            text = open(os.path.join(root, name), encoding="utf-8",
                        errors="replace").read()
            for banned in ("supply_two_factor", "forticlient_2fa",
                           "auth_window_target"):
                assert banned not in text, (name, banned)
    detail = open(os.path.join(_PARENT, "ui", "detail_panel.py"), encoding="utf-8").read()
    assert "vpn_connect.fill_forticlient_token(dlg.code())" in detail
    panel = open(os.path.join(_PARENT, "ui", "vpn_panel.py"), encoding="utf-8").read()
    assert "vpn_connect.is_2fa_prompt(line)" in panel


def test_the_registered_provider_still_refuses_to_connect():
    result = vpn.default_registry.get("forticlient").connect(
        VpnRequest(provider_id="forticlient"))
    assert result.success is False and result.error_code == "unsupported"
