"""Stage 26 part B: the flow looks once more before it reaches for the window.

Stage 22 made the connect wait for the user to bring FortiClient forward.
Stage 24 then measured what nobody had asked: how long the gap is between that
answer and the first secret.  It is seconds — a whole navigation sequence — and
Stage 25 proved that nothing looked at the desktop in between.  The first thing
that did look was ``acquire_focus``, and it looks *after* restoring and raising
the window, so a user who had just put the client away got it pushed back in
their face and their password typed into it.

Stage 26 reproduced the sharper version on the real desktop: gate says yes,
the operator clicks another window, and a foreign process holds the foreground.

The fix is one reading, in the one place where the flow knows an activation was
observed and has not yet touched the machine:
``FortiConnectSystem.activation_still_holds``.  These tests are about what that
reading must be — strict, read-only, and incapable of standing in for the
guards that follow it.

What it deliberately does **not** do
------------------------------------
It closes the gap between the gate and the *start* of the autofill.  It says
nothing about the user minimising the client halfway through the fill; the
per-operation guards own that, and they still use ``confirm_target``, which
ignores ``is_iconic`` (Stage 25, ``test_2``).  That remains open and is not
touched here.
"""

import ast
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import secure_window as sw  # noqa: E402
from vpn import AutofillStatus, AutomationMode, ErrorCode  # noqa: E402
from vpn.providers import forticlient_connect as fcc  # noqa: E402
from vpn.providers.secure_target import ForegroundCheck  # noqa: E402
from tests.test_vpn_forticlient_connect_assembled import (  # noqa: E402
    FakeLaunch, FakeMessages, RecTrace, FORTI_DIR, FORTI_GUI, LOGIN, PASSWORD,
    FakeClock, ScriptedProvider, connect, desktop_with, phase_names, request,
)
from tests.test_vpn_forticlient_autofill import (  # noqa: E402
    FakeInput, forti_environment,
)
from tests.test_vpn_forticlient_detect import FakeEnvironment  # noqa: E402
from tests.test_vpn_secure_target import (  # noqa: E402
    FORTI_PID, HWND, OTHER,
)


def build(*, foreground=None, iconic=False, main_hwnds=(HWND,)):
    """The assembled connect, on a desktop whose foreground a test scripts."""
    inputs = FakeInput()
    provider = ScriptedProvider(
        environment=forti_environment(),
        main_hwnds=main_hwnds, system=FakeLaunch())
    desktop = desktop_with(foreground=foreground)
    desktop.iconic = iconic
    desktop.is_iconic = lambda hwnd: desktop.iconic
    runtime = provider.connect_runtime(
        clock=FakeClock(), launch_system=FakeLaunch(), input_system=inputs,
        window_api=desktop, message_system=FakeMessages(), trace=RecTrace(),
        activation_timeout_s=2.0, msaa_system=inputs.msaa)
    return provider, runtime, desktop, inputs


def _function(module, name):
    tree = ast.parse(open(module.__file__, encoding="utf-8").read())
    return next(n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == name)


def system_calls(module, function_name):
    """Methods called on ``self._system``, in source order.

    ``ast.walk`` is breadth-first, so it cannot answer "which came first" —
    and that is exactly the question here.  Sorting by position can.
    """
    found = []
    for node in ast.walk(_function(module, function_name)):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                and isinstance(node.func.value, ast.Attribute)
                and node.func.value.attr == "_system"):
            found.append((node.lineno, node.col_offset, node.func.attr))
    return [attr for _line, _col, attr in sorted(found)]


def code_names(node):
    """Identifiers and attributes in code — docstrings and comments excluded."""
    names = {n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)}
    return names | {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}


def secret_events(inputs):
    return [e for e in inputs.events
            if e[0] in ("type", "key", "combo", "clip_set")]


# ══════════════════════════════════════════════════════════════════════════
# 1–3. The three outcomes the reading has to tell apart
# ══════════════════════════════════════════════════════════════════════════

def test_1_the_user_switches_away_and_the_autofill_never_starts():
    """Gate says yes; the desktop has moved on by the time we look again."""
    # In front while the gate polls, somebody else's window afterwards.
    provider, runtime, _desktop, inputs = build(
        foreground=lambda n: HWND if n <= 1 else OTHER)

    result = connect(provider, runtime)

    assert fcc.PHASE_AUTOFILL not in phase_names(result)
    assert result.error_code == ErrorCode.FOCUS_FAILED.value
    assert result.automation is AutomationMode.MANUAL
    assert result.requires_user_action
    assert result.autofill is not None
    assert result.autofill.blocked_at == fcc.PHASE_AWAIT_ACTIVATION
    assert result.autofill.status is AutofillStatus.BLOCKED
    assert secret_events(inputs) == [], inputs.events


def test_2_the_client_still_in_front_lets_the_autofill_run():
    """The ordinary case has to stay ordinary — this is not a new refusal."""
    provider, runtime, _desktop, _inputs = build()

    result = connect(provider, runtime)

    names = phase_names(result)
    assert names.index(fcc.PHASE_AWAIT_ACTIVATION) < names.index(fcc.PHASE_AUTOFILL)
    assert result.error_code is None
    assert result.automation is AutomationMode.TAB_SEQUENCE


def test_3_a_minimised_client_blocks_the_autofill_too():
    """Still the foreground window, and still not somewhere a secret may go.

    This is the case ``confirm_target`` would have waved through: Windows keeps
    reporting a minimised window as the foreground, so only the ``is_iconic``
    half of the reading refuses it.
    """
    provider, runtime, desktop, inputs = build()

    calls = {"n": 0}
    original = desktop.is_iconic

    def iconic_after_the_gate(hwnd):
        calls["n"] += 1
        return calls["n"] > 1          # in front for the gate, away after

    desktop.is_iconic = iconic_after_the_gate

    result = connect(provider, runtime)

    assert fcc.PHASE_AUTOFILL not in phase_names(result)
    assert result.autofill.blocked_at == fcc.PHASE_AWAIT_ACTIVATION
    assert secret_events(inputs) == [], inputs.events
    desktop.is_iconic = original


def test_3b_the_recorded_reason_says_which_of_the_two_it_was():
    """A trace has to distinguish "they clicked away" from "they minimised it"."""
    provider, runtime, _desktop, _inputs = build(
        foreground=lambda n: HWND if n <= 1 else OTHER)
    result = connect(provider, runtime)
    step = [s for s in result.steps if s.phase == fcc.PHASE_AWAIT_ACTIVATION][-1]
    assert step.reason_code == "foreground-is-other-window", step.reason_code
    for secret in (LOGIN, PASSWORD):
        assert secret not in repr(result)


# ══════════════════════════════════════════════════════════════════════════
# 4. The reading is a reading
# ══════════════════════════════════════════════════════════════════════════

def test_4_the_check_happens_before_anything_reaches_for_the_window():
    """Order in the source: gate, re-read, autofill — and nothing in between."""
    calls = system_calls(fcc, "_gui_outcome")
    assert calls.index("await_activation") < calls.index("activation_still_holds")
    assert calls.index("activation_still_holds") < calls.index("start_autofill")
    assert calls[calls.index("activation_still_holds") + 1] == "start_autofill", calls


def test_5_the_new_check_adds_no_way_to_touch_the_desktop():
    """No new Win32 anywhere in the added path — it composes existing readings."""
    from vpn.providers import forticlient_runtime as fcr

    for module in (fcc, fcr):
        names = code_names(ast.parse(open(module.__file__,
                                          encoding="utf-8").read()))
        for banned in ("SetForegroundWindow", "set_foreground_window",
                       "ShowWindow", "SW_RESTORE", "AttachThreadInput",
                       "attach_thread_input", "SendInput", "BringWindowToTop",
                       "SetFocus", "SwitchToThisWindow", "keybd_event"):
            assert banned not in names, (module.__name__, banned)

    # And the added method itself reads, full stop.
    names = code_names(_function(fcr, "activation_still_holds"))
    assert "foreground_check" in names
    for banned in ("acquire", "acquire_any", "acquire_focus", "restore_window",
                   "release"):
        assert banned not in names, banned


def test_5b_the_runtime_asks_the_strict_reading_not_the_lenient_one():
    """`foreground_check`, not `confirm_target` — the two disagree on iconic."""
    from vpn.providers import forticlient_runtime as fcr

    names = code_names(_function(fcr, "activation_still_holds"))
    assert "confirm_target" not in names
    assert "foreground_check" in names


def test_6_a_system_that_cannot_tell_changes_nothing():
    """The default answers None, and the flow behaves exactly as before."""
    assert fcc.FortiConnectSystem().activation_still_holds(HWND) is None

    provider, runtime, _desktop, _inputs = build()
    runtime.activation_still_holds = lambda hwnd: None
    result = connect(provider, runtime)
    assert fcc.PHASE_AUTOFILL in phase_names(result)


def test_7_the_check_is_asked_about_the_window_the_gate_pinned():
    """Not "a" client window — *that* handle, the one the user activated."""
    provider, runtime, _desktop, _inputs = build()
    asked = []
    original = runtime.activation_still_holds
    runtime.activation_still_holds = lambda hwnd: (asked.append(hwnd),
                                                   original(hwnd))[1]
    connect(provider, runtime)
    assert asked == [HWND], asked


# ══════════════════════════════════════════════════════════════════════════
# 8. Everything that had to stay where it was
# ══════════════════════════════════════════════════════════════════════════

def test_8_the_legacy_path_is_untouched():
    import vpn_connect

    source = open(vpn_connect.__file__, encoding="utf-8").read()
    for token in ("activation_still_holds", "foreground_check",
                  "ActivationGate", "activation_gate"):
        assert token not in source, token

    # And the shared focus machinery still has exactly the shape Stage 25 found:
    # a restore before the confirmation, and a confirmation blind to iconic.
    focus = open(sw.__file__, encoding="utf-8").read()
    confirm = focus[focus.index("def confirm_target"):focus.index("def acquire_focus")]
    assert "is_iconic" not in confirm, \
        "confirm_target celowo NIE zostało zmienione w tym etapie"
    acquire = focus[focus.index("def acquire_focus"):focus.index("class _FocusNotes")]
    assert "restore_window" in acquire, "acquire_focus celowo bez zmian"


def test_8b_production_is_still_the_legacy_connect():
    from vpn.providers import FortiClientProvider

    assert FortiClientProvider.CONNECT_ENABLED is False
    for panel in ("vpn_panel.py", "detail_panel.py"):
        source = open(os.path.join(_PARENT, "ui", panel), encoding="utf-8").read()
        assert "activation_still_holds" not in source
        assert "vpn_connect." in source


def test_9_the_check_does_not_replace_the_guards_that_follow():
    """It permits a start; it promises nothing about the rest of the sequence.

    The autofill still acquires and still confirms before every operation, so
    a target that goes away mid-fill is refused by the guard exactly as before
    — which is the part this stage deliberately did not change.
    """
    provider, runtime, _desktop, inputs = build(
        foreground=lambda n: HWND if n <= 3 else OTHER)

    result = connect(provider, runtime)

    assert PASSWORD not in [e[1] for e in inputs.events if e[0] == "clip_set"]
    assert result.error_code is not None
