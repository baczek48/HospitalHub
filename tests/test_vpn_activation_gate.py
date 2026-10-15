"""Stage 22: waiting for the user to bring FortiClient forward.

Three stages of measurement established that a background process cannot take
the foreground from another process' window — and that the existing machinery
works perfectly once the window is already in front.  The gate changes nothing
about the mechanism; it changes when the mechanism is asked.

What these tests are really about is what the gate must *not* be: it must not
activate anything, must not know a password, and must not let its own
observation stand in for the guards.  "The window was in front a moment ago" is
permission to start, never proof to type by — so the last test in this file
forces the race and insists the refusal still comes from the guard.
"""

import ast
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import secure_window as sw  # noqa: E402
from vpn.providers import SecureWindowTarget  # noqa: E402
from vpn.providers import activation_gate as ag  # noqa: E402
from vpn.providers.activation_gate import (  # noqa: E402
    ActivationGate, ActivationState, CancellationToken, Clock,
)
from tests.test_vpn_secure_target import (  # noqa: E402
    EVIL_EXE, EVIL_PID, FORTI_DIR, FORTI_GUI, FORTI_PID, HWND, OTHER, TRUSTED,
    FakeDesktop, ListFinder,
)

FORTI_TRAY = FORTI_DIR + r"\FortiTray.exe"
SECOND_HWND, SECOND_PID = 0x9001, 7777
TRAY_HWND, TRAY_PID = 0x9002, 7778


class FakeClock(Clock):
    """Virtual time.  Nothing in this file waits a real second."""

    def __init__(self):
        self.now = 0.0
        self.slept = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.slept.append(seconds)
        self.now += seconds


class ScriptedDesktop(FakeDesktop):
    """A desktop whose foreground (and window map) follows a script.

    `foreground_script` is consulted once per foreground read; `on_poll` lets a
    test rearrange the desktop between polls — a client restarting, say.
    """

    def __init__(self, *, foreground_script=None, iconic=False, **kwargs):
        kwargs.setdefault("windows", {
            HWND: (FORTI_PID, 41, HWND),
            SECOND_HWND: (SECOND_PID, 42, SECOND_HWND),
            TRAY_HWND: (TRAY_PID, 43, TRAY_HWND),
            OTHER: (EVIL_PID, 99, OTHER),
        })
        kwargs.setdefault("images", {
            FORTI_PID: FORTI_GUI, SECOND_PID: FORTI_GUI,
            TRAY_PID: FORTI_TRAY, EVIL_PID: EVIL_EXE,
        })
        super().__init__(**kwargs)
        self._script = foreground_script
        self.iconic = iconic

    def foreground_window(self):
        self.fg_checks += 1
        if self._script is not None:
            return self._script(self.fg_checks)
        return self._foreground(self.fg_checks)

    def is_iconic(self, hwnd):
        return self.iconic


def gate(desktop, *, hwnds=(HWND,), clock=None, cancellation=None,
         timeout_s=ag.ACTIVATION_TIMEOUT_S, max_repins=ag.MAX_REPINS):
    target = SecureWindowTarget(TRUSTED, api=desktop, finder=ListFinder(hwnds))
    return ActivationGate(
        target=target, clock=clock if clock is not None else FakeClock(),
        cancellation=cancellation if cancellation is not None
        else CancellationToken(),
        timeout_s=timeout_s, max_repins=max_repins)


def run(desktop, **kwargs):
    return gate(desktop, **kwargs).wait()


# ══════════════════════════════════════════════════════════════════════════
# 1–5. Observing (or not) an activation
# ══════════════════════════════════════════════════════════════════════════

def test_1_a_client_already_in_front_needs_no_waiting():
    clock = FakeClock()
    result = run(ScriptedDesktop(), clock=clock)
    assert result.ok and result.state is ActivationState.ACTIVATION_OBSERVED
    assert result.polls == 1 and result.waited_s == 0.0
    assert clock.slept == [], "nie czekaliśmy ani chwili"
    assert result.pid == FORTI_PID and result.image_name == "forticlient.exe"


def test_2_another_window_in_front_makes_the_gate_wait():
    clock = FakeClock()
    result = run(ScriptedDesktop(foreground_script=lambda n: OTHER),
                 clock=clock, timeout_s=2.0)
    assert result.state is ActivationState.ACTIVATION_TIMEOUT
    assert result.polls > 1 and clock.slept, "naprawdę czekał"
    assert set(clock.slept) == {ag.POLL_INTERVAL_S}


def test_3_the_gate_opens_when_the_client_comes_forward():
    # Somebody else is in front for the first three reads, then the user
    # switches to the client.
    desktop = ScriptedDesktop(
        foreground_script=lambda n: OTHER if n <= 3 else HWND)
    result = run(desktop, timeout_s=30.0)
    assert result.ok and result.polls == 4
    assert result.hwnd == HWND


def test_4_the_wrong_window_coming_forward_is_not_an_activation():
    """A second, verified client window is not the one we are waiting for."""
    desktop = ScriptedDesktop(
        foreground_script=lambda n: SECOND_HWND if n <= 3 else HWND)
    result = run(desktop, timeout_s=30.0)
    assert result.ok and result.hwnd == HWND
    assert result.repins == 0, "nikt nie przypiął innego okna"


def test_4b_an_untrusted_window_never_opens_the_gate():
    desktop = ScriptedDesktop(foreground_script=lambda n: OTHER)
    result = run(desktop, timeout_s=2.0)
    assert not result.ok
    assert result.state is ActivationState.ACTIVATION_TIMEOUT


def test_5_a_minimised_client_is_not_an_activation():
    """Windows can report a minimised window as the foreground one."""
    desktop = ScriptedDesktop(iconic=True)
    result = run(desktop, timeout_s=2.0)
    assert not result.ok
    assert result.reason == "target-minimised"
    check = SecureWindowTarget(TRUSTED, api=desktop,
                               finder=ListFinder((HWND,))).foreground_check()
    assert check.foreground is True and check.iconic is True and check.ok is False


def test_5b_an_unknown_iconic_state_does_not_block_an_otherwise_good_target():
    """A seam that cannot tell must not veto — only a positive "yes" does."""
    class Silent(ScriptedDesktop):
        def is_iconic(self, hwnd):
            return None

    assert run(Silent()).ok


# ══════════════════════════════════════════════════════════════════════════
# 7–13. Identity: pinning and re-pinning
# ══════════════════════════════════════════════════════════════════════════

class RestartingDesktop(ScriptedDesktop):
    """The client is replaced by a fresh window after `after` foreground reads."""

    def __init__(self, *, restarts, after=2, **kwargs):
        super().__init__(**kwargs)
        self.restarts, self.after = restarts, after
        self.generation = 0
        self._next_hwnd = HWND

    def foreground_window(self):
        self.fg_checks += 1
        if (self.fg_checks % self.after == 0
                and self.generation < self.restarts):
            self.generation += 1
            old = self._next_hwnd
            self._next_hwnd = HWND + self.generation * 0x100
            self.windows.pop(old, None)
            self.windows[self._next_hwnd] = (
                FORTI_PID + self.generation, 41, self._next_hwnd)
            self.images[FORTI_PID + self.generation] = FORTI_GUI
            self.finder_hwnds[:] = [self._next_hwnd]
        return OTHER                       # never in front — we only count re-pins


def restarting(restarts, **kwargs):
    desktop = RestartingDesktop(restarts=restarts, **kwargs)
    desktop.finder_hwnds = [HWND]
    target = SecureWindowTarget(TRUSTED, api=desktop,
                                finder=ListFinder(desktop.finder_hwnds))
    return desktop, ActivationGate(target=target, clock=FakeClock(),
                                   timeout_s=30.0)


def test_7_a_new_window_of_the_same_client_costs_a_repin():
    _desktop, the_gate = restarting(1)
    result = the_gate.wait()
    assert result.repins == 1
    assert result.state is ActivationState.ACTIVATION_TIMEOUT


def test_8_a_new_pid_of_the_same_client_costs_a_repin():
    _desktop, the_gate = restarting(1)
    result = the_gate.wait()
    assert result.repins == 1
    assert result.pid != FORTI_PID, "przypięty jest NOWY proces"


def test_9_a_different_trusted_program_is_refused_not_repinned():
    """FortiTray is trusted and is not the client we were waiting for."""
    desktop = ScriptedDesktop(foreground_script=lambda n: OTHER)
    hwnds = [HWND]
    target = SecureWindowTarget(TRUSTED, api=desktop, finder=ListFinder(hwnds))
    the_gate = ActivationGate(target=target, clock=FakeClock(), timeout_s=30.0)

    original = desktop.foreground_window

    def swap_after_first(*_args):
        value = original()
        if desktop.fg_checks == 1:
            desktop.windows.pop(HWND, None)
            hwnds[:] = [TRAY_HWND]
        return value

    desktop.foreground_window = swap_after_first
    result = the_gate.wait()
    assert result.state is ActivationState.TARGET_CHANGED
    assert result.reason == "image-identity-changed"
    assert result.repins == 0, "inny program to nie re-pin, to odmowa"


@pytest.mark.parametrize("restarts,expected", [(1, 1), (2, 2), (3, 3)])
def test_10_three_repins_are_allowed(restarts, expected):
    _desktop, the_gate = restarting(restarts)
    result = the_gate.wait()
    assert result.repins == expected
    assert result.state is ActivationState.ACTIVATION_TIMEOUT, \
        "limit nieprzekroczony — kończy nas dopiero budżet"


def test_11_the_fourth_change_ends_the_wait_terminally():
    _desktop, the_gate = restarting(4)
    result = the_gate.wait()
    assert result.state is ActivationState.TARGET_CHANGED
    assert result.reason == "too-many-repins"
    assert result.repins == ag.MAX_REPINS + 1


def test_12_a_restarted_client_can_still_be_activated_before_the_first_secret():
    """A re-pinned window is a full target, not a degraded one."""
    desktop = ScriptedDesktop()
    hwnds = [HWND]
    target = SecureWindowTarget(TRUSTED, api=desktop, finder=ListFinder(hwnds))
    the_gate = ActivationGate(target=target, clock=FakeClock(), timeout_s=30.0)

    def script(n):
        if n == 1:
            desktop.windows.pop(HWND, None)
            hwnds[:] = [SECOND_HWND]
            return OTHER
        return SECOND_HWND

    desktop._script = script
    result = the_gate.wait()
    assert result.ok and result.repins == 1
    assert result.hwnd == SECOND_HWND and result.pid == SECOND_PID


def test_13_an_unverified_process_never_opens_the_gate():
    """A look-alike window, however insistently in front."""
    desktop = ScriptedDesktop(images={FORTI_PID: EVIL_EXE, EVIL_PID: EVIL_EXE})
    result = run(desktop, timeout_s=2.0)
    assert not result.ok
    assert result.state is ActivationState.NO_TARGET, \
        "nigdy nie było czego przypiąć"
    assert result.hwnd is None and result.repins == 0


# ══════════════════════════════════════════════════════════════════════════
# 14–16. Ending the wait
# ══════════════════════════════════════════════════════════════════════════

def test_14_the_budget_runs_out_without_an_autofill():
    clock = FakeClock()
    result = run(ScriptedDesktop(foreground_script=lambda n: OTHER),
                 clock=clock, timeout_s=ag.ACTIVATION_TIMEOUT_S)
    assert result.state is ActivationState.ACTIVATION_TIMEOUT
    assert result.waited_s >= ag.ACTIVATION_TIMEOUT_S
    assert clock.now >= 60.0, "budżet to 60 s wirtualnych"
    assert result.ok is False


def test_15_cancelling_ends_the_wait_immediately_and_terminally():
    token = CancellationToken()
    token.cancel()
    result = run(ScriptedDesktop(), cancellation=token)
    assert result.state is ActivationState.CANCELLED
    assert result.ok is False and result.polls == 0, "nawet nie spojrzał"


def test_15b_cancelling_mid_wait_stops_the_next_poll():
    token = CancellationToken()
    desktop = ScriptedDesktop(foreground_script=lambda n: OTHER)
    the_gate = gate(desktop, cancellation=token, timeout_s=30.0)
    original = desktop.foreground_window

    def cancel_after_two(*_args):
        value = original()
        if desktop.fg_checks >= 2:
            token.cancel()
        return value

    desktop.foreground_window = cancel_after_two
    result = the_gate.wait()
    assert result.state is ActivationState.CANCELLED and result.polls == 2


def test_16_no_test_here_spends_a_real_second():
    """Structural: the gate takes its clock from outside."""
    import inspect
    source = inspect.getsource(ag.ActivationGate)
    assert "time.sleep" not in source and "time.monotonic" not in source
    assert "clock" in inspect.signature(ag.wait_for_activation).parameters


# ══════════════════════════════════════════════════════════════════════════
# 17–18. What the gate is forbidden to be
# ══════════════════════════════════════════════════════════════════════════

def test_17_the_gate_never_reaches_for_a_window_or_a_keyboard():
    tree = ast.parse(open(ag.__file__, encoding="utf-8").read())
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    for banned in ("acquire", "acquire_any", "acquire_focus", "restore_window",
                   "set_foreground_window", "ShowWindow", "BringWindowToTop",
                   "SetFocus", "AttachThreadInput", "press_key", "press_combo",
                   "type_text", "copy_to_clipboard", "SendInput", "WM_SETTEXT"):
        assert banned not in names, banned

    modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    modules |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import)
                for a in n.names}
    for forbidden in ("ctypes", "win32gui", "win32con", "vpn_connect"):
        assert not any(m and m.split(".")[0] == forbidden for m in modules), forbidden


def test_17b_the_gate_only_ever_asks_one_thing_of_the_target():
    tree = ast.parse(open(ag.__file__, encoding="utf-8").read())
    asked = {n.func.attr for n in ast.walk(tree)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and isinstance(n.func.value, ast.Attribute)
             and n.func.value.attr == "target"}
    assert asked == {"foreground_check"}, asked


def test_17c_foreground_check_itself_changes_nothing():
    desktop = ScriptedDesktop()
    before = dict(desktop.windows), list(desktop.events)
    target = SecureWindowTarget(TRUSTED, api=desktop, finder=ListFinder((HWND,)))
    for _ in range(5):
        target.foreground_check()
        target.foreground_check(HWND)
    assert desktop.windows == before[0]
    assert desktop.events == before[1], "żadnego attach, restore ani aktywacji"


def test_18_the_gate_cannot_be_handed_a_credential():
    import inspect
    for function in (ag.wait_for_activation, ActivationGate.wait):
        params = set(inspect.signature(function).parameters)
        assert not ({"login", "password", "token", "request", "secret"} & params), \
            function.__name__
    assert not ({"login", "password", "token"}
                & set(ActivationGate.__dataclass_fields__))


def test_18b_no_result_can_carry_a_secret():
    result = run(ScriptedDesktop())
    blob = f"{result!r} {result.to_trace_data()}"
    for secret in ("jkowalski", "SuperSecret123", "845217"):
        assert secret not in blob
    assert "title" not in result.to_trace_data()


# ══════════════════════════════════════════════════════════════════════════
# 6 + 19. The gate decides when to start — the guard decides what is sent
# ══════════════════════════════════════════════════════════════════════════

def test_19_the_autofill_only_runs_after_the_gate_says_yes():
    from vpn.providers import forticlient_connect as fcc

    tree = ast.parse(open(fcc.__file__, encoding="utf-8").read())
    body = next(n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == "_gui_outcome")
    calls = [n.func.attr for n in ast.walk(body)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)]
    assert calls.index("await_activation") < calls.index("start_autofill")


def test_6_a_foreground_lost_right_after_the_gate_is_the_guards_problem():
    """The race, forced.

    The gate sees the client in front and returns; on the very next read the
    user has switched away.  The gate must not have promised anything — the
    refusal has to come from the machinery that reads the desktop again before
    it sends, exactly as it did before this stage existed.
    """
    desktop = ScriptedDesktop(
        foreground_script=lambda n: HWND if n <= 1 else OTHER)
    target = SecureWindowTarget(TRUSTED, api=desktop, finder=ListFinder((HWND,)))

    opened = ActivationGate(target=target, clock=FakeClock()).wait()
    assert opened.ok, "bramka widziała prawidłową aktywację"

    # ...and one read later the desktop has moved on.
    assert sw.confirm_target(HWND, FORTI_PID, TRUSTED, desktop).ok is False
    rejected = target.acquire_any()
    assert getattr(rejected, "ok", False) is False, \
        "to guard odmawia, nie bramka"
    assert rejected.reason == "foreground-is-other-window"


def test_6b_the_gate_hands_over_no_handle_and_no_promise():
    result = run(ScriptedDesktop())
    assert not hasattr(result, "window")
    assert not hasattr(result, "verified_window")
    assert isinstance(result.hwnd, int), "tylko uchwyt jako liczba, nie obiekt"


# ══════════════════════════════════════════════════════════════════════════
# 20. Legacy
# ══════════════════════════════════════════════════════════════════════════

def test_20_legacy_never_waits_for_anybody():
    legacy = open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read()
    for banned in ("activation_gate", "ActivationGate", "await_activation",
                   "foreground_check"):
        assert banned not in legacy, banned
    assert "focus = acquire_focus(hwnd, owner.pid, trusted, api)" in legacy
    assert "def _autofill_forticlient(" in legacy


def test_20b_the_dropped_restore_is_recorded_as_an_intended_difference():
    from vpn.providers import forticlient_connect as fcc

    ids = {name for name, _kind, _text in fcc.LEGACY_BEHAVIOR}
    assert "window-restore-dropped" in ids
    parity = {entry[0]: entry[5] for entry in fcc.CONNECT_PARITY}
    assert parity["window-already-open-not-raised"] == "security"
    assert parity["user-never-activates"] == "information"
