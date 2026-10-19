"""Stage 23: showing the activation wait, and being able to call it off.

Stage 22 built a gate that waits, read-only, for the user to bring FortiClient
forward.  A wait nobody can see is a hang, so this stage puts a sentence and a
Cancel button on it — and the whole difficulty is that the obvious way to help
the user (raise the client for them) is exactly the thing three stages of
measurement proved impossible and this design deliberately gave up.

So these tests spend most of their effort on what the UI is **not**: it does
not activate, focus, restore, type or touch the clipboard; it is handed a state
name, never a credential; and it cannot decide that the autofill may start —
only the gate's own result can, and only when it succeeded.

The other half is the wait itself.  A minute-long wait on the UI thread would
freeze the very window the user is being asked to leave, so the gate runs in a
``QThread`` and reports through signals — the shape ``StatusWorker`` and
``VpnMonitorWorker`` already use in this project.  ``test_13`` holds the worker
still and proves the UI keeps running underneath it.
"""

import ast
import os
import sys
import threading

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

# Offscreen: the tests build real widgets, and a real window on a build agent
# (or on the developer's screen, mid-run) is nobody's idea of a good time.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QLabel, QWidget  # noqa: E402

from vpn.providers import SecureWindowTarget  # noqa: E402
from vpn.providers import activation_gate as ag  # noqa: E402
from vpn.providers.activation_gate import (  # noqa: E402
    ActivationGate, ActivationState, CancellationToken, wait_for_activation,
)
from ui import activation_prompt as ap  # noqa: E402
from ui.activation_prompt import (  # noqa: E402
    STATE_COLOURS, STATE_MESSAGES, ActivationPresenter, ActivationPrompt,
    ActivationWorker, label_style_sheet,
)
from tests.test_vpn_activation_gate import (  # noqa: E402
    FakeClock, ScriptedDesktop,
)
from tests.test_vpn_secure_target import (  # noqa: E402
    HWND, OTHER, TRUSTED, ListFinder,
)

AWAIT_MESSAGE = ("Okno FortiClient jest otwarte, ale nieaktywne — kliknij je, "
                 "aby wpisać dane.")


@pytest.fixture(scope="module")
def app():
    """One QApplication for the module — Qt allows exactly one per process."""
    existing = QApplication.instance()
    yield existing if existing is not None else QApplication([])


@pytest.fixture
def prompt(app):
    """A prompt inside a parent, so nothing ever becomes a top-level window."""
    holder = QWidget()
    widget = ActivationPrompt(holder)
    yield widget
    holder.deleteLater()


def build_gate(desktop, *, clock=None, cancellation=None, timeout_s=30.0):
    target = SecureWindowTarget(TRUSTED, api=desktop, finder=ListFinder((HWND,)))
    return ActivationGate(
        target=target, clock=clock if clock is not None else FakeClock(),
        cancellation=cancellation if cancellation is not None
        else CancellationToken(),
        timeout_s=timeout_s)


class Run:
    """A gate on a worker, a prompt on the signals — the whole Stage-23 wiring.

    Deliberately assembled here and not in ``ui``: the widget must stay unable
    to name a gate, so somebody outside has to introduce them.  That somebody
    is this class in tests, and would be the panel when the new connect is
    finally switched on.
    """

    def __init__(self, gate, prompt):
        self.gate, self.prompt = gate, prompt
        self.states, self.results, self.failures = [], [], []
        self.worker = ActivationWorker(gate.wait)
        gate.observer = self.worker.report_state
        self.worker.state_changed.connect(prompt.apply_state)
        self.worker.state_changed.connect(self.states.append)
        self.worker.finished_with.connect(self.results.append)
        self.worker.failed.connect(self.failures.append)
        prompt.cancelled.connect(self.cancel)

    def cancel(self):
        """What the Cancel button reaches: a token, not a window."""
        self.gate.cancellation.cancel()

    def start(self):
        self.worker.start()
        return self

    def pump(self, until=None, timeout_s=10.0):
        """Run the UI thread's event loop, as a real application would."""
        import time
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            QApplication.processEvents()
            if until is not None:
                if until():
                    break
            elif not self.worker.isRunning():
                break
            self.worker.wait(5)
        for _ in range(3):          # deliver whatever is still queued
            QApplication.processEvents()
        return self

    def finish(self):
        self.worker.wait(10000)
        self.pump(until=lambda: bool(self.results or self.failures))
        return self.results[0] if self.results else None


class PausingDesktop(ScriptedDesktop):
    """Holds the wait still after the target is pinned, so the test can look.

    Without this the fake clock makes the whole wait happen between two
    instructions, and "what does the user see while waiting" would have no
    moment to be asked in.
    """

    def __init__(self, *, pause_at=2, **kwargs):
        super().__init__(**kwargs)
        self.reached = threading.Event()
        self.release = threading.Event()
        self._pause_at = pause_at

    def foreground_window(self):
        if self.fg_checks + 1 == self._pause_at:
            self.reached.set()
            self.release.wait(10)
        return super().foreground_window()


# ══════════════════════════════════════════════════════════════════════════
# 1–6. The sentence: what the user is told, and what they are never told
# ══════════════════════════════════════════════════════════════════════════

def test_1_awaiting_activation_asks_the_user_to_switch():
    presenter = ActivationPresenter("awaiting-activation")
    assert presenter.message == AWAIT_MESSAGE
    assert presenter.waiting and not presenter.finished


def test_1b_the_message_makes_no_promise_and_names_no_button():
    """Not "click Done": there is no Done.  Not "in a moment": we do not know."""
    for state, text in STATE_MESSAGES.items():
        low = text.lower()
        for banned in ("gotowe", "kliknij ok", "automatycznie", "za chwilę",
                       "poczekaj chwilę", "sekund"):
            assert banned not in low, (state, banned)


def test_2_cancel_is_offered_while_waiting_and_only_then():
    for state in ("locating-target", "awaiting-activation"):
        assert ActivationPresenter(state).cancel_visible, state
    for state in ("activation-observed", "activation-timeout", "no-target",
                  "target-changed", "cancelled"):
        presenter = ActivationPresenter(state)
        assert not presenter.cancel_visible and presenter.finished, state


def test_3_every_state_the_gate_can_end_in_has_something_to_say():
    """Coupling test: a new state in the gate must not reach the user as a gap."""
    assert {s.value for s in ActivationState} == set(STATE_MESSAGES)
    assert set(STATE_MESSAGES) == set(STATE_COLOURS)


def test_4_an_unknown_state_fails_safe():
    presenter = ActivationPresenter("something-stage-24-invented")
    assert not presenter.known
    assert presenter.message == ap.UNKNOWN_MESSAGE
    assert presenter.finished and not presenter.succeeded
    assert not presenter.cancel_visible, "nie proponujemy anulowania czegoś, co się skończyło"


def test_5_nothing_shown_to_the_user_carries_a_diagnostic_or_a_secret():
    blob = " ".join(STATE_MESSAGES.values()).lower()
    for leak in ("hwnd", "pid", "0x", "jkowalski", "supersecret123", "845217",
                 "forticlient.exe", "error", "reason", "traceback"):
        assert leak not in blob, leak


def test_6_the_prompt_reuses_the_panels_own_status_vocabulary():
    """The colours are the card's colours, with the card's meanings.

    Amber while something is happening, green when it worked, red when it did
    not, grey when nothing is going on — the same four the VPN card already
    uses for "◌ Łączenie…", "● Połączono", errors and "○ Rozłączono".
    """
    panel = open(os.path.join(_PARENT, "ui", "vpn_panel.py"),
                 encoding="utf-8").read()
    for colour in set(STATE_COLOURS.values()):
        # The panel writes the same declaration, sometimes with a `font-weight`
        # for emphasis; the colour and the size are the shared vocabulary.
        assert f"color: {colour}; font-size: 10px;" in panel, colour
    assert label_style_sheet("#d29922") in panel, "styl 1:1 z kartą profilu"
    assert STATE_COLOURS["awaiting-activation"] == "#d29922"
    assert STATE_COLOURS["activation-observed"] == "#3fb950"
    assert STATE_COLOURS["cancelled"] == "#8b949e"


# ══════════════════════════════════════════════════════════════════════════
# 7–9. The widget
# ══════════════════════════════════════════════════════════════════════════

def test_7_the_widget_shows_the_sentence_and_the_button(prompt):
    prompt.apply_state("awaiting-activation")
    assert prompt.message == AWAIT_MESSAGE
    assert prompt.cancel_button.text() == "Anuluj"
    assert prompt.cancel_button.isVisibleTo(prompt)
    assert prompt.status_label.styleSheet() == label_style_sheet("#d29922")


def test_8_the_sentence_can_go_into_the_cards_existing_status_label(app):
    """No second status system: the card's own label is the one that speaks."""
    holder = QWidget()
    card_label = QLabel("◌ Łączenie...", holder)
    widget = ActivationPrompt(holder, status_label=card_label)
    assert widget.borrowed_label
    widget.apply_state("awaiting-activation")
    assert card_label.text() == AWAIT_MESSAGE
    assert card_label.styleSheet() == label_style_sheet("#d29922")
    widget.apply_state("cancelled")
    assert card_label.text() == STATE_MESSAGES["cancelled"]
    assert card_label.styleSheet() == label_style_sheet("#8b949e")
    assert not widget.isVisibleTo(holder), "po anulowaniu zostaje tylko zdanie"


def test_9_the_button_reports_a_click_and_does_nothing_else(prompt):
    seen = []
    prompt.cancelled.connect(lambda: seen.append(True))
    prompt.apply_state("awaiting-activation")
    prompt.cancel_button.click()
    assert seen == [True]


# ══════════════════════════════════════════════════════════════════════════
# 10–14. The wait, on a worker, driving the UI
# ══════════════════════════════════════════════════════════════════════════

def test_10_a_client_that_is_not_in_front_makes_the_ui_ask_for_the_switch(prompt):
    desktop = PausingDesktop(foreground_script=lambda n: OTHER)
    run = Run(build_gate(desktop, timeout_s=5.0), prompt).start()
    run.pump(until=desktop.reached.is_set)
    run.pump(until=lambda: prompt.presenter.state == "awaiting-activation")

    assert prompt.message == AWAIT_MESSAGE
    assert prompt.cancel_button.isVisibleTo(prompt)
    assert prompt.presenter.waiting, "czekamy — to nie jest wynik"

    desktop.release.set()
    run.finish()


def test_11_the_user_switching_to_the_client_ends_the_wait_and_the_banner(prompt):
    desktop = PausingDesktop(foreground_script=lambda n: OTHER if n <= 2 else HWND)
    run = Run(build_gate(desktop), prompt).start()
    run.pump(until=desktop.reached.is_set)
    run.pump(until=lambda: prompt.presenter.state == "awaiting-activation")
    assert prompt.message == AWAIT_MESSAGE

    desktop.release.set()
    result = run.finish()

    assert result.ok and result.state is ActivationState.ACTIVATION_OBSERVED
    assert prompt.presenter.state == "activation-observed"
    assert prompt.presenter.succeeded
    assert not prompt.cancel_button.isVisibleTo(prompt)
    assert not prompt.isVisibleTo(prompt.parent()), "baner znika"
    assert run.states[0] == "locating-target"
    assert "awaiting-activation" in run.states


def test_12_another_window_staying_in_front_keeps_the_ui_waiting(prompt):
    """Somebody else's window coming forward is not the activation we want."""
    desktop = PausingDesktop(foreground_script=lambda n: OTHER, pause_at=4)
    run = Run(build_gate(desktop, timeout_s=5.0), prompt).start()
    run.pump(until=desktop.reached.is_set)

    assert prompt.presenter.state == "awaiting-activation"
    assert prompt.message == AWAIT_MESSAGE
    assert desktop.fg_checks >= 3, "naprawdę odpytywał, a nie poddał się od razu"

    desktop.release.set()
    result = run.finish()
    assert result.state is ActivationState.ACTIVATION_TIMEOUT


def test_13_the_timeout_leaves_the_user_with_an_instruction_not_an_error(prompt):
    desktop = ScriptedDesktop(foreground_script=lambda n: OTHER)
    result = Run(build_gate(desktop, timeout_s=2.0), prompt).start().finish()

    assert result.state is ActivationState.ACTIVATION_TIMEOUT
    assert prompt.presenter.state == "activation-timeout"
    assert prompt.message == STATE_MESSAGES["activation-timeout"]
    assert "ręcznie" in prompt.message, "użytkownik dostaje wyjście, nie komunikat błędu"
    assert not prompt.cancel_button.isVisibleTo(prompt)
    assert prompt.presenter.finished and not prompt.presenter.succeeded


def test_14_the_ui_thread_keeps_running_while_the_wait_is_held(prompt):
    """The wait must not freeze the window the user is being told to leave."""
    desktop = PausingDesktop(foreground_script=lambda n: OTHER)
    run = Run(build_gate(desktop, timeout_s=5.0), prompt).start()
    run.pump(until=desktop.reached.is_set)

    ticks = []
    for _ in range(50):
        QApplication.processEvents()
        ticks.append(True)
    assert len(ticks) == 50
    assert run.worker.isRunning(), "wciąż czeka — i mimo to UI żyje"
    # And the UI is not merely spinning: it can still be driven.
    prompt.apply_state("awaiting-activation")
    assert prompt.message == AWAIT_MESSAGE

    desktop.release.set()
    run.finish()


def test_14b_the_terminal_state_is_reported_once_not_twice(prompt):
    """Found on the real client (Stage 24): it used to arrive twice.

    The gate reports the final state through the observer, and the worker then
    unwraps the same state from the result.  Harmless on screen — rendering is
    idempotent — but a `state_changed` that fires without a change misleads
    anything that counts transitions.
    """
    desktop = ScriptedDesktop()                     # the client is in front
    run = Run(build_gate(desktop), prompt).start()
    result = run.finish()

    assert result.state is ActivationState.ACTIVATION_OBSERVED
    # Three states even for a client already in front: the target is pinned
    # (AWAITING_ACTIVATION) before the same reading is judged an activation.
    assert run.states == ["locating-target", "awaiting-activation",
                          "activation-observed"], run.states
    assert len(run.states) == len(set(run.states)), "żaden stan nie powtórzony"


def test_15_a_broken_wait_reaches_the_ui_as_a_type_not_as_a_message(prompt):
    def explode():
        raise RuntimeError("ścieżka C:\\Users\\jkowalski i hasło SuperSecret123")

    worker = ActivationWorker(explode)
    failures = []
    worker.failed.connect(failures.append)
    worker.start()
    worker.wait(5000)
    for _ in range(3):
        QApplication.processEvents()
    assert failures == ["RuntimeError"]


# ══════════════════════════════════════════════════════════════════════════
# 16–19. Cancelling, at each of the four moments it can happen
# ══════════════════════════════════════════════════════════════════════════

def test_16_cancelling_the_moment_the_message_appears(prompt):
    desktop = PausingDesktop(foreground_script=lambda n: OTHER)
    run = Run(build_gate(desktop, timeout_s=30.0), prompt).start()
    run.pump(until=desktop.reached.is_set)
    run.pump(until=lambda: prompt.presenter.state == "awaiting-activation")

    prompt.cancel_button.click()          # the user, as soon as they read it
    desktop.release.set()
    result = run.finish()

    assert result.state is ActivationState.CANCELLED
    assert prompt.presenter.state == "cancelled"
    assert not prompt.cancel_button.isVisibleTo(prompt), "nie da się anulować dwa razy"


def test_17_cancelling_in_the_middle_of_the_polling(prompt):
    desktop = PausingDesktop(foreground_script=lambda n: OTHER, pause_at=5)
    run = Run(build_gate(desktop, timeout_s=30.0), prompt).start()
    run.pump(until=desktop.reached.is_set)
    assert desktop.fg_checks >= 4, "odpytywanie trwało, gdy klikał"

    prompt.cancel_button.click()
    desktop.release.set()
    result = run.finish()

    assert result.state is ActivationState.CANCELLED
    assert result.polls >= 4 and result.repins == 0


def test_18_cancelling_just_before_the_client_comes_forward(prompt):
    """A dead heat, decided the safe way: cancelled wins, nothing is typed.

    The gate checks the token at the top of every poll, so a cancel that lands
    while the previous poll is still in flight is honoured before the next
    reading — even though the very next reading would have said "activated".
    """
    desktop = PausingDesktop(foreground_script=lambda n: HWND, pause_at=1)
    run = Run(build_gate(desktop, timeout_s=30.0), prompt).start()
    run.pump(until=desktop.reached.is_set)

    prompt.cancel_button.click()
    run.pump(until=lambda: run.gate.cancellation.cancelled)
    desktop.release.set()
    result = run.finish()

    assert result.state is ActivationState.CANCELLED
    assert not result.ok, "wyścig nie może skończyć się wpisaniem hasła"
    assert prompt.presenter.state == "cancelled"


def test_19_cancelling_after_the_timeout_changes_nothing(prompt):
    desktop = ScriptedDesktop(foreground_script=lambda n: OTHER)
    run = Run(build_gate(desktop, timeout_s=2.0), prompt).start()
    result = run.finish()
    assert result.state is ActivationState.ACTIVATION_TIMEOUT

    prompt.request_cancel()               # the click that arrived too late
    assert prompt.presenter.state == "activation-timeout", "wynik jest wynikiem"
    assert len(run.results) == 1, "nic się nie uruchomiło ponownie"
    assert not run.worker.isRunning()


def test_20_a_cancelled_wait_is_terminal_and_never_retries():
    token = CancellationToken()
    token.cancel()
    desktop = ScriptedDesktop()          # the client IS in front
    result = build_gate(desktop, cancellation=token, timeout_s=30.0).wait()
    assert result.state is ActivationState.CANCELLED
    assert result.polls == 0 and desktop.fg_checks == 0, "nawet nie spojrzał"


# ══════════════════════════════════════════════════════════════════════════
# 21–24. What the UI is forbidden to be
# ══════════════════════════════════════════════════════════════════════════

def test_21_the_ui_never_reaches_for_a_window_or_a_keyboard():
    """The same tripwire as the gate's `test_17`, pointed at the UI module."""
    tree = ast.parse(open(ap.__file__, encoding="utf-8").read())
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    for banned in ("acquire", "acquire_any", "acquire_focus", "restore_window",
                   "set_foreground_window", "activateWindow", "raise_",
                   "setFocus", "ShowWindow", "BringWindowToTop", "SetFocus",
                   "AttachThreadInput", "press_key", "press_combo", "type_text",
                   "copy_to_clipboard", "clipboard", "QClipboard", "SendInput",
                   "WM_SETTEXT", "keyPressEvent", "QKeyEvent"):
        assert banned not in names, banned

    modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    modules |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import)
                for a in n.names}
    for forbidden in ("ctypes", "win32gui", "win32con", "win32api", "keyboard",
                      "vpn", "vpn_connect", "secure_window"):
        assert not any(m and m.split(".")[0] == forbidden for m in modules), forbidden


def test_21c_the_ui_never_polls_anything():
    """States arrive; they are not fetched.

    A timer in the banner would be a second state machine racing the gate's
    own, and it would read a state the gate had already moved on from.  The
    gate tells the worker, the worker emits, the widget renders — that is the
    whole path, and none of it has a clock in it.
    """
    tree = ast.parse(open(ap.__file__, encoding="utf-8").read())
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    for banned in ("QTimer", "singleShot", "startTimer", "timerEvent", "sleep",
                   "msleep", "processEvents", "exec"):
        assert banned not in names, banned


def test_21b_watching_the_wait_changes_nothing_on_the_desktop(prompt):
    """Behavioural twin of the AST test: the desktop is read, never touched."""
    desktop = ScriptedDesktop(foreground_script=lambda n: OTHER)
    run = Run(build_gate(desktop, timeout_s=3.0), prompt).start()
    run.finish()
    prompt.request_cancel()
    assert desktop.events == [], "żadnego attach, restore ani aktywacji"
    assert desktop.fg_checks > 1, "a jednak patrzył"


def test_22_the_ui_cannot_be_handed_a_credential():
    import inspect
    for callable_ in (ActivationPrompt.__init__, ActivationPresenter.__init__,
                      ActivationPresenter.update, ActivationPrompt.apply_state,
                      ActivationWorker.__init__, ActivationWorker.report_state,
                      ActivationPrompt.request_cancel):
        params = set(inspect.signature(callable_).parameters)
        assert not ({"login", "password", "token", "request", "secret",
                     "credentials"} & params), callable_.__qualname__


def test_22b_the_prompt_only_ever_learns_a_state_name(prompt):
    """Whatever is passed in, what is kept is a string — and it is shown as one."""
    class Sneaky:
        password = "SuperSecret123"

        def __str__(self):
            return "awaiting-activation"

    prompt.apply_state(Sneaky())
    assert prompt.presenter.state == "awaiting-activation"
    assert isinstance(prompt.presenter.state, str)
    assert "SuperSecret123" not in prompt.message


def test_23_the_gate_still_works_with_no_ui_at_all():
    """The UI is an observer, not a dependency: remove it and nothing changes."""
    desktop = ScriptedDesktop()
    assert wait_for_activation(
        SecureWindowTarget(TRUSTED, api=desktop, finder=ListFinder((HWND,))),
        clock=FakeClock()).ok

    tree = ast.parse(open(ag.__file__, encoding="utf-8").read())
    modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    modules |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import)
                for a in n.names}
    for forbidden in ("ui", "PyQt6"):
        assert not any(m and m.split(".")[0] == forbidden for m in modules), forbidden


def test_23b_the_observer_cannot_break_a_wait():
    """A UI that raises must not be able to abort — or half-finish — the wait."""
    gate = build_gate(ScriptedDesktop())
    gate.observer = lambda state: (_ for _ in ()).throw(RuntimeError("UI padło"))
    assert gate.wait().ok


# ══════════════════════════════════════════════════════════════════════════
# 25–27. The autofill still starts only when the gate says so
# ══════════════════════════════════════════════════════════════════════════

def test_25_no_activation_means_no_keystroke_and_no_autofill_phase():
    from tests.test_vpn_forticlient_connect_assembled import (
        FakeClock as ConnectClock, FakeLaunch, FakeMessages, RecTrace,
        FORTI_DIR, FORTI_GUI, PASSWORD, ScriptedProvider, connect,
        desktop_with, phase_names,
    )
    from tests.test_vpn_forticlient_autofill import FakeInput
    from tests.test_vpn_forticlient_detect import FakeEnvironment
    from vpn.providers import forticlient_connect as fcc

    inputs = FakeInput()
    provider = ScriptedProvider(
        environment=FakeEnvironment(files=[FORTI_GUI], dirs=[FORTI_DIR]),
        main_hwnds=(HWND,), system=FakeLaunch())
    desktop = desktop_with(foreground=lambda n: OTHER)
    runtime = provider.connect_runtime(
        clock=ConnectClock(), launch_system=FakeLaunch(), input_system=inputs,
        window_api=desktop, message_system=FakeMessages(), trace=RecTrace(),
        activation_timeout_s=2.0)

    result = connect(provider, runtime)

    assert fcc.PHASE_AWAIT_ACTIVATION in phase_names(result)
    assert fcc.PHASE_AUTOFILL not in phase_names(result),         "bramka nie wpuściła autofillu"
    # Not "no keystrokes": nothing at all.  On the autofill route the password
    # only reaches the clipboard inside the autofill itself, so a wait that
    # ended without an activation leaves the input system completely untouched.
    assert inputs.events == [], inputs.events
    assert PASSWORD not in repr(inputs.events)


def test_26_the_autofill_runs_when_the_user_does_come_forward():
    from tests.test_vpn_forticlient_connect_assembled import (
        build, connect, phase_names,
    )
    from vpn.providers import forticlient_connect as fcc

    provider, runtime, _desktop = build()
    result = connect(provider, runtime)
    names = phase_names(result)
    assert names.index(fcc.PHASE_AWAIT_ACTIVATION) < names.index(fcc.PHASE_AUTOFILL)


def test_27_the_new_ui_path_is_unreachable_from_production():
    """Nothing the application actually runs can get to any of this."""
    import glob

    for path in glob.glob(os.path.join(_PARENT, "**", "*.py"), recursive=True):
        rel = os.path.relpath(path, _PARENT)
        head = rel.split(os.sep)[0]
        # build/ and dist/: PyInstaller output, copies of the sources.
        if head in ("tests", "vpn", "smoke", "build", "dist") or "__pycache__" in rel:
            continue
        # Stage 46: the prepared V2 controller is the one other module allowed
        # to name the prompt — and `test_vpn_panel_v2_bridge` is what keeps
        # that controller itself unreachable from the application.
        if rel in (os.path.join("ui", "activation_prompt.py"),
                   os.path.join("ui", "vpn_v2_connect.py")):
            continue
        source = open(path, encoding="utf-8").read()
        assert "activation_prompt" not in source, rel
        assert "ActivationPrompt" not in source, rel

    from vpn.providers import FortiClientProvider
    assert FortiClientProvider.CONNECT_ENABLED is False


# ══════════════════════════════════════════════════════════════════════════
# 28. The whole thing, end to end, with nothing real behind it
# ══════════════════════════════════════════════════════════════════════════

def test_28_smoke_awaiting_then_cancel_touches_nothing(prompt):
    """Gate → awaiting → the user gives up → cancelled.  Zero of everything.

    The one test that plays the whole Stage-23 story in order, and then asks
    the only question that matters afterwards: did anything happen to the
    machine?  No key, no clipboard, no window raised, no autofill — a wait
    that was called off must leave no trace beyond a sentence on screen.
    """
    from tests.test_vpn_forticlient_autofill import FakeInput

    inputs = FakeInput()                  # handed to nobody, deliberately
    desktop = PausingDesktop(foreground_script=lambda n: OTHER)
    run = Run(build_gate(desktop, timeout_s=30.0), prompt).start()

    run.pump(until=desktop.reached.is_set)
    run.pump(until=lambda: prompt.presenter.state == "awaiting-activation")
    assert prompt.message == AWAIT_MESSAGE
    assert prompt.cancel_button.isVisibleTo(prompt)

    prompt.cancel_button.click()
    desktop.release.set()
    result = run.finish()

    assert result.state is ActivationState.CANCELLED and not result.ok
    assert prompt.message == STATE_MESSAGES["cancelled"]
    assert inputs.events == [], "InputSystem nawet nie został dotknięty"
    assert desktop.events == [], "pulpit tylko czytany"
    assert run.failures == []
