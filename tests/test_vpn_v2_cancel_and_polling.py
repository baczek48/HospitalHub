"""Stage 47: Cancel through the whole V2 fill, and status polling around it.

Two blockers the bridge stage (46) left open, closed here without a new Win32
mechanism — the same :class:`CancellationToken` the activation gate already
carries, checked before every guarded operation of the autofill, and a polling
lifecycle driven by the real session state rather than the legacy's fixed 14 s.

The autofill is exercised directly for the fine-grained moments (between the
login and the password, just before Enter) because only there can a test place
a cancel exactly between two keystrokes; the whole chain — card, worker, prompt,
session — is exercised for the coarse ones (during the wait, right after the
activation) through the Stage-46 harness.
"""

import os
import sys
import threading
import time
from types import SimpleNamespace

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication, QLabel, QWidget  # noqa: E402

from vpn import AutofillStatus, ErrorCode, VpnRequest  # noqa: E402
from vpn.panel_bridge import PanelOutcome, build_request  # noqa: E402
from vpn.providers import FortiClientProvider  # noqa: E402
from vpn.providers import forticlient_autofill as fa  # noqa: E402
from vpn.providers.activation_gate import (  # noqa: E402
    ActivationState, CancellationToken,
)
from vpn.providers.input_system import VK_CONTROL, VK_RETURN  # noqa: E402
from ui.activation_prompt import (  # noqa: E402
    HELD_STATES, STATE_MESSAGES, ActivationPresenter,
)
from ui.vpn_v2_connect import V2ConnectController  # noqa: E402
from tests.test_vpn_forticlient_autofill import (  # noqa: E402
    CTRL_V, ENTER, FakeInput, LOGIN, PASSWORD, PREV_CLIP, clipboard_secrets,
    forti_environment, secret_ops, sole_environment, submit_enters,
)
from tests.test_vpn_forticlient_detect import FakeEnvironment  # noqa: E402
from tests.test_vpn_secure_target import (  # noqa: E402
    FORTI_DIR, FORTI_GUI, HWND, OTHER, FakeDesktop, ListFinder,
)
from tests.test_vpn_panel_v2_bridge import (  # noqa: E402
    Harness, machine, secret_events, session_on, vault_profile,
)


# --------------------------------------------------------------------------- #
# A token that flips itself mid-fill, so a cancel can land between keystrokes  #
# --------------------------------------------------------------------------- #

class CancellingInput(FakeInput):
    """A recorder that trips a token the instant a chosen keystroke happens.

    The autofill checks the token *before* each guarded operation, so tripping
    it during operation *N* makes operation *N+1* the one that is refused.  Two
    triggers are enough for the two moments the tests care about:

    * ``cancel_when_read_equals`` — fires the moment a clipboard read returns
      this value, which for the login is its read-back verification: the login
      has landed, so the *next* guard (the Tab to the password) is the refusal.
    * ``cancel_when_field_becomes`` — fires the moment a paste makes the field
      hold this value, which for the password is its paste: nothing verifies a
      password, so the *next* guard (submit / Enter) is the refusal.
    """

    def __init__(self, token, *, cancel_when_read_equals=None,
                 cancel_when_field_becomes=None):
        super().__init__()
        self._token = token
        self._read_trigger = cancel_when_read_equals
        self._field_trigger = cancel_when_field_becomes

    def read_clipboard(self):
        value = super().read_clipboard()
        if self._read_trigger is not None and value == self._read_trigger:
            self._token.cancel()
        return value

    def press_combo(self, modifier_vk, key):
        super().press_combo(modifier_vk, key)
        if (self._field_trigger is not None
                and self.field == self._field_trigger):
            self._token.cancel()


def autofill(token, inp, *, profile="", login=LOGIN, password=PASSWORD,
             desktop=None):
    # No profile name: the one-tunnel machine, its tunnel showing (L1).
    provider = FortiClientProvider(forti_environment() if profile
                                   else sole_environment())
    target = provider.secure_window_target(
        api=desktop if desktop is not None else FakeDesktop(),
        finder=ListFinder((HWND,)))
    request = VpnRequest(provider_id="forticlient", profile_name=profile,
                         login=login, password=password)
    return provider.autofill_login_password(
        request, target=target, input_system=inp, cancellation=token,
        msaa=inp.msaa)


# ══════════════════════════════════════════════════════════════════════════
# 1. The autofill honours the token at every step
# ══════════════════════════════════════════════════════════════════════════

def test_1_cancel_before_the_first_secret_types_nothing():
    token = CancellationToken()
    token.cancel()                       # already off before the fill begins
    inp = FakeInput()
    result = autofill(token, inp)

    assert result.status is AutofillStatus.CANCELLED
    assert result.error_code == ErrorCode.CANCELLED.value
    assert not result.login_entered and not result.password_entered
    assert secret_ops(inp.events) == [], inp.events
    assert clipboard_secrets(inp.events) == []
    assert ENTER not in inp.events


def test_2_cancel_between_login_and_password_keeps_the_password_home():
    token = CancellationToken()
    inp = CancellingInput(token, cancel_when_read_equals=LOGIN)
    result = autofill(token, inp)

    assert result.status is AutofillStatus.CANCELLED
    assert result.login_entered, "login zdążył wejść przed anulowaniem"
    assert not result.password_entered
    assert result.blocked_at == fa.PHASE_PASSWORD_CLEAR
    # The login reached the field; the password never touched the clipboard.
    assert clipboard_secrets(inp.events) == [LOGIN]
    assert PASSWORD not in [e[1] for e in inp.events if e[0] == "clip_set"]
    assert ENTER not in inp.events


def test_3_cancel_before_enter_leaves_the_form_filled_but_unsubmitted():
    token = CancellationToken()
    inp = CancellingInput(token, cancel_when_field_becomes=PASSWORD)
    result = autofill(token, inp)

    assert result.status is AutofillStatus.CANCELLED
    assert result.login_entered and result.password_entered
    assert result.blocked_at == fa.PHASE_SUBMIT
    assert ENTER not in inp.events, "żaden Enter po anulowaniu"


def test_4_the_clipboard_is_restored_after_a_cancel():
    for trigger in (dict(cancel_when_read_equals=LOGIN),
                    dict(cancel_when_field_becomes=PASSWORD)):
        token = CancellationToken()
        inp = CancellingInput(token, **trigger)
        autofill(token, inp)
        # The very last clipboard write puts the operator's content back.
        assert inp.clipboard == PREV_CLIP, (trigger, inp.clipboard)
        assert inp.events[-1] == ("clip_set", PREV_CLIP)


def test_5_nothing_at_all_happens_after_the_cancel_point():
    """No keystroke, paste, clipboard write or Enter follows the refusal."""
    token = CancellationToken()
    inp = CancellingInput(token, cancel_when_field_becomes=PASSWORD)
    autofill(token, inp)

    # Find the refusal: the last password paste.  What follows it is the tail
    # of that same permitted paste op (a sleep) and then the single clipboard
    # restore — no further keystroke, paste, secret write or Enter.
    last_paste = max(i for i, e in enumerate(inp.events) if e == CTRL_V)
    after = inp.events[last_paste + 1:]
    assert after == [("sleep", 0.4), ("clip_set", PREV_CLIP)], after
    assert ENTER not in inp.events
    assert [e for e in after if e[0] in ("key", "combo", "type")] == []
    assert [e for e in after if e[0] == "clip_set" and e[1] in (LOGIN, PASSWORD)] == []


def test_6_a_fill_that_is_never_cancelled_still_completes():
    """The token is inert unless tripped — the happy path is unchanged."""
    token = CancellationToken()
    inp = FakeInput()
    result = autofill(token, inp)
    assert result.status is AutofillStatus.DONE
    assert result.login_entered and result.password_entered
    assert ENTER in inp.events


def test_6b_no_cancellation_argument_behaves_exactly_as_before():
    provider = FortiClientProvider(sole_environment())
    target = provider.secure_window_target(api=FakeDesktop(),
                                           finder=ListFinder((HWND,)))
    inp = FakeInput()
    result = provider.autofill_login_password(
        VpnRequest(provider_id="forticlient", login=LOGIN, password=PASSWORD),
        target=target, input_system=inp, msaa=inp.msaa)   # no cancellation=
    assert result.status is AutofillStatus.DONE


# ══════════════════════════════════════════════════════════════════════════
# 2. The prompt keeps Cancel through the fill, and the token is shared
# ══════════════════════════════════════════════════════════════════════════

def test_7_the_held_presenter_offers_cancel_through_activation_observed():
    held = ActivationPresenter("activation-observed", hold_cancel=True)
    assert held.cancel_visible, "trzymany prompt daje Anuluj w trakcie wypełniania"
    plain = ActivationPresenter("activation-observed")
    assert not plain.cancel_visible, "zwykły prompt kończy się z bramką"
    assert "activation-observed" in HELD_STATES


def test_7b_a_held_prompt_still_hides_cancel_for_a_finished_state():
    for state in ("activation-timeout", "no-target", "cancelled",
                  "target-changed"):
        assert not ActivationPresenter(state, hold_cancel=True).cancel_visible, state
    # And an unknown state never gets a button, held or not.
    assert not ActivationPresenter("stage-48-invented",
                                   hold_cancel=True).cancel_visible


def test_8_the_runtime_cancellation_reaches_the_fill(app_module):
    """End to end on the fake machine: a Cancel after the wait stops the fill.

    The session, the worker, the provider and the fill all share one token,
    and the fill checks it before every keystroke.  Tripping it once the
    activation has been observed makes the fill stop with CANCELLED and the
    card say so.
    """
    from tests.test_vpn_forticlient_connect_assembled import (
        FakeClock, FakeLaunch, FakeMessages, RecTrace, ScriptedProvider,
        desktop_with,
    )

    provider = ScriptedProvider(
        environment=forti_environment(),
        main_hwnds=(HWND,), system=FakeLaunch())
    desktop = desktop_with(main_window=True)
    token = CancellationToken()
    # An input that trips the shared token as soon as the login is read back.
    inp = CancellingInput(token, cancel_when_read_equals=LOGIN)
    runtime = provider.connect_runtime(
        clock=FakeClock(), launch_system=FakeLaunch(), input_system=inp,
        window_api=desktop, message_system=FakeMessages(), trace=RecTrace(),
        cancellation=token, msaa_system=inp.msaa)

    result = provider.connect(
        build_request(vault_profile(), app_path=FORTI_GUI, autofill=True),
        system=runtime)

    assert result.error_code == ErrorCode.CANCELLED.value
    assert result.autofill is not None
    assert result.autofill.status is AutofillStatus.CANCELLED
    assert PASSWORD not in [e[1] for e in inp.events if e[0] == "clip_set"]
    # The profile's own Enter (it commits the VPN Name list, before any
    # secret) is allowed; no Enter that would connect.
    assert submit_enters(inp.events) == []


# ══════════════════════════════════════════════════════════════════════════
# 3. Cancel through the whole UI chain (card → worker → prompt → session)
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def app_module():
    existing = QApplication.instance()
    return existing if existing is not None else QApplication([])


@pytest.fixture
def card(app_module):
    holder = QWidget()
    label = QLabel("", holder)
    yield SimpleNamespace(holder=holder, label=label)
    holder.deleteLater()


def test_9_cancel_during_the_wait_is_cancelled_and_touches_nothing(card):
    reached, release = threading.Event(), threading.Event()

    def foreground(n):
        if n == 2:
            reached.set()
            release.wait(10)
        return HWND if n > 2 else OTHER      # the client WOULD come forward

    m = machine(foreground=foreground, timeout_s=30.0)
    session = session_on(m)
    run = Harness(session, card).start()
    run.pump(until=reached.is_set)
    run.pump(until=lambda: run.controller.prompt.presenter.state
             == "awaiting-activation")
    assert run.controller.prompt.cancel_button.isVisibleTo(run.controller.prompt)

    run.controller.prompt.cancel_button.click()
    assert session.cancellation.cancelled
    release.set()
    outcome = run.finish()

    assert outcome.code is PanelOutcome.CANCELLED
    assert secret_events(m.inputs) == []
    assert card.label.text() == STATE_MESSAGES["cancelled"]


def test_10_cancel_right_after_activation_observed_still_stops_the_fill(card):
    """The gap Stage 46 could not cover: the activation is in, the fill has
    just begun, and Cancel is still on screen and still works."""
    m = machine()                               # client in front the whole time
    # Trip the shared token the moment the login is read back — i.e. one step
    # into the fill, right after ACTIVATION_OBSERVED.
    m.inputs.__class__ = CancellingInput
    m.inputs._token = None
    run = Harness(session_on(m), card)
    # Wire the machine's input to the session's token now that it exists.
    m.inputs._token = run.session.cancellation
    m.inputs._read_trigger = LOGIN
    m.inputs._field_trigger = None
    outcome = run.start().finish()

    assert outcome.code is PanelOutcome.CANCELLED and not outcome.started
    assert PASSWORD not in [e[1] for e in m.inputs.events if e[0] == "clip_set"]
    assert submit_enters(m.inputs.events) == []
    assert card.label.text() == STATE_MESSAGES["cancelled"]


def test_11_the_button_stays_until_the_session_is_over(card):
    """While the fill runs the prompt still shows Cancel; when it ends, gone."""
    m = machine()
    run = Harness(session_on(m), card).start()
    outcome = run.finish()
    # After a normal success the held prompt is released and hidden.
    assert outcome.code is PanelOutcome.SUBMITTED
    assert run.controller.done
    assert not run.controller.prompt.cancel_button.isVisibleTo(card.holder)


# ══════════════════════════════════════════════════════════════════════════
# 4. Status polling: paused for the session, resumed when it ends
# ══════════════════════════════════════════════════════════════════════════

class PollingSpy:
    """Stands in for the panel's status timer.  Records pause/resume order."""

    def __init__(self, controller):
        self.events = []
        controller.polling_pause.connect(lambda: self.events.append("pause"))
        controller.polling_resume.connect(lambda: self.events.append("resume"))
        controller.finished.connect(lambda _o: self.events.append("finished"))


def test_12_polling_pauses_at_start_and_resumes_once_at_the_end(card):
    m = machine()
    run = Harness(session_on(m), card)
    spy = PollingSpy(run.controller)

    assert spy.events == [], "nic zanim wystartujemy"
    run.start()
    assert spy.events[0] == "pause", "pauza zanim worker dotknie klienta"
    assert run.controller.active
    run.finish()

    assert spy.events == ["pause", "finished", "resume"]
    assert not run.controller.active
    assert spy.events.count("resume") == 1


@pytest.mark.parametrize("build_machine,expected", [
    (lambda: machine(), PanelOutcome.SUBMITTED),
    (lambda: machine(window=False, files=[]), PanelOutcome.CLIENT_NOT_FOUND),
    (lambda: machine(foreground=lambda n: OTHER, timeout_s=2.0),
     PanelOutcome.ACTIVATION_TIMEOUT),
])
def test_13_resume_fires_for_every_terminal_outcome(card, build_machine, expected):
    m = build_machine()
    run = Harness(session_on(m), card)
    spy = PollingSpy(run.controller)
    outcome = run.start().finish()

    assert outcome.code is expected
    assert spy.events == ["pause", "finished", "resume"]


def test_14_resume_fires_after_a_cancel_too(card):
    m = machine(foreground=lambda n: OTHER, timeout_s=30.0)
    session = session_on(m)
    run = Harness(session, card)
    spy = PollingSpy(run.controller)
    run.controller.cancel()               # off before it even starts
    run.start().finish()

    assert spy.events == ["pause", "finished", "resume"]
    assert not run.controller.active


def test_15_active_is_false_before_start_and_after_finish(card):
    m = machine()
    run = Harness(session_on(m), card)
    assert not run.controller.active, "nieuruchomiona sesja nie jest aktywna"
    run.start()
    assert run.controller.active
    run.finish()
    assert not run.controller.active, "po zakończeniu polling wraca"


def test_16_the_card_is_not_touched_by_a_would_be_poll_while_active(card):
    """The card belongs to the session while active; a poll must defer to it.

    The panel gates its own `_apply_status_results` on `controller.active`;
    this proves the flag is true across the whole run and false at its edges,
    which is the contract that gating relies on.
    """
    reached, release = threading.Event(), threading.Event()

    def foreground(n):
        if n == 2:
            reached.set()
            release.wait(10)
        return OTHER if n <= 2 else HWND

    m = machine(foreground=foreground)
    run = Harness(session_on(m), card).start()
    run.pump(until=reached.is_set)
    assert run.controller.active, "aktywna przez cały czas czekania"
    release.set()
    run.finish()
    assert not run.controller.active
