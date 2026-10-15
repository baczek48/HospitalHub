"""Stage 25 part C: the user minimises the client after the gate said yes.

Stage 24 saw this on the real machine and left it undecided: the gate reports
``ACTIVATION_OBSERVED``, the user then minimises FortiClient, and the autofill
still finishes ``done``.  Nothing was measured as unsafe — every keystroke went
to a window that really was in front — but "nothing went wrong this time" is
not a contract, and these tests exist to turn the question into evidence.

What is actually being asked
----------------------------
There are two definitions of "this window is ready to receive a secret" in the
tree, and Stage 22 only changed one of them:

* ``foreground_check`` (Stage 22, read-only, used by the gate) refuses a
  minimised window — ``REASON_MINIMISED``;
* ``confirm_target`` (shared with the legacy, used by every guard inside the
  autofill) does not look at ``is_iconic`` at all.

Between them sits ``acquire_focus``, which calls ``restore_window`` — an
unconditional ``SW_RESTORE`` — *before* it confirms anything.  So the flow can
undo the user's decision to put the client away, and then satisfy itself that
the window it just raised is in front.

These tests pinned down exactly where the restore happens, what the desktop
looks like at the instant the first secret moves, and what happens when the
restore does not work.  Stage 29 then acted on that evidence: ``VerifiedWindow``
learned to refuse a minimised target, so ``test_6`` below now asserts the
opposite of what it originally proved — deliberately kept in place, because the
measurement is the reason the condition exists.

Stage 33 then finished the job: ``acquire_focus`` gained ``raise_window``, the
FortiClient main-window target asks for ``False``, and the V2 path no longer
restores or raises anything at all.  The tests below were rewritten again at
that point — each one still starts from the same measured situation, and each
now asserts what the contract says should happen instead.

``SW_RESTORE`` still exists, unchanged, for ``raise_window=True`` — the legacy
and the EMS auth window.  What changed is who asks for it.
"""

import ast
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import secure_window as sw  # noqa: E402
import vpn  # noqa: E402
from vpn import AutofillStatus, VpnRequest  # noqa: E402
from vpn.providers import FortiClientProvider, SecureWindowTarget  # noqa: E402
from vpn.providers.activation_gate import (  # noqa: E402
    ActivationGate, ActivationState, CancellationToken,
)
from tests.test_vpn_activation_gate import FakeClock  # noqa: E402
from tests.test_vpn_forticlient_autofill import (  # noqa: E402
    LOGIN, PASSWORD, FakeInput, RecTrace,
)
from tests.test_vpn_forticlient_detect import FakeEnvironment  # noqa: E402
from tests.test_vpn_secure_target import (  # noqa: E402
    FORTI_DIR, FORTI_GUI, FORTI_PID, HWND, OTHER, TRUSTED, FakeDesktop,
    ListFinder,
)


class MinimisableDesktop(FakeDesktop):
    """A desktop that knows what minimised means, and records what happened.

    Two knobs, because the difference between them is the whole question:

    ``restore_works`` — whether ``SW_RESTORE`` actually un-minimises.  True is
    the ordinary case.  False is not a fantasy: Stage 19 measured a minimised
    window staying ``GetForegroundWindow()``, and a client that is busy, hung,
    or animating can fail to come back inside the flow's timing.

    ``iconic`` starts as whatever the test says the user did.
    """

    def __init__(self, *, iconic=True, restore_works=True, foreground=None,
                 **kwargs):
        kwargs.setdefault("foreground", foreground or (lambda n: HWND))
        super().__init__(**kwargs)
        self.iconic = iconic
        self.restore_works = restore_works
        #: Index into `self.events` at which each restore happened.
        self.restores = []

    def is_iconic(self, hwnd):
        return self.iconic if hwnd == HWND else False

    def restore_window(self, hwnd):
        self.restores.append(len(self.events))
        self.events.append(("restore",))
        if self.restore_works:
            self.iconic = False


class WatchingInput(FakeInput):
    """Records keystrokes *and* what the desktop looked like at that instant.

    The safety property is not "the autofill refused" — it is "no secret moved
    while the window was unusable".  That can only be asked at the moment of
    the move, so the desktop is sampled here rather than reconstructed after.
    """

    def __init__(self, desktop):
        super().__init__()
        self.desktop = desktop
        #: (event, iconic-at-that-moment) for every event carrying a secret.
        self.secret_moments = []

    def _note(self, event):
        if event[0] == "clip_set" and event[1] in (LOGIN, PASSWORD):
            self.secret_moments.append((event, self.desktop.iconic))

    def type_text(self, text):
        super().type_text(text)
        self._note(("type", text))

    def copy_to_clipboard(self, text):
        result = super().copy_to_clipboard(text)
        self._note(("clip_set", text))
        return result


def provider():
    return FortiClientProvider(
        FakeEnvironment(files=[FORTI_GUI], dirs=[FORTI_DIR]))


def run_autofill(desktop, *, inputs=None):
    inputs = inputs if inputs is not None else WatchingInput(desktop)
    prov = provider()
    target = prov.secure_window_target(api=desktop, finder=ListFinder((HWND,)))
    request = VpnRequest(provider_id="forticlient", login=LOGIN,
                         password=PASSWORD, profile_name="")
    result = prov.autofill_login_password(
        request, target=target, input_system=inputs, trace=RecTrace())
    return result, inputs


def run_gate(desktop):
    return ActivationGate(
        target=SecureWindowTarget(TRUSTED, api=desktop,
                                  finder=ListFinder((HWND,))),
        clock=FakeClock(), cancellation=CancellationToken(),
        timeout_s=5.0).wait()


def first_secret_index(events):
    for index, event in enumerate(events):
        if event[0] == "clip_set" and event[1] in (LOGIN, PASSWORD):
            return index
    return None


# ══════════════════════════════════════════════════════════════════════════
# 1–2. The two definitions of "ready", and where they disagree
# ══════════════════════════════════════════════════════════════════════════

def test_1_the_gate_says_yes_and_then_the_user_puts_the_client_away():
    """The sequence Stage 24 measured, reproduced exactly."""
    desktop = MinimisableDesktop(iconic=False)
    assert run_gate(desktop).state is ActivationState.ACTIVATION_OBSERVED

    desktop.iconic = True                      # the user minimises it
    again = SecureWindowTarget(TRUSTED, api=desktop,
                               finder=ListFinder((HWND,))).foreground_check()
    assert not again.ok and again.reason == "target-minimised"
    assert again.foreground is True and again.iconic is True


def test_2_confirm_target_does_not_look_at_iconic_at_all():
    """The guard's own definition of "ready" has no idea the window is away.

    This is the disagreement in one assertion: the same desktop, the same
    window, two readings, opposite answers.  ``foreground_check`` refuses
    because Stage 22 taught it to; ``confirm_target`` — which is what every
    guard inside the autofill calls — says yes.
    """
    desktop = MinimisableDesktop(iconic=True)
    check = sw.confirm_target(HWND, FORTI_PID, TRUSTED, desktop)
    assert check.ok is True and check.reason == "focused"

    source = open(sw.__file__, encoding="utf-8").read()
    body = source[source.index("def confirm_target"):source.index("def acquire_focus")]
    assert "is_iconic" not in body, \
        "gdyby to się zmieniło, ten etap trzeba przeczytać od nowa"


# ══════════════════════════════════════════════════════════════════════════
# 3–5. Where SW_RESTORE happens, and what the desktop looks like at the
#      instant the first secret moves
# ══════════════════════════════════════════════════════════════════════════

def test_3_the_v2_path_no_longer_restores_or_raises_anything():
    """Until Stage 33 this measured ``attach → restore → set_foreground``.

    That order was the problem: the restore came first and the confirmation
    came after, so the window was already back up before anything had a chance
    to object.  With ``raise_window=False`` the objection happens first and the
    desktop is never touched at all.
    """
    desktop = MinimisableDesktop(iconic=True)
    result, _inputs = run_autofill(desktop)

    assert desktop.events == [], desktop.events
    assert desktop.restores == [], "żadnego SW_RESTORE"
    assert result.status is AutofillStatus.NO_FOCUS
    assert result.blocked_at == "acquire"


def test_4_there_is_no_navigation_to_precede_a_secret_any_more():
    """This used to measure the distance between the restore and the first
    secret — eight operations and nearly three seconds of it.  The distance is
    now the whole sequence, because the sequence never starts.
    """
    desktop = MinimisableDesktop(iconic=True)
    _result, inputs = run_autofill(desktop)

    assert first_secret_index(inputs.events) is None, "żaden sekret nie ruszył"
    assert inputs.events == [], "ani jedno zdarzenie wejścia"


def test_5_a_working_restore_no_longer_makes_a_minimised_window_usable():
    """The case Stage 24 measured as "nothing unsafe happened".

    It was true and it was not enough: the secret reached a visible window only
    because the flow had just made it visible.  Now a minimised target is
    refused whether or not it *could* have been restored.
    """
    desktop = MinimisableDesktop(iconic=True, restore_works=True)
    result, inputs = run_autofill(desktop)

    assert result.status is AutofillStatus.NO_FOCUS
    assert inputs.secret_moments == [], "żaden sekret nie ruszył"
    assert desktop.restores == []


def test_5b_the_flow_no_longer_undoes_the_users_decision():
    """The heart of Variant 2, in one assertion: the window stays put.

    Stage 24 measured this on the real desktop and it was not exotic: a
    minimised window can remain ``GetForegroundWindow()``, so
    ``SetForegroundWindow`` succeeded trivially, nothing refused anything, the
    window the user had put away came back up and the credentials went into it.
    No guard was violated — the guards were never asked the question.

    Now the question is asked before anything is touched, and the answer ends
    the attempt.
    """
    desktop = MinimisableDesktop(iconic=True, restore_works=True)
    assert desktop.iconic is True, "użytkownik odłożył okno"

    result, inputs = run_autofill(desktop)

    assert desktop.iconic is True, "i okno TAM ZOSTAŁO — flow go nie cofnął"
    assert desktop.restores == [], "żadnego SW_RESTORE"
    assert result.status is AutofillStatus.NO_FOCUS
    assert inputs.secret_moments == []
    # The refusal carries the reason the gate would have given.
    assert (result.metadata or {}).get("reason_code") == "target-minimised"


# ══════════════════════════════════════════════════════════════════════════
# 6. The gap: a restore that does not work
# ══════════════════════════════════════════════════════════════════════════

def test_6_a_window_that_does_not_come_back_now_receives_nothing():
    """The gap this file was written to document, and its closing.

    Until Stage 29 this test asserted the opposite, and passed: ``SW_RESTORE``
    was asked for, did not take effect, the window stayed minimised *and* stayed
    the foreground window, every guard confirmed — because ``confirm_target``
    never asks about ``is_iconic`` — and both credentials were pasted into a
    window the user could not see.

    Variant 1 added that missing question to ``VerifiedWindow.confirm``, so the
    very first guard now refuses and the sequence stops before the navigation
    is even finished.  The window still fails to come back; what changed is
    that nothing is typed into it.
    """
    desktop = MinimisableDesktop(iconic=True, restore_works=False)
    result, inputs = run_autofill(desktop)

    assert result.status is not AutofillStatus.DONE
    assert not result.login_entered and not result.password_entered
    assert inputs.secret_moments == [], "żaden sekret nie ruszył"
    # Stage 29 stopped this at `navigation`, one guard in.  Stage 33 stops it
    # at `acquire`, before the window is even attached to.
    assert result.blocked_at == "acquire", result.blocked_at
    assert desktop.events == []

    # `confirm_target` itself is unchanged and would still have waved it
    # through — the refusal comes from the V2-only conditions above it.
    assert sw.confirm_target(HWND, FORTI_PID, TRUSTED, desktop).ok


def test_6b_the_stage_22_reading_would_have_refused_that_very_window():
    """The tree already contains the check that would have stopped it."""
    desktop = MinimisableDesktop(iconic=True, restore_works=False)
    check = SecureWindowTarget(TRUSTED, api=desktop,
                               finder=ListFinder((HWND,))).foreground_check()
    assert not check.ok and check.reason == "target-minimised"


def test_6c_nothing_re_reads_the_desktop_between_the_gate_and_the_autofill():
    """The flow does not look again — so the gate's answer is the last word.

    Structural, on the connect flow itself: between ``await_activation`` and
    ``start_autofill`` there is no further call on the system.  Whatever the
    gate concluded is what the autofill starts from, and the autofill's own
    guards then use the definition that ignores ``is_iconic``.
    """
    from vpn.providers import forticlient_connect as fcc

    tree = ast.parse(open(fcc.__file__, encoding="utf-8").read())
    body = next(n for n in ast.walk(tree)
                if isinstance(n, ast.FunctionDef) and n.name == "_gui_outcome")
    calls = [n.func.attr for n in ast.walk(body)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)
             and isinstance(n.func.value, ast.Attribute)
             and n.func.value.attr == "_system"]
    start, end = calls.index("await_activation"), calls.index("start_autofill")
    assert calls[start + 1:end] == [], calls


# ══════════════════════════════════════════════════════════════════════════
# 7. The control: a *foreign* window in front still closes everything
# ══════════════════════════════════════════════════════════════════════════

def test_7_a_foreign_foreground_refuses_the_focus_and_sends_nothing():
    """Scenario D on fakes — the case the real desktop would not let us stage.

    Windows refuses ``SetForegroundWindow`` to a background process when
    another process holds the foreground (measured in Stages 18 and 20), so
    this models the refusal rather than the policy.  The point is what the flow
    does with it: no focus, no navigation, no keystroke, no clipboard write.
    """
    desktop = MinimisableDesktop(iconic=False, foreground=lambda n: OTHER,
                                 set_foreground="fails")
    result, inputs = run_autofill(desktop)

    assert result.status is not AutofillStatus.DONE
    assert result.error_code == "no_focus" or result.blocked_at == "acquire", \
        (result.error_code, result.blocked_at)
    assert not result.login_entered and not result.password_entered
    assert inputs.events == [], inputs.events
    assert inputs.secret_moments == []


def test_7b_the_foreground_changing_mid_sequence_stops_the_next_secret():
    """And when it goes away *during* the fill, the password is not sent."""
    # In front for the acquire and the navigation, gone by the login clipboard.
    desktop = MinimisableDesktop(
        iconic=False, foreground=lambda n: HWND if n <= 4 else OTHER)
    result, inputs = run_autofill(desktop)

    assert result.status is not AutofillStatus.DONE
    assert not result.password_entered
    assert PASSWORD not in [e[1] for e in inputs.events if e[0] == "clip_set"]
