"""Stage 33 / Variant 2: after the gate, V2 stops raising the window itself.

Stage 22 made the connect wait for the user to bring FortiClient forward,
because measurement had shown a background process cannot take the foreground
from another process' window.  But the path to the autofill still ran through
``acquire_focus``, whose first act is an unconditional ``SW_RESTORE`` followed
by ``SetForegroundWindow`` — so the flow undid the user's decision the moment
it started typing, and Stage 31 showed ``require_visible`` could not catch it:
by the time any guard looked, the window had already been put back.

Variant 2 closes that with one keyword argument.  ``acquire_focus`` keeps its
behaviour for every existing caller (``raise_window=True``, the default, which
is what the legacy passes by passing nothing), and the FortiClient main-window
target asks for ``raise_window=False``: the window must **already** be active
and visible, and if it is not, the answer is no.

``raise_window=False`` is not a second way of activating a window.  There is no
fallback, no retry, no alternative API — that is the whole point.
"""

import ast
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import secure_window as sw  # noqa: E402
from vpn import AutofillStatus  # noqa: E402
from vpn.providers import FortiClientProvider  # noqa: E402
from vpn.providers.secure_target import (  # noqa: E402
    REASON_MINIMISED, REASON_VISIBILITY_UNKNOWN, SecureWindowTarget,
    TargetRejected, VerifiedWindow,
)
from tests.test_vpn_forticlient_detect import FakeEnvironment  # noqa: E402
from tests.test_vpn_forticlient_autofill import (  # noqa: E402
    LOGIN, PASSWORD, FakeInput, RecTrace,
)
from tests.test_vpn_secure_target import (  # noqa: E402
    FORTI_DIR, FORTI_GUI, FORTI_PID, HWND, OTHER, TRUSTED, FakeDesktop,
    ListFinder,
)


class Desktop(FakeDesktop):
    """A desktop that records what was done to it and knows about minimising."""

    def __init__(self, *, iconic=False, iconic_raises=False, **kwargs):
        kwargs["iconic"] = iconic
        super().__init__(**kwargs)
        self._iconic_raises = iconic_raises

    def is_iconic(self, hwnd):
        if self._iconic_raises:
            raise OSError("pulpit odmowil odpowiedzi")
        return self._iconic

    def did(self, what):
        return [e for e in self.events if e[0] == what]


def target(desktop, *, raise_window=True, require_visible=False):
    return SecureWindowTarget(TRUSTED, api=desktop, finder=ListFinder((HWND,)),
                              raise_window=raise_window,
                              require_visible=require_visible)


def v2_target(desktop):
    """Exactly what the FortiClient main-window target is configured as."""
    return target(desktop, raise_window=False, require_visible=True)


# ══════════════════════════════════════════════════════════════════════════
# A. raise_window=True — the existing behaviour, untouched
# ══════════════════════════════════════════════════════════════════════════

def test_1_the_default_still_attaches_restores_and_raises_in_that_order():
    desktop = Desktop()
    acquired = target(desktop).acquire(HWND)

    assert isinstance(acquired, VerifiedWindow)
    assert [e[0] for e in desktop.events] == ["attach", "restore",
                                              "set_foreground"]
    acquired.release()


def test_1b_a_minimised_window_is_still_raised_when_raising_is_allowed():
    """The legacy shape: restore first, ask questions afterwards."""
    desktop = Desktop(iconic=True)
    acquired = target(desktop).acquire(HWND)

    assert isinstance(acquired, VerifiedWindow)
    assert desktop.did("restore"), "to jest dokladnie stare zachowanie"
    acquired.release()


def test_1c_the_default_is_true_so_no_existing_caller_changes():
    import inspect

    signature = inspect.signature(sw.acquire_focus)
    assert signature.parameters["raise_window"].default is True
    assert signature.parameters["raise_window"].kind is inspect.Parameter.KEYWORD_ONLY
    assert SecureWindowTarget(TRUSTED)._raise_window is True


# ══════════════════════════════════════════════════════════════════════════
# B. raise_window=False — the window must already be active
# ══════════════════════════════════════════════════════════════════════════

def test_2_nothing_is_restored_and_nothing_is_raised():
    desktop = Desktop()
    acquired = v2_target(desktop).acquire(HWND)

    assert isinstance(acquired, VerifiedWindow), "okno bylo aktywne, wiec OK"
    assert desktop.did("restore") == [], "zadnego SW_RESTORE"
    assert desktop.did("set_foreground") == [], "zadnego SetForegroundWindow"
    assert desktop.did("attach"), "attach zostaje — VerifiedWindow go potrzebuje"
    acquired.release()


def test_3_another_window_in_front_is_refused():
    desktop = Desktop(foreground=lambda n: OTHER)
    rejected = v2_target(desktop).acquire(HWND)

    assert isinstance(rejected, TargetRejected)
    assert rejected.reason == "foreground-is-other-window"
    assert desktop.events == [], "odmowa zanim czegokolwiek dotknieto"


def test_4_a_minimised_target_is_refused():
    desktop = Desktop(iconic=True)
    rejected = v2_target(desktop).acquire(HWND)

    assert isinstance(rejected, TargetRejected)
    assert rejected.reason == REASON_MINIMISED
    assert desktop.did("restore") == [], "nie przywracamy, zeby moc go uzyc"
    assert desktop.events == []


def test_5_an_active_and_visible_target_is_accepted():
    desktop = Desktop(iconic=False)
    acquired = v2_target(desktop).acquire(HWND)

    assert isinstance(acquired, VerifiedWindow)
    assert acquired.pid == FORTI_PID
    acquired.release()


def test_6_a_desktop_that_cannot_answer_is_refused():
    """"We could not see" is not a yes — not on the path to a password.

    ``foreground_check`` keeps its own contract: there an unreadable
    ``is_iconic`` must not veto, because it is what the activation gate polls
    with and "we could not see" is not "the user went away".  The acquire path
    asks a different question — *may a secret be typed here?* — and composes
    the stricter answer through :meth:`strict_foreground_check`.
    """
    for desktop in (Desktop(iconic_raises=True), Desktop(iconic=None)):
        rejected = v2_target(desktop).acquire(HWND)
        assert isinstance(rejected, TargetRejected), desktop._iconic
        assert rejected.reason == REASON_VISIBILITY_UNKNOWN, rejected.reason
        assert desktop.events == [], "odmowa przed attach"


def test_6b_the_shared_reading_still_treats_unknown_as_unknown():
    """The global contract is untouched — only the V2 path narrows it."""
    plain = target(Desktop(iconic=None)).foreground_check(HWND)
    assert plain.ok and plain.iconic is None

    strict = target(Desktop(iconic=None)).strict_foreground_check(HWND)
    assert not strict.ok and strict.reason == REASON_VISIBILITY_UNKNOWN


def test_6c_a_minimised_window_is_told_apart_from_an_unreadable_one():
    """Two refusals, two reasons — a trace has to be able to say which."""
    minimised = v2_target(Desktop(iconic=True)).acquire(HWND)
    unknown = v2_target(Desktop(iconic=None)).acquire(HWND)
    assert minimised.reason == REASON_MINIMISED
    assert unknown.reason == REASON_VISIBILITY_UNKNOWN


def test_7_acquire_any_inherits_the_setting_without_its_own_mechanism():
    desktop = Desktop(iconic=True)
    rejected = v2_target(desktop).acquire_any()

    assert isinstance(rejected, TargetRejected)
    assert rejected.reason == REASON_MINIMISED
    assert desktop.events == [], "petla po kandydatach tez niczego nie podnosi"


# ══════════════════════════════════════════════════════════════════════════
# C + D. Which target gets which contract
# ══════════════════════════════════════════════════════════════════════════

def test_8_the_forticlient_main_window_target_is_the_new_contract():
    provider = FortiClientProvider(
        FakeEnvironment(files=[FORTI_GUI], dirs=[FORTI_DIR]))
    main = provider.secure_window_target()
    assert main._raise_window is False
    assert main._require_visible is True


def test_9_the_ems_auth_window_target_is_unchanged():
    """A different window, a different contract — and deliberately so.

    The EMS dialog appears *because* the gateway asked for a token; no
    activation gate stands behind it, the token goes in by ``WM_SETTEXT``
    rather than keystrokes, and raising a dialog that is asking for input is
    the helpful thing to do.
    """
    provider = FortiClientProvider(
        FakeEnvironment(files=[FORTI_GUI], dirs=[FORTI_DIR]))
    auth = provider.auth_window_target()
    assert auth._raise_window is True
    assert auth._require_visible is False


# ══════════════════════════════════════════════════════════════════════════
# E + F. Legacy, and the absence of new machinery
# ══════════════════════════════════════════════════════════════════════════

def test_10_legacy_calls_acquire_focus_without_the_new_argument():
    legacy = open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read()
    assert "raise_window" not in legacy, \
        "legacy nie zna tego parametru i ma dostawac domyslne zachowanie"

    tree = ast.parse(legacy)
    calls = [n for n in ast.walk(tree)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
             and n.func.id == "acquire_focus"]
    assert calls, "legacy nadal wola wspolna funkcje"
    for call in calls:
        assert not [k for k in call.keywords if k.arg == "raise_window"]


def test_11_the_legacy_shaped_call_behaves_exactly_as_before():
    """Positional, no keywords — the call legacy makes — still raises."""
    desktop = Desktop(iconic=True)
    result = sw.acquire_focus(HWND, FORTI_PID, TRUSTED, desktop)
    assert result.ok
    assert [e[0] for e in desktop.events] == ["attach", "restore",
                                              "set_foreground"]


def test_12_no_new_way_of_taking_the_foreground_was_introduced():
    for module_path in (sw.__file__,
                        os.path.join(_PARENT, "vpn", "providers",
                                     "secure_target.py")):
        tree = ast.parse(open(module_path, encoding="utf-8").read())
        names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
        names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
        for banned in ("SwitchToThisWindow", "keybd_event", "mouse_event",
                       "BringWindowToTop", "SetFocus", "AllowSetForegroundWindow",
                       "SetWindowPos", "ShowWindowAsync", "SendInput"):
            assert banned not in names, (os.path.basename(module_path), banned)


def test_12b_the_v2_path_reaches_the_desktop_through_reads_only():
    """Behavioural twin: a refused V2 acquire leaves no trace on the desktop."""
    for desktop in (Desktop(iconic=True), Desktop(foreground=lambda n: OTHER)):
        v2_target(desktop).acquire_any()
        assert desktop.events == [], desktop.events


# ══════════════════════════════════════════════════════════════════════════
# G. Regression on the exact gap Stage 31 identified
# ══════════════════════════════════════════════════════════════════════════

def test_13_activation_observed_then_minimised_sends_nothing():
    """The whole point of Variant 2, end to end.

    The user activates the client, the gate is satisfied, and then — in the
    gap before the autofill acquires anything — they put the window away.
    Before this stage ``SW_RESTORE`` pulled it back up and the credentials went
    in.  Now the acquire refuses and not one seam is touched.
    """
    from vpn.providers.activation_gate import ActivationGate, ActivationState
    from vpn.providers.activation_gate import CancellationToken
    from tests.test_vpn_activation_gate import FakeClock
    from vpn import VpnRequest

    desktop = Desktop(iconic=False)
    provider = FortiClientProvider(
        FakeEnvironment(files=[FORTI_GUI], dirs=[FORTI_DIR]))

    # 1. A real activation, observed by the real gate.
    gate = ActivationGate(
        target=SecureWindowTarget(TRUSTED, api=desktop,
                                  finder=ListFinder((HWND,))),
        clock=FakeClock(), cancellation=CancellationToken(), timeout_s=5.0)
    assert gate.wait().state is ActivationState.ACTIVATION_OBSERVED

    # 2. The user puts the client away.
    desktop._iconic = True

    # 3. The autofill tries to start, through the V2 target.
    inputs = FakeInput()
    result = provider.autofill_login_password(
        VpnRequest(provider_id="forticlient", login=LOGIN, password=PASSWORD,
                   profile_name=""),
        target=v2_target(desktop), input_system=inputs, trace=RecTrace())

    assert result.status is AutofillStatus.NO_FOCUS
    assert result.blocked_at == "acquire"
    assert (result.metadata or {}).get("reason_code") == REASON_MINIMISED
    assert not result.login_entered and not result.password_entered
    assert desktop.did("restore") == [], "SW_RESTORE: 0"
    assert desktop.did("set_foreground") == [], "SetForegroundWindow: 0"
    assert desktop.events == [], "nic nie dotknelo pulpitu"
    assert inputs.events == [], "zaden InputSystem, zaden schowek, zaden sekret"
    assert desktop._iconic is True, "okno zostalo tam, gdzie je uzytkownik zostawil"


def test_13b_the_same_gap_with_the_user_switching_windows_instead():
    from vpn import VpnRequest

    desktop = Desktop(iconic=False)
    provider = FortiClientProvider(
        FakeEnvironment(files=[FORTI_GUI], dirs=[FORTI_DIR]))
    desktop._foreground = lambda n: OTHER          # they clicked elsewhere

    inputs = FakeInput()
    result = provider.autofill_login_password(
        VpnRequest(provider_id="forticlient", login=LOGIN, password=PASSWORD,
                   profile_name=""),
        target=v2_target(desktop), input_system=inputs, trace=RecTrace())

    assert result.status is AutofillStatus.NO_FOCUS
    assert (result.metadata or {}).get("reason_code") == "foreground-is-other-window"
    assert inputs.events == []
    assert desktop.events == []
