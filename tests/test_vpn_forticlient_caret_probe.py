"""Stage 42: the autofill checks where the caret is before the secret moves.

A live run in Stage 41 did this: the operator clicked the FortiClient window to
satisfy the activation gate, three Tabs landed on the hamburger next to the
profile list instead of the username field, ``Ctrl+A`` selected the entire
document, and ``Enter`` opened a menu.  The result said ``done``,
``login_entered=True``, ``password_entered=True``.  Nothing had been entered
anywhere.

Two things were wrong and both are fixed here:

* the password reached the **system clipboard** before anything established
  that a paste had somewhere to land — an exposure that bought nothing;
* the sequence reported success for keystrokes that went into a document body.

The fix is two readings.  A **probe** after each clear asks whether the caret
is in a text box, and it is asked *after* the field was emptied, so it reads an
empty field and never the user's data.  A **verify** after the login paste
reads the field back; if the login did not land, the password never follows.

The password is not verified the same way — a password box refuses to be
copied from, so reading it back would prove nothing.  The login's verify is
what establishes that the caret walks the fields as expected.
"""

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from vpn import AutofillStatus  # noqa: E402
from vpn.providers import forticlient_autofill as fa  # noqa: E402
from tests.test_vpn_forticlient_autofill import (  # noqa: E402
    LOGIN, PASSWORD, PREV_CLIP, FakeInput, RecTrace, clipboard_secrets, run,
    secret_ops,
)
from tests.test_vpn_forticlient_detect import FakeEnvironment  # noqa: E402
from tests.test_vpn_secure_target import (  # noqa: E402
    FORTI_DIR, FORTI_GUI, HWND, FakeDesktop, ListFinder,
)


def run_with(inputs):
    """The real autofill, against a good desktop, with a chosen input seam."""
    from vpn import VpnRequest
    from vpn.providers import FortiClientProvider

    from tests.test_vpn_forticlient_autofill import sole_environment

    # No profile name: the one-tunnel machine, its tunnel showing (L1).
    provider = FortiClientProvider(sole_environment())
    desktop = FakeDesktop()
    target = provider.secure_window_target(api=desktop, finder=ListFinder((HWND,)))
    request = VpnRequest(provider_id="forticlient", profile_name="",
                         login=LOGIN, password=PASSWORD)
    result = provider.autofill_login_password(
        request, target=target, input_system=inputs, trace=RecTrace(),
        msaa=inputs.msaa)
    return result, inputs.events


# ══════════════════════════════════════════════════════════════════════════
# The caret is not in a field — the Stage-41 live failure
# ══════════════════════════════════════════════════════════════════════════

def test_1_a_caret_outside_a_text_box_stops_before_the_clipboard():
    """The exact live case: Ctrl+A grabs the document, so nothing is pasted.

    Before Stage 42 this run reported ``done`` and had put both credentials on
    the system clipboard.  Since Stage 43 the sequence looks for the field
    instead of counting Tabs, so a window where no tab stop is ever a text box
    exhausts the search and refuses — still before any secret exists outside
    this process.
    """
    result, events = run_with(FakeInput(caret_in_field=False))

    assert result.status is AutofillStatus.BLOCKED
    assert result.blocked_at == fa.PHASE_LOCATE
    assert result.metadata.get("reason_code") == "no-text-field-found"
    assert not result.login_entered and not result.password_entered


def test_1b_the_search_gives_up_instead_of_tabbing_for_ever():
    """A budget, so a client whose layout changed ends the attempt."""
    _result, events = run_with(FakeInput(caret_in_field=False))
    tabs = [e for e in events if e[0] == "key" and e[1] == 0x09]
    assert len(tabs) <= fa.MAX_TAB_STOPS + 1, len(tabs)


def test_2_no_secret_reaches_the_system_clipboard_in_that_case():
    """The point of the whole change: an exposure that bought nothing is gone."""
    _result, events = run_with(FakeInput(caret_in_field=False))

    assert clipboard_secrets(events) == []
    assert PASSWORD not in [e[1] for e in events if e[0] == "clip_set"]
    assert LOGIN not in [e[1] for e in events if e[0] == "clip_set"]


def test_3_and_nothing_is_pasted_or_submitted():
    _result, events = run_with(FakeInput(caret_in_field=False))

    ctrl_v = [e for e in events if e[0] == "combo" and e[2] == ord("V")]
    enter = [e for e in events if e[0] == "key" and e[1] == 0x0D]
    assert ctrl_v == [], "nie wklejamy tam, gdzie nie ma pola"
    assert enter == [], "i na pewno nie zatwierdzamy"


def test_4_the_users_clipboard_is_left_as_it_was():
    """Refusing early must not cost the operator their clipboard either."""
    inputs = FakeInput(caret_in_field=False)
    run_with(inputs)
    assert inputs.clipboard == PREV_CLIP


# ══════════════════════════════════════════════════════════════════════════
# The paste did not land
# ══════════════════════════════════════════════════════════════════════════

class SwallowingField(FakeInput):
    """A field that accepts focus and a probe, but discards what is pasted.

    Models the half-broken case: the caret *is* somewhere Ctrl+A works, but the
    paste does not arrive — a read-only input, a control that steals the
    keystroke, a form that re-renders underneath.  The login verify is what
    catches it.
    """

    def press_combo(self, modifier_vk, key):
        if key == ord("V"):
            self.events.append(("combo", modifier_vk, key))
            return                                    # paste goes nowhere
        super().press_combo(modifier_vk, key)


def test_5_a_login_that_does_not_land_stops_before_the_password():
    result, events = run_with(SwallowingField())

    assert result.status is AutofillStatus.BLOCKED
    assert result.blocked_at == fa.PHASE_LOGIN_VERIFY
    assert result.metadata.get("reason_code") == "paste-did-not-land"


def test_6_the_password_never_reaches_the_clipboard_after_a_failed_login():
    _result, events = run_with(SwallowingField())

    assert clipboard_secrets(events) == [LOGIN], "login owszem, hasło nigdy"
    assert PASSWORD not in [e[1] for e in events if e[0] == "clip_set"]


def test_7_no_enter_after_a_failed_verify():
    _result, events = run_with(SwallowingField())
    assert not [e for e in events if e[0] == "key" and e[1] == 0x0D]


# ══════════════════════════════════════════════════════════════════════════
# The ordinary case still works, and the order is right
# ══════════════════════════════════════════════════════════════════════════

def test_8_a_real_field_fills_and_submits_as_before():
    result, events, _tr = run(profile="")

    assert result.status is AutofillStatus.DONE
    assert result.login_entered and result.password_entered
    assert clipboard_secrets(events) == [LOGIN, PASSWORD]


def test_9_the_probe_happens_before_the_secret_every_time():
    """Order, not just presence: probe, then clipboard.  For both fields."""
    _result, events, _tr = run(profile="")

    kinds = []
    for event in events:
        if event[0] == "clip_set" and event[1] in (LOGIN, PASSWORD):
            kinds.append("secret-to-clipboard")
        elif event[0] == "combo" and event[2] == ord("C"):
            kinds.append("read-back")
    # locate, probe, secret, verify, probe, secret
    assert kinds[0] == "read-back"
    assert kinds.count("secret-to-clipboard") == 2
    for index, kind in enumerate(kinds):
        if kind == "secret-to-clipboard":
            assert kinds[index - 1] == "read-back", \
                "każdy sekret poprzedzony odczytem pola"


def test_10_the_new_phases_are_in_the_published_list():
    assert fa.PHASE_LOGIN_PROBE in fa.PHASES
    assert fa.PHASE_LOGIN_VERIFY in fa.PHASES
    assert fa.PHASE_PASSWORD_PROBE in fa.PHASES
    assert fa.PHASES.index(fa.PHASE_LOGIN_PROBE) < fa.PHASES.index(
        fa.PHASE_LOGIN_CLIPBOARD)
    assert fa.PHASES.index(fa.PHASE_LOGIN_VERIFY) < fa.PHASES.index(
        fa.PHASE_PASSWORD_CLEAR)


def test_11_the_probe_reads_an_empty_field_not_the_users_data():
    """It runs after the clear, so there is nothing of theirs left to read."""
    source = open(fa.__file__, encoding="utf-8").read()
    body = source[source.index("def _fill_field"):]
    clear_at = body.index("clear_phase")
    probe_at = body.index("probe_phase")
    assert clear_at < probe_at, "czyszczenie przed sondą"


def test_12_no_secret_appears_in_the_result_or_trace_when_the_probe_refuses():
    from vpn import VpnRequest
    from vpn.providers import FortiClientProvider

    from tests.test_vpn_forticlient_autofill import sole_environment

    trace = RecTrace()
    provider = FortiClientProvider(sole_environment())
    desktop = FakeDesktop()
    inp = FakeInput(caret_in_field=False)
    result = provider.autofill_login_password(
        VpnRequest(provider_id="forticlient", profile_name="", login=LOGIN,
                   password=PASSWORD),
        target=provider.secure_window_target(api=desktop,
                                             finder=ListFinder((HWND,))),
        input_system=inp, trace=trace, msaa=inp.msaa)

    blob = repr(result) + repr(trace.steps)
    for secret in (LOGIN, PASSWORD):
        assert secret not in blob, secret


# ══════════════════════════════════════════════════════════════════════════
# The stale-clipboard trap, found live
# ══════════════════════════════════════════════════════════════════════════

LONG_CLIPBOARD = "cos dlugiego, co operator mial w schowku " * 3


def test_13_a_long_clipboard_does_not_make_an_empty_field_look_like_a_page():
    """Observed live: the probe refused a field the caret was genuinely in.

    ``Ctrl+C`` over an empty selection copies nothing, so the clipboard keeps
    whatever was there — and if the operator happened to be carrying a long
    piece of text, the probe read *that* and called it a page selection.  The
    fix is to empty the clipboard before asking.
    """
    inputs = FakeInput(caret_in_field=True)
    inputs.clipboard = LONG_CLIPBOARD

    result, events = run_with(inputs)

    assert result.status is AutofillStatus.DONE, result.blocked_at
    assert result.login_entered and result.password_entered


def test_14_a_stale_clipboard_cannot_fake_a_successful_paste():
    """The same trap from the other side, and the more dangerous one.

    If the paste silently fails, the value just copied is still on the
    clipboard — so a verify that reads without clearing first compares the
    secret against itself and reports success.  Clearing first turns that into
    the refusal it should be.
    """
    result, events = run_with(SwallowingField())

    assert result.status is AutofillStatus.BLOCKED
    assert result.blocked_at == fa.PHASE_LOGIN_VERIFY
    assert PASSWORD not in [e[1] for e in events if e[0] == "clip_set"]


def test_15_the_read_back_empties_the_clipboard_before_asking():
    """Structural: the clear has to come first, or both traps come back."""
    source = open(fa.__file__, encoding="utf-8").read()
    body = source[source.index("def _read_selection"):
                  source.index("def _caret_is_in_a_text_box")]
    clear_at = body.index('copy_to_clipboard("")')
    select_at = body.index('ord("A")')
    assert clear_at < select_at, "czyszczenie schowka przed Ctrl+A"
