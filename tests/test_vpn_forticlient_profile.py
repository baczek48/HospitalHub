"""Stage 45: choosing the VPN profile is production behaviour, and it is timed.

Two things arrive together here because they were learned together on the live
client.

**The route.**  Stage 41 shipped a profile step that opened with a blind Tab,
pressed Space to drop the combo open, typed, and pressed Enter.  That assumed
the caret starts one stop before the combo, which is true when the window has
just been shown from the tray and false once the user has clicked it to satisfy
the activation gate.  Live, those keystrokes landed on the hamburger beside the
profile list, Enter opened its menu, and the run still reported ``done``.  The
replacement walks *backwards* from the username field the search already found,
types into a closed combo — type-ahead selects without opening anything — and
walks forward again, checking where it ended up.

**The clock.**  The sequence reads the selection ten times over, and every read
used to sleep a fixed 0.2 s after Ctrl+C whether the answer had arrived or not.
The operator noticed.  The budget below is asserted, not hoped for, because
these constants have a way of creeping back up one safety margin at a time.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from vpn import AutofillStatus  # noqa: E402
from vpn.providers import forticlient_autofill as fa  # noqa: E402
from vpn.providers.input_system import (  # noqa: E402
    VK_RETURN, VK_SHIFT, VK_SPACE, VK_TAB,
)
from tests.test_vpn_forticlient_autofill import (  # noqa: E402
    LOGIN, FakeInput, clipboard_secrets, profile_commit_enters, run,
    secret_ops, submit_enters,
)
from tests.test_vpn_secure_target import FakeDesktop, focus_lost_after  # noqa: E402

PROFILE = "SZPITAL-A"
SHIFT_TAB = ("combo", VK_SHIFT, VK_TAB)


def sleep_budget(events):
    return sum(e[1] for e in events if e[0] == "sleep")


# ══════════════════════════════════════════════════════════════════════════
# The route
# ══════════════════════════════════════════════════════════════════════════

def test_1_the_profile_is_reached_backwards_from_the_username_field():
    """Two Shift+Tabs reach the combo; the list is opened only after that.
    Combo, hamburger, username — reversed."""
    _result, events, _tr = run(profile=PROFILE)

    space = events.index(("key", VK_SPACE))
    before = events[:space]
    assert before.count(SHIFT_TAB) == 2, before.count(SHIFT_TAB)
    # The last two keystrokes before opening are those Shift+Tabs, so nothing
    # else moved the caret in between.
    steps = [e for e in before if e[0] in ("key", "combo")]
    assert steps[-1] == SHIFT_TAB and steps[-2] == SHIFT_TAB


def test_2_open_type_commit_and_only_one_enter_besides_submit():
    """Stage 60: the closed-combo type-ahead of Stage 44 does nothing on
    FortiClient 7.4.3, so the list is opened (Space), the name picks the item
    and Enter commits it — the legacy sequence.  That Enter is the only one
    before the credentials; the submit is the only one after."""
    _result, events, _tr = run(profile=PROFILE)

    space = events.index(("key", VK_SPACE))
    typed = events.index(("type", PROFILE))
    commits = profile_commit_enters(events)
    assert space < typed < commits[0], (space, typed, commits)
    assert len(commits) == 1 and len(submit_enters(events)) == 1
    first_secret = next(i for i, e in enumerate(events)
                        if e[0] == "clip_set" and e[1] == LOGIN)
    assert commits[0] < first_secret < submit_enters(events)[0]


def test_3_the_caret_comes_back_to_a_text_field_afterwards():
    """Two Tabs forward, and then it is checked rather than assumed."""
    _result, events, _tr = run(profile=PROFILE)

    typed = events.index(("type", PROFILE))
    after = events[typed:]
    assert len([e for e in after if e == ("key", VK_TAB)]) >= 2
    first_secret = next(i for i, e in enumerate(after)
                        if e[0] == "clip_set" and e[1] == LOGIN)
    reads = [i for i, e in enumerate(after[:first_secret])
             if e[0] == "combo" and e[2] == ord("C")]
    assert reads, "po powrocie sprawdzamy, gdzie jestesmy"


def test_4_the_profile_is_set_before_any_secret_leaves_the_process():
    """Changing the profile does not clear the credential fields, so it goes
    first — and if it fails, nothing has been exposed yet."""
    _result, events, _tr = run(profile=PROFILE)

    typed = events.index(("type", PROFILE))
    first_secret = next(i for i, e in enumerate(events)
                        if e[0] == "clip_set" and e[1] in clipboard_secrets(events))
    assert typed < first_secret


def test_5_no_profile_name_means_no_profile_keystrokes():
    _result, events, _tr = run(profile="")

    assert SHIFT_TAB not in events, "bez nazwy profilu combo nie jest ruszane"
    assert not [e for e in events if e[0] == "type"]


# ══════════════════════════════════════════════════════════════════════════
# When it goes wrong
# ══════════════════════════════════════════════════════════════════════════

def test_6_a_guard_refusing_mid_profile_stops_the_whole_run():
    """Guards 4-9 are the profile step; the window changing owner there has to
    end the attempt before the credentials, not after."""
    result, events, _tr = run(desktop=FakeDesktop(foreground=focus_lost_after(6)),
                              profile=PROFILE)

    assert result.status is AutofillStatus.BLOCKED
    assert result.blocked_at == fa.PHASE_PROFILE
    assert secret_ops(events) == [] and clipboard_secrets(events) == []


def test_7_a_refusal_there_still_gives_the_operator_their_clipboard_back():
    from vpn import VpnRequest
    from vpn.providers import FortiClientProvider
    from tests.test_vpn_forticlient_detect import FakeEnvironment
    from tests.test_vpn_secure_target import FORTI_DIR, FORTI_GUI, HWND, ListFinder
    from tests.test_vpn_forticlient_autofill import PASSWORD

    theirs = "cos, co operator mial w schowku"
    inp = FakeInput()
    inp.clipboard = theirs
    from tests.test_vpn_forticlient_autofill import forti_environment
    provider = FortiClientProvider(forti_environment())
    provider.autofill_login_password(
        VpnRequest(provider_id="forticlient", profile_name=PROFILE,
                   login=LOGIN, password=PASSWORD),
        target=provider.secure_window_target(
            api=FakeDesktop(foreground=focus_lost_after(6)),
            finder=ListFinder((HWND,))),
        input_system=inp, msaa=inp.msaa)

    assert inp.clipboard == theirs


class WrongLanding(FakeInput):
    """The two Tabs back do not land where the measurement said they would.

    Models a client whose tab order differs by one — the case the fallback
    exists for.  The stop after the walk back is not a field; the one after
    that is.
    """

    def __init__(self):
        super().__init__()
        self._typed = False
        self._tabs_after = 0

    def type_text(self, text):
        super().type_text(text)
        self._typed = True
        self.caret_in_field = False          # the walk back misses the field

    def press_key(self, vk):
        super().press_key(vk)
        if self._typed and vk == VK_TAB:
            self._tabs_after += 1
            if self._tabs_after > 2:         # one stop further along
                self.caret_in_field = True


def test_8_a_wrong_landing_falls_back_to_searching_instead_of_insisting():
    """The measurement is a shortcut, not a contract.  When it does not hold,
    the sequence looks for the field the slow way and still fills it."""
    from vpn import VpnRequest
    from vpn.providers import FortiClientProvider
    from tests.test_vpn_forticlient_detect import FakeEnvironment
    from tests.test_vpn_secure_target import FORTI_DIR, FORTI_GUI, HWND, ListFinder
    from tests.test_vpn_forticlient_autofill import PASSWORD

    inp = WrongLanding()
    from tests.test_vpn_forticlient_autofill import forti_environment
    provider = FortiClientProvider(forti_environment())
    result = provider.autofill_login_password(
        VpnRequest(provider_id="forticlient", profile_name=PROFILE,
                   login=LOGIN, password=PASSWORD),
        target=provider.secure_window_target(api=FakeDesktop(),
                                             finder=ListFinder((HWND,))),
        input_system=inp, msaa=inp.msaa)

    assert result.status is AutofillStatus.DONE, result.blocked_at
    assert result.login_entered and result.password_entered


def test_8b_the_fallback_is_the_ordinary_field_search():
    """Structural: the routine ends by delegating, and a refusal still stops."""
    source = open(fa.__file__, encoding="utf-8").read()
    body = source[source.index("def _select_profile"):
                  source.index("def _caret_is_in_a_text_box")]
    assert "_locate_text_field(win, inp, guard, state)" in body
    assert "return False, reason" in body


# ══════════════════════════════════════════════════════════════════════════
# The clock
# ══════════════════════════════════════════════════════════════════════════

def test_9_the_sequence_stays_within_its_time_budget():
    """Before Stage 45 the same modelled run slept 9.4 s and the live one took
    roughly seventeen.  A ceiling, not a target: raising it needs a reason in
    the diff.
    """
    _result, events, _tr = run(profile="")
    assert sleep_budget(events) < 5.5, sleep_budget(events)

    # Stage 63: +0.1 s — the change is confirmed by two MSAA readings in a
    # row, one poll apart, instead of one (a single reading could catch a
    # value shown before the choice was committed).
    _result, events, _tr = run(profile=PROFILE)
    assert sleep_budget(events) < 7.6, sleep_budget(events)


def test_10_no_single_pause_is_longer_than_half_a_second():
    """The 1.5 s render wait was for a window the V2 path never restores, and
    the 1.5 s after submit was for a clipboard nobody was reading."""
    _result, events, _tr = run(profile=PROFILE)
    assert max(e[1] for e in events if e[0] == "sleep") <= 0.5


def test_11_the_copy_wait_ends_when_the_answer_arrives():
    """A field with content answers at once; only an empty one costs the whole
    deadline, and an empty one has no signal to give."""
    quick = FakeInput()
    quick.field = "cokolwiek"
    fa._read_selection(quick)

    empty = FakeInput()
    empty.field = ""
    fa._read_selection(empty)

    assert sleep_budget(quick.events) < sleep_budget(empty.events)
    assert sleep_budget(quick.events) <= 0.2, sleep_budget(quick.events)


def test_12_the_copy_wait_cannot_spin_for_ever():
    """A clipboard that never answers still has to end the read."""
    class Mute(FakeInput):
        def read_clipboard(self):
            self.events.append(("clip_get",))
            return ""

    inp = Mute()
    assert fa._read_selection(inp) == ""
    assert sleep_budget(inp.events) <= fa._COPY_DEADLINE_S + 0.2


def test_13_the_phase_is_published_and_ordered_before_the_credentials():
    assert fa.PHASE_PROFILE in fa.PHASES
    assert fa.PHASES.index(fa.PHASE_PROFILE) < fa.PHASES.index(fa.PHASE_LOGIN_CLEAR)
    assert fa.PHASES.index(fa.PHASE_LOCATE) < fa.PHASES.index(fa.PHASE_PROFILE)


def test_14_the_trace_records_the_step_and_not_the_site():
    """A profile name is not a credential, so it may be typed — but it names a
    hospital, so it does not go into a diagnostics file."""
    _result, _events, tr = run(profile=PROFILE)

    assert [s for s in tr.steps if s.get("event") == "profile-step"]
    assert PROFILE not in repr(tr.steps)


# ══════════════════════════════════════════════════════════════════════════
# Stage 60: the choice is proven, and an unproven choice sends nothing
# ══════════════════════════════════════════════════════════════════════════

from types import SimpleNamespace  # noqa: E402

import pytest  # noqa: E402

from vpn.providers.input_system import (  # noqa: E402
    UIA_COMBOBOX_CONTROL_TYPE, VK_CONTROL, VK_DELETE, FocusedControl,
    InputSystem,
)
from tests.test_vpn_forticlient_autofill import (  # noqa: E402
    CTRL_V, ENTER, PASSWORD, PREV_CLIP, LinkedMsaa, RecTrace, forti_environment,
)
from tests.test_vpn_secure_target import FORTI_PID, HWND, OTHER  # noqa: E402
from vpn.providers import forticlient_profile as fp  # noqa: E402
from vpn.providers.msaa_system import MsaaNode, MsaaScan, MsaaSystem  # noqa: E402

UIA_BUTTON = 50000
UIA_EDIT = 50004


def drive(inp, *, profile=PROFILE, login=LOGIN, password=PASSWORD,
          desktop=None, cancellation=None, trace=None, registry=None,
          environment=None, finder_hwnds=None):
    from vpn import VpnRequest
    from vpn.providers import FortiClientProvider
    from tests.test_vpn_secure_target import ListFinder

    from tests.test_vpn_forticlient_autofill import sole_environment

    if environment is None and registry is None and not profile:
        environment = sole_environment()      # no name: one-tunnel machine (L1)
    provider = FortiClientProvider(environment if environment is not None
                                   else forti_environment(registry))
    return provider.autofill_login_password(
        VpnRequest(provider_id="forticlient", profile_name=profile,
                   login=login, password=password),
        target=provider.secure_window_target(
            api=desktop if desktop is not None else FakeDesktop(),
            finder=ListFinder(finder_hwnds or (HWND,))),
        input_system=inp, trace=trace, cancellation=cancellation,
        msaa=inp.msaa)


def nothing_secret_left(inp, result):
    """The fail-closed contract: no credential, no paste, no Enter after the
    profile step, and the operator's clipboard back."""
    assert clipboard_secrets(inp.events) == [], "sekret nie trafil do schowka"
    assert CTRL_V not in inp.events, "zadne wklejanie"
    assert submit_enters(inp.events) == [], "zaden Enter laczacy"
    assert not result.login_entered and not result.password_entered
    assert inp.clipboard == PREV_CLIP, "schowek operatora przywrocony"


class ForeignWindowMsaa(LinkedMsaa):
    """The accessible object answers for a window other than the one asked."""

    def __init__(self, inp, window):
        super().__init__(inp)
        self._foreign = window

    def node(self, hwnd):
        n = super().node(hwnd)
        return MsaaNode(role=n.role, name=n.name, state=n.state, value=n.value,
                        window=self._foreign)


class ScriptedMsaa(LinkedMsaa):
    """Scans answered from a script first — a scan, or an exception to raise —
    then from the linked combo."""

    def __init__(self, inp, script):
        super().__init__(inp)
        self.script = list(script)

    def combo_boxes(self, hwnd):
        if self.script:
            self.asked.append(hwnd)
            self.inp.events.append(("msaa_read",))
            item = self.script.pop(0)
            if isinstance(item, Exception):
                raise item
            return item
        return super().combo_boxes(hwnd)


def tunnels(*ssl, ipsec=()):
    """Registry entries for extra tunnels, beside the combo's own."""
    reg = {fp.SSL_TUNNELS_KEY + "\\" + n: {"Server": "x"} for n in ssl}
    reg.update({fp.IPSEC_TUNNELS_KEY + "\\" + n: {"Server": "x"} for n in ipsec})
    return reg


class IgnoresSelection(FakeInput):
    """FortiClient 7.4.3 as Stage 59 met it: the keys go in, the profile does
    not change.  Space lands and the list never opens."""

    def press_key(self, vk):
        if self.combo_focused and vk == VK_SPACE:
            self.events.append(("key", vk))
            return                                   # the list never opens
        super().press_key(vk)


class IgnoresCommit(FakeInput):
    """The list opens, takes the name and closes on Enter — without applying
    the choice.  Every key landed; only the read-back can tell."""

    def press_key(self, vk):
        if self.combo_focused and self.combo_open and vk == VK_RETURN:
            self.events.append(("key", vk))
            self.combo_open, self.combo_pending = False, None
            return
        super().press_key(vk)


class MissesTheCombo(FakeInput):
    """The two Shift+Tabs land on the hamburger: the combo never has focus."""

    def press_combo(self, modifier_vk, key):
        super().press_combo(modifier_vk, key)
        if modifier_vk == VK_SHIFT:
            self.combo_focused = False


class FocusEscapesBeforeCommit(FakeInput):
    """The list opened and took the name, then focus went to a text field —
    exactly where an Enter would submit the form."""

    def type_text(self, text):
        super().type_text(text)
        if text == PROFILE:
            self.combo_focused = self.combo_open = False


class StaysOpen(FakeInput):
    """Enter applies the choice but the list never closes."""

    def press_key(self, vk):
        was_open = self.combo_focused and self.combo_open
        super().press_key(vk)
        if was_open and vk == VK_RETURN:
            self.combo_open = True


def msaa_reads_before(events, marker):
    """Was the event just before `marker` (pauses aside) an MSAA reading?"""
    ev = [e for e in events if e[0] != "sleep"]
    i = ev.index(marker)
    return ev[i - 1] == ("msaa_read",)


def test_60_1_every_profile_key_is_decided_by_a_reading_in_the_same_step():
    """Stage 63: Space, the name and the committing Enter each follow an MSAA
    reading directly — nothing in between that could move the focus."""
    inp = FakeInput()
    result = drive(inp)

    assert result.status is AutofillStatus.DONE, result.metadata
    assert inp.combo_value == PROFILE
    assert msaa_reads_before(inp.events, ("key", VK_SPACE)), "odczyt PRZED Space"
    assert msaa_reads_before(inp.events, ("type", PROFILE)), "odczyt PRZED nazwą"
    commit = profile_commit_enters(inp.events)
    assert len(commit) == 1
    ev = inp.events
    assert [e for e in ev[commit[0] - 2:commit[0]] if e[0] != "sleep"] == [("msaa_read",)]
    after = [e for e in ev[commit[0] + 1:] if e[0] != "sleep"]
    assert after[:2] == [("msaa_read",), ("msaa_read",)], "dwa odczyty PO Enterze"
    assert inp.msaa.asked and set(inp.msaa.asked) == {HWND}, "tylko zweryfikowane okno"


def test_60_2_a_profile_already_showing_needs_no_key_at_all():
    """Read before anything moves: not even the two Shift+Tabs are sent."""
    inp = FakeInput()
    inp.combo_value = PROFILE
    tr = RecTrace()
    result = drive(inp, trace=tr)

    assert result.status is AutofillStatus.DONE
    assert SHIFT_TAB not in inp.events
    assert ("key", VK_SPACE) not in inp.events
    assert ("type", PROFILE) not in inp.events
    assert profile_commit_enters(inp.events) == []
    step = [s for s in tr.steps if s.get("event") == "profile-step"][0]
    assert step["already_selected"] is True and step["verified"] is True


def test_60_3_a_list_that_never_opens_gets_no_name_and_no_enter():
    inp = IgnoresSelection()
    result = drive(inp)

    assert result.status is AutofillStatus.BLOCKED
    assert result.blocked_at == fa.PHASE_PROFILE
    assert result.metadata["reason_code"] == fa.REASON_PROFILE_LIST_CLOSED
    assert ("type", PROFILE) not in inp.events and ENTER not in inp.events
    nothing_secret_left(inp, result)


def test_60_3b_keys_sent_but_profile_unchanged_blocks_everything():
    """The Stage-59 failure, fail-closed: sending the keys is not proof."""
    inp = IgnoresCommit()
    result = drive(inp)

    assert result.status is AutofillStatus.BLOCKED
    assert result.metadata["reason_code"] == fa.REASON_PROFILE_NOT_CONFIRMED
    assert inp.combo_value != PROFILE
    nothing_secret_left(inp, result)


def test_60_4_a_profile_the_client_does_not_have_is_refused_before_any_key():
    """Stage 63: not a tunnel in the registry — refused before the first key,
    so type-ahead never gets to pick something merely similar."""
    inp = FakeInput()
    result = drive(inp, profile="NIE-MA-TAKIEGO")

    assert result.status is AutofillStatus.BLOCKED
    assert result.metadata["reason_code"] == fp.REASON_REQUEST_NOT_CONFIGURED
    assert inp.msaa.asked == []
    assert [e for e in inp.events if e[0] in ("key", "combo", "type")] == []
    nothing_secret_left(inp, result)


def test_60_5_a_prefix_match_is_not_the_requested_profile():
    """"1S" is configured, the list has no "1S" item: typing it picks "1SZP".
    The combo shows a profile — the wrong one."""
    inp = FakeInput()
    result = drive(inp, profile="1S", registry=tunnels("1S"))

    assert inp.combo_value == "1SZP"
    assert result.status is AutofillStatus.BLOCKED
    assert result.metadata["reason_code"] == fa.REASON_PROFILE_NOT_CONFIRMED
    nothing_secret_left(inp, result)


def test_60_6_focus_on_the_hamburger_sends_no_space_and_no_enter():
    """The caret probe cannot tell the combo from the hamburger, whose menu
    offers to delete the connection.  MSAA's FOCUSED bit can."""
    inp = MissesTheCombo()
    result = drive(inp)

    assert result.metadata["reason_code"] == fa.REASON_PROFILE_NOT_FOCUSED
    assert ("key", VK_SPACE) not in inp.events
    assert ENTER not in inp.events
    assert not [e for e in inp.events if e[0] == "type"]
    nothing_secret_left(inp, result)


@pytest.mark.parametrize("window", [OTHER, None, HWND + 1])
def test_60_7_a_combo_of_another_window_is_refused(window):
    inp = FakeInput()
    inp.msaa = ForeignWindowMsaa(inp, window)
    result = drive(inp)

    assert result.metadata["reason_code"] == fp.REASON_FOREIGN_WINDOW
    assert ENTER not in inp.events and ("key", VK_SPACE) not in inp.events
    assert SHIFT_TAB not in inp.events, "odmowa przed pierwszym klawiszem"
    nothing_secret_left(inp, result)


@pytest.mark.parametrize("broken", ["raises", "not-ok", "base-seam"])
def test_60_8_an_unreadable_tree_is_a_refusal_not_a_guess(broken):
    inp = FakeInput()
    if broken == "raises":
        inp.msaa = ScriptedMsaa(inp, [OSError("COM went away")])
    elif broken == "not-ok":
        inp.msaa = ScriptedMsaa(inp, [MsaaScan(ok=False, reason="msaa-no-root")])
    else:
        inp.msaa = MsaaSystem()                 # NotImplementedError
    result = drive(inp)

    assert result.status is AutofillStatus.BLOCKED
    assert result.metadata["reason_code"] == fp.REASON_MSAA_UNAVAILABLE
    assert SHIFT_TAB not in inp.events and ENTER not in inp.events
    nothing_secret_left(inp, result)


@pytest.mark.real_system_guard
def test_60_9_without_an_injected_reader_the_real_one_is_asked_and_refuses():
    """No `msaa=`: the real reader is created — and under the test guard it
    cannot reach the machine, so it answers "unavailable", never "yes"."""
    from vpn import VpnRequest
    from vpn.providers import FortiClientProvider
    from tests.test_vpn_secure_target import ListFinder

    inp = FakeInput()
    provider = FortiClientProvider(forti_environment())
    result = provider.autofill_login_password(
        VpnRequest(provider_id="forticlient", profile_name=PROFILE,
                   login=LOGIN, password=PASSWORD),
        target=provider.secure_window_target(api=FakeDesktop(),
                                             finder=ListFinder((HWND,))),
        input_system=inp)
    assert result.status is AutofillStatus.BLOCKED
    assert result.metadata["reason_code"] == fp.REASON_MSAA_UNAVAILABLE
    nothing_secret_left(inp, result)


def test_60_10_enter_is_withheld_when_focus_left_the_list():
    inp = FocusEscapesBeforeCommit()
    result = drive(inp)

    assert result.metadata["reason_code"] == fa.REASON_PROFILE_LIST_CLOSED
    assert ENTER not in inp.events, "Enter nie idzie do pola tekstowego"
    nothing_secret_left(inp, result)


def test_60_10b_a_list_that_does_not_close_is_not_a_confirmation():
    inp = StaysOpen()
    result = drive(inp)

    assert result.status is AutofillStatus.BLOCKED
    assert result.metadata["reason_code"] == fa.REASON_PROFILE_STATE
    nothing_secret_left(inp, result)


def test_60_11_a_guard_refusal_anywhere_in_the_profile_step_stops_it():
    """Every guard of the profile step, one at a time: the window leaves the
    foreground there.  Counted, not assumed, so a new guard is covered too."""
    stopped_in_profile = []
    for n in range(1, 80):
        inp = FakeInput()
        result = drive(inp, desktop=FakeDesktop(foreground=focus_lost_after(n)))
        if result.status is AutofillStatus.NO_FOCUS:
            continue                          # lost before the window was acquired
        if result.status is AutofillStatus.DONE:
            break                             # past the last guard
        assert result.status is AutofillStatus.BLOCKED, n
        assert submit_enters(inp.events) == [], n
        assert inp.clipboard == PREV_CLIP, n
        if result.blocked_at == fa.PHASE_PROFILE:
            stopped_in_profile.append(n)
            nothing_secret_left(inp, result)
    else:
        raise AssertionError("przebieg nigdy nie doszedł do końca")
    assert len(stopped_in_profile) >= 10, stopped_in_profile
    assert stopped_in_profile == list(range(stopped_in_profile[0],
                                            stopped_in_profile[-1] + 1))


def test_60_12_cancel_during_the_profile_step_is_cancelled_and_sends_nothing():
    token = SimpleNamespace(cancelled=False)

    class CancelOnScan(LinkedMsaa):
        def combo_boxes(self, hwnd):
            token.cancelled = True              # the next guard refuses
            return super().combo_boxes(hwnd)

    inp = FakeInput()
    inp.msaa = CancelOnScan(inp)
    result = drive(inp, cancellation=token)

    assert result.status is AutofillStatus.CANCELLED
    assert result.blocked_at == fa.PHASE_PROFILE
    assert ("key", VK_SPACE) not in inp.events and ENTER not in inp.events
    nothing_secret_left(inp, result)


def test_60_13_the_focus_read_never_returns_a_text_fields_value():
    """Only a combo's value is read.  Pinned on the real implementation's
    source: the value patterns are reached only after the combo check."""
    from vpn.providers import input_system as isys
    src = open(isys.__file__, encoding="utf-8").read()
    body = src[src.index("class Win32InputSystem"):]
    body = body[body.index("def focused_control"):]
    gate = body.index("if ctrl != UIA_COMBOBOX_CONTROL_TYPE:")
    assert gate < body.index("_UIA_VALUE_PATTERN_ID")
    assert gate < body.index("_UIA_SELECTION_PATTERN_ID")
    assert FocusedControl(found=True, control_type=UIA_EDIT).value is None


def test_60_14_refusals_carry_codes_not_the_profile_name():
    inp = IgnoresSelection()
    tr = RecTrace()
    result = drive(inp, trace=tr)

    assert PROFILE not in repr(result)
    assert PROFILE not in repr(tr.steps)


# ══════════════════════════════════════════════════════════════════════════
# Stage 60: empty credentials are skipped, not cleared (legacy parity)
# ══════════════════════════════════════════════════════════════════════════

CTRL_A = ("combo", VK_CONTROL, ord("A"))
DELETE = ("key", VK_DELETE)


def clears(events):
    """Ctrl+A followed by Delete — the only way the fill empties a field."""
    keys = [e for e in events if e[0] != "sleep"]
    return [i for i in range(len(keys) - 1)
            if keys[i] == CTRL_A and keys[i + 1] == DELETE]


def test_60_15_empty_login_leaves_the_username_field_alone():
    inp = FakeInput()
    inp.field = "zapisany"
    result = drive(inp, profile="", login="")

    assert result.status is AutofillStatus.DONE
    assert not result.login_entered and result.password_entered
    tab_to_password = inp.events.index(("key", VK_TAB))
    assert clears(inp.events[:tab_to_password]) == [], "pole loginu nietkniete"
    assert clipboard_secrets(inp.events) == [PASSWORD]
    assert len(submit_enters(inp.events)) == 1


def test_60_16_empty_password_leaves_the_password_field_alone():
    inp = FakeInput()
    result = drive(inp, profile="", password="")

    assert result.status is AutofillStatus.DONE
    assert result.login_entered and not result.password_entered
    last_tab = len(inp.events) - 1 - inp.events[::-1].index(("key", VK_TAB))
    assert clears(inp.events[last_tab:]) == [], "pole hasla nietkniete"
    assert clipboard_secrets(inp.events) == [LOGIN]
    assert inp.events.count(CTRL_V) == 1


def test_60_17_both_empty_types_nothing_and_still_submits_like_the_legacy():
    """Legacy `_autofill_forticlient`: `if login:` / `if password:` skip, then
    Enter regardless — FortiClient submits what it has saved."""
    inp = FakeInput()
    result = drive(inp, profile="", login="", password="")

    assert result.status is AutofillStatus.DONE
    assert clears(inp.events) == []
    assert CTRL_V not in inp.events and clipboard_secrets(inp.events) == []
    assert len(submit_enters(inp.events)) == 1


def test_60_18_the_fill_helper_itself_never_clears_for_an_empty_secret():
    calls = []
    blocked, _reason = fa._fill_field(
        None, FakeInput(), lambda *a: calls.append(a) or (True, ""), "",
        fa.PHASE_LOGIN_CLEAR, fa.PHASE_LOGIN_PROBE, fa.PHASE_LOGIN_CLIPBOARD,
        fa.PHASE_LOGIN_PASTE, 0.0, {"clip_dirty": False})
    assert blocked is None and calls == [], "zadnej operacji dla pustej wartosci"


def test_60_19_parity_records_both_stage_60_fixes():
    from vpn.providers import forticlient_connect as fcc
    parity = {e[0]: e for e in fcc.CONNECT_PARITY}
    assert parity["gui-autofill-empty-field"][5] == "same"
    assert parity["gui-profile-select"][5] == "security"
