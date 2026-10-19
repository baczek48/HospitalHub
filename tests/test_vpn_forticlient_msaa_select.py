"""Stage 63: the profile step decided by MSAA — every refusal sends nothing.

Stage 62 built a read-only MSAA reader of the ``VPN Name`` combo; this stage
wires it into ``_select_profile`` in place of the UI Automation focus read that
FortiClient 7.4.3 can never answer.  The cases below came from two independent
read-only audits (security and tests) and pin the invariants they asked for:

* refusals that need no key at all — a request that could never be confirmed,
  a tree that is unreadable, ambiguous or cut short, a display in a format the
  step does not change from;
* each key decided by a reading in the same guarded step, with the window
  confirmed once more between reading and key;
* a confirmation of two readings in a row, closed;
* the profile read again before each credential reaches the clipboard and
  before the final Enter;
* cancellation, empty credentials and the operator's clipboard on every path.

Everything is a fake: :class:`FakeInput` with its :class:`LinkedMsaa`, the
desktop, the registry.  No real window, key, clipboard or FortiClient.
"""

import os
import sys
from types import SimpleNamespace

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from vpn import AutofillStatus  # noqa: E402
from vpn.providers import forticlient_autofill as fa  # noqa: E402
from vpn.providers import forticlient_profile as fp  # noqa: E402
from vpn.providers.input_system import VK_RETURN, VK_SPACE, VK_TAB  # noqa: E402
from vpn.providers.msaa_system import (  # noqa: E402
    STATE_SYSTEM_FOCUSED, MsaaScan,
)
from tests.test_vpn_forticlient_autofill import (  # noqa: E402
    CTRL_V, ENTER, GROUP_PREFIX, LOGIN, PASSWORD, PREV_CLIP, FakeInput,
    LinkedMsaa, RecTrace, clipboard_secrets, forti_environment,
    profile_commit_enters, submit_enters,
)
from tests.test_vpn_forticlient_detect import FakeEnvironment  # noqa: E402
from tests.test_vpn_forticlient_profile import (  # noqa: E402
    PROFILE, SHIFT_TAB, IgnoresCommit, ScriptedMsaa, clears, drive,
    nothing_secret_left, tunnels,
)
from tests.test_vpn_secure_target import (  # noqa: E402
    FORTI_DIR, FORTI_GUI, HWND, OTHER, FakeDesktop,
)


def keys(events):
    return [e for e in events if e[0] in ("key", "combo", "type")]


def node_scan(inp, *nodes):
    return MsaaScan(ok=True, combos=tuple(nodes))


class Drifts(LinkedMsaa):
    """After `after` scans, the combo shows something else: another
    value, or the focus, or an open list — the user touching it after the
    profile was confirmed."""

    def __init__(self, inp, after, *, value=None, focused=False, expanded=False):
        super().__init__(inp)
        self.after, self.drift_value = after, value
        self.drift_focused, self.drift_expanded = focused, expanded
        self.scans = 0

    def node(self, hwnd):
        n = super().node(hwnd)
        if self.scans <= self.after:
            return n
        state = n.state
        if self.drift_focused:
            state |= STATE_SYSTEM_FOCUSED
        if self.drift_expanded:
            state = (state | fp.STATE_SYSTEM_EXPANDED) & ~fp.STATE_SYSTEM_COLLAPSED
        value = self.drift_value if self.drift_value is not None else n.value
        return type(n)(role=n.role, name=n.name, state=state, value=value,
                       window=n.window)

    def combo_boxes(self, hwnd):
        self.scans += 1
        return super().combo_boxes(hwnd)


#: Scans in a clean change of profile: the first look, Space, the name,
#: Enter, and the two confirming readings.
SCANS_IN_PROFILE_STEP = 6


# ══════════════════════════════════════════════════════════════════════════
# A. Refused before the first key
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("profile,registry,environment,reason", [
    (" " + PROFILE, None, None, fp.REASON_REQUEST_UNTRIMMED),
    (PROFILE + " ", None, None, fp.REASON_REQUEST_UNTRIMMED),
    (PROFILE, None, FakeEnvironment(files=[FORTI_GUI], dirs=[FORTI_DIR]),
     fp.REASON_CATALOG_UNAVAILABLE),
    (PROFILE, tunnels(ipsec=(PROFILE,)), None, fp.REASON_AMBIGUOUS_TUNNEL),
    (PROFILE, tunnels(GROUP_PREFIX + "X"), None, fp.REASON_LABEL_COLLISION),
])
def test_a1_a_request_that_could_never_be_confirmed_sends_nothing(
        profile, registry, environment, reason):
    inp = FakeInput()
    result = drive(inp, profile=profile, registry=registry, environment=environment)

    assert result.status is AutofillStatus.BLOCKED
    assert result.blocked_at == fa.PHASE_PROFILE
    assert result.metadata["reason_code"] == reason
    assert inp.msaa.asked == [], "MSAA nie pytane"
    assert keys(inp.events) == [], "zaden klawisz"
    nothing_secret_left(inp, result)


def test_a2_a_registry_that_cannot_be_read_is_an_empty_catalog():
    class Broken(FakeEnvironment):
        def registry_subkeys(self, subkey):
            raise OSError("access denied")

    inp = FakeInput()
    result = drive(inp, environment=Broken(files=[FORTI_GUI], dirs=[FORTI_DIR]))
    assert result.metadata["reason_code"] == fp.REASON_CATALOG_UNAVAILABLE
    assert keys(inp.events) == []


@pytest.mark.parametrize("scan,reason", [
    ("two", fp.REASON_CONTROL_AMBIGUOUS),
    ("none", fp.REASON_CONTROL_MISSING),
    ("truncated", fp.REASON_SCAN_TRUNCATED),
])
def test_a3_an_ambiguous_missing_or_partial_tree_sends_no_key(scan, reason):
    inp = FakeInput()
    one = inp.msaa.node(HWND)
    scans = {"two": node_scan(inp, one, one),
             "none": node_scan(inp),
             "truncated": MsaaScan(ok=True, combos=(one,), truncated=True)}
    inp.msaa = ScriptedMsaa(inp, [scans[scan]])
    result = drive(inp)

    assert result.metadata["reason_code"] == reason
    assert keys(inp.events)[-1:] != [SHIFT_TAB] and SHIFT_TAB not in inp.events
    nothing_secret_left(inp, result)


@pytest.mark.parametrize("shown", [
    "Corporate VPNs " + PROFILE,          # a label that was never measured
    GROUP_PREFIX + "DUCH",                # a tunnel the registry does not have
    GROUP_PREFIX.rstrip(),                # the label alone
    GROUP_PREFIX + " ",                   # the label and an empty name
    PROFILE,                              # no label at all
])
def test_a4_a_display_in_an_unknown_form_is_not_changed(shown):
    inp = FakeInput()
    inp.msaa.value = shown
    result = drive(inp)

    assert result.metadata["reason_code"] == fa.REASON_PROFILE_UNCHANGEABLE
    assert keys(inp.events) == [] or SHIFT_TAB not in inp.events
    assert ("key", VK_SPACE) not in inp.events and ENTER not in inp.events
    nothing_secret_left(inp, result)


def test_a5_the_right_profile_with_its_list_open_is_not_taken_as_chosen():
    inp = FakeInput()
    inp.combo_value, inp.combo_open = PROFILE, True
    result = drive(inp)

    assert result.metadata["reason_code"] == fa.REASON_PROFILE_STATE
    assert SHIFT_TAB not in inp.events and ENTER not in inp.events
    nothing_secret_left(inp, result)


def test_a5b_another_profile_with_its_list_open_gets_no_shift_tab():
    """Security review, N1: a Shift+Tab leaving an open list could commit its
    highlighted item, so an open list is refused before the walk back."""
    inp = FakeInput()
    inp.combo_open = True
    result = drive(inp)

    assert result.metadata["reason_code"] == fa.REASON_PROFILE_STATE
    assert SHIFT_TAB not in inp.events and ENTER not in inp.events
    nothing_secret_left(inp, result)


def test_a6_only_the_acquired_window_is_read():
    """The finder offers a foreign window first; the fill acquires the
    FortiClient one, and MSAA is asked about that window and no other."""
    inp = FakeInput()
    result = drive(inp, finder_hwnds=(OTHER, HWND))

    assert result.status is AutofillStatus.DONE, result.metadata
    assert inp.msaa.asked and set(inp.msaa.asked) == {HWND}


# ══════════════════════════════════════════════════════════════════════════
# B. The reading must be of this window and this process
# ══════════════════════════════════════════════════════════════════════════

class _Win:
    def __init__(self, hwnd=HWND, pid=1234, ok=True):
        self.hwnd, self.pid, self._ok = hwnd, pid, ok

    def confirm(self):
        return SimpleNamespace(ok=self._ok, reason="" if self._ok else "foreground-changed")


def reader_reading(**kw):
    defaults = dict(ok=True, reason="read", hwnd=HWND, pid=1234,
                    state=fp.STATE_SYSTEM_COLLAPSED, value=GROUP_PREFIX + PROFILE)
    defaults.update(kw)
    return fp.ProfileControlReading(**defaults)


@pytest.mark.parametrize("reading", [
    dict(pid=4321),            # same window, another (trusted) process
    dict(pid=None),
    dict(hwnd=HWND + 1),
])
def test_b1_a_reading_for_another_process_or_window_is_refused(monkeypatch, reading):
    monkeypatch.setattr(fp, "read_profile_control",
                        lambda target, msaa, hwnd=None: reader_reading(**reading))
    r = fa._ProfileReader(None, None, _Win(), PROFILE,
                          fp.TunnelCatalog(ssl=(PROFILE,)))
    _reading, match, refusal = r.read()
    assert refusal == fa.REASON_PROFILE_WINDOW_CHANGED and match is None
    assert r.initial() == (fa.REASON_PROFILE_WINDOW_CHANGED, False)
    assert r.still_selected() == fa.REASON_PROFILE_WINDOW_CHANGED


def test_b2_a_window_without_a_pid_is_never_a_match(monkeypatch):
    monkeypatch.setattr(fp, "read_profile_control",
                        lambda target, msaa, hwnd=None: reader_reading(pid=None))
    r = fa._ProfileReader(None, None, _Win(pid=None), PROFILE,
                          fp.TunnelCatalog(ssl=(PROFILE,)))
    assert r.read()[2] == fa.REASON_PROFILE_WINDOW_CHANGED


def test_b3_the_window_is_confirmed_again_between_reading_and_key(monkeypatch):
    """A guard checks before its operation; the tree walk inside takes time.
    The key goes only if the window still confirms *after* the reading."""
    monkeypatch.setattr(fp, "read_profile_control",
                        lambda target, msaa, hwnd=None: reader_reading(
                            state=fp.STATE_SYSTEM_COLLAPSED | STATE_SYSTEM_FOCUSED,
                            value=GROUP_PREFIX + "INNY"))
    pressed = []
    r = fa._ProfileReader(None, None, _Win(ok=False), PROFILE,
                          fp.TunnelCatalog(ssl=(PROFILE, "INNY")))
    r.act(r.ready_to_open, lambda: pressed.append("space"))()
    assert pressed == [] and r.refusal == "foreground-changed"


def test_b4_the_foreground_moving_during_the_scan_withholds_space():
    """End to end: the desktop changes while MSAA walks the tree before Space."""
    fg = {"hwnd": HWND}
    desktop = FakeDesktop(foreground=lambda n: fg["hwnd"])

    class LosesFocusOnScan(Drifts):
        def combo_boxes(self, hwnd):
            scan = super().combo_boxes(hwnd)
            if self.scans == 2:                 # the reading that decides Space
                fg["hwnd"] = OTHER
            return scan

    inp = FakeInput()
    inp.msaa = LosesFocusOnScan(inp, after=99)
    result = drive(inp, desktop=desktop)

    assert result.status is AutofillStatus.BLOCKED
    assert result.blocked_at == fa.PHASE_PROFILE
    assert ("key", VK_SPACE) not in inp.events
    nothing_secret_left(inp, result)


# ══════════════════════════════════════════════════════════════════════════
# C. The confirmation
# ══════════════════════════════════════════════════════════════════════════

def test_c1_one_good_reading_between_bad_ones_is_not_a_confirmation():
    """Two readings in a row, closed and right — a value that flickers past
    the requested profile does not count."""
    class Flickers(LinkedMsaa):
        def __init__(self, inp):
            super().__init__(inp)
            self.n = 0

        def combo_boxes(self, hwnd):
            self.n += 1
            # scans 5.. are the confirmation: right, wrong, right, wrong
            self.value = (None if self.n < 5 or self.n % 2
                          else GROUP_PREFIX + "INNY-PROFIL")
            return super().combo_boxes(hwnd)

    inp = FakeInput()
    inp.msaa = Flickers(inp)
    result = drive(inp)

    assert result.metadata["reason_code"] == fa.REASON_PROFILE_NOT_CONFIRMED
    nothing_secret_left(inp, result)


def test_c2_a_reading_that_settles_late_still_confirms():
    class Settles(LinkedMsaa):
        def __init__(self, inp):
            super().__init__(inp)
            self.n = 0

        def combo_boxes(self, hwnd):
            self.n += 1
            self.value = GROUP_PREFIX + "INNY-PROFIL" if self.n == 5 else None
            return super().combo_boxes(hwnd)

    inp = FakeInput()
    inp.msaa = Settles(inp)
    result = drive(inp)
    assert result.status is AutofillStatus.DONE, result.metadata


def test_c3_an_exception_from_the_reader_fails_closed():
    """Not caught as a "yes": the fill ends FAILED, nothing typed, clipboard
    back."""
    class Explodes(LinkedMsaa):
        def combo_boxes(self, hwnd):
            raise RuntimeError("boom")

    inp = FakeInput()
    inp.msaa = Explodes(inp)
    result = drive(inp)
    # The reader turns a raising seam into "unavailable"; a refusal, not a pass.
    assert result.metadata["reason_code"] == fp.REASON_MSAA_UNAVAILABLE
    nothing_secret_left(inp, result)


def test_c4_an_owner_check_that_raises_mid_step_fails_the_fill_closed():
    """An exception outside the reader's own handling (here: re-verifying the
    window owner) reaches the fill's catch-all: FAILED, nothing typed."""
    class Desk(FakeDesktop):
        calls = 0

        def window_pid(self, hwnd):
            Desk.calls += 1
            if Desk.calls > 6:
                raise OSError("desktop went away")
            return super().window_pid(hwnd)

    inp = FakeInput()
    result = drive(inp, desktop=Desk())
    assert result.status in (AutofillStatus.FAILED, AutofillStatus.BLOCKED)
    nothing_secret_left(inp, result)


# ══════════════════════════════════════════════════════════════════════════
# D. The profile changed after it was confirmed
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("drift", [
    dict(value=GROUP_PREFIX + "INNY-PROFIL"),
    dict(focused=True),
    dict(expanded=True),
])
def test_d1_before_the_login_reaches_the_clipboard(drift):
    inp = FakeInput()
    inp.msaa = Drifts(inp, after=SCANS_IN_PROFILE_STEP, **drift)
    result = drive(inp)

    assert result.status is AutofillStatus.BLOCKED
    assert result.blocked_at == fa.PHASE_LOGIN_CLIPBOARD
    nothing_secret_left(inp, result)


def test_d1b_between_the_clipboard_and_the_paste():
    """The clipboard write and Ctrl+V are separate guarded steps; a change in
    between stops the paste (security review, N2)."""
    inp = FakeInput()
    inp.msaa = Drifts(inp, after=SCANS_IN_PROFILE_STEP + 1,
                      value=GROUP_PREFIX + "INNY-PROFIL")
    result = drive(inp)

    assert result.status is AutofillStatus.BLOCKED
    assert result.blocked_at == fa.PHASE_LOGIN_PASTE
    assert CTRL_V not in inp.events, "nic nie wklejone"
    assert submit_enters(inp.events) == []
    assert not result.login_entered
    assert inp.clipboard == PREV_CLIP, "login zdjety ze schowka"


def test_d2_before_the_password_reaches_the_clipboard():
    inp = FakeInput()
    inp.msaa = Drifts(inp, after=SCANS_IN_PROFILE_STEP + 2,
                      value=GROUP_PREFIX + "INNY-PROFIL")
    result = drive(inp)

    assert result.status is AutofillStatus.BLOCKED
    assert result.blocked_at == fa.PHASE_PASSWORD_CLIPBOARD
    assert clipboard_secrets(inp.events) == [LOGIN], "haslo nie trafilo do schowka"
    assert submit_enters(inp.events) == []
    assert result.login_entered and not result.password_entered
    assert inp.clipboard == PREV_CLIP


@pytest.mark.parametrize("drift", [
    dict(value=GROUP_PREFIX + "INNY-PROFIL"),
    dict(focused=True),
])
def test_d3_before_the_final_enter(drift):
    inp = FakeInput()
    # Login: clipboard + paste; password: clipboard + paste; then the submit.
    inp.msaa = Drifts(inp, after=SCANS_IN_PROFILE_STEP + 4, **drift)
    result = drive(inp)

    assert result.status is AutofillStatus.BLOCKED
    assert result.blocked_at == fa.PHASE_SUBMIT
    assert submit_enters(inp.events) == [], "brak Entera laczacego"
    assert inp.clipboard == PREV_CLIP


def test_d4_without_drift_each_secret_and_the_enter_follow_a_reading():
    inp = FakeInput()
    result = drive(inp)
    assert result.status is AutofillStatus.DONE
    ev = [e for e in inp.events if e[0] != "sleep"]
    for marker in (("clip_set", LOGIN), ("clip_set", PASSWORD)):
        assert ev[ev.index(marker) - 1] == ("msaa_read",), marker
    pastes = [i for i, e in enumerate(ev) if e == CTRL_V]
    assert len(pastes) == 2 and all(ev[i - 1] == ("msaa_read",) for i in pastes)
    submit = submit_enters(ev)
    assert len(submit) == 1 and ev[submit[0] - 1] == ("msaa_read",)


# ── 2026-10-14 (L1): no profile name ──────────────────────────────────────
# The legacy typed the credentials into whatever profile was showing — one
# hospital's login at another's gateway, then Enter.  Until the user decides
# (G5), V2 accepts a nameless request only where the target is unambiguous:
# exactly one tunnel configured, of a measured kind, and that one showing.

def one_tunnel(name, kind="ssl"):
    key = fp.SSL_TUNNELS_KEY if kind == "ssl" else fp.IPSEC_TUNNELS_KEY
    return FakeEnvironment(registry={key + "\\" + name: {"Server": "x"}},
                           files=[FORTI_GUI], dirs=[FORTI_DIR])


@pytest.mark.parametrize("environment", [
    lambda: drive_environment_with_all_tunnels(),
    lambda: FakeEnvironment(files=[FORTI_GUI], dirs=[FORTI_DIR]),   # none
])
def test_d5_no_profile_and_no_unambiguous_target_sends_nothing(environment):
    inp = FakeInput()
    result = drive(inp, profile="", environment=environment())

    assert result.status is AutofillStatus.BLOCKED
    assert result.blocked_at == fa.PHASE_PROFILE
    assert result.metadata["reason_code"] == fa.REASON_PROFILE_UNSPECIFIED
    assert inp.msaa.asked == [], "MSAA nie pytane"
    assert keys(inp.events) == []
    nothing_secret_left(inp, result)


def drive_environment_with_all_tunnels():
    return forti_environment()


def test_d5b_no_profile_with_the_one_tunnel_showing_fills_without_profile_keys():
    inp = FakeInput()                         # the combo shows INNY-PROFIL
    result = drive(inp, profile="", environment=one_tunnel("INNY-PROFIL"))

    assert result.status is AutofillStatus.DONE, result.metadata
    assert SHIFT_TAB not in inp.events and ("key", VK_SPACE) not in inp.events
    assert inp.msaa.asked, "profil potwierdzony odczytem"
    assert clipboard_secrets(inp.events) == [LOGIN, PASSWORD]


def test_d5c_no_profile_with_another_tunnel_showing_is_refused():
    """One tunnel configured, but the combo shows something else (here a
    name the registry does not have): nothing is chosen on the user's behalf."""
    inp = FakeInput()
    result = drive(inp, profile="", environment=one_tunnel("SZPITAL-A"))

    assert result.status is AutofillStatus.BLOCKED
    assert ("key", VK_SPACE) not in inp.events and SHIFT_TAB not in inp.events
    nothing_secret_left(inp, result)


def test_d5d_the_step_never_changes_the_profile_when_none_was_named():
    """Defence in depth: even a reading that would allow a change is refused
    without a name."""
    reader = SimpleNamespace(initial=lambda: ("", False))
    calls = []
    ok, reason = fa._select_profile(
        _Win(), FakeInput(), lambda win, phase, op: (calls.append(op), op(),
                                                      (True, "verified"))[2],
        "INNY-PROFIL", {"profile_already_selected": False}, reader,
        may_change=False)
    assert (ok, reason) == (False, fa.REASON_PROFILE_UNSPECIFIED)
    assert len(calls) == 1, "tylko odczyt, zadnego klawisza"


@pytest.mark.parametrize("ssl,ipsec,expected", [
    (("A",), (), "A"),
    (("A", "B"), (), None),
    (("A",), ("B",), None),
    ((), ("B",), "B"),          # IPsec: same label, measured 2026-10-19
    ((), (), None),
])
def test_d5e_sole_tunnel(ssl, ipsec, expected):
    assert fp.sole_tunnel(fp.TunnelCatalog(ssl=ssl, ipsec=ipsec)) == expected


# ══════════════════════════════════════════════════════════════════════════
# E. Cancellation
# ══════════════════════════════════════════════════════════════════════════

def cancel_on(event):
    token = SimpleNamespace(cancelled=False)

    class Cancels(FakeInput):
        def _hit(self, e):
            if e == event:
                token.cancelled = True

        def press_key(self, vk):
            super().press_key(vk)
            self._hit(("key", vk))

        def type_text(self, text):
            super().type_text(text)
            self._hit(("type", text))

    return token, Cancels()


@pytest.mark.parametrize("event", [("key", VK_SPACE), ("type", PROFILE)])
def test_e1_cancel_between_opening_and_committing_sends_no_enter(event):
    token, inp = cancel_on(event)
    result = drive(inp, cancellation=token)

    assert result.status is AutofillStatus.CANCELLED
    assert result.blocked_at == fa.PHASE_PROFILE
    assert profile_commit_enters(inp.events) == [] and ENTER not in inp.events
    nothing_secret_left(inp, result)


def test_e2_cancel_after_the_commit_leaves_the_credentials_home():
    """The profile has changed; nothing else will.  A visible state, and
    nothing was sent into it."""
    token = SimpleNamespace(cancelled=False)

    class CancelAfterCommit(FakeInput):
        def press_key(self, vk):
            committing = self.combo_focused and self.combo_open and vk == VK_RETURN
            super().press_key(vk)
            if committing:
                token.cancelled = True

    inp = CancelAfterCommit()
    result = drive(inp, cancellation=token)

    assert result.status is AutofillStatus.CANCELLED
    assert inp.combo_value == PROFILE
    assert len(profile_commit_enters(inp.events)) == 1
    nothing_secret_left(inp, result)


def test_e3_cancel_after_the_profile_before_the_login():
    token = SimpleNamespace(cancelled=False)

    class CancelOnLastProfileTab(FakeInput):
        def __init__(self):
            super().__init__()
            self.tabs = 0

        def press_key(self, vk):
            super().press_key(vk)
            if vk == VK_TAB and inp_holder[0].combo_value == PROFILE:
                self.tabs += 1
                if self.tabs == 2:
                    token.cancelled = True

    inp_holder = [None]
    inp = CancelOnLastProfileTab()
    inp_holder[0] = inp
    result = drive(inp, cancellation=token)

    assert result.status is AutofillStatus.CANCELLED
    assert clipboard_secrets(inp.events) == [] and CTRL_V not in inp.events
    nothing_secret_left(inp, result)


# ══════════════════════════════════════════════════════════════════════════
# F. Empty credentials with a profile (legacy parity, Stage 60)
# ══════════════════════════════════════════════════════════════════════════

def test_f1_empty_login_with_a_profile():
    inp = FakeInput()
    inp.field = "zapisany"
    result = drive(inp, login="")

    assert result.status is AutofillStatus.DONE, result.metadata
    assert not result.login_entered and result.password_entered
    assert clipboard_secrets(inp.events) == [PASSWORD]
    assert len(submit_enters(inp.events)) == 1


def test_f2_empty_password_with_a_profile():
    inp = FakeInput()
    result = drive(inp, password="")

    assert result.status is AutofillStatus.DONE, result.metadata
    assert result.login_entered and not result.password_entered
    assert clipboard_secrets(inp.events) == [LOGIN]
    assert len(submit_enters(inp.events)) == 1


def test_f3_both_empty_with_a_profile_still_checks_before_enter():
    inp = FakeInput()
    result = drive(inp, login="", password="")

    assert result.status is AutofillStatus.DONE, result.metadata
    assert clears(inp.events) == [] and CTRL_V not in inp.events
    assert inp.combo_value == PROFILE
    submit = submit_enters(inp.events)
    ev = inp.events
    assert len(submit) == 1
    assert [e for e in ev[:submit[0]] if e[0] != "sleep"][-1] == ("msaa_read",)


@pytest.mark.parametrize("login,password", [("", PASSWORD), (LOGIN, ""), ("", "")])
def test_f4_a_profile_refusal_with_empty_fields_still_submits_nothing(login, password):
    inp = IgnoresCommit()
    result = drive(inp, login=login, password=password)

    assert result.status is AutofillStatus.BLOCKED
    assert result.blocked_at == fa.PHASE_PROFILE
    commit = profile_commit_enters(inp.events)[0]
    assert ("key", VK_TAB) not in inp.events[commit:], "zaden krok do pol"
    nothing_secret_left(inp, result)


# ══════════════════════════════════════════════════════════════════════════
# G. What leaves the process
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("make", [
    lambda: FakeInput(),
    lambda: IgnoresCommit(),
])
def test_g1_results_and_traces_carry_codes_not_the_display(make):
    inp = make()
    tr = RecTrace()
    result = drive(inp, trace=tr)

    for text in (PROFILE, GROUP_PREFIX.strip()):
        assert text not in repr(result)
        assert text not in repr(tr.steps)


def test_g2_the_profile_step_no_longer_asks_ui_automation():
    """Stage 61 measured that UIA cannot answer on 7.4.3; nothing in the fill
    may fall back to it as an alternative "yes"."""
    src = open(fa.__file__, encoding="utf-8").read()
    assert "focused_control" not in src
    assert "read_profile_control" not in src.split("class _ProfileReader")[0] \
        .split("def _select_profile")[1], "kazdy odczyt przez _ProfileReader"


def test_g3_the_profile_reader_keeps_no_value():
    r = fa._ProfileReader(None, None, _Win(), PROFILE, fp.TunnelCatalog())
    assert not any(isinstance(v, str) and GROUP_PREFIX in v for v in vars(r).values())


# ══════════════════════════════════════════════════════════════════════════
# H. COM apartment per worker thread (2026-10-14, L3)
# ══════════════════════════════════════════════════════════════════════════

def test_h1_the_calling_thread_is_put_in_an_apartment():
    from vpn.providers import msaa_system as ms
    calls = []
    fake = SimpleNamespace(COINIT_MULTITHREADED=0,
                           CoInitializeEx=lambda flags: calls.append(flags))
    ms.ensure_com_apartment(fake)
    assert calls == [0], "MTA, jak w pomiarze (review 64/N1)"


def test_h2_a_thread_already_in_another_apartment_is_left_alone():
    from vpn.providers import msaa_system as ms

    def changed_mode(flags):
        raise OSError("RPC_E_CHANGED_MODE")
    ms.ensure_com_apartment(SimpleNamespace(COINIT_MULTITHREADED=0,
                                            CoInitializeEx=changed_mode))


def test_h3_both_readers_initialise_com_before_their_first_call():
    from vpn.providers import msaa_system as ms
    from vpn.providers import uia_value_system as uv
    msaa = open(ms.__file__, encoding="utf-8").read()
    body = msaa[msaa.index("class Win32MsaaSystem"):]
    assert body.index("ensure_com_apartment(comtypes)") < body.index(
        "AccessibleObjectFromWindow")
    uia = open(uv.__file__, encoding="utf-8").read()
    body = uia[uia.index("def _element"):]
    assert body.index("ensure_com_apartment(comtypes)") < body.index("CreateObject")
