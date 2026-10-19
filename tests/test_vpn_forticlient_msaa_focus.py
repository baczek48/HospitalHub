"""2026-10-19 (owner's question): FortiClient's fields reached by name.

"Why does it Tab around — from the tray one Tab lands on the list."  One Tab
is right only for one way of opening the window; a Tab too few lands on the
hamburger, whose menu can delete the connection.  FortiClient 7.4.3 exposes
``VPN Name``, ``Username`` and ``Password`` through MSAA and
``accSelect(SELFLAG_TAKEFOCUS)`` moves the focus to each (measured live), so
with an MSAA seam that offers ``focus_element`` the fill sends no Tab and no
Shift+Tab at all: combo, Username, Password, each by name, each confirmed.

Fakes only; the form model is ``FakeInput`` from the autofill tests.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from vpn import AutofillStatus  # noqa: E402
from vpn.providers import forticlient_autofill as fa  # noqa: E402
from vpn.providers.input_system import VK_SHIFT, VK_SPACE, VK_TAB  # noqa: E402
from vpn.providers.msaa_system import (  # noqa: E402
    ROLE_SYSTEM_COMBOBOX, ROLE_SYSTEM_TEXT, MsaaFocus,
)
from tests.test_vpn_forticlient_autofill import (  # noqa: E402
    LOGIN, PASSWORD, FakeInput, LinkedMsaa, clipboard_secrets, submit_enters,
)
from tests.test_vpn_forticlient_profile import PROFILE, drive  # noqa: E402

SHIFT_TAB = ("combo", VK_SHIFT, VK_TAB)
TAB = ("key", VK_TAB)


class FocusingMsaa(LinkedMsaa):
    """The MSAA view, plus ``focus_element`` moving the model's focus."""

    def __init__(self, inp, *, refuse=()):
        super().__init__(inp)
        self.focused: list[str] = []
        self._refuse = set(refuse)

    def focus_element(self, hwnd, role, name):
        self.inp.events.append(("msaa_focus", name))
        if name in self._refuse:
            return MsaaFocus(False, "focus-not-taken")
        expected = {"VPN Name": ROLE_SYSTEM_COMBOBOX, "Username": ROLE_SYSTEM_TEXT,
                    "Password": ROLE_SYSTEM_TEXT}
        assert expected[name] == role, (name, role)
        inp = self.inp
        inp.combo_focused = name == "VPN Name"
        inp.combo_open = False
        if name != "VPN Name":
            inp.field = "" if name == "Password" else inp.field
        self.focused.append(name)
        return MsaaFocus(True, "focused")


def make(**kw):
    inp = FakeInput()
    inp.msaa = FocusingMsaa(inp, **kw)
    return inp


def test_profile_login_password_reached_by_name_without_a_single_tab():
    inp = make()
    result = drive(inp)
    assert result.status is AutofillStatus.DONE, result.metadata
    assert inp.msaa.focused == ["VPN Name", "Username", "Password"]
    assert SHIFT_TAB not in inp.events and TAB not in inp.events
    assert inp.combo_value == PROFILE
    assert clipboard_secrets(inp.events) == [LOGIN, PASSWORD]
    assert len(submit_enters(inp.events)) == 1


def test_the_list_is_opened_only_after_its_focus_was_confirmed():
    inp = make()
    drive(inp)
    order = [e for e in inp.events if e[0] in ("msaa_focus",) or e == ("key", VK_SPACE)]
    assert order.index(("msaa_focus", "VPN Name")) < order.index(("key", VK_SPACE))


def test_a_profile_already_showing_goes_straight_to_username():
    inp = make()
    inp.combo_value = PROFILE
    result = drive(inp)
    assert result.status is AutofillStatus.DONE
    assert inp.msaa.focused == ["Username", "Password"]
    assert ("key", VK_SPACE) not in inp.events


def test_a_field_that_will_not_take_the_focus_stops_before_any_secret():
    for refused in ("VPN Name", "Username", "Password"):
        inp = make(refuse=(refused,))
        result = drive(inp)
        assert result.status is AutofillStatus.BLOCKED, refused
        if refused != "Password":
            assert clipboard_secrets(inp.events) == [], refused
        else:
            assert clipboard_secrets(inp.events) == [LOGIN]
        assert submit_enters(inp.events) == [], refused


def test_without_focus_element_the_tab_navigation_remains():
    inp = FakeInput()                           # LinkedMsaa: no focus_element
    result = drive(inp)
    assert result.status is AutofillStatus.DONE
    assert SHIFT_TAB in inp.events


def test_the_password_goes_where_the_password_focus_was_confirmed():
    inp = make()
    drive(inp)
    events = inp.events
    password_focus = events.index(("msaa_focus", "Password"))
    password_clip = next(i for i, e in enumerate(events)
                         if e == ("clip_set", PASSWORD))
    assert password_focus < password_clip
    assert fa.FIELD_PASSWORD == "Password" and fa.FIELD_USERNAME == "Username"


# ══════════════════════════════════════════════════════════════════════════
# The paste confirmed by MSAA's value, not by fixed waits (2026-10-19)
# ══════════════════════════════════════════════════════════════════════════

class ReadingMsaa(FocusingMsaa):
    """Also answers ``field_value``: the text for Username, the mask for
    Password; ``lag`` reads come back empty first (a paste on its way)."""

    def __init__(self, inp, *, lag=0, never=(), **kw):
        super().__init__(inp, **kw)
        self.lag, self.never, self.reads = lag, set(never), []
        self._current = None

    def focus_element(self, hwnd, role, name):
        result = super().focus_element(hwnd, role, name)
        if result.ok and name != "VPN Name":
            self._current = name
        return result

    def field_value(self, hwnd, role, name):
        self.reads.append(name)
        self.inp.events.append(("msaa_value", name))
        if name in self.never or self.reads.count(name) <= self.lag:
            return ""
        text = self.inp.field
        return "•" * len(text) if name == "Password" else text


def make_reading(**kw):
    inp = FakeInput()
    inp.msaa = ReadingMsaa(inp, **kw)
    return inp


def test_the_password_is_focused_only_after_the_login_shows_in_its_field():
    inp = make_reading(lag=3)
    result = drive(inp)
    assert result.status is AutofillStatus.DONE, result.metadata
    events = inp.events
    last_login_read = max(i for i, e in enumerate(events) if e == ("msaa_value", "Username"))
    assert last_login_read < events.index(("msaa_focus", "Password"))


def test_between_login_and_password_only_what_the_paste_needs():
    inp = make_reading()
    drive(inp)
    ev = inp.events
    start = ev.index(("clip_set", LOGIN))
    end = ev.index(("clip_set", PASSWORD))
    between = ev[start:end]
    waited = sum(e[1] for e in between if e[0] == "sleep")
    assert waited <= 0.1, between            # was ~2 s of fixed waits
    assert ("combo", 0x11, ord("C")) not in between, "zadnego Ctrl+C przez schowek"
    assert ("key", 0x2E) not in between, "Ctrl+A + Ctrl+V zastepuje, bez Delete"


def test_a_login_that_never_shows_stops_before_the_password():
    inp = make_reading(never=("Username",))
    result = drive(inp)
    assert result.status is AutofillStatus.BLOCKED
    assert result.metadata["reason_code"] == "paste-did-not-land"
    assert clipboard_secrets(inp.events) == [LOGIN]
    assert ("msaa_focus", "Password") not in inp.events
    assert submit_enters(inp.events) == []


def test_a_password_of_the_wrong_length_is_not_submitted():
    inp = make_reading(never=("Password",))
    result = drive(inp)
    assert result.status is AutofillStatus.BLOCKED
    assert submit_enters(inp.events) == []
