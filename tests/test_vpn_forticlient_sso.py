"""2026-10-28 (owner): a FortiClient profile without a login form.

"ND" is set up in FortiClient so that, once its profile is chosen, the window
shows only Connect; the gateway's login page and Duo Mobile follow in the
browser.  The fill reached the profile and then stopped: MSAA had no
``Username`` to focus ("element-missing"), and the VPN section showed an
error.  Now a profile whose form stays without Username has its Connect
button focused by name and pressed — under the same guard and the same
last-moment profile check as the Enter of a normal submit, and with nothing
typed and nothing secret on the clipboard.

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
from vpn.providers.input_system import VK_RETURN  # noqa: E402
from vpn.providers.msaa_system import (  # noqa: E402
    ROLE_SYSTEM_PUSHBUTTON, ROLE_SYSTEM_TEXT, MsaaFocus,
)
from tests.test_vpn_forticlient_autofill import (  # noqa: E402
    LOGIN, PASSWORD, FakeInput, clipboard_secrets, submit_enters,
)
from tests.test_vpn_forticlient_msaa_focus import FocusingMsaa  # noqa: E402
from tests.test_vpn_forticlient_profile import PROFILE, drive  # noqa: E402


class SsoMsaa(FocusingMsaa):
    """A form with only a button: no Username, no Password.

    ``buttons`` are the push buttons the window has; ``username_after`` makes
    Username appear after that many misses (a normal form still drawing);
    ``refuse_button`` makes the button refuse the focus.
    """

    def __init__(self, inp, *, buttons=("Connect",), username_after=None,
                 refuse_button=False):
        super().__init__(inp)
        self.buttons = tuple(buttons)
        self.username_after = username_after
        self.refuse_button = refuse_button
        self.username_asks = 0

    def focus_element(self, hwnd, role, name):
        if role == ROLE_SYSTEM_PUSHBUTTON:
            self.inp.events.append(("msaa_focus", name))
            if name not in self.buttons:
                return MsaaFocus(False, "element-missing")
            if self.refuse_button:
                return MsaaFocus(False, "focus-not-taken")
            self.inp.combo_focused = False
            self.focused.append(name)
            return MsaaFocus(True, "focused")
        if role == ROLE_SYSTEM_TEXT and name in ("Username", "Password"):
            self.username_asks += name == "Username"
            if (self.username_after is None
                    or self.username_asks <= self.username_after):
                self.inp.events.append(("msaa_focus", name))
                return MsaaFocus(False, "element-missing")
        return super().focus_element(hwnd, role, name)


def make(**kw):
    inp = FakeInput()
    inp.msaa = SsoMsaa(inp, **kw)
    return inp


def presses_after_button(inp):
    events = inp.events
    at = max(i for i, e in enumerate(events) if e[0] == "msaa_focus")
    return [e for e in events[at:] if e == ("key", VK_RETURN)]


def test_a_profile_with_only_connect_is_selected_and_connected():
    inp = make()
    result = drive(inp)
    assert result.status is AutofillStatus.DONE, result.metadata
    assert result.metadata == {"route": "sso"}
    assert not result.login_entered and not result.password_entered
    assert inp.combo_value == PROFILE
    assert inp.msaa.focused == ["VPN Name", "Connect"]
    assert len(presses_after_button(inp)) == 1
    assert clipboard_secrets(inp.events) == []          # nothing secret, ever


def test_the_vault_login_and_password_are_never_typed_there():
    inp = make()
    drive(inp, login=LOGIN, password=PASSWORD)
    assert clipboard_secrets(inp.events) == []
    typed = [e[1] for e in inp.events if e[0] == "type"]
    assert typed and all(LOGIN not in t and PASSWORD not in t for t in typed)


def test_older_clients_call_the_button_saml_login():
    inp = make(buttons=("SAML Login",))
    result = drive(inp)
    assert result.status is AutofillStatus.DONE
    assert inp.msaa.focused == ["VPN Name", "SAML Login"]


def test_a_normal_form_still_drawing_is_filled_as_before():
    # Username missing on the first look only: not an SSO profile.
    inp = make(username_after=1)
    result = drive(inp)
    assert result.status is AutofillStatus.DONE
    assert result.metadata.get("route") != "sso"
    assert clipboard_secrets(inp.events) == [LOGIN, PASSWORD]
    assert "Connect" not in inp.msaa.focused


def test_no_button_either_stops_without_a_key():
    inp = make(buttons=())
    result = drive(inp)
    assert result.status is AutofillStatus.BLOCKED
    assert result.metadata["reason_code"] == fa.REASON_SSO_BUTTON_MISSING
    assert submit_enters(inp.events) == []


def test_a_button_refusing_the_focus_stops_without_a_key():
    inp = make(refuse_button=True)
    result = drive(inp)
    assert result.status is AutofillStatus.BLOCKED
    assert result.metadata["reason_code"] == "focus-not-taken"
    assert submit_enters(inp.events) == []


def test_a_profile_changed_before_the_press_is_not_connected():
    inp = make()
    original = fa._sso_connect

    def change_then_connect(*args, **kw):
        inp.combo_value = "Inny szpital"        # someone picked another one
        return original(*args, **kw)
    fa._sso_connect, saved = change_then_connect, fa._sso_connect
    try:
        result = drive(inp)
    finally:
        fa._sso_connect = saved
    assert result.status is AutofillStatus.BLOCKED
    assert presses_after_button(inp) == []


def test_the_one_tunnel_machine_connects_its_sso_profile_too():
    # No name given: the only configured tunnel, confirmed on screen (L1) —
    # the same tunnel the button then connects.
    inp = make()
    result = drive(inp, profile="")
    assert result.status is AutofillStatus.DONE, result.metadata
    assert result.metadata == {"route": "sso"}
    assert clipboard_secrets(inp.events) == []
