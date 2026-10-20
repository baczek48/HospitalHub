"""2026-10-19: Stormshield and Barracuda fill field by field — focus by
AutomationId, confirm the focus, then type (``vpn.providers.field_fill``).

Replaces the Stage-40/41 Shift+Tab sequence (on the owner's client the cursor
started in Firewall address and the password was typed there, in plain text)
and the Stage-50C ``SetValue`` fill (Qt kept "Log in" disabled).  Both were
measured live before this rewrite; the replacement was measured live on both
clients with dummy credentials.

Fakes only: no window, no keystroke, no secret printed.  A typed value is
recorded with the field that had the focus when it was typed, which is the
property that matters — the password goes into the password field and nowhere
else.
"""

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from vpn import AutofillStatus, ErrorCode, VpnRequest  # noqa: E402
from vpn.providers import barracuda_autofill as ba  # noqa: E402
from vpn.providers import stormshield_autofill as sa  # noqa: E402
from vpn.providers.activation_gate import CancellationToken  # noqa: E402
from vpn.providers.input_system import InputSystem, VK_CONTROL, VK_RETURN  # noqa: E402
from vpn.providers.uia_value_system import UiaSetOutcome, UiaValueSystem  # noqa: E402
from vpn.providers.stormshield import StormshieldProvider  # noqa: E402
from tests.test_vpn_forticlient_detect import FakeEnvironment  # noqa: E402
from tests.test_vpn_secure_target import ListFinder  # noqa: E402
from tests import test_vpn_barracuda as tb  # noqa: E402
from tests import test_vpn_stormshield as ts  # noqa: E402

LOGIN, PASSWORD, SERVER = "jkowalski", "SuperSecret123", "vpn.szpital.pl"


class FakeUia(UiaValueSystem):
    """Focus by AutomationId on a described form; records only ids."""

    def __init__(self, *, owner_pid, missing=(), refuse_focus=(), on_focus=None,
                 drop_first=False, unreadable=(), never_takes=()):
        self.focused = None
        self.calls: list[str] = []
        self.cleared: list[str] = []
        self._drop_first = drop_first
        self._dropped: set = set()
        self._unreadable = set(unreadable)
        self._never = set(never_takes)
        self._owner = owner_pid
        self._missing = set(missing)
        self._refuse = set(refuse_focus)
        self._on_focus = on_focus

    def find(self, hwnd, automation_id):
        raise AssertionError("fill uses focus(), not find()")

    def set_value(self, hwnd, automation_id, value, *, expected_pid):
        # Only ever to clear: SetValue with text does not wake Qt's Log in.
        assert value == "", "SetValue tylko do czyszczenia pola"
        self.calls.append("clear:" + automation_id)
        self.cleared.append(automation_id)
        return UiaSetOutcome(True, performed=True, reason="set",
                             process_id=self._owner)

    def value_matches(self, hwnd, automation_id, expected, *, expected_pid):
        if automation_id in self._unreadable or "Password" in automation_id \
                or "password" in automation_id:
            return None
        if self._drop_first and automation_id not in self._dropped:
            self._dropped.add(automation_id)
            return False
        return True

    def focus(self, hwnd, automation_id, *, expected_pid):
        self.calls.append(automation_id)
        if automation_id in self._missing:
            return UiaSetOutcome(False, reason="not-found")
        if self._owner != expected_pid:
            return UiaSetOutcome(True, reason="pid-mismatch", process_id=self._owner)
        if automation_id in self._refuse:
            return UiaSetOutcome(True, reason="focus-not-taken", process_id=self._owner)
        self.focused = automation_id
        if automation_id in self._never:
            self._dropped.discard(automation_id)
            self._drop_first = True
        if self._on_focus is not None:
            self._on_focus(automation_id)
        return UiaSetOutcome(True, performed=True, reason="focused",
                             process_id=self._owner)


class FakeKeys(InputSystem):
    """Keystrokes, attributed to the field that had the focus."""

    def __init__(self, uia):
        self.uia = uia
        self.events: list[tuple] = []

    def press_key(self, vk):
        self.events.append(("key", self.uia.focused, vk))

    def press_combo(self, modifier_vk, key):
        self.events.append(("combo", self.uia.focused, modifier_vk, key))

    def type_text(self, text):
        self.events.append(("type", self.uia.focused, text))

    def sleep(self, seconds):
        pass

    def typed(self):
        return [(field, text) for kind, field, *rest in self.events
                if kind == "type" for text in rest]


def storm(*, desktop=None, uia_kwargs=None, cancellation=None, hwnds=(ts.HWND,),
          **req):
    provider = StormshieldProvider(environment=FakeEnvironment(
        files=[ts.GUI], dirs=[ts.INSTALL_DIR]))
    desktop = desktop if desktop is not None else ts.Desktop()
    target = provider.secure_window_target(api=desktop, finder=ListFinder(hwnds))
    uia = FakeUia(owner_pid=ts.PID, **(uia_kwargs or {}))
    keys = FakeKeys(uia)
    fields = dict(login=LOGIN, password=PASSWORD, server=SERVER, port="443")
    fields.update(req)
    request = VpnRequest(provider_id="stormshield", **fields)
    result = provider.autofill_login_password(request, target=target,
                                              input_system=keys, uia=uia,
                                              cancellation=cancellation)
    return result, uia, keys


def barra(*, desktop=None, uia_kwargs=None, cancellation=None, hwnds=(tb.HWND,),
          **req):
    provider = tb.provider()
    desktop = desktop if desktop is not None else tb.Desktop()
    target = provider.secure_window_target(api=desktop, finder=ListFinder(hwnds))
    uia = FakeUia(owner_pid=tb.PID, **(uia_kwargs or {}))
    keys = FakeKeys(uia)
    fields = dict(login=LOGIN, password=PASSWORD)
    fields.update(req)
    request = VpnRequest(provider_id="barracuda", **fields)
    result = provider.autofill_login_password(request, target=target, uia=uia,
                                              input_system=keys,
                                              cancellation=cancellation)
    return result, uia, keys


# ══════════════════════════════════════════════════════════════════════════
# Stormshield
# ══════════════════════════════════════════════════════════════════════════

def test_storm_every_value_goes_into_its_own_field():
    result, uia, keys = storm()
    assert result.status is AutofillStatus.DONE
    assert keys.typed() == [(sa.AID_ADDRESS, SERVER + ":443"),
                            (sa.AID_LOGIN, LOGIN),
                            (sa.AID_PASSWORD, PASSWORD)]


def test_storm_the_password_is_never_typed_outside_the_password_field():
    _r, _uia, keys = storm()
    assert [f for f, text in keys.typed() if text == PASSWORD] == [sa.AID_PASSWORD]


def test_storm_each_field_is_cleared_before_typing():
    """Ctrl+A does not select in Stormshield's password box (measured: the new
    password was appended) — every field is emptied through UIA first."""
    _r, uia, keys = storm()
    assert uia.cleared == [sa.AID_ADDRESS, sa.AID_LOGIN, sa.AID_PASSWORD]
    assert not [e for e in keys.events if e[0] == "combo"]
    order = [c for c in uia.calls]
    for aid in (sa.AID_ADDRESS, sa.AID_LOGIN, sa.AID_PASSWORD):
        assert order.index(aid) < order.index("clear:" + aid)


def test_a_lost_first_keystrokes_are_typed_again():
    """A just-activated window dropped the login typed first (measured)."""
    result, _uia, keys = barra(uia_kwargs=dict(drop_first=True))
    assert result.status is AutofillStatus.DONE
    assert keys.typed().count((ba.AID_USER, LOGIN)) == 2
    assert keys.typed().count((ba.AID_PASSWORD, PASSWORD)) == 1


def test_a_field_that_never_takes_the_text_stops_before_the_password():
    result, _uia, keys = storm(uia_kwargs=dict(never_takes=(sa.AID_LOGIN,)))
    assert result.status is AutofillStatus.BLOCKED
    assert result.metadata["reason_code"] == "value-not-taken"
    assert PASSWORD not in [text for _f, text in keys.typed()]


def test_storm_is_not_submitted():
    result, _uia, keys = storm()
    assert not [e for e in keys.events if e[0] == "key" and e[2] == VK_RETURN]
    assert result.metadata["submitted"] is False
    assert result.metadata["filled_only"] is True


def test_storm_empty_server_or_login_is_skipped():
    _r, _uia, keys = storm(server="", login="")
    assert keys.typed() == [(sa.AID_PASSWORD, PASSWORD)]


def test_storm_a_field_that_will_not_take_the_focus_stops_before_any_key():
    result, uia, keys = storm(uia_kwargs=dict(refuse_focus=(sa.AID_ADDRESS,)))
    assert result.status is AutofillStatus.BLOCKED
    assert result.error_code == ErrorCode.SECRET_INPUT_BLOCKED.value
    assert keys.events == []


def test_storm_a_missing_password_field_keeps_the_password_home():
    result, _uia, keys = storm(uia_kwargs=dict(missing=(sa.AID_PASSWORD,)))
    assert result.status is AutofillStatus.BLOCKED
    assert PASSWORD not in [text for _f, text in keys.typed()]


def test_storm_an_element_of_another_process_is_refused():
    provider = StormshieldProvider(environment=FakeEnvironment(
        files=[ts.GUI], dirs=[ts.INSTALL_DIR]))
    target = provider.secure_window_target(api=ts.Desktop(),
                                           finder=ListFinder((ts.HWND,)))
    uia = FakeUia(owner_pid=ts.PID + 1)
    keys = FakeKeys(uia)
    result = provider.autofill_login_password(
        VpnRequest(provider_id="stormshield", login=LOGIN, password=PASSWORD),
        target=target, input_system=keys, uia=uia)
    assert result.status is AutofillStatus.BLOCKED and keys.events == []


def test_storm_foreground_lost_after_login_sends_no_password():
    desktop = ts.Desktop()

    def lose(aid):
        if aid == sa.AID_PASSWORD:
            desktop._foreground = lambda n: ts.OTHER_HWND

    result, _uia, keys = storm(desktop=desktop, uia_kwargs=dict(on_focus=lose))
    assert result.status is AutofillStatus.BLOCKED
    assert PASSWORD not in [text for _f, text in keys.typed()]


def test_storm_cancel_between_fields():
    token = CancellationToken()

    def cancel_on_login(aid):
        if aid == sa.AID_LOGIN:
            token.cancel()

    result, _uia, keys = storm(cancellation=token,
                               uia_kwargs=dict(on_focus=cancel_on_login))
    assert result.status is AutofillStatus.CANCELLED
    assert result.error_code == ErrorCode.CANCELLED.value
    assert PASSWORD not in [text for _f, text in keys.typed()]


def test_storm_no_verified_window_touches_nothing():
    result, uia, keys = storm(hwnds=())
    assert result.status is AutofillStatus.NO_TARGET
    assert uia.calls == [] and keys.events == []


def test_storm_the_result_carries_no_secret():
    result, _uia, _keys = storm()
    blob = repr(result) + repr(result.metadata)
    assert LOGIN not in blob and PASSWORD not in blob


# ══════════════════════════════════════════════════════════════════════════
# Barracuda
# ══════════════════════════════════════════════════════════════════════════

def test_barra_login_and_password_then_enter_in_the_password():
    result, _uia, keys = barra()
    assert result.status is AutofillStatus.DONE
    assert keys.typed() == [(ba.AID_USER, LOGIN), (ba.AID_PASSWORD, PASSWORD)]
    enters = [e for e in keys.events if e[0] == "key" and e[2] == VK_RETURN]
    assert enters == [("key", ba.AID_PASSWORD, VK_RETURN)]
    assert keys.events[-1] == enters[0], "Enter po wpisaniu, nie wcześniej"
    assert result.metadata["submitted"] is True


@pytest.mark.parametrize("second_factor", [dict(requires_2fa=True),
                                           dict(token="123456")])
def test_barra_a_second_factor_is_left_for_the_person(second_factor):
    result, _uia, keys = barra(**second_factor)
    assert result.status is AutofillStatus.DONE
    assert not [e for e in keys.events if e[0] == "key" and e[2] == VK_RETURN]
    assert result.metadata["filled_only"] is True


def test_barra_otp_and_certificate_fields_are_never_touched():
    _r, uia, _keys = barra()
    touched = {c.split(":", 1)[-1] for c in uia.calls}
    assert touched <= {ba.AID_USER, ba.AID_PASSWORD}


def test_barra_no_password_means_no_enter():
    result, _uia, keys = barra(password="")
    assert keys.typed() == [(ba.AID_USER, LOGIN)]
    assert not [e for e in keys.events if e[0] == "key" and e[2] == VK_RETURN]


def test_barra_foreground_lost_before_enter_submits_nothing():
    desktop = tb.Desktop()
    focus_count = {"n": 0}

    def lose(aid):
        focus_count["n"] += 1
        if focus_count["n"] == 3:          # the submit's focus
            desktop._foreground = lambda n: tb.OTHER_HWND

    result, _uia, keys = barra(desktop=desktop, uia_kwargs=dict(on_focus=lose))
    assert result.status is AutofillStatus.BLOCKED
    assert not [e for e in keys.events if e[0] == "key" and e[2] == VK_RETURN]


def test_barra_the_result_carries_no_secret():
    result, _uia, _keys = barra()
    blob = repr(result) + repr(result.metadata)
    assert LOGIN not in blob and PASSWORD not in blob


def test_every_typed_field_ends_with_one_real_key_that_edits_nothing():
    """WPF re-evaluates "Connect" only on a real key (measured on Barracuda)."""
    from vpn.providers.field_fill import VK_END
    for run in (storm, barra):
        _r, _uia, keys = run()
        for i, event in enumerate(keys.events):
            if event[0] == "type":
                assert keys.events[i + 1] == ("key", event[1], VK_END)


# ══════════════════════════════════════════════════════════════════════════
# 2026-10-20 (owner's laptop): Barracuda showed "Default", the card was MCX
# ══════════════════════════════════════════════════════════════════════════

class ProfileUia(FakeUia):
    """A combo whose items are `profiles`; selecting changes the layout."""

    def __init__(self, *, owner_pid, profiles=("Default", "MCX"), shown="Default",
                 confirm=True, **kw):
        super().__init__(owner_pid=owner_pid, **kw)
        self.profiles, self.shown, self.confirm = profiles, shown, confirm

    def select_list_item(self, hwnd, text, *, expected_pid):
        self.calls.append("select:" + text)
        if self._owner != expected_pid:
            return UiaSetOutcome(True, reason="pid-mismatch")
        hits = [p for p in self.profiles if p == text]
        if len(hits) != 1:
            return UiaSetOutcome(True, reason="profile-not-in-client" if not hits
                                 else "profile-ambiguous")
        if not self.confirm:
            return UiaSetOutcome(True, reason="profile-not-confirmed")
        self.shown = text
        return UiaSetOutcome(True, performed=True, reason="selected")

    def focus(self, hwnd, automation_id, *, expected_pid):
        if automation_id == ba.AID_USER and self.shown == "Default":
            self.calls.append(automation_id)
            return UiaSetOutcome(True, reason="field-not-shown")
        return super().focus(hwnd, automation_id, expected_pid=expected_pid)


def barra_profile(profile_name="MCX", **uia_kwargs):
    provider = tb.provider()
    target = provider.secure_window_target(api=tb.Desktop(),
                                           finder=ListFinder((tb.HWND,)))
    uia = ProfileUia(owner_pid=tb.PID, **uia_kwargs)
    keys = FakeKeys(uia)
    request = VpnRequest(provider_id="barracuda", login=LOGIN, password=PASSWORD,
                         profile_name=profile_name)
    result = provider.autofill_login_password(request, target=target, uia=uia,
                                              input_system=keys)
    return result, uia, keys


def test_barra_the_cards_profile_is_chosen_before_anything_is_typed():
    result, uia, keys = barra_profile()
    assert result.status is AutofillStatus.DONE, result.metadata
    assert uia.calls[0] == "select:MCX"
    assert uia.shown == "MCX"
    assert keys.typed() == [(ba.AID_USER, LOGIN), (ba.AID_PASSWORD, PASSWORD)]


@pytest.mark.parametrize("kwargs,reason", [
    (dict(profiles=("Default",)), "profile-not-in-client"),
    (dict(profiles=("MCX", "MCX")), "profile-ambiguous"),
    (dict(confirm=False), "profile-not-confirmed"),
])
def test_barra_a_profile_that_cannot_be_chosen_types_nothing(kwargs, reason):
    result, _uia, keys = barra_profile(**kwargs)
    assert result.status is AutofillStatus.BLOCKED
    assert result.metadata["reason_code"] == reason
    assert keys.events == []


def test_barra_without_a_profile_name_the_form_shown_is_used():
    result, uia, keys = barra_profile(profile_name="", shown="MCX")
    assert result.status is AutofillStatus.DONE
    assert not [c for c in uia.calls if c.startswith("select:")]


def test_barra_a_form_without_user_name_stops_with_a_clear_reason():
    """The laptop's case without a profile name: "Default", certificate form."""
    result, _uia, keys = barra_profile(profile_name="")
    assert result.status is AutofillStatus.BLOCKED
    assert result.metadata["reason_code"] == "field-not-shown"
    assert keys.events == []


def test_the_card_says_what_happened_for_the_new_reasons():
    from ui.vpn_v2_connect import present_outcome
    for reason in ("profile-not-in-client", "profile-ambiguous", "field-not-shown",
                   "profile-not-confirmed"):
        text = present_outcome("autofill-blocked", reason, client="Barracuda").text
        assert "FortiClient" not in text and "{" not in text, (reason, text)
        assert "Logowanie nie zostało wysłane" in text


def test_barra_a_client_without_a_profile_list_goes_on_to_the_fields():
    """2026-10-20: one profile, no list — nothing to choose, the fields decide."""
    class NoList(ProfileUia):
        def select_list_item(self, hwnd, text, *, expected_pid):
            self.calls.append("select:" + text)
            return UiaSetOutcome(True, performed=True, reason="no-list")

    provider = tb.provider()
    target = provider.secure_window_target(api=tb.Desktop(),
                                           finder=ListFinder((tb.HWND,)))
    uia = NoList(owner_pid=tb.PID, shown="MCX")
    keys = FakeKeys(uia)
    result = provider.autofill_login_password(
        VpnRequest(provider_id="barracuda", login=LOGIN, password=PASSWORD,
                   profile_name="MCX"), target=target, uia=uia, input_system=keys)
    assert result.status is AutofillStatus.DONE
    assert keys.typed() == [(ba.AID_USER, LOGIN), (ba.AID_PASSWORD, PASSWORD)]


# ══════════════════════════════════════════════════════════════════════════
# 2026-10-20: a "Barracuda License" profile (owner's laptop)
# ══════════════════════════════════════════════════════════════════════════

class LicenseUia(ProfileUia):
    """After MCX is chosen the form shows User Password + Certificate/License
    Password, no User Name."""

    def __init__(self, *, owner_pid, **kw):
        super().__init__(owner_pid=owner_pid, **kw)

    def is_shown(self, hwnd, automation_id, *, expected_pid):
        if self.shown != "MCX":
            return automation_id == ba.AID_PASSWORD
        return automation_id in (ba.AID_PASSWORD, ba.AID_CERT)

    def focus(self, hwnd, automation_id, *, expected_pid):
        if automation_id == ba.AID_USER:
            self.calls.append(automation_id)
            return UiaSetOutcome(True, reason="field-not-shown")
        return FakeUia.focus(self, hwnd, automation_id, expected_pid=expected_pid)


def barra_license(**req):
    provider = tb.provider()
    target = provider.secure_window_target(api=tb.Desktop(),
                                           finder=ListFinder((tb.HWND,)))
    uia = LicenseUia(owner_pid=tb.PID)
    keys = FakeKeys(uia)
    fields = dict(login=LOGIN, password=PASSWORD, profile_name="MCX")
    fields.update(req)
    result = provider.autofill_login_password(
        VpnRequest(provider_id="barracuda", **fields), target=target, uia=uia,
        input_system=keys)
    return result, uia, keys


def test_barra_license_profile_fills_the_two_fields_under_the_list():
    """As the legacy did and the owner confirmed: the card's login into User
    Password, its password into Certificate/License Password, Enter there."""
    result, uia, keys = barra_license()
    assert result.status is AutofillStatus.DONE, result.metadata
    assert keys.typed() == [(ba.AID_PASSWORD, LOGIN), (ba.AID_CERT, PASSWORD)]
    enters = [e for e in keys.events if e[0] == "key" and e[2] == VK_RETURN]
    assert enters == [("key", ba.AID_CERT, VK_RETURN)]
    assert ba.AID_USER not in uia.calls, "User Name nie istnieje w tym układzie"


def test_barra_license_profile_with_a_second_factor_is_not_submitted():
    result, _uia, keys = barra_license(requires_2fa=True)
    assert result.status is AutofillStatus.DONE
    assert not [e for e in keys.events if e[0] == "key" and e[2] == VK_RETURN]


def test_barra_user_name_layout_is_unchanged_when_is_shown_is_known():
    class UserNameUia(ProfileUia):
        def is_shown(self, hwnd, automation_id, *, expected_pid):
            return automation_id in (ba.AID_USER, ba.AID_PASSWORD)

    provider = tb.provider()
    target = provider.secure_window_target(api=tb.Desktop(),
                                           finder=ListFinder((tb.HWND,)))
    uia = UserNameUia(owner_pid=tb.PID)
    keys = FakeKeys(uia)
    result = provider.autofill_login_password(
        VpnRequest(provider_id="barracuda", login=LOGIN, password=PASSWORD,
                   profile_name="MCX"), target=target, uia=uia, input_system=keys)
    assert result.status is AutofillStatus.DONE
    assert keys.typed() == [(ba.AID_USER, LOGIN), (ba.AID_PASSWORD, PASSWORD)]
