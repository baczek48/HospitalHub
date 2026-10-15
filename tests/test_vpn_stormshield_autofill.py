"""Stage 41: the Stormshield autofill — backwards, guarded, and never submitted.

Three things make this different from FortiClient's, and each is measured
rather than assumed (Stage 40, on the real client):

* the cursor starts on **Password**, and the form is filled *backwards* —
  ``Shift+Tab`` to Login, ``Shift+Tab`` to Firewall address;
* the secret is typed **directly**, not pasted through the clipboard;
* nothing is submitted — the user clicks **Log in** themselves, which is a
  successful outcome and not a failure.

Walking backwards is also what makes the sequence survive MFA: the client grows
an **OTP** field *after* Password when multifactor is enabled, so anything
tabbing forward lands one field off.  The legacy sequence has that bug; these
tests pin the behaviour that does not.

The shared layer is not re-tested here.  ``run_guarded`` and its re-validation
of foreground, iconic state, PID and trusted image were proven against
FortiClient and then live; what is tested is that this provider actually routes
every operation through them, in the right order, and stops at the first
refusal.  No real credentials appear anywhere — the values below are obvious
placeholders.
"""

import ast
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from vpn import AutofillStatus, VpnRequest  # noqa: E402
from vpn.providers import stormshield_autofill as sa  # noqa: E402
from vpn.providers.input_system import (  # noqa: E402
    VK_CONTROL, VK_SHIFT, VK_TAB,
)
from vpn.providers.stormshield import StormshieldProvider  # noqa: E402
from tests.test_vpn_forticlient_detect import FakeEnvironment  # noqa: E402
from tests.test_vpn_forticlient_autofill import FakeInput, RecTrace  # noqa: E402
from tests.test_vpn_stormshield import (  # noqa: E402
    GUI, HWND, INSTALL_DIR, PID, Desktop,
)
from tests.test_vpn_secure_target import ListFinder  # noqa: E402

LOGIN = "PLACEHOLDER-LOGIN"
PASSWORD = "PLACEHOLDER-PASSWORD"
SERVER, PORT = "vpn.example.invalid", "4433"
ADDRESS = f"{SERVER}:{PORT}"

SHIFT_TAB = ("combo", VK_SHIFT, VK_TAB)
CTRL_A = ("combo", VK_CONTROL, ord("A"))
ENTER_KEY = 0x0D


def run(*, desktop=None, login=LOGIN, password=PASSWORD, server=SERVER,
        port=PORT, hwnds=(HWND,)):
    desktop = desktop if desktop is not None else Desktop()
    inputs = FakeInput()
    trace = RecTrace()
    provider = StormshieldProvider(
        environment=FakeEnvironment(files=[GUI], dirs=[INSTALL_DIR]))
    target = provider.secure_window_target(api=desktop, finder=ListFinder(hwnds))
    request = VpnRequest(provider_id="stormshield", login=login,
                         password=password, server=server, port=port)
    result = provider.autofill_login_password(
        request, target=target, input_system=inputs, trace=trace)
    return result, inputs.events, trace


def typed(events):
    return [e[1] for e in events if e[0] == "type"]


def sent(events):
    """Everything that reached the window, in order — sleeps dropped."""
    return [e for e in events if e[0] in ("type", "key", "combo")]


# ══════════════════════════════════════════════════════════════════════════
# The sequence
# ══════════════════════════════════════════════════════════════════════════

def test_1_the_form_is_filled_backwards_from_password():
    result, events, _trace = run()

    assert result.status is AutofillStatus.DONE
    assert sent(events) == [
        ("type", PASSWORD),      # cursor is already on Password
        SHIFT_TAB,               # -> Login
        CTRL_A, ("type", LOGIN),
        SHIFT_TAB,               # -> Firewall address
        CTRL_A, ("type", ADDRESS),
    ]


def test_2_exactly_seven_operations_reach_the_window():
    """Not one keystroke more than the measured sequence needs."""
    _result, events, _trace = run()
    assert len(sent(events)) == 7
    assert [e for e in events if e[0] == "combo"].count(SHIFT_TAB) == 2


def test_3_enter_is_never_sent():
    """Stormshield's own client does not submit here, and neither do we."""
    _result, events, _trace = run()
    assert not [e for e in events if e[0] == "key" and e[1] == ENTER_KEY]
    assert not [e for e in events if e[0] == "key"], "zero pojedynczych klawiszy"


def test_4_no_clipboard_is_used_for_the_secret():
    """FortiClient pastes; this client is typed into directly."""
    _result, events, _trace = run()
    assert not [e for e in events if e[0] == "clip_set"]
    assert PASSWORD not in [e[1] for e in events if e[0] == "clip_set"]


def test_5_the_password_field_is_not_cleared_first():
    """It was measured empty; Ctrl+A in a password box buys nothing."""
    _result, events, _trace = run()
    first = sent(events)[0]
    assert first == ("type", PASSWORD), first


def test_6_the_address_is_host_and_port():
    _result, events, _trace = run()
    assert typed(events)[-1] == ADDRESS


def test_6b_a_missing_port_leaves_the_host_alone():
    _result, events, _trace = run(port="")
    assert typed(events)[-1] == SERVER


def test_7_an_empty_field_is_skipped_without_breaking_the_walk():
    """No login configured: the navigation still has to reach the address."""
    _result, events, _trace = run(login="")
    assert sent(events) == [
        ("type", PASSWORD), SHIFT_TAB, SHIFT_TAB, CTRL_A, ("type", ADDRESS)]


# ══════════════════════════════════════════════════════════════════════════
# Every operation is guarded
# ══════════════════════════════════════════════════════════════════════════

def test_8_all_five_phases_go_through_run_guarded():
    """The guard is the only way anything reaches the window."""
    seen = []

    class Watching(Desktop):
        pass

    from vpn.providers.secure_target import VerifiedWindow

    original = VerifiedWindow.run_guarded

    def recording(self, purpose, operation, **kwargs):
        seen.append(purpose)
        return original(self, purpose, operation, **kwargs)

    VerifiedWindow.run_guarded = recording
    try:
        run(desktop=Watching())
    finally:
        VerifiedWindow.run_guarded = original

    assert seen == list(sa.PHASES), seen


def test_9_the_phases_are_named_after_what_they_do():
    assert sa.PHASES == ("password-type", "shift-tab-to-login", "login-type",
                         "shift-tab-to-address", "address-type")


# ══════════════════════════════════════════════════════════════════════════
# Losing the target, at each point that matters
# ══════════════════════════════════════════════════════════════════════════

def focus_lost_after(n):
    """Foreground belongs to the client for n reads, then to a stranger."""
    from tests.test_vpn_stormshield import OTHER_HWND
    return lambda k: HWND if k <= n else OTHER_HWND


def test_10_foreground_lost_before_the_password_sends_nothing():
    # Reads: V2 pre-check (1), acquire (2); gone by the password guard (3).
    result, events, _trace = run(desktop=Desktop(foreground=focus_lost_after(2)))

    assert result.status is AutofillStatus.BLOCKED
    assert result.blocked_at == sa.PHASE_PASSWORD
    assert not result.password_entered and not result.login_entered
    assert sent(events) == [], events


def test_11_foreground_lost_between_password_and_login():
    result, events, _trace = run(desktop=Desktop(foreground=focus_lost_after(3)))

    assert result.status is AutofillStatus.BLOCKED
    assert result.password_entered, "haslo zdazylo wejsc"
    assert not result.login_entered
    assert LOGIN not in typed(events)
    assert result.blocked_at == sa.PHASE_TO_LOGIN


def test_12_foreground_lost_between_login_and_address():
    result, events, _trace = run(desktop=Desktop(foreground=focus_lost_after(5)))

    assert result.status is AutofillStatus.BLOCKED
    assert result.password_entered and result.login_entered
    assert ADDRESS not in typed(events)


def test_13_a_minimised_window_blocks_the_sequence():
    """The Stage-29 condition, reached through this provider's target."""
    result, events, _trace = run(desktop=Desktop(iconic=True))
    assert result.status is not AutofillStatus.DONE
    assert sent(events) == []


def test_14_a_changed_owner_blocks_the_next_operation():
    desktop = Desktop()
    original = desktop._foreground
    swapped = {"done": False}

    def swap_after_password(n):
        if n >= 4 and not swapped["done"]:
            desktop.images[PID] = r"C:\Users\Sebastian\Downloads\evil.exe"
            swapped["done"] = True
        return original(n)

    desktop._foreground = swap_after_password
    result, events, _trace = run(desktop=desktop)

    assert result.status is AutofillStatus.BLOCKED
    assert LOGIN not in typed(events)


def test_15_nothing_runs_after_the_first_refusal():
    """A blocked guard ends the attempt — no later phase gets a chance."""
    result, events, _trace = run(desktop=Desktop(foreground=focus_lost_after(3)))
    after_block = typed(events)
    assert after_block == [PASSWORD], after_block
    assert result.blocked_at == sa.PHASE_TO_LOGIN


def test_16_an_untrusted_window_is_refused_before_anything_is_acquired():
    desktop = Desktop(image=r"C:\Users\Sebastian\Downloads\sslvpn_client.exe")
    result, events, _trace = run(desktop=desktop)

    assert result.status is AutofillStatus.NO_TARGET
    assert result.blocked_at == "acquire"
    assert sent(events) == []


# ══════════════════════════════════════════════════════════════════════════
# The result, and what it must not carry
# ══════════════════════════════════════════════════════════════════════════

def test_17_success_says_the_user_still_has_to_click_log_in():
    result, _events, _trace = run()

    assert result.success and result.status is AutofillStatus.DONE
    assert result.login_entered and result.password_entered
    assert result.metadata.get("requires_user_action") is True
    assert result.metadata.get("submitted") is False
    assert result.error_code is None, "brak submitu to nie blad"


def test_18_no_secret_reaches_the_result_or_the_trace():
    result, _events, trace = run()
    blob = repr(result) + repr(trace.steps)
    for secret in (LOGIN, PASSWORD):
        assert secret not in blob, secret


def test_18b_a_blocked_attempt_also_carries_no_secret():
    result, _events, trace = run(desktop=Desktop(foreground=focus_lost_after(3)))
    blob = repr(result) + repr(trace.steps)
    for secret in (LOGIN, PASSWORD):
        assert secret not in blob, secret


def test_19_a_broken_seam_is_reported_not_raised():
    class Exploding(FakeInput):
        def type_text(self, text):
            raise OSError("sterownik klawiatury padl")

    provider = StormshieldProvider(
        environment=FakeEnvironment(files=[GUI], dirs=[INSTALL_DIR]))
    desktop = Desktop()
    result = provider.autofill_login_password(
        VpnRequest(provider_id="stormshield", login=LOGIN, password=PASSWORD,
                   server=SERVER, port=PORT),
        target=provider.secure_window_target(api=desktop,
                                             finder=ListFinder((HWND,))),
        input_system=Exploding(), trace=RecTrace())

    assert result.status is AutofillStatus.FAILED
    assert "sterownik klawiatury padl" not in repr(result)


# ══════════════════════════════════════════════════════════════════════════
# Shape of the change
# ══════════════════════════════════════════════════════════════════════════

def test_20_vk_shift_is_the_only_new_constant():
    from vpn.providers import input_system

    assert VK_SHIFT == 0x10
    assert "VK_SHIFT" in input_system.__all__
    source = open(input_system.__file__, encoding="utf-8").read()
    assert source.count("VK_SHIFT") <= 3, "stała, nie mechanizm"


def test_21_shift_tab_uses_the_existing_combo_mechanism():
    """Shift down, Tab, Shift up — through `press_combo`, not a new path."""
    tree = ast.parse(open(sa.__file__, encoding="utf-8").read())
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert "press_combo" in names
    for banned in ("keybd_event", "SendInput", "_send", "_send_input_key"):
        assert banned not in names, banned


def test_22_no_window_mechanism_came_along():
    tree = ast.parse(open(sa.__file__, encoding="utf-8").read())
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    for banned in ("SetForegroundWindow", "set_foreground_window", "ShowWindow",
                   "SW_RESTORE", "restore_window", "SetWindowPos",
                   "HWND_TOPMOST", "PostMessage", "AttachThreadInput"):
        assert banned not in names, banned


def test_23_no_otp_automation_in_this_stage():
    """The field exists in the client; automating it is a separate decision."""
    source = open(sa.__file__, encoding="utf-8").read()
    tree = ast.parse(source)
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    for banned in ("token", "otp", "OTP", "two_factor"):
        assert banned not in names, banned

    from vpn import Capability
    provider = StormshieldProvider(
        environment=FakeEnvironment(files=[GUI], dirs=[INSTALL_DIR]))
    assert not provider.supports(Capability.TWO_FACTOR), \
        "capability nie wynika z tego, ze UI ma pole"


def test_24_connect_is_still_not_armed():
    assert StormshieldProvider.CONNECT_ENABLED is False


def test_25_legacy_does_not_know_this_module():
    legacy = open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read()
    for token in ("stormshield_autofill", "autofill_login_password"):
        assert token not in legacy, token
