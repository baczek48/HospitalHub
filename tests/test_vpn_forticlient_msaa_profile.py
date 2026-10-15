"""Stage 62: reading the FortiClient profile through MSAA — read-only, fail-closed.

Stage 61 measured FortiClient VPN 7.4.3: UI Automation sees only the window
chrome, MSAA sees the form, and the ``VPN Name`` combo's ``accValue`` is the
group label and the tunnel name (``"Personal VPNs <name>"``).  These tests pin
the two halves built on that: finding and reading exactly that control in the
verified window, and matching its value to a configured tunnel exactly.

Everything is a fake — the desktop (:class:`FakeDesktop`), the MSAA tree
(:class:`FakeMsaa`) and the registry (:class:`FakeEnvironment`).  The one test
that touches the real seam does so on purpose, under the conftest guard.
"""

import ast
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from vpn.providers import FortiClientProvider  # noqa: E402
from vpn.providers import forticlient_profile as fp  # noqa: E402
from vpn.providers import msaa_system as ms  # noqa: E402
from vpn.providers.msaa_system import (  # noqa: E402
    ROLE_SYSTEM_COMBOBOX, STATE_SYSTEM_COLLAPSED, STATE_SYSTEM_FOCUSED,
    MsaaNode, MsaaScan, MsaaSystem, Win32MsaaSystem,
)
from tests.test_vpn_forticlient_detect import FakeEnvironment  # noqa: E402
from tests.test_vpn_secure_target import (  # noqa: E402
    EVIL_EXE, EVIL_PID, FORTI_DIR, FORTI_GUI, FORTI_PID, FORTI_TID, HWND,
    OTHER, FakeDesktop, ListFinder,
)

PROFILE = "SZPITAL-A"
SHOWN = "Personal VPNs " + PROFILE
#: Measured on 7.4.3 (Stage 61): collapsed + focusable, not focused.
STATE_IDLE = STATE_SYSTEM_COLLAPSED | 0x100000
#: A second window of the same, verified FortiClient process.
SIBLING = 0x3003
#: A second FortiClient process (trusted image, different pid).
OTHER_FORTI_PID = 4200
ROLE_SYSTEM_TEXT = 0x2A


def combo(*, name=fp.PROFILE_CONTROL_NAME, value=SHOWN, state=STATE_IDLE,
          window=HWND, role=ROLE_SYSTEM_COMBOBOX):
    return MsaaNode(role=role, name=name, state=state, value=value, window=window)


class FakeMsaa(MsaaSystem):
    """An MSAA tree described up front; records which windows were asked."""

    def __init__(self, *combos, ok=True, reason="", raises=False):
        self.scan = MsaaScan(ok=ok, combos=tuple(combos), reason=reason)
        self.raises = raises
        self.asked = []

    def combo_boxes(self, hwnd):
        self.asked.append(hwnd)
        if self.raises:
            raise OSError("COM went away")
        return self.scan


def desktop():
    return FakeDesktop(
        windows={HWND: (FORTI_PID, FORTI_TID, HWND),
                 SIBLING: (OTHER_FORTI_PID, 77, SIBLING),
                 OTHER: (EVIL_PID, 99, OTHER)},
        images={FORTI_PID: FORTI_GUI, OTHER_FORTI_PID: FORTI_GUI,
                EVIL_PID: EVIL_EXE})


def make_target(desk=None, finder_hwnds=(HWND,)):
    provider = FortiClientProvider(FakeEnvironment(files=[FORTI_GUI], dirs=[FORTI_DIR]))
    return provider.secure_window_target(api=desk if desk is not None else desktop(),
                                         finder=ListFinder(finder_hwnds))


def catalog(ssl=(PROFILE, "1SZP"), ipsec=("ALFA IPsec",)):
    return fp.TunnelCatalog(ssl=tuple(ssl), ipsec=tuple(ipsec))


# ══════════════════════════════════════════════════════════════════════════
# A. Reading the control
# ══════════════════════════════════════════════════════════════════════════

def test_a1_the_vpn_name_combo_of_the_verified_window_is_read():
    msaa = FakeMsaa(combo(name="Something else", value="x"), combo())
    r = fp.read_profile_control(make_target(), msaa)

    assert r.ok and r.reason == "read"
    assert r.hwnd == HWND and r.pid == FORTI_PID
    assert r.value == SHOWN
    assert r.collapsed and not r.expanded and not r.focused
    assert msaa.asked == [HWND], "pytany wylacznie zweryfikowane okno"


def test_a2_focused_comes_from_acc_state():
    r = fp.read_profile_control(make_target(),
                                FakeMsaa(combo(state=STATE_IDLE | STATE_SYSTEM_FOCUSED)))
    assert r.ok and r.focused


def test_a3_no_verified_window_reads_nothing():
    msaa = FakeMsaa(combo())
    r = fp.read_profile_control(make_target(finder_hwnds=(OTHER,)), msaa)

    assert not r.ok and r.reason == fp.REASON_NO_WINDOW
    assert msaa.asked == [], "obce okno nie jest nawet odpytywane"


def test_a4_an_explicit_untrusted_window_is_refused_before_msaa():
    msaa = FakeMsaa(combo(window=OTHER))
    r = fp.read_profile_control(make_target(), msaa, hwnd=OTHER)

    assert not r.ok and r.reason == fp.REASON_WINDOW_UNTRUSTED
    assert msaa.asked == []


@pytest.mark.parametrize("msaa", [
    FakeMsaa(ok=False, reason="msaa-no-root"),
    FakeMsaa(raises=True),
])
def test_a5_an_unreadable_tree_is_a_refusal(msaa):
    r = fp.read_profile_control(make_target(), msaa)
    assert not r.ok and r.reason == fp.REASON_MSAA_UNAVAILABLE


@pytest.mark.parametrize("nodes", [
    (),
    (combo(name="VPN name"),),                 # case differs
    (combo(name="VPN Name "),),                # trailing space
    (combo(name=None),),
    (combo(role=ROLE_SYSTEM_TEXT),),           # right name, wrong role
])
def test_a6_no_vpn_name_combo_is_missing(nodes):
    r = fp.read_profile_control(make_target(), FakeMsaa(*nodes))
    assert not r.ok and r.reason == fp.REASON_CONTROL_MISSING


def test_a7_two_vpn_name_combos_is_ambiguous_not_the_first_one():
    r = fp.read_profile_control(make_target(),
                                FakeMsaa(combo(), combo(value="Personal VPNs 1SZP")))
    assert not r.ok and r.reason == fp.REASON_CONTROL_AMBIGUOUS
    assert r.value is None


@pytest.mark.parametrize("window", [OTHER, None, 0xDEAD])
def test_a8_a_control_outside_the_verified_window_is_refused(window):
    r = fp.read_profile_control(make_target(), FakeMsaa(combo(window=window)))
    assert not r.ok and r.reason == fp.REASON_FOREIGN_WINDOW
    assert r.value is None


class ChangesDuringScan(FakeMsaa):
    """The desktop changes while the tree is being walked."""

    def __init__(self, change, *combos):
        super().__init__(*combos)
        self._change = change

    def combo_boxes(self, hwnd):
        self._change()
        return super().combo_boxes(hwnd)


def test_a9_the_window_must_still_verify_to_the_same_process():
    """Verified before the walk; by the time the control is checked the HWND
    belongs to another process — even another trusted FortiClient one."""
    desk = desktop()

    def recycle():
        desk.windows[HWND] = (OTHER_FORTI_PID, 77, HWND)

    r = fp.read_profile_control(make_target(desk), ChangesDuringScan(recycle, combo()))
    assert not r.ok and r.reason == fp.REASON_FOREIGN_PROCESS
    assert r.value is None


def test_a10_a_window_that_stops_verifying_is_refused():
    desk = desktop()

    def swap_image():
        desk.images[FORTI_PID] = EVIL_EXE

    r = fp.read_profile_control(make_target(desk), ChangesDuringScan(swap_image, combo()))
    assert not r.ok and r.reason == fp.REASON_FOREIGN_PROCESS
    assert r.value is None


@pytest.mark.parametrize("state", [None, "collapsed", 1.0, True])
def test_a11_unreadable_acc_state_is_a_refusal(state):
    r = fp.read_profile_control(make_target(), FakeMsaa(combo(state=state)))
    assert not r.ok and r.reason == fp.REASON_STATE_UNREADABLE


@pytest.mark.parametrize("value", [None, "", 42])
def test_a12_unreadable_acc_value_is_a_refusal(value):
    r = fp.read_profile_control(make_target(), FakeMsaa(combo(value=value)))
    assert not r.ok and r.reason == fp.REASON_VALUE_UNREADABLE


def test_a13_the_value_stays_out_of_repr():
    r = fp.read_profile_control(make_target(), FakeMsaa(combo()))
    assert PROFILE not in repr(r)
    assert PROFILE not in repr(combo())


# ══════════════════════════════════════════════════════════════════════════
# B. Matching the profile
# ══════════════════════════════════════════════════════════════════════════

def test_b1_the_measured_format_matches_its_ssl_tunnel():
    m = fp.match_profile(SHOWN, PROFILE, catalog())
    assert m.matched and m.reason == fp.REASON_MATCHED
    assert m.group_label == "Personal VPNs" and m.tunnel_kind == fp.TUNNEL_KIND_SSL


def test_b2_only_measured_labels_are_known():
    assert fp.GROUP_LABELS == {"Personal VPNs": fp.TUNNEL_KIND_SSL}


@pytest.mark.parametrize("shown", [
    PROFILE,                              # no label at all
    "Managed VPNs " + PROFILE,            # EMS — not measured
    "IPsec VPNs ALFA IPsec",              # IPsec — not measured
    "Osobiste VPN " + PROFILE,            # a translation — not measured
    "personal vpns " + PROFILE,           # case
    "Personal VPNs" + PROFILE,            # no separator
    " Personal VPNs " + PROFILE,          # leading space
])
def test_b3_an_unknown_label_or_format_is_refused(shown):
    m = fp.match_profile(shown, PROFILE, catalog())
    assert not m.matched and m.reason == fp.REASON_UNKNOWN_GROUP


def test_b4_two_labels_that_both_parse_are_ambiguous(monkeypatch):
    monkeypatch.setattr(fp, "GROUP_LABELS", {"Personal VPNs": fp.TUNNEL_KIND_SSL,
                                             "Personal": fp.TUNNEL_KIND_IPSEC})
    m = fp.match_profile(SHOWN, PROFILE, catalog())
    assert not m.matched and m.reason == fp.REASON_AMBIGUOUS_GROUP


@pytest.mark.parametrize("shown", ["Personal VPNs ", "Personal VPNs   "])
def test_b5_a_label_with_no_name_is_refused(shown):
    m = fp.match_profile(shown, PROFILE, catalog())
    assert not m.matched and m.reason == fp.REASON_EMPTY_NAME


@pytest.mark.parametrize("requested", ["", "   ", None])
def test_b6_an_empty_request_is_refused(requested):
    m = fp.match_profile(SHOWN, requested, catalog())
    assert not m.matched and m.reason == fp.REASON_REQUEST_EMPTY


@pytest.mark.parametrize("shown", [None, "", 7])
def test_b7_an_unreadable_value_is_refused(shown):
    m = fp.match_profile(shown, PROFILE, catalog())
    assert not m.matched and m.reason == fp.REASON_VALUE_UNREADABLE


def test_b8_another_configured_profile_on_display_is_a_mismatch():
    m = fp.match_profile("Personal VPNs 1SZP", PROFILE, catalog())
    assert not m.matched and m.reason == fp.REASON_MISMATCH


@pytest.mark.parametrize("shown,requested,ssl", [
    ("Personal VPNs 1SZP", "1S", ("1SZP", "1S")),         # requested is a prefix
    ("Personal VPNs 1S", "1SZP", ("1SZP", "1S")),         # shown is a prefix
    ("Personal VPNs 1szp", "1SZP", ("1SZP", "1szp")),     # case only
    ("Personal VPNs 1SZP ", "1SZP", ("1SZP", "1SZP ")),   # trailing space
])
def test_b9_no_prefix_case_or_whitespace_tolerance(shown, requested, ssl):
    m = fp.match_profile(shown, requested, catalog(ssl=ssl))
    assert not m.matched and m.reason == fp.REASON_MISMATCH


@pytest.mark.parametrize("shown", [
    "Personal VPNs NIE-MA-TAKIEGO",       # nothing like it
    "Personal VPNs 1S",                   # a prefix of a real tunnel
    "Personal VPNs SZPITAL-A-STARY",      # a real tunnel is its prefix
    "Personal VPNs szpital-a",            # case
])
def test_b10_a_name_that_is_not_a_configured_tunnel_is_refused(shown):
    m = fp.match_profile(shown, shown[len("Personal VPNs "):], catalog())
    assert not m.matched and m.reason == fp.REASON_TUNNEL_NOT_CONFIGURED


def test_b11_an_ipsec_tunnel_under_the_ssl_label_is_refused():
    """The label was measured over SSL tunnels only."""
    m = fp.match_profile("Personal VPNs ALFA IPsec", "ALFA IPsec", catalog())
    assert not m.matched and m.reason == fp.REASON_TUNNEL_NOT_CONFIGURED


def test_b12_a_name_configured_as_both_kinds_is_ambiguous():
    m = fp.match_profile(SHOWN, PROFILE, catalog(ipsec=(PROFILE,)))
    assert not m.matched and m.reason == fp.REASON_AMBIGUOUS_TUNNEL


def test_b13_no_tunnels_configured_or_unreadable_is_refused():
    m = fp.match_profile(SHOWN, PROFILE, fp.TunnelCatalog())
    assert not m.matched and m.reason == fp.REASON_CATALOG_UNAVAILABLE


def test_b14_the_match_never_carries_the_names():
    for m in (fp.match_profile(SHOWN, PROFILE, catalog()),
              fp.match_profile("Personal VPNs 1SZP", PROFILE, catalog())):
        assert PROFILE not in repr(m) and "1SZP" not in repr(m)


# ══════════════════════════════════════════════════════════════════════════
# C. The tunnel catalog (registry key names only)
# ══════════════════════════════════════════════════════════════════════════

def test_c1_tunnel_names_are_the_subkey_names_per_kind():
    env = FakeEnvironment(registry={
        fp.SSL_TUNNELS_KEY + "\\" + PROFILE: {"Server": "vpn.example:443",
                                              "Username": "nie-czytane"},
        fp.SSL_TUNNELS_KEY + "\\1SZP": {},
        fp.IPSEC_TUNNELS_KEY + "\\ALFA IPsec": {},
    })
    cat = fp.configured_tunnels(env)
    assert cat.ssl == (PROFILE, "1SZP") and cat.ipsec == ("ALFA IPsec",)


def test_c2_no_value_under_a_tunnel_key_is_read():
    class Watching(FakeEnvironment):
        def __init__(self, *a, **k):
            super().__init__(*a, **k)
            self.values = []

        def registry_value(self, subkey, name):
            self.values.append((subkey, name))
            return super().registry_value(subkey, name)

    env = Watching(registry={fp.SSL_TUNNELS_KEY + "\\" + PROFILE: {"Password": "x"}})
    fp.configured_tunnels(env)
    assert env.values == []


def test_c3_an_unreadable_registry_gives_an_empty_catalog():
    class Broken(FakeEnvironment):
        def registry_subkeys(self, subkey):
            raise OSError("access denied")

    cat = fp.configured_tunnels(Broken())
    assert cat.empty
    assert fp.match_profile(SHOWN, PROFILE, cat).reason == fp.REASON_CATALOG_UNAVAILABLE


# ══════════════════════════════════════════════════════════════════════════
# D. End to end, and what it must never do
# ══════════════════════════════════════════════════════════════════════════

def test_d1_verify_displayed_profile_yes_only_on_an_exact_tunnel():
    reading, match = fp.verify_displayed_profile(
        make_target(), FakeMsaa(combo()), catalog(), PROFILE)
    assert reading.ok and match.matched

    reading, match = fp.verify_displayed_profile(
        make_target(), FakeMsaa(combo(), combo()), catalog(), PROFILE)
    assert not match.matched and match.reason == fp.REASON_CONTROL_AMBIGUOUS


def test_d2_reading_sends_nothing_to_the_window():
    desk = desktop()
    fp.verify_displayed_profile(make_target(desk), FakeMsaa(combo()), catalog(), PROFILE)
    assert desk.events == [], "zadnego attach/restore/set_foreground"
    assert desk.fg_checks == 0, "nawet nie pyta o pierwszy plan"


_ACTING = {"press_key", "press_combo", "type_text", "copy_to_clipboard",
           "SendInput", "keybd_event", "mouse_event", "SendMessage",
           "SendMessageW", "PostMessage", "PostMessageW", "SetFocus",
           "SetForegroundWindow", "AttachThreadInput", "accDoDefaultAction",
           "accSelect", "put_accValue", "acquire", "acquire_any", "run_guarded",
           "set_value", "SetValue"}


@pytest.mark.parametrize("module", [fp, ms])
def test_d3_neither_module_can_act_on_a_window(module):
    tree = ast.parse(open(module.__file__, encoding="utf-8").read())
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    assert not (names & _ACTING), names & _ACTING


def test_d4_the_real_seam_asks_acc_value_only_of_a_combo_box():
    src = open(ms.__file__, encoding="utf-8").read()
    body = src[src.index("class Win32MsaaSystem"):]
    assert body.count("accValue(") == 1
    assert body.index("if role == ROLE_SYSTEM_COMBOBOX:") < body.index("accValue(")


@pytest.mark.real_system_guard
def test_d5_the_real_seam_under_the_guard_reports_unavailable_not_raises():
    """No real window is read in the suite: the guard blocks comtypes, and the
    seam turns that into ``ok=False`` instead of an exception."""
    scan = Win32MsaaSystem().combo_boxes(HWND)
    assert scan.ok is False and scan.reason.startswith("msaa-error:")
    assert scan.combos == ()


def test_d6_only_the_v2_fill_uses_the_new_layer():
    """Stage 62 added the reader; Stage 63 wired it into the V2 fill
    (`forticlient_autofill`) and nowhere else — the legacy path, the panels
    and the bridge do not know it exists."""
    fill = open(os.path.join(_PARENT, "vpn", "providers", "forticlient_autofill.py"),
                encoding="utf-8").read()
    assert "forticlient_profile" in fill and "Win32MsaaSystem" in fill
    for rel in ("vpn_connect.py", os.path.join("ui", "vpn_panel.py"),
                os.path.join("ui", "detail_panel.py"), "main.py",
                os.path.join("vpn", "panel_bridge.py")):
        source = open(os.path.join(_PARENT, rel), encoding="utf-8").read()
        for token in ("forticlient_profile", "msaa_system", "Win32MsaaSystem"):
            assert token not in source, f"{rel}: {token}"


def test_d7_connect_flags_are_still_off_in_source():
    for rel in ("forticlient.py", "stormshield.py", "barracuda.py"):
        src = open(os.path.join(_PARENT, "vpn", "providers", rel), encoding="utf-8").read()
        assert "    CONNECT_ENABLED = False\n" in src, rel
