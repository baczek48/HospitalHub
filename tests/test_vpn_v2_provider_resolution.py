"""Stage 53: the V2 session picks its provider from the request, not FortiClient.

``build_request`` and ``PanelConnectSession`` used to assume FortiClient
(``provider_id=FortiClientProvider.id`` / ``default_registry.get("forticlient")``).
They now resolve the provider the profile names, through one central,
fail-closed resolver keyed by stable id — deterministic, order-independent, and
never falling back to another provider.

Three concepts are kept apart:
  A. a V2 implementation exists           → membership in ``_V2_BY_ID``
  B. a provider is resolvable/constructible → ``resolve_v2_provider`` returns one
  C. a provider is production-enabled      → its ``CONNECT_ENABLED`` flag (all off)
"""

import ast
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import models  # noqa: E402
import vpn  # noqa: E402
from vpn import VpnRequest  # noqa: E402
from vpn import panel_bridge as pb  # noqa: E402
from vpn.panel_bridge import (  # noqa: E402
    PanelConnectSession, PanelOutcome, build_request, resolve_v2_provider,
    v2_provider_id_for,
)
from vpn.providers.barracuda import BarracudaProvider  # noqa: E402
from vpn.providers.forticlient import FortiClientProvider  # noqa: E402
from vpn.providers.forticlient import WindowsEnvironment  # noqa: E402
from vpn.providers.stormshield import StormshieldProvider  # noqa: E402

CASES = [
    ("FortiClient", "forticlient", FortiClientProvider),
    ("Stormshield", "stormshield", StormshieldProvider),
    ("Barracuda", "barracuda", BarracudaProvider),
]

LOGIN, PASSWORD = "jkowalski", "SuperSecret123"

#: A plausible install directory under Program Files that is in *no* provider's
#: built-in list — the case Stage 55 exists for.
ELSEWHERE_DIR = os.path.join(
    os.environ.get("ProgramFiles", "C:" + os.sep + "Program Files"),
    "Szpital", "VPN")
ELSEWHERE = os.path.join(ELSEWHERE_DIR, "client.exe")


def profile(provider, **kw):
    values = dict(name="p", provider=provider, server="vpn.x", port="443",
                  login=LOGIN, password=PASSWORD, group="g", domain="d",
                  app_path=r"C:\x\client.exe", profile_name="SZP")
    values.update(kw)
    return models.VpnProfile(**values)


# ══════════════════════════════════════════════════════════════════════════
# A–C. Each provider resolves to its own class
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("name,pid,cls", CASES)
def test_abc_name_and_id_resolve_to_the_right_provider(name, pid, cls):
    assert v2_provider_id_for(name) == pid
    resolved = resolve_v2_provider(pid)
    assert isinstance(resolved, cls)


@pytest.mark.parametrize("name,pid,cls", CASES)
def test_abc_build_request_carries_the_profiles_provider(name, pid, cls):
    req = build_request(profile(name), app_path=r"C:\x\client.exe", autofill=True)
    assert req.provider_id == pid


# ══════════════════════════════════════════════════════════════════════════
# D–F. Fail-closed: unknown / missing / non-V2
# ══════════════════════════════════════════════════════════════════════════

def test_d_unknown_provider_resolves_to_nothing():
    for name in ("Nope", "forticlient", "FORTICLIENT", "FortiClient ", "Forti"):
        assert v2_provider_id_for(name) == ""
    for pid in ("nope", "FortiClient", "forti", "", "forticlient "):
        assert resolve_v2_provider(pid) is None


def test_e_missing_provider_resolves_to_nothing():
    assert v2_provider_id_for("") == ""
    assert v2_provider_id_for(None) == ""
    assert resolve_v2_provider(None) is None
    assert resolve_v2_provider("") is None


def test_f_non_v2_providers_do_not_resolve():
    for name in ("GlobalProtect", "SonicWall NetExtender",
                 "Hillstone Secure Connect", "Windows VPN"):
        assert v2_provider_id_for(name) == ""
        assert name not in pb.V2_PROVIDERS


def test_f2_a_name_resolves_to_its_own_id_never_a_neighbours():
    # Exact only: no name maps to a different provider's id.
    for name, pid, _cls in CASES:
        others = {p for _n, p, _c in CASES} - {pid}
        assert v2_provider_id_for(name) not in others


# ══════════════════════════════════════════════════════════════════════════
# G. Provider A can never construct provider B
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("name,pid,cls", CASES)
def test_g_resolution_never_yields_another_provider(name, pid, cls):
    resolved = resolve_v2_provider(pid)
    for _n, _p, other in CASES:
        if other is not cls:
            assert not isinstance(resolved, other)


# ══════════════════════════════════════════════════════════════════════════
# H. Order-independent; does not consult default_registry
# ══════════════════════════════════════════════════════════════════════════

def test_h_resolution_does_not_depend_on_registry_or_its_order(monkeypatch):
    """Emptying the default registry changes nothing: the resolver is its own
    dict, not a registry scan."""
    from vpn.registry import VpnRegistry
    monkeypatch.setattr(pb, "default_registry", VpnRegistry())   # empty
    for _name, pid, cls in CASES:
        assert isinstance(resolve_v2_provider(pid), cls)


def test_h2_the_resolver_is_a_dict_keyed_by_id():
    assert set(pb._V2_BY_ID) == {"forticlient", "stormshield", "barracuda"}
    assert pb._V2_BY_ID["forticlient"] is FortiClientProvider
    assert pb._V2_BY_ID["stormshield"] is StormshieldProvider
    assert pb._V2_BY_ID["barracuda"] is BarracudaProvider


# ══════════════════════════════════════════════════════════════════════════
# I, J, K. Resolvability ≠ enablement; production stays legacy; registry state
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("name,pid,cls", CASES)
def test_i_resolving_a_provider_does_not_arm_it(name, pid, cls):
    resolved = resolve_v2_provider(pid)
    assert resolved.CONNECT_ENABLED is False
    assert cls.CONNECT_ENABLED is False


def test_j_disabled_providers_still_route_legacy():
    from vpn.panel_bridge import ROUTE_LEGACY, select_connect_route
    for name, _pid, cls in CASES:
        assert cls.CONNECT_ENABLED is False
        assert select_connect_route(name) == ROUTE_LEGACY


def test_k_default_registry_is_unchanged_by_this_stage():
    """The chosen design does NOT extend the registry — it is the cutover set,
    kept separate from the resolver."""
    assert vpn.default_registry.ids() == ["forticlient"]
    assert "stormshield" not in vpn.default_registry.ids()
    assert "barracuda" not in vpn.default_registry.ids()


# ══════════════════════════════════════════════════════════════════════════
# M, N. Stormshield / Barracuda requests keep their parameters
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("name,pid,_cls", CASES)
def test_mn_request_preserves_every_field(name, pid, _cls):
    p = profile(name, login="userX", password="passX", profile_name="PX",
                server="s.x", port="9443", group="grp", domain="dom",
                requires_2fa=True)
    req = build_request(p, app_path=r"C:\p\c.exe", autofill=False)
    assert req.provider_id == pid
    assert req.login == "userX" and req.password == "passX"
    assert req.profile_name == "PX" and req.server == "s.x" and req.port == "9443"
    assert req.group == "grp" and req.domain == "dom"
    assert req.app_path == r"C:\p\c.exe" and req.autofill is False
    assert req.requires_2fa is True and req.token == ""


# ══════════════════════════════════════════════════════════════════════════
# O. No credential leaks
# ══════════════════════════════════════════════════════════════════════════

def test_o_credentials_never_appear_in_request_repr_or_the_outcome():
    req = build_request(profile("Stormshield"), app_path="", autofill=True)
    assert PASSWORD not in repr(req), "repr(request) must hide the password"
    assert "jkowalski" in repr(req), "login is allowed in debug, password is not"
    # A disarmed session's outcome carries no secret either.
    outcome = PanelConnectSession(req).run()
    assert PASSWORD not in repr(outcome) and LOGIN not in repr(outcome)


# ══════════════════════════════════════════════════════════════════════════
# P. Resolver exception → safe failure, no fallback
# ══════════════════════════════════════════════════════════════════════════

def test_p_a_construction_error_resolves_to_none_not_another_provider(monkeypatch):
    class Boom(FortiClientProvider):
        def __init__(self, *a, **k):
            raise RuntimeError("construction padła")

    monkeypatch.setitem(pb._V2_BY_ID, "forticlient", Boom)
    assert resolve_v2_provider("forticlient") is None          # not a fallback
    # A session for it fails-closed, never silently becomes another provider.
    outcome = PanelConnectSession(
        VpnRequest(provider_id="forticlient")).run()
    assert outcome.code is PanelOutcome.UNSUPPORTED


def test_p2_a_hostile_provider_id_is_safe():
    # Unhashable / weird ids must not raise out of the resolver.
    assert resolve_v2_provider(["forticlient"]) is None
    assert v2_provider_id_for(["FortiClient"]) == ""


# ══════════════════════════════════════════════════════════════════════════
# The session resolves the request's provider (not always FortiClient)
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("name,pid,cls", CASES)
def test_session_resolves_the_requests_provider(monkeypatch, name, pid, cls):
    seen = []

    def spy(provider_id, app_path=""):
        seen.append((provider_id, app_path))
        return None            # decline → UNSUPPORTED, but we captured the id

    monkeypatch.setattr(pb, "resolve_v2_provider", spy)
    req = build_request(profile(name), app_path=ELSEWHERE, autofill=True)
    PanelConnectSession(req).run()
    # Stage 55: the profile's own executable path travels with the id, so the
    # provider can anchor its trust to the directory the profile names.
    assert seen == [(pid, ELSEWHERE)], f"session resolved {seen}, expected {pid}"


def test_panel_bridge_has_no_forticlient_hardcode_in_build_or_session():
    """Structural: neither `build_request` nor the session pins FortiClient."""
    src = open(pb.__file__, encoding="utf-8").read()
    build = src[src.index("def build_request"):src.index("class PanelOutcome")]
    assert "FortiClientProvider.id" not in build
    run = src[src.index("def run(self)"):src.index("class TwoFactorMonitorSession")]
    assert "FortiClientProvider.id" not in run
    assert "resolve_v2_provider(request.provider_id," in run


# ═════════════════════════════════════════════════════════════════════════
# Stage 55: the resolved provider is told the profile's own app_path
# ═════════════════════════════════════════════════════════════════════════

#: The two providers that anchor trust to a *configured* directory.
CONFIGURABLE = [("stormshield", StormshieldProvider),
                ("barracuda", BarracudaProvider)]


@pytest.fixture
def installed_elsewhere(monkeypatch):
    """Make that unusual directory look like a real install.

    Only the file check is faked — the Program Files rule that decides whether
    the directory may be trusted is the provider's own and runs for real.
    """
    original = WindowsEnvironment.is_file
    monkeypatch.setattr(
        WindowsEnvironment, "is_file",
        lambda self, path: path == ELSEWHERE or original(self, path))


@pytest.mark.parametrize("pid,cls", CONFIGURABLE)
def test_q_app_path_under_program_files_becomes_a_trusted_dir(
        pid, cls, installed_elsewhere):
    """The profile's directory joins the trust anchor — the point of the stage.

    Without it, a site whose client lives outside the known install directories
    has its verified window refused under V2 while legacy accepts it.
    """
    without = set(resolve_v2_provider(pid).trusted_window_dirs())
    with_path = set(resolve_v2_provider(pid, ELSEWHERE).trusted_window_dirs())
    assert ELSEWHERE_DIR not in without
    assert ELSEWHERE_DIR in with_path
    assert without <= with_path, "the built-in directories are never dropped"


@pytest.mark.parametrize("pid,cls", CONFIGURABLE)
def test_q2_app_path_outside_program_files_widens_nothing(pid, cls, monkeypatch):
    """Trust comes from Program Files, not from a profile saying so.

    A profile may name any executable; only a directory whose contents need
    administrator rights to replace can become a trust anchor.
    """
    outside = os.path.join(os.path.expanduser("~"), "Downloads", "client.exe")
    original = WindowsEnvironment.is_file
    monkeypatch.setattr(WindowsEnvironment, "is_file",
                        lambda self, path: path == outside or original(self, path))
    assert (set(resolve_v2_provider(pid, outside).trusted_window_dirs())
            == set(resolve_v2_provider(pid).trusted_window_dirs()))


def test_q3_forticlient_has_no_configured_anchor_and_is_left_alone(
        installed_elsewhere):
    """FortiClient takes its install directory from its own detection.

    It has no ``with_app_path``; passing one must neither raise nor invent an
    anchor for it.
    """
    assert not hasattr(FortiClientProvider, "with_app_path")
    provider = resolve_v2_provider("forticlient", ELSEWHERE)
    assert isinstance(provider, FortiClientProvider)
    assert ELSEWHERE_DIR not in provider.trusted_window_dirs()


@pytest.mark.parametrize("pid,cls", CONFIGURABLE)
def test_q4_an_empty_app_path_is_simply_not_applied(pid, cls):
    assert (set(resolve_v2_provider(pid, "").trusted_window_dirs())
            == set(resolve_v2_provider(pid).trusted_window_dirs()))


@pytest.mark.parametrize("pid,cls", CONFIGURABLE)
def test_q5_a_failing_anchor_declines_rather_than_guessing(pid, cls, monkeypatch):
    """Fail-closed: if the configured path cannot even be read, resolve to None.

    An unknown trust anchor is not a reason to carry on with the built-in one —
    the session then answers ``unsupported`` instead of connecting.
    """
    def boom(self, app_path):
        raise OSError("ścieżka nieczytelna")

    monkeypatch.setattr(cls, "with_app_path", boom)
    assert resolve_v2_provider(pid, ELSEWHERE) is None
    outcome = PanelConnectSession(
        VpnRequest(provider_id=pid, app_path=ELSEWHERE)).run()
    assert outcome.code is PanelOutcome.UNSUPPORTED


@pytest.mark.parametrize("pid,cls", CONFIGURABLE)
def test_q6_each_resolution_is_a_fresh_provider(pid, cls, installed_elsewhere):
    """One card's app_path never leaks into the next card's provider."""
    first = resolve_v2_provider(pid, ELSEWHERE)
    second = resolve_v2_provider(pid)
    assert first is not second
    assert ELSEWHERE_DIR not in second.trusted_window_dirs()


@pytest.mark.parametrize("pid,cls", CONFIGURABLE)
def test_q7_the_flag_is_still_off(pid, cls):
    """None of this arms anything: production still connects through legacy."""
    assert cls.CONNECT_ENABLED is False
