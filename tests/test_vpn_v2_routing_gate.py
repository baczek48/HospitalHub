"""Stage 51: the provider-scoped V2 routing gate.

``select_connect_route`` used to be hardcoded to FortiClient.  It is now an
explicit, per-provider allowlist keyed by stable ``legacy_name``: FortiClient,
Stormshield and Barracuda each have an *independent* gate, and — with every flag
off, as it is now — every provider still routes to legacy.

These tests are the whole contract: fail-closed everywhere, one provider's flag
never activates another, non-V2 providers are always legacy, and the production
state (all off, registry unchanged, panel unwired) is pinned.
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
from vpn import panel_bridge as pb  # noqa: E402
from vpn.panel_bridge import (  # noqa: E402
    ROUTE_BARRACUDA_V2, ROUTE_FORTICLIENT_V2, ROUTE_LEGACY, ROUTE_STORMSHIELD_V2,
    V2_PROVIDERS, select_connect_route,
)
from vpn.providers.barracuda import BarracudaProvider  # noqa: E402
from vpn.providers.forticlient import FortiClientProvider  # noqa: E402
from vpn.providers.stormshield import StormshieldProvider  # noqa: E402

FORTI, STORM, BARR = "FortiClient", "Stormshield", "Barracuda"
V2_NAMES = (FORTI, STORM, BARR)
V2_ROUTE = {FORTI: ROUTE_FORTICLIENT_V2, STORM: ROUTE_STORMSHIELD_V2,
            BARR: ROUTE_BARRACUDA_V2}
#: Every builtin provider that must always be legacy (no V2 implementation).
NON_V2 = [n for n in models.VPN_PROVIDERS_BUILTIN if n not in V2_NAMES]


@pytest.fixture
def arm(monkeypatch):
    """Return a helper that sets each provider's CONNECT_ENABLED for one test."""
    classes = {FORTI: FortiClientProvider, STORM: StormshieldProvider,
               BARR: BarracudaProvider}

    def _arm(**flags):
        for name, cls in classes.items():
            monkeypatch.setattr(cls, "CONNECT_ENABLED", flags.get(name, False))
    return _arm


def routes():
    return {name: select_connect_route(name) for name in V2_NAMES}


# ══════════════════════════════════════════════════════════════════════════
# 1. Default (production) state: everything off → everything legacy
# ══════════════════════════════════════════════════════════════════════════

def test_1_all_three_disabled_is_the_current_state_and_all_legacy():
    for cls in (FortiClientProvider, StormshieldProvider, BarracudaProvider):
        assert cls.CONNECT_ENABLED is False
    for name in V2_NAMES:
        assert select_connect_route(name) == ROUTE_LEGACY, name


def test_1b_every_builtin_provider_is_legacy_by_default():
    for name in models.VPN_PROVIDERS_BUILTIN:
        assert select_connect_route(name) == ROUTE_LEGACY, name


# ══════════════════════════════════════════════════════════════════════════
# 2. Each provider, armed alone, routes only itself to V2
# ══════════════════════════════════════════════════════════════════════════

def test_2_forticlient_enabled_routes_only_forticlient(arm):
    arm(FortiClient=True)
    assert routes() == {FORTI: ROUTE_FORTICLIENT_V2, STORM: ROUTE_LEGACY,
                        BARR: ROUTE_LEGACY}


def test_3_stormshield_enabled_routes_only_stormshield(arm):
    arm(Stormshield=True)
    assert routes() == {FORTI: ROUTE_LEGACY, STORM: ROUTE_STORMSHIELD_V2,
                        BARR: ROUTE_LEGACY}


def test_4_barracuda_enabled_routes_only_barracuda(arm):
    arm(Barracuda=True)
    assert routes() == {FORTI: ROUTE_LEGACY, STORM: ROUTE_LEGACY,
                        BARR: ROUTE_BARRACUDA_V2}


# ══════════════════════════════════════════════════════════════════════════
# 3. One flag never leaks to another provider
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("armed,other", [
    (FORTI, STORM), (FORTI, BARR), (STORM, FORTI), (STORM, BARR),
    (BARR, FORTI), (BARR, STORM),
])
def test_5_one_provider_enabled_does_not_activate_another(arm, armed, other):
    arm(**{armed: True})
    assert select_connect_route(armed) == V2_ROUTE[armed]
    assert select_connect_route(other) == ROUTE_LEGACY


# ══════════════════════════════════════════════════════════════════════════
# 4. Non-V2 providers are always legacy, in every combination
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("flags", [
    {}, {FORTI: True}, {STORM: True}, {BARR: True},
    {FORTI: True, STORM: True, BARR: True},
])
def test_6_the_other_providers_stay_legacy_whatever_is_armed(arm, flags):
    arm(**flags)
    for name in NON_V2:
        assert select_connect_route(name) == ROUTE_LEGACY, (name, flags)


# ══════════════════════════════════════════════════════════════════════════
# 5. Fail-closed: unknown, missing implementation, resolution error
# ══════════════════════════════════════════════════════════════════════════

def test_7_unknown_provider_is_legacy():
    for name in ("", "Nope", "forticlient", "FORTICLIENT", "FortiClient ",
                 "Barracuda Network Access"):
        assert select_connect_route(name) == ROUTE_LEGACY, name


def test_7b_exact_match_only_no_fuzzy_no_substring():
    # A substring of a real name must not resolve.
    for name in ("Forti", "Storm", "Barr", "Client", "SSL VPN"):
        assert select_connect_route(name) == ROUTE_LEGACY, name


def test_8_a_provider_without_a_v2_implementation_is_legacy():
    for name in ("GlobalProtect", "SonicWall NetExtender",
                 "Hillstone Secure Connect", "Windows VPN"):
        assert name not in V2_PROVIDERS
        assert select_connect_route(name) == ROUTE_LEGACY, name


def test_9_a_resolution_exception_is_legacy():
    class Hostile:
        def get(self, _name):
            raise RuntimeError("resolution padła")

    assert select_connect_route(FORTI, providers=Hostile()) == ROUTE_LEGACY


def test_9b_an_unhashable_name_is_legacy():
    assert select_connect_route(["FortiClient"]) == ROUTE_LEGACY


def test_9c_a_provider_class_that_raises_on_attribute_is_legacy():
    class Broken:
        legacy_name = "Broken"
        id = "broken"

        def __getattribute__(self, name):
            if name == "CONNECT_ENABLED":
                raise RuntimeError("flag padła")
            return object.__getattribute__(self, name)

    assert select_connect_route("Broken", providers={"Broken": Broken()}) \
        == ROUTE_LEGACY


# ══════════════════════════════════════════════════════════════════════════
# 6. Only a literal True arms a provider
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("value", [1, "True", "yes", "1", object(), None, False,
                                   1.0])
def test_10_only_literal_true_opens_the_gate(arm, monkeypatch, value):
    monkeypatch.setattr(FortiClientProvider, "CONNECT_ENABLED", value)
    monkeypatch.setattr(StormshieldProvider, "CONNECT_ENABLED", False)
    monkeypatch.setattr(BarracudaProvider, "CONNECT_ENABLED", False)
    assert select_connect_route(FORTI) == ROUTE_LEGACY


def test_10b_literal_true_does_open_it(monkeypatch):
    monkeypatch.setattr(FortiClientProvider, "CONNECT_ENABLED", True)
    assert select_connect_route(FORTI) == ROUTE_FORTICLIENT_V2


# ══════════════════════════════════════════════════════════════════════════
# 7. The full matrix
# ══════════════════════════════════════════════════════════════════════════

def _cell(name, route):
    return "V2" if route == V2_ROUTE[name] else ("L" if route == ROUTE_LEGACY
                                                 else "?")


MATRIX = [
    # (forti, storm, barr) -> expected cells (F, S, B)
    ((False, False, False), ("L", "L", "L")),
    ((True, False, False), ("V2", "L", "L")),
    ((False, True, False), ("L", "V2", "L")),
    ((False, False, True), ("L", "L", "V2")),
    ((True, True, False), ("V2", "V2", "L")),
    ((True, False, True), ("V2", "L", "V2")),
    ((False, True, True), ("L", "V2", "V2")),
    ((True, True, True), ("V2", "V2", "V2")),
]


@pytest.mark.parametrize("flags,expected", MATRIX)
def test_11_the_full_route_matrix(arm, flags, expected):
    arm(**dict(zip(V2_NAMES, flags)))
    cells = tuple(_cell(name, select_connect_route(name)) for name in V2_NAMES)
    assert cells == expected, (flags, cells)
    # …and every non-V2 provider stays legacy in this row.
    for name in NON_V2:
        assert select_connect_route(name) == ROUTE_LEGACY, (name, flags)


# ══════════════════════════════════════════════════════════════════════════
# 8. Rollback: True → V2 → False → legacy, per provider, independently
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("armed", V2_NAMES)
def test_12_rollback_per_provider(monkeypatch, armed):
    classes = {FORTI: FortiClientProvider, STORM: StormshieldProvider,
               BARR: BarracudaProvider}
    others = [n for n in V2_NAMES if n != armed]

    # off → legacy
    assert select_connect_route(armed) == ROUTE_LEGACY
    # on → V2
    monkeypatch.setattr(classes[armed], "CONNECT_ENABLED", True)
    assert select_connect_route(armed) == V2_ROUTE[armed]
    for other in others:
        assert select_connect_route(other) == ROUTE_LEGACY, other
    # rollback off → legacy, others never moved
    monkeypatch.setattr(classes[armed], "CONNECT_ENABLED", False)
    assert select_connect_route(armed) == ROUTE_LEGACY
    for other in others:
        assert select_connect_route(other) == ROUTE_LEGACY, other


# ══════════════════════════════════════════════════════════════════════════
# 9. Registration ≠ cutover; importing a class does not arm anything
# ══════════════════════════════════════════════════════════════════════════

def test_13_the_map_is_not_the_registry_and_registry_is_unchanged():
    assert vpn.default_registry.ids() == ["forticlient"]
    # The map has all three implementations; the registry has only the cutover
    # set.  They are deliberately different objects with different meanings.
    assert set(V2_PROVIDERS) == {FORTI, STORM, BARR}
    assert "stormshield" not in vpn.default_registry.ids()
    assert "barracuda" not in vpn.default_registry.ids()


def test_14_membership_in_the_map_does_not_enable_a_provider():
    """Every mapped class exists (was imported); all still route legacy."""
    for name, cls in V2_PROVIDERS.items():
        assert cls.CONNECT_ENABLED is False
        assert select_connect_route(name) == ROUTE_LEGACY, name


def test_15_the_gate_does_not_consult_the_default_registry():
    """No default_registry lookup in the resolution — it is not an enablement
    signal."""
    src = open(pb.__file__, encoding="utf-8").read()
    fn = src[src.index("def select_connect_route"):src.index("def build_request")]
    assert "default_registry" not in fn
    assert "V2_PROVIDERS" in fn or "providers" in fn


# ══════════════════════════════════════════════════════════════════════════
# 10. Production is still legacy end to end
# ══════════════════════════════════════════════════════════════════════════

def test_16_connect_card_dispatches_by_route_and_keeps_the_legacy_call():
    """Stage 52: the panel now selects a route and wires V2, but the legacy
    call is still there for the (currently universal) legacy route."""
    panel = open(os.path.join(_PARENT, "ui", "vpn_panel.py"), encoding="utf-8").read()
    assert "vpn_connect.connect_monitored(" in panel        # legacy path intact
    assert "select_connect_route(" in panel                 # route decision
    tree = ast.parse(panel)
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    for token in ("select_connect_route", "PanelConnectSession",
                  "V2ConnectController"):
        assert token in names, token


def test_17_all_three_flags_are_false_in_source_not_just_at_runtime():
    for module, cls in (("forticlient", "FortiClientProvider"),
                        ("stormshield", "StormshieldProvider"),
                        ("barracuda", "BarracudaProvider")):
        src = open(os.path.join(_PARENT, "vpn", "providers", f"{module}.py"),
                   encoding="utf-8").read()
        assert "CONNECT_ENABLED = False" in src, module
