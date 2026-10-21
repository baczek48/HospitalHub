"""2026-10-21: a Forti tunnel HospitalHub did not connect is still recognised.

Owner: "I'm connected to Forti, I start HospitalHub — it doesn't notice".
HospitalHub remembers which profile it connected (_last_connected); a tunnel
that was up before it started has no such record, and then only the
profile's own server could tell the profiles apart — the Forti profiles have
none, so every one read 'Disconnected'.  Now the server FortiClient itself
has configured for the tunnel the profile names (registry) is compared with
the address the Forti daemon is connected to.

No FortiClient, registry, DNS or netstat is touched: all are faked.
"""

import os
import sys
import socket

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import vpn_connect as vc  # noqa: E402

TUNNELS = [
    {"name": "Betanin", "server": "198.51.100.25", "port": "4443"},
    {"name": "1SZP", "server": "vpn2.szpital-x.example", "port": "4433"},
    {"name": "Bez serwera", "server": "", "port": ""},
]
DNS = {"vpn2.szpital-x.example": ["91.0.0.10", "91.0.0.11"],
       "198.51.100.25": ["198.51.100.25"]}


@pytest.fixture
def forti(monkeypatch):
    state = {"adapter": True, "ip": "198.51.100.25", "registry_reads": 0}

    def registry():
        state["registry_reads"] += 1
        return [dict(t) for t in TUNNELS]

    def getaddrinfo(host, *a, **k):
        if host not in DNS:
            raise socket.gaierror("no such host")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0))
                for ip in DNS[host]]

    monkeypatch.setattr(vc, "_is_fortivpn_cli_supported", lambda *a: False)
    monkeypatch.setattr(vc, "_is_forti_tunnel_active", lambda: state["adapter"])
    monkeypatch.setattr(vc, "_get_vpn_connected_server_ip",
                        lambda name: state["ip"])
    monkeypatch.setattr(vc, "_get_status_from_log", lambda: None)
    monkeypatch.setattr(vc, "is_forticlient_installed", lambda: True)
    monkeypatch.setattr(vc, "get_forti_tunnels_from_registry", registry)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(vc, "_last_connected", {})
    monkeypatch.setattr(vc, "_server_ip_cache", {})
    monkeypatch.setattr(vc, "_dns_cache", {})
    monkeypatch.setattr(vc, "_dns_inflight", set())
    monkeypatch.setattr(vc, "_forti_registry_cache", (0.0, []))
    monkeypatch.setattr(vc, "_connected_ip_cache", {})
    monkeypatch.setattr(vc, "_CONNECTED_IP_TTL_S", 0.0)
    # The lookups run in a background thread; here they finish at once.
    monkeypatch.setattr(vc.threading, "Thread", ImmediateThread)
    return state


class ImmediateThread:
    def __init__(self, target=None, name=None, daemon=None):
        self._target = target

    def start(self):
        self._target()


def status(profile, server=""):
    return vc.get_status("FortiClient", "", profile, server)


def test_a_tunnel_up_before_start_is_recognised_by_its_forticlient_server(forti):
    assert status("Betanin") == "Connected"
    assert status("1SZP") == "Disconnected"
    assert status("Bez serwera") == "Disconnected"
    assert status("Nieznany") == "Disconnected"
    assert status("") == "Disconnected"


def test_a_hostname_with_several_addresses_matches_any_of_them(forti):
    forti["ip"] = "91.0.0.11"
    assert status("1SZP") == "Connected"
    assert status("Betanin") == "Disconnected"


def test_without_the_adapter_the_daemon_connection_is_enough(forti):
    forti["adapter"] = False                # EMS/ZTNA: no named adapter
    assert status("Betanin") == "Connected"
    assert status("1SZP") == "Disconnected"


def test_no_tunnel_no_connected(forti):
    forti["ip"] = None
    assert status("Betanin") == "Disconnected"
    forti["adapter"] = False
    assert status("Betanin") == "Disconnected"


def test_the_profiles_own_server_still_decides_when_it_has_one(forti):
    assert status("Inna nazwa", server="198.51.100.25:4443") == "Connected"
    assert status("Betanin", server="10.9.9.9") == "Disconnected"


def test_a_tunnel_this_hospitalhub_connected_is_still_decided_by_the_record(forti):
    vc._last_connected["FortiClient"] = "1SZP"
    assert status("1SZP") == "Connected"
    assert status("Betanin") == "Disconnected"


def test_the_registry_is_read_once_a_minute_not_on_every_poll(forti, monkeypatch):
    clock = [1000.0]
    monkeypatch.setattr(vc.time, "monotonic", lambda: clock[0])
    for _ in range(5):
        status("Betanin")
    assert forti["registry_reads"] == 1
    clock[0] += vc._FORTI_TUNNEL_IP_TTL_S + 1
    status("Betanin")
    assert forti["registry_reads"] == 2


def test_a_server_with_a_port_and_a_list_of_hosts(forti, monkeypatch):
    monkeypatch.setattr(vc, "get_forti_tunnels_from_registry", lambda: [
        {"name": "Dwa", "server": "vpn2.szpital-x.example:4433;198.51.100.25", "port": ""}])
    assert status("Dwa") == "Connected"


# ══════════════════════════════════════════════════════════════════════════
# Every provider: the only profile of a provider gets an unpinned tunnel
# ══════════════════════════════════════════════════════════════════════════

def test_forti_unpinned_tunnel_is_up_unless_forticlient_says_it_is_anothers(forti):
    forti["ip"] = "203.0.113.5"            # a server no tunnel has (e.g. IPsec)
    assert vc.unpinned_tunnel_up("FortiClient", "ALFA IPsec") is True
    forti["ip"] = "198.51.100.25"          # FortiClient's own Betanin
    assert vc.unpinned_tunnel_up("FortiClient", "1SZP") is False
    assert vc.unpinned_tunnel_up("FortiClient", "Betanin") is True
    vc._last_connected["FortiClient"] = "1SZP"   # HospitalHub knows whose
    assert vc.unpinned_tunnel_up("FortiClient", "Betanin") is False


def test_forti_no_tunnel_nothing_unpinned(forti):
    forti["ip"] = None
    forti["adapter"] = False
    assert vc.unpinned_tunnel_up("FortiClient", "Betanin") is False


def test_stormshield_unpinned_tunnel(monkeypatch):
    adapters = {"stormshield-tap": "Connected"}
    monkeypatch.setattr(vc, "_check_adapter_status",
                        lambda *names: adapters.get(names[0]))
    monkeypatch.setattr(vc, "_last_connected", {})
    monkeypatch.setattr(vc, "_last_connected_meta", {})
    assert vc.get_status("Stormshield", "", "Lasowo", "") is None, \
        "bez rekordu legacy nie wie, czyj to tunel"
    assert vc.unpinned_tunnel_up("Stormshield", "Lasowo") is True
    vc._last_connected["Stormshield"] = "Inny"
    assert vc.unpinned_tunnel_up("Stormshield", "Lasowo") is False
    vc._last_connected.clear()
    adapters["stormshield-tap"] = "Disconnected"
    assert vc.unpinned_tunnel_up("Stormshield", "Lasowo") is False


def test_other_providers_never_report_an_unpinned_tunnel():
    for provider in ("Barracuda", "SonicWall NetExtender", "Hillstone Secure Connect",
                     "GlobalProtect", "Windows VPN", "AnyDesk"):
        assert vc.unpinned_tunnel_up(provider, "x") is False


def test_vpn_status_gives_the_tunnel_to_the_sole_profile_only(monkeypatch):
    from types import SimpleNamespace
    from ui import vpn_panel as vp
    monkeypatch.setattr(vp.vpn_connect, "get_status", lambda *a: None)
    monkeypatch.setattr(vp.vpn_connect, "unpinned_tunnel_up", lambda p, n: True)
    assert vp.vpn_status("Stormshield", "", "Lasowo", "", sole=True) == "Connected"
    assert vp.vpn_status("Stormshield", "", "Lasowo", "", sole=False) is None
    monkeypatch.setattr(vp.vpn_connect, "unpinned_tunnel_up", lambda p, n: False)
    assert vp.vpn_status("Stormshield", "", "Lasowo", "", sole=True) is None

    P = lambda provider: SimpleNamespace(provider=provider)  # noqa: E731
    assert vp.sole_providers([P("FortiClient"), P("FortiClient"), P("Stormshield"),
                              P("Barracuda")]) == {"Stormshield", "Barracuda"}


def test_the_status_worker_passes_sole_per_provider(monkeypatch):
    from types import SimpleNamespace
    from ui import vpn_panel as vp
    seen = {}

    def fake_status(provider, app_path, profile_name, server, sole=False):
        seen[profile_name] = sole
        return "Disconnected"
    monkeypatch.setattr(vp, "vpn_status", fake_status)
    profiles = [SimpleNamespace(provider=pr, app_path="", profile_name=n, server="")
                for pr, n in (("FortiClient", "Betanin"), ("FortiClient", "1SZP"),
                              ("Stormshield", "Lasowo"))]
    vp.StatusWorker(profiles).run()
    assert seen == {"Betanin": False, "1SZP": False, "Lasowo": True}


# ══════════════════════════════════════════════════════════════════════════
# 2026-10-21: a status check never waits for DNS
# ══════════════════════════════════════════════════════════════════════════

def test_a_slow_lookup_does_not_hold_the_status(monkeypatch):
    """A lookup that has not answered yet: the status is given at once
    (not yet the tunnel's), and the next check, after the answer, is."""
    import threading
    monkeypatch.setattr(vc, "_dns_cache", {})
    monkeypatch.setattr(vc, "_dns_inflight", set())
    monkeypatch.setattr(vc, "_forti_registry_cache", (0.0, []))
    monkeypatch.setattr(vc, "_connected_ip_cache", {})
    monkeypatch.setattr(vc, "_last_connected", {})
    monkeypatch.setattr(vc, "_is_fortivpn_cli_supported", lambda *a: False)
    monkeypatch.setattr(vc, "_is_forti_tunnel_active", lambda: True)
    monkeypatch.setattr(vc, "_get_vpn_connected_server_ip", lambda n: "91.0.0.10")
    monkeypatch.setattr(vc, "get_forti_tunnels_from_registry", lambda: [
        {"name": "1SZP", "server": "vpn2.szpital-x.example", "port": "4433"}])
    release = threading.Event()

    def slow_dns(host, *a, **k):
        release.wait(5)
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("91.0.0.10", 0))]
    monkeypatch.setattr(socket, "getaddrinfo", slow_dns)

    import time
    started = time.monotonic()
    assert status("1SZP") == "Disconnected"
    assert time.monotonic() - started < 1.0, "status nie czeka na DNS"
    assert vc.dns_pending()
    release.set()
    end = time.monotonic() + 3
    while vc.dns_pending() and time.monotonic() < end:
        time.sleep(0.01)
    assert status("1SZP") == "Connected"


def test_an_ip_needs_no_lookup(monkeypatch):
    monkeypatch.setattr(vc, "_dns_cache", {})
    monkeypatch.setattr(vc, "_dns_inflight", set())
    assert vc._resolve_nowait("198.51.100.25") == frozenset(["198.51.100.25"])
    assert not vc.dns_pending()


def test_one_netstat_per_pass_not_per_profile(forti, monkeypatch):
    calls = []
    monkeypatch.setattr(vc, "_CONNECTED_IP_TTL_S", 2.0)
    monkeypatch.setattr(vc, "_get_vpn_connected_server_ip",
                        lambda n: calls.append(n) or "198.51.100.25")
    for name in ("Betanin", "1SZP", "DKA", "WIA", "ZLA"):
        status(name)
    assert len(calls) == 1
