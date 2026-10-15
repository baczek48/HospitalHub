"""Tests for the VPN provider architecture (contract only — nothing is wired).

The providers here are fakes built for the tests. Their job is to prove that
the contract can express the shapes the real code has: a client that can do
almost everything (FortiClient), one that can only be launched (SonicWall),
one that Windows connects for us, and one that is simply broken.

The regression test that matters most in this file is
`test_production_path_is_not_rewired`: the running application must still go
through `vpn_connect` exactly as before.
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
import vpn_connect  # noqa: E402
from vpn import (  # noqa: E402
    AutomationMode, Capability, ConnectResult, DetectionResult, DetectionState,
    DisconnectResult, DuplicateProviderIdError, ErrorCode, LaunchResult,
    LegacyVpnProviderAdapter, SecretInResultError, StatusResult, StatusSource,
    UnknownProviderError, VpnProvider, VpnRegistry, VpnRequest, VpnState,
    check_contract,
)

FAKE_PASSWORD = "SuperSecret123"
FAKE_TOKEN = "ABC123"


# ── fake providers ────────────────────────────────────────────────────────

class FullProvider(VpnProvider):
    """Shape of a client that can do nearly everything (cf. FortiClient)."""

    id = "fake_full"
    display_name = "Fake Full Client"
    legacy_name = "FakeFull"

    def capabilities(self):
        return (Capability.LAUNCH | Capability.AUTOFILL | Capability.TWO_FACTOR
                | Capability.STATUS | Capability.AUTO_DISCONNECT
                | Capability.CREDENTIAL_COPY)

    def detect(self, request):
        return DetectionResult(provider_id=self.id, success=True,
                               state=DetectionState.INSTALLED, version="7.4.1",
                               source="registry", path=r"C:\ProgramFiles\fake.exe")

    def launch(self, request):
        return LaunchResult(provider_id=self.id, success=True,
                            strategy="popen_clean_env", started=True, pid=4242)

    def connect(self, request):
        return ConnectResult(provider_id=self.id, success=True,
                             state=VpnState.CONNECTING,
                             automation=AutomationMode.TAB_SEQUENCE)

    def disconnect(self, request):
        return DisconnectResult(provider_id=self.id, success=True,
                                method="gui_auto_click",
                                automation=AutomationMode.TAB_SEQUENCE)

    def status(self, request):
        return StatusResult(provider_id=self.id, success=True,
                            state=VpnState.CONNECTED,
                            source=StatusSource.ADAPTER)


class LaunchOnlyProvider(VpnProvider):
    """Shape of a client we can only start (cf. SonicWall, Hillstone)."""

    id = "fake_launch_only"
    display_name = "Fake Launch Only"

    def capabilities(self):
        return Capability.LAUNCH | Capability.MANUAL_AUTH | Capability.STATUS

    def detect(self, request):
        return DetectionResult(provider_id=self.id, success=bool(request.app_path),
                               state=DetectionState.INSTALLED if request.app_path
                               else DetectionState.NOT_INSTALLED,
                               error_code=None if request.app_path
                               else ErrorCode.CLIENT_NOT_FOUND.value)

    def connect(self, request):
        return ConnectResult(provider_id=self.id, success=True,
                             state=VpnState.UNKNOWN,
                             automation=AutomationMode.MANUAL,
                             requires_user_action=True)

    def status(self, request):
        return StatusResult(provider_id=self.id, success=True,
                            state=VpnState.DISCONNECTED,
                            source=StatusSource.ADAPTER)


class SystemProvider(VpnProvider):
    """Shape of Windows VPN: the OS connects, we do not touch credentials."""

    id = "fake_system"
    display_name = "Fake System VPN"

    def capabilities(self):
        return Capability.SYSTEM_CONNECT | Capability.CLI_DISCONNECT

    def detect(self, request):
        return DetectionResult(provider_id=self.id, success=True,
                               state=DetectionState.INSTALLED, source="system")

    def connect(self, request):
        return ConnectResult(provider_id=self.id, success=True,
                             state=VpnState.CONNECTING,
                             automation=AutomationMode.SYSTEM)

    def disconnect(self, request):
        return DisconnectResult(provider_id=self.id, success=True,
                                method="rasdial_disconnect",
                                automation=AutomationMode.SYSTEM)


class MinimalProvider(VpnProvider):
    """Declares nothing beyond detection — everything else must degrade."""

    id = "fake_minimal"
    display_name = "Fake Minimal"

    def capabilities(self):
        return Capability.NONE

    def detect(self, request):
        return DetectionResult(provider_id=self.id, state=DetectionState.NOT_INSTALLED,
                               error_code=ErrorCode.CLIENT_NOT_FOUND.value)


def request(**kwargs):
    kwargs.setdefault("provider_id", "fake_full")
    return VpnRequest(**kwargs)


# ══════════════════════════════════════════════════════════════════════════
# 1. Contract
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("provider_cls", [FullProvider, LaunchOnlyProvider,
                                          SystemProvider, MinimalProvider])
def test_fake_providers_satisfy_the_contract(provider_cls):
    assert check_contract(provider_cls()) == []


def test_contract_requires_capabilities_and_detect():
    class Incomplete(VpnProvider):
        id = "incomplete"
        display_name = "Incomplete"

    with pytest.raises(TypeError):
        Incomplete()          # abstract methods missing


def test_contract_check_reports_inconsistent_declarations():
    class Liar(VpnProvider):
        id = "liar"
        display_name = "Liar"

        def capabilities(self):
            return Capability.STATUS | Capability.CLI_CONNECT

        def detect(self, request):
            return DetectionResult(provider_id=self.id)

    problems = check_contract(Liar())
    assert any("status()" in p for p in problems)
    assert any("connect()" in p for p in problems)


def test_contract_accepts_launch_implemented_by_launch_alone():
    """A migrated launcher (FortiClient, stage 8) needs no connect()."""
    class Launcher(MinimalProvider):
        id = "fake_launcher"

        def capabilities(self):
            return Capability.LAUNCH

        def launch(self, request):
            return LaunchResult(provider_id=self.id, success=True)

    assert check_contract(Launcher()) == []


def test_contract_rejects_launch_without_launch_or_connect():
    class Boaster(MinimalProvider):
        id = "fake_boaster"

        def capabilities(self):
            return Capability.LAUNCH

    assert any("LAUNCH" in p for p in check_contract(Boaster()))


def test_contract_check_rejects_bad_id():
    class BadId(MinimalProvider):
        id = "Fake Provider"

    assert any("id" in p for p in check_contract(BadId()))


def test_unimplemented_operations_degrade_to_unsupported():
    provider = MinimalProvider()
    for result in (provider.launch(request()), provider.connect(request()),
                   provider.disconnect(request()), provider.status(request())):
        assert result.ok is False
        assert result.error_code == ErrorCode.UNSUPPORTED.value
    assert provider.status(request()).state is VpnState.UNKNOWN


def test_provider_repr_never_leaks_a_request():
    assert repr(FullProvider()) == "<FullProvider id='fake_full'>"


# ══════════════════════════════════════════════════════════════════════════
# 2. Capability model
# ══════════════════════════════════════════════════════════════════════════

def test_capabilities_combine_and_report_names():
    caps = Capability.LAUNCH | Capability.STATUS
    assert Capability.LAUNCH in caps
    assert Capability.AUTOFILL not in caps
    assert caps.names() == ["launch", "status"]
    assert Capability.NONE.names() == []


def test_supports_helper():
    provider = LaunchOnlyProvider()
    assert provider.supports(Capability.LAUNCH)
    assert not provider.supports(Capability.TWO_FACTOR)


def test_automation_mode_follows_capabilities():
    assert FullProvider().automation_mode is AutomationMode.TAB_SEQUENCE
    assert SystemProvider().automation_mode is AutomationMode.SYSTEM
    assert LaunchOnlyProvider().automation_mode is AutomationMode.MANUAL


def test_catalog_covers_every_builtin_provider():
    """A provider added to models must get a capability declaration."""
    declared = {spec.legacy_name for spec in vpn.SPECS if spec.legacy_name}
    assert declared == set(models.VPN_PROVIDERS_BUILTIN)


def test_catalog_matches_the_real_code():
    """Spot-checks against what vpn_connect actually does today."""
    forti = vpn.spec_for_legacy_name("FortiClient")
    assert forti.supports(Capability.AUTOFILL)
    assert forti.supports(Capability.TWO_FACTOR)
    assert forti.supports(Capability.PROFILE_IMPORT)

    # GlobalProtect has no autofill: _autofill_globalprotect is never called.
    gp = vpn.spec_for_legacy_name("GlobalProtect")
    assert not gp.supports(Capability.AUTOFILL)
    assert gp.automation is AutomationMode.MANUAL

    # SonicWall: launch + manual only; its CLI machinery is dead code.
    sonic = vpn.spec_for_legacy_name("SonicWall NetExtender")
    assert sonic.supports(Capability.LAUNCH)
    assert not sonic.supports(Capability.CLI_CONNECT)
    assert not sonic.supports(Capability.AUTOFILL)

    # Windows VPN reports no status at all — get_status returns None for it.
    win = vpn.spec_for_legacy_name("Windows VPN")
    assert win.supports(Capability.SYSTEM_CONNECT)
    assert win.status_sources == ()

    # Stormshield and Barracuda have no known install paths.
    assert _PATHS_EMPTY("Stormshield") and _PATHS_EMPTY("Barracuda")
    assert any("app_path" in c for c in vpn.BY_ID["stormshield"].caveats)


def _PATHS_EMPTY(name):
    return vpn_connect._PATHS.get(name) == []


def test_every_spec_documents_its_evidence():
    for spec in vpn.SPECS:
        assert spec.evidence, f"{spec.id}: brak wskazania miejsca w kodzie"


def test_providers_with_filters_by_capability():
    autofill = {spec.id for spec in vpn.providers_with(Capability.AUTOFILL)}
    assert autofill == {"forticlient", "stormshield", "barracuda"}


# ══════════════════════════════════════════════════════════════════════════
# 3-5. Result types
# ══════════════════════════════════════════════════════════════════════════

def test_detection_result_states():
    installed = DetectionResult(provider_id="x", success=True,
                                state=DetectionState.INSTALLED)
    incomplete = DetectionResult(provider_id="x", state=DetectionState.INCOMPLETE,
                                 error_code=ErrorCode.NO_CONFIGURATION.value)
    missing = DetectionResult(provider_id="x", state=DetectionState.NOT_INSTALLED,
                              error_code=ErrorCode.CLIENT_NOT_FOUND.value)
    failed = DetectionResult(provider_id="x", state=DetectionState.ERROR,
                             error_code=ErrorCode.PYWIN32_MISSING.value)

    assert installed.installed and incomplete.installed
    assert not missing.installed and not failed.installed
    assert missing.to_trace_data()["state"] == "not_installed"


def test_connect_result_carries_machine_data_only():
    result = ConnectResult(provider_id="forticlient", success=True,
                           state=VpnState.CONNECTING,
                           automation=AutomationMode.TAB_SEQUENCE,
                           monitor=object())
    data = result.to_trace_data()
    assert data["state"] == "connecting"
    assert data["automation_mode"] == "tab_sequence"
    assert data["process_monitor"] is True
    assert "monitor" not in data, "uchwyt procesu nie jest danymi"
    assert result.ok


def test_status_result_and_legacy_mapping():
    result = StatusResult(provider_id="x", success=True, state=VpnState.CONNECTED,
                          source=StatusSource.NETSTAT)
    assert result.connected
    assert result.to_trace_data() == {"state": "connected", "source": "netstat"}

    assert VpnState.from_legacy("Connected") is VpnState.CONNECTED
    assert VpnState.from_legacy("Connecting") is VpnState.CONNECTING
    assert VpnState.from_legacy(None) is VpnState.UNKNOWN
    assert VpnState.from_legacy("cokolwiek") is VpnState.UNKNOWN
    assert VpnState.CONNECTED.to_legacy() == "Connected"
    assert VpnState.UNKNOWN.to_legacy() is None


def test_launch_and_disconnect_results():
    launch = LaunchResult(provider_id="x", success=True, strategy="explorer_lnk",
                          started=False, fallback=True,
                          error_code=ErrorCode.LAUNCH_NO_PROCESS.value)
    assert launch.to_trace_data() == {"strategy": "explorer_lnk",
                                      "started": False, "fallback": True}
    disc = DisconnectResult(provider_id="x", success=True, method="manual",
                            automation=AutomationMode.MANUAL)
    assert disc.to_trace_data()["method"] == "manual"


def test_results_are_immutable():
    result = StatusResult(provider_id="x", state=VpnState.CONNECTED)
    with pytest.raises(Exception):
        result.state = VpnState.DISCONNECTED


def test_unsupported_helper():
    result = vpn.unsupported("x", StatusResult)
    assert isinstance(result, StatusResult)
    assert result.error_code == ErrorCode.UNSUPPORTED.value


# ══════════════════════════════════════════════════════════════════════════
# 6-7. Error codes and status sources
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("name,value", [
    ("CLIENT_NOT_FOUND", "client-not-found"),
    ("LAUNCH_FAILED", "launch-failed"),
    ("WINDOW_NOT_FOUND", "window-not-found"),
    ("AUTOMATION_TIMEOUT", "automation-timeout"),
    ("CONNECT_TIMEOUT", "connect-timeout"),
    ("DISCONNECT_FAILED", "disconnect-failed"),
    ("STATUS_UNKNOWN", "status-unknown"),
    ("UNSUPPORTED", "unsupported"),
    ("MANUAL_ACTION_REQUIRED", "manual-action-required"),
])
def test_error_codes_are_stable(name, value):
    assert getattr(ErrorCode, name).value == value
    assert str(getattr(ErrorCode, name)) == value


def test_error_codes_used_by_the_instrumentation_exist_in_the_enum():
    """Codes already written to traces must be part of the shared vocabulary."""
    source = open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read()
    tree = ast.parse(source)
    emitted = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.keyword) and node.arg == "error_code":
            if isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                emitted.add(node.value.value)
    known = {code.value for code in ErrorCode}
    assert emitted, "instrumentacja nie emituje żadnych kodów?"
    assert emitted <= known, f"kody spoza słownika: {sorted(emitted - known)}"


@pytest.mark.parametrize("source,value", [
    (StatusSource.ADAPTER, "adapter"), (StatusSource.CLI, "cli"),
    (StatusSource.LOG, "log"), (StatusSource.NETSTAT, "netstat"),
    (StatusSource.SYSTEM, "system"), (StatusSource.UNKNOWN, "unknown"),
])
def test_status_sources(source, value):
    assert source.value == value


def test_status_sources_cover_what_the_code_marks():
    """Every `_trace_source(...)` marker must map onto a StatusSource."""
    source = open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read()
    tree = ast.parse(source)
    marked = set()
    for node in ast.walk(tree):
        if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                and node.func.id == "_trace_source" and node.args
                and isinstance(node.args[0], ast.Constant)):
            marked.add(node.args[0].value)
    known = {s.value for s in StatusSource}
    assert marked and marked <= known, f"nieznane źródła: {sorted(marked - known)}"


# ══════════════════════════════════════════════════════════════════════════
# 8-11. Registry
# ══════════════════════════════════════════════════════════════════════════

def test_registry_registers_and_finds():
    registry = VpnRegistry()
    provider = FullProvider()
    registry.register(provider)
    assert registry.get("fake_full") is provider
    assert registry.require("fake_full") is provider
    assert registry.ids() == ["fake_full"]
    assert "fake_full" in registry and len(registry) == 1


def test_registry_rejects_duplicate_id():
    registry = VpnRegistry([FullProvider()])
    with pytest.raises(DuplicateProviderIdError) as excinfo:
        registry.register(FullProvider())
    assert "fake_full" in str(excinfo.value)
    assert len(registry) == 1


def test_registry_allows_explicit_replace():
    registry = VpnRegistry([FullProvider()])
    replacement = FullProvider()
    registry.register(replacement, replace=True)
    assert registry.get("fake_full") is replacement


def test_registry_missing_provider_is_safe_or_explicit():
    registry = VpnRegistry()
    assert registry.get("nie-ma") is None
    with pytest.raises(UnknownProviderError):
        registry.require("nie-ma")


def test_registry_rejects_provider_without_id():
    class NoId(MinimalProvider):
        id = ""

    with pytest.raises(ValueError):
        VpnRegistry().register(NoId())


def test_registry_finds_by_legacy_name():
    registry = VpnRegistry([FullProvider(), LaunchOnlyProvider()])
    assert registry.find_by_legacy_name("FakeFull").id == "fake_full"
    assert registry.find_by_legacy_name("FortiClient") is None


def test_registry_lists_sorted_and_is_iterable():
    registry = VpnRegistry([SystemProvider(), FullProvider()])
    assert [p.id for p in registry] == ["fake_full", "fake_system"]
    assert registry.ids() == ["fake_full", "fake_system"]


def test_default_registry_holds_only_the_builtin_providers():
    """Only providers whose migrated part proved parity may be registered.

    Stage 7 registered FortiClient (detection only); every other client must
    stay out until it is migrated deliberately.
    """
    assert vpn.default_registry.ids() == ["forticlient"]


# ══════════════════════════════════════════════════════════════════════════
# 12. Results must not carry secrets
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("key", ["password", "token", "otp", "secret",
                                 "private_key", "credential", "pin"])
def test_result_metadata_rejects_secret_keys(key):
    with pytest.raises(SecretInResultError):
        ConnectResult(provider_id="x", metadata={key: "cokolwiek"})


def test_result_metadata_rejects_secret_shaped_values():
    with pytest.raises(SecretInResultError):
        ConnectResult(provider_id="x",
                      metadata={"note": "-----BEGIN PRIVATE KEY-----MIIEv"})


def test_result_metadata_rejects_arbitrary_objects():
    with pytest.raises(SecretInResultError):
        ConnectResult(provider_id="x", metadata={"note": object()})


def test_result_metadata_accepts_safe_values():
    result = ConnectResult(provider_id="x", metadata={"strategy": "cli",
                                                      "attempt": 2,
                                                      "fallback": True})
    assert result.to_trace_data()["attempt"] == 2


def test_request_repr_hides_credentials():
    req = VpnRequest(provider_id="forticlient", login="jkowalski",
                     password=FAKE_PASSWORD, token=FAKE_TOKEN)
    text = repr(req)
    assert FAKE_PASSWORD not in text and FAKE_TOKEN not in text
    assert "jkowalski" in text, "login jest potrzebny w debugowaniu, hasło nie"


def test_request_trace_meta_describes_without_revealing():
    req = VpnRequest(provider_id="forticlient", profile_name="SZPITAL-A",
                     server="vpn.szpital-a.pl", login="jkowalski",
                     password=FAKE_PASSWORD, token=FAKE_TOKEN)
    meta = req.to_trace_meta()
    assert meta["has_credentials"] is True
    assert meta["requires_2fa"] is True
    assert FAKE_PASSWORD not in str(meta) and FAKE_TOKEN not in str(meta)


# ══════════════════════════════════════════════════════════════════════════
# 13. Diagnostics compatibility
# ══════════════════════════════════════════════════════════════════════════

def test_provider_diagnostics_returns_safe_data():
    data = FullProvider().diagnostics(request())
    assert data["provider"] == "fake_full"
    assert "autofill" in data["capabilities"]
    assert data["app_version"] == "7.4.1"


def test_record_result_writes_into_an_existing_trace(tmp_path, monkeypatch):
    import diagnostics
    from diagnostics import vpn as vpn_diag

    monkeypatch.setenv(diagnostics.DIR_ENV_VAR, str(tmp_path / "diag"))
    diagnostics.reset_for_tests()
    try:
        trace = vpn_diag.start("vpn.connect", provider="fake_full")
        vpn.record_result(trace, "vpn.detect", FullProvider().detect(request()))
        vpn.record_result(trace, "vpn.connect", FullProvider().connect(request()))
        trace.finish("ok")

        text = diagnostics.get_store().read_jsonl()
        assert '"vpn.detect"' in text and '"tab_sequence"' in text
        assert '"app_version": "7.4.1"' in text
        # Written through the existing trace API, so the existing redactor ran:
        # a user-profile path would have come out masked, never raw.
        user = os.environ.get("USERNAME") or ""
        assert not user or user not in text
    finally:
        diagnostics.reset_for_tests()


def test_record_result_survives_a_broken_trace():
    class BrokenTrace:
        def step(self, *a, **k):
            raise RuntimeError("diagnostyka padła")

    vpn.record_result(BrokenTrace(), "vpn.detect", FullProvider().detect(request()))
    vpn.record_result(None, "vpn.detect", None)     # must not raise either


def test_providers_do_not_import_their_own_logging():
    """No second redactor, no second trace recorder inside vpn/."""
    for name in ("types.py", "provider.py", "registry.py", "catalog.py",
                 "__init__.py", "shadow.py",
                 os.path.join("providers", "__init__.py"),
                 os.path.join("providers", "forticlient.py"),
                 os.path.join("providers", "launch_system.py"),
                 os.path.join("providers", "forticlient_connect.py"),
                 os.path.join("providers", "secure_target.py")):
        source = open(os.path.join(_PARENT, "vpn", name), encoding="utf-8").read()
        assert "import logging" not in source, f"{name}: własny logging w warstwie VPN"
        assert "TraceRecorder(" not in source, f"{name}: własny TraceRecorder"


# ══════════════════════════════════════════════════════════════════════════
# Legacy bridge + THE regression test of this stage
# ══════════════════════════════════════════════════════════════════════════

class FakeLegacyModule:
    """Stands in for vpn_connect so the bridge can be tested without Windows."""

    def __init__(self):
        self.calls = []

    def connect_monitored(self, provider, server, port, login, password, group,
                          domain, app_path, profile_name, token, autofill):
        self.calls.append(("connect", provider, profile_name, autofill))
        return True, "Otwarto FortiClient — hasło w schowku.", "PROC"

    def disconnect(self, provider, server, app_path, profile_name):
        self.calls.append(("disconnect", provider, profile_name))
        return True, "Rozłączanie FortiClient..."

    def get_status(self, provider, app_path, profile_name, server):
        self.calls.append(("status", provider))
        return "Connected"


def test_legacy_adapter_delegates_and_translates():
    legacy = FakeLegacyModule()
    adapter = LegacyVpnProviderAdapter(
        "forticlient", "FortiClient", "FortiClient",
        Capability.LAUNCH | Capability.AUTOFILL | Capability.STATUS,
        legacy_module=legacy, automation=AutomationMode.TAB_SEQUENCE)

    req = VpnRequest(provider_id="forticlient", profile_name="SZPITAL-A",
                     login="jkowalski", password=FAKE_PASSWORD)
    result = adapter.connect(req)
    assert result.ok and result.state is VpnState.CONNECTING
    assert result.automation is AutomationMode.TAB_SEQUENCE
    assert result.monitor == "PROC"
    assert legacy.calls[0] == ("connect", "FortiClient", "SZPITAL-A", True)

    status = adapter.status(req)
    assert status.state is VpnState.CONNECTED

    disc = adapter.disconnect(req)
    assert disc.ok and disc.method == "legacy"


def test_legacy_adapter_keeps_ui_text_out_of_results():
    legacy = FakeLegacyModule()
    adapter = LegacyVpnProviderAdapter("forticlient", "FortiClient", "FortiClient",
                                       Capability.LAUNCH, legacy_module=legacy)
    result = adapter.connect(VpnRequest(provider_id="forticlient"))
    assert "Otwarto" not in str(result.to_trace_data())
    assert adapter.last_message.startswith("Otwarto")   # dostępne dla UI


def test_legacy_adapter_is_not_registered_anywhere():
    assert not any(isinstance(p, LegacyVpnProviderAdapter)
                   for p in vpn.default_registry)
    assert not isinstance(vpn.default_registry.get("forticlient"),
                          LegacyVpnProviderAdapter)


def test_production_path_is_not_rewired():
    """Stage 52: the panel wires V2 only through ``vpn.panel_bridge``.

    ``vpn_connect.py``, ``detail_panel.py`` and ``main.py`` must not import
    ``vpn`` at all; ``vpn_panel.py`` may import the one sanctioned abstraction
    ``vpn.panel_bridge`` and nothing deeper.  ``vpn_connect`` must not reference
    a registry or a provider class.
    """
    watched = [os.path.join(_PARENT, "vpn_connect.py"),
               os.path.join(_PARENT, "ui", "detail_panel.py"),
               os.path.join(_PARENT, "ui", "vpn_panel.py"),
               os.path.join(_PARENT, "main.py")]
    for path in watched:
        panel = os.path.basename(path) == "vpn_panel.py"
        tree = ast.parse(open(path, encoding="utf-8").read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            else:
                continue
            for name in names:
                if panel and name == "vpn.panel_bridge":
                    continue
                assert name != "vpn" and not name.startswith("vpn."), (
                    f"{os.path.basename(path)} importuje nową architekturę "
                    f"({name}) — tylko vpn_panel→vpn.panel_bridge jest dozwolone")
    source = open(watched[0], encoding="utf-8").read()
    for token in ("VpnRegistry", "VpnProvider", "default_registry"):
        assert token not in source, f"vpn_connect.py odwołuje się do {token}"
