"""Stage 7: FortiClient in the registry + shadow detection.

Two guarantees are tested here.

1. The registry knows FortiClient — once, by id and by legacy name — and
   nothing else.
2. Shadow detection compares legacy and migrated detection *without touching
   the production path*: it never raises, never launches, waits or polls, and
   the legacy answer it returns is exactly what the legacy functions said.

Machines are described with the fakes from the parity tests; the legacy
functions run for real against a patched `winreg`/`os` inside `vpn_connect`.
"""

import ast
import glob
import os
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import vpn  # noqa: E402
import vpn_connect  # noqa: E402
from vpn import (  # noqa: E402
    SPECS, DetectionResult, DetectionState, DuplicateProviderIdError,
    FortiClientProvider, LegacyFailure, VpnRegistry, VpnRequest,
    compare_detection, collect_legacy_detection, record_comparison,
    register_builtin_providers, shadow_detect_forticlient,
)
from vpn import shadow  # noqa: E402
from vpn.providers import forticlient as fc  # noqa: E402
from tests.test_vpn_forticlient_detect import (  # noqa: E402
    DIR_32, DIR_64, FA_FCM, FORTI_KEY, FORTIVPN_64, GUI_32, GUI_64, LNK,
    UNINSTALL, FakeEnvironment, FakeWinreg, _os_shim, legacy_detection,
)

FAKE_SECRETS = ("SuperSecret123", "ABC123", "123456", "-----BEGIN PRIVATE KEY-----")


def run_shadow(monkeypatch, legacy_env, new_env=None, app_path="", **kwargs):
    """Legacy sees `legacy_env`, the provider sees `new_env` (default: same)."""
    monkeypatch.setattr(vpn_connect, "winreg", FakeWinreg(legacy_env))
    monkeypatch.setattr(vpn_connect, "os", _os_shim(legacy_env))
    if "registry" in kwargs:            # an empty registry is falsy — no `or`
        registry = kwargs.pop("registry")
    else:
        registry = VpnRegistry(
            [FortiClientProvider(new_env if new_env is not None else legacy_env)])
    return shadow_detect_forticlient(app_path, registry=registry,
                                     legacy=vpn_connect, **kwargs)


def installed_machine(**extra):
    registry = {FORTI_KEY: {"INSTALLDIR": DIR_64}}
    registry.update(extra.pop("registry", {}))
    return FakeEnvironment(registry=registry,
                           files=[GUI_64, FORTIVPN_64, LNK] + extra.pop("files", []),
                           dirs=[DIR_64])


# ══════════════════════════════════════════════════════════════════════════
# 1–4. Registry
# ══════════════════════════════════════════════════════════════════════════

def test_1_forticlient_is_in_default_registry():
    assert "forticlient" in vpn.default_registry
    assert isinstance(vpn.default_registry.get("forticlient"), FortiClientProvider)


def test_2_lookup_by_id():
    provider = vpn.default_registry.require("forticlient")
    assert provider.id == "forticlient"
    assert vpn.default_registry.get("forticlient") is provider


def test_3_lookup_by_legacy_name_matches_existing_vault_value():
    import models
    provider = vpn.default_registry.find_by_legacy_name("FortiClient")
    assert provider is vpn.default_registry.get("forticlient")
    assert provider.legacy_name == "FortiClient"
    assert "FortiClient" in models.VPN_PROVIDERS_BUILTIN, (
        "legacy_name musi być dokładnie tym napisem, który zapisują vaulty")
    assert vpn.spec_for_legacy_name("FortiClient").id == provider.id


def test_4_no_duplicate_registration():
    before = vpn.default_registry.all()
    assert register_builtin_providers(vpn.default_registry) == [], "idempotentne"
    assert vpn.default_registry.all() == before
    assert len(vpn.default_registry) == 1

    with pytest.raises(DuplicateProviderIdError):
        vpn.default_registry.register(FortiClientProvider())


def test_4b_a_foreign_class_with_the_same_id_is_a_conflict():
    class Impostor(FortiClientProvider.__mro__[1]):     # plain VpnProvider
        id = "forticlient"

        def capabilities(self):
            return vpn.Capability.NONE

        def detect(self, request):
            return DetectionResult(provider_id=self.id)

    registry = VpnRegistry([Impostor()])
    with pytest.raises(DuplicateProviderIdError):
        register_builtin_providers(registry)


def test_4c_no_other_real_provider_is_registered():
    assert vpn.default_registry.ids() == ["forticlient"]
    for spec in SPECS:
        if spec.id != "forticlient":
            assert vpn.default_registry.get(spec.id) is None, spec.id
            assert vpn.default_registry.find_by_legacy_name(spec.legacy_name) is None


@pytest.mark.parametrize("entry", [
    "import vpn",
    "import vpn.shadow",
    "import vpn.registry",
    "import vpn.providers.forticlient",
    "from vpn.registry import default_registry",
    "from vpn.providers import FortiClientProvider",
])
def test_4d_every_import_route_gives_one_populated_registry(entry):
    """Deterministic init, no cycles, no double registration, no heavy imports."""
    code = (f"{entry}\nimport sys, vpn\n"
            "print(vpn.default_registry.ids(), "
            "'vpn_connect' in sys.modules, 'subprocess' in sys.modules)")
    out = subprocess.run([sys.executable, "-c", code], cwd=_PARENT,
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == "['forticlient'] False False", out.stdout


def test_4e_registration_happens_in_exactly_one_place():
    callers = []
    for path in glob.glob(os.path.join(_PARENT, "**", "*.py"), recursive=True):
        rel = os.path.relpath(path, _PARENT)
        if rel.startswith("tests") or "__pycache__" in rel:
            continue
        tree = ast.parse(open(path, encoding="utf-8").read())
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
                    and node.func.id == "register_builtin_providers"):
                callers.append(rel)
    assert callers == [os.path.join("vpn", "__init__.py")]


def test_4f_constructing_providers_touches_nothing():
    class Exploding(fc.DetectionEnvironment):
        def __getattribute__(self, name):
            raise AssertionError(f"rejestracja dotknęła środowiska: {name}")

    FortiClientProvider(Exploding())                    # no I/O in __init__
    registry = VpnRegistry()
    register_builtin_providers(registry)                # WindowsEnvironment()
    assert registry.ids() == ["forticlient"]


# ══════════════════════════════════════════════════════════════════════════
# 5. Agreement
# ══════════════════════════════════════════════════════════════════════════

def test_5_shadow_comparison_equal(monkeypatch):
    run = run_shadow(monkeypatch, installed_machine())
    c = run.comparison
    assert c.equal is True and c.reason == "equal"
    assert c.differences == () and c.field is None
    assert c.to_trace_data() == {"provider": "forticlient",
                                 "detection_parity": True, "reason": "equal",
                                 "diff_count": 0}


@pytest.mark.parametrize("env", [
    pytest.param(FakeEnvironment(), id="not-installed"),
    pytest.param(FakeEnvironment(files=[GUI_32], dirs=[DIR_32]), id="known-path-32"),
    pytest.param(FakeEnvironment(registry={FORTI_KEY: {"INSTALLDIR": r"D:\Duch"}}),
                 id="registry-ghost"),
    pytest.param(FakeEnvironment(registry={FORTI_KEY: {"Language": "pl"}},
                                 files=[GUI_64], dirs=[DIR_64]),
                 id="key-without-installdir"),
    pytest.param(FakeEnvironment(registry={FORTI_KEY: {"INSTALLDIR": ""}},
                                 files=[GUI_64], dirs=[DIR_64]),
                 id="empty-installdir-quirk"),
    pytest.param(installed_machine(registry={FA_FCM: {"installed": 0}}),
                 id="free-edition"),
])
def test_5b_equal_across_machines(env, monkeypatch):
    c = run_shadow(monkeypatch, env).comparison
    assert c.equal, c.differences


def test_5c_app_path_source_is_compared(monkeypatch):
    custom = r"D:\Narzedzia\FortiClient.exe"
    env = installed_machine(files=[custom])
    c = run_shadow(monkeypatch, env, app_path=custom).comparison
    assert c.equal


def test_5d_ambiguous_legacy_source_accepts_either_route(monkeypatch):
    """Legacy returns a bare path; when INSTALLDIR joins to a known path the
    source could be registry or known paths, and both are accepted."""
    env = installed_machine()
    run = run_shadow(monkeypatch, env)
    legacy_sources = shadow.normalize_legacy(run.legacy)["source"]
    assert legacy_sources == frozenset({"registry", "known_paths"})
    assert run.comparison.equal


# ══════════════════════════════════════════════════════════════════════════
# 6–8. Differences
# ══════════════════════════════════════════════════════════════════════════

def test_6_difference_installed(monkeypatch):
    c = run_shadow(monkeypatch, installed_machine(), FakeEnvironment()).comparison
    assert c.equal is False and c.reason == "value-mismatch"
    diff = c.difference("installed")
    assert diff.legacy_value is True and diff.new_value is False
    assert diff.legacy_present is True and diff.new_present is False
    assert c.field == "installed"                       # FIELDS order
    assert {"state", "path", "registry_present"} <= set(c.fields)


def test_7_difference_path(monkeypatch):
    legacy_env = FakeEnvironment(files=[GUI_64], dirs=[DIR_64])
    new_env = FakeEnvironment(files=[GUI_32], dirs=[DIR_32])
    c = run_shadow(monkeypatch, legacy_env, new_env).comparison
    assert not c.equal
    assert "installed" not in c.fields and "state" not in c.fields
    assert set(c.fields) == {"install_dir", "path"}
    diff = c.difference("path")
    assert diff.reason == "value-mismatch"
    assert diff.legacy_present and diff.new_present
    assert diff.legacy_value != diff.new_value
    assert diff.legacy_value.endswith(r"Fortinet\FortiClient\FortiClient.exe")


def test_7b_path_comparison_is_semantic_not_bytewise():
    assert shadow._same("path", GUI_64, GUI_64.upper())
    assert shadow._same("install_dir", DIR_64 + "\\", DIR_64)
    assert shadow._same("path", None, None)
    assert not shadow._same("path", GUI_64, GUI_32)


def test_8_difference_edition(monkeypatch):
    legacy_env = installed_machine(registry={FA_FCM: {"installed": 0}})
    new_env = installed_machine(registry={FA_FCM: {"installed": 1}})
    c = run_shadow(monkeypatch, legacy_env, new_env).comparison
    assert c.fields == ("edition",)
    assert (c.legacy_value, c.new_value) == ("free", None)
    assert c.to_trace_data()["field"] == "edition"


# ══════════════════════════════════════════════════════════════════════════
# 9. Legacy raising
# ══════════════════════════════════════════════════════════════════════════

def test_9_legacy_exception_does_not_break_comparison(monkeypatch):
    """The known legacy bug: a non-text DisplayName makes the edition check raise."""
    legacy_env = installed_machine(
        registry={f"{UNINSTALL}\\CudzyProdukt": {"DisplayName": ["x"]}})
    run = run_shadow(monkeypatch, legacy_env, installed_machine())

    assert run.legacy.values["free_edition"] == LegacyFailure("AttributeError")
    assert run.legacy.values["gui"] == GUI_64, "pozostałe wywołania legacy działają"
    c = run.comparison
    assert c.reason == "legacy-error" and c.legacy_errors == ("free_edition",)
    assert c.fields == ("edition",)
    assert c.difference("edition").legacy_value == "error:AttributeError"


def test_9b_same_bug_on_both_sides_is_reported_not_raised(monkeypatch):
    env = installed_machine(
        registry={f"{UNINSTALL}\\CudzyProdukt": {"DisplayName": 7}})
    c = run_shadow(monkeypatch, env).comparison
    assert c.reason == "new-provider-error"
    assert c.new_error == "AttributeError"
    assert c.legacy_errors == ("free_edition",)


def test_9c_every_legacy_call_raising(monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("legacy padło")

    legacy = SimpleNamespace(
        is_forticlient_installed=boom, _forti_install_dir=boom,
        _find_forticlient_gui=boom, _is_forti_free_edition=boom,
        _find_fortivpn=boom, find_executable=boom, _FORTI_LNK=LNK,
        os=SimpleNamespace(path=SimpleNamespace(isfile=boom)))
    run = shadow_detect_forticlient(
        registry=VpnRegistry([FortiClientProvider(installed_machine())]),
        legacy=legacy)
    assert set(run.legacy.failures) == set(shadow._LEGACY_CALLS)
    assert run.comparison.reason == "legacy-error"


def test_9d_legacy_module_that_cannot_be_imported(monkeypatch):
    monkeypatch.setitem(sys.modules, "vpn_connect", None)   # import -> ImportError
    snapshot = collect_legacy_detection()
    assert set(snapshot.failures) == set(shadow._LEGACY_CALLS)
    assert {v.error_type for v in snapshot.values.values()} == {"ModuleNotFoundError"}


# ══════════════════════════════════════════════════════════════════════════
# 10. New provider raising — legacy answer unchanged
# ══════════════════════════════════════════════════════════════════════════

class RaisingProvider(FortiClientProvider):
    def detect(self, request=None):
        raise RuntimeError("nowy provider padł")


def test_10_new_provider_exception_leaves_legacy_result_unchanged(monkeypatch):
    env = installed_machine()
    expected = legacy_detection(env, monkeypatch=monkeypatch)

    run = run_shadow(monkeypatch, env,
                     registry=VpnRegistry([RaisingProvider(env)]))
    assert run.legacy.values == expected, "odpowiedź legacy bajt w bajt ta sama"
    assert run.comparison.reason == "new-provider-error"
    assert run.comparison.new_error == "RuntimeError"
    assert run.comparison.difference("state").legacy_value == "installed"


def test_10b_provider_error_state_and_missing_provider(monkeypatch):
    class Broken(fc.DetectionEnvironment):
        def registry_value(self, *a):
            raise OSError("rejestr niedostępny")
        registry_key_exists = registry_subkeys = registry_value

        def is_file(self, path):
            return False
        is_dir = is_file

    env = installed_machine()
    run = run_shadow(monkeypatch, env, registry=VpnRegistry([FortiClientProvider(Broken())]))
    assert run.comparison.new_error == "OSError"
    assert run.legacy.values["gui"] == GUI_64

    run = run_shadow(monkeypatch, env, registry=VpnRegistry())
    assert run.comparison.reason == "provider-missing"
    assert run.legacy.values["gui"] == GUI_64


def test_10c_a_bug_in_the_comparison_itself_is_contained(monkeypatch):
    def broken(*a, **k):
        raise KeyError("błąd porównania")

    monkeypatch.setattr(shadow, "normalize_legacy", broken)
    env = installed_machine()
    run = run_shadow(monkeypatch, env)
    assert run.comparison.reason == "comparison-failed"
    assert run.legacy.values["gui"] == GUI_64


def test_10d_compare_detection_accepts_anything_without_raising():
    snapshot = collect_legacy_detection(legacy=SimpleNamespace())  # all AttributeError
    for new in (None, RuntimeError("x"), "not a result", 42,
                DetectionResult(provider_id="forticlient")):
        assert isinstance(compare_detection(snapshot, new), vpn.DetectionComparison)


# ══════════════════════════════════════════════════════════════════════════
# 11–13. No launching, no sleeping, no status polling
# ══════════════════════════════════════════════════════════════════════════

LAUNCHERS = ["_open_forticlient_gui", "launch_app", "connect", "connect_monitored",
             "disconnect", "_autofill_forticlient", "_fill_forti_auth_window",
             "_is_fortivpn_cli_supported"]
WAITERS = ["_wait_for_process", "_wait_forticlient_window", "_find_forti_auth_window"]
POLLERS = ["get_status", "_check_adapter_status", "_get_status_from_log",
           "invalidate_adapter_cache"]


@pytest.fixture
def side_effects(monkeypatch):
    """Record (and block) everything a detection must never do."""
    calls = []

    def tripwire(name):
        def _hit(*a, **k):
            calls.append(name)
            raise AssertionError(f"shadow detection wywołało {name}")
        return _hit

    for name in ("Popen", "run", "call", "check_call", "check_output"):
        monkeypatch.setattr(subprocess, name, tripwire(f"subprocess.{name}"))
    if hasattr(os, "startfile"):
        monkeypatch.setattr(os, "startfile", tripwire("os.startfile"))
    monkeypatch.setattr(time, "sleep", tripwire("time.sleep"))
    for name in LAUNCHERS + WAITERS + POLLERS:
        if hasattr(vpn_connect, name):
            monkeypatch.setattr(vpn_connect, name, tripwire(name))
    from diagnostics import vpn as vpn_diag
    monkeypatch.setattr(vpn_diag, "note_status", tripwire("note_status"))
    monkeypatch.setattr(vpn_diag, "mark_status_source", tripwire("mark_status_source"))
    return calls


def _real_machine_shadow():
    """Real registry, real disk, real legacy module, default registry."""
    cache = dict(vpn_connect._cli_supported_cache)
    last = dict(vpn_connect._last_connected)
    run = shadow_detect_forticlient()
    assert vpn_connect._cli_supported_cache == cache
    assert vpn_connect._last_connected == last
    return run


def test_11_shadow_does_not_launch_the_client(side_effects):
    run = _real_machine_shadow()
    assert not [c for c in side_effects
                if c.startswith(("subprocess", "os.startfile")) or c in LAUNCHERS]
    assert run.comparison.equal, run.comparison     # real machine: parity


def test_12_shadow_does_not_sleep_or_wait(side_effects):
    _real_machine_shadow()
    assert not [c for c in side_effects if c == "time.sleep" or c in WAITERS]


def test_13_shadow_does_not_poll_status(side_effects):
    _real_machine_shadow()
    assert side_effects == []


def test_11_13_structural_no_process_sleep_or_status_in_new_layer():
    """Code references, not docstrings: what the new modules could call."""
    forbidden_modules = {"subprocess", "time", "threading", "ctypes", "win32gui",
                         "win32api", "win32process", "psutil"}
    forbidden_names = {"Popen", "sleep", "startfile", "get_status",
                       "_check_adapter_status", "_get_status_from_log",
                       "_is_fortivpn_cli_supported", "_wait_for_process",
                       "_wait_forticlient_window", "connect", "connect_monitored",
                       "disconnect", "launch_app"}
    for rel in ("vpn/shadow.py", "vpn/registry.py", "vpn/__init__.py",
                "vpn/providers/__init__.py", "vpn/providers/forticlient.py"):
        tree = ast.parse(open(os.path.join(_PARENT, rel), encoding="utf-8").read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                mods = {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                mods = {node.module.split(".")[0]}
            else:
                mods = set()
            assert not mods & forbidden_modules, f"{rel}: import {mods}"
            if isinstance(node, ast.Attribute):
                assert node.attr not in forbidden_names, f"{rel}: .{node.attr}"
            if isinstance(node, ast.Name):
                assert node.id not in forbidden_names, f"{rel}: {node.id}"


# ══════════════════════════════════════════════════════════════════════════
# 14. Private paths and secrets
# ══════════════════════════════════════════════════════════════════════════

def test_14_private_paths_never_reach_the_trace_raw(monkeypatch, tmp_path):
    monkeypatch.setenv("USERPROFILE", r"C:\Users\Testowy")
    monkeypatch.setenv("USERNAME", "Testowy")
    mine = r"C:\Users\Testowy\Apps\Forti\FortiClient.exe"
    env_legacy = FakeEnvironment(files=[mine])
    run = run_shadow(monkeypatch, env_legacy, FakeEnvironment(), app_path=mine)
    c = run.comparison
    assert not c.equal

    trace = c.to_trace_data()
    assert "Testowy" not in str(trace) and "FortiClient.exe" not in str(trace)
    assert trace["legacy_present"] is True and trace["new_present"] is False

    diff = c.difference("path")
    assert diff.legacy_value.startswith("%USERPROFILE%")
    assert "Testowy" not in repr(c)
    assert "Testowy" not in repr(run.legacy), "surowe wartości legacy poza repr"


def test_14b_another_users_profile_is_masked_too(monkeypatch):
    monkeypatch.setenv("USERNAME", "Ktos")
    monkeypatch.setenv("USERPROFILE", r"C:\Users\Ktos")
    other = r"C:\Users\InnaOsoba\Forti\FortiClient.exe"
    c = run_shadow(monkeypatch, FakeEnvironment(files=[other]), FakeEnvironment(),
                   app_path=other).comparison
    assert "InnaOsoba" not in repr(c)
    assert c.difference("path").legacy_value.startswith(r"C:\Users\<user>")


def test_14c_secret_shaped_values_are_replaced(monkeypatch):
    weird = r"D:\-----BEGIN PRIVATE KEY-----\FortiClient.exe"
    c = run_shadow(monkeypatch, FakeEnvironment(files=[weird]), FakeEnvironment(),
                   app_path=weird).comparison
    blob = repr(c) + str(c.to_trace_data())
    for secret in FAKE_SECRETS:
        assert secret not in blob
    assert c.difference("path").legacy_value == "<redacted>"


def test_14d_record_comparison_writes_only_safe_metadata(monkeypatch, tmp_path):
    import diagnostics
    from diagnostics import vpn as vpn_diag

    monkeypatch.setenv(diagnostics.DIR_ENV_VAR, str(tmp_path / "diag"))
    monkeypatch.setenv("USERPROFILE", r"C:\Users\Testowy")
    monkeypatch.setenv("USERNAME", "Testowy")
    diagnostics.reset_for_tests()
    try:
        mine = r"C:\Users\Testowy\Apps\FortiClient.exe"
        trace = vpn_diag.start("vpn.detect", provider="forticlient")
        run_shadow(monkeypatch, FakeEnvironment(files=[mine]), FakeEnvironment(),
                   app_path=mine, trace=trace)
        trace.finish("ok")

        text = diagnostics.get_store().read_jsonl()
        assert '"vpn.detect.shadow"' in text
        assert '"detection_parity": false' in text
        assert '"field": "installed"' in text
        assert '"legacy_present": true' in text and '"new_present": false' in text
        assert "Testowy" not in text and "FortiClient.exe" not in text
    finally:
        diagnostics.reset_for_tests()


def test_14e_record_comparison_never_raises():
    class BrokenTrace:
        def step(self, *a, **k):
            raise RuntimeError("diagnostyka padła")

    c = vpn.DetectionComparison("forticlient", equal=True)
    record_comparison(BrokenTrace(), c)
    record_comparison(None, c)
    record_comparison(BrokenTrace(), None)


# ══════════════════════════════════════════════════════════════════════════
# Production path: UI -> vpn_connect.py, nothing else
# ══════════════════════════════════════════════════════════════════════════

def _vpn_connect_attributes(rel):
    tree = ast.parse(open(os.path.join(_PARENT, rel), encoding="utf-8").read())
    return {node.attr for node in ast.walk(tree)
            if isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name) and node.value.id == "vpn_connect"}


def test_production_ui_still_drives_the_vpn_through_vpn_connect():
    detail = _vpn_connect_attributes(os.path.join("ui", "detail_panel.py"))
    panel = _vpn_connect_attributes(os.path.join("ui", "vpn_panel.py"))
    assert {"connect_monitored", "disconnect", "get_status"} <= detail
    assert {"launch_app", "connect_monitored", "disconnect", "get_status"} <= panel
    for name in ("connect", "connect_monitored", "disconnect", "get_status",
                 "launch_app"):
        assert getattr(vpn_connect, name).__module__ == "vpn_connect", name


#: Directories that are not the running application: the new architecture
#: itself, its tests, and the Stage-17 live observation scripts (opt-in, run by
#: hand, never imported by the app — `test_smoke_tooling_is_not_reachable_from
#: _production` below is what keeps that true).
NON_PRODUCTION_DIRS = ("vpn", "tests", "smoke")


def test_production_modules_do_not_import_the_new_architecture():
    production = [p for p in glob.glob(os.path.join(_PARENT, "**", "*.py"),
                                       recursive=True)
                  if os.path.relpath(p, _PARENT).split(os.sep)[0]
                  not in NON_PRODUCTION_DIRS and "__pycache__" not in p]
    assert any(p.endswith("vpn_connect.py") for p in production)
    for path in production:
        tree = ast.parse(open(path, encoding="utf-8").read())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0:
                names = [node.module or ""]
            else:
                continue
            for name in names:
                # Stage 52: the panel wires V2 through the *one* sanctioned
                # abstraction, ``vpn.panel_bridge`` — nothing deeper (no
                # providers, no secure_window, no bare ``vpn``).
                if name == "vpn.panel_bridge":
                    continue
                assert name != "vpn" and not name.startswith("vpn."), (
                    f"{os.path.relpath(path, _PARENT)} importuje {name}")
        source = open(path, encoding="utf-8").read()
        for token in ("shadow_detect", "compare_detection", "default_registry",
                      "FortiClientProvider"):
            assert token not in source, f"{os.path.relpath(path, _PARENT)}: {token}"


def test_smoke_tooling_is_not_reachable_from_production():
    """The live scripts may import `vpn`; nothing in the app may import them."""
    for path in glob.glob(os.path.join(_PARENT, "**", "*.py"), recursive=True):
        head = os.path.relpath(path, _PARENT).split(os.sep)[0]
        if head in ("smoke", "tests") or "__pycache__" in path:
            continue
        source = open(path, encoding="utf-8").read()
        assert "smoke" not in source, os.path.relpath(path, _PARENT)


def test_registry_cannot_take_over_connect_disconnect_status_launch():
    for name in ("connect", "disconnect", "status", "launch"):
        assert not hasattr(VpnRegistry, name)
    provider = vpn.default_registry.get("forticlient")
    # Stage 8 migrated launch — declared, but never called from here: on this
    # machine it would start the real FortiClient.
    assert provider.capabilities() == vpn.Capability.LAUNCH
    request = VpnRequest(provider_id="forticlient")
    for call in (provider.connect, provider.disconnect, provider.status):
        assert call(request).error_code == "unsupported"
