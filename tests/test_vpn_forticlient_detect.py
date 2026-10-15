"""FortiClient detection: does the migrated provider behave like the legacy?

Both implementations are run against the *same* described machine — a fake
registry and a fake filesystem — and their answers are compared field by
field.  The legacy functions are driven by swapping the `winreg` and `os`
they see inside `vpn_connect`; the new provider is driven through its
:class:`DetectionEnvironment` seam.  No real FortiClient, no real registry.

Parity is the whole point of this stage, so where the legacy does something
odd (a registry path that does not exist, an edition check that only matches
an exact English product name) the test pins that behaviour down rather than
correcting it.
"""

import ast
import os
import sys
from types import SimpleNamespace

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import vpn_connect  # noqa: E402
from vpn import DetectionState, VpnRequest, check_contract  # noqa: E402
from vpn.providers import FortiClientProvider  # noqa: E402
from vpn.providers import forticlient as fc  # noqa: E402

FAKE_SECRETS = ("SuperSecret123", "ABC123", "123456", "-----BEGIN PRIVATE KEY-----")

GUI_64 = r"C:\Program Files\Fortinet\FortiClient\FortiClient.exe"
GUI_32 = r"C:\Program Files (x86)\Fortinet\FortiClient\FortiClient.exe"
DIR_64 = r"C:\Program Files\Fortinet\FortiClient"
DIR_32 = r"C:\Program Files (x86)\Fortinet\FortiClient"
FORTIVPN_64 = r"C:\Program Files\Fortinet\FortiClient\FortiVPN.exe"
SSLVPN_64 = r"C:\Program Files\Fortinet\FortiClient\FortiSSLVPNclient.exe"
LNK = r"C:\Users\Public\Desktop\FortiClient VPN.lnk"
FORTI_KEY = r"SOFTWARE\Fortinet\FortiClient"
FA_FCM = r"SOFTWARE\Fortinet\FortiClient\FA_FCM"
UNINSTALL = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"


# ══════════════════════════════════════════════════════════════════════════
# A described machine, usable by both implementations
# ══════════════════════════════════════════════════════════════════════════

class FakeEnvironment(fc.DetectionEnvironment):
    """Registry + filesystem of an imaginary machine."""

    def __init__(self, registry: dict | None = None, files=(), dirs=()):
        self.registry = registry or {}
        self.files = {p.lower() for p in files}
        self.dirs = {p.lower() for p in dirs}

    # -- the seam the new provider uses ------------------------------------ #

    def registry_value(self, subkey, name):
        return self.registry.get(subkey, {}).get(name)

    def registry_key_exists(self, subkey):
        return subkey in self.registry or any(
            k.startswith(subkey + "\\") for k in self.registry)

    def registry_subkeys(self, subkey):
        prefix = subkey + "\\"
        names = []
        for key in self.registry:
            if key.startswith(prefix):
                child = key[len(prefix):].split("\\", 1)[0]
                if child not in names:
                    names.append(child)
        return names

    def is_file(self, path):
        return bool(path) and path.lower() in self.files

    def is_dir(self, path):
        return bool(path) and path.lower() in self.dirs


class _FakeKey:
    def __init__(self, subkey):
        self.subkey = subkey


class FakeWinreg:
    """Just enough winreg for the legacy detection functions."""

    HKEY_LOCAL_MACHINE = "HKLM"

    def __init__(self, env: FakeEnvironment):
        self._env = env

    def OpenKey(self, root, subkey):
        full = f"{root.subkey}\\{subkey}" if isinstance(root, _FakeKey) else subkey
        if not self._env.registry_key_exists(full):
            raise OSError(2, "brak klucza")
        return _FakeKey(full)

    def QueryValueEx(self, key, name):
        values = self._env.registry.get(key.subkey, {})
        if name not in values:
            raise OSError(2, "brak wartości")
        return values[name], 1

    def EnumKey(self, key, index):
        children = self._env.registry_subkeys(key.subkey)
        if index >= len(children):
            raise OSError(259, "koniec")
        return children[index]

    def CloseKey(self, key):
        return None


def _os_shim(env: FakeEnvironment):
    """`os` as the legacy module should see it for this machine."""
    return SimpleNamespace(
        path=SimpleNamespace(isfile=env.is_file, isdir=env.is_dir,
                             join=os.path.join, dirname=os.path.dirname,
                             basename=os.path.basename,
                             exists=lambda p: env.is_file(p) or env.is_dir(p)),
        environ=os.environ,
    )


def legacy_detection(env: FakeEnvironment, app_path: str = "",
                     monkeypatch=None) -> dict:
    """Run the legacy detection functions against `env`."""
    patcher = monkeypatch or pytest.MonkeyPatch()
    patcher.setattr(vpn_connect, "winreg", FakeWinreg(env))
    patcher.setattr(vpn_connect, "os", _os_shim(env))
    try:
        return {
            "installed": vpn_connect.is_forticlient_installed(),
            "install_dir": vpn_connect._forti_install_dir(),
            "gui": vpn_connect._find_forticlient_gui(app_path),
            "free_edition": vpn_connect._is_forti_free_edition(),
            "fortivpn": vpn_connect._find_fortivpn(app_path),
            "sslvpn_client": vpn_connect.find_executable("FortiClient"),
            "lnk": vpn_connect.os.path.isfile(vpn_connect._FORTI_LNK),
        }
    finally:
        if monkeypatch is None:
            patcher.undo()


def new_detection(env: FakeEnvironment, app_path: str = "") -> dict:
    """Run the migrated provider against the same `env`, shaped alike."""
    provider = FortiClientProvider(env)
    result = provider.detect(VpnRequest(provider_id="forticlient",
                                        app_path=app_path))
    return {
        "installed": result.metadata["registry_present"],
        "install_dir": result.metadata["install_dir"] or None,
        "gui": result.path,
        "free_edition": result.metadata["free_edition"],
        "fortivpn": provider._fortivpn_executable(app_path),
        "sslvpn_client": provider._first_existing(fc.SSLVPN_CLIENT_PATHS),
        "lnk": result.metadata["lnk_present"],
    }


def assert_parity(env, app_path="", monkeypatch=None):
    legacy = legacy_detection(env, app_path, monkeypatch)
    new = new_detection(env, app_path)
    assert new == legacy, f"rozjazd legacy/new:\nlegacy={legacy}\nnew   ={new}"
    return legacy


# ══════════════════════════════════════════════════════════════════════════
# A. Installed — found through the registry
# ══════════════════════════════════════════════════════════════════════════

def test_case_a_installed_via_registry(monkeypatch):
    env = FakeEnvironment(
        registry={FORTI_KEY: {"INSTALLDIR": DIR_64}},
        files=[GUI_64, FORTIVPN_64, LNK], dirs=[DIR_64])

    shared = assert_parity(env, monkeypatch=monkeypatch)
    assert shared["installed"] is True
    assert shared["gui"] == GUI_64

    result = FortiClientProvider(env).detect(VpnRequest(provider_id="forticlient"))
    assert result.state is DetectionState.INSTALLED
    assert result.success is True
    assert result.source == fc.SOURCE_REGISTRY
    assert result.error_code is None


# ══════════════════════════════════════════════════════════════════════════
# B. Installed — found through a known path (no registry at all)
# ══════════════════════════════════════════════════════════════════════════

def test_case_b_installed_via_known_path(monkeypatch):
    env = FakeEnvironment(files=[GUI_64], dirs=[DIR_64])

    shared = assert_parity(env, monkeypatch=monkeypatch)
    assert shared["installed"] is False, "brak klucza rejestru"
    assert shared["gui"] == GUI_64
    assert shared["install_dir"] == DIR_64, "fallback na znane katalogi"

    result = FortiClientProvider(env).detect(VpnRequest(provider_id="forticlient"))
    assert result.state is DetectionState.INSTALLED
    assert result.source == fc.SOURCE_KNOWN_PATHS


def test_case_b2_app_path_wins_over_everything(monkeypatch):
    custom = r"D:\Narzedzia\Fortinet\FortiClient.exe"
    env = FakeEnvironment(registry={FORTI_KEY: {"INSTALLDIR": DIR_64}},
                          files=[GUI_64, custom], dirs=[DIR_64])

    shared = assert_parity(env, app_path=custom, monkeypatch=monkeypatch)
    assert shared["gui"] == custom

    result = FortiClientProvider(env).detect(
        VpnRequest(provider_id="forticlient", app_path=custom))
    assert result.source == fc.SOURCE_APP_PATH


# ══════════════════════════════════════════════════════════════════════════
# C. Not installed
# ══════════════════════════════════════════════════════════════════════════

def test_case_c_not_installed(monkeypatch):
    env = FakeEnvironment()

    shared = assert_parity(env, monkeypatch=monkeypatch)
    assert shared == {"installed": False, "install_dir": None, "gui": None,
                      "free_edition": False, "fortivpn": None,
                      "sslvpn_client": None, "lnk": False}

    result = FortiClientProvider(env).detect(VpnRequest(provider_id="forticlient"))
    assert result.state is DetectionState.NOT_INSTALLED
    assert result.success is False
    assert result.error_code == "client-not-found"
    assert result.path is None


# ══════════════════════════════════════════════════════════════════════════
# D. Registry points at a file that is not there
# ══════════════════════════════════════════════════════════════════════════

def test_case_d_registry_points_at_missing_install(monkeypatch):
    """Legacy quirk preserved: INSTALLDIR is returned without checking it."""
    ghost = r"D:\StaraInstalacja\FortiClient"
    env = FakeEnvironment(registry={FORTI_KEY: {"INSTALLDIR": ghost}})

    shared = assert_parity(env, monkeypatch=monkeypatch)
    assert shared["installed"] is True, "klucz rejestru istnieje"
    assert shared["gui"] is None, "ale pliku nie ma"
    assert shared["install_dir"] == ghost, (
        "_forti_install_dir zwraca wartość z rejestru bez sprawdzenia, "
        "czy katalog istnieje — zachowane 1:1")

    result = FortiClientProvider(env).detect(VpnRequest(provider_id="forticlient"))
    assert result.state is DetectionState.INCOMPLETE
    assert result.success is False
    assert result.error_code == "client-not-found"


def test_case_d2_registry_missing_but_known_path_present(monkeypatch):
    """The other half of the quirk: the GUI lookup *does* fall through."""
    ghost = r"D:\StaraInstalacja\FortiClient"
    env = FakeEnvironment(registry={FORTI_KEY: {"INSTALLDIR": ghost}},
                          files=[GUI_32], dirs=[DIR_32])

    shared = assert_parity(env, monkeypatch=monkeypatch)
    assert shared["gui"] == GUI_32, "_find_forticlient_gui schodzi do znanych ścieżek"
    assert shared["install_dir"] == ghost, "_forti_install_dir już nie — inna logika"


def test_case_d3_installdir_value_missing_falls_back_in_both(monkeypatch):
    """Key present, INSTALLDIR absent: the read fails, both use known paths."""
    env = FakeEnvironment(registry={FORTI_KEY: {"Language": "pl"}},
                          files=[GUI_64], dirs=[DIR_64])

    shared = assert_parity(env, monkeypatch=monkeypatch)
    assert shared["installed"] is True
    assert shared["install_dir"] == DIR_64
    assert shared["gui"] == GUI_64


def _both_lookups(env, monkeypatch):
    legacy = legacy_detection(env, monkeypatch=monkeypatch)
    provider = FortiClientProvider(env)
    return legacy, provider._install_dir(), provider._gui_executable("")[0]


def test_case_d4_empty_installdir_quirk(monkeypatch):
    """Legacy bug preserved: an empty INSTALLDIR is a "successful read".

    `_forti_install_dir` returns "" (no fallback to known dirs), and
    `_find_forticlient_gui` joins "" + "FortiClient.exe" — a lookup relative
    to the process's current directory.
    """
    env = FakeEnvironment(registry={FORTI_KEY: {"INSTALLDIR": ""}},
                          files=[GUI_64], dirs=[DIR_64])
    legacy, install_dir, gui = _both_lookups(env, monkeypatch)
    assert legacy["install_dir"] == install_dir == ""
    assert legacy["gui"] == gui == GUI_64, "bez pliku w CWD — znane ścieżki"

    env_cwd = FakeEnvironment(registry={FORTI_KEY: {"INSTALLDIR": ""}},
                              files=["FortiClient.exe", GUI_64], dirs=[DIR_64])
    legacy, install_dir, gui = _both_lookups(env_cwd, monkeypatch)
    assert legacy["gui"] == gui == "FortiClient.exe", (
        "plik w katalogu roboczym wygrywa ze znanymi ścieżkami — zachowane 1:1")


def test_case_d5_non_text_installdir(monkeypatch):
    """INSTALLDIR stored as a number: returned raw, GUI lookup falls back."""
    env = FakeEnvironment(registry={FORTI_KEY: {"INSTALLDIR": 5}},
                          files=[GUI_64], dirs=[DIR_64])
    legacy, install_dir, gui = _both_lookups(env, monkeypatch)
    assert legacy["install_dir"] == install_dir == 5
    assert legacy["gui"] == gui == GUI_64

    result = FortiClientProvider(env).detect(VpnRequest(provider_id="forticlient"))
    assert result.state is DetectionState.INSTALLED
    assert result.metadata["install_dir"] == "5"


# ══════════════════════════════════════════════════════════════════════════
# E. 32-bit / 64-bit
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("gui,directory", [(GUI_64, DIR_64), (GUI_32, DIR_32)])
def test_case_e_both_program_files_locations(gui, directory, monkeypatch):
    env = FakeEnvironment(files=[gui], dirs=[directory])
    shared = assert_parity(env, monkeypatch=monkeypatch)
    assert shared["gui"] == gui


def test_case_e2_legacy_uses_only_the_default_registry_view():
    """Documented parity boundary, not an omission in the new provider.

    The legacy code opens every key with the default view and never asks for
    the 32-bit one (no KEY_WOW64_* flags anywhere), and never reads HKCU. The
    migrated provider does the same; changing that would be a new feature.
    """
    source = open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read()
    assert "KEY_WOW64" not in source
    assert "HKEY_CURRENT_USER" not in source

    provider_source = open(fc.__file__, encoding="utf-8").read()
    assert "KEY_WOW64" not in provider_source
    assert "HKEY_CURRENT_USER" not in provider_source


# ══════════════════════════════════════════════════════════════════════════
# F. The public-desktop shortcut
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("lnk_present", [True, False])
def test_case_f_lnk_presence(lnk_present, monkeypatch):
    files = [GUI_64] + ([LNK] if lnk_present else [])
    env = FakeEnvironment(files=files, dirs=[DIR_64])

    shared = assert_parity(env, monkeypatch=monkeypatch)
    assert shared["lnk"] is lnk_present

    result = FortiClientProvider(env).detect(VpnRequest(provider_id="forticlient"))
    assert result.metadata["lnk_present"] is lnk_present
    # The shortcut's path is never reported — only whether it exists.
    assert LNK not in str(result.to_trace_data())


def test_lnk_constant_matches_legacy():
    assert fc.LNK_PATH == vpn_connect._FORTI_LNK


# ══════════════════════════════════════════════════════════════════════════
# G. Editions and versions
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("registry,expected_free", [
    ({FORTI_KEY: {"INSTALLDIR": DIR_64}, FA_FCM: {"installed": 0}}, True),
    ({FORTI_KEY: {"INSTALLDIR": DIR_64}, FA_FCM: {"installed": 1}}, False),
    ({FORTI_KEY: {"INSTALLDIR": DIR_64}}, False),
])
def test_case_g_edition_from_fa_fcm(registry, expected_free, monkeypatch):
    env = FakeEnvironment(registry=registry, files=[GUI_64], dirs=[DIR_64])
    shared = assert_parity(env, monkeypatch=monkeypatch)
    assert shared["free_edition"] is expected_free

    result = FortiClientProvider(env).detect(VpnRequest(provider_id="forticlient"))
    assert result.edition == ("free" if expected_free else None)


@pytest.mark.parametrize("display_name,expected_free", [
    ("FortiClient VPN", True),
    ("FortiClient Free", True),
    ("FortiClient", False),
    ("FortiClient VPN 7.4.1", False),      # exact-match only — legacy quirk
    ("FortiClient VPN (tylko VPN)", False),
    ("Notepad++", False),
])
def test_case_g2_edition_from_uninstall_list(display_name, expected_free,
                                             monkeypatch):
    env = FakeEnvironment(
        registry={FORTI_KEY: {"INSTALLDIR": DIR_64},
                  f"{UNINSTALL}\\SomeProduct": {"DisplayName": display_name}},
        files=[GUI_64], dirs=[DIR_64])

    shared = assert_parity(env, monkeypatch=monkeypatch)
    assert shared["free_edition"] is expected_free


@pytest.mark.parametrize("display_name,error", [
    (["FortiClient VPN"], AttributeError),   # REG_MULTI_SZ -> list
    (7, AttributeError),                     # REG_DWORD -> int
    (b"FortiClient VPN", TypeError),         # REG_BINARY -> bytes
])
def test_case_g4_non_text_display_name_breaks_both(display_name, error,
                                                   monkeypatch):
    """Legacy bug preserved: any non-text DisplayName aborts the edition check.

    The entry need not even be FortiClient's. The legacy lets the exception
    escape (up through `_is_fortivpn_cli_supported` into `connect`); the
    provider reports the same failure as DetectionState.ERROR.
    """
    env = FakeEnvironment(
        registry={FORTI_KEY: {"INSTALLDIR": DIR_64},
                  f"{UNINSTALL}\\CudzyProdukt": {"DisplayName": display_name}},
        files=[GUI_64], dirs=[DIR_64])

    monkeypatch.setattr(vpn_connect, "winreg", FakeWinreg(env))
    with pytest.raises(error):
        vpn_connect._is_forti_free_edition()

    result = FortiClientProvider(env).detect(VpnRequest(provider_id="forticlient"))
    assert result.state is DetectionState.ERROR
    assert result.error_code == "detection-failed"
    assert result.metadata["reason_code"] == error.__name__


def test_case_g5_fa_fcm_short_circuits_before_the_uninstall_list(monkeypatch):
    """With FA_FCM installed=0 neither implementation reaches the bad entry."""
    env = FakeEnvironment(
        registry={FORTI_KEY: {"INSTALLDIR": DIR_64}, FA_FCM: {"installed": 0},
                  f"{UNINSTALL}\\CudzyProdukt": {"DisplayName": 7}},
        files=[GUI_64], dirs=[DIR_64])

    shared = assert_parity(env, monkeypatch=monkeypatch)
    assert shared["free_edition"] is True


def test_case_g3_no_version_is_read_anywhere():
    """The legacy never reads a version, so neither may the provider.

    Adding version detection here would look like a migration and behave like
    a new feature — and the parity test would have nothing to compare against.
    """
    legacy_source = open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read()
    for marker in ("DisplayVersion", "GetFileVersionInfo", "FileVersion",
                   "ProductVersion"):
        assert marker not in legacy_source, f"legacy jednak czyta wersję ({marker})"

    env = FakeEnvironment(files=[GUI_64], dirs=[DIR_64])
    result = FortiClientProvider(env).detect(VpnRequest(provider_id="forticlient"))
    assert result.version is None
    assert "app_version" not in result.to_trace_data()


# ══════════════════════════════════════════════════════════════════════════
# Parity on this actual machine
# ══════════════════════════════════════════════════════════════════════════

def test_parity_on_the_real_machine():
    """Both implementations, the real registry and disk, same answers.

    Works on a machine with FortiClient and on one without — the assertion is
    agreement, not a particular outcome.
    """
    provider = FortiClientProvider()
    request = VpnRequest(provider_id="forticlient")
    result = provider.detect(request)

    assert result.path == vpn_connect._find_forticlient_gui("")
    assert result.metadata["registry_present"] is vpn_connect.is_forticlient_installed()
    assert result.metadata["free_edition"] is vpn_connect._is_forti_free_edition()
    assert (result.metadata["install_dir"] or None) == vpn_connect._forti_install_dir()
    assert result.metadata["fortivpn_present"] is bool(vpn_connect._find_fortivpn(""))
    assert result.metadata["sslvpn_client_present"] is bool(
        vpn_connect.find_executable("FortiClient"))
    assert result.metadata["lnk_present"] is os.path.isfile(vpn_connect._FORTI_LNK)

    expected = (DetectionState.INSTALLED if result.path
                else DetectionState.INCOMPLETE if result.metadata["registry_present"]
                else DetectionState.NOT_INSTALLED)
    assert result.state is expected


# ══════════════════════════════════════════════════════════════════════════
# Constants must not drift apart
# ══════════════════════════════════════════════════════════════════════════

def test_constants_match_the_legacy_module():
    assert list(fc.GUI_PATHS) == list(vpn_connect._FORTICLIENT_GUI_PATHS)
    assert list(fc.FORTIVPN_PATHS) == list(vpn_connect._FORTIVPN_PATHS)
    assert list(fc.SSLVPN_CLIENT_PATHS) == list(vpn_connect._PATHS["FortiClient"])
    assert fc.LNK_PATH == vpn_connect._FORTI_LNK
    assert fc.GUI_EXE_NAME == "FortiClient.exe"


# ══════════════════════════════════════════════════════════════════════════
# Safety and cost
# ══════════════════════════════════════════════════════════════════════════

def test_detection_starts_no_processes_and_never_waits():
    """Structural guarantee, not a timing measurement."""
    tree = ast.parse(open(fc.__file__, encoding="utf-8").read())
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
    for forbidden in ("subprocess", "time", "threading", "ctypes", "win32gui"):
        assert forbidden not in imported, (
            f"detection nie może zależeć od {forbidden}")
    source = open(fc.__file__, encoding="utf-8").read()
    for forbidden in ("sleep(", "Popen(", "startfile(", "EnumWindows"):
        assert forbidden not in source


def test_result_contains_no_secrets_even_from_a_hostile_environment():
    env = FakeEnvironment(
        registry={FORTI_KEY: {"INSTALLDIR": DIR_64}},
        files=[GUI_64], dirs=[DIR_64])
    request = VpnRequest(provider_id="forticlient", login="jkowalski",
                         password="SuperSecret123", token="ABC123",
                         group="123456", domain="-----BEGIN PRIVATE KEY-----")

    result = FortiClientProvider(env).detect(request)
    blob = f"{result} {result.metadata} {result.to_trace_data()}"
    for secret in FAKE_SECRETS:
        assert secret not in blob
    assert "jkowalski" not in blob


def test_user_paths_are_masked_in_trace_data(monkeypatch):
    """A client installed under the user's profile must not expose the name."""
    monkeypatch.setenv("USERPROFILE", r"C:\Users\Testowy")
    monkeypatch.setenv("USERNAME", "Testowy")
    custom = r"C:\Users\Testowy\Apps\FortiClient.exe"
    env = FakeEnvironment(files=[custom])

    result = FortiClientProvider(env).detect(
        VpnRequest(provider_id="forticlient", app_path=custom))
    assert result.path == custom, "surowa ścieżka zostaje w wyniku — jest potrzebna"

    from diagnostics import redactor
    traced = redactor.redact(result.to_trace_data())
    assert "Testowy" not in str(traced), "ale w trace'ie już nie"
    assert traced["exe_path"].startswith("%USERPROFILE%")


def test_detection_survives_a_broken_environment():
    class Broken(fc.DetectionEnvironment):
        def registry_value(self, subkey, name):
            raise OSError("rejestr niedostępny")

        registry_key_exists = registry_subkeys = registry_value

        def is_file(self, path):
            return False

        def is_dir(self, path):
            return False

    result = FortiClientProvider(Broken()).detect(VpnRequest(provider_id="forticlient"))
    assert result.state is DetectionState.ERROR
    assert result.error_code == "detection-failed"
    assert result.metadata["reason_code"] == "OSError"


# ══════════════════════════════════════════════════════════════════════════
# Migration bookkeeping
# ══════════════════════════════════════════════════════════════════════════

def test_provider_satisfies_the_contract():
    assert check_contract(FortiClientProvider()) == []


def test_connect_disconnect_status_are_not_migrated():
    """Detection and launch are migrated; the rest must answer 'unsupported'.

    Launch is not called here — its tests use a fake launch system.
    """
    provider = FortiClientProvider(FakeEnvironment())
    request = VpnRequest(provider_id="forticlient")
    for result in (provider.connect(request), provider.disconnect(request),
                   provider.status(request)):
        assert result.error_code == "unsupported"


def test_implemented_capabilities_are_a_subset_of_the_catalog():
    """Migration invariant: a provider never claims more than the client can."""
    provider = FortiClientProvider()
    assert provider.capabilities() in provider.spec.capabilities or \
        provider.capabilities() == type(provider.capabilities())(0)
    assert provider.spec.legacy_name == "FortiClient"


def test_provider_is_registered_but_only_for_detection():
    """Registered since stage 7; everything but detection still 'unsupported'."""
    import vpn
    assert isinstance(vpn.default_registry.get("forticlient"), FortiClientProvider)
    assert vpn.default_registry.ids() == ["forticlient"]


def test_production_code_does_not_import_the_new_provider():
    for name in ("vpn_connect.py", os.path.join("ui", "detail_panel.py"),
                 os.path.join("ui", "vpn_panel.py")):
        source = open(os.path.join(_PARENT, name), encoding="utf-8").read()
        assert "FortiClientProvider" not in source
        assert "vpn.providers" not in source
