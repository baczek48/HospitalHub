"""What each VPN client in this project can really do.

This is **data, not logic** — a declaration of the capabilities the existing
`vpn_connect.py` actually exercises for every provider, with the code paths
that justify each entry.  It exists so the capability model can be checked
against reality instead of against a mental picture, and so migrating a
provider starts from a written-down expectation.

No connection logic lives here and none may ever be added.  When a provider is
migrated, its class declares the same capabilities and this table becomes the
regression baseline.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .types import AutomationMode, Capability, StatusSource

C = Capability


@dataclass(frozen=True)
class ProviderSpec:
    """Declared abilities of one provider, as implemented today."""

    id: str
    legacy_name: str
    display_name: str
    capabilities: Capability
    automation: AutomationMode
    status_sources: tuple[StatusSource, ...] = ()
    #: Where in `vpn_connect.py` these abilities live — the evidence.
    evidence: tuple[str, ...] = ()
    #: Known gaps, deliberately recorded rather than smoothed over.
    caveats: tuple[str, ...] = ()

    def supports(self, capability: Capability) -> bool:
        return capability in self.capabilities


FORTICLIENT = ProviderSpec(
    id="forticlient",
    legacy_name="FortiClient",
    display_name="FortiClient",
    capabilities=(C.LAUNCH | C.RESTORE_WINDOW | C.CLI_CONNECT | C.CLI_DISCONNECT
                  | C.AUTOFILL | C.AUTO_DISCONNECT | C.TWO_FACTOR
                  | C.PROCESS_MONITOR | C.CREDENTIAL_COPY | C.STATUS
                  | C.PROFILE_IMPORT),
    automation=AutomationMode.TAB_SEQUENCE,
    status_sources=(StatusSource.CLI, StatusSource.ADAPTER, StatusSource.NETSTAT,
                    StatusSource.LOG, StatusSource.REGISTRY),
    evidence=(
        "connect(): fast-path okna, okno EMS (_fill_forti_auth_window), CLI "
        "FortiVPN.exe, legacy FortiSSLVPNclient.exe, GUI przez "
        "_open_forticlient_gui (explorer_lnk → popen_clean_env)",
        "_autofill_forticlient: SendInput + wklejanie ze schowka",
        "fill_forticlient_token + is_2fa_prompt: obsługa tokenu",
        "get_forti_tunnels_from_registry: import profili",
        "_auto_disconnect_forticlient: klika Disconnect za użytkownika",
    ),
    caveats=(
        "autofill opiera się na ślepej kolejności Tab i stałych sleep()",
        "edycja klienta rozpoznawana po nazwie produktu (zależna od języka)",
        "launch explorer_lnk: przy przejętym skojarzeniu .lnk explorer otwiera "
        "Dokumenty zamiast klienta (NIENAPRAWIONE, reprodukowalne)",
        "launch explorer_lnk: explorer może uruchomić klienta po upływie 4 s — "
        "fallback popen_clean_env uruchomi wtedy drugą instancję (wyścig, "
        "NIENAPRAWIONE)",
        "launch explorer_lnk: wyjątek sondy tasklist tuż po explorerze wychodzi "
        "z legacy _open_forticlient_gui (NIENAPRAWIONE — decyzja o semantyce)",
    ),
)

GLOBALPROTECT = ProviderSpec(
    id="globalprotect",
    legacy_name="GlobalProtect",
    display_name="Palo Alto GlobalProtect",
    capabilities=(C.LAUNCH | C.CLI_CONNECT | C.CLI_DISCONNECT | C.MANUAL_AUTH
                  | C.CREDENTIAL_COPY | C.STATUS),
    automation=AutomationMode.MANUAL,
    status_sources=(StatusSource.CLI, StatusSource.ADAPTER, StatusSource.LOG),
    evidence=(
        "connect(): globalprotect.exe connect --portal, potem "
        "_open_globalprotect_gui (launch + druga aktywacja okna)",
        "disconnect(): globalprotect.exe disconnect",
        "get_status(): CLI show --status, adapter pangp, PanGPS.log",
    ),
    caveats=(
        "_autofill_globalprotect istnieje, ale NIE jest wywoływane — "
        "GlobalProtect nie ma dziś autofillu (martwy kod, świadomie zostawiony)",
    ),
)

STORMSHIELD = ProviderSpec(
    id="stormshield",
    legacy_name="Stormshield",
    display_name="Stormshield SSL VPN",
    capabilities=(C.LAUNCH | C.RESTORE_WINDOW | C.ELEVATED_LAUNCH | C.AUTOFILL
                  | C.AUTO_DISCONNECT | C.CREDENTIAL_COPY | C.STATUS),
    automation=AutomationMode.TAB_SEQUENCE,
    status_sources=(StatusSource.ADAPTER, StatusSource.SESSION_CACHE),
    evidence=(
        "connect(): okno widoczne → front, tray Qt, ShellExecuteW (UAC), "
        "fallback Popen; _autofill_stormshield wypełnia pola",
        "disconnect(): przywrócenie okna + Enter",
        "get_status(): adapter stormshield-tap / stormshield ssl vpn",
    ),
    caveats=(
        "brak znanych ścieżek instalacji (_PATHS['Stormshield'] == []) — bez "
        "app_path providera nie da się uruchomić",
        "get_status zwraca None, gdy tunel zestawiono poza HospitalHubem",
    ),
)

BARRACUDA = ProviderSpec(
    id="barracuda",
    legacy_name="Barracuda",
    display_name="Barracuda Network Access",
    capabilities=(C.LAUNCH | C.AUTOFILL | C.SYSTEM_CONNECT | C.CREDENTIAL_COPY
                  | C.STATUS),
    automation=AutomationMode.NATIVE_WINDOW,
    status_sources=(StatusSource.ADAPTER, StatusSource.SESSION_CACHE),
    evidence=(
        "connect(): os.startfile + _autofill_native_vpn_window "
        "(WM_SETTEXT, fallback SendInput); awaryjnie rasdial z poświadczeniami",
        "get_status(): adapter nacvpn/barracuda, potem cache sesji",
    ),
    caveats=(
        "brak znanych ścieżek instalacji — wymaga app_path",
        "rozłączenie wyłącznie ręczne",
    ),
)

SONICWALL = ProviderSpec(
    id="sonicwall_netextender",
    legacy_name="SonicWall NetExtender",
    display_name="SonicWall NetExtender",
    capabilities=(C.LAUNCH | C.RESTORE_WINDOW | C.MANUAL_AUTH | C.CREDENTIAL_COPY
                  | C.STATUS),
    automation=AutomationMode.MANUAL,
    status_sources=(StatusSource.ADAPTER,),
    evidence=(
        "connect(): wykrycie NetExtender.exe obok nxcli/NECLI, ubicie "
        "zawieszonej instancji, przywrócenie okna albo os.startfile",
        "get_status(): adapter sonicwall/netextender",
    ),
    caveats=(
        "cała maszyneria CLI (_nxcli_pty_run, _validate_cli) jest martwa — "
        "nic jej nie wywołuje, więc providera opisuje tylko launch + manual",
        "rozłączenie wyłącznie ręczne",
    ),
)

HILLSTONE = ProviderSpec(
    id="hillstone",
    legacy_name="Hillstone Secure Connect",
    display_name="Hillstone Secure Connect",
    capabilities=(C.LAUNCH | C.RESTORE_WINDOW | C.ELEVATED_LAUNCH | C.MANUAL_AUTH
                  | C.CREDENTIAL_COPY | C.STATUS),
    automation=AutomationMode.MANUAL,
    status_sources=(StatusSource.ADAPTER,),
    evidence=(
        "connect(): tray Qt gdy działa, inaczej ShellExecuteW (UAC) "
        "z fallbackiem Popen",
        "get_status(): adapter hillstone/virtualnet",
    ),
    caveats=("rozłączenie wyłącznie ręczne",),
)

WINDOWS_VPN = ProviderSpec(
    id="windows_vpn",
    legacy_name="Windows VPN",
    display_name="Windows VPN",
    capabilities=(C.SYSTEM_CONNECT | C.CLI_DISCONNECT | C.PROFILE_IMPORT),
    automation=AutomationMode.SYSTEM,
    status_sources=(),
    evidence=(
        "connect(): _windows_vpn_connect → rasdial async z fallbackiem rasphone",
        "disconnect(): rasdial /DISCONNECT",
    ),
    caveats=(
        "get_status() celowo zwraca None — rasdial nie widzi połączeń "
        "z nowych Ustawień Windows (_rasdial_active_connections jest martwe)",
        "poświadczenia pochodzą z profilu Windows, HospitalHub ich nie podaje",
    ),
)

GENERIC = ProviderSpec(
    id="generic",
    legacy_name="",
    display_name="Inny klient VPN",
    capabilities=(C.LAUNCH | C.MANUAL_AUTH | C.CREDENTIAL_COPY | C.STATUS),
    automation=AutomationMode.MANUAL,
    status_sources=(StatusSource.PROCESS,),
    evidence=(
        "connect(): gałąź domyślna — os.startfile(app_path)",
        "get_status(): sprawdzenie, czy proces działa",
    ),
    caveats=(
        "narzędzia zdalnego pulpitu (AnyDesk, TeamViewer…) celowo zwracają "
        "status None — działają cały czas, więc status nic nie znaczy",
    ),
)

SPECS: tuple[ProviderSpec, ...] = (
    FORTICLIENT, GLOBALPROTECT, STORMSHIELD, BARRACUDA, SONICWALL, HILLSTONE,
    WINDOWS_VPN, GENERIC,
)

BY_ID = {spec.id: spec for spec in SPECS}
BY_LEGACY_NAME = {spec.legacy_name: spec for spec in SPECS if spec.legacy_name}


def spec_for_legacy_name(name: str) -> ProviderSpec | None:
    """Find the declaration for a provider as stored in a vault."""
    return BY_LEGACY_NAME.get(str(name).strip())


def providers_with(capability: Capability) -> list[ProviderSpec]:
    return [spec for spec in SPECS if capability in spec.capabilities]
