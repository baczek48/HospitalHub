"""The VPN provider contract.

A provider answers questions about one VPN client: can I see it, can I start
it, can I log in for the user, what is the connection doing.  It returns data
(:mod:`vpn.types`), never user-facing text, and it never logs on its own — the
diagnostics package owns tracing and redaction.

Why an ABC with working defaults rather than a Protocol full of abstract
methods: most clients cannot do most things.  SonicWall cannot disconnect,
Hillstone cannot autofill, Windows VPN has nothing to detect.  Forcing every
provider to implement every method would fill the codebase with stubs that
raise, and the caller would have to guard every call anyway.  Here a provider
declares what it can do through :meth:`capabilities`, implements only that, and
everything else answers with a well-formed "unsupported" result.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, ClassVar

from .types import (
    AutomationMode, Capability, ConnectResult, DetectionResult, DetectionState,
    DisconnectResult, ErrorCode, LaunchResult, StatusResult, StatusSource,
    VpnRequest, VpnState,
)

__all__ = ["VpnProvider", "LegacyVpnProviderAdapter", "check_contract",
           "record_result"]


class VpnProvider(ABC):
    """Base class for every VPN provider."""

    #: Stable identifier: lowercase, ``[a-z0-9_]``. Never shown to the user,
    #: never changed — it ends up in traces and, later, in configuration.
    id: ClassVar[str] = ""
    #: Name as the user knows the product.
    display_name: ClassVar[str] = ""
    #: The exact string this provider is stored as in existing vaults
    #: (``models.VPN_PROVIDERS_BUILTIN``), so a migration can find it.
    legacy_name: ClassVar[str] = ""

    # -- required ---------------------------------------------------------- #

    @abstractmethod
    def capabilities(self) -> Capability:
        """What this provider can actually do."""

    @abstractmethod
    def detect(self, request: VpnRequest) -> DetectionResult:
        """Is the client installed, and do we have what we need to use it?"""

    # -- optional ---------------------------------------------------------- #

    def launch(self, request: VpnRequest) -> LaunchResult:
        """Start (or surface) the client without connecting."""
        return LaunchResult(provider_id=self.id, success=False,
                            error_code=ErrorCode.UNSUPPORTED.value)

    def connect(self, request: VpnRequest) -> ConnectResult:
        return ConnectResult(provider_id=self.id, success=False,
                             error_code=ErrorCode.UNSUPPORTED.value)

    def disconnect(self, request: VpnRequest) -> DisconnectResult:
        return DisconnectResult(provider_id=self.id, success=False,
                                error_code=ErrorCode.UNSUPPORTED.value)

    def status(self, request: VpnRequest) -> StatusResult:
        return StatusResult(provider_id=self.id, success=False,
                            state=VpnState.UNKNOWN,
                            source=StatusSource.UNKNOWN,
                            error_code=ErrorCode.UNSUPPORTED.value)

    def diagnostics(self, request: VpnRequest | None = None) -> dict:
        """Safe facts about this provider for a diagnostics report.

        Returns plain data. Collecting, redacting and writing it is the job of
        the ``diagnostics`` package — a provider never writes a file.
        """
        data: dict[str, Any] = {
            "provider": self.id,
            "capabilities": self.capabilities().names(),
        }
        if request is not None:
            try:
                detection = self.detect(request)
            except Exception as exc:                  # detect must not escape
                data["error_code"] = type(exc).__name__
            else:
                data.update(detection.to_trace_data())
        return data

    # -- helpers ----------------------------------------------------------- #

    def supports(self, capability: Capability) -> bool:
        return capability in self.capabilities()

    @property
    def automation_mode(self) -> AutomationMode:
        """Default automation for this provider; override when it varies."""
        caps = self.capabilities()
        if Capability.AUTOFILL in caps:
            return AutomationMode.TAB_SEQUENCE
        if Capability.SYSTEM_CONNECT in caps:
            return AutomationMode.SYSTEM
        if Capability.CLI_CONNECT in caps:
            return AutomationMode.CLI
        return AutomationMode.MANUAL

    def __repr__(self) -> str:          # never prints a request/credential
        return f"<{type(self).__name__} id={self.id!r}>"


# --------------------------------------------------------------------------- #
# Diagnostics bridge                                                           #
# --------------------------------------------------------------------------- #

def record_result(trace, step: str, result) -> None:
    """Write a provider result into an existing diagnostics trace.

    `trace` is whatever :func:`diagnostics.vpn.start` returned (including the
    no-op object). This function exists so providers never touch the trace API
    directly and never invent their own step payloads.
    """
    if trace is None or result is None:
        return
    status = "ok" if getattr(result, "ok", False) else "fail"
    try:
        trace.step(step, status, error_code=getattr(result, "error_code", None),
                   **result.to_trace_data())
    except Exception:
        # Diagnostics observes; it never breaks the operation it observes.
        pass


# --------------------------------------------------------------------------- #
# Contract check (used by tests and by future migrations)                      #
# --------------------------------------------------------------------------- #

def check_contract(provider: VpnProvider) -> list[str]:
    """Return a list of contract violations; empty means the provider is sane."""
    problems: list[str] = []
    pid = getattr(provider, "id", "")
    if not pid or not isinstance(pid, str):
        problems.append("brak stabilnego id")
    elif not all(ch.islower() or ch.isdigit() or ch == "_" for ch in pid):
        problems.append(f"id {pid!r} musi być w formacie a-z0-9_")
    if not getattr(provider, "display_name", ""):
        problems.append("brak display_name")

    try:
        caps = provider.capabilities()
    except Exception as exc:
        problems.append(f"capabilities() rzuca {type(exc).__name__}")
        return problems
    if not isinstance(caps, Capability):
        problems.append("capabilities() musi zwracać Capability")
        return problems

    base = VpnProvider
    overridden = {name for name in ("launch", "connect", "disconnect", "status")
                  if type(provider).__dict__.get(name) is not None
                  or getattr(type(provider), name) is not getattr(base, name)}

    connect_caps = (Capability.CLI_CONNECT | Capability.SYSTEM_CONNECT
                    | Capability.AUTOFILL)
    if caps & connect_caps and "connect" not in overridden:
        problems.append("deklaruje zdolność łączenia, ale nie implementuje connect()")
    # LAUNCH is served either by launch() itself (a migrated launcher, e.g.
    # FortiClient) or through connect() (legacy-shaped: "connecting" = opening
    # the client window for the user).  Neither of them is a contract breach.
    if (Capability.LAUNCH in caps
            and not {"launch", "connect"} & overridden):
        problems.append("deklaruje LAUNCH, ale nie implementuje launch() ani connect()")
    if Capability.STATUS in caps and "status" not in overridden:
        problems.append("deklaruje STATUS, ale nie implementuje status()")
    if (caps & (Capability.CLI_DISCONNECT | Capability.AUTO_DISCONNECT)
            and "disconnect" not in overridden):
        problems.append("deklaruje rozłączanie, ale nie implementuje disconnect()")
    return problems


# --------------------------------------------------------------------------- #
# Legacy bridge                                                                #
# --------------------------------------------------------------------------- #

class LegacyVpnProviderAdapter(VpnProvider):
    """Wraps the existing ``vpn_connect`` module behind the new contract.

    This is the migration path: providers move one at a time, and until one is
    rewritten it can be served by this adapter, which **delegates** to the old
    functions and only translates their answers into result objects.  It copies
    no VPN logic.

    Nothing registers or uses it yet — the production path still calls
    ``vpn_connect`` directly, exactly as before.  The legacy module is imported
    lazily so that merely importing :mod:`vpn` pulls in nothing heavy.

    The Polish message the legacy layer returns is kept in
    :attr:`last_message` rather than in the result: it is UI text (and may name
    a server), so it must not end up in a trace.
    """

    def __init__(self, provider_id: str, legacy_name: str, display_name: str,
                 capabilities: Capability, legacy_module: Any = None,
                 automation: AutomationMode = AutomationMode.MANUAL):
        self.id = provider_id
        self.legacy_name = legacy_name
        self.display_name = display_name
        self._capabilities = capabilities
        self._automation = automation
        self._module = legacy_module
        self.last_message: str = ""

    # -- plumbing ---------------------------------------------------------- #

    @property
    def legacy(self):
        if self._module is None:
            import vpn_connect                      # lazy: only when used
            self._module = vpn_connect
        return self._module

    def capabilities(self) -> Capability:
        return self._capabilities

    @property
    def automation_mode(self) -> AutomationMode:
        return self._automation

    # -- contract ---------------------------------------------------------- #

    def detect(self, request: VpnRequest) -> DetectionResult:
        """Legacy has no detect(); the closest honest answer is "we don't know".

        Detection in the old module is woven into connect(), so reporting
        anything else here would be an invention. A migrated provider replaces
        this with a real implementation.
        """
        state = (DetectionState.INCOMPLETE if request.app_path
                 else DetectionState.NOT_INSTALLED)
        return DetectionResult(provider_id=self.id, success=bool(request.app_path),
                               state=state, source="legacy",
                               error_code=None if request.app_path
                               else ErrorCode.NO_CONFIGURATION.value)

    def connect(self, request: VpnRequest) -> ConnectResult:
        ok, message, monitor = self._call_connect(request)
        self.last_message = message or ""
        return ConnectResult(
            provider_id=self.id, success=bool(ok),
            state=VpnState.CONNECTING if ok else VpnState.UNKNOWN,
            automation=self._automation if request.autofill else AutomationMode.MANUAL,
            requires_user_action=bool(ok) and self._automation is AutomationMode.MANUAL,
            monitor=monitor,
            error_code=None if ok else ErrorCode.CONNECT_FAILED.value,
            metadata={"source": "legacy"},
        )

    def _call_connect(self, request: VpnRequest):
        legacy = self.legacy
        if hasattr(legacy, "connect_monitored"):
            return legacy.connect_monitored(
                self.legacy_name, request.server, request.port, request.login,
                request.password, request.group, request.domain,
                request.app_path, request.profile_name, request.token,
                request.autofill)
        ok, message = legacy.connect(
            self.legacy_name, request.server, request.port, request.login,
            request.password, request.group, request.domain, request.app_path,
            request.profile_name, request.autofill)
        return ok, message, None

    def disconnect(self, request: VpnRequest) -> DisconnectResult:
        ok, message = self.legacy.disconnect(
            self.legacy_name, request.server, request.app_path,
            request.profile_name)
        self.last_message = message or ""
        return DisconnectResult(
            provider_id=self.id, success=bool(ok), method="legacy",
            automation=self._automation,
            error_code=None if ok else ErrorCode.DISCONNECT_FAILED.value,
        )

    def status(self, request: VpnRequest) -> StatusResult:
        raw = self.legacy.get_status(self.legacy_name, request.app_path,
                                     request.profile_name, request.server)
        state = VpnState.from_legacy(raw)
        return StatusResult(
            provider_id=self.id, success=state is not VpnState.UNKNOWN,
            state=state, source=StatusSource.UNKNOWN,
            error_code=None if state is not VpnState.UNKNOWN
            else ErrorCode.STATUS_UNKNOWN.value,
            metadata={"source": "legacy"},
        )
