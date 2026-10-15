"""Value types for the VPN provider contract.

These types describe *what a provider can do and what happened* — never how.
They carry machine-readable data only: no Polish UI strings, no credentials.
The UI layer turns a code into a sentence; the diagnostics layer turns a result
into trace data.  Both happen outside this module.

The vocabularies here are deliberately identical to the strings the existing
instrumentation in ``vpn_connect.py`` already writes (``automation_mode``,
``source``, ``error_code``).  Aligning them now means that when a provider is
eventually migrated, its traces keep the same shape and older traces stay
readable.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Flag, StrEnum, auto
from typing import Any

from diagnostics.redactor import allow_keys, find_secrets, is_secret_key

# Trace keys emitted by the result types below (declared where they are made).
allow_keys("requires_user_action", "strategies", "attempt_count",
           "route", "automation_pending", "phases", "launch_strategy",
           "login_entered", "password_entered", "blocked_at",
           "autofill_status", "two_factor_status",
           # two-factor: how it would be supplied, and what happened — the
           # token itself is never a trace value under any key.
           "mode", "manual_submit_required", "control_count", "line_index")

# --------------------------------------------------------------------------- #
# Capabilities                                                                 #
# --------------------------------------------------------------------------- #


class Capability(Flag):
    """What a provider is actually able to do.

    One flag per thing the current code really does for at least one provider.
    Deliberately *not* an idealised model: there is no ``DISCONNECT`` flag, for
    example, because half the providers can only tell the user to disconnect by
    hand — that is what :attr:`MANUAL_AUTH` and the absence of a flag mean.
    """

    NONE = 0
    #: Can start the client process (Popen / ShellExecute / startfile / .lnk).
    LAUNCH = auto()
    #: Can bring an already running client back from the tray / background.
    RESTORE_WINDOW = auto()
    #: Launch may trigger a UAC prompt (requireAdministrator manifest).
    ELEVATED_LAUNCH = auto()
    #: Connects through the client's own command line.
    CLI_CONNECT = auto()
    #: Disconnects through the client's own command line.
    CLI_DISCONNECT = auto()
    #: Connection is made by Windows itself (rasdial / phonebook profile).
    SYSTEM_CONNECT = auto()
    #: Fills the client's login form for the user.
    AUTOFILL = auto()
    #: Can press the client's Disconnect button for the user.
    AUTO_DISCONNECT = auto()
    #: Can put a token / OTP into the client's 2FA window.
    TWO_FACTOR = auto()
    #: Exposes a process whose stdout can be watched for prompts.
    PROCESS_MONITOR = auto()
    #: The user has to authenticate in the client themselves.
    MANUAL_AUTH = auto()
    #: Helps by copying the password to the clipboard.
    CREDENTIAL_COPY = auto()
    #: Can report a connection status.
    STATUS = auto()
    #: Can import connection profiles from the system (registry, phonebook).
    PROFILE_IMPORT = auto()

    def names(self) -> list[str]:
        """Sorted lowercase names — safe for traces and reports."""
        return sorted(flag.name.lower() for flag in Capability
                      if flag is not Capability.NONE and flag in self)


class AutomationMode(StrEnum):
    """How (if at all) the provider gets credentials into the client."""

    NONE = "none"
    MANUAL = "manual"                 # user types it themselves
    TAB_SEQUENCE = "tab_sequence"     # SendInput + blind Tab order
    WM_SETTEXT = "wm_settext"         # Win32 messages straight into controls
    NATIVE_WINDOW = "native_window"   # WM_SETTEXT with SendInput fallback
    CLI = "cli"                       # credentials passed to a command line
    SYSTEM = "system"                 # Windows supplies them from its profile


class StatusSource(StrEnum):
    """Where a status reading came from — part of the answer, not a detail."""

    ADAPTER = "adapter"
    CLI = "cli"
    LOG = "log"
    NETSTAT = "netstat"
    RASDIAL = "rasdial"
    PROCESS = "process"
    SESSION_CACHE = "session_cache"
    REGISTRY = "registry"
    SYSTEM = "system"
    UNKNOWN = "unknown"


class VpnState(StrEnum):
    CONNECTED = "connected"
    CONNECTING = "connecting"
    DISCONNECTED = "disconnected"
    UNKNOWN = "unknown"

    @classmethod
    def from_legacy(cls, value: str | None) -> "VpnState":
        """Map the legacy strings ('Connected' / None / ...) onto the enum."""
        if not value:
            return cls.UNKNOWN
        low = str(value).strip().lower()
        for member in cls:
            if member.value == low:
                return member
        return cls.UNKNOWN

    def to_legacy(self) -> str | None:
        """Back to what `vpn_connect.get_status` returns today."""
        if self is VpnState.UNKNOWN:
            return None
        return self.value.capitalize()


class DetectionState(StrEnum):
    NOT_INSTALLED = "not_installed"
    INSTALLED = "installed"
    #: Installed, but we lack what we would need to use it (e.g. Stormshield
    #: has no known install paths — without app_path there is nothing to run).
    INCOMPLETE = "incomplete"
    ERROR = "error"


# --------------------------------------------------------------------------- #
# Error codes                                                                  #
# --------------------------------------------------------------------------- #


class ErrorCode(StrEnum):
    """Stable, machine-readable failure reasons.

    Every value here is one the code already emits or one the contract needs;
    none were invented to look complete.  A provider may add its own code when
    something is genuinely specific to it, but it should reach for these first
    — a shared vocabulary is what makes traces from different machines
    comparable.
    """

    # discovery
    CLIENT_NOT_FOUND = "client-not-found"
    NO_CONFIGURATION = "no-configuration"
    UNSUPPORTED = "unsupported"
    UNSUPPORTED_PROVIDER = "unsupported-provider"
    # launching
    LAUNCH_FAILED = "launch-failed"
    LAUNCH_NO_PROCESS = "launch-no-process"
    #: The client's own process could not be created (Popen raised).
    PROCESS_START_FAILED = "process-start-failed"
    #: The process was created (a pid exists), only watching for it failed.
    PROCESS_OBSERVATION_FAILED = "process-started-but-observation-failed"
    STALE_PROCESS = "stale-process"
    ELEVATION_REQUIRED = "elevation-required"
    TRAY_ACTIVATION_FAILED = "tray-activation-failed"
    # windows / automation
    WINDOW_NOT_FOUND = "window-not-found"
    FOCUS_FAILED = "focus-failed"
    #: The window that would receive a secret is not owned by the client's process.
    TARGET_WINDOW_UNTRUSTED = "target-window-untrusted"
    #: A secret was not sent because its target could not be confirmed.
    SECRET_INPUT_BLOCKED = "secret-input-blocked"
    AUTOMATION_FAILED = "automation-failed"
    AUTOMATION_TIMEOUT = "automation-timeout"
    CONNECT_BUTTON_NOT_FOUND = "connect-button-not-found"
    NO_EDIT_CONTROLS = "no-edit-controls"
    # 2FA
    OTP_WINDOW_NOT_FOUND = "otp-window-not-found"
    OTP_FIELD_NOT_FOUND = "otp-field-not-found"
    OTP_TIMEOUT = "otp-timeout"
    # connecting
    CONNECT_FAILED = "connect-failed"
    CONNECT_TIMEOUT = "connect-timeout"
    CLI_FAILED = "cli-failed"
    CLI_REJECTED = "cli-rejected"
    DISCONNECT_FAILED = "disconnect-failed"
    # status / environment
    DETECTION_FAILED = "detection-failed"
    STATUS_UNKNOWN = "status-unknown"
    MANUAL_ACTION_REQUIRED = "manual-action-required"
    #: The user called the operation off (Stage 47).  Not a failure.
    CANCELLED = "cancelled"
    PYWIN32_MISSING = "pywin32-missing"
    RASDIAL_MISSING = "rasdial-missing"


# --------------------------------------------------------------------------- #
# Safety guard for result payloads                                             #
# --------------------------------------------------------------------------- #


class SecretInResultError(ValueError):
    """A result tried to carry something that looks like a credential."""


_SCALARS = (str, int, float, bool, type(None))


def guard_metadata(metadata: dict, where: str = "metadata") -> dict:
    """Reject credentials before they can reach a result object.

    Uses the diagnostics redactor — there is exactly one definition of "this
    key smells like a secret" in the project and this is not a second one.
    Raising (rather than scrubbing) is deliberate: a provider putting a
    password in a result is a programming error, and we want it to surface in
    tests, not to be silently cleaned up at runtime.
    """
    if not metadata:
        return {}
    for key, value in metadata.items():
        if not isinstance(key, str):
            raise SecretInResultError(f"{where}: klucz musi być tekstem: {key!r}")
        if is_secret_key(key):
            raise SecretInResultError(
                f"{where}: pole '{key}' wygląda na sekret — wynik providera "
                "nie może przenosić poświadczeń")
        if isinstance(value, str) and find_secrets(value):
            raise SecretInResultError(
                f"{where}: wartość pola '{key}' wygląda na sekret")
        if not isinstance(value, (*_SCALARS, list, tuple)):
            raise SecretInResultError(
                f"{where}: pole '{key}' ma niedozwolony typ {type(value).__name__} "
                "— dozwolone są tylko proste wartości")
    return dict(metadata)


# --------------------------------------------------------------------------- #
# Request                                                                      #
# --------------------------------------------------------------------------- #


@dataclass
class VpnRequest:
    """Everything a provider needs for one operation.

    Mirrors the arguments the legacy `vpn_connect.connect()` already takes, so
    a bridge is a straight mapping rather than a translation.  The two secret
    fields carry ``repr=False``: an accidental ``repr(request)`` in a log line
    or an exception message must not print a password.
    """

    provider_id: str
    profile_name: str = ""
    server: str = ""
    port: str = ""
    login: str = ""
    password: str = field(default="", repr=False)
    group: str = ""
    domain: str = ""
    app_path: str = ""
    token: str = field(default="", repr=False)
    autofill: bool = True
    #: The profile's "requires 2FA" flag.  Distinct from ``token``: the UI
    #: never has a token up front — it decides *how* to ask for one from this
    #: flag (vpn profile field ``requires_2fa``).
    requires_2fa: bool = False

    def to_trace_meta(self) -> dict:
        """Safe description of the request for diagnostics.

        Facts about the credentials, never the credentials.
        """
        return {
            "provider": self.provider_id,
            "profile_name": self.profile_name,
            "autofill": bool(self.autofill),
            "has_server": bool(self.server),
            "has_app_path": bool(self.app_path),
            "has_credentials": bool(self.login or self.password),
            "requires_2fa": bool(self.token or self.requires_2fa),
        }


# --------------------------------------------------------------------------- #
# Results                                                                      #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class ProviderResult:
    """Base for every operation result."""

    provider_id: str
    success: bool = False
    error_code: str | None = None
    metadata: dict = field(default_factory=dict)

    def __post_init__(self):
        object.__setattr__(self, "metadata",
                           guard_metadata(self.metadata,
                                          f"{type(self).__name__}.metadata"))

    @property
    def ok(self) -> bool:
        return bool(self.success)

    def to_trace_data(self) -> dict:
        """Flat, safe dict for `diagnostics.vpn.VpnTrace`."""
        data: dict[str, Any] = {}
        for key, value in self._trace_fields().items():
            if value is None or value == "":
                continue
            data[key] = value.value if isinstance(value, StrEnum) else value
        data.update(self.metadata)
        return data

    def _trace_fields(self) -> dict:
        return {}


@dataclass(frozen=True)
class DetectionResult(ProviderResult):
    state: DetectionState = DetectionState.NOT_INSTALLED
    version: str | None = None
    edition: str | None = None
    path: str | None = None
    source: str | None = None

    @property
    def installed(self) -> bool:
        return self.state in (DetectionState.INSTALLED, DetectionState.INCOMPLETE)

    def _trace_fields(self) -> dict:
        return {"state": self.state, "installed": self.installed,
                "app_version": self.version, "edition": self.edition,
                "exe_path": self.path, "source": self.source}


@dataclass(frozen=True)
class LaunchAttempt:
    """One launch strategy as it was tried — results keep them in order.

    ``started`` means "a process of the client's image was seen afterwards",
    which is how the legacy code decides; it does not prove that *this*
    attempt created it — None when it could not be observed at all.
    ``process_started`` is narrower and certain: the spawn call of this
    strategy succeeded (``explorer.exe`` for ``explorer_lnk``, the client
    itself for ``popen_clean_env``).  No paths, no command lines.
    """

    strategy: str
    started: bool | None = None
    pid: int | None = None
    #: This attempt ran *because* an earlier attempt failed.
    fallback: bool = False
    error_code: str | None = None
    #: Exception type or a short label — never an exception message.
    reason_code: str | None = None
    process_started: bool | None = None
    #: The process was created but watching for it raised.
    observation_failed: bool = False
    #: Strategy this attempt fell back from (only when ``fallback``).
    fallback_from: str | None = None
    #: Where the working directory came from (``launch_rules.CWD_*``).
    cwd_source: str | None = None

    def to_trace_data(self) -> dict:
        return {key: value for key, value in (
            ("strategy", self.strategy), ("started", self.started),
            ("pid", self.pid), ("fallback", self.fallback or None),
            ("error_code", self.error_code), ("reason_code", self.reason_code),
            ("process_started", self.process_started),
            ("observation_failed", self.observation_failed or None),
            ("fallback_from", self.fallback_from),
            ("cwd_source", self.cwd_source),
        ) if value is not None}


@dataclass(frozen=True)
class LaunchResult(ProviderResult):
    """Outcome of starting a client.  The top-level fields describe the
    strategy that decided the outcome (the last attempt); ``attempts`` keeps
    the whole sequence, e.g. ``explorer_lnk`` then ``popen_clean_env``."""

    strategy: str | None = None
    started: bool | None = None
    pid: int | None = None
    fallback: bool = False
    #: The client is up but the user still has to act in its window.
    requires_user_action: bool = False
    attempts: tuple[LaunchAttempt, ...] = ()
    #: See :class:`LaunchAttempt` — copied from the deciding attempt.
    process_started: bool | None = None
    observation_failed: bool = False

    def _trace_fields(self) -> dict:
        last = self.attempts[-1] if self.attempts else None
        return {"strategy": self.strategy, "started": self.started,
                "pid": self.pid, "fallback": self.fallback or None,
                "requires_user_action": self.requires_user_action or None,
                "process_started": self.process_started,
                "observation_failed": self.observation_failed or None,
                "fallback_from": last.fallback_from if last else None,
                "cwd_source": last.cwd_source if last else None,
                "strategies": ",".join(a.strategy for a in self.attempts) or None,
                "attempt_count": len(self.attempts) or None}


class TwoFactorMode(StrEnum):
    """How a second factor can be supplied after this connect, if at all.

    Describes what the connect made *possible*; asking the user is the
    caller's job.  Values mirror the mechanisms the application has today.
    """

    NONE = "none"                       # no second factor expected
    PROCESS_STDOUT = "process_stdout"   # a monitored process prompts; token → stdin
    AUTH_WINDOW = "auth_window"         # the client's auth window gets a token field
    IN_CLIENT = "in_client"             # the user types it into the client himself


@dataclass(frozen=True)
class ConnectStep:
    """One phase a connect went through, in order.  No values, no paths."""

    phase: str
    #: "ok" — done / found; "none" — probed, nothing there; "failed".
    status: str
    error_code: str | None = None
    #: Exception type or a short label — never an exception message.
    reason_code: str | None = None

    def to_trace_data(self) -> dict:
        return {key: value for key, value in (
            ("phase", self.phase), ("status", self.status),
            ("error_code", self.error_code), ("reason_code", self.reason_code),
        ) if value is not None}


@dataclass(frozen=True)
class ConnectResult(ProviderResult):
    """Outcome of a connect.

    ``success`` means the connect was *initiated* (a CLI started, credentials
    submitted, automation started or the client opened for the user) — not
    that the tunnel is up.  Confirmation is a status question.
    """

    state: VpnState = VpnState.UNKNOWN
    automation: AutomationMode = AutomationMode.NONE
    requires_user_action: bool = False
    #: Live handle (e.g. a Popen whose stdout carries 2FA prompts). Never
    #: serialised, never compared — it is not data.
    monitor: Any = field(default=None, repr=False, compare=False)
    #: Which way the connect went (provider-specific names, e.g. "cli").
    route: str | None = None
    #: Automation was started in the background; its outcome is not known yet.
    automation_pending: bool = False
    two_factor: TwoFactorMode = TwoFactorMode.NONE
    #: Phases in the order they ran — where a failure happened, what was skipped.
    steps: tuple[ConnectStep, ...] = ()
    #: The launch this connect performed, when it had to start the client.
    launch: LaunchResult | None = None
    #: The form fill this connect ran, when it filled one.  ``None`` means it
    #: was skipped, or started in the background with an unknown outcome.
    autofill: "AutofillResult | None" = None
    #: What became of the second factor.  ``None`` means the connect did not
    #: get that far, or left it to the caller (``two_factor`` says how).
    two_factor_result: "TwoFactorResult | None" = None

    def _trace_fields(self) -> dict:
        return {"state": self.state, "automation_mode": self.automation,
                "process_monitor": self.monitor is not None or None,
                "result": "manual-action" if self.requires_user_action else None,
                "route": self.route,
                "automation_pending": self.automation_pending or None,
                "two_factor": (self.two_factor
                               if self.two_factor is not TwoFactorMode.NONE else None),
                "two_factor_status": (self.two_factor_result.status
                                      if self.two_factor_result else None),
                "autofill_status": (self.autofill.status if self.autofill else None),
                "phases": ",".join(s.phase for s in self.steps) or None,
                "launch_strategy": self.launch.strategy if self.launch else None}


@dataclass(frozen=True)
class DisconnectResult(ProviderResult):
    method: str | None = None
    automation: AutomationMode = AutomationMode.NONE

    def _trace_fields(self) -> dict:
        return {"method": self.method, "automation_mode": self.automation}


@dataclass(frozen=True)
class StatusResult(ProviderResult):
    state: VpnState = VpnState.UNKNOWN
    source: StatusSource = StatusSource.UNKNOWN

    @property
    def connected(self) -> bool:
        return self.state is VpnState.CONNECTED

    def _trace_fields(self) -> dict:
        return {"state": self.state, "source": self.source}


class AutofillStatus(StrEnum):
    """What became of an autofill attempt."""

    DONE = "done"                 # login and password entered, form submitted
    BLOCKED = "blocked"           # a security check refused before a secret
    NO_TARGET = "no-target"       # no verified FortiClient window found
    NO_FOCUS = "no-focus"         # window found but focus could not be taken
    FAILED = "failed"             # unexpected error
    #: The session was called off; nothing further was sent (Stage 47).
    CANCELLED = "cancelled"


@dataclass(frozen=True)
class AutofillResult(ProviderResult):
    """Outcome of entering login + password (no 2FA — that is a later stage).

    ``success`` is true only for :attr:`AutofillStatus.DONE`.  The booleans let
    a future ``connect()`` tell "password never left the app" (blocked before
    it) from "password was submitted".
    """

    status: AutofillStatus = AutofillStatus.FAILED
    login_entered: bool = False
    password_entered: bool = False
    #: Phase at which a security check refused (e.g. "password-paste").
    blocked_at: str | None = None

    def _trace_fields(self) -> dict:
        return {"status": self.status, "login_entered": self.login_entered,
                "password_entered": self.password_entered,
                "blocked_at": self.blocked_at}


class TwoFactorStatus(StrEnum):
    """What became of the second authentication factor.

    Separate from :class:`TwoFactorMode`, which says *how* a token could be
    supplied: the mode is the plan, the status is what actually happened.
    """

    NOT_REQUIRED = "not-required"      # no second factor for this connect
    TOKEN_REQUIRED = "token-required"  # a token is needed and nobody supplied one
    MANUAL_REQUIRED = "manual-required"  # the user authenticates in the client
    SUBMITTED = "submitted"            # the token was handed to the client
    BLOCKED = "blocked"                # a security check refused before the token
    #: Reserved.  Nothing in the application learns whether a token was
    #: accepted — the legacy flow reports "connect initiated" and the UI polls
    #: the tunnel status afterwards — so no migrated path returns this yet.
    REJECTED = "rejected"
    FAILED = "failed"                  # window/field/channel error


@dataclass(frozen=True)
class TwoFactorResult(ProviderResult):
    """Outcome of supplying (or deliberately not supplying) a second factor.

    ``success`` is true only for :attr:`TwoFactorStatus.SUBMITTED` and
    :attr:`TwoFactorStatus.NOT_REQUIRED` — both mean "connect may go on".
    The token itself never appears here, in any field or in ``metadata``:
    the only facts recorded are *whether* one was sent and *where* a check
    stopped it.
    """

    status: TwoFactorStatus = TwoFactorStatus.FAILED
    #: The mechanism this attempt used (or would have used).
    mode: TwoFactorMode = TwoFactorMode.NONE
    #: True once the client has the token; says nothing about acceptance.
    submitted: bool = False
    #: Entered, but the client's Connect button was not pressed for us.
    manual_submit_required: bool = False
    #: Phase at which a security check refused (e.g. "submit").
    blocked_at: str | None = None

    def _trace_fields(self) -> dict:
        return {"status": self.status, "mode": self.mode,
                "submitted": self.submitted,
                "manual_submit_required": self.manual_submit_required,
                "blocked_at": self.blocked_at}


def unsupported(provider_id: str, result_type: type = ProviderResult,
                **kwargs: Any):
    """Uniform "this provider does not do that" answer."""
    return result_type(provider_id=provider_id, success=False,
                       error_code=ErrorCode.UNSUPPORTED.value, **kwargs)
