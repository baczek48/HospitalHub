"""What a VPN card hands a V2 provider, and what it gets back.  Wired, disarmed.

Stage 46, re-read in Stage 56.  ``ui/vpn_panel.py`` **does** call this module
(Stage 52): every click asks :func:`select_connect_route` first, and goes to
``vpn_connect.connect_monitored`` only because that gate answers ``legacy`` for
every provider today.  This module is the VPN-layer half of the switch-over:

* :func:`select_connect_route` — **the feature gate**.  Legacy for every
  provider, and legacy for FortiClient too unless
  :attr:`FortiClientProvider.CONNECT_ENABLED` is *exactly* ``True``.
* :func:`build_request` — a vault profile, as the provider's request.  The
  mapping mirrors the arguments the panel passes to the legacy call today.
* :class:`PanelConnectSession` — one connect: owns the
  :class:`CancellationToken`, forwards the activation states to whoever
  observes, and runs ``connect()`` exactly once.
* :func:`classify_connect_result` — a :class:`ConnectResult`, reduced to the
  one fact a card can show (:class:`PanelOutcome`).  Codes only: turning a
  code into Polish is the UI's job (``ui/vpn_v2_connect.py``), as everywhere
  else in this package.

What still stands between a click and the new flow
-------------------------------------------------
**One barrier, not two.**  Until Stage 52 there were two — the gate answered
"legacy" *and* nothing called this module — and older revisions of this
docstring still promised the second one.  It is gone: the panel calls the
bridge on every click.  What keeps production on the legacy path is the gate
alone, and the gate is exactly the provider's ``CONNECT_ENABLED`` being
literally ``True``.  Flipping one flag is therefore the whole cutover, with no
further edit standing in the way — which is why it is a deliberate, reviewed
decision and not a tidy-up.

What a session does not do
--------------------------
It never builds the real runtime while the provider is disarmed — the check is
made *before* :meth:`FortiClientProvider.connect_runtime` is called, so a
stray session cannot even construct the object that owns ``SendInput``.  Tests
supply a ``runtime_factory`` over a fake machine instead.

Cancellation is honoured where the flow can honour it: at the activation gate
and at every guarded operation of the fill, which together cover the GUI route
up to and including the Enter.  On the CLI route the token is read once, before
the process is started (Stage 47); after that only the stdout watch can stop,
and only between lines (see :data:`KNOWN_GAPS`).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from .providers.activation_gate import ActivationState, CancellationToken
from .providers.barracuda import BarracudaProvider
from .providers.forticlient import FortiClientProvider
from .providers.forticlient_2fa import watch_for_challenge
from .providers.stormshield import StormshieldProvider
from .providers.forticlient_connect import (
    ENTRY_CONNECT_MONITORED, PHASE_AWAIT_ACTIVATION, ROUTE_CLI,
    ROUTE_CLI_MONITORED, ROUTE_LEGACY_CLIENT,
)
from .providers.process_channel import PopenProcessChannel
from .registry import default_registry
from .types import (
    AutofillStatus, AutomationMode, ErrorCode, TwoFactorMode, TwoFactorStatus,
    VpnRequest,
)

__all__ = ["ROUTE_LEGACY", "ROUTE_FORTICLIENT_V2", "ROUTE_STORMSHIELD_V2",
           "ROUTE_BARRACUDA_V2", "V2_PROVIDERS", "v2_route_for",
           "v2_provider_id_for", "resolve_v2_provider",
           "select_connect_route", "build_request", "PanelOutcome",
           "PanelConnectOutcome", "classify_connect_result",
           "PanelConnectSession", "KNOWN_GAPS", "MonitorPhase",
           "TwoFactorOutcome", "TwoFactorMonitorSession"]

#: Which connect a card click would go through.
ROUTE_LEGACY = "legacy"
#: Provider-scoped V2 route values: ``"<provider id>-v2"``.  The FortiClient one
#: keeps its historic spelling for callers that reference it directly.
ROUTE_FORTICLIENT_V2 = "forticlient-v2"
ROUTE_STORMSHIELD_V2 = "stormshield-v2"
ROUTE_BARRACUDA_V2 = "barracuda-v2"


#: The providers that *have* a V2 implementation, keyed by their stable catalog
#: ``legacy_name`` (the exact string a vault stores; see :mod:`vpn.catalog`).
#:
#: **Membership means "an implementation exists", never "it is on".**  Whether a
#: provider actually routes to V2 is a second, independent decision — its own
#: ``CONNECT_ENABLED`` class flag — so importing a provider class, or adding it
#: here, can never by itself send a click to V2.  This map is deliberately *not*
#: :data:`vpn.default_registry`: the registry is the production *cutover* set,
#: while this is "which V2 code paths exist" — the two are kept apart on purpose
#: (a provider can be implemented, and gated here, long before it is registered).
#:
#: Resolution is by exact key only: no fuzzy match, no substring, no fallback.
V2_PROVIDERS: dict[str, type] = {
    FortiClientProvider.legacy_name: FortiClientProvider,   # "FortiClient"
    StormshieldProvider.legacy_name: StormshieldProvider,   # "Stormshield"
    BarracudaProvider.legacy_name: BarracudaProvider,       # "Barracuda"
}


#: The same three implementations keyed by their stable **id** (``cls.id``), so
#: a :class:`VpnRequest` — which carries ``provider_id`` — can be resolved back
#: to its class.  Built from :data:`V2_PROVIDERS`, so the two never drift.
_V2_BY_ID: dict[str, type] = {cls.id: cls for cls in V2_PROVIDERS.values()}


def v2_route_for(provider_id: str) -> str:
    """The route value a given provider id uses when armed."""
    return f"{provider_id}-v2"


def v2_provider_id_for(provider_name) -> str:
    """A vault ``profile.provider`` (a ``legacy_name``) → its stable ``id``.

    Exact match against :data:`V2_PROVIDERS`; anything else — a non-V2 provider,
    an unknown or hostile name — yields ``""`` (fail-closed), which
    :class:`PanelConnectSession` then declines.
    """
    try:
        cls = V2_PROVIDERS.get(provider_name)
    except Exception:
        return ""
    return cls.id if cls is not None else ""


def resolve_v2_provider(provider_id, app_path: str = ""):
    """A ``provider_id`` → a freshly constructed V2 provider, or ``None``.

    **Concept C is separate from A and B.**  Membership in this map means "a V2
    implementation exists and can be built" (A/B) — never "it is on" (C, the
    ``CONNECT_ENABLED`` flag, checked elsewhere).  Resolution is by exact id,
    order-independent (a dict, not a registry scan), and fail-closed: an unknown
    id or any construction error returns ``None``, and the caller declines
    rather than falling back to some other provider.

    Deliberately **not** :data:`vpn.default_registry`: the registry is the
    production *cutover* set (still ``['forticlient']``), while this resolver is
    "which V2 implementations can be constructed" — the two are kept apart on
    purpose (see the module docstring on registration vs cutover).

    ``app_path`` is the profile's own executable path (Stage 55).  Providers
    that anchor trust to a *configured* directory — Stormshield and Barracuda —
    are told about it through their own ``with_app_path``; FortiClient has no
    such method (its install directory comes from its registry detection) and is
    simply left alone.  Passing it widens nothing by itself: the provider still
    accepts the directory only when it sits under Program Files, which is where
    the trust comes from.  Without this, a site whose client lives outside the
    known install directories would have its verified window refused under V2
    while the legacy path accepted it.
    """
    try:
        cls = _V2_BY_ID.get(provider_id)
        if cls is None:
            return None
        provider = cls()
        configure = getattr(provider, "with_app_path", None)
        if app_path and callable(configure):
            # Returns self by contract; keep the instance either way.
            configured = configure(app_path)
            if configured is not None:
                provider = configured
        return provider
    except Exception:
        # Including a failure to read the configured path: the trust anchor is
        # then unknown, and unknown means decline.
        return None


def select_connect_route(provider_name, *, providers: dict | None = None) -> str:
    """The provider-scoped feature gate.  Fail-closed: any doubt means legacy.

    Resolves ``provider_name`` against the explicit :data:`V2_PROVIDERS` map by
    **exact** ``legacy_name`` — a provider with no V2 implementation, an unknown
    name, or a resolution error all return :data:`ROUTE_LEGACY`.  A resolved
    provider routes to its own ``"<id>-v2"`` only when its ``CONNECT_ENABLED`` is
    *exactly* ``True`` (``1``, ``"yes"`` or a mock do not count), and each
    provider's flag is independent of every other's.

    ``providers`` overrides the map for tests; production always uses
    :data:`V2_PROVIDERS`.
    """
    table = providers if providers is not None else V2_PROVIDERS
    try:
        provider_class = table.get(provider_name)
    except Exception:
        # A name that cannot even be looked up (unhashable, hostile) is legacy.
        return ROUTE_LEGACY
    if provider_class is None:
        # Unknown provider, or one without a V2 implementation.
        return ROUTE_LEGACY
    try:
        enabled = getattr(provider_class, "CONNECT_ENABLED", False)
        provider_id = provider_class.id
    except Exception:
        return ROUTE_LEGACY
    if enabled is not True:
        return ROUTE_LEGACY
    return v2_route_for(provider_id)


def build_request(profile, *, app_path: str, autofill: bool) -> VpnRequest:
    """The same values ``_connect_card`` hands to the legacy connect, plus 2FA.

    ``app_path`` is passed in already resolved (profile path, else the global
    provider path) because resolving it is the panel's existing job.  The token
    stays empty, as both panels pass it today.
    """
    return VpnRequest(
        # The provider the *profile* names — resolved to its stable id — not a
        # hardcoded FortiClient.  A non-V2 provider yields "" and the session
        # declines (this path is only reached for an armed V2 provider anyway).
        provider_id=v2_provider_id_for(getattr(profile, "provider", "")),
        profile_name=profile.profile_name or "",
        server=profile.server or "",
        port=profile.port or "",
        login=profile.login or "",
        password=profile.password or "",
        group=profile.group or "",
        domain=profile.domain or "",
        app_path=app_path or "",
        autofill=bool(autofill),
        requires_2fa=bool(getattr(profile, "requires_2fa", False)),
    )


class PanelOutcome(StrEnum):
    """The one thing a card needs to know about a finished V2 connect.

    The four activation endings reuse the gate's own state names, so the
    sentences the activation prompt already has apply unchanged.
    """

    #: Login and password entered and the form submitted.
    SUBMITTED = "submitted"
    #: Credentials entered; the second factor is still the user's move.
    TWO_FACTOR_REQUIRED = "two-factor-required"
    #: FortiVPN CLI / the legacy SSL-VPN client was started.
    CLI_STARTED = "cli-started"
    #: Autofill off: the client is open and the password is on the clipboard.
    MANUAL = "manual"
    #: Initiated some other way (e.g. a system without an autofill result).
    STARTED = "started"
    ACTIVATION_TIMEOUT = ActivationState.ACTIVATION_TIMEOUT.value
    NO_TARGET = ActivationState.NO_TARGET.value
    TARGET_CHANGED = ActivationState.TARGET_CHANGED.value
    CANCELLED = ActivationState.CANCELLED.value
    #: Activation observed, then revoked before the first keystroke.
    FOCUS_LOST = "focus-lost"
    #: A guard stopped the autofill part-way.
    AUTOFILL_BLOCKED = "autofill-blocked"
    CLIENT_NOT_FOUND = "client-not-found"
    #: The provider is disarmed and no test runtime was supplied.
    UNSUPPORTED = "unsupported"
    #: Another V2 connect is running in this process (2026-10-14, L2): two
    #: fills would type into one client through one clipboard.
    BUSY = "busy"
    FAILED = "failed"


#: Outcomes after which the client really is on its way to a tunnel — the
#: card flips to "connecting", exactly as it does after a legacy ``ok``.
STARTED_OUTCOMES = frozenset({PanelOutcome.SUBMITTED, PanelOutcome.CLI_STARTED,
                              PanelOutcome.MANUAL, PanelOutcome.STARTED,
                              PanelOutcome.TWO_FACTOR_REQUIRED})

_ACTIVATION_ENDINGS = {s.value for s in (
    ActivationState.ACTIVATION_TIMEOUT, ActivationState.NO_TARGET,
    ActivationState.TARGET_CHANGED, ActivationState.CANCELLED)}

_CLI_ROUTES = (ROUTE_CLI, ROUTE_CLI_MONITORED, ROUTE_LEGACY_CLIENT)

_TWO_FACTOR_USER_MOVE = (TwoFactorStatus.TOKEN_REQUIRED,
                         TwoFactorStatus.MANUAL_REQUIRED,
                         TwoFactorStatus.BLOCKED, TwoFactorStatus.FAILED)


@dataclass(frozen=True)
class PanelConnectOutcome:
    """Codes and a live handle — never a credential, never a sentence.

    ``state`` is the activation state the wait ended in (``None`` when the
    route never waited).  It is named ``state`` because
    ``ui.activation_prompt.ActivationWorker`` reports ``result.state`` as the
    closing state of the prompt; a :class:`ConnectResult` would have handed it
    ``connecting``, which the prompt does not know.
    """

    code: PanelOutcome
    state: str | None = None
    started: bool = False
    #: Why the autofill stopped (its ``reason_code``), when it did — a code
    #: such as ``requested-tunnel-not-configured``, never a value.  Lets the
    #: card tell a configuration problem from a security stop (L5).
    reason: str | None = None
    route: str | None = None
    error_code: str | None = None
    #: The monitored CLI process, for the panel's stdout 2FA monitor.
    monitor: Any = field(default=None, repr=False, compare=False)


def _left_to_the_stdout_monitor(result, two_factor) -> bool:
    """A monitored CLI without a token is not yet a second-factor situation.

    Both panels pass an empty token and start a stdout monitor for every
    process the CLI returns; whether the client ever asks for a code is known
    only once it prints the prompt.  So ``TOKEN_REQUIRED`` over
    ``PROCESS_STDOUT`` means "the monitor decides", not "tell the user now".
    """
    return (result.route == ROUTE_CLI_MONITORED and result.monitor is not None
            and two_factor.mode is TwoFactorMode.PROCESS_STDOUT
            and two_factor.status is TwoFactorStatus.TOKEN_REQUIRED)


def _activation_state(result) -> str | None:
    for step in result.steps:
        if step.phase == PHASE_AWAIT_ACTIVATION:
            return step.reason_code
    return None


def classify_connect_result(result) -> PanelConnectOutcome:
    """Reduce a :class:`ConnectResult` to one :class:`PanelOutcome`.

    Order matters and follows the flow: a failure to start beats everything,
    a wait that never let the autofill start beats the autofill, a blocked
    autofill beats the second factor.
    """
    activation = _activation_state(result)
    code = _classify(result, activation)
    return PanelConnectOutcome(
        code=code, state=activation, started=code in STARTED_OUTCOMES,
        route=result.route, error_code=result.error_code,
        monitor=result.monitor, reason=_autofill_reason(result))


def _autofill_reason(result) -> str | None:
    autofill = getattr(result, "autofill", None)
    if autofill is None or autofill.status is AutofillStatus.DONE:
        return None
    reason = (getattr(autofill, "metadata", None) or {}).get("reason_code")
    return str(reason) if reason else None


#: One V2 connect at a time in this process, whatever the provider (L2).  Two
#: sessions — two cards, or two vault windows — would both pass the activation
#: gate when the user switches to the client, and both fills would type into
#: the same window through the one system clipboard: login of one profile,
#: password of another, and Enter.  The guards ask "is this the verified
#: window", not "whose session is this", so the exclusion has to be here.
_SESSION_GUARD = threading.Lock()
_session_active = [False]


def v2_session_running() -> bool:
    """Is a V2 connect running anywhere in this process right now?"""
    with _SESSION_GUARD:
        return _session_active[0]


def _claim_session() -> bool:
    with _SESSION_GUARD:
        if _session_active[0]:
            return False
        _session_active[0] = True
        return True


def _release_session() -> None:
    with _SESSION_GUARD:
        _session_active[0] = False


def _classify(result, activation) -> PanelOutcome:
    if not result.success:
        if result.error_code == ErrorCode.CANCELLED.value:
            # A Cancel the flow honoured at one of its side effects, or the
            # autofill stopped mid-fill (Stage 47).  Terminal and unambiguous:
            # never a FAILED.
            return PanelOutcome.CANCELLED
        if result.error_code == ErrorCode.UNSUPPORTED.value:
            return PanelOutcome.UNSUPPORTED
        if result.error_code == ErrorCode.CLIENT_NOT_FOUND.value:
            return PanelOutcome.CLIENT_NOT_FOUND
        return PanelOutcome.FAILED
    autofill = result.autofill
    if autofill is not None and autofill.blocked_at == PHASE_AWAIT_ACTIVATION:
        return PanelOutcome.FOCUS_LOST
    if activation in _ACTIVATION_ENDINGS:
        return PanelOutcome(activation)
    if autofill is not None and autofill.status is not AutofillStatus.DONE:
        return PanelOutcome.AUTOFILL_BLOCKED
    two_factor = result.two_factor_result
    if (two_factor is not None and two_factor.status in _TWO_FACTOR_USER_MOVE
            and not _left_to_the_stdout_monitor(result, two_factor)):
        return PanelOutcome.TWO_FACTOR_REQUIRED
    if autofill is not None:
        return PanelOutcome.SUBMITTED
    if result.route in _CLI_ROUTES:
        return PanelOutcome.CLI_STARTED
    if result.automation is AutomationMode.MANUAL and result.requires_user_action:
        return PanelOutcome.MANUAL
    return PanelOutcome.STARTED


class PanelConnectSession:
    """One V2 connect, as a card would start it.  Single use.

    ``run`` is the callable handed to the UI's ``ActivationWorker``; the worker
    sets :attr:`observer` to its ``report_state`` and the Cancel button reaches
    :meth:`cancel`.  The request is dropped as soon as ``connect()`` has it, so
    a session kept around after the click holds no password.
    """

    def __init__(self, request: VpnRequest, *, provider=None,
                 runtime_factory=None, entry: str = ENTRY_CONNECT_MONITORED):
        self._request: VpnRequest | None = request
        self._provider = provider
        self._runtime_factory = runtime_factory
        self._entry = entry
        self._used = False
        self.cancellation = CancellationToken()
        #: Called with every activation state, in the thread running `run`.
        self.observer = None

    def __repr__(self) -> str:          # never prints the request
        return f"<PanelConnectSession used={self._used}>"

    def cancel(self) -> None:
        self.cancellation.cancel()

    def _notify(self, state) -> None:
        observer = self.observer
        if observer is not None:
            observer(state)

    def run(self) -> PanelConnectOutcome:
        """Never raises.  Returns an outcome even when nothing was attempted."""
        request, self._request = self._request, None
        if self._used or request is None:
            return PanelConnectOutcome(PanelOutcome.FAILED,
                                       error_code=ErrorCode.CONNECT_FAILED.value)
        self._used = True
        if self.cancellation.cancelled:
            # Called off before it began: not even detection runs.
            return PanelConnectOutcome(PanelOutcome.CANCELLED,
                                       state=ActivationState.CANCELLED.value)
        # The provider is the one the request names — resolved deterministically
        # and fail-closed — not a hardcoded FortiClient.  An unresolvable id
        # (unknown provider, construction error) declines; it never falls back
        # to another provider.
        provider = (self._provider if self._provider is not None
                    else resolve_v2_provider(request.provider_id,
                                             request.app_path))
        if provider is None:
            return PanelConnectOutcome(PanelOutcome.UNSUPPORTED,
                                       error_code=ErrorCode.UNSUPPORTED.value)
        armed = (self._runtime_factory is not None
                 or getattr(provider, "CONNECT_ENABLED", False) is True)
        if not armed:
            return PanelConnectOutcome(PanelOutcome.UNSUPPORTED,
                                       error_code=ErrorCode.UNSUPPORTED.value)
        if not _claim_session():
            return PanelConnectOutcome(PanelOutcome.BUSY,
                                       error_code=ErrorCode.CONNECT_FAILED.value)
        try:
            return self._run_armed(request, provider)
        finally:
            _release_session()

    def _run_armed(self, request: VpnRequest, provider) -> PanelConnectOutcome:
        trace = _start_trace(request, self._entry)
        try:
            if self._runtime_factory is not None:
                system = self._runtime_factory(
                    cancellation=self.cancellation,
                    activation_observer=self._notify)
            else:
                system = provider.connect_runtime(
                    cancellation=self.cancellation,
                    activation_observer=self._notify, trace=trace)
            result = provider.connect(request, self._entry, system=system)
        except Exception as exc:
            _finish_trace(trace, None, error=type(exc).__name__)
            return PanelConnectOutcome(PanelOutcome.FAILED,
                                       error_code=ErrorCode.CONNECT_FAILED.value)
        outcome = classify_connect_result(result)
        _finish_trace(trace, outcome)
        return outcome


# Keys the vpn.connect.v2 trace emits (codes and flags only).  Declared to
# the redactor next to the code that produces them, as the other VPN modules
# do — otherwise an exported trace would arrive with these dropped.
try:
    from diagnostics.redactor import allow_keys as _allow_keys
    _allow_keys("entry", "has_profile_name", "has_credentials", "outcome",
                "reason_code", "activation", "route", "exception", "autofill")
except Exception:      # pragma: no cover - best-effort, like diagnostics.vpn
    pass


def _start_trace(request: VpnRequest, entry: str):
    """A ``vpn.connect.v2`` diagnostics trace (L4).  Never raises.

    Facts only, as the legacy ``vpn.connect`` trace — never a login, a
    password, a token, and (unlike the legacy) not the profile name either:
    it names a hospital.
    """
    try:
        from diagnostics import vpn as vpn_diag
        return vpn_diag.start(
            "vpn.connect.v2", provider=request.provider_id, entry=str(entry),
            autofill=bool(request.autofill),
            has_profile_name=bool(request.profile_name),
            has_server=bool(request.server), has_app_path=bool(request.app_path),
            has_credentials=bool(request.login or request.password))
    except Exception:
        return None


def _finish_trace(trace, outcome, *, error: str | None = None) -> None:
    if trace is None:
        return
    try:
        if outcome is None:
            trace.finish(status="fail", error_code="v2-session-raised",
                         exception=error)
            return
        ok = outcome.code in STARTED_OUTCOMES or outcome.code is PanelOutcome.MANUAL
        trace.finish(status="ok" if ok else "fail",
                     error_code=None if ok else str(outcome.error_code or outcome.code),
                     outcome=str(outcome.code), reason_code=outcome.reason,
                     activation=outcome.state, route=outcome.route)
    except Exception:
        pass


# --------------------------------------------------------------------------- #
# CLI / PROCESS_STDOUT — the second-factor monitor that owns the channel        #
# --------------------------------------------------------------------------- #

class MonitorPhase(StrEnum):
    """What watching the monitored CLI's stdout came to (Stage 50).

    The intermediate result of the second factor, before a token is even asked
    for: it tells the UI whether to show a token prompt or move on.
    """

    #: stdout asked for a token — the UI must collect one.
    CHALLENGE = "challenge"
    #: the stream ended, or the read bound was reached, without ever asking —
    #: the CLI connected (or failed) without a second factor.
    NO_CHALLENGE = "no-challenge"
    #: the caller called the watch off between reads.
    CANCELLED = "cancelled"
    #: reading the pipe raised.
    ERROR = "error"


class TwoFactorOutcome(StrEnum):
    """What became of the whole second-factor exchange (Stage 50).

    These are the codes the UI turns into its own signals; they line up with
    the seven the panel asked for (CLI_STARTED lives on
    :class:`PanelConnectOutcome`, the rest are here).
    """

    TOKEN_REQUIRED = "token-required"    # a challenge appeared; UI must ask
    SUBMITTED = "submitted"              # the token was handed to the process
    NO_CHALLENGE = "no-challenge"        # connected without a second factor
    CANCELLED = "cancelled"              # called off; nothing was sent
    TIMEOUT = "timeout"                  # nobody supplied a token in time
    FAILED = "failed"                    # write/verify/pipe error
    PROCESS_ENDED = "process-ended"      # the stream closed under us


#: Which submit statuses mean "the token really went to the process".
_SUBMIT_OK = (TwoFactorStatus.SUBMITTED, TwoFactorStatus.NOT_REQUIRED)


class TwoFactorMonitorSession:
    """Owns the live :class:`ProcessChannel` from CLI start to a terminal state.

    This is the answer to the lifecycle gap: after ``PanelConnectSession.run``
    returns ``CLI_STARTED``, the ``ConnectResult``/``PanelConnectOutcome`` still
    carries the live ``monitor`` (the ``Popen``), and **this object takes
    ownership of it** — wrapping it in a :class:`ProcessChannel` and holding it
    until a token is submitted, the process ends, an error occurs, a timeout
    passes, or the wait is cancelled.  Nothing else keeps the channel alive, so
    nothing else can close it out from under a pending token.

    Two blocking steps, both meant to run **off the UI thread** (a UI worker
    calls them):

    * :meth:`watch` — reads stdout until a challenge, EOF, the read bound, or a
      cancellation; returns a :class:`MonitorPhase`.  Uses the existing
      :func:`~vpn.providers.forticlient_2fa.watch_for_challenge`, with the
      session's own :class:`CancellationToken` as its ``should_stop``.
    * :meth:`submit` — delivers a token through the existing, guarded
      :meth:`FortiClientProvider.supply_two_factor` (process-image verification,
      write-error surfaced).  Refuses outright if the session was cancelled, so
      a Cancel between the challenge and the submit sends nothing.

    It performs no Win32 itself, touches no clipboard and no window: the process
    check inside ``supply_two_factor`` goes through the injected
    :class:`WindowApi` seam, exactly as the token path already did.  The token
    is never stored on this object, never logged, never traced by default.
    """

    def __init__(self, provider, request: VpnRequest, channel, *,
                 cancellation: CancellationToken | None = None, window_api=None):
        self._provider = provider
        # A request without the token: the login/profile matter to the 2FA
        # component's plan, the token arrives later and is never kept here.
        self._base_request = request
        self._channel = channel
        self.cancellation = (cancellation if cancellation is not None
                             else CancellationToken())
        self._window_api = window_api
        self._submitted = False
        self._process_ended = False

    @classmethod
    def from_outcome(cls, outcome: "PanelConnectOutcome", provider,
                     request: VpnRequest, *, cancellation=None, window_api=None):
        """Take ownership of the monitor a ``CLI_STARTED`` outcome carries.

        Returns ``None`` when there is no live monitor to own — a CLI connect
        that handed nothing back, or any non-CLI outcome.
        """
        if outcome.monitor is None:
            return None
        channel = PopenProcessChannel(outcome.monitor)
        return cls(provider, request, channel, cancellation=cancellation,
                   window_api=window_api)

    @property
    def pid(self):
        return getattr(self._channel, "pid", None)

    def cancel(self) -> None:
        self.cancellation.cancel()

    def watch(self) -> MonitorPhase:
        """Block reading stdout for a challenge.  Runs off the UI thread."""
        if self.cancellation.cancelled:
            return MonitorPhase.CANCELLED
        watch = watch_for_challenge(
            self._channel, should_stop=lambda: self.cancellation.cancelled)
        if watch.stopped:
            return MonitorPhase.CANCELLED
        if watch.detected:
            return MonitorPhase.CHALLENGE
        if watch.ended:
            # The stream closed.  Distinguish a clean "connected without 2FA"
            # from a channel that died mid-exchange only by whether a challenge
            # had been seen — here none was, so it is simply no-challenge.
            self._process_ended = True
            return MonitorPhase.NO_CHALLENGE
        return MonitorPhase.NO_CHALLENGE

    def submit(self, token: str) -> TwoFactorOutcome:
        """Deliver a token through the guarded 2FA component.  Off the UI thread.

        Refuses if cancelled (nothing is written) or already submitted once.
        """
        if self.cancellation.cancelled:
            return TwoFactorOutcome.CANCELLED
        if self._submitted:
            return TwoFactorOutcome.FAILED
        # A fresh request carrying just this token; the base request's login and
        # profile are reused, the token is not kept on the session.
        request = VpnRequest(
            provider_id=self._provider.id,
            profile_name=self._base_request.profile_name,
            login=self._base_request.login, token=token,
            requires_2fa=True)
        result = self._provider.supply_two_factor(
            request, mode=TwoFactorMode.PROCESS_STDOUT, channel=self._channel,
            api=self._window_api, trace=None)
        if result is None:
            return TwoFactorOutcome.FAILED
        if result.status in _SUBMIT_OK:
            self._submitted = True
            return TwoFactorOutcome.SUBMITTED
        return TwoFactorOutcome.FAILED

    def __repr__(self) -> str:          # never the token, never a line
        return (f"<TwoFactorMonitorSession pid={self.pid} "
                f"submitted={self._submitted} "
                f"cancelled={self.cancellation.cancelled}>")


#: What still stands between this bridge and a switched-on Connect button.
KNOWN_GAPS: tuple[tuple[str, str], ...] = (
    ("detail-panel-not-covered",
     "detail_panel ma własną ścieżkę connect (i własne okno 2FA) — most jej "
     "nie obejmuje"),
    ("cli-cancellation-between-reads-only",
     "TwoFactorMonitorSession przerywa watch między liniami (should_stop) i nie "
     "wysyła tokenu po cancel; odczyt już zablokowany w OS kończy dopiero linia "
     "lub EOF procesu — ograniczenie potoku, nie kodu"),
    ("cli-live-unverified",
     "ścieżka CLI/PROCESS_STDOUT nie była uruchomiona na prawdziwym kliencie z "
     "CLI (Free/VPN-only nie ma użytecznego CLI) — CONTRACT-ONLY"),
    ("cli-monitor-not-owned-by-panel",
     "po CLI_STARTED panel nie przejmuje outcome.monitor: nie startuje ani "
     "_start_monitor, ani TwoFactorMonitorSession, więc pod V2 nie ma wykrycia "
     "prośby o token na stdout, którą legacy ma — a strumień procesu nikt nie "
     "czyta (trasa CLI jest próbowana jako PIERWSZA dla connect_monitored)"),
    ("connect-runtime-not-live-armed",
     "łańcuch UI→provider przeszedł na żywo (Etap 51), ale uzbrojony przez "
     "runtime_factory z wstrzymanym Enterem; prawdziwe connect_runtime() spod "
     "flagi CONNECT_ENABLED, z Win32InputSystem i realnym Enterem, nie "
     "wykonało się nigdy"),
)
