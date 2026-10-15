"""Concrete VPN providers, migrated from `vpn_connect.py` one responsibility
at a time.

A provider moves here only after its behaviour has been shown to match the
legacy code on controlled fixtures.  Being registered does **not** mean being
used: the running application still connects, disconnects, launches and polls
status through `vpn_connect.py` in full.

Migration status:

===============  ========================================================
FortiClient      ``detect()`` — parity verified, shadow comparison available
                 ``launch()`` — parity verified on fake machines only
                 (never run side by side with the legacy on a real one)
                 ``connect()`` — phases prepared (`forticlient_connect`),
                 runs only with an injected seam; answers ``unsupported``
                 ``autofill_login_password()`` — login + password behind the
                 secure-window guard (`forticlient_autofill`), tests only
                 ``supply_two_factor()`` — token into the EMS auth window or a
                 monitored process' stdin (`forticlient_2fa`), tests only
                 activation gate — waits, read-only, for the user to bring the
                 client forward before any autofill (`activation_gate`)
                 registered; none of it is used by the UI
everything else  still entirely in `vpn_connect.py`, not registered
===============  ========================================================
"""

from __future__ import annotations

from .forticlient import FortiClientProvider
from .activation_gate import (
    ActivationGate, ActivationResult, ActivationState, CancellationToken,
)
from .process_channel import PopenProcessChannel, ProcessChannel
from .secure_target import (
    ForegroundCheck, GuardResult, SecureWindowTarget, TargetRejected,
    VerifiedWindow, WindowCandidateFinder,
)
from .window_message_system import (
    Win32WindowMessageSystem, WindowControl, WindowMessageSystem,
)

__all__ = ["FortiClientProvider", "BUILTIN_PROVIDERS",
           "register_builtin_providers",
           "SecureWindowTarget", "VerifiedWindow", "TargetRejected",
           "GuardResult", "WindowCandidateFinder",
           "WindowMessageSystem", "Win32WindowMessageSystem", "WindowControl",
           "ProcessChannel", "PopenProcessChannel", "ForegroundCheck",
           "ActivationGate", "ActivationResult", "ActivationState",
           "CancellationToken"]

#: Real providers shipped with the application, in registration order.  A
#: class is listed here only once its migrated part has proven parity.
BUILTIN_PROVIDERS = (FortiClientProvider,)


def register_builtin_providers(registry) -> list[str]:
    """Register every builtin provider that `registry` does not hold yet.

    Idempotent: calling it twice registers nothing the second time.  A
    *different* class already holding one of the ids is a real conflict and
    raises :class:`vpn.registry.DuplicateProviderIdError` from the registry.
    Construction is free of I/O — providers touch the registry or disk only
    when asked to detect.  Returns the ids added by this call.
    """
    added: list[str] = []
    for provider_class in BUILTIN_PROVIDERS:
        if isinstance(registry.get(provider_class.id), provider_class):
            continue
        registry.register(provider_class())
        added.append(provider_class.id)
    return added
