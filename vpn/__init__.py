"""VPN provider architecture — providers are registered, none drives the VPN.

The running application still goes through `vpn_connect.py` exactly as before
for connect, disconnect, launch and status.  This package defines *how*
providers are expressed as they are migrated one at a time:

``types.py``      capabilities, states, error codes, request and result objects
``provider.py``   the :class:`VpnProvider` contract + a legacy bridge
``catalog.py``    what each existing client can really do, as declared data
``registry.py``   a registry that hands providers back by id and nothing more
``providers/``    migrated providers (FortiClient: detection only)
``shadow.py``     legacy vs migrated detection, compared on explicit request

Initialisation happens here and only here: the last statement of this module
fills :data:`default_registry` with the builtin providers.  Python runs a
package's ``__init__`` exactly once per process and before any of its
submodules, so every import route (``import vpn``, ``import vpn.shadow``,
``from vpn.registry import default_registry``) sees the same, fully populated
registry, and nothing is ever registered twice.

Three rules shaped this package:

* **No VPN logic here.** Detection, launching, autofill and status stay in
  `vpn_connect.py` until a provider is migrated deliberately. Two
  implementations of the same behaviour would be worse than one messy one.
* **No user-facing text in results.** Providers return codes and data; the UI
  turns them into sentences.
* **No private logging.** Tracing and redaction belong to ``diagnostics``;
  :func:`vpn.provider.record_result` is the only bridge, and it writes through
  the existing trace API.
"""

from .catalog import (  # noqa: F401
    BY_ID, BY_LEGACY_NAME, SPECS, ProviderSpec, providers_with,
    spec_for_legacy_name,
)
from .provider import (  # noqa: F401
    LegacyVpnProviderAdapter, VpnProvider, check_contract, record_result,
)
from .registry import (  # noqa: F401
    DuplicateProviderIdError, UnknownProviderError, VpnRegistry,
    default_registry,
)
from .types import (  # noqa: F401
    AutofillResult, AutofillStatus, AutomationMode, Capability, ConnectResult,
    ConnectStep, DetectionResult, DetectionState, DisconnectResult, ErrorCode,
    LaunchResult, ProviderResult, SecretInResultError, StatusResult,
    StatusSource, TwoFactorMode, TwoFactorResult, TwoFactorStatus, VpnRequest,
    VpnState, guard_metadata, unsupported,
)
from .providers import (  # noqa: F401
    BUILTIN_PROVIDERS, FortiClientProvider, GuardResult, SecureWindowTarget,
    TargetRejected, VerifiedWindow, WindowCandidateFinder,
    register_builtin_providers,
)
from .shadow import (  # noqa: F401
    DetectionComparison, FieldDifference, LegacyFailure, LegacySnapshot,
    ShadowDetection, collect_legacy_detection, compare_detection,
    record_comparison, shadow_detect_forticlient,
)

__all__ = [
    # contract
    "VpnProvider", "LegacyVpnProviderAdapter", "check_contract", "record_result",
    # registry
    "VpnRegistry", "default_registry", "DuplicateProviderIdError",
    "UnknownProviderError",
    # types
    "Capability", "AutomationMode", "StatusSource", "VpnState",
    "DetectionState", "ErrorCode", "VpnRequest", "ProviderResult",
    "DetectionResult", "LaunchResult", "ConnectResult", "DisconnectResult",
    "StatusResult", "SecretInResultError", "guard_metadata", "unsupported",
    "ConnectStep", "TwoFactorMode", "AutofillResult", "AutofillStatus",
    "TwoFactorResult", "TwoFactorStatus",
    # catalog
    "ProviderSpec", "SPECS", "BY_ID", "BY_LEGACY_NAME", "spec_for_legacy_name",
    "providers_with",
    # providers
    "BUILTIN_PROVIDERS", "FortiClientProvider", "register_builtin_providers",
    "SecureWindowTarget", "VerifiedWindow", "TargetRejected", "GuardResult",
    "WindowCandidateFinder",
    # shadow detection
    "DetectionComparison", "FieldDifference", "LegacyFailure", "LegacySnapshot",
    "ShadowDetection", "collect_legacy_detection", "compare_detection",
    "record_comparison", "shadow_detect_forticlient",
]

# The single initialisation point of the registry (see module docstring).
register_builtin_providers(default_registry)
