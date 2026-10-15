"""HospitalHub V2 — diagnostics.

Why this package exists: when a VPN connection misbehaves on somebody else's
machine there is currently no trace of what happened.  This package makes an
operation describe itself — step by step, with timings and safe technical
detail — and lets the user export that description as a package that can be
sent to whoever is debugging it.

The rule that shapes everything here: **nothing leaves the machine that we
cannot account for.**  Every value is filtered through
:mod:`diagnostics.redactor`, unknown fields are dropped rather than trusted,
and an export that still looks like it contains a secret fails loudly instead
of being quietly scrubbed.

Layout
------
``redactor.py``   allowlist filtering, masking, secret detection — the gate
``trace.py``      TraceRecorder / TraceStep / TraceStore (retention)
``collector.py``  host + app facts, UI-automation data model
``export.py``     building, checking and writing the ZIP

This package is self-contained: it imports nothing from the application, so it
works headless, is testable without Qt, and adding it changes no existing
behaviour.  Wiring it into VPN/RDP/SSH happens in the next stages.

Typical use::

    from diagnostics import TraceRecorder, export

    rec = TraceRecorder("vpn.connect", meta={"provider": "FortiClient"})
    with rec.step("forti.detect") as st:
        st.ok(source="registry", app_version="7.4.1")
    rec.finish("ok")

    result = export()      # → %APPDATA%\\HospitalHubV2\\diagnostics\\exports\\*.zip
"""

from __future__ import annotations

import os
from pathlib import Path

APP_NAME = "HospitalHub"
APP_VARIANT = "V2"
#: Kept here for now; moves to a shared constant when the app has one.
APP_VERSION = "2.0.0-dev"

#: Overridable so tests never touch the user's real %APPDATA%.
DIR_ENV_VAR = "HOSPITALHUB_DIAG_DIR"

_store = None


def base_dir() -> Path:
    """Root directory for diagnostics data (own subtree, never shared with V1)."""
    override = os.environ.get(DIR_ENV_VAR)
    if override:
        return Path(override)
    app_data = os.environ.get("APPDATA") or str(Path.home())
    return Path(app_data) / "HospitalHubV2" / "diagnostics"


def traces_dir() -> Path:
    return base_dir() / "traces"


def export_dir() -> Path:
    return base_dir() / "exports"


def get_store(retention: int | None = None):
    """Return the process-wide trace store, creating it on first use.

    Re-created automatically when the target directory changes (tests point
    :data:`DIR_ENV_VAR` at a temporary path).
    """
    global _store
    from .trace import DEFAULT_RETENTION, TraceStore

    wanted_dir = traces_dir()
    wanted_retention = DEFAULT_RETENTION if retention is None else retention
    if (_store is None or _store.directory != wanted_dir
            or (retention is not None and _store.retention != wanted_retention)):
        _store = TraceStore(wanted_dir, retention=wanted_retention)
    return _store


def init(retention: int | None = None):
    """Create the directories and apply retention. Safe to call repeatedly.

    Not called from ``main.py`` on purpose — at this stage the application is
    unchanged.  The store also initialises lazily, so this is only for callers
    that want the pruning to happen at startup.
    """
    store = get_store(retention)
    try:
        traces_dir().mkdir(parents=True, exist_ok=True)
        store.prune()
    except OSError:
        pass
    return store


def reset_for_tests() -> None:
    """Drop cached state (store + masker salt)."""
    global _store
    _store = None
    redactor.reset_default_masker()


from . import collector, export as _export_mod, redactor, trace  # noqa: E402
from .collector import UiaNode, WindowInfo, collect, register  # noqa: E402
from .export import ExportResult, build, export, preview  # noqa: E402
from .redactor import (  # noqa: E402
    Masker, Mode, RedactionReport, SecretLeakError, assert_no_secrets,
    find_secrets, redact,
)
from .trace import (  # noqa: E402
    DEFAULT_RETENTION, STATUS_FAIL, STATUS_OK, STATUS_WARN, TraceRecorder,
    TraceStep, TraceStore,
)

__all__ = [
    "APP_NAME", "APP_VARIANT", "APP_VERSION",
    "base_dir", "traces_dir", "export_dir", "get_store", "init",
    "reset_for_tests",
    "TraceRecorder", "TraceStep", "TraceStore", "DEFAULT_RETENTION",
    "STATUS_OK", "STATUS_WARN", "STATUS_FAIL",
    "redact", "Mode", "Masker", "RedactionReport", "SecretLeakError",
    "find_secrets", "assert_no_secrets",
    "collect", "register", "UiaNode", "WindowInfo",
    "build", "preview", "export", "ExportResult",
    "collector", "redactor", "trace",
]
