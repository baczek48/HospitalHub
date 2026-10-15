"""Trace helper for the existing VPN flow — an observer, never a participant.

`vpn_connect.py` is instrumented with calls from this module.  Every entry
point here is defensive: it catches its own errors and returns something
usable, so a broken diagnostics layer can never turn a working VPN connection
into a failure.  That is the whole contract of this file.

Two shapes of trace come out of it:

``vpn.connect`` / ``vpn.disconnect`` / ``vpn.2fa``
    The synchronous part of an operation, recorded on the calling thread and
    written when the call returns.

``vpn.autofill``
    The autofill threads outlive the connect() call that spawned them, so they
    get their own trace linked back through ``parent_trace_id`` rather than
    appending to a trace that has already been written.

Status polling deliberately does **not** create a trace per poll — it would
bury everything else in the store.  :func:`note_status` is edge-triggered: it
remembers the last status per profile and writes a short trace only when the
status actually changes (and never on the first observation, so starting the
app does not produce a burst of traces).

Nothing here starts a process, opens a handle or waits for anything.  All the
data comes from what the VPN code already computed.
"""

from __future__ import annotations

import threading
from typing import Any

_STATUS_LOCK = threading.Lock()
#: (provider, profile) → last status seen. Seeded on first observation.
_last_status: dict[tuple[str, str], str] = {}
#: Per-thread marker set by the status code to say which source decided.
_source_local = threading.local()


# --------------------------------------------------------------------------- #
# Trace objects                                                                #
# --------------------------------------------------------------------------- #

class NullTrace:
    """Does nothing, accepts everything. Used when diagnostics is unavailable."""

    trace_id = ""
    recorder = None

    def step(self, *args: Any, **kwargs: Any) -> "NullTrace":
        return self

    ok = warn = fail = step

    def child(self, *args: Any, **kwargs: Any) -> "NullTrace":
        return self

    def finish(self, *args: Any, **kwargs: Any) -> None:
        return None


NULL = NullTrace()


class VpnTrace:
    """Thin, failure-proof wrapper around :class:`diagnostics.trace.TraceRecorder`.

    Step durations are measured as "time since the previous step", which needs
    no control-flow changes in the code being observed — the VPN functions
    simply report what they just did.
    """

    def __init__(self, recorder, monotonic=None):
        import time
        self.recorder = recorder
        self._monotonic = monotonic or time.monotonic
        self._last_mark = self._monotonic()
        self._lock = threading.Lock()

    @property
    def trace_id(self) -> str:
        try:
            return self.recorder.trace_id
        except Exception:
            return ""

    def step(self, name: str, status: str = "ok", error_code: str | None = None,
             message: str | None = None, **data: Any) -> "VpnTrace":
        try:
            with self._lock:
                now = self._monotonic()
                duration_ms = (now - self._last_mark) * 1000.0
                self._last_mark = now
            self.recorder.add_step(name, status=status, duration_ms=duration_ms,
                                   error_code=error_code, message=message, **data)
        except Exception:
            # An observer must not be able to break the operation it watches.
            pass
        return self

    def ok(self, name: str, **data: Any) -> "VpnTrace":
        return self.step(name, "ok", **data)

    def warn(self, name: str, message: str | None = None, **data: Any) -> "VpnTrace":
        return self.step(name, "warn", message=message, **data)

    def fail(self, name: str, error_code: str | None = None,
             message: str | None = None, **data: Any) -> "VpnTrace":
        return self.step(name, "fail", error_code=error_code, message=message, **data)

    def child(self, operation: str, **meta: Any) -> "VpnTrace":
        """A linked trace for work that continues after this one is written."""
        try:
            meta.setdefault("parent_trace_id", self.trace_id)
        except Exception:
            pass
        return start(operation, **meta)

    def finish(self, status: str | None = None, error_code: str | None = None,
               **result: Any) -> None:
        try:
            self.recorder.finish(status=status, error_code=error_code, **result)
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Entry points used by vpn_connect                                             #
# --------------------------------------------------------------------------- #

def start(operation: str, **meta: Any) -> VpnTrace | NullTrace:
    """Begin a trace. Returns a no-op object if diagnostics cannot start."""
    try:
        from .trace import TraceRecorder
        return VpnTrace(TraceRecorder(operation, meta=meta))
    except Exception:
        return NULL


def mark_status_source(source: str) -> None:
    """Record which source decided the status, for the current thread."""
    try:
        _source_local.value = source
    except Exception:
        pass


def take_status_source() -> str:
    """Read and clear the marker set by :func:`mark_status_source`."""
    try:
        value = getattr(_source_local, "value", "")
        _source_local.value = ""
        return value or ""
    except Exception:
        return ""


def note_status(provider: str, status: str | None, profile_name: str = "",
                server: str = "", adapter: str = "") -> None:
    """Note a status observation; write a trace only when it changed.

    Called from the status poll, which runs every couple of seconds per
    profile — hence the edge trigger. The first observation only seeds the
    cache, so application start-up produces no traces at all.
    """
    try:
        key = (str(provider), str(profile_name or server or ""))
        current = status or "unknown"
        source = take_status_source()
        with _STATUS_LOCK:
            previous = _last_status.get(key)
            _last_status[key] = current
        if previous is None or previous == current:
            return
        trace = start("vpn.status", provider=provider, profile_name=profile_name)
        data: dict[str, Any] = {"state": current, "source": source or "unknown"}
        if adapter:
            data["adapter"] = adapter
        trace.ok("vpn.status", **data)
        trace.finish("ok", state=current)
    except Exception:
        # Status notes are the least important thing here — never let one
        # interfere with the poll that produced it.
        pass


def reset_status_cache() -> None:
    """Forget remembered statuses (tests, and a fresh session)."""
    try:
        with _STATUS_LOCK:
            _last_status.clear()
    except Exception:
        pass


# Keys the VPN traces emit that are not part of the generic allowlist.
# Declared here, next to the code that produces them (cf. collector.py).
try:
    from .redactor import allow_keys as _allow_keys

    _allow_keys(
        "automation_mode",      # "tab_sequence" | "wm_settext" | "manual" | "system"
        "has_server", "has_app_path", "parent_trace_id",
        "event",                # e.g. "credential_copy_requested"
        "field",                # WHICH field was touched — never its value
        "entered", "submitted", "window_found", "restored", "fallback",
        "image_name",           # target-window guard: process image base name, never a path
        "purpose",              # what a guarded window was about to receive (no value)
        "lnk_present", "gui_visible", "process_monitor", "requires_2fa",
        "tray_activated", "elevation", "retries", "installed", "rc",
    )
except Exception:      # pragma: no cover - allowlist is best-effort at import
    pass
