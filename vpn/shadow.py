"""Shadow detection — legacy and migrated FortiClient detection, side by side.

The legacy answer is the production answer, full stop.  This module only
*observes*: it asks the legacy functions in `vpn_connect.py` and the migrated
:class:`~vpn.providers.FortiClientProvider` the same question and describes
whether they agree.  Nothing here feeds a decision back into the VPN:

* it is called **explicitly** — no import side effect, no hook in the status
  poller, no timer;
* it never raises — a broken provider, a broken legacy function or a bug in
  the comparison itself all come back as data;
* it only reads the registry and the disk.  The legacy CLI probe
  (``_is_fortivpn_cli_supported`` runs ``FortiVPN.exe``) is deliberately not
  part of the snapshot.

Two layers, on purpose:

``collect_legacy_detection``  raw legacy answers, exactly as returned — a bool,
                              None, a path, or the exception a call raised.
                              The legacy is not reshaped to the new format.
``compare_detection``         normalises both sides *here*, compares them
                              field by field on meaning (not bytes) and
                              returns a :class:`DetectionComparison` whose
                              values are already safe to show.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import Any

from diagnostics.redactor import allow_keys, find_secrets, shorten_path

from .providers import forticlient as fc
from .types import DetectionResult, DetectionState, VpnRequest

__all__ = [
    "LegacyFailure", "LegacySnapshot", "FieldDifference", "DetectionComparison",
    "ShadowDetection", "collect_legacy_detection", "compare_detection",
    "record_comparison", "shadow_detect_forticlient",
    "FIELDS", "TRACE_STEP",
]

PROVIDER_ID = "forticlient"
LEGACY_PROVIDER_NAME = "FortiClient"

#: Semantic fields compared, in reporting order.
FIELDS = (
    "installed", "state", "source", "registry_present", "install_dir", "path",
    "edition", "lnk_present", "fortivpn_present", "sslvpn_client_present",
)
PATH_FIELDS = frozenset({"install_dir", "path"})

#: Why two answers differ (or that they do not).  Stable strings — they end up
#: in diagnostics traces.
REASON_EQUAL = "equal"
REASON_MISMATCH = "value-mismatch"
REASON_LEGACY_ERROR = "legacy-error"
REASON_NEW_ERROR = "new-provider-error"
REASON_PROVIDER_MISSING = "provider-missing"
REASON_COMPARISON_FAILED = "comparison-failed"

#: Trace step name used by :func:`record_comparison`.
TRACE_STEP = "vpn.detect.shadow"

# Keys this module emits into a trace (declared next to the emitting code).
allow_keys("detection_parity", "diff_count", "field", "fields",
           "legacy_present", "new_present", "legacy_errors", "new_error")

_SOURCE_APP_PATH = fc.SOURCE_APP_PATH
_SOURCE_REGISTRY = fc.SOURCE_REGISTRY
_SOURCE_KNOWN = fc.SOURCE_KNOWN_PATHS

#: A profile directory of *any* user, not only the current one.
_USERS_DIR_RE = re.compile(r"^([a-z]:[\\/]+users[\\/]+)[^\\/]+", re.IGNORECASE)


# --------------------------------------------------------------------------- #
# Legacy side — raw, untouched                                                 #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class LegacyFailure:
    """A legacy call that raised.  Only the exception *type* is kept."""

    error_type: str

    def __str__(self) -> str:
        return f"error:{self.error_type}"


#: Legacy calls making up one detection snapshot: name -> how to call it.
#: `legacy` is the `vpn_connect` module (or a stand-in with the same names).
_LEGACY_CALLS = {
    "installed": lambda legacy, app_path: legacy.is_forticlient_installed(),
    "install_dir": lambda legacy, app_path: legacy._forti_install_dir(),
    "gui": lambda legacy, app_path: legacy._find_forticlient_gui(app_path),
    "free_edition": lambda legacy, app_path: legacy._is_forti_free_edition(),
    "fortivpn": lambda legacy, app_path: legacy._find_fortivpn(app_path),
    "sslvpn_client": lambda legacy, app_path:
        legacy.find_executable(LEGACY_PROVIDER_NAME),
    "lnk": lambda legacy, app_path: legacy.os.path.isfile(legacy._FORTI_LNK),
}


@dataclass(frozen=True)
class LegacySnapshot:
    """What the legacy detection functions returned, exactly as returned.

    This is the production truth of a shadow run and is never modified.
    ``values`` may hold raw paths, so it is excluded from ``repr`` — print a
    :class:`DetectionComparison` instead.
    """

    values: dict = field(repr=False)
    app_path: str = field(default="", repr=False)

    @property
    def failures(self) -> dict[str, LegacyFailure]:
        return {k: v for k, v in self.values.items() if isinstance(v, LegacyFailure)}


def collect_legacy_detection(app_path: str = "", legacy=None) -> LegacySnapshot:
    """Call the legacy detection functions one by one.  Never raises.

    Each call is isolated: one raising (e.g. ``_is_forti_free_edition`` on a
    non-text ``DisplayName``) is recorded as :class:`LegacyFailure` and the
    others still run.
    """
    app_path = app_path or ""
    if legacy is None:
        try:
            import vpn_connect as legacy                # lazy, on demand only
        except Exception as exc:
            failure = LegacyFailure(type(exc).__name__)
            return LegacySnapshot({name: failure for name in _LEGACY_CALLS},
                                  app_path)
    values: dict[str, Any] = {}
    for name, call in _LEGACY_CALLS.items():
        try:
            values[name] = call(legacy, app_path)
        except Exception as exc:
            values[name] = LegacyFailure(type(exc).__name__)
    return LegacySnapshot(values, app_path)


# --------------------------------------------------------------------------- #
# Normalisation — done on the comparison side, never inside the legacy         #
# --------------------------------------------------------------------------- #

def _failed(*values) -> LegacyFailure | None:
    for value in values:
        if isinstance(value, LegacyFailure):
            return value
    return None


def _legacy_state(snapshot: LegacySnapshot):
    v = snapshot.values
    failure = _failed(v["gui"], v["installed"])
    if failure:
        return failure
    if v["gui"]:
        return DetectionState.INSTALLED.value
    if v["installed"]:
        return DetectionState.INCOMPLETE.value
    return DetectionState.NOT_INSTALLED.value


def _legacy_sources(snapshot: LegacySnapshot):
    """Which lookup can have produced the legacy GUI path.

    The legacy returns only a path, so the source is *inferred* from the order
    of `_find_forticlient_gui`: app_path, then ``INSTALLDIR``, then the known
    paths.  One case is genuinely ambiguous — the key exists, ``INSTALLDIR``
    joins to a known path — and then both candidates are returned.
    """
    v = snapshot.values
    gui = v["gui"]
    if isinstance(gui, LegacyFailure):
        return gui
    if not gui:
        return frozenset()
    if snapshot.app_path and gui == snapshot.app_path:
        return frozenset({_SOURCE_APP_PATH})
    if gui not in fc.GUI_PATHS:
        # Only the registry route can yield a path outside the known list.
        return frozenset({_SOURCE_REGISTRY})
    installed, install_dir = v["installed"], v["install_dir"]
    if _failed(installed, install_dir):
        return frozenset({_SOURCE_REGISTRY, _SOURCE_KNOWN})
    if (installed and isinstance(install_dir, str)
            and os.path.join(install_dir, fc.GUI_EXE_NAME) == gui):
        return frozenset({_SOURCE_REGISTRY, _SOURCE_KNOWN})
    return frozenset({_SOURCE_KNOWN})


def _as_bool(value):
    return value if isinstance(value, LegacyFailure) else bool(value)


def _as_dir(value):
    if isinstance(value, LegacyFailure):
        return value
    return "" if value is None else str(value)


def normalize_legacy(snapshot: LegacySnapshot) -> dict[str, Any]:
    v = snapshot.values
    state = _legacy_state(snapshot)
    free = v["free_edition"]
    return {
        "installed": state if isinstance(state, LegacyFailure) else state in (
            DetectionState.INSTALLED.value, DetectionState.INCOMPLETE.value),
        "state": state,
        "source": _legacy_sources(snapshot),
        "registry_present": _as_bool(v["installed"]),
        "install_dir": _as_dir(v["install_dir"]),
        "path": v["gui"] if isinstance(v["gui"], LegacyFailure) else (v["gui"] or None),
        "edition": free if isinstance(free, LegacyFailure) else ("free" if free else None),
        "lnk_present": _as_bool(v["lnk"]),
        "fortivpn_present": _as_bool(v["fortivpn"]),
        "sslvpn_client_present": _as_bool(v["sslvpn_client"]),
    }


def normalize_provider(result: DetectionResult) -> dict[str, Any]:
    md = result.metadata
    return {
        "installed": result.installed,
        "state": result.state.value,
        "source": result.source,
        "registry_present": bool(md.get("registry_present")),
        "install_dir": str(md.get("install_dir") or ""),
        "path": result.path or None,
        "edition": result.edition,
        "lnk_present": bool(md.get("lnk_present")),
        "fortivpn_present": bool(md.get("fortivpn_present")),
        "sslvpn_client_present": bool(md.get("sslvpn_client_present")),
    }


# --------------------------------------------------------------------------- #
# Comparison result                                                            #
# --------------------------------------------------------------------------- #

def _safe_path(value: str) -> str:
    text = _USERS_DIR_RE.sub(r"\1<user>", shorten_path(value))
    return "<redacted>" if find_secrets(text) else text


def _safe_value(name: str, value: Any) -> Any:
    """A value fit for a report: no raw private paths, no secret-shaped text."""
    if isinstance(value, LegacyFailure):
        return str(value)
    if isinstance(value, frozenset):
        return "|".join(sorted(value)) or None
    if value is None or isinstance(value, bool):
        return value
    if name in PATH_FIELDS:
        return _safe_path(value) if value != "" else ""
    text = str(value)
    return "<redacted>" if find_secrets(text) else text


def _present(value: Any) -> bool:
    if isinstance(value, LegacyFailure):
        return False
    return bool(value)


@dataclass(frozen=True)
class FieldDifference:
    """One field on which legacy and the migrated provider disagree.

    ``legacy_value`` / ``new_value`` are already made safe: paths are
    shortened (``%PROGRAMFILES%``, ``%USERPROFILE%``, ``<user>``), secret-shaped
    text is replaced, a legacy exception appears as ``error:<Type>``.
    """

    field: str
    reason: str
    legacy_value: Any = None
    new_value: Any = None
    legacy_present: bool = False
    new_present: bool = False


@dataclass(frozen=True)
class DetectionComparison:
    """Outcome of comparing one legacy snapshot with one provider result."""

    provider_id: str
    equal: bool
    reason: str = REASON_EQUAL
    differences: tuple[FieldDifference, ...] = ()
    #: Legacy calls that raised (snapshot keys, e.g. ``("free_edition",)``).
    legacy_errors: tuple[str, ...] = ()
    #: Exception type / reason code when the migrated provider failed.
    new_error: str | None = None
    compared_fields: tuple[str, ...] = FIELDS

    # -- convenience for the common single-difference case ----------------- #

    @property
    def fields(self) -> tuple[str, ...]:
        return tuple(d.field for d in self.differences)

    @property
    def field(self) -> str | None:
        return self.differences[0].field if self.differences else None

    @property
    def legacy_value(self) -> Any:
        return self.differences[0].legacy_value if self.differences else None

    @property
    def new_value(self) -> Any:
        return self.differences[0].new_value if self.differences else None

    def difference(self, name: str) -> FieldDifference | None:
        for diff in self.differences:
            if diff.field == name:
                return diff
        return None

    def to_trace_data(self) -> dict:
        """Presence flags and field names only — never a value, never a path."""
        data: dict[str, Any] = {
            "provider": self.provider_id,
            "detection_parity": bool(self.equal),
            "reason": self.reason,
            "diff_count": len(self.differences),
        }
        if self.differences:
            first = self.differences[0]
            data.update(field=first.field, fields=",".join(self.fields),
                        legacy_present=first.legacy_present,
                        new_present=first.new_present)
        if self.legacy_errors:
            data["legacy_errors"] = ",".join(self.legacy_errors)
        if self.new_error:
            data["new_error"] = self.new_error
        return data


def _same(name: str, legacy_value: Any, new_value: Any) -> bool:
    if name == "source":
        return new_value in legacy_value if legacy_value else new_value is None
    if name in PATH_FIELDS:
        def norm(p):
            return str(p).replace("/", "\\").rstrip("\\").lower() if p else ""
        return norm(legacy_value) == norm(new_value)
    return legacy_value == new_value


def compare_detection(legacy: LegacySnapshot,
                      new: DetectionResult | BaseException | None) -> DetectionComparison:
    """Compare on meaning.  Never raises; `new` may be an exception or None."""
    try:
        return _compare(legacy, new)
    except Exception as exc:                            # our own bug — still data
        return DetectionComparison(PROVIDER_ID, equal=False,
                                   reason=REASON_COMPARISON_FAILED,
                                   new_error=type(exc).__name__)


def _compare(legacy: LegacySnapshot, new) -> DetectionComparison:
    legacy_errors = tuple(legacy.failures)
    legacy_n = normalize_legacy(legacy)

    if new is None:
        return DetectionComparison(PROVIDER_ID, equal=False,
                                   reason=REASON_PROVIDER_MISSING,
                                   legacy_errors=legacy_errors)

    new_error = None
    if isinstance(new, BaseException):
        new_error = type(new).__name__
    elif not isinstance(new, DetectionResult):
        new_error = f"unexpected-{type(new).__name__}"
    elif new.state is DetectionState.ERROR:
        new_error = str(new.metadata.get("reason_code") or new.error_code or "error")
    if new_error is not None:
        legacy_state = legacy_n["state"]
        diff = FieldDifference(
            "state", REASON_NEW_ERROR,
            legacy_value=_safe_value("state", legacy_state),
            new_value=DetectionState.ERROR.value,
            legacy_present=_present(legacy_state), new_present=False)
        return DetectionComparison(PROVIDER_ID, equal=False,
                                   reason=REASON_NEW_ERROR, differences=(diff,),
                                   legacy_errors=legacy_errors,
                                   new_error=new_error)

    new_n = normalize_provider(new)
    differences: list[FieldDifference] = []
    for name in FIELDS:
        lv, nv = legacy_n[name], new_n[name]
        if isinstance(lv, LegacyFailure):
            reason = REASON_LEGACY_ERROR
        elif _same(name, lv, nv):
            continue
        else:
            reason = REASON_MISMATCH
        differences.append(FieldDifference(
            name, reason,
            legacy_value=_safe_value(name, lv), new_value=_safe_value(name, nv),
            legacy_present=_present(lv), new_present=_present(nv)))

    if not differences:
        reason = REASON_EQUAL
    elif any(d.reason == REASON_LEGACY_ERROR for d in differences):
        reason = REASON_LEGACY_ERROR
    else:
        reason = REASON_MISMATCH
    return DetectionComparison(PROVIDER_ID, equal=not differences, reason=reason,
                               differences=tuple(differences),
                               legacy_errors=legacy_errors)


# --------------------------------------------------------------------------- #
# Running it                                                                   #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class ShadowDetection:
    """One shadow run: the production (legacy) answer and the comparison."""

    legacy: LegacySnapshot
    comparison: DetectionComparison


def _run_provider(registry, app_path: str):
    try:
        provider = registry.get(PROVIDER_ID)
    except Exception as exc:
        return exc
    if provider is None:
        return None
    try:
        return provider.detect(VpnRequest(provider_id=PROVIDER_ID,
                                          app_path=app_path))
    except Exception as exc:
        return exc


def record_comparison(trace, comparison: DetectionComparison) -> None:
    """Write a comparison into an existing diagnostics trace.  Never raises.

    `trace` is what :func:`diagnostics.vpn.start` returned (or its no-op).
    Only :meth:`DetectionComparison.to_trace_data` is written — flags and
    field names, no values.
    """
    if trace is None or comparison is None:
        return
    try:
        trace.step(TRACE_STEP, "ok" if comparison.equal else "warn",
                   **comparison.to_trace_data())
    except Exception:
        pass


def shadow_detect_forticlient(app_path: str = "", *, registry=None, legacy=None,
                              trace=None) -> ShadowDetection:
    """Run legacy and migrated FortiClient detection and compare them.

    Explicit calls only.  Returns the legacy snapshot untouched plus the
    comparison; never raises, never launches, waits, polls or shows anything.
    `registry` defaults to :data:`vpn.default_registry`, `legacy` to the
    `vpn_connect` module; `trace`, when given, receives one safe step.
    """
    app_path = app_path or ""
    snapshot = collect_legacy_detection(app_path, legacy)
    try:
        if registry is None:
            from .registry import default_registry as registry
        new = _run_provider(registry, app_path)
        comparison = compare_detection(snapshot, new)
    except Exception as exc:
        comparison = DetectionComparison(PROVIDER_ID, equal=False,
                                         reason=REASON_COMPARISON_FAILED,
                                         new_error=type(exc).__name__)
    record_comparison(trace, comparison)
    return ShadowDetection(snapshot, comparison)
