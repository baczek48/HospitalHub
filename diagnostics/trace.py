"""Operation tracing for HospitalHub diagnostics.

A trace answers one question: *which step of this operation failed, and how
long did each step take?*  That is exactly the question we cannot answer today
when a VPN connection misbehaves on somebody else's machine.

Usage::

    rec = TraceRecorder("vpn.connect", meta={"provider": "FortiClient"})
    with rec.step("forti.detect") as st:
        st.ok(source="registry", app_version="7.4.1")
    with rec.step("forti.launch") as st:
        st.warn(strategy="explorer_lnk", started=False)
    rec.finish("fail", error_code="window-not-found")

Every step's payload goes through :func:`redactor.redact` in RUNTIME mode
*before* it is stored, so a secret accidentally handed to a step never reaches
the disk.  Steps are thread-safe: VPN work happens on worker threads.
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from . import redactor
from .redactor import Masker, Mode, RedactionReport

STATUS_OK = "ok"
STATUS_WARN = "warn"
STATUS_FAIL = "fail"
VALID_STATUSES = (STATUS_OK, STATUS_WARN, STATUS_FAIL)

#: How many traces stay on disk.  Twenty covers "the last few attempts plus
#: whatever the user did before them" without turning into an unbounded log.
DEFAULT_RETENTION = 20

TRACE_SCHEMA = "hospitalhub.trace/1"


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="milliseconds")


# --------------------------------------------------------------------------- #
# Steps                                                                        #
# --------------------------------------------------------------------------- #

@dataclass
class TraceStep:
    """One step of an operation.  `data` is already redacted."""

    name: str
    status: str = STATUS_OK
    started_at: str = ""
    duration_ms: float = 0.0
    data: dict = field(default_factory=dict)
    error_code: str | None = None
    message: str | None = None

    def to_dict(self) -> dict:
        out: dict[str, Any] = {
            "step": self.name,
            "status": self.status,
            "started_at": self.started_at,
            "duration_ms": round(self.duration_ms, 3),
        }
        if self.error_code:
            out["error_code"] = self.error_code
        if self.message:
            out["message"] = self.message
        if self.data:
            out["data"] = self.data
        return out


class StepContext:
    """Context manager returned by :meth:`TraceRecorder.step`.

    Defaults to ``ok``.  An exception escaping the block marks the step as
    ``fail`` with the exception type as error code — and is then re-raised,
    because diagnostics observes the operation, it does not decide for it.
    """

    def __init__(self, recorder: "TraceRecorder", name: str):
        self._recorder = recorder
        self._name = name
        self._status = STATUS_OK
        self._data: dict[str, Any] = {}
        self._error_code: str | None = None
        self._message: str | None = None
        self._started_at = ""
        self._t0 = 0.0
        self._closed = False

    # -- payload ----------------------------------------------------------- #

    def set(self, **data: Any) -> "StepContext":
        self._data.update(data)
        return self

    def ok(self, **data: Any) -> "StepContext":
        self._status = STATUS_OK
        return self.set(**data)

    def warn(self, message: str | None = None, **data: Any) -> "StepContext":
        self._status = STATUS_WARN
        if message is not None:
            self._message = message
        return self.set(**data)

    def fail(self, error_code: str | None = None, message: str | None = None,
             **data: Any) -> "StepContext":
        self._status = STATUS_FAIL
        if error_code is not None:
            self._error_code = error_code
        if message is not None:
            self._message = message
        return self.set(**data)

    # -- lifecycle --------------------------------------------------------- #

    def __enter__(self) -> "StepContext":
        self._started_at = _iso(self._recorder._clock())
        self._t0 = self._recorder._monotonic()
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        if exc_type is not None:
            self._status = STATUS_FAIL
            if self._error_code is None:
                self._error_code = exc_type.__name__
            if self._message is None:
                self._message = str(exc)[:400]
        self._commit()
        return False                      # never swallow — caller decides

    def _commit(self) -> None:
        if self._closed:
            return
        self._closed = True
        duration = (self._recorder._monotonic() - self._t0) * 1000.0
        self._recorder._append(TraceStep(
            name=self._name,
            status=self._status,
            started_at=self._started_at,
            duration_ms=duration,
            data=self._data,
            error_code=self._error_code,
            message=self._message,
        ))


# --------------------------------------------------------------------------- #
# Store (retention)                                                            #
# --------------------------------------------------------------------------- #

class TraceStore:
    """Rotating on-disk store: one ``.jsonl`` file per trace, newest N kept."""

    _write_lock = threading.Lock()

    def __init__(self, directory: str | os.PathLike, retention: int = DEFAULT_RETENTION):
        self.directory = Path(directory)
        self.retention = max(1, int(retention))

    def _ensure_dir(self) -> None:
        self.directory.mkdir(parents=True, exist_ok=True)

    def path_for(self, trace: dict) -> Path:
        stamp = str(trace.get("started_at", ""))[:19]
        stamp = "".join(ch for ch in stamp if ch.isdigit()) or "00000000000000"
        return self.directory / f"trace-{stamp}-{trace.get('trace_id', 'unknown')}.jsonl"

    def write(self, trace: dict) -> Path:
        """Persist a finished trace: header line, then one line per step."""
        self._ensure_dir()
        target = self.path_for(trace)
        header = {k: v for k, v in trace.items() if k != "steps"}
        header["kind"] = "trace"
        lines = [json.dumps(header, ensure_ascii=False)]
        for step in trace.get("steps", []):
            line = dict(step)
            line["kind"] = "step"
            line["trace_id"] = trace.get("trace_id")
            lines.append(json.dumps(line, ensure_ascii=False))
        with self._write_lock:
            tmp = target.with_suffix(".tmp")
            tmp.write_text("\n".join(lines) + "\n", encoding="utf-8")
            os.replace(tmp, target)
            self.prune()
        return target

    def list_traces(self) -> list[Path]:
        """Newest first."""
        if not self.directory.is_dir():
            return []
        files = [p for p in self.directory.glob("trace-*.jsonl") if p.is_file()]
        return sorted(files, key=lambda p: p.name, reverse=True)

    def prune(self) -> list[Path]:
        """Delete everything past the retention limit. Returns removed paths."""
        removed: list[Path] = []
        for old in self.list_traces()[self.retention:]:
            try:
                old.unlink()
                removed.append(old)
            except OSError:
                pass
        return removed

    def read_jsonl(self, limit: int | None = None) -> str:
        """Concatenate the newest `limit` traces into one JSONL document."""
        files = self.list_traces()
        if limit is not None:
            files = files[:limit]
        chunks: list[str] = []
        for path in reversed(files):          # oldest first in the output
            try:
                chunks.append(path.read_text(encoding="utf-8").rstrip("\n"))
            except OSError:
                continue
        return ("\n".join(chunks) + "\n") if chunks else ""

    def stats(self) -> dict:
        files = self.list_traces()
        return {
            "count": len(files),
            "retention": self.retention,
            "size_bytes": sum((p.stat().st_size for p in files if p.exists()), 0),
        }

    def clear(self) -> None:
        for path in self.list_traces():
            try:
                path.unlink()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# Recorder                                                                     #
# --------------------------------------------------------------------------- #

class TraceRecorder:
    """Records one operation as an ordered list of steps."""

    def __init__(self, operation: str, meta: dict | None = None,
                 store: TraceStore | None = None, masker: Masker | None = None,
                 clock: Callable[[], datetime] | None = None,
                 monotonic: Callable[[], float] | None = None,
                 trace_id: str | None = None):
        self.operation = str(operation)
        self._clock = clock or _utc_now
        self._monotonic = monotonic or time.monotonic
        self._masker = masker or redactor.default_masker()
        self._store = store
        self._lock = threading.RLock()
        self._steps: list[TraceStep] = []
        self._redaction = RedactionReport()
        self._started = self._clock()
        self._t0 = self._monotonic()
        self._finished_at: datetime | None = None
        self._end_monotonic: float | None = None
        self._status: str | None = None
        self._error_code: str | None = None
        self._result: dict = {}
        self.trace_id = trace_id or uuid.uuid4().hex[:12]
        self.meta = self._clean(meta or {})

    # -- internals --------------------------------------------------------- #

    def _clean(self, data: dict) -> dict:
        return redactor.redact(data, mode=Mode.RUNTIME, masker=self._masker,
                               report=self._redaction)

    def _append(self, step: TraceStep) -> None:
        step.data = self._clean(step.data)
        if step.message:
            step.message = self._clean({"message": step.message})["message"]
        with self._lock:
            self._steps.append(step)

    # -- public API -------------------------------------------------------- #

    def step(self, name: str) -> StepContext:
        """Open a timed step; use as a context manager."""
        return StepContext(self, name)

    def add_step(self, name: str, status: str = STATUS_OK,
                 duration_ms: float = 0.0, error_code: str | None = None,
                 message: str | None = None, **data: Any) -> TraceStep:
        """Record a step that was timed elsewhere (or takes no measurable time)."""
        if status not in VALID_STATUSES:
            raise ValueError(f"nieznany status kroku: {status!r}")
        step = TraceStep(
            name=name, status=status, started_at=_iso(self._clock()),
            duration_ms=float(duration_ms), data=dict(data),
            error_code=error_code, message=message,
        )
        self._append(step)
        return step

    @property
    def steps(self) -> list[TraceStep]:
        with self._lock:
            return list(self._steps)

    @property
    def duration_ms(self) -> float:
        end = self._end_monotonic
        if end is None:
            end = self._monotonic()
        return (end - self._t0) * 1000.0

    @property
    def redaction(self) -> RedactionReport:
        return self._redaction

    def worst_status(self) -> str:
        statuses = {s.status for s in self.steps}
        if STATUS_FAIL in statuses:
            return STATUS_FAIL
        if STATUS_WARN in statuses:
            return STATUS_WARN
        return STATUS_OK

    def to_dict(self) -> dict:
        with self._lock:
            return {
                "schema": TRACE_SCHEMA,
                "trace_id": self.trace_id,
                "operation": self.operation,
                "started_at": _iso(self._started),
                "ended_at": _iso(self._finished_at) if self._finished_at else "",
                "duration_ms": round(self.duration_ms, 3),
                "status": self._status or self.worst_status(),
                **({"error_code": self._error_code} if self._error_code else {}),
                "meta": self.meta,
                "result": self._result,
                "steps": [s.to_dict() for s in self._steps],
            }

    def finish(self, status: str | None = None, error_code: str | None = None,
               store: TraceStore | None = None, **result: Any) -> Path | None:
        """Close the trace and persist it. Returns the file path (or None)."""
        if status is not None and status not in VALID_STATUSES:
            raise ValueError(f"nieznany status trace'u: {status!r}")
        self._end_monotonic = self._monotonic()
        self._finished_at = self._clock()
        self._status = status or self.worst_status()
        self._error_code = error_code
        self._result = self._clean(result)

        target_store = store or self._store
        if target_store is None:
            from . import get_store            # local import: avoids a cycle
            target_store = get_store()
        if target_store is None:
            return None
        return target_store.write(self.to_dict())
