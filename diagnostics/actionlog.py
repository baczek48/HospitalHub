"""Opt-in, human-readable log of VPN actions and application errors.

Why: the JSONL traces describe one operation each and are meant for an
export; when a VPN misbehaves on a colleague's computer the person debugging
it wants one plain text file to read top to bottom — what was clicked, what
the client said back, which error came up.  This module writes that file,
but only after the user switched it on in the VPN settings (per computer).

What never gets in: passwords, logins, tokens.  Every line is built from
values we chose, passes through :mod:`diagnostics.redactor` (servers and
logins masked, unknown keys dropped), has every secret the panel registered
(the profiles' passwords and logins) replaced by ``***``, and is finally
scanned; a line that still looks like it holds a secret is replaced by a
note saying so.  The profile *name* and the provider stay readable — without
them the log could not say which tunnel failed.

Like the rest of the package this imports nothing from the application; the
UI tells it whether it is enabled (:func:`set_enabled`).
"""

from __future__ import annotations

import os
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

#: Rotated at this size: vpn.log → vpn.log.1 → … → vpn.log.<_KEEP>.
MAX_BYTES = 1024 * 1024
_KEEP = 3
#: Secrets shorter than this are not scrubbed: "a" or "12" would shred the
#: log while protecting nothing worth protecting.
_MIN_SECRET_LEN = 3
_LINE_LIMIT = 2000

_lock = threading.Lock()
_enabled = False
_secrets: set[str] = set()


def log_dir() -> Path:
    from . import base_dir
    return base_dir() / "logs"


def log_path() -> Path:
    return log_dir() / "vpn.log"


def log_files() -> list[Path]:
    """Oldest first, the current file last."""
    base = log_path()
    rotated = [base.with_name(f"{base.name}.{i}") for i in range(_KEEP, 0, -1)]
    return [p for p in rotated + [base] if p.is_file()]


def is_enabled() -> bool:
    return _enabled


def set_enabled(enabled: bool) -> None:
    """Switch the log on/off; the change itself is written while it is on."""
    global _enabled
    enabled = bool(enabled)
    if enabled == _enabled:
        return
    if not enabled:
        info("log", "Logowanie wyłączone")
        _enabled = False
        return
    _enabled = True
    info("log", "Logowanie włączone")


def register_secrets(values: Iterable[Any]) -> None:
    """Values that must never appear in the log (replaced by ``***``)."""
    with _lock:
        for value in values:
            text = str(value or "")
            if len(text) >= _MIN_SECRET_LEN:
                _secrets.add(text)


def read_text() -> str:
    """Every log file, oldest first, as one text."""
    chunks = []
    for path in log_files():
        try:
            chunks.append(path.read_text(encoding="utf-8", errors="replace"))
        except OSError:
            continue
    return "".join(chunks)


def clear() -> None:
    with _lock:
        for path in log_files():
            try:
                path.unlink()
            except OSError:
                pass


# --------------------------------------------------------------------------- #
# Writing                                                                      #
# --------------------------------------------------------------------------- #

def info(area: str, what: str, /, **fields: Any) -> None:
    _write("INFO", area, what, fields)


def warn(area: str, what: str, /, **fields: Any) -> None:
    _write("WARN", area, what, fields)


def error(area: str, what: str, /, **fields: Any) -> None:
    _write("BŁĄD", area, what, fields)


def exception_text(text: str, where: str = "") -> None:
    """An uncaught exception (the formatted traceback from main.py)."""
    if not _enabled:
        return
    head = "Nieobsłużony wyjątek" + (f" {where.strip()}" if where.strip() else "")
    _write("BŁĄD", "app", head, {}, body=text)


def trace_written(trace: dict) -> None:
    """A finished diagnostics trace (already redacted by its recorder)."""
    if not _enabled:
        return
    try:
        operation = str(trace.get("operation", "?"))
        status = str(trace.get("status", "?"))
        level = {"ok": "INFO", "warn": "WARN"}.get(status, "BŁĄD")
        meta = trace.get("meta") or {}
        fields = {k: v for k, v in meta.items()
                  if isinstance(v, (str, int, float, bool)) and v != ""}
        if trace.get("error_code"):
            fields["error_code"] = trace["error_code"]
        fields["duration_ms"] = int(float(trace.get("duration_ms") or 0))
        body_lines = []
        for step in trace.get("steps") or []:
            line = f"  · {step.get('step', '?')}: {step.get('status', '?')}"
            if step.get("error_code"):
                line += f" [{step['error_code']}]"
            if step.get("message"):
                line += f" — {step['message']}"
            data = step.get("data") or {}
            extra = " ".join(f"{k}={v}" for k, v in data.items()
                             if isinstance(v, (str, int, float, bool)))
            if extra:
                line += f"  ({extra})"
            body_lines.append(line)
        _write(level, operation, f"zakończono: {status}", fields,
               body="\n".join(body_lines), already_redacted=True)
    except Exception:
        pass


def _scrub(text: str) -> str:
    with _lock:
        secrets = sorted(_secrets, key=len, reverse=True)
    for secret in secrets:
        if secret in text:
            text = text.replace(secret, "***")
    return text


def _format_fields(fields: dict, already_redacted: bool) -> str:
    if not fields:
        return ""
    if not already_redacted:
        from .redactor import redact
        clean = {}
        for key, value in fields.items():
            # The profile name and provider stay readable on purpose (see the
            # module docstring); everything else goes through the redactor.
            if key in ("profile", "provider", "operation", "result", "error_code"):
                clean[key] = value
            else:
                clean.update(redact({key: value}))
        fields = clean
    from .redactor import DROPPED
    parts = [f"{k}={v}" for k, v in fields.items() if v != DROPPED]
    return "  " + " ".join(parts) if parts else ""


def _write(level: str, area: str, message: str, fields: dict, body: str = "",
           already_redacted: bool = False) -> None:
    if not _enabled:
        return
    try:
        from .redactor import find_secrets
        stamp = datetime.now().isoformat(sep=" ", timespec="milliseconds")
        line = f"{stamp}  {level:<4}  {area}  {message}"
        line += _format_fields(fields, already_redacted)
        text = line[:_LINE_LIMIT]
        if body:
            text += "\n" + "\n".join("    " + b for b in body.splitlines())
        text = _scrub(text)
        if find_secrets(text):
            text = (f"{stamp}  {level:<4}  {area}  [wpis pominięty: wyglądał na "
                    f"zawierający sekret]")
        _append(text + "\n")
    except Exception:
        # The log is a helper: it must never break the action it describes.
        pass


def _append(text: str) -> None:
    path = log_path()
    with _lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        try:
            if path.stat().st_size + len(text) > MAX_BYTES:
                _rotate(path)
        except OSError:
            pass
        with open(path, "a", encoding="utf-8") as f:
            f.write(text)


def _rotate(path: Path) -> None:
    oldest = path.with_name(f"{path.name}.{_KEEP}")
    if oldest.exists():
        oldest.unlink()
    for i in range(_KEEP - 1, 0, -1):
        src = path.with_name(f"{path.name}.{i}")
        if src.exists():
            os.replace(src, path.with_name(f"{path.name}.{i + 1}"))
    os.replace(path, path.with_name(f"{path.name}.1"))


def reset_for_tests() -> None:
    global _enabled
    _enabled = False
    with _lock:
        _secrets.clear()
