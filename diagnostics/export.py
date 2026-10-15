"""Building and writing the diagnostics package.

Everything is assembled **in memory** first, checked, and only then written to
a ZIP.  A failed check means no file at all — a half-written package that a
user might still send is the outcome we are trying to avoid.

Pipeline::

    collectors (raw)
        → redactor.redact(Mode.EXPORT)        ← named secrets scrubbed,
        → serialise to JSON / text              unknown-shaped secrets RAISE
        → find_secrets() on the final bytes   ← last gate, per file
        → sha256 each file
        → manifest.json (digests are exempt from the scan)
        → zip

Package contents:

    report.json     structured facts (redacted)
    report.txt      the same, readable without a JSON viewer
    trace.jsonl     recent operation traces (already redacted at record time)
    manifest.json   schema, id, file list + SHA-256 of each file
    REDACTION.txt   what was removed and by which rule
"""

from __future__ import annotations

import hashlib
import json
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import collector as _collector
from . import redactor
from .redactor import Masker, Mode, RedactionReport

REPORT_SCHEMA = "hospitalhub.diagnostics/1"

REPORT_JSON = "report.json"
REPORT_TXT = "report.txt"
TRACE_JSONL = "trace.jsonl"
MANIFEST_JSON = "manifest.json"
REDACTION_TXT = "REDACTION.txt"


@dataclass
class ExportResult:
    path: Path
    report_id: str
    files: list[str] = field(default_factory=list)
    digests: dict[str, str] = field(default_factory=dict)
    size_bytes: int = 0
    redaction: dict = field(default_factory=dict)


@dataclass
class ExportBundle:
    """The finished package, still in memory — this is what `preview` shows."""

    report_id: str
    files: dict[str, str]                     # name → text content
    report: dict
    redaction: RedactionReport

    def digests(self) -> dict[str, str]:
        return {name: hashlib.sha256(text.encode("utf-8")).hexdigest()
                for name, text in self.files.items()}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _report_id(moment: datetime) -> str:
    return moment.strftime("%Y%m%d-%H%M%S")


# --------------------------------------------------------------------------- #
# Rendering                                                                    #
# --------------------------------------------------------------------------- #

def _render_text(data: Any, indent: int = 0, lines: list[str] | None = None) -> list[str]:
    lines = lines if lines is not None else []
    pad = "  " * indent
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, (dict, list)) and value:
                lines.append(f"{pad}{key}:")
                _render_text(value, indent + 1, lines)
            else:
                lines.append(f"{pad}{key}: {_scalar_text(value)}")
    elif isinstance(data, list):
        for i, item in enumerate(data):
            if isinstance(item, (dict, list)):
                lines.append(f"{pad}- [{i}]")
                _render_text(item, indent + 1, lines)
            else:
                lines.append(f"{pad}- {_scalar_text(item)}")
    else:
        lines.append(f"{pad}{_scalar_text(data)}")
    return lines


def _scalar_text(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, bool):
        return "tak" if value else "nie"
    if isinstance(value, (list, dict)) and not value:
        return "—"
    return str(value)


def _render_redaction(report: RedactionReport) -> str:
    data = report.as_dict()
    lines = [
        "HospitalHub — diagnostyka: raport redakcji",
        "",
        "Zasady:",
        "  * dozwolone są wyłącznie znane klucze (allowlist); nieznane → <dropped:unknown-key>",
        "  * klucze zawierające pass/pwd/secret/token/otp/code/key/cred/pin/hash/salt/auth",
        "    → <redacted:secret-key>, niezależnie od allowlisty",
        "  * adresy IP, hosty, loginy i nazwy profili → stabilne pseudonimy (spójne w tym raporcie)",
        "  * komendy procesów → nazwa exe + liczba argumentów + bezpieczne flagi; wartości nigdy",
        "  * wartości pól formularzy (UI Automation) nie są w ogóle odczytywane",
        "  * zawartość vaulta nie jest zbierana",
        "",
        "Uwaga: trace.jsonl został zredagowany już w chwili zapisu kroku",
        "(tryb RUNTIME), więc jego statystyki nie są ujęte w liczbach poniżej —",
        "te dotyczą danych zebranych w momencie eksportu.",
        "",
        f"Kluczy zredagowanych (nazwa sekretu): {sum(data['redacted_keys'].values())}",
    ]
    for key, count in data["redacted_keys"].items():
        lines.append(f"    {key}: {count}")
    lines.append(f"Kluczy odrzuconych (spoza allowlisty): {sum(data['dropped_keys'].values())}")
    for key, count in data["dropped_keys"].items():
        lines.append(f"    {key}: {count}")
    lines.append(f"Wartości zamaskowanych: {sum(data['masked_keys'].values())}")
    for key, count in data["masked_keys"].items():
        lines.append(f"    {key}: {count}")
    lines.append(f"Wartości przyciętych: {data['truncated']}")
    if data["blocked"]:
        lines.append("")
        lines.append("Zablokowane w czasie działania (wyglądały jak sekret):")
        for where in data["blocked"]:
            lines.append(f"    {where}")
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# Building                                                                     #
# --------------------------------------------------------------------------- #

def build(sections: list[str] | None = None, extra: dict | None = None,
          include_traces: bool = True, trace_limit: int | None = None,
          masker: Masker | None = None, store=None) -> ExportBundle:
    """Assemble the package in memory. Raises :class:`SecretLeakError` on leaks."""
    from . import APP_NAME, APP_VARIANT, APP_VERSION, get_store

    masker = masker or redactor.default_masker()
    report_obj = RedactionReport()
    created = _now()
    report_id = _report_id(created)

    raw_sections = _collector.collect(sections, safe=False)
    clean_sections = redactor.redact(raw_sections, mode=Mode.EXPORT,
                                     masker=masker, report=report_obj)

    report: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "report_id": report_id,
        "created_at": created.isoformat(timespec="seconds"),
        "app_name": APP_NAME,
        "app_variant": APP_VARIANT,
        "app_version": APP_VERSION,
        "sections": clean_sections,
    }
    if extra:
        report["extra"] = redactor.redact(extra, mode=Mode.EXPORT,
                                          masker=masker, report=report_obj)

    trace_text = ""
    if include_traces:
        target_store = store or get_store()
        if target_store is not None:
            trace_text = target_store.read_jsonl(limit=trace_limit)

    files = {
        REPORT_JSON: json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        REPORT_TXT: "\n".join(_render_text(report)) + "\n",
        TRACE_JSONL: trace_text,
        REDACTION_TXT: _render_redaction(report_obj),
    }
    return ExportBundle(report_id=report_id, files=files, report=report,
                        redaction=report_obj)


def _gate(bundle: ExportBundle) -> dict[str, str]:
    """Last line of defence: scan every file, then build the manifest.

    Returns the digests. Raises :class:`SecretLeakError` if any file still
    contains something that looks like a secret — we refuse to write rather
    than scrub silently, because at this point we no longer know what we are
    scrubbing.
    """
    for name, text in bundle.files.items():
        redactor.assert_no_secrets(text, where=name)
    return bundle.digests()


def manifest_for(bundle: ExportBundle, digests: dict[str, str]) -> str:
    from . import APP_VARIANT, APP_VERSION

    manifest = {
        "schema": REPORT_SCHEMA,
        "report_id": bundle.report_id,
        "created_at": bundle.report.get("created_at"),
        "app_variant": APP_VARIANT,
        "app_version": APP_VERSION,
        "files": [
            {"name": name, "size_bytes": len(text.encode("utf-8")),
             "sha256": digests[name]}
            for name, text in sorted(bundle.files.items())
        ],
        "redaction": bundle.redaction.as_dict(),
    }
    text = json.dumps(manifest, ensure_ascii=False, indent=2) + "\n"
    # The manifest legitimately contains 64-hex digests, which the secret
    # scanner would otherwise flag as high-entropy blobs. Exempt exactly those
    # literals — nothing else.
    redactor.assert_no_secrets(text, where=MANIFEST_JSON,
                               allow_literals=set(digests.values()))
    return text


def preview(sections: list[str] | None = None, extra: dict | None = None,
            include_traces: bool = True, trace_limit: int | None = None,
            masker: Masker | None = None, store=None) -> ExportBundle:
    """Build and check the package without writing anything.

    This is what the UI will show the user before they agree to save or send.
    """
    bundle = build(sections=sections, extra=extra, include_traces=include_traces,
                   trace_limit=trace_limit, masker=masker, store=store)
    _gate(bundle)
    return bundle


def export(dest_dir: str | Path | None = None, filename: str | None = None,
           sections: list[str] | None = None, extra: dict | None = None,
           include_traces: bool = True, trace_limit: int | None = None,
           masker: Masker | None = None, store=None) -> ExportResult:
    """Write the diagnostics ZIP. Nothing is written if any check fails."""
    from . import export_dir

    bundle = build(sections=sections, extra=extra, include_traces=include_traces,
                   trace_limit=trace_limit, masker=masker, store=store)
    digests = _gate(bundle)
    manifest_text = manifest_for(bundle, digests)

    files = dict(bundle.files)
    files[MANIFEST_JSON] = manifest_text
    digests[MANIFEST_JSON] = hashlib.sha256(manifest_text.encode("utf-8")).hexdigest()

    target_dir = Path(dest_dir) if dest_dir else export_dir()
    target_dir.mkdir(parents=True, exist_ok=True)
    name = filename or f"HospitalHub-diag-{bundle.report_id}.zip"
    target = target_dir / name

    tmp = target.with_suffix(".zip.tmp")
    with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        for entry, text in sorted(files.items()):
            zf.writestr(entry, text)
    tmp.replace(target)

    return ExportResult(
        path=target,
        report_id=bundle.report_id,
        files=sorted(files),
        digests=digests,
        size_bytes=target.stat().st_size,
        redaction=bundle.redaction.as_dict(),
    )
