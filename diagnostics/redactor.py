"""Central redaction layer for HospitalHub diagnostics.

This module is the **only** sanctioned way for diagnostic data to reach a file.
No collector, trace or exporter may write a value it has not passed through
:func:`redact` first.

Design — allowlist, not blocklist
---------------------------------
A key is emitted only when it appears in :data:`ALLOWED_KEYS` (or has been
registered later via :func:`allow_keys`).  Everything else is dropped with a
``<dropped:unknown-key>`` marker.  We never reason "this field isn't called
password, so it must be safe" — an unknown field is assumed unsafe.

On top of that allowlist sits a hard blocklist (:data:`SECRET_TOKENS`).  A key
whose name contains any of those tokens is redacted even if somebody added it
to the allowlist by mistake.  The two layers are deliberately redundant.

Two modes
---------
``Mode.RUNTIME``
    Used while the application is running (trace steps, live views).  A value
    that *looks* like a secret is replaced with ``<blocked:looks-like-secret>``
    so it never lands on disk.  Nothing raises — diagnostics must never break
    the operation it is observing.

``Mode.EXPORT``
    Used when building an export package.  A value that looks like a secret
    raises :class:`SecretLeakError` instead of being quietly scrubbed, because
    at that point silence would be the dangerous outcome: the export is about
    to leave the machine and we would rather fail loudly than ship a file whose
    contents we do not fully understand.

Masking
-------
Infrastructure identifiers (IPs, hostnames, logins, profile names) are not
dropped — they are replaced with stable pseudonyms via :class:`Masker`, so a
reader can still tell "the same host appears in step 2 and step 7" without
learning anything about the hospital's topology.  The mapping is salted per
process, so two exports from the same machine do not share identifiers.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import os
import re
import secrets as _secrets
import shlex
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# --------------------------------------------------------------------------- #
# Placeholders                                                                 #
# --------------------------------------------------------------------------- #

REDACTED = "<redacted:secret-key>"
DROPPED = "<dropped:unknown-key>"
BLOCKED = "<blocked:looks-like-secret>"
MASKED_ARGS = "<masked:args>"
TRUNCATED = "…<truncated>"

MAX_TEXT_LEN = 500
MAX_VALUE_LEN = 200
MAX_LIST_LEN = 200
MAX_DEPTH = 6


class Mode(Enum):
    RUNTIME = "runtime"
    EXPORT = "export"


class SecretLeakError(Exception):
    """Raised when data heading for an export looks like a secret.

    The message never contains the offending value — only where it was found
    and which rule matched.
    """


# --------------------------------------------------------------------------- #
# Key classification                                                           #
# --------------------------------------------------------------------------- #

#: Substrings that make a key sensitive no matter what.  Checked before the
#: allowlist, so a mistake in the allowlist cannot leak a named secret.
SECRET_TOKENS = (
    "pass", "pwd", "password", "passphrase", "secret", "token", "otp",
    "code", "key", "cred", "credential", "pin", "hash", "salt", "auth",
    "bearer", "cookie", "session", "private", "signature", "seed",
)

#: Keys that contain a SECRET_TOKENS substring but are provably harmless.
#: Kept as an exact-match list so adding one is a conscious act.
ALLOW_EXACT_OVERRIDES = frozenset({
    "error_code", "exit_code", "status_code", "return_code", "country_code",
    "language_code", "sha256", "keyboard_layout", "public_key_type",
    "known_hosts_count", "code_page", "session_count",
    "saved_credentials_policy", "credential_injected",
    # PyInstaller's _MEIPASS marker happens to contain "pass"; it is a boolean
    # flag and the single best clue for the FortiClient/Electron launch bug.
    "has_meipass", "meipass_env_present", "session_type",
    # Boolean "were credentials available at all" flag — no value, just yes/no.
    "has_credentials",
    # Exception type / reason label; "code" makes it look sensitive, it is not.
    "reason_code",
})

#: Keys whose value is an IP address (or host:port).
IP_KEYS = frozenset({
    "ip", "ipv4", "ipv6", "local_ip", "remote_ip", "server_ip", "peer_ip",
    "gateway", "dns", "address",
})

#: Keys whose value names a host.
HOST_KEYS = frozenset({
    "host", "hostname", "server", "portal", "fqdn", "endpoint", "target",
})

#: Keys that identify a person, tenant or site.  Masked (not dropped) so that
#: repeated occurrences stay correlatable.
IDENTITY_KEYS = frozenset({
    "user", "username", "login", "account", "domain", "email", "profile",
    "profile_name", "tunnel", "tunnel_name", "hospital", "site", "label",
    "vault", "vault_label", "machine", "machine_name", "group",
})

#: Keys holding a filesystem path — shortened, user name stripped.
PATH_KEYS = frozenset({
    "path", "exe_path", "app_path", "install_dir", "log_path", "file",
    "filename", "dir", "directory", "cwd", "executable", "lnk", "shortcut",
    "temp_dir", "config_path", "dest", "source_path",
})

#: Keys holding a command line — always reduced to exe + safe flags.
COMMAND_KEYS = frozenset({
    "cmd", "command", "command_line", "cmdline", "argv", "args", "arguments",
})

#: Keys holding free text written by us or by the OS.  Scanned, not trusted.
TEXT_KEYS = frozenset({
    "message", "note", "summary", "details", "detail", "error", "reason",
    "title", "name", "description", "friendly_name", "caption", "value_kind",
    "stderr_head", "stdout_head", "log_tail", "hint",
})

#: Top-level section names.  Without these the whole subtree a collector
#: produced would be dropped as "unknown key" — a mistake worth naming
#: explicitly, because the symptom (an almost empty report) looks like a
#: collector failure rather than a redaction rule.
SECTION_KEYS = frozenset({
    "app", "system", "runtime", "diagnostics", "environment", "network",
    "vpn", "rdp", "ssh", "sftp", "windows", "uia", "extra", "vault_meta",
})

#: Everything else the diagnostics system is allowed to emit.  Values are
#: scalars passed through after type and length checks.
ALLOWED_KEYS = set(IP_KEYS | HOST_KEYS | IDENTITY_KEYS | PATH_KEYS
                   | COMMAND_KEYS | TEXT_KEYS | ALLOW_EXACT_OVERRIDES
                   | SECTION_KEYS) | {
    # trace / generic structure
    "trace_id", "operation", "step", "status", "started_at", "ended_at",
    "duration_ms", "elapsed_ms", "timeout_ms", "result", "steps", "meta",
    "schema", "schema_version", "created_at", "report_id", "index", "count",
    "ok", "warn", "fail", "kind", "type", "state", "phase", "attempt",
    "strategy", "source", "method", "enabled", "present", "supported",
    "detected", "running", "started", "exists", "changed", "retention",
    "truncated", "reason_code", "severity", "section", "sections", "files",
    "size", "size_bytes", "mtime", "age_s", "limit", "total", "skipped",
    # app / system
    "app", "app_name", "app_version", "app_variant", "frozen", "python",
    "python_version", "qt_version", "pyqt_version", "platform", "os_name",
    "os_version", "os_build", "os_release", "os_edition", "arch",
    "machine_arch", "processor", "locale", "language", "is_admin",
    "integrity_level", "uac_enabled", "cpu_count", "ram_mb", "ram_free_mb",
    "boot_time", "timezone", "encoding", "display", "screens", "width",
    "height", "dpi", "scale", "primary", "monitor_count",
    # process
    "pid", "ppid", "exe", "arg_count", "flags", "process_count", "elevated",
    "window_count", "handle_count", "exit_status",
    # windows / UI automation (structure only — never values)
    "hwnd", "class_name", "visible", "control_type", "automation_id",
    "is_enabled", "is_offscreen", "depth", "children", "rect", "x", "y",
    "w", "h", "control_count", "tree_depth", "has_value_pattern",
    # network adapters
    "adapter", "adapters", "oper_status", "has_ipv4", "has_ipv6", "port",
    "interface", "connection_type", "tcp_state",
    # vpn / rdp / ssh domain (used by later stages)
    "provider", "edition", "cli_supported", "connected", "tunnel_active",
    "status_source", "autofill", "two_factor", "adapter_match", "policy",
    "powershell_policy", "saved_credentials_policy", "certificate_present",
    "thumbprint_present", "signed", "drives_mapped", "session_count",
    "scrollback", "transport", "cipher", "server_version",
    # launch outcome (emitted by vpn_connect itself, which never imports vpn/)
    "process_started", "observation_failed", "fallback_from", "cwd_source",
}

_FLAG_RE = re.compile(r"^-{1,2}[A-Za-z][A-Za-z0-9][\w-]*$")

#: Flags whose *value* is a secret — the flag itself is dropped too, so the
#: report cannot even hint that a password was passed on a command line.
SENSITIVE_FLAGS = frozenset({
    "-p", "-u", "--password", "--passwd", "--pwd", "--pass", "--token",
    "--otp", "--code", "--secret", "--pin", "--username", "--user",
    "--login", "--key", "--keyfile", "--cert-password", "--savecredentials",
})


def allow_keys(*names: str) -> None:
    """Register extra keys a collector is allowed to emit.

    Call this at import time from the collector that needs them, so the full
    set of emitted keys stays greppable in one place per module.
    """
    for name in names:
        ALLOWED_KEYS.add(str(name))


# --------------------------------------------------------------------------- #
# Masking                                                                      #
# --------------------------------------------------------------------------- #

def _strip_port(value: str) -> str:
    """Return `value` without a trailing :port (IPv6 in brackets supported)."""
    raw = value.strip()
    if raw.startswith("[") and "]" in raw:            # [::1]:443
        return raw[1:raw.index("]")]
    if raw.count(":") == 1:                            # host:443 / 1.2.3.4:443
        head, _, tail = raw.partition(":")
        if tail.isdigit():
            return head
    return raw


class Masker:
    """Stable pseudonyms for infrastructure identifiers.

    One instance == one report.  The salt is random per instance, so the same
    host gets the same pseudonym inside a report and a different one in the
    next report.
    """

    def __init__(self, salt: bytes | None = None):
        self._salt = salt if salt is not None else _secrets.token_bytes(16)
        self._cache: dict[tuple[str, str], str] = {}

    def _tag(self, kind: str, value: str) -> str:
        norm = value.strip().lower()
        cache_key = (kind, norm)
        hit = self._cache.get(cache_key)
        if hit is not None:
            return hit
        digest = hashlib.blake2s(
            self._salt + kind.encode("utf-8") + norm.encode("utf-8", "replace"),
            digest_size=4,
        ).hexdigest()
        out = f"{kind}-{digest}"
        self._cache[cache_key] = out
        return out

    # -- public ------------------------------------------------------------ #

    def ip(self, value: Any) -> str:
        raw = _strip_port(str(value))
        if not raw:
            return ""
        try:
            addr = ipaddress.ip_address(raw)
        except ValueError:
            return self.host(raw)
        if addr.is_loopback or addr.is_unspecified:
            return str(addr)                    # no topology in 127.0.0.1
        scope = "priv" if addr.is_private else "pub"
        return self._tag(f"ip{addr.version}-{scope}", str(addr))

    def host(self, value: Any) -> str:
        raw = _strip_port(str(value)).rstrip(".")
        if not raw:
            return ""
        if raw.lower() in ("localhost", "::1"):
            return raw.lower()
        try:
            ipaddress.ip_address(raw)
        except ValueError:
            return self._tag("host", raw)
        return self.ip(raw)

    def identity(self, value: Any) -> str:
        raw = str(value).strip()
        return self._tag("id", raw) if raw else ""


_default_masker = Masker()


def default_masker() -> Masker:
    return _default_masker


def reset_default_masker() -> Masker:
    """New salt — used by tests and when starting a fresh report."""
    global _default_masker
    _default_masker = Masker()
    return _default_masker


# --------------------------------------------------------------------------- #
# Paths and commands                                                           #
# --------------------------------------------------------------------------- #

def _path_roots() -> list[tuple[str, str]]:
    roots = [
        (os.environ.get("LOCALAPPDATA"), "%LOCALAPPDATA%"),
        (os.environ.get("APPDATA"), "%APPDATA%"),
        (os.environ.get("TEMP"), "%TEMP%"),
        (os.environ.get("ProgramFiles(x86)"), "%PROGRAMFILES(X86)%"),
        (os.environ.get("ProgramFiles"), "%PROGRAMFILES%"),
        (os.environ.get("ProgramData"), "%PROGRAMDATA%"),
        (os.environ.get("SystemRoot"), "%WINDIR%"),
        (os.environ.get("USERPROFILE"), "%USERPROFILE%"),
    ]
    # Longest first so %LOCALAPPDATA% wins over %USERPROFILE%.
    return sorted(((r, name) for r, name in roots if r),
                  key=lambda item: len(item[0]), reverse=True)


def shorten_path(value: Any) -> str:
    """Replace well-known roots with placeholders and strip the user name."""
    raw = str(value)
    if not raw:
        return ""
    low = raw.lower()
    for root, placeholder in _path_roots():
        if low.startswith(root.lower()):
            raw = placeholder + raw[len(root):]
            break
    user = os.environ.get("USERNAME") or ""
    if user and len(user) >= 3:
        raw = re.sub(re.escape(user), "<user>", raw, flags=re.IGNORECASE)
    # 2026-10-14 (audit E-04): whatever is left under X:\Users\<name> — a
    # short 8.3 name (SEBAST~1), a login under 3 characters, another
    # profile — and the organisation in "OneDrive - <organisation>".
    raw = _USERS_DIR_RE.sub(r"\g<1><user>", raw)
    raw = _ONEDRIVE_ORG_RE.sub(r"\g<1><organisation>", raw)
    return raw[:MAX_VALUE_LEN]


#: X:\Users\<anything up to the next separator> — the profile folder name.
_USERS_DIR_RE = re.compile(r"(?i)([A-Z]:[\\/]+Users[\\/]+)(?!<user>)[^\\/\s\"']+")
#: "OneDrive - Szpital Wojewódzki" → the tenant names the organisation.
_ONEDRIVE_ORG_RE = re.compile(r"(?i)(OneDrive - )[^\\/\"']+")


def mask_command(value: Any) -> dict:
    """Reduce a command line to what is safe: exe name, arg count, safe flags.

    Argument *values* are never kept.  A VPN client invoked with
    ``--password hunter2`` must be reportable as "we launched FortiVPN.exe with
    6 arguments including --connect" and nothing more.
    """
    if isinstance(value, (list, tuple)):
        parts = [str(p) for p in value]
    else:
        text = str(value)
        try:
            parts = shlex.split(text, posix=False)
        except ValueError:
            parts = text.split()
    if not parts:
        return {"exe": "", "arg_count": 0, "flags": [], "args": MASKED_ARGS}
    exe = os.path.basename(parts[0].strip('"'))
    flags: list[str] = []
    for part in parts[1:]:
        low = part.lower()
        if low in SENSITIVE_FLAGS:
            continue
        if _FLAG_RE.match(part):
            flags.append(part[:40])
    return {
        "exe": exe[:MAX_VALUE_LEN],
        "arg_count": len(parts) - 1,
        "flags": flags[:12],
        "args": MASKED_ARGS,
    }


# --------------------------------------------------------------------------- #
# Secret detection                                                             #
# --------------------------------------------------------------------------- #

_PEM_RE = re.compile(
    r"-{3,}\s*BEGIN[ A-Z0-9]*(PRIVATE KEY|RSA PRIVATE|OPENSSH PRIVATE|"
    r"ENCRYPTED PRIVATE|PGP PRIVATE)", re.IGNORECASE)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{4,}")
_INLINE_RE = re.compile(
    r"\b(pass(word|wd)?|pwd|secret|token|otp|apikey|api_key|passphrase)\b"
    r"\s*[:=]\s*[\"']?([^\s\"',;}]{4,})", re.IGNORECASE)
_VENDOR_RE = re.compile(
    r"(AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|gh[pousr]_[A-Za-z0-9]{20,}|"
    r"sk-[A-Za-z0-9]{20,}|AIza[0-9A-Za-z_-]{30,})")
_HEX_RE = re.compile(r"\b[0-9a-fA-F]{40,}\b")
_B64_RE = re.compile(r"\b[A-Za-z0-9+/_-]{32,}={0,2}\b")

_PLACEHOLDERS = (REDACTED, DROPPED, BLOCKED, MASKED_ARGS)


def _shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def find_secrets(text: str, allow_literals: frozenset[str] | set[str] = frozenset()) -> list[str]:
    """Return rule names + offsets for anything that looks like a secret.

    Never returns the matched text itself — a leak report must not become the
    leak.  `allow_literals` lets the caller exempt values it knows are safe
    (the SHA-256 digests we put in the manifest, for example).
    """
    if not text:
        return []
    findings: list[str] = []

    def _record(rule: str, match: re.Match) -> None:
        findings.append(f"{rule}@{match.start()}")

    for match in _PEM_RE.finditer(text):
        _record("pem-private-key", match)
    for match in _JWT_RE.finditer(text):
        if match.group(0) not in allow_literals:
            _record("jwt", match)
    for match in _VENDOR_RE.finditer(text):
        if match.group(0) not in allow_literals:
            _record("vendor-token", match)
    for match in _INLINE_RE.finditer(text):
        value = match.group(3)
        if value in _PLACEHOLDERS or value.startswith("<"):
            continue
        if value in allow_literals:
            continue
        _record("inline-assignment", match)
    for match in _HEX_RE.finditer(text):
        if match.group(0) not in allow_literals:
            _record("long-hex", match)
    for match in _B64_RE.finditer(text):
        candidate = match.group(0)
        if candidate in allow_literals or candidate in _PLACEHOLDERS:
            continue
        if _HEX_RE.fullmatch(candidate):
            continue                                  # already reported above
        if _looks_like_random_blob(candidate):
            _record("high-entropy-blob", match)
    return findings


def _looks_like_random_blob(candidate: str) -> bool:
    """Entropy alone flags ordinary prose like "pass/pwd/secret/token/otp".

    Base64 (or hex) of random bytes practically always mixes upper case,
    lower case and digits; slash-separated words do not. Requiring that mix
    keeps real blobs while letting documentation through.
    """
    if _shannon_entropy(candidate) < 3.6:
        return False
    has_upper = any(c.isupper() for c in candidate)
    has_lower = any(c.islower() for c in candidate)
    has_digit = any(c.isdigit() for c in candidate)
    return has_upper and has_lower and has_digit


def looks_like_secret(value: Any,
                      allow_literals: frozenset[str] | set[str] = frozenset()) -> list[str]:
    if not isinstance(value, str):
        return []
    return find_secrets(value, allow_literals)


def assert_no_secrets(text: str, where: str = "report",
                      allow_literals: frozenset[str] | set[str] = frozenset()) -> None:
    """Final gate. Raises :class:`SecretLeakError` instead of scrubbing."""
    findings = find_secrets(text, allow_literals)
    if findings:
        raise SecretLeakError(
            f"Zablokowano eksport diagnostyki: w '{where}' wykryto dane "
            f"wyglądające na sekret ({len(findings)}): {', '.join(findings[:8])}"
        )


# --------------------------------------------------------------------------- #
# Redaction                                                                    #
# --------------------------------------------------------------------------- #

@dataclass
class RedactionReport:
    """What the redactor did — shipped with every export as REDACTION.txt."""

    redacted: Counter = field(default_factory=Counter)
    dropped: Counter = field(default_factory=Counter)
    masked: Counter = field(default_factory=Counter)
    blocked: list[str] = field(default_factory=list)
    truncated: int = 0

    def merge(self, other: "RedactionReport") -> None:
        self.redacted.update(other.redacted)
        self.dropped.update(other.dropped)
        self.masked.update(other.masked)
        self.blocked.extend(other.blocked)
        self.truncated += other.truncated

    def as_dict(self) -> dict:
        return {
            "redacted_keys": dict(sorted(self.redacted.items())),
            "dropped_keys": dict(sorted(self.dropped.items())),
            "masked_keys": dict(sorted(self.masked.items())),
            "blocked": list(self.blocked),
            "truncated": self.truncated,
        }

    def is_clean(self) -> bool:
        return not self.blocked


def is_secret_key(key: str) -> bool:
    low = str(key).lower()
    if low in ALLOW_EXACT_OVERRIDES:
        return False
    return any(token in low for token in SECRET_TOKENS)


def _truncate(text: str, limit: int, report: RedactionReport) -> str:
    if len(text) <= limit:
        return text
    report.truncated += 1
    return text[:limit] + TRUNCATED


def mask_embedded(text: str, masker: Masker) -> str:
    """Mask IPs, e-mails and user paths that appear inside free text."""
    def _ip_sub(match: re.Match) -> str:
        return masker.ip(match.group(0))

    out = re.sub(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", _ip_sub, text)
    out = re.sub(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b",
                 lambda m: masker.identity(m.group(0)), out)
    out = re.sub(r"[A-Za-z]:\\\\?Users\\\\?[^\\\s\"']+",
                 "%USERPROFILE%", out, flags=re.IGNORECASE)
    user = os.environ.get("USERNAME") or ""
    if user and len(user) >= 3:
        out = re.sub(re.escape(user), "<user>", out, flags=re.IGNORECASE)
    return out


def _scalar(key: str, value: Any, mode: Mode, masker: Masker,
            report: RedactionReport, path: str) -> Any:
    low = key.lower()

    if low in COMMAND_KEYS:
        report.masked[low] += 1
        return mask_command(value)
    if low in IP_KEYS:
        report.masked[low] += 1
        return masker.ip(value)
    if low in HOST_KEYS:
        report.masked[low] += 1
        return masker.host(value)
    if low in IDENTITY_KEYS:
        report.masked[low] += 1
        return masker.identity(value)
    if low in PATH_KEYS:
        report.masked[low] += 1
        return shorten_path(value)

    if isinstance(value, bool) or isinstance(value, (int, float)) or value is None:
        return value

    text = str(value)
    if low in TEXT_KEYS:
        text = mask_embedded(text, masker)
        text = _truncate(text, MAX_TEXT_LEN, report)
    else:
        text = _truncate(text, MAX_VALUE_LEN, report)

    findings = find_secrets(text)
    if findings:
        if mode is Mode.EXPORT:
            raise SecretLeakError(
                f"Zablokowano eksport diagnostyki: pole '{path or key}' zawiera "
                f"dane wyglądające na sekret ({', '.join(findings[:4])})"
            )
        report.blocked.append(path or key)
        return BLOCKED
    return text


def redact(data: Any, mode: Mode = Mode.RUNTIME, masker: Masker | None = None,
           report: RedactionReport | None = None, _path: str = "",
           _depth: int = 0) -> Any:
    """Return a copy of `data` safe to write to disk.

    Unknown keys are dropped, sensitive keys are redacted, infrastructure
    identifiers are masked.  See the module docstring for the two modes.
    """
    masker = masker or _default_masker
    report = report if report is not None else RedactionReport()

    if _depth > MAX_DEPTH:
        return "<dropped:too-deep>"

    if isinstance(data, dict):
        out: dict[str, Any] = {}
        for raw_key, value in data.items():
            key = str(raw_key)
            low = key.lower()
            path = f"{_path}.{key}" if _path else key

            if is_secret_key(key):
                report.redacted[low] += 1
                out[key] = REDACTED
                continue
            if low not in ALLOWED_KEYS:
                report.dropped[low] += 1
                out[key] = DROPPED
                continue
            if low in COMMAND_KEYS:
                # A command is a list *or* a string — both collapse to the
                # same safe summary, so it must not be walked as a container.
                out[key] = _scalar(key, value, mode, masker, report, path)
            elif isinstance(value, (dict, list, tuple)):
                out[key] = redact(value, mode, masker, report, path, _depth + 1)
            else:
                out[key] = _scalar(key, value, mode, masker, report, path)
        return out

    if isinstance(data, (list, tuple)):
        items = list(data)[:MAX_LIST_LEN]
        if len(data) > MAX_LIST_LEN:
            report.truncated += 1
        return [
            redact(item, mode, masker, report, f"{_path}[{i}]", _depth + 1)
            if isinstance(item, (dict, list, tuple))
            else _scalar("value", item, mode, masker, report, f"{_path}[{i}]")
            for i, item in enumerate(items)
        ]

    return _scalar("value", data, mode, masker, report, _path)


def redact_with_report(data: Any, mode: Mode = Mode.RUNTIME,
                       masker: Masker | None = None) -> tuple[Any, RedactionReport]:
    report = RedactionReport()
    clean = redact(data, mode=mode, masker=masker, report=report)
    return clean, report
