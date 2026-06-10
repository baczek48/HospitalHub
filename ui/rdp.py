"""RDP connection launcher for Windows.

Strategy:
  1. Store credentials in Windows Credential Manager via ctypes (CredWriteW)
     (target = TERMSRV/<ip>  — the exact namespace mstsc looks up).
  2. Launch mstsc.exe /v:<ip>[:<port>]  — it picks up the stored creds.
  3. After 10 s delete the stored credentials so they don't persist.

No extra libraries required; works on every Windows installation.
"""

import ctypes
import ctypes.wintypes
import os
import re
import subprocess
import tempfile

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QMessageBox

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import models

_MSTSC   = r"C:\Windows\System32\mstsc.exe"
_NO_WIN  = getattr(subprocess, "CREATE_NO_WINDOW", 0)   # suppress console flash

# Subject for the per-user code-signing cert we use to sign .rdp files.
# Stable subject so we don't regenerate on every launch.
_RDP_CERT_SUBJECT = "CN=HospitalHub RDP Auto-Sign"

# On Windows Pro/Enterprise rdpsign.exe ships in System32. Home edition
# omits it from System32 but the binary still lives in WinSxS — we copy
# it out lazily and cache the path here so subsequent launches skip the
# scan. Module-global because the cost amortises across all RDP launches
# in a single app session.
_rdpsign_path_cache: str | None = None

# ──────────────────────────────────────────────────────────────────────────────
# Windows Credential Manager via ctypes (avoids cmdkey.exe password in argv)
# ──────────────────────────────────────────────────────────────────────────────

CRED_TYPE_GENERIC          = 1
# CRED_PERSIST_SESSION (= 1) auto-clears the stored credential at
# Windows logout/restart. We previously used CRED_PERSIST_LOCAL_MACHINE
# (= 2), which kept the entry forever — fine when the 30 s cleanup
# timer fires, but if HospitalHub crashed or was force-closed inside
# that window the credential would remain in Credential Manager
# indefinitely, available to anything else that opens TERMSRV/<ip>.
# Mstsc only needs the cred at connect time, so SESSION lifetime is
# the strictest scope that doesn't break re-injection on next launch.
CRED_PERSIST_SESSION       = 1

class _CREDENTIAL(ctypes.Structure):
    _fields_ = [
        ("Flags", ctypes.wintypes.DWORD),
        ("Type", ctypes.wintypes.DWORD),
        ("TargetName", ctypes.wintypes.LPWSTR),
        ("Comment", ctypes.wintypes.LPWSTR),
        ("LastWritten", ctypes.wintypes.FILETIME),
        ("CredentialBlobSize", ctypes.wintypes.DWORD),
        ("CredentialBlob", ctypes.POINTER(ctypes.c_byte)),
        ("Persist", ctypes.wintypes.DWORD),
        ("AttributeCount", ctypes.wintypes.DWORD),
        ("Attributes", ctypes.c_void_p),
        ("TargetAlias", ctypes.wintypes.LPWSTR),
        ("UserName", ctypes.wintypes.LPWSTR),
    ]

_advapi32 = ctypes.windll.advapi32
_CredWriteW = _advapi32.CredWriteW
_CredDeleteW = _advapi32.CredDeleteW

# Allowed characters for hostname/IP: alphanumeric, dots, hyphens only
_IP_RE = re.compile(r'^[A-Za-z0-9.\-]{1,253}$')


def _validate_ip(ip: str) -> str:
    """Return sanitized IP/hostname or raise ValueError."""
    ip = ip.strip()
    if not ip or not _IP_RE.match(ip):
        raise ValueError(f"Nieprawidłowy adres hosta: {ip!r}")
    return ip


def _validate_port(port: str) -> int:
    """Return port as int (1–65535) or raise ValueError."""
    try:
        p = int(port.strip()) if port.strip() else 3389
    except ValueError:
        raise ValueError(f"Nieprawidłowy port: {port!r}")
    if not 1 <= p <= 65535:
        raise ValueError(f"Port poza zakresem: {p}")
    return p


# ──────────────────────────────────────────────────────────────────────────────

def connect_rdp(machine: "models.Machine", parent=None,
                admin_unlocked: bool = False) -> None:
    """Open an RDP session for *machine*.

    If the machine has credentials stored in the vault, they are injected
    automatically so the user does not have to type them.  The temporary
    Credential Manager entry is removed ~10 s after launch.

    Shows a QMessageBox on error (missing mstsc, launch failure, etc.).
    """
    if not os.path.exists(_MSTSC):
        QMessageBox.critical(
            parent,
            "Błąd RDP",
            "Nie znaleziono mstsc.exe.\n"
            "Funkcja RDP jest dostępna tylko na systemie Windows.",
        )
        return

    try:
        ip   = _validate_ip(machine.ip)
        port = _validate_port(machine.rdp_port or "3389")
    except ValueError as exc:
        QMessageBox.critical(parent, "Błąd RDP", str(exc))
        return

    # mstsc syntax: /v:host  or  /v:host:port  (only when non-standard)
    target = f"{ip}:{port}" if port != 3389 else ip

    vis_creds = machine.credentials if admin_unlocked else [
        c for c in machine.credentials if not c.admin_only]
    cred = vis_creds[0] if vis_creds else None
    injected = False

    if cred and cred.login and cred.password:
        injected = _cmdkey_add(ip, cred.login, cred.password)

    # Hybrid launch strategy:
    #
    # * No drive mapping → just `mstsc /v:host`. Win11 only shows the
    #   "Verify publisher" dialog for custom .rdp files; calling mstsc
    #   directly inherits the user's Default.rdp (clipboard ON by
    #   default) and bypasses the dialog entirely. This was the v1.0
    #   behaviour; v1.3.0 lost it when we added drivestoredirect.
    #
    # * Drives requested → custom .rdp + sign + Trust/Bypass/Permissions
    #   shenanigans. We can't avoid the dialog here (the .rdp content is
    #   what mstsc wants the user to confirm), but signing reduces the
    #   warning from red "Untrusted" to yellow "Verify".
    #
    # Most machines don't map drives, so most launches are dialog-free.
    drives = getattr(machine, 'rdp_drives', None) or []
    use_rdp_file = bool(drives)

    rdp_file: str | None = None
    if use_rdp_file:
        rdp_file = _make_rdp_file(target, machine)
        thumbprint = _ensure_signing_cert()
        if thumbprint:
            _sign_rdp(rdp_file, thumbprint)
        launch_args = [_MSTSC, rdp_file]
    else:
        # Legacy /v:host path. Inherits user defaults — clipboard ON is
        # the standard default on Windows. Normalise Default.rdp first
        # to make sure drives/printers default to OFF; otherwise mstsc's
        # first-connect permission dialog would arrive with drives
        # pre-checked simply because the user's Default.rdp happened to
        # remember a previous drive mapping. No dialog if all defaults
        # are already sane and the server is in mstsc's recent list.
        _normalise_default_rdp()
        launch_args = [_MSTSC, f"/v:{target}"]

    try:
        subprocess.Popen(launch_args, creationflags=_NO_WIN)
    except Exception as exc:
        if injected:
            _cmdkey_delete(ip)
        if rdp_file:
            _cleanup_rdp_file(rdp_file)
        QMessageBox.critical(
            parent,
            "Błąd RDP",
            f"Nie można uruchomić mstsc.exe:\n{exc}",
        )
        return

    # Schedule cleanup — 30 s gives mstsc enough time even on slow networks.
    def _cleanup():
        if injected:
            _cmdkey_delete(ip)
        if rdp_file:
            _cleanup_rdp_file(rdp_file)
    QTimer.singleShot(30_000, _cleanup)


# ──────────────────────────────────────────────────────────────────────────────
# .rdp file generation
# ──────────────────────────────────────────────────────────────────────────────

def _make_rdp_file(target: str, machine: "models.Machine") -> str:
    """Create a temporary .rdp file with resource/device settings.

    Settings:
      - redirectclipboard:i:1  — clipboard always enabled
      - redirectprinters:i:0   — printers always disabled
      - drivestoredirect:s:... — selected drives or empty
    """
    drives = getattr(machine, 'rdp_drives', [])

    lines = [
        f"full address:s:{target}",
        "redirectclipboard:i:1",
        "redirectprinters:i:0",
    ]
    if drives:
        # mstsc format: "C:\;D:\;" for specific drives
        drive_str = ";".join(f"{d}\\" for d in drives) + ";"
        lines.append(f"drivestoredirect:s:{drive_str}")
    else:
        lines.append("drivestoredirect:s:")

    rdp_dir = os.path.join(os.path.realpath(tempfile.gettempdir()), 'hhub_rdp')
    os.makedirs(rdp_dir, exist_ok=True)
    # Use mkstemp for unpredictable filename and restrictive permissions (0o600)
    fd, rdp_path = tempfile.mkstemp(suffix='.rdp', dir=rdp_dir)
    with os.fdopen(fd, 'wb') as f:
        f.write(('\r\n'.join(lines) + '\r\n').encode('utf-8'))
    return rdp_path


_DIAG_LOG = os.path.join(os.path.realpath(tempfile.gettempdir()),
                          'hospitalhub_rdp_sign.log')


def _diag(msg: str) -> None:
    """Append a diagnostic line so we can debug signing failures in the
    packaged exe (no console attached → no print() visibility)."""
    try:
        from datetime import datetime
        with open(_DIAG_LOG, 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().isoformat(timespec='seconds')}] {msg}\n")
    except OSError:
        pass


def _powershell(script: str, timeout: int) -> tuple[int, str, str]:
    """Run a PowerShell snippet with no-window, no-stdin, captured output.

    In --windowed PyInstaller builds the parent has no console; passing
    stdin=DEVNULL keeps PowerShell from blocking on an inherited NULL
    handle. Returns (returncode, stdout, stderr); on Exception the code
    is -1 and the message lands in stderr.
    """
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
            stdin=subprocess.DEVNULL,
            creationflags=_NO_WIN,
        )
        return r.returncode, (r.stdout or ""), (r.stderr or "")
    except Exception as exc:
        return -1, "", f"{type(exc).__name__}: {exc}"


def _ensure_signing_cert() -> str | None:
    """Return the SHA-1 thumbprint of a code-signing cert in CurrentUser\\My
    whose subject matches _RDP_CERT_SUBJECT, creating it (and trusting
    it via CurrentUser\\TrustedPublisher + PublisherBypassList) on first
    call.

    Returns None if PowerShell isn't available or any step fails — the
    caller falls back to launching mstsc with an unsigned .rdp, which
    just means the old "untrusted publisher" prompt comes back. Never
    raises.
    """
    # Fast path: a cert already exists from a previous run.
    check = (
        f"$c = Get-ChildItem Cert:\\CurrentUser\\My -CodeSigningCert "
        f"-ErrorAction SilentlyContinue | "
        f"Where-Object {{ $_.Subject -eq '{_RDP_CERT_SUBJECT}' }} | "
        f"Select-Object -First 1; if ($c) {{ $c.Thumbprint }}"
    )
    rc, out, err = _powershell(check, timeout=15)
    thumbprint = out.strip()
    if rc == 0 and len(thumbprint) >= 40:
        _diag(f"cert: fast path → {thumbprint}")
        _ensure_publisher_bypass(thumbprint)
        _ensure_local_devices_trust(thumbprint)
        return thumbprint
    if rc != 0:
        _diag(f"cert: fast check failed rc={rc} stderr={err.strip()[:200]}")

    # Slow path (first ever launch): create the cert, add to
    # TrustedPublisher so mstsc trusts signatures, and also add to
    # CurrentUser\\Root so the self-signed chain validates. Adding to
    # Root triggers a single Windows security prompt — that's the
    # price for never seeing the 'Untrusted publisher' dialog again.
    # Cert EKU is Code Signing only, so even if abused it can't be
    # used for HTTPS server-auth MitM.
    # NotAfter 10 lat — krótszy czas zmusiłby usera do regeneracji.
    gen = (
        f"$c = New-SelfSignedCertificate -Type CodeSigningCert "
        f"-Subject '{_RDP_CERT_SUBJECT}' "
        f"-CertStoreLocation Cert:\\CurrentUser\\My "
        f"-KeyUsage DigitalSignature "
        f"-NotAfter (Get-Date).AddYears(10); "
        f"$tmp = Join-Path $env:TEMP ('hhub_signing_' + [System.Guid]::NewGuid().ToString() + '.cer'); "
        f"Export-Certificate -Cert $c -FilePath $tmp -Force | Out-Null; "
        f"Import-Certificate -FilePath $tmp -CertStoreLocation Cert:\\CurrentUser\\TrustedPublisher | Out-Null; "
        # X509Store API avoids the duplicate-import confirmation when
        # the cert is already partially trusted; the Root install still
        # shows Windows's one-time security warning regardless.
        f"$rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root','CurrentUser'); "
        f"$rootStore.Open('ReadWrite'); "
        f"$rootStore.Add($c); "
        f"$rootStore.Close(); "
        f"Remove-Item $tmp -Force -ErrorAction SilentlyContinue; "
        f"$c.Thumbprint"
    )
    rc, out, err = _powershell(gen, timeout=60)
    thumbprint = out.strip()
    if rc == 0 and len(thumbprint) >= 40:
        _diag(f"cert: created → {thumbprint}")
        _ensure_publisher_bypass(thumbprint)
        _ensure_local_devices_trust(thumbprint)
        return thumbprint
    _diag(f"cert: generation failed rc={rc} out={out.strip()[:200]} stderr={err.strip()[:200]}")
    return None


def _ensure_publisher_bypass(thumbprint: str) -> None:
    """Add the cert thumbprint to HKCU PublisherBypassList so mstsc
    skips the 'Untrusted publisher' dialog even when TrustedPublisher
    on its own isn't enough (some Windows builds/policies need both).

    Best-effort — failure just means the user keeps seeing the prompt.
    """
    if not thumbprint:
        return
    script = (
        f"$key='HKCU:\\Software\\Microsoft\\Terminal Server Client\\PublisherBypassList'; "
        f"if (!(Test-Path $key)) {{ New-Item -Path $key -Force | Out-Null }}; "
        f"New-ItemProperty -Path $key -Name '{thumbprint}' -Value 1 "
        f"-PropertyType DWord -Force | Out-Null; 'OK'"
    )
    rc, out, err = _powershell(script, timeout=10)
    if rc == 0 and 'OK' in out:
        _diag(f"bypass: registered {thumbprint}")
    else:
        _diag(f"bypass: failed rc={rc} stderr={err.strip()[:200]}")


def _ensure_local_devices_trust(thumbprint: str) -> None:
    """Pre-grant device-redirection trust for our publisher so mstsc
    doesn't show the "Zezwalaj komputerowi zdalnemu na dostęp do..."
    dialog (smart cards / WebAuthn / clipboard).

    Two registry locations cover legacy and modern mstsc:

    * Legacy ``LocalDevices\\<sha1-thumbprint>`` — DWORD bitmask of
      allowed resources. Used by older Windows builds; still honoured
      where present.
    * Modern ``PublisherPermissions\\<key>`` — per-resource DWORDs
      (SmartCards, WebAuthn, Clipboard). Win11 24H2+ ignores
      LocalDevices and only checks here. The key name is the SHA-256
      of the cert RawData with a trailing "00" byte (33 bytes,
      66 hex chars) — empirically derived from a registry diff of
      what the dialog's "Zapamiętaj moje wybory" checkbox actually
      writes.

    Setting both means the dialog is suppressed regardless of which
    code path mstsc takes on this OS build. Failures are non-fatal —
    the user just keeps seeing the dialog.
    """
    if not thumbprint:
        return

    # Legacy path — cheap, keep it for back-compat with older mstsc.
    script_legacy = (
        f"$key='HKCU:\\Software\\Microsoft\\Terminal Server Client\\LocalDevices'; "
        f"if (!(Test-Path $key)) {{ New-Item -Path $key -Force | Out-Null }}; "
        f"New-ItemProperty -Path $key -Name '{thumbprint}' -Value 0xFF "
        f"-PropertyType DWord -Force | Out-Null; 'OK'"
    )
    rc, out, err = _powershell(script_legacy, timeout=10)
    if rc == 0 and 'OK' in out:
        _diag(f"local devices (legacy): granted for {thumbprint}")
    else:
        _diag(f"local devices (legacy): failed rc={rc} stderr={err.strip()[:200]}")

    # Modern path — Win11 24H2+ reads only this.
    script_modern = (
        f"$cert = Get-ChildItem Cert:\\CurrentUser\\My | "
        f"Where-Object {{ $_.Thumbprint -eq '{thumbprint}' }} | Select-Object -First 1; "
        f"if (-not $cert) {{ Write-Output 'NO_CERT'; exit 0 }}; "
        f"$sha = [System.Security.Cryptography.SHA256]::Create(); "
        f"$digest = $sha.ComputeHash($cert.RawData); "
        # 33-byte key: sha256 digest + trailing 0x00 (empirical — that's the
        # exact format the "Remember my choices" checkbox writes on Win11).
        f"$keyName = ([System.BitConverter]::ToString($digest).Replace('-','')) + '00'; "
        f"$root = 'HKCU:\\Software\\Microsoft\\Terminal Server Client\\PublisherPermissions'; "
        f"if (!(Test-Path $root)) {{ New-Item -Path $root -Force | Out-Null }}; "
        f"$keyPath = Join-Path $root $keyName; "
        f"if (!(Test-Path $keyPath)) {{ New-Item -Path $keyPath -Force | Out-Null }}; "
        f"New-ItemProperty -Path $keyPath -Name 'SmartCards' -Value 1 -PropertyType DWord -Force | Out-Null; "
        f"New-ItemProperty -Path $keyPath -Name 'WebAuthn'   -Value 1 -PropertyType DWord -Force | Out-Null; "
        f"New-ItemProperty -Path $keyPath -Name 'Clipboard'  -Value 1 -PropertyType DWord -Force | Out-Null; "
        f"Write-Output $keyName"
    )
    rc, out, err = _powershell(script_modern, timeout=15)
    out = out.strip()
    if rc == 0 and out and out != 'NO_CERT' and len(out) == 66:
        _diag(f"publisher permissions (modern): granted under {out}")
    else:
        _diag(f"publisher permissions (modern): failed rc={rc} out={out[:100]} stderr={err.strip()[:200]}")


def _locate_rdpsign() -> str | None:
    """Return a path to a runnable rdpsign.exe, or None if we can't find one.

    On Windows Pro/Enterprise the binary lives at System32\\rdpsign.exe.
    Home edition leaves it only in WinSxS — we copy the newest version
    out to TEMP on first use and reuse it. Cache the result in
    _rdpsign_path_cache so we pay the WinSxS scan once per process.
    """
    global _rdpsign_path_cache
    if _rdpsign_path_cache and os.path.exists(_rdpsign_path_cache):
        return _rdpsign_path_cache

    # Pro/Enterprise — straight from System32.
    sys32 = r"C:\Windows\System32\rdpsign.exe"
    if os.path.exists(sys32):
        _rdpsign_path_cache = sys32
        return sys32

    # Home edition — sniff the WinSxS staging area. Files are inside
    # versioned dirs whose names mention "...publishing-wmiprovider...".
    import glob
    candidates = glob.glob(
        r"C:\Windows\WinSxS\amd64_microsoft-windows-t..lishing-wmiprovider_*\rdpsign.exe"
    )
    if not candidates:
        return None
    # Newest version wins (lexicographic sort of the WinSxS dir name puts
    # the highest build last because the version is zero-padded enough).
    candidates.sort()
    src = candidates[-1]

    # Cache the copy in our per-user temp area so antivirus heuristics
    # don't re-scan it every launch.
    cache_dir = os.path.join(os.path.realpath(tempfile.gettempdir()),
                              'hhub_signing')
    try:
        os.makedirs(cache_dir, exist_ok=True)
    except OSError:
        return None
    dst = os.path.join(cache_dir, 'rdpsign.exe')
    try:
        import shutil
        shutil.copy2(src, dst)
    except OSError:
        return None
    _rdpsign_path_cache = dst
    return dst


def _sign_rdp(path: str, thumbprint: str) -> bool:
    """Sign an .rdp file with rdpsign.exe.

    Returns True on success. Failures are non-fatal — the caller just
    launches the file unsigned and the user sees the legacy warning.
    """
    signer = _locate_rdpsign()
    if not signer:
        _diag("sign: no rdpsign.exe available")
        return False
    try:
        result = subprocess.run(
            [signer, "/sha256", thumbprint, path],
            capture_output=True, text=True, timeout=15,
            stdin=subprocess.DEVNULL,
            creationflags=_NO_WIN,
        )
        if result.returncode == 0:
            _diag(f"sign: ok {os.path.basename(path)}")
            return True
        _diag(f"sign: failed rc={result.returncode} "
              f"stdout={(result.stdout or '').strip()[:200]} "
              f"stderr={(result.stderr or '').strip()[:200]}")
        return False
    except Exception as exc:
        _diag(f"sign: exception {type(exc).__name__}: {exc}")
        return False


def _cleanup_rdp_file(path: str) -> None:
    """Remove temporary .rdp file."""
    try:
        if os.path.exists(path):
            os.remove(path)
    except OSError:
        pass


# Process-local flag so we don't re-read/rewrite Default.rdp on every
# launch — running once per app session is enough; the file persists.
_default_rdp_normalised = False


def _normalise_default_rdp() -> None:
    """Ensure the user's Default.rdp turns dangerous defaults OFF.

    Used only by the /v:host path (machines without drive mapping) —
    mstsc inherits its resource defaults from this file, so without
    normalising it the first-connect permission dialog would arrive
    with 'Drives' already ticked just because the user (or some prior
    mstsc session) happened to leave it that way. We don't touch keys
    we don't care about; specifically we leave clipboard/audio/smart-
    cards/webauthn at whatever the user prefers.

    Idempotent and best-effort: failures are silent.
    """
    global _default_rdp_normalised
    if _default_rdp_normalised:
        return
    _default_rdp_normalised = True

    docs = os.path.join(os.path.expanduser('~'), 'Documents')
    if not os.path.isdir(docs):
        return
    path = os.path.join(docs, 'Default.rdp')

    # Read existing settings into a key→line dict. mstsc tolerates both
    # UTF-8 and UTF-16 — try the most common one first.
    lines: list[str] = []
    if os.path.exists(path):
        for enc in ('utf-16', 'utf-16-le', 'utf-8'):
            try:
                with open(path, 'r', encoding=enc) as f:
                    lines = f.read().splitlines()
                break
            except (UnicodeDecodeError, OSError):
                continue

    # Force these regardless of what was there before.
    overrides = {
        'drivestoredirect:s:': '',     # no drives mapped by default
        'redirectprinters:i:':  '0',   # never forward printers
    }

    changed = False
    seen: set[str] = set()
    for i, line in enumerate(lines):
        for prefix, val in overrides.items():
            if line.startswith(prefix):
                seen.add(prefix)
                expected = prefix + val
                if line != expected:
                    lines[i] = expected
                    changed = True
                break

    for prefix, val in overrides.items():
        if prefix not in seen:
            lines.append(prefix + val)
            changed = True

    if not changed:
        return

    # Windows quirk: Default.rdp ships with the Hidden attribute, which
    # makes open(path, 'w') fail with PermissionError because 'w' mode
    # asks CreateFile to truncate-create, and CreateFile refuses to
    # create a hidden file unless the existing one already says so.
    # Strip Hidden for the write, then restore it so we don't visibly
    # change the user's file listing.
    had_hidden = False
    try:
        attrs = os.stat(path).st_file_attributes  # type: ignore[attr-defined]
        if attrs & 0x2:                            # FILE_ATTRIBUTE_HIDDEN
            had_hidden = True
            import ctypes
            ctypes.windll.kernel32.SetFileAttributesW(path, attrs & ~0x2)
    except (AttributeError, OSError):
        pass

    try:
        with open(path, 'w', encoding='utf-8') as f:
            f.write('\r\n'.join(lines) + '\r\n')
    except OSError:
        pass
    finally:
        if had_hidden:
            try:
                import ctypes
                cur = os.stat(path).st_file_attributes  # type: ignore[attr-defined]
                ctypes.windll.kernel32.SetFileAttributesW(path, cur | 0x2)
            except (AttributeError, OSError):
                pass


# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

def _cmdkey_add(ip: str, login: str, password: str) -> bool:
    """Store credentials in Credential Manager via ctypes.

    Uses CredWriteW directly — password never appears in process arguments.
    """
    try:
        target = f"TERMSRV/{ip}"
        pw_bytes = password.encode("utf-16-le")

        blob = (ctypes.c_byte * len(pw_bytes)).from_buffer_copy(pw_bytes)

        cred = _CREDENTIAL()
        cred.Flags = 0
        cred.Type = CRED_TYPE_GENERIC
        cred.TargetName = target
        cred.CredentialBlobSize = len(pw_bytes)
        cred.CredentialBlob = blob
        cred.Persist = CRED_PERSIST_SESSION
        cred.UserName = login

        return bool(_CredWriteW(ctypes.byref(cred), 0))
    except Exception:
        return False


def _cmdkey_delete(ip: str) -> None:
    """Remove the temporary Credential Manager entry via ctypes."""
    try:
        target = f"TERMSRV/{ip}"
        _CredDeleteW(target, CRED_TYPE_GENERIC, 0)
    except Exception:
        pass
