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
_RDP_CERT_SUBJECT = "CN=HospitalHub V2 RDP Auto-Sign"

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

#: One drive letter and a colon — the only shape a redirected drive may take
#: in the .rdp file (2026-10-14, C2-02).  Anything else came from a vault
#: edited outside the UI and could carry a line break, i.e. extra settings
#: in a file we then sign with a trusted certificate.
_DRIVE_RE = re.compile(r'[A-Za-z]:')
#: A SHA-1 certificate thumbprint as PowerShell prints it (C2-03).
_THUMBPRINT_RE = re.compile(r'[0-9A-Fa-f]{40}')

#: TERMSRV/<ip> entries written and not yet removed, with how many launches
#: still rely on each (C2-04): a second RDP to the same address within the
#: 30 s window used to lose its credential to the first one's cleanup.
_PENDING_CREDENTIALS: dict[str, int] = {}


def _valid_drives(drives) -> list[str]:
    """The drive letters that are just that, upper-cased; others dropped."""
    out = []
    for d in drives or []:
        if isinstance(d, str) and _DRIVE_RE.fullmatch(d.strip()):
            letter = d.strip().upper()
            if letter not in out:
                out.append(letter)
        else:
            _diag("rdp: dropped an invalid drive entry from the vault")
    return out


def _valid_thumbprint(value: str) -> str | None:
    value = (value or "").strip()
    return value.upper() if _THUMBPRINT_RE.fullmatch(value) else None


def _hold_credential(ip: str) -> None:
    _PENDING_CREDENTIALS[ip] = _PENDING_CREDENTIALS.get(ip, 0) + 1


def _release_credential(ip: str) -> None:
    """Delete TERMSRV/<ip> once the last launch relying on it is done."""
    left = _PENDING_CREDENTIALS.get(ip, 0) - 1
    if left > 0:
        _PENDING_CREDENTIALS[ip] = left
        return
    _PENDING_CREDENTIALS.pop(ip, None)
    _cmdkey_delete(ip)


def cleanup_pending_credentials() -> None:
    """Remove every TERMSRV entry still waiting for its timer — for the exit
    path, which ends the process before those timers fire (C2-04)."""
    for ip in list(_PENDING_CREDENTIALS):
        _PENDING_CREDENTIALS.pop(ip, None)
        _cmdkey_delete(ip)


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

    # Diagnostics — the "mstsc keeps prompting for a password on PC X but
    # not on PC Y" class of bug is almost always environmental (Group
    # Policy), not code. Log enough to tell apart the three usual causes:
    # no usable credential / CredWriteW rejected / mstsc policy refuses
    # saved creds. Reads land in %TEMP%\hospitalhub_v2_rdp_sign.log.
    _diag(f"connect: ip={ip} admin_unlocked={admin_unlocked} "
          f"total_creds={len(machine.credentials)} visible_creds={len(vis_creds)} "
          f"cred_has_login={bool(cred and cred.login)} "
          f"cred_has_password={bool(cred and cred.password)}")
    _diag_saved_cred_policy()

    if cred and cred.login and cred.password:
        injected = _cmdkey_add(ip, cred.login, cred.password)
        if injected:
            _hold_credential(ip)
        # No login in the log: it is a plain-text file in %TEMP% (C2-04).
        _diag(f"cmdkey: TERMSRV/{ip} injected={injected}")
    else:
        _diag("cmdkey: skipped — no visible credential with both "
              "login and password (admin-only cred while locked, or "
              "empty fields). mstsc will prompt.")

    # Always launch through a signed .rdp file. This is the v1.3.0
    # behaviour that the field reported working; v1.5.3 split it so that
    # drive-less machines went via `mstsc /v:host` to dodge the "Verify
    # publisher" dialog, but on PCs with credential-delegation Group
    # Policy mstsc treats a bare `/v:host` connection as ad-hoc and
    # prompts for the password instead of using the saved TERMSRV/<ip>
    # credential. A connection launched from an .rdp file is treated as a
    # trusted saved connection, so the stored credential is honoured —
    # which is exactly why it "used to work" before the v1.5.3 split.
    #
    # Signing the file (cert already trusted via _ensure_signing_cert)
    # suppresses the publisher dialog, so we keep the no-dialog benefit
    # that motivated the /v:host path in the first place. If signing
    # fails we still launch unsigned — the user may see the publisher
    # prompt but the credential injection (the thing that regressed)
    # works regardless.
    try:
        rdp_file = _make_rdp_file(target, machine)
    except Exception as exc:
        # Released here, or TERMSRV/<ip> would stay until exit (review 67/R2).
        if injected:
            _release_credential(ip)
        QMessageBox.critical(parent, "Błąd RDP",
                             f"Nie można przygotować pliku .rdp:\n{exc}")
        return
    thumbprint = _ensure_signing_cert()
    if thumbprint:
        _sign_rdp(rdp_file, thumbprint)
    launch_args = [_MSTSC, rdp_file]

    try:
        subprocess.Popen(launch_args, creationflags=_NO_WIN)
    except Exception as exc:
        if injected:
            _release_credential(ip)
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
            _release_credential(ip)
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
    drives = _valid_drives(getattr(machine, 'rdp_drives', []))

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
                          'hospitalhub_v2_rdp_sign.log')


def _diag(msg: str) -> None:
    """Append a diagnostic line so we can debug signing failures in the
    packaged exe (no console attached → no print() visibility)."""
    try:
        from datetime import datetime
        # Bounded: keep the last ~256 KB (C2-04 — it grew without limit).
        try:
            if os.path.getsize(_DIAG_LOG) > 512 * 1024:
                with open(_DIAG_LOG, 'rb') as f:
                    f.seek(-256 * 1024, os.SEEK_END)
                    tail = f.read()
                with open(_DIAG_LOG, 'wb') as f:
                    f.write(tail)
        except OSError:
            pass
        with open(_DIAG_LOG, 'a', encoding='utf-8') as f:
            f.write(f"[{datetime.now().isoformat(timespec='seconds')}] {msg}\n")
    except OSError:
        pass


def _diag_saved_cred_policy() -> None:
    """Log the Windows policies that decide whether mstsc will use a saved
    credential at all. This is the usual reason RDP auto-login works on one
    PC and prompts for a password on another — the difference is policy,
    not the vault.

    Checks, in order of how often they bite:

      * Terminal Services Client ``DisablePasswordSaving`` (HKLM policy and
        HKCU). =1 → mstsc refuses to use saved creds and always prompts.
      * CredentialsDelegation ``AllowSavedCredentials`` + its
        ``TERMSRV/*`` allow-list. If saved-credential delegation isn't
        allowed for TERMSRV targets, mstsc prompts.

    Pure registry reads via winreg — no admin needed, never raises.
    """
    try:
        import winreg
    except ImportError:
        return

    def _read(root, path, name):
        try:
            with winreg.OpenKey(root, path) as k:
                val, _ = winreg.QueryValueEx(k, name)
                return val
        except OSError:
            return None

    HKLM = winreg.HKEY_LOCAL_MACHINE
    HKCU = winreg.HKEY_CURRENT_USER

    dps_hklm = _read(HKLM,
        r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services",
        "DisablePasswordSaving")
    dps_client = _read(HKLM,
        r"SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\Client",
        "DisablePasswordSaving")
    dps_hkcu = _read(HKCU,
        r"SOFTWARE\Microsoft\Terminal Server Client",
        "DisablePasswordSaving")

    allow_saved = _read(HKLM,
        r"SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation",
        "AllowSavedCredentials")
    # The allow-list is stored as numbered string values under this subkey.
    termsrv_listed = None
    try:
        with winreg.OpenKey(HKLM,
                r"SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation"
                r"\AllowSavedCredentials") as k:
            termsrv_listed = False
            i = 0
            while True:
                try:
                    _name, v, _t = winreg.EnumValue(k, i)
                except OSError:
                    break
                if isinstance(v, str) and "TERMSRV" in v.upper():
                    termsrv_listed = True
                i += 1
    except OSError:
        pass

    _diag(
        "policy: DisablePasswordSaving "
        f"HKLM\\TS={dps_hklm} HKLM\\TS\\Client={dps_client} HKCU={dps_hkcu}; "
        f"AllowSavedCredentials={allow_saved} TERMSRV_in_list={termsrv_listed}"
    )

    flagged = []
    if dps_hklm == 1 or dps_client == 1 or dps_hkcu == 1:
        flagged.append("DisablePasswordSaving=1 → mstsc will NOT use saved "
                       "credentials (this is almost certainly the cause)")
    if allow_saved == 1 and termsrv_listed is False:
        flagged.append("AllowSavedCredentials enabled but TERMSRV/* not in "
                       "allow-list → saved-credential delegation blocked")
    if flagged:
        _diag("policy: LIKELY CAUSE → " + " | ".join(flagged))


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
    if _VERIFIED_THUMBPRINT[0]:
        return _VERIFIED_THUMBPRINT[0]
    # It also reports whether TrustedPublisher and Root still hold the cert
    # (C2-01): a first run whose Root prompt was not confirmed in time left
    # it in My only, and this path then returned it for ever without trust.
    check = (
        f"$c = Get-ChildItem Cert:\\CurrentUser\\My -CodeSigningCert "
        f"-ErrorAction SilentlyContinue | "
        f"Where-Object {{ $_.Subject -eq '{_RDP_CERT_SUBJECT}' }} | "
        f"Select-Object -First 1; if ($c) {{ "
        f"$p = Test-Path ('Cert:\\CurrentUser\\TrustedPublisher\\' + $c.Thumbprint); "
        f"$r = Test-Path ('Cert:\\CurrentUser\\Root\\' + $c.Thumbprint); "
        f"$c.Thumbprint + '|' + $p + '|' + $r }}"
    )
    rc, out, err = _powershell(check, timeout=15)
    parts = out.strip().split('|')
    thumbprint = _valid_thumbprint(parts[0]) if rc == 0 else None
    if thumbprint:
        trusted = [p.strip().lower() == 'true' for p in parts[1:3]]
        if len(trusted) != 2 or not all(trusted):
            _repair_cert_trust(thumbprint)
        _diag(f"cert: fast path → {thumbprint}")
        _ensure_publisher_bypass(thumbprint)
        _ensure_local_devices_trust(thumbprint)
        _VERIFIED_THUMBPRINT[0] = thumbprint
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
    thumbprint = _valid_thumbprint(out.strip().splitlines()[-1] if out.strip() else "")
    if rc == 0 and thumbprint:
        _diag(f"cert: created → {thumbprint}")
        _ensure_publisher_bypass(thumbprint)
        _ensure_local_devices_trust(thumbprint)
        _VERIFIED_THUMBPRINT[0] = thumbprint
        return thumbprint
    _diag(f"cert: generation failed rc={rc} out={out.strip()[:200]} stderr={err.strip()[:200]}")
    return None


#: The signing cert found and checked earlier in this process (D-09): each
#: RDP launch used to start PowerShell on the UI thread to look it up again.
_VERIFIED_THUMBPRINT: list = [None]

#: Thumbprints whose trust repair already ran in this process (review
#: 67/R1): where the user declined the Root prompt, or a policy forbids it,
#: repeating it on every RDP would show the prompt and block the UI each time.
_TRUST_REPAIR_TRIED: set = set()


def _repair_cert_trust(thumbprint: str) -> None:
    """Put the existing signing cert back into TrustedPublisher and Root.

    Only ever called with a thumbprint that passed :func:`_valid_thumbprint`,
    so nothing but 40 hex characters reaches the script.  Adding to Root shows
    Windows's one-time security prompt again, exactly as on the first run.
    """
    thumbprint = _valid_thumbprint(thumbprint)
    if not thumbprint or thumbprint in _TRUST_REPAIR_TRIED:
        return
    _TRUST_REPAIR_TRIED.add(thumbprint)
    script = (
        f"$c = Get-Item ('Cert:\\CurrentUser\\My\\{thumbprint}') "
        f"-ErrorAction SilentlyContinue; if ($c) {{ "
        f"foreach ($n in 'TrustedPublisher','Root') {{ "
        f"$s = New-Object System.Security.Cryptography.X509Certificates.X509Store($n,'CurrentUser'); "
        f"$s.Open('ReadWrite'); $s.Add($c); $s.Close() }} }}"
    )
    rc, _out, err = _powershell(script, timeout=60)
    _diag(f"cert: trust repair rc={rc} stderr={err.strip()[:200]}")


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

        ok = bool(_CredWriteW(ctypes.byref(cred), 0))
        if not ok:
            # GetLastError 1330 = ERROR_PASSWORD_EXPIRED-ish; 1314 =
            # ERROR_PRIVILEGE_NOT_HELD; most relevant here is the policy
            # "Network access: Do not allow storage of passwords" which
            # makes CredWrite fail with ERROR_ACCESS_DENIED (5). Logging
            # the code tells us exactly why injection didn't happen.
            err = ctypes.windll.kernel32.GetLastError()
            _diag(f"cmdkey: CredWriteW failed GetLastError={err}")
        return ok
    except Exception as exc:
        _diag(f"cmdkey: CredWriteW exception {type(exc).__name__}: {exc}")
        return False


def _cmdkey_delete(ip: str) -> None:
    """Remove the temporary Credential Manager entry via ctypes."""
    try:
        target = f"TERMSRV/{ip}"
        _CredDeleteW(target, CRED_TYPE_GENERIC, 0)
    except Exception:
        pass
