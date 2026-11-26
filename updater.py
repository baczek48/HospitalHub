"""Checking for and fetching a new HospitalHub release from GitHub.

No Qt here — the dialog (ui/update_dialog.py) runs these in a thread.

* :func:`fetch_latest` asks the public GitHub API for the latest release; the
  request carries nothing about this machine or its vaults.
* :func:`compare` tells whether that release is newer than this build
  (``dev`` and unreadable numbers are "unknown", never "newer").
* :func:`download` writes the asset to a private folder under %TEMP% and only
  keeps it when its size and the SHA-256 GitHub publishes both match.
* :func:`installer_after_exit_command` is the hand-over: a hidden PowerShell
  waits for this process to end, then starts the installer the way a
  double-click does (the UAC prompt comes from the installer's own manifest),
  silently, with ``/HHUPDATE=1`` so the installer starts HospitalHub again.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import urllib.request
from dataclasses import dataclass, field

API_LATEST = "https://api.github.com/repos/baczek48/HospitalHub/releases/latest"
USER_AGENT = "HospitalHub-updater"
TIMEOUT_S = 15
CHUNK = 256 * 1024

#: Asset of each edition: the installer for HospitalHub, the zip for Portable.
ASSET_PATTERNS = {
    "V2": re.compile(r"^HospitalHub-Setup-[\d.]+\.exe$", re.I),
    "Portable": re.compile(r"^HospitalHubPortable-[\d.]+\.zip$", re.I),
}

INSTALLER_ARGS = "/SILENT /SUPPRESSMSGBOXES /NORESTART /HHUPDATE=1"


class UpdateError(Exception):
    """A user-facing reason, in Polish."""


@dataclass
class Asset:
    name: str
    url: str
    size: int
    sha256: str | None


@dataclass
class Release:
    version: str
    tag: str
    page: str
    published: str
    notes: str
    assets: list[Asset] = field(default_factory=list)

    def asset_for(self, variant: str) -> Asset | None:
        pattern = ASSET_PATTERNS.get(variant)
        if pattern is None:
            return None
        return next((a for a in self.assets if pattern.match(a.name)), None)


def parse_version(text: str) -> tuple[int, ...] | None:
    """"2.0.5" → (2, 0, 5); a local test build "2.0.5_1" → (2, 0, 5, 1):
    newer than 2.0.5, older than 2.0.6."""
    m = re.fullmatch(r"v?(\d+(?:[._]\d+)*)", (text or "").strip())
    return tuple(int(p) for p in re.split(r"[._]", m.group(1))) if m else None


def compare(latest: str, current: str) -> int | None:
    """1 newer, 0 same, -1 older than this build; None when unknown."""
    a, b = parse_version(latest), parse_version(current)
    if a is None or b is None:
        return None
    width = max(len(a), len(b))
    a += (0,) * (width - len(a))
    b += (0,) * (width - len(b))
    return (a > b) - (a < b)


def _get(url: str, accept: str):
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT,
                                               "Accept": accept})
    return urllib.request.urlopen(req, timeout=TIMEOUT_S)


def release_from_json(data: dict) -> Release:
    tag = str(data.get("tag_name") or "")
    assets = []
    for a in data.get("assets") or []:
        digest = str(a.get("digest") or "")
        assets.append(Asset(
            name=str(a.get("name") or ""),
            url=str(a.get("browser_download_url") or ""),
            size=int(a.get("size") or 0),
            sha256=digest[7:].lower() if digest.lower().startswith("sha256:") else None))
    return Release(version=tag.lstrip("vV"), tag=tag,
                   page=str(data.get("html_url") or ""),
                   published=str(data.get("published_at") or "")[:10],
                   notes=str(data.get("body") or ""), assets=assets)


def changes_only(notes: str) -> str:
    """The "### Zmiany…" section of the release notes — what the update
    window shows; how to install and the file list are for the web page."""
    lines = (notes or "").splitlines()
    start = next((i for i, line in enumerate(lines)
                  if re.match(r"^#{1,6}\s*Zmiany", line.strip(), re.I)), None)
    if start is None:
        return notes or ""
    level = len(lines[start].strip()) - len(lines[start].strip().lstrip("#"))
    out = [lines[start]]
    for line in lines[start + 1:]:
        stripped = line.strip()
        depth = len(stripped) - len(stripped.lstrip("#"))
        if 0 < depth <= level and stripped[depth:depth + 1] == " ":
            break
        out.append(line)
    return "\n".join(out).strip()


def fetch_latest(opener=_get) -> Release:
    try:
        with opener(API_LATEST, "application/vnd.github+json") as resp:
            data = json.loads(resp.read().decode("utf-8"))
    except Exception as exc:
        raise UpdateError("Nie udało się połączyć z GitHubem "
                          f"({type(exc).__name__}). Sprawdź internet / proxy.") from exc
    release = release_from_json(data)
    if parse_version(release.version) is None:
        raise UpdateError(f"GitHub zwrócił nieczytelny numer wersji: {release.tag!r}")
    return release


def download_dir() -> str:
    path = os.path.join(tempfile.gettempdir(), "HospitalHubUpdate")
    os.makedirs(path, exist_ok=True)
    return path


def download(asset: Asset, dest_dir: str | None = None, progress=None,
             cancelled=None, opener=_get) -> str:
    """The verified file's path.  ``progress(done, total)``; ``cancelled()``
    True stops the download.  A file that does not verify is deleted."""
    if not asset.sha256:
        raise UpdateError("GitHub nie podał sumy SHA-256 tego pliku — "
                          "nie da się go sprawdzić, pobierz ręcznie ze strony wydania.")
    if os.path.basename(asset.name) != asset.name or not asset.name:
        raise UpdateError("Nieprawidłowa nazwa pliku wydania.")
    if dest_dir is None:
        dest_dir = download_dir()
        # Our own folder: installers of earlier updates (~40 MB each) go.
        for name in os.listdir(dest_dir):
            _remove(os.path.join(dest_dir, name))
    final = os.path.join(dest_dir, asset.name)
    part = final + ".part"
    digest = hashlib.sha256()
    done = 0
    try:
        with opener(asset.url, "application/octet-stream") as resp, open(part, "wb") as out:
            while True:
                if cancelled is not None and cancelled():
                    raise UpdateError("Pobieranie przerwane.")
                chunk = resp.read(CHUNK)
                if not chunk:
                    break
                out.write(chunk)
                digest.update(chunk)
                done += len(chunk)
                if progress is not None:
                    progress(done, asset.size)
    except UpdateError:
        _remove(part)
        raise
    except Exception as exc:
        _remove(part)
        raise UpdateError(f"Pobieranie nie powiodło się ({type(exc).__name__}).") from exc
    if done != asset.size or digest.hexdigest().lower() != asset.sha256:
        _remove(part)
        raise UpdateError("Pobrany plik nie zgadza się z sumą SHA-256 z GitHuba — "
                          "usunięty, nic nie zainstalowano.")
    _remove(final)
    os.replace(part, final)
    return final


def _remove(path: str) -> None:
    try:
        os.remove(path)
    except OSError:
        pass


def _ps_quote(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def installer_after_exit_command(installer: str, pid: int) -> list[str]:
    """PowerShell that waits for `pid` to end, then starts the installer."""
    script = (f"Wait-Process -Id {int(pid)} -Timeout 120 -ErrorAction SilentlyContinue; "
              f"Start-Process -FilePath {_ps_quote(installer)} "
              f"-ArgumentList {_ps_quote(INSTALLER_ARGS)}")
    return ["powershell.exe", "-NoProfile", "-NonInteractive", "-WindowStyle", "Hidden",
            "-Command", script]


def start_installer_after_exit(installer: str, pid: int | None = None) -> None:
    """Spawn the hand-over, detached and windowless.  Raises when it cannot."""
    import subprocess
    from launch_rules import _clean_pyinstaller_env
    flags = (getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
             | getattr(subprocess, "CREATE_NO_WINDOW", 0))
    subprocess.Popen(installer_after_exit_command(installer, pid or os.getpid()),
                     env=_clean_pyinstaller_env(), creationflags=flags, close_fds=True)
