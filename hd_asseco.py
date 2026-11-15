"""Downloads from hd.asseco.pl, "Publikacje wersji" (2026-11-15, owner).

The newest AMMS publication is found on the list of released versions; each
of its packages (all but PACZKI-KONFIGURACYJNE) is downloaded into the chosen
folder and unpacked there at once — the zips hold ``<version>/AMMS/…jar``,
``<version>/PI/…jar`` and ``<version>/DODATKOWE/…``.

The site is a plain form login (Symfony): POST /login with ``username``
(upper case, as the form shows it), ``password`` and a fixed
``_csrf_token``.  The list is ``/resources/list?search[code]=AMMS``: a row per
version followed by collapsed rows "AMMS <ver>-<PACKAGE>" with
``/resources/<id>/download``.  The server has no byte ranges, so a broken
download starts again.

Only the standard library: the Portable build carries no ``requests``.
"""

from __future__ import annotations

import http.cookiejar
import os
import re
import shutil
import urllib.parse
import urllib.request
import zipfile
from dataclasses import dataclass, field

__all__ = [
    "BASE", "Package", "Release", "HdError", "LoginError", "parse_releases",
    "newest", "wanted_packages", "HdClient", "safe_extract", "version_key",
    "DEFAULT_SKIP",
]

BASE = "https://hd.asseco.pl"
#: Packages left out by default (owner: "wszystko oprócz paczki-konfiguracyjne").
DEFAULT_SKIP = ("PACZKI-KONFIGURACYJNE",)
_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) HospitalHub"
_TIMEOUT = 60


class HdError(Exception):
    pass


class LoginError(HdError):
    pass


@dataclass
class Package:
    name: str           # "AMMS 6.10.07.95-AMMS"
    url: str            # absolute download URL
    date: str = ""


@dataclass
class Release:
    code: str
    version: str
    status: str
    date: str
    packages: list = field(default_factory=list)


def version_key(v: str) -> tuple:
    return tuple(int(p) if p.isdigit() else -1 for p in re.split(r"[._]", v))


def _text(html: str) -> str:
    import html as _h
    return re.sub(r"\s+", " ", _h.unescape(re.sub(r"<[^>]+>", " ", html))).strip()


_ROW_RE = re.compile(r"<tr\b[^>]*>(.*?)</tr>", re.S)
_TD_RE = re.compile(r"<td\b[^>]*>(.*?)</td>", re.S)
_DL_RE = re.compile(r'href="(/resources/\d+/download)"')


def parse_releases(html: str, code: str = "AMMS") -> list:
    """The releases of `code` on one page of the list, packages attached."""
    out: list[Release] = []
    for row in _ROW_RE.findall(html):
        cells = [_text(c) for c in _TD_RE.findall(row)]
        dl = _DL_RE.search(row)
        if dl and cells:
            if out:
                out[-1].packages.append(Package(
                    name=cells[0], url=BASE + dl.group(1),
                    date=cells[1] if len(cells) > 1 else ""))
            continue
        if len(cells) >= 4 and cells[0] == code and re.match(r"\d", cells[1]):
            out.append(Release(code=cells[0], version=cells[1],
                               status=cells[2], date=cells[3]))
    return out


def newest(releases: list) -> Release | None:
    with_files = [r for r in releases if r.packages]
    return max(with_files, key=lambda r: version_key(r.version), default=None)


def wanted_packages(release: Release, skip=DEFAULT_SKIP) -> list:
    skip_u = [s.upper() for s in skip if s.strip()]
    return [p for p in release.packages
            if not any(s in p.name.upper() for s in skip_u)]


def safe_extract(zip_path: str, dest: str, progress=None, cancelled=None,
                 written: list | None = None) -> list:
    """Unpack `zip_path` into `dest`; no member may land outside it.
    Returns the top-level names written; the paths of the files go to
    `written` when given."""
    root = os.path.realpath(dest)
    tops = []
    with zipfile.ZipFile(zip_path) as z:
        members = z.infolist()
        total = sum(m.file_size for m in members) or 1
        done = 0
        for m in members:
            if cancelled is not None and cancelled():
                raise HdError("Przerwano")
            target = os.path.realpath(os.path.join(root, m.filename))
            if target != root and not target.startswith(root + os.sep):
                raise HdError(f"Niebezpieczna ścieżka w archiwum: {m.filename}")
            top = m.filename.replace("\\", "/").split("/", 1)[0]
            if top and top not in tops:
                tops.append(top)
            if m.is_dir():
                os.makedirs(target, exist_ok=True)
                continue
            os.makedirs(os.path.dirname(target), exist_ok=True)
            if written is not None:
                written.append(target)
            with z.open(m) as src, open(target, "wb") as dst:
                while True:
                    if cancelled is not None and cancelled():
                        raise HdError("Przerwano")
                    buf = src.read(1 << 20)
                    if not buf:
                        break
                    dst.write(buf)
                    done += len(buf)
                    if progress:
                        progress(done, total)
    return tops


def nested_zips(paths: list) -> list:
    """The .zip files among unpacked `paths` (not .jar/.war — those are
    zips too, but are installed as they are)."""
    return [p for p in paths if p.lower().endswith(".zip")]


def extract_nested(zip_path: str, progress=None, cancelled=None) -> str:
    """Unpack a zip found inside a package into a folder beside it, named
    after it: ``AMMS/upgrade-06.10.07.95.zip`` → ``AMMS/upgrade-06.10.07.95/``.
    A zip whose every entry already sits in a folder of that name goes into
    the parent, so the folder is not doubled.  The zip itself stays."""
    stem = os.path.splitext(os.path.basename(zip_path))[0]
    parent = os.path.dirname(zip_path)
    with zipfile.ZipFile(zip_path) as z:
        names = [n.replace("\\", "/") for n in z.namelist()]
    own_folder = names and all(n == stem + "/" or n.startswith(stem + "/")
                               for n in names)
    dest = parent if own_folder else os.path.join(parent, stem)
    safe_extract(zip_path, dest, progress, cancelled)
    return os.path.join(parent, stem)


class HdClient:
    """A logged-in session with hd.asseco.pl."""

    def __init__(self, opener=None):
        self.jar = http.cookiejar.CookieJar()
        self.opener = opener or urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.jar))
        self.opener.addheaders = [("User-Agent", _UA)]

    def _get(self, url: str):
        return self.opener.open(url, timeout=_TIMEOUT)

    def login(self, user: str, password: str) -> None:
        if not user.strip() or not password:
            raise LoginError("Brak loginu lub hasła do hd.asseco.pl")
        self._get(BASE + "/login").read()
        data = urllib.parse.urlencode({
            "username": user.strip().upper(), "password": password,
            "_csrf_token": "csrf-token"}).encode()
        with self.opener.open(BASE + "/login", data=data, timeout=_TIMEOUT) as r:
            page = r.read().decode("utf-8", "replace")
            final = r.geturl()
        if final.rstrip("/").endswith("/login") or 'name="password"' in page:
            raise LoginError("Logowanie do hd.asseco.pl nieudane — sprawdź login i hasło")

    def releases(self, code: str = "AMMS") -> list:
        q = urllib.parse.urlencode({"search[code]": code})
        with self._get(f"{BASE}/resources/list?{q}") as r:
            page = r.read().decode("utf-8", "replace")
            if r.geturl().rstrip("/").endswith("/login"):
                raise LoginError("Sesja hd.asseco.pl wygasła")
        return parse_releases(page, code)

    def download(self, url: str, folder: str, progress=None, cancelled=None) -> str:
        """Download to `folder`; returns the file path.  Written as .part
        and renamed only when complete (size checked)."""
        with self._get(url) as r:
            cd = r.headers.get("Content-Disposition", "")
            m = re.search(r'filename\*?=(?:UTF-8\'\')?"?([^";]+)"?', cd)
            name = os.path.basename(urllib.parse.unquote(m.group(1))) if m \
                else url.rstrip("/").split("/")[-2] + ".zip"
            total = int(r.headers.get("Content-Length") or 0)
            ctype = r.headers.get("Content-Type", "")
            if "text/html" in ctype:
                raise LoginError("Zamiast pliku przyszła strona — sesja wygasła?")
            os.makedirs(folder, exist_ok=True)
            path = os.path.join(folder, name)
            part = path + ".part"
            done = 0
            try:
                with open(part, "wb") as f:
                    while True:
                        if cancelled is not None and cancelled():
                            raise HdError("Przerwano")
                        buf = r.read(1 << 20)
                        if not buf:
                            break
                        f.write(buf)
                        done += len(buf)
                        if progress:
                            progress(done, total)
                if total and done != total:
                    raise HdError(f"Plik {name} niekompletny ({done} z {total} B)")
                os.replace(part, path)
            except BaseException:
                try:
                    os.remove(part)
                except OSError:
                    pass
                raise
        return path


def free_bytes(folder: str) -> int:
    probe = folder
    while probe and not os.path.exists(probe):
        parent = os.path.dirname(probe)
        if parent == probe:
            break
        probe = parent
    try:
        return shutil.disk_usage(probe or ".").free
    except OSError:
        return -1
