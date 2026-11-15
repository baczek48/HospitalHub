"""2026-11-15 (owner): the newest AMMS from hd.asseco.pl — every package but
PACZKI-KONFIGURACYJNE, into a chosen folder, unpacked at once."""

import io
import os
import sys
import time
import zipfile

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for _p in (_PARENT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import hd_asseco as hd  # noqa: E402
import upgrade_plan as up  # noqa: E402


def _main_row(ver, date="2026-11-13 15:51"):
    return f"""<tr style="vertical-align: middle">
      <td><div title="AMMS">AMMS</div></td><td><div title="{ver}">{ver}</div></td>
      <td><div title="Dla wszystkich">Dla wszystkich</div></td>
      <td><div title="{date}">{date}</div></td>
      <td class="text-end"><button>Pokaż</button></td></tr>"""


def _pkg_row(ver, kind, rid):
    return f"""<tr class="collapse container-x"><td colspan="3">
      AMMS {ver}-{kind}</td><td>2026-11-13 15:39</td><td class="text-end">
      <a href="/resources/{rid}/download" target="_blank" class="btn">Pobierz</a></td></tr>"""


PAGE = ("<table><thead><tr><th>Kod</th></tr></thead><tbody>"
        + _main_row("6.10.07.92")
        + _pkg_row("6.10.07.92", "AMMS", 1885)
        + _main_row("6.10.07.95")
        + _pkg_row("6.10.07.95", "PACZKI-KONFIGURACYJNE", 1889)
        + _pkg_row("6.10.07.95", "AMMS", 1890)
        + _pkg_row("6.10.07.95", "DODATKOWE", 1891)
        + _pkg_row("6.10.07.95", "PLATFORMA-INTEGRACYJNA", 1892)
        + _main_row("6.10.07.100")       # listed, nothing to download yet
        + "</tbody></table>")


def test_the_newest_release_with_files_and_its_packages():
    rel = hd.newest(hd.parse_releases(PAGE))
    assert rel.version == "6.10.07.95"
    names = [p.name for p in hd.wanted_packages(rel)]
    assert names == ["AMMS 6.10.07.95-AMMS", "AMMS 6.10.07.95-DODATKOWE",
                     "AMMS 6.10.07.95-PLATFORMA-INTEGRACYJNA"]
    assert rel.packages[1].url == "https://hd.asseco.pl/resources/1890/download"
    assert hd.version_key("6.10.07.100") > hd.version_key("6.10.07.95")


def _zip_bytes(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, data in files.items():
            z.writestr(name, data)
    return buf.getvalue()


def test_extract_keeps_the_folders_and_refuses_an_escape(tmp_path):
    ok = tmp_path / "ok.zip"
    ok.write_bytes(_zip_bytes({"6.10.07.95/AMMS/AMMS_6.10.07.95-standard.jar": b"x"}))
    assert hd.safe_extract(str(ok), str(tmp_path / "out")) == ["6.10.07.95"]
    assert (tmp_path / "out/6.10.07.95/AMMS/AMMS_6.10.07.95-standard.jar").read_bytes() == b"x"
    bad = tmp_path / "bad.zip"
    bad.write_bytes(_zip_bytes({"../evil.txt": b"x"}))
    with pytest.raises(hd.HdError):
        hd.safe_extract(str(bad), str(tmp_path / "out2"))
    assert not (tmp_path / "evil.txt").exists()


def test_a_nested_zip_with_its_own_folder_is_not_doubled(tmp_path):
    z = tmp_path / "upgrade-1.zip"
    z.write_bytes(_zip_bytes({"upgrade-1/a.sql": b"a"}))
    assert hd.extract_nested(str(z)) == str(tmp_path / "upgrade-1")
    assert (tmp_path / "upgrade-1/a.sql").exists()
    assert not (tmp_path / "upgrade-1/upgrade-1").exists()
    assert hd.nested_zips(["x/a.ZIP", "x/b.jar", "x/c.war"]) == ["x/a.ZIP"]


# ── A fake site ──────────────────────────────────────────────────────────

class _Resp(io.BytesIO):
    def __init__(self, body: bytes, url: str, headers=None):
        super().__init__(body)
        self._url = url
        self.headers = headers or {}

    def geturl(self):
        return self._url

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class FakeSite:
    def __init__(self, password="good", zips=None, truncate=False):
        self.password = password
        self.zips = zips or {}
        self.truncate = truncate
        self.logged = False
        self.downloads = []
        self.addheaders = []

    def open(self, url, data=None, timeout=None):
        if url.endswith("/login"):
            if data is None:
                return _Resp(b'<form><input name="password"></form>', url)
            from urllib.parse import parse_qs
            q = parse_qs(data.decode())
            self.logged = q["password"][0] == self.password
            assert q["username"][0] == q["username"][0].upper()
            return (_Resp(b"<html>konsola</html>", "https://hd.asseco.pl/")
                    if self.logged else
                    _Resp(b'<input name="password">', "https://hd.asseco.pl/login"))
        assert self.logged
        if "/resources/list" in url:
            return _Resp(PAGE.encode(), url)
        rid = int(url.split("/")[-2])
        self.downloads.append(rid)
        body = self.zips[rid]
        size = len(body) + (10 if self.truncate else 0)
        return _Resp(body, url, {
            "Content-Type": "application/octet-stream",
            "Content-Length": str(size),
            "Content-Disposition": f"attachment; filename=pkg-{rid}.zip"})


def _site(**kw):
    inner = _zip_bytes({"skrypty/01.sql": b"select 1;", "readme.txt": b"r"})
    zips = {1890: _zip_bytes({"6.10.07.95/AMMS/AMMS_6.10.07.95-standard.jar": b"a" * 3000,
                              "6.10.07.95/AMMS/upgrade-06.10.07.95.zip": inner}),
            1891: _zip_bytes({"6.10.07.95/DODATKOWE/WYMD/x.exe": b"d"}),
            1892: _zip_bytes({"6.10.07.95/PI/platform-installer_6.10.07.95-standard.jar": b"p"})}
    return FakeSite(zips=zips, **kw)


def test_login_refused_with_a_wrong_password():
    c = hd.HdClient(opener=_site(password="other"))
    with pytest.raises(hd.LoginError):
        c.login("jkowalski", "good")


def test_a_short_download_is_not_kept(tmp_path):
    tmp_path = tmp_path / "dl"
    site = _site(truncate=True)
    c = hd.HdClient(opener=site)
    c.login("jkowalski", "good")
    with pytest.raises(hd.HdError):
        c.download("https://hd.asseco.pl/resources/1891/download", str(tmp_path))
    assert os.listdir(tmp_path) == []       # no .part, no zip


# ── The worker and the box ───────────────────────────────────────────────

@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def _run_worker(app, settings, site):
    from ui.hd_download import HdWorker
    w = HdWorker(settings, lambda: hd.HdClient(opener=site))
    res, found, steps = [], [], []
    w.finished_ok.connect(lambda ok, m: res.append((ok, m)))
    w.found.connect(found.append)
    w.progress.connect(lambda t, p: steps.append(t))
    w.start()
    end = time.monotonic() + 10
    while not res and time.monotonic() < end:
        app.processEvents()
        time.sleep(0.01)
    w.wait(2000)
    return res[0], found, steps


def test_the_worker_downloads_unpacks_and_skips_what_is_done(app, tmp_path):
    folder = tmp_path / "upgrade"
    s = dict(up.default_hd(), login="jkowalski", password="good", folder=str(folder))
    site = _site()
    (ok, msg), found, steps = _run_worker(app, s, site)
    assert ok, msg
    assert found == ["6.10.07.95"]
    assert site.downloads == [1890, 1891, 1892]             # no PACZKI (1889)
    assert (folder / "6.10.07.95/AMMS/AMMS_6.10.07.95-standard.jar").exists()
    assert (folder / "6.10.07.95/PI/platform-installer_6.10.07.95-standard.jar").exists()
    assert not list(folder.glob("*.zip"))                    # zips deleted
    # The zip inside the package: unpacked beside it, the zip kept.
    amms = folder / "6.10.07.95/AMMS"
    assert (amms / "upgrade-06.10.07.95/skrypty/01.sql").read_bytes() == b"select 1;"
    assert (amms / "upgrade-06.10.07.95.zip").exists()
    # The jar is a zip too, but is never unpacked.
    assert not (amms / "AMMS_6.10.07.95-standard").exists()
    assert any("rozpakowywanie" in t for t in steps)

    site2 = _site()
    (ok, msg), _f, _s = _run_worker(app, s, site2)
    assert ok and site2.downloads == [] and "już pobrane" in msg


def test_zips_are_kept_when_asked(app, tmp_path):
    tmp_path = tmp_path / "keep"
    s = dict(up.default_hd(), login="jkowalski", password="good",
             folder=str(tmp_path), delete_zip=False, skip="")
    site = _site()
    site.zips[1889] = _zip_bytes({"6.10.07.95/KONF/a.txt": b"k"})
    (ok, msg), _f, _s = _run_worker(app, s, site)
    assert ok and site.downloads == [1889, 1890, 1891, 1892]
    assert len(list(tmp_path.glob("*.zip"))) == 4


def test_a_wrong_password_ends_with_a_message(app, tmp_path):
    s = dict(up.default_hd(), login="jkowalski", password="bad", folder=str(tmp_path))
    (ok, msg), found, _s = _run_worker(app, s, _site())
    assert not ok and "Logowanie" in msg and not found


def test_the_panel_keeps_the_settings_and_takes_the_version(app):
    import models
    from ui.upgrade_panel import UpgradePanel
    h = models.Hospital(name="S")
    p = UpgradePanel(h)
    saves = []
    p.data_changed.connect(lambda: saves.append(1))
    assert p.plan["hd"]["folder"] == r"C:\app\upgrade"
    p._hd_settings({"login": "jkowalski", "password": "x", "folder": "D:\\u",
                    "delete_zip": False, "skip": "PACZKI"})
    assert h.upgrade["hd"]["login"] == "jkowalski" and h.upgrade["hd"]["delete_zip"] is False
    p._hd_version("6.10.07.95")
    assert p.version() == "6.10.07.95" and h.upgrade["version"] == "6.10.07.95"
    assert len(saves) == 2
    back = up.normalize_plan(models.from_dict(models.to_dict([h]))[0].upgrade)
    assert back["hd"]["folder"] == "D:\\u"
