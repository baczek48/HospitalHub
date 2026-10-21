"""SFTP files edited in an external Windows editor (2026-10-15) — on fakes.

The scenario: two files with one name (``config.xml``) from different servers
and directories are open in the editor at once.  A save of one must reach its
own server and path, and nothing else — whatever tab is active, in whatever
order the files are saved, after tabs are closed and files reopened.

Also covered:
* F1 — a file already open is downloaded again ("Otwórz za pomocą…"): the
  poll never uploads a half-written download, a cancel never deletes the copy
  the editor is working on;
* F2 — an upload still running when the user comes back to its tab is not
  started a second time in parallel;
* F3 — a watch is bound to its connection: an entry that somehow sits under
  another connection is never uploaded through it;
* P1 — ``upload_edit`` safe replace (temp file + posix-rename): a broken or
  cancelled transfer, a server without posix-rename, an owner that cannot be
  kept or a directory without write access leave the original untouched and
  never fall back to the direct put.

No network: every server is an in-memory ``FakeServer``.
"""

import os
import re
import stat as st_mod
import sys
from types import SimpleNamespace

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture
def sp(app):
    from ui import ssh_panel
    return ssh_panel


# ══════════════════════════════════════════════════════════════════════════
# In-memory SFTP server
# ══════════════════════════════════════════════════════════════════════════

class FakeServer:
    """A tiny POSIX-ish file tree with failure injection."""

    def __init__(self, name, uid=1000, gid=1000):
        self.name = name
        self.uid, self.gid = uid, gid
        self.groups = {gid}  # a user may chgrp its own file to these
        self.files = {}      # path -> dict(data, mode, uid, gid, link)
        self.log = []        # (op, path, ...)
        self.posix_rename_supported = True
        self.chown_allowed = False
        self.readonly_dirs = set()
        self.break_put_after = None   # bytes written before the link drops
        self.disk_full_after = None   # a write past this size is refused
        self.mtime = 1_000

    def add(self, path, data, mode=0o644, uid=None, gid=None):
        self.files[path] = dict(data=data, mode=st_mod.S_IFREG | mode,
                                uid=self.uid if uid is None else uid,
                                gid=self.gid if gid is None else gid,
                                link=None, mtime=self.mtime)

    def link(self, path, target):
        self.files[path] = dict(data=b"", mode=st_mod.S_IFLNK | 0o777,
                                uid=self.uid, gid=self.gid, link=target,
                                mtime=self.mtime)

    def data(self, path):
        return self.files[path]["data"]

    def leftovers(self):
        return [p for p in self.files if p.endswith(".part")]


def _attrs(f):
    return SimpleNamespace(st_size=len(f["data"]), st_mode=f["mode"],
                           st_uid=f["uid"], st_gid=f["gid"],
                           st_mtime=f["mtime"])


class FakeHandle:
    """A remote file opened for writing (``sftp.open(path, 'wbx')``)."""

    def __init__(self, sftp, path):
        self.sftp, self.path = sftp, path

    def chmod(self, mode):
        self.sftp.s.log.append(("fchmod", self.path, mode))
        f = self.sftp.s.files[self.path]
        f["mode"] = st_mod.S_IFMT(f["mode"]) | mode

    def set_pipelined(self, on=True):
        pass

    def write(self, data):
        self.sftp._alive()
        self.sftp.s.log.append(("write", self.path, len(data)))
        f = self.sftp.s.files[self.path]
        full = self.sftp.s.disk_full_after
        if full is not None and len(f["data"]) + len(data) > full:
            raise OSError(28, "No space left on device")   # the server's status
        limit = self.sftp.s.break_put_after
        if limit is not None and len(f["data"]) + len(data) > limit:
            f["data"] += data[:max(0, limit - len(f["data"]))]
            self.sftp.dead = True          # the link is gone for good
            raise OSError("Socket is closed")
        f["data"] += data

    def close(self):
        self.sftp._alive()
        self.sftp.s.mtime += 1
        self.sftp.s.files[self.path]["mtime"] = self.sftp.s.mtime


class FakeSftp:
    def __init__(self, server, on_get=None):
        self.s = server
        self.on_get = on_get
        self.closed = False
        self.dead = False

    def _alive(self):
        if self.dead or self.closed:
            raise OSError("Socket is closed")

    def open(self, path, mode="r", bufsize=-1):
        self._alive()
        self.s.log.append(("open", path, mode))
        assert bufsize == 0, "zapis bez buforowania i bez potokowania"
        real, existing = self._resolve(path)
        if "x" in mode and existing is not None:
            raise OSError("File exists")
        if existing is not None:
            existing["data"] = b""          # O_TRUNC: same file, same owner/mode
            return FakeHandle(self, real)
        directory = path.rsplit("/", 1)[0] or "/"
        if directory in self.s.readonly_dirs:
            raise PermissionError(13, "Permission denied")
        self.s.files[path] = dict(data=b"", mode=st_mod.S_IFREG | 0o644,
                                  uid=self.s.uid, gid=self.s.gid, link=None,
                                  mtime=self.s.mtime)
        return FakeHandle(self, path)

    def _resolve(self, path):
        f = self.s.files.get(path)
        while f is not None and f["link"]:
            path = f["link"]
            f = self.s.files.get(path)
        return path, f

    def stat(self, path):
        self._alive()
        _, f = self._resolve(path)
        if f is None:
            raise FileNotFoundError(2, "No such file")
        return _attrs(f)

    def lstat(self, path):
        self._alive()
        f = self.s.files.get(path)
        if f is None:
            raise FileNotFoundError(2, "No such file")
        return _attrs(f)

    def normalize(self, path):
        return self._resolve(path)[0]

    def get(self, remote, local, callback=None):
        data = self.stat(remote) and self._resolve(remote)[1]["data"]
        with open(local, "wb") as fh:
            half = len(data) // 2
            fh.write(data[:half])
            fh.flush()
            if self.on_get is not None:
                self.on_get(local)         # the download is half-way here
            if callback:
                callback(half, len(data))
            fh.write(data[half:])
        if callback:
            callback(len(data), len(data))

    def put(self, local, remote, callback=None, confirm=True):
        raise AssertionError("sftp.put (zapis potokowy) nie może być używany")

    def chmod(self, path, mode):
        self._alive()
        self.s.log.append(("chmod", path, mode))
        f = self._resolve(path)[1]
        f["mode"] = st_mod.S_IFMT(f["mode"]) | mode

    def chown(self, path, uid, gid):
        self._alive()
        self.s.log.append(("chown", path, uid, gid))
        own = uid == self.s.uid and gid in self.s.groups
        if not (self.s.chown_allowed or own):
            raise PermissionError(1, "Operation not permitted")
        f = self._resolve(path)[1]
        f["uid"], f["gid"] = uid, gid

    def posix_rename(self, old, new):
        self._alive()
        self.s.log.append(("posix_rename", old, new))
        if not self.s.posix_rename_supported:
            raise IOError("Operation unsupported")
        self.s.files[new] = self.s.files.pop(old)

    def remove(self, path):
        self._alive()
        self.s.log.append(("remove", path))
        if path not in self.s.files:
            raise FileNotFoundError(2, "No such file")
        del self.s.files[path]

    def close(self):
        self.closed = True


class FakeClient:
    """Stands in for paramiko.SSHClient (weak-referenceable)."""

    def __init__(self, server, on_get=None):
        self.server = server
        self.on_get = on_get

    def open_sftp(self):
        return FakeSftp(self.server, self.on_get)


# ══════════════════════════════════════════════════════════════════════════
# A real SftpPanel, its workers run synchronously
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def env(sp, monkeypatch, tmp_path):
    opened = []
    monkeypatch.setattr(sp._SimpleWorker, "start", lambda self: self.run())
    monkeypatch.setattr(sp, "QDesktopServices",
                        SimpleNamespace(openUrl=lambda url: opened.append(url)))
    monkeypatch.setattr(sp, "open_sftp_bounded", lambda c, *a, **k: c.open_sftp())
    # The "changed on the server" question: recorded, answered by the test
    # (default "Nie wgrywaj") — a real modal would block the run.
    asked = []
    answer = ["skip"]

    def ask(self, name, info, err, allow_show=True):
        asked.append((name, err))
        return answer[0]
    monkeypatch.setattr(sp.SftpPanel, "_ask_remote_changed", ask)
    unsent = []
    monkeypatch.setattr(sp.SftpPanel, "_notify_unsent",
                        lambda self, lines: unsent.extend(lines))
    monkeypatch.setattr(sp, "unsent_copies_dir", lambda: str(tmp_path / "unsent"))
    panels = []

    def panel(name="p"):
        p = sp.SftpPanel()
        p._temp_dir = str(tmp_path / name)
        p._list = lambda path: None
        p._probe_writable = lambda remote: True
        p._open_local.disconnect()
        p._open_local.connect(lambda path: opened.append(path))
        panels.append(p)
        return p

    yield SimpleNamespace(panel=panel, opened=opened, asked=asked,
                          answer=answer, unsent=unsent)
    for p in panels:
        p._watch_poll.stop()
        p.deleteLater()


def connect(panel, client):
    panel.switch_sftp(client.open_sftp(), client, "/")


def open_file(panel, remote):
    panel._open_remote(remote, remote.rsplit("/", 1)[1])
    return panel._local_copy_path(remote, remote.rsplit("/", 1)[1])


_SAVES = __import__("itertools").count(1)


def writes(server):
    """Every write-open on `server` — an upload of any kind."""
    return [e for e in server.log if e[0] in ("open", "put")]


def opened_for_write(server, path):
    return any(e[0] == "open" and e[1] == path for e in server.log)


def save_in_editor(local, data):
    """What an editor does on Ctrl+S: new content, newer mtime."""
    with open(local, "wb") as fh:
        fh.write(data)
    t = os.path.getmtime(local) + 5 * next(_SAVES)   # always newer
    os.utime(local, (t, t))


def servers():
    a, b = FakeServer("A"), FakeServer("B")
    for s in (a, b):
        s.add("/opt/x/config.xml", f"{s.name}-x".encode() * 40)
        s.add("/opt/y/config.xml", f"{s.name}-y".encode() * 40)
    return a, b


# ══════════════════════════════════════════════════════════════════════════
# Same name, different servers and directories
# ══════════════════════════════════════════════════════════════════════════

def test_four_files_named_alike_get_four_local_copies_with_their_own_content(env):
    a, b = servers()
    ca, cb = FakeClient(a), FakeClient(b)
    p = env.panel()
    connect(p, ca)
    ax, ay = open_file(p, "/opt/x/config.xml"), open_file(p, "/opt/y/config.xml")
    connect(p, cb)
    bx, by = open_file(p, "/opt/x/config.xml"), open_file(p, "/opt/y/config.xml")

    assert len({ax, ay, bx, by}) == 4
    assert {os.path.basename(x) for x in (ax, ay, bx, by)} == {"config.xml"}
    for local, server, path in ((ax, a, "/opt/x/config.xml"),
                                (ay, a, "/opt/y/config.xml"),
                                (bx, b, "/opt/x/config.xml"),
                                (by, b, "/opt/y/config.xml")):
        with open(local, "rb") as fh:
            assert fh.read() == server.data(path)


def test_saves_in_any_order_reach_only_their_own_server_and_path(env):
    a, b = servers()
    ca, cb = FakeClient(a), FakeClient(b)
    p = env.panel()
    connect(p, ca)
    ax, ay = open_file(p, "/opt/x/config.xml"), open_file(p, "/opt/y/config.xml")
    connect(p, cb)
    bx, by = open_file(p, "/opt/x/config.xml"), open_file(p, "/opt/y/config.xml")

    # B is active.  Save A's files first (their tab is in the background),
    # then B's, then switch around.
    save_in_editor(ay, b"edit A /opt/y" * 10)
    save_in_editor(ax, b"edit A /opt/x" * 10)
    p._poll_watched_files()
    assert a.log == [] and b.log == [], "nic nie idzie przez aktywną kartę B"

    save_in_editor(by, b"edit B /opt/y" * 10)
    p._poll_watched_files()
    connect(p, ca)                      # flush of B, then A's watches back
    p._poll_watched_files()
    save_in_editor(bx, b"edit B /opt/x" * 10)
    connect(p, cb)
    p._poll_watched_files()

    assert a.data("/opt/x/config.xml") == b"edit A /opt/x" * 10
    assert a.data("/opt/y/config.xml") == b"edit A /opt/y" * 10
    assert b.data("/opt/x/config.xml") == b"edit B /opt/x" * 10
    assert b.data("/opt/y/config.xml") == b"edit B /opt/y" * 10
    # The file itself, or the safe replace's temp file next to it.
    assert {re.sub(r"/\.(.+)\.hhv2-[0-9a-f]{8}\.part$", r"/\1", e[1])
            for e in a.log if e[0] == "open"} <= {"/opt/x/config.xml",
                                                  "/opt/y/config.xml"}


def test_two_windows_on_two_servers_never_write_to_each_other(env):
    a, b = servers()
    ca, cb = FakeClient(a), FakeClient(b)
    p1, p2 = env.panel("w1"), env.panel("w2")
    connect(p1, ca)
    connect(p2, cb)
    l1, l2 = open_file(p1, "/opt/x/config.xml"), open_file(p2, "/opt/x/config.xml")
    assert l1 != l2

    save_in_editor(l2, b"only B" * 20)
    p1._poll_watched_files()            # window 1 polls first: not its file
    assert a.log == []
    p2._poll_watched_files()
    assert b.data("/opt/x/config.xml") == b"only B" * 20
    assert a.data("/opt/x/config.xml") == b"A-x" * 40


def test_a_closed_tab_uploads_nothing_and_a_reopen_starts_clean(env):
    a, _ = servers()
    ca = FakeClient(a)
    p = env.panel()
    connect(p, ca)
    old = open_file(p, "/opt/x/config.xml")
    p.forget_connection(ca)                 # tab closed / session dropped

    save_in_editor(old, b"lost on purpose" * 9)
    p._poll_watched_files()
    p._flush_pending_edits()
    assert writes(a) == []

    reconnect = FakeClient(a)               # new session to the same server
    connect(p, reconnect)
    new = open_file(p, "/opt/x/config.xml")
    assert new != old, "nowa sesja = nowa kopia, bez dziedziczenia obserwacji"
    with open(new, "rb") as fh:
        assert fh.read() == b"A-x" * 40
    p._poll_watched_files()
    assert writes(a) == []


def test_a_watch_under_the_wrong_connection_is_never_uploaded(env, sp):
    """F3: even if an entry of A ended up in B's list, B never sends it."""
    a, b = servers()
    ca, cb = FakeClient(a), FakeClient(b)
    p = env.panel()
    connect(p, ca)
    local = open_file(p, "/opt/x/config.xml")
    entry = p._watched_files.pop(local)
    connect(p, cb)
    p._watched_files[local] = entry         # simulated bookkeeping slip
    save_in_editor(local, b"meant for A" * 10)

    p._poll_watched_files()
    p._upload_changed_file(local, "/opt/x/config.xml")
    p._flush_pending_edits()
    assert writes(b) == []
    assert b.data("/opt/x/config.xml") == b"B-x" * 40


def test_an_upload_names_the_watched_path_or_nothing(env):
    a, _ = servers()
    ca = FakeClient(a)
    p = env.panel()
    connect(p, ca)
    local = open_file(p, "/opt/x/config.xml")
    save_in_editor(local, b"x" * 200)
    p._upload_changed_file(local, "/opt/y/config.xml")   # wrong remote
    assert a.log == []


# ══════════════════════════════════════════════════════════════════════════
# F1 — downloading again into a file that is open
# ══════════════════════════════════════════════════════════════════════════

def test_a_redownload_is_never_uploaded_half_way(env, sp, monkeypatch):
    a, _ = servers()
    p = env.panel()
    polls = []

    def mid_download(path):
        # The 2 s poll fires while the file is half-written.
        polls.append(path)
        p._poll_watched_files()

    ca = FakeClient(a, on_get=mid_download)
    connect(p, ca)
    local = open_file(p, "/opt/x/config.xml")
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: None)

    p._open_with("/opt/x/config.xml", "config.xml")

    assert polls and all(x != local for x in polls), "pobieranie do pliku .part"
    assert writes(a) == []
    with open(local, "rb") as fh:
        assert fh.read() == b"A-x" * 40
    assert local in p._watched_files and not p._download_active
    assert not [f for f in os.listdir(os.path.dirname(local)) if f.endswith(".part")]


def test_a_cancelled_redownload_keeps_the_copy_being_edited(env, sp, monkeypatch):
    a, _ = servers()
    p = env.panel()
    ca = FakeClient(a)
    connect(p, ca)
    local = open_file(p, "/opt/x/config.xml")
    save_in_editor(local, b"unsent edit" * 10)
    p._watched_files[local]["mtime"] = os.path.getmtime(local)  # already polled

    def cancel_mid_way(path):
        p._active_transfer_worker._cancel = True
    ca.on_get = cancel_mid_way
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: None)

    p._open_with("/opt/x/config.xml", "config.xml")

    with open(local, "rb") as fh:
        assert fh.read() == b"unsent edit" * 10
    assert not p._download_active
    assert not [f for f in os.listdir(os.path.dirname(local)) if f.endswith(".part")]


def test_a_second_open_while_downloading_does_not_start_another(env):
    a, _ = servers()
    p = env.panel()
    ca = FakeClient(a)
    connect(p, ca)
    local = p._local_copy_path("/opt/x/config.xml", "config.xml")
    p._download_active.add(local)
    p._open_remote("/opt/x/config.xml", "config.xml")
    assert not os.path.exists(local)


# ══════════════════════════════════════════════════════════════════════════
# F2 — no second, parallel upload after a tab round trip
# ══════════════════════════════════════════════════════════════════════════

def test_an_upload_still_running_is_not_started_again(env, sp, monkeypatch):
    a, b = servers()
    ca, cb = FakeClient(a), FakeClient(b)
    p = env.panel()
    connect(p, ca)
    local = open_file(p, "/opt/x/config.xml")
    started = []
    monkeypatch.setattr(sp._SimpleWorker, "start", lambda self: started.append(self))

    save_in_editor(local, b"first" * 30)
    p._poll_watched_files()
    assert len(started) == 1            # upload of A in flight
    connect(p, cb)
    connect(p, ca)
    save_in_editor(local, b"second" * 30)
    p._poll_watched_files()
    assert len(started) == 1, "brak drugiego równoległego zapisu tego pliku"


# ══════════════════════════════════════════════════════════════════════════
# P1 — upload_edit, safe replace
# ══════════════════════════════════════════════════════════════════════════

ORIGINAL = b'<?xml version="1.0"?><config><item k="a"/></config>\n' * 50


@pytest.fixture
def xmlfile(tmp_path):
    server = FakeServer("H")
    server.groups.add(50)               # the SFTP user is in group 50
    server.add("/data/out/config.xml", ORIGINAL, mode=0o640, uid=1000, gid=50)
    local = tmp_path / "config.xml"
    local.write_bytes(b'<?xml version="1.0"?><config><item k="b"/></config>\n' * 60)
    return server, FakeSftp(server), str(local)


def test_the_safe_replace_is_on(sp):
    """2026-10-21 (owner): on, with the in-place write where the server does
    not allow it (``fallback_direct``)."""
    assert sp.SFTP_SAFE_REPLACE_ENABLED is True


@pytest.mark.parametrize("setup, why", [
    (lambda s: s.files["/data/out/config.xml"].update(uid=2000), "właściciela"),
    (lambda s: setattr(s, "posix_rename_supported", False), "posix-rename"),
    (lambda s: s.readonly_dirs.add("/data/out"), "tymczasowego"),
])
def test_where_the_server_does_not_allow_it_the_edit_is_written_in_place(
        sp, xmlfile, setup, why):
    server, sftp, local = xmlfile
    setup(server)
    in_place = []
    sp.upload_edit(sftp, local, "/data/out/config.xml", fallback_direct=True,
                   in_place=in_place)
    f = server.files["/data/out/config.xml"]
    assert f["data"] == open(local, "rb").read()
    assert st_mod.S_IMODE(f["mode"]) == 0o640, "zapis w miejscu: tryb bez zmian"
    assert len(in_place) == 1 and why in in_place[0]
    assert server.leftovers() == []


def test_a_broken_temp_write_never_falls_back_to_the_original(sp, xmlfile):
    server, sftp, local = xmlfile
    server.break_put_after = 100
    in_place = []
    with pytest.raises(sp.SafeReplaceError):
        sp.upload_edit(sftp, local, "/data/out/config.xml", fallback_direct=True,
                       in_place=in_place)
    assert server.data("/data/out/config.xml") == ORIGINAL
    assert in_place == [] and not opened_for_write(server, "/data/out/config.xml")


def test_a_cancel_before_the_fallback_write_leaves_the_original(sp, xmlfile):
    server, sftp, local = xmlfile
    server.posix_rename_supported = False

    def before_commit():
        if any(e[0] == "posix_rename" for e in server.log):
            raise sp._CancelledError()      # hit Cancel after the refusal
    with pytest.raises(sp._CancelledError):
        sp.upload_edit(sftp, local, "/data/out/config.xml", fallback_direct=True,
                       before_commit=before_commit)
    assert server.data("/data/out/config.xml") == ORIGINAL
    assert not opened_for_write(server, "/data/out/config.xml")


def test_the_panel_saves_a_file_owned_by_someone_else_in_place(env):
    a, _ = servers()
    a.files["/opt/x/config.xml"]["uid"] = 2000      # group-writable, not ours
    p = env.panel()
    connect(p, FakeClient(a))
    local = open_file(p, "/opt/x/config.xml")
    messages = []
    p.status_msg.connect(lambda text, err: messages.append((text, err)))
    save_in_editor(local, b"edited" * 30)

    p._poll_watched_files()

    assert a.data("/opt/x/config.xml") == b"edited" * 30
    assert a.files["/opt/x/config.xml"]["uid"] == 2000
    assert p._watched_files[local]["dirty"] is False
    assert any(not err and "zapis bezpośredni" in text for text, err in messages)


def test_the_panel_by_default_keeps_the_server_file_on_a_drop(env):
    a, _ = servers()
    original = a.data("/opt/x/config.xml")
    p = env.panel()
    connect(p, FakeClient(a))
    local = open_file(p, "/opt/x/config.xml")
    a.break_put_after = 10
    save_in_editor(local, b"new content" * 20)

    p._poll_watched_files()

    assert a.data("/opt/x/config.xml") == original
    assert p._watched_files[local]["dirty"] is True


def test_safe_replace_swaps_the_file_and_keeps_mode_and_owner(sp, xmlfile):
    server, sftp, local = xmlfile
    sp.upload_edit(sftp, local, "/data/out/config.xml", safe_replace=True)
    f = server.files["/data/out/config.xml"]
    assert f["data"] == open(local, "rb").read()
    assert st_mod.S_IMODE(f["mode"]) == 0o640 and (f["uid"], f["gid"]) == (1000, 50)
    assert server.leftovers() == []
    assert not opened_for_write(server, "/data/out/config.xml"), "oryginał nigdy otwarty do zapisu"


def test_the_temp_file_is_hidden_and_next_to_the_original(sp, xmlfile):
    server, sftp, local = xmlfile
    sp.upload_edit(sftp, local, "/data/out/config.xml", safe_replace=True)
    tmp = next(e[1] for e in server.log if e[0] == "open")
    assert ("open", tmp, "wbx") in server.log, "nigdy nie nadpisuje istniejącego"
    assert ("fchmod", tmp, 0o600) in server.log
    assert server.log.index(("fchmod", tmp, 0o600)) < server.log.index(("posix_rename", tmp, "/data/out/config.xml"))
    head, base = tmp.rsplit("/", 1)
    assert head == "/data/out" and base.startswith(".config.xml.") and base.endswith(".part")
    assert not base.endswith(".xml")


def test_a_broken_transfer_leaves_the_original_whole(sp, xmlfile):
    """The link drops mid-transfer: the original is whole; the temp file
    cannot be removed over the dead channel and is reported (review M3)."""
    server, sftp, local = xmlfile
    server.break_put_after = 100
    leftovers = []
    with pytest.raises(sp.SafeReplaceError, match="nie został zmieniony"):
        sp.upload_edit(sftp, local, "/data/out/config.xml", safe_replace=True,
                       leftovers=leftovers)
    assert server.data("/data/out/config.xml") == ORIGINAL
    assert leftovers == server.leftovers() and len(leftovers) == 1
    assert st_mod.S_IMODE(server.files[leftovers[0]]["mode"]) == 0o600,         "fragment z danymi nie jest czytelny dla innych"


def test_a_failure_on_a_live_link_removes_the_temp_file(sp, xmlfile):
    server, sftp, local = xmlfile
    server.files["/data/out/config.xml"]["uid"] = 2000
    leftovers = []
    with pytest.raises(sp.SafeReplaceError):
        sp.upload_edit(sftp, local, "/data/out/config.xml", safe_replace=True,
                       leftovers=leftovers)
    assert leftovers == [] and server.leftovers() == []


def test_a_lost_rename_reply_is_reported_as_unknown(sp, xmlfile):
    """Review M4: no reply to the rename — never claim the file is intact."""
    server, sftp, local = xmlfile
    real = sftp.posix_rename

    def rename_then_drop(old, new):
        real(old, new)
        sftp.dead = True
        raise OSError("Socket is closed")
    sftp.posix_rename = rename_then_drop
    with pytest.raises(sp.SafeReplaceError, match="NIEZNANY"):
        sp.upload_edit(sftp, local, "/data/out/config.xml", safe_replace=True)


def test_a_file_taken_by_the_receiver_right_after_the_rename_is_success(sp, xmlfile):
    """Review M4: a receiver that moves the file away at once must not turn
    a done replace into an error (and a needless second write on retry)."""
    server, sftp, local = xmlfile
    real = sftp.posix_rename

    def rename_then_receiver_takes_it(old, new):
        real(old, new)
        del server.files[new]
    sftp.posix_rename = rename_then_receiver_takes_it
    assert sp.upload_edit(sftp, local, "/data/out/config.xml", safe_replace=True) is None


def test_a_file_gone_from_the_server_is_not_recreated(sp, xmlfile):
    server, sftp, local = xmlfile
    del server.files["/data/out/config.xml"]
    with pytest.raises(sp.SafeReplaceError, match="nie istnieje"):
        sp.upload_edit(sftp, local, "/data/out/config.xml", safe_replace=True)
    assert server.files == {}


def test_a_cancel_during_the_transfer_leaves_the_original_whole(sp, xmlfile):
    server, sftp, local = xmlfile

    def cb(done, total):
        raise sp._CancelledError()
    with pytest.raises(sp._CancelledError):
        sp.upload_edit(sftp, local, "/data/out/config.xml", callback=cb,
                       safe_replace=True)
    assert server.data("/data/out/config.xml") == ORIGINAL
    assert server.leftovers() == []


def test_a_cancel_just_before_the_rename_leaves_the_original_whole(sp, xmlfile):
    server, sftp, local = xmlfile

    def before_commit():
        raise sp._CancelledError()
    with pytest.raises(sp._CancelledError):
        sp.upload_edit(sftp, local, "/data/out/config.xml", safe_replace=True,
                       before_commit=before_commit)
    assert server.data("/data/out/config.xml") == ORIGINAL
    assert server.leftovers() == []


def test_no_posix_rename_means_a_clear_error_and_no_direct_write(sp, xmlfile):
    server, sftp, local = xmlfile
    server.posix_rename_supported = False
    with pytest.raises(sp.SafeReplaceError, match="posix-rename"):
        sp.upload_edit(sftp, local, "/data/out/config.xml", safe_replace=True)
    assert server.data("/data/out/config.xml") == ORIGINAL
    assert not opened_for_write(server, "/data/out/config.xml")
    assert server.leftovers() == []


def test_an_owner_that_cannot_be_kept_aborts(sp, xmlfile):
    server, sftp, local = xmlfile
    server.files["/data/out/config.xml"]["uid"] = 2000     # owned by another user
    with pytest.raises(sp.SafeReplaceError, match="właściciela"):
        sp.upload_edit(sftp, local, "/data/out/config.xml", safe_replace=True)
    assert server.data("/data/out/config.xml") == ORIGINAL
    assert server.files["/data/out/config.xml"]["uid"] == 2000
    assert server.leftovers() == []


def test_an_owner_is_restored_when_the_server_allows_it(sp, xmlfile):
    server, sftp, local = xmlfile
    server.files["/data/out/config.xml"]["uid"] = 2000
    server.chown_allowed = True                         # e.g. root
    sp.upload_edit(sftp, local, "/data/out/config.xml", safe_replace=True)
    assert server.files["/data/out/config.xml"]["uid"] == 2000


def test_a_directory_without_write_access_aborts_without_fallback(sp, xmlfile):
    server, sftp, local = xmlfile
    server.readonly_dirs.add("/data/out")
    with pytest.raises(sp.SafeReplaceError, match="tymczasowego"):
        sp.upload_edit(sftp, local, "/data/out/config.xml", safe_replace=True)
    assert server.data("/data/out/config.xml") == ORIGINAL
    assert not opened_for_write(server, "/data/out/config.xml"), "bez powrotu do zapisu bezpośredniego"


def test_a_symlink_is_kept_and_its_target_replaced(sp, xmlfile):
    server, sftp, local = xmlfile
    server.link("/data/current.xml", "/data/out/config.xml")
    sp.upload_edit(sftp, local, "/data/current.xml", safe_replace=True)
    assert server.files["/data/current.xml"]["link"] == "/data/out/config.xml"
    assert server.data("/data/out/config.xml") == open(local, "rb").read()


def test_something_that_is_not_a_file_is_refused(sp, xmlfile):
    server, sftp, local = xmlfile
    server.files["/data/out/config.xml"]["mode"] = st_mod.S_IFDIR | 0o755
    with pytest.raises(sp.SafeReplaceError, match="zwykłym plikiem"):
        sp.upload_edit(sftp, local, "/data/out/config.xml", safe_replace=True)


def test_direct_mode_writes_in_place_with_acknowledged_writes(sp, xmlfile):
    """Flag off (the default): the file is truncated and written in place —
    through an unbuffered handle, never paramiko's pipelined put."""
    server, sftp, local = xmlfile
    final = sp.upload_edit(sftp, local, "/data/out/config.xml", safe_replace=False)
    assert [e for e in server.log if e[0] == "open"] == [
        ("open", "/data/out/config.xml", "wb")]
    f = server.files["/data/out/config.xml"]
    assert f["data"] == open(local, "rb").read() and final.st_size == len(f["data"])
    assert st_mod.S_IMODE(f["mode"]) == 0o640 and (f["uid"], f["gid"]) == (1000, 50), \
        "zapis w miejscu: ten sam plik, ten sam właściciel i tryb"


def test_direct_mode_reports_a_full_disk_at_once(sp, xmlfile):
    server, sftp, local = xmlfile
    server.disk_full_after = 1000
    with pytest.raises(OSError, match="No space"):
        sp.upload_edit(sftp, local, "/data/out/config.xml", safe_replace=False)
    # Honest: in place, the original is already cut — the error says so to
    # the caller, it does not pretend the file is intact.
    assert len(server.data("/data/out/config.xml")) <= 1000


def test_direct_mode_does_not_protect_the_original_on_a_drop(sp, xmlfile):
    """The reason SFTP_SAFE_REPLACE_ENABLED exists: a drop mid-transfer
    truncates the original in direct mode."""
    server, sftp, local = xmlfile
    server.break_put_after = 100
    with pytest.raises(OSError):
        sp.upload_edit(sftp, local, "/data/out/config.xml", safe_replace=False)
    assert server.data("/data/out/config.xml") != ORIGINAL


def test_direct_mode_catches_bytes_the_server_lost(sp, xmlfile, monkeypatch):
    server, sftp, local = xmlfile
    real = FakeHandle.write

    def lossy(self, data):
        real(self, data[:-1] if len(data) > 1 else data)   # OK, but short
    monkeypatch.setattr(FakeHandle, "write", lossy)
    with pytest.raises(IOError, match="weryfikacja po zapisie"):
        sp.upload_edit(sftp, local, "/data/out/config.xml", safe_replace=False)


def test_direct_mode_cancel_stops_the_writes(sp, xmlfile):
    server, sftp, local = xmlfile

    def cb(done, total):
        raise sp._CancelledError()
    with pytest.raises(sp._CancelledError):
        sp.upload_edit(sftp, local, "/data/out/config.xml", callback=cb,
                       safe_replace=False)
    assert len([e for e in server.log if e[0] == "write"]) == 1


def test_the_panel_in_direct_mode_reports_a_full_disk(env):
    a, _ = servers()
    ca = FakeClient(a)
    p = env.panel()
    connect(p, ca)
    local = open_file(p, "/opt/x/config.xml")
    messages = []
    p.status_msg.connect(lambda text, err: messages.append((text, err)))
    a.disk_full_after = 50
    save_in_editor(local, b"new content" * 20)

    p._poll_watched_files()

    assert p._watched_files[local]["dirty"] is True
    assert any(err and "No space" in text for text, err in messages)
    a.disk_full_after = None                # space freed: the next save goes
    save_in_editor(local, b"new content 2" * 20)
    p._poll_watched_files()
    assert a.data("/opt/x/config.xml") == b"new content 2" * 20
    assert p._watched_files[local]["dirty"] is False


def test_the_panel_with_safe_replace_keeps_the_server_file_on_a_drop(env, sp,
                                                                     monkeypatch):
    monkeypatch.setattr(sp, "SFTP_SAFE_REPLACE_ENABLED", True)
    a, _ = servers()
    ca = FakeClient(a)
    p = env.panel()
    connect(p, ca)
    local = open_file(p, "/opt/x/config.xml")
    messages = []
    p.status_msg.connect(lambda text, err: messages.append((text, err)))
    a.break_put_after = 10
    save_in_editor(local, b"new content" * 20)

    p._poll_watched_files()

    assert a.data("/opt/x/config.xml") == b"A-x" * 40
    assert p._watched_files[local]["dirty"] is True
    assert any(err and "nie został zmieniony" in text for text, err in messages)
    left = a.leftovers()
    assert len(left) == 1 and any(err and left[0] in text for text, err in messages),         "pozostawiony plik tymczasowy jest nazwany w komunikacie"

    a.break_put_after = None                # link back: the next save goes
    save_in_editor(local, b"new content 2" * 20)
    p._poll_watched_files()
    assert a.data("/opt/x/config.xml") == b"new content 2" * 20
    assert p._watched_files[local]["dirty"] is False


# ══════════════════════════════════════════════════════════════════════════
# Review 2026-10-15: M1 (open during upload), M2 (unsent edits), L7
# ══════════════════════════════════════════════════════════════════════════

def test_m1_no_download_while_the_same_file_is_uploading(env, monkeypatch):
    a, _ = servers()
    p = env.panel()
    ca = FakeClient(a)
    connect(p, ca)
    local = open_file(p, "/opt/x/config.xml")
    gets = []
    ca.on_get = gets.append
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: None)
    p._upload_active.add(local)

    p._open_with("/opt/x/config.xml", "config.xml")
    a.files["/opt/x/config.xml"]["mtime"] += 100     # looks changed on server
    p._open_remote("/opt/x/config.xml", "config.xml")

    assert gets == [] and local in p._watched_files


def test_m2_open_with_never_replaces_unsent_edits(env, monkeypatch):
    a, _ = servers()
    p = env.panel()
    ca = FakeClient(a)
    connect(p, ca)
    local = open_file(p, "/opt/x/config.xml")
    save_in_editor(local, b"not uploaded yet" * 9)
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: None)

    p._open_with("/opt/x/config.xml", "config.xml")
    with open(local, "rb") as fh:
        assert fh.read() == b"not uploaded yet" * 9

    p._watched_files[local]["mtime"] = os.path.getmtime(local)
    p._watched_files[local]["dirty"] = True               # last upload failed
    p._open_with("/opt/x/config.xml", "config.xml")
    with open(local, "rb") as fh:
        assert fh.read() == b"not uploaded yet" * 9


def test_m2_a_newer_server_file_never_replaces_unsent_edits(env):
    a, _ = servers()
    p = env.panel()
    ca = FakeClient(a)
    connect(p, ca)
    local = open_file(p, "/opt/x/config.xml")
    save_in_editor(local, b"mine" * 50)
    a.add("/opt/x/config.xml", b"someone else" * 30)
    a.files["/opt/x/config.xml"]["mtime"] += 100

    p._open_remote("/opt/x/config.xml", "config.xml")

    with open(local, "rb") as fh:
        assert fh.read() == b"mine" * 50
    assert local in p._watched_files


def test_m2_a_save_during_the_download_is_kept_and_uploaded(env, monkeypatch):
    a, _ = servers()
    p = env.panel()
    ca = FakeClient(a)
    connect(p, ca)
    local = open_file(p, "/opt/x/config.xml")
    ca.on_get = lambda part: save_in_editor(local, b"saved meanwhile" * 9)
    monkeypatch.setattr("subprocess.Popen", lambda *a, **k: None)

    p._open_with("/opt/x/config.xml", "config.xml")
    with open(local, "rb") as fh:
        assert fh.read() == b"saved meanwhile" * 9
    assert not p._download_active

    p._poll_watched_files()
    assert a.data("/opt/x/config.xml") == b"saved meanwhile" * 9


def test_l7_a_manual_upload_through_a_drops_only_as_watch(env):
    a, b = servers()
    ca, cb = FakeClient(a), FakeClient(b)
    p = env.panel()
    connect(p, ca)
    la = open_file(p, "/opt/x/config.xml")
    connect(p, cb)
    lb = open_file(p, "/opt/x/config.xml")

    p._invalidate_open_remote_cache("/opt/x/config.xml", ca)  # A's put ended

    assert lb in p._watched_files, "obserwacja B bez zmian"
    connect(p, ca)
    assert la not in p._watched_files


def test_m2_open_remote_keeps_the_watch_when_the_redownload_fails(env):
    """Re-review: the server file changed, the user saves during the new
    download — the save is kept AND still uploaded (the watch never left)."""
    a, _ = servers()
    p = env.panel()
    ca = FakeClient(a)
    connect(p, ca)
    local = open_file(p, "/opt/x/config.xml")
    a.add("/opt/x/config.xml", b"newer on server" * 9)
    a.files["/opt/x/config.xml"]["mtime"] += 100
    ca.on_get = lambda part: save_in_editor(local, b"saved meanwhile" * 9)

    p._open_remote("/opt/x/config.xml", "config.xml")

    assert local in p._watched_files and not p._download_active
    env.answer[0] = "overwrite"
    p._poll_watched_files()
    assert len(env.asked) == 1, "serwer się zmienił: najpierw pytanie (2026-10-21)"
    assert a.data("/opt/x/config.xml") == b"saved meanwhile" * 9


def test_m2_open_remote_refused_large_file_keeps_the_watch(env, monkeypatch):
    a, _ = servers()
    p = env.panel()
    ca = FakeClient(a)
    connect(p, ca)
    local = open_file(p, "/opt/x/config.xml")
    a.files["/opt/x/config.xml"]["mtime"] += 100
    monkeypatch.setattr(p, "_LARGE_FILE_THRESHOLD", 1)
    monkeypatch.setattr(p, "_confirm_large_file", lambda *a: False)

    p._open_remote("/opt/x/config.xml", "config.xml")
    save_in_editor(local, b"still mine" * 9)
    env.answer[0] = "overwrite"
    p._poll_watched_files()
    assert len(env.asked) == 1, "serwer się zmienił: najpierw pytanie (2026-10-21)"
    assert a.data("/opt/x/config.xml") == b"still mine" * 9


def test_unknown_state_is_reported_even_after_a_cancel(env, sp, monkeypatch):
    monkeypatch.setattr(sp, "SFTP_SAFE_REPLACE_ENABLED", True)
    a, _ = servers()
    p = env.panel()
    ca = FakeClient(a)
    connect(p, ca)
    local = open_file(p, "/opt/x/config.xml")
    messages = []
    p.status_msg.connect(lambda text, err: messages.append((text, err)))
    real_open = ca.open_sftp

    def sftp_with_lost_rename():
        sftp = real_open()
        real = sftp.posix_rename

        def rename(old, new):
            real(old, new)
            p._active_transfer_worker._cancel = True   # user hit Cancel
            sftp.dead = True
            raise OSError("Socket is closed")
        sftp.posix_rename = rename
        return sftp
    ca.open_sftp = sftp_with_lost_rename
    save_in_editor(local, b"edit" * 50)

    p._poll_watched_files()
    assert any(err and "NIEZNANY" in text for text, err in messages)


# ══════════════════════════════════════════════════════════════════════════
# UX audit 2026-10-16, S-01: a reconnect keeps the editor's later saves
# ══════════════════════════════════════════════════════════════════════════

def test_a_reconnect_of_the_session_keeps_uploading_saves(env):
    a, _ = servers()
    old = FakeClient(a)
    p = env.panel()
    connect(p, old)
    local = open_file(p, "/opt/x/config.xml")
    old.server = None                       # the link is gone

    new = FakeClient(a)                     # same session, same server
    p.rebind_connection(old, new)
    assert p._sftp is None, "nic nie biegnie przez martwe połączenie"
    connect(p, new)
    save_in_editor(local, b"after the drop" * 10)
    p._poll_watched_files()
    assert a.data("/opt/x/config.xml") == b"after the drop" * 10


def test_a_reconnect_of_an_inactive_tab_waits_for_that_tab(env):
    a, b = servers()
    old_a, cb = FakeClient(a), FakeClient(b)
    p = env.panel()
    connect(p, old_a)
    local = open_file(p, "/opt/x/config.xml")
    connect(p, cb)                          # user is on tab B meanwhile
    new_a = FakeClient(a)
    p.rebind_connection(old_a, new_a)
    save_in_editor(local, b"edit for A" * 10)
    p._poll_watched_files()
    assert b.data("/opt/x/config.xml") == b"B-x" * 40, "nigdy na inny serwer"
    connect(p, new_a)                       # back on tab A
    p._poll_watched_files()
    assert a.data("/opt/x/config.xml") == b"edit for A" * 10


def test_closing_the_tab_still_forgets_its_watches(env):
    a, _ = servers()
    c = FakeClient(a)
    p = env.panel()
    connect(p, c)
    local = open_file(p, "/opt/x/config.xml")
    p.forget_connection(c)
    save_in_editor(local, b"lost on purpose" * 9)
    p._poll_watched_files()
    assert a.data("/opt/x/config.xml") == b"A-x" * 40


# ══════════════════════════════════════════════════════════════════════════
# 2026-10-21: the server file changed under an open edit ("jak MobaXterm")
# ══════════════════════════════════════════════════════════════════════════

def change_on_server(server, path, data):
    """Someone else writes the file: new content, newer mtime."""
    server.mtime += 10
    server.add(path, data)


def test_one_file_in_two_windows_the_second_save_asks_and_keeps_the_first(env):
    a, _ = servers()
    p1, p2 = env.panel("w1"), env.panel("w2")
    connect(p1, FakeClient(a))
    connect(p2, FakeClient(a))
    l1 = open_file(p1, "/opt/x/config.xml")
    l2 = open_file(p2, "/opt/x/config.xml")

    save_in_editor(l1, b"edit from window 1" * 5)
    p1._poll_watched_files()
    assert a.data("/opt/x/config.xml") == b"edit from window 1" * 5
    assert env.asked == []

    save_in_editor(l2, b"edit from window 2" * 5)
    p2._poll_watched_files()

    assert len(env.asked) == 1 and not env.asked[0][1].deleted
    assert a.data("/opt/x/config.xml") == b"edit from window 1" * 5, \
        "zmiana z okna 1 nie może zniknąć bez pytania"
    assert p2._watched_files[l2]["dirty"] is True
    with open(l2, "rb") as fh:
        assert fh.read() == b"edit from window 2" * 5, "moja wersja zostaje"


def test_one_file_in_two_tabs_of_one_window(env):
    a, _ = servers()
    c1, c2 = FakeClient(a), FakeClient(a)
    p = env.panel()
    connect(p, c1)
    l1 = open_file(p, "/opt/x/config.xml")
    connect(p, c2)
    l2 = open_file(p, "/opt/x/config.xml")

    save_in_editor(l2, b"tab 2" * 20)
    p._poll_watched_files()
    connect(p, c1)
    save_in_editor(l1, b"tab 1" * 20)
    p._poll_watched_files()

    assert len(env.asked) == 1
    assert a.data("/opt/x/config.xml") == b"tab 2" * 20


def test_a_change_from_the_terminal_is_not_overwritten_unasked(env):
    a, _ = servers()
    p = env.panel()
    connect(p, FakeClient(a))
    local = open_file(p, "/opt/x/config.xml")
    change_on_server(a, "/opt/x/config.xml", b"vim in the terminal" * 4)

    save_in_editor(local, b"editor" * 30)
    p._poll_watched_files()
    assert len(env.asked) == 1
    assert a.data("/opt/x/config.xml") == b"vim in the terminal" * 4

    env.answer[0] = "overwrite"            # the next save: user overwrites
    save_in_editor(local, b"editor 2" * 30)
    p._poll_watched_files()
    assert len(env.asked) == 2
    assert a.data("/opt/x/config.xml") == b"editor 2" * 30
    assert p._watched_files[local]["dirty"] is False

    save_in_editor(local, b"editor 3" * 30)  # nothing new on the server
    p._poll_watched_files()
    assert len(env.asked) == 2, "po własnym zapisie bez fałszywych alarmów"
    assert a.data("/opt/x/config.xml") == b"editor 3" * 30


def test_overwrite_right_away_from_the_question(env):
    a, _ = servers()
    p = env.panel()
    connect(p, FakeClient(a))
    local = open_file(p, "/opt/x/config.xml")
    change_on_server(a, "/opt/x/config.xml", b"theirs" * 9)
    env.answer[0] = "overwrite"

    save_in_editor(local, b"mine" * 9)
    p._poll_watched_files()

    assert len(env.asked) == 1
    assert a.data("/opt/x/config.xml") == b"mine" * 9


def test_many_saves_of_my_own_never_ask(env):
    a, _ = servers()
    p = env.panel()
    connect(p, FakeClient(a))
    local = open_file(p, "/opt/x/config.xml")
    for i in range(5):
        save_in_editor(local, f"save {i}".encode() * 20)
        p._poll_watched_files()
    assert env.asked == []
    assert a.data("/opt/x/config.xml") == b"save 4" * 20


def test_show_server_version_opens_a_separate_unwatched_copy(env):
    a, _ = servers()
    p = env.panel()
    connect(p, FakeClient(a))
    local = open_file(p, "/opt/x/config.xml")
    change_on_server(a, "/opt/x/config.xml", b"theirs" * 9)
    env.answer[0] = "show"
    env.opened.clear()

    save_in_editor(local, b"mine" * 9)
    p._poll_watched_files()

    assert a.data("/opt/x/config.xml") == b"theirs" * 9
    shown = [x for x in env.opened if isinstance(x, str)]
    assert len(shown) == 1 and shown[0] != local
    assert "wersja z serwera" in os.path.basename(shown[0])
    assert shown[0].endswith(".xml")
    with open(shown[0], "rb") as fh:
        assert fh.read() == b"theirs" * 9
    assert shown[0] not in p._watched_files, "zapis podglądu niczego nie wgrywa"
    with open(local, "rb") as fh:
        assert fh.read() == b"mine" * 9


def test_a_file_deleted_on_the_server_is_not_recreated_unasked(env):
    a, _ = servers()
    p = env.panel()
    connect(p, FakeClient(a))
    local = open_file(p, "/opt/x/config.xml")
    del a.files["/opt/x/config.xml"]

    save_in_editor(local, b"mine" * 9)
    p._poll_watched_files()
    assert len(env.asked) == 1 and env.asked[0][1].deleted
    assert "/opt/x/config.xml" not in a.files

    env.answer[0] = "overwrite"
    save_in_editor(local, b"mine again" * 9)
    p._poll_watched_files()
    assert a.data("/opt/x/config.xml") == b"mine again" * 9


def test_my_own_broken_write_is_not_reported_as_someone_elses(env):
    a, _ = servers()
    p = env.panel()
    connect(p, FakeClient(a))
    local = open_file(p, "/opt/x/config.xml")
    a.disk_full_after = 50
    save_in_editor(local, b"new content" * 20)
    p._poll_watched_files()                 # half-written by us, then refused
    a.disk_full_after = None
    save_in_editor(local, b"new content 2" * 20)
    p._poll_watched_files()
    assert env.asked == []
    assert a.data("/opt/x/config.xml") == b"new content 2" * 20


def test_a_tab_switch_never_overwrites_and_asks_on_return(env):
    a, b = servers()
    ca, cb = FakeClient(a), FakeClient(b)
    p = env.panel()
    connect(p, ca)
    local = open_file(p, "/opt/x/config.xml")
    change_on_server(a, "/opt/x/config.xml", b"theirs" * 9)
    save_in_editor(local, b"mine" * 9)

    connect(p, cb)                          # flush on the way out
    assert env.asked == [], "przełączenie karty nie pyta"
    assert a.data("/opt/x/config.xml") == b"theirs" * 9

    env.answer[0] = "overwrite"
    connect(p, ca)
    p._poll_watched_files()
    assert len(env.asked) == 1
    assert a.data("/opt/x/config.xml") == b"mine" * 9


def test_closing_with_a_conflict_asks_and_keeps_my_version(env):
    a, _ = servers()
    p = env.panel()
    connect(p, FakeClient(a))
    local = open_file(p, "/opt/x/config.xml")
    change_on_server(a, "/opt/x/config.xml", b"theirs" * 9)
    save_in_editor(local, b"mine" * 9)

    p._flush_pending_edits(final=True)

    assert len(env.asked) == 1
    assert a.data("/opt/x/config.xml") == b"theirs" * 9
    assert len(env.unsent) == 1
    kept = env.unsent[0].split("zachowana: ", 1)[1]
    with open(kept, "rb") as fh:
        assert fh.read() == b"mine" * 9


def test_closing_with_a_conflict_can_overwrite(env):
    a, _ = servers()
    p = env.panel()
    connect(p, FakeClient(a))
    local = open_file(p, "/opt/x/config.xml")
    change_on_server(a, "/opt/x/config.xml", b"theirs" * 9)
    save_in_editor(local, b"mine" * 9)
    env.answer[0] = "overwrite"

    p._flush_pending_edits(final=True)

    assert a.data("/opt/x/config.xml") == b"mine" * 9
    assert env.unsent == []


def test_closing_with_a_dead_link_keeps_my_version(env):
    a, _ = servers()
    c = FakeClient(a)
    p = env.panel()
    connect(p, c)
    local = open_file(p, "/opt/x/config.xml")
    save_in_editor(local, b"mine" * 9)

    def dead():
        raise OSError("Socket is closed")
    c.open_sftp = dead
    p._flush_pending_edits(final=True)

    assert len(env.unsent) == 1 and "zachowana: " in env.unsent[0]
    kept = env.unsent[0].split("zachowana: ", 1)[1]
    with open(kept, "rb") as fh:
        assert fh.read() == b"mine" * 9


def test_a_flush_refreshes_the_baseline(env):
    """After a flush on a tab switch, the next save from the same copy is
    not mistaken for a conflict."""
    a, b = servers()
    ca, cb = FakeClient(a), FakeClient(b)
    p = env.panel()
    connect(p, ca)
    local = open_file(p, "/opt/x/config.xml")
    save_in_editor(local, b"first" * 9)
    connect(p, cb)                          # uploaded by the flush
    connect(p, ca)
    save_in_editor(local, b"second" * 9)
    p._poll_watched_files()
    assert env.asked == []
    assert a.data("/opt/x/config.xml") == b"second" * 9


def test_check_remote_unchanged_unknown_baseline_is_not_a_conflict(sp):
    s = FakeServer("A")
    s.add("/f", b"x")
    sp.check_remote_unchanged(FakeSftp(s), "/f", 0, 0)       # nothing raised
    with pytest.raises(sp.RemoteChangedError):
        sp.check_remote_unchanged(FakeSftp(s), "/f", 999, 1)
    with pytest.raises(sp.RemoteChangedError):
        sp.check_remote_unchanged(FakeSftp(s), "/f", s.mtime, 2)
    sp.check_remote_unchanged(FakeSftp(s), "/f", s.mtime, 1)


def test_downloading_several_files_asks_before_replacing_local_files(
        env, sp, monkeypatch, tmp_path):
    from PyQt6.QtCore import Qt
    from PyQt6.QtWidgets import QTableWidgetItem
    a, _ = servers()
    a.add("/opt/x/other.xml", b"other" * 9)
    p = env.panel()
    connect(p, FakeClient(a))
    p._path = "/opt/x"
    folder = tmp_path / "down"
    folder.mkdir()
    (folder / "config.xml").write_bytes(b"my local file")
    monkeypatch.setattr(sp.QFileDialog, "getExistingDirectory",
                        staticmethod(lambda *a, **k: str(folder)))
    p._table.setRowCount(2)
    for row, name in enumerate(("config.xml", "other.xml")):
        it = QTableWidgetItem(name)
        it.setData(Qt.ItemDataRole.UserRole,
                   (name, False, len(a.data(f"/opt/x/{name}"))))
        p._table.setItem(row, 0, it)
        it.setSelected(True)
    asked = []
    queued = []
    monkeypatch.setattr(p, "_ask_overwrite",
                        lambda paths, where="": asked.append((paths, where)) or "skip")
    monkeypatch.setattr(p, "_enqueue_transfers", queued.extend)

    p._download()

    assert len(asked) == 1 and asked[0][1] == "w wybranym folderze"
    assert [os.path.basename(x) for x in asked[0][0]] == ["config.xml"]
    assert [os.path.basename(q[2]) for q in queued] == ["other.xml"]
    assert (folder / "config.xml").read_bytes() == b"my local file"
