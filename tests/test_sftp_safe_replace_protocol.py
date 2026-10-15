"""G10 — SFTP write safety and compatibility, over the real SFTP protocol.

``upload_edit`` is exercised against a real paramiko SFTP server running in
this process: client and server talk through ``socket.socketpair()`` (no
network, no real server, no production data) and the server keeps its files
in a pytest temp directory.  The files are ordinary XML test files.

What this proves beyond the in-memory fakes of
``test_sftp_edit_collisions.py``: the client really sends ``open`` with
CREATE|EXCL, ``fsetstat``, ``posix-rename@openssh.com`` and gets real SFTP
status codes back; a dropped connection really kills the channel.

What it cannot prove (documented in RELEASE_READINESS_V2.md, G10): POSIX
owner, mode bits and ACLs — the backing store here is Windows NTFS, where
``chmod`` only toggles read-only and there is no ``chown``.  Those rules are
pinned on the fakes.
"""

import os
import socket
import sys
import threading

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

paramiko = pytest.importorskip("paramiko")
from paramiko import (AUTH_SUCCESSFUL, OPEN_SUCCEEDED, SFTP_FAILURE, SFTP_OK,
                      SFTP_OP_UNSUPPORTED, ServerInterface, SFTPAttributes,
                      SFTPHandle, SFTPServer, SFTPServerInterface)


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


@pytest.fixture
def sp(app):
    from ui import ssh_panel
    return ssh_panel


# ══════════════════════════════════════════════════════════════════════════
# An in-process SFTP server over a directory
# ══════════════════════════════════════════════════════════════════════════

class Faults:
    """What the server does wrong, set per test."""

    def __init__(self):
        self.drop_after_bytes = None   # cut the connection mid-write
        self.write_fails_after = None  # SFTP_FAILURE (e.g. disk full)
        self.posix_rename = "ok"       # "ok" | "unsupported" | "denied"
        self.deny_create_in = set()    # directories where open(CREATE) fails
        self.written = 0
        self.ops = []
        self.server_sock = None


class _Handle(SFTPHandle):
    faults: Faults = None

    def write(self, offset, data):
        f = self.faults
        if (f.drop_after_bytes is not None
                and f.written + len(data) > f.drop_after_bytes):
            keep = max(0, f.drop_after_bytes - f.written)
            super().write(offset, data[:keep])
            self.writefile.flush()
            f.written += keep
            f.server_sock.shutdown(socket.SHUT_RDWR)    # the link is gone
            return SFTP_FAILURE
        if (f.write_fails_after is not None
                and f.written + len(data) > f.write_fails_after):
            return SFTP_FAILURE
        f.written += len(data)
        return super().write(offset, data)

    def stat(self):
        return SFTPAttributes.from_stat(os.fstat(self.readfile.fileno()))

    def chattr(self, attr):
        f = self.faults
        f.ops.append(("fsetstat", self.filename, attr.st_mode))
        try:
            SFTPServer.set_file_attr(self.filename, attr)
        except OSError as e:
            return SFTPServer.convert_errno(e.errno)
        return SFTP_OK


def make_server_class(root, faults):
    class _Sftp(SFTPServerInterface):
        def _real(self, path):
            return os.path.join(root, *[p for p in path.split("/") if p])

        def canonicalize(self, path):
            return "/" + "/".join(p for p in path.split("/") if p)

        def stat(self, path):
            try:
                return SFTPAttributes.from_stat(os.stat(self._real(path)))
            except OSError as e:
                return SFTPServer.convert_errno(e.errno)

        lstat = stat

        def open(self, path, flags, attr):
            faults.ops.append(("open", path, flags))
            real = self._real(path)
            if (flags & os.O_CREAT
                    and os.path.dirname(path) in faults.deny_create_in):
                return SFTPServer.convert_errno(13)
            try:
                fd = os.open(real, flags | getattr(os, "O_BINARY", 0), 0o666)
            except OSError as e:
                return SFTPServer.convert_errno(e.errno)
            mode = "wb" if flags & os.O_WRONLY else ("r+b" if flags & os.O_RDWR else "rb")
            h = _Handle(flags)
            h.faults = faults
            h.filename = real
            h.readfile = h.writefile = os.fdopen(fd, mode)
            return h

        def remove(self, path):
            faults.ops.append(("remove", path))
            try:
                os.remove(self._real(path))
            except OSError as e:
                return SFTPServer.convert_errno(e.errno)
            return SFTP_OK

        def posix_rename(self, old, new):
            faults.ops.append(("posix_rename", old, new))
            if faults.posix_rename == "unsupported":
                return SFTP_OP_UNSUPPORTED
            if faults.posix_rename == "denied":
                return SFTPServer.convert_errno(13)
            os.replace(self._real(old), self._real(new))
            return SFTP_OK

        def chattr(self, path, attr):
            faults.ops.append(("setstat", path, attr.st_mode))
            try:
                SFTPServer.set_file_attr(self._real(path), attr)
            except OSError as e:
                return SFTPServer.convert_errno(e.errno)
            return SFTP_OK
    return _Sftp


class _Auth(ServerInterface):
    def check_auth_password(self, username, password):
        return AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return OPEN_SUCCEEDED


@pytest.fixture(scope="module")
def host_key():
    return paramiko.RSAKey.generate(2048)


@pytest.fixture
def server(tmp_path, host_key):
    """A connected SFTP client, the server root and the fault switches."""
    root = tmp_path / "srv"
    (root / "data").mkdir(parents=True)
    faults = Faults()
    s_sock, c_sock = socket.socketpair()
    faults.server_sock = s_sock
    st = paramiko.Transport(s_sock)
    st.add_server_key(host_key)
    st.set_subsystem_handler("sftp", SFTPServer, make_server_class(str(root), faults))
    started = threading.Event()

    def serve():
        st.start_server(server=_Auth())
        started.set()
    threading.Thread(target=serve, daemon=True).start()
    ct = paramiko.Transport(c_sock)
    ct.connect(username="test", password="test")     # no host key check: loopback
    started.wait(5)
    client = paramiko.SFTPClient.from_transport(ct)
    client.get_channel().settimeout(5)
    yield client, root, faults
    for obj in (client, ct, st):
        try:
            obj.close()
        except Exception:
            pass


ORIGINAL = (b'<?xml version="1.0" encoding="UTF-8"?>\n<config>\n'
            + b'  <entry key="k" value="original"/>\n' * 4000 + b'</config>\n')
EDITED = (b'<?xml version="1.0" encoding="UTF-8"?>\n<config>\n'
          + b'  <entry key="k" value="edited"/>\n' * 5000 + b'</config>\n')


@pytest.fixture
def files(server, tmp_path):
    client, root, faults = server
    (root / "data" / "config.xml").write_bytes(ORIGINAL)
    local = tmp_path / "local-config.xml"
    local.write_bytes(EDITED)
    return client, root, faults, str(local)


def leftovers(root):
    return sorted(p.name for p in (root / "data").iterdir() if p.name.endswith(".part"))


# ══════════════════════════════════════════════════════════════════════════
# The existing file is replaced correctly
# ══════════════════════════════════════════════════════════════════════════

def test_an_existing_file_is_replaced_whole(sp, files):
    client, root, faults, local = files
    progress = []
    final = sp.upload_edit(client, local, "/data/config.xml", safe_replace=True,
                           callback=lambda done, total: progress.append(done))
    assert (root / "data" / "config.xml").read_bytes() == EDITED
    assert final.st_size == len(EDITED)
    assert leftovers(root) == []
    assert progress and progress[-1] == len(EDITED)


def test_the_temp_file_is_created_exclusively_and_private_first(sp, files):
    client, root, faults, local = files
    sp.upload_edit(client, local, "/data/config.xml", safe_replace=True)
    opens = [op for op in faults.ops if op[0] == "open"]
    assert len(opens) == 1
    _, tmp, flags = opens[0]
    assert tmp.startswith("/data/.config.xml.hhv2-") and tmp.endswith(".part")
    assert flags & os.O_CREAT and flags & os.O_EXCL, "O_EXCL: nigdy cudzy plik"
    first_chmod = next(op for op in faults.ops if op[0] == "fsetstat")
    assert first_chmod[2] & 0o777 == 0o600
    renames = [op for op in faults.ops if op[0] == "posix_rename"]
    assert renames == [("posix_rename", tmp, "/data/config.xml")]
    assert not any(op[0] == "open" and op[1] == "/data/config.xml" for op in faults.ops), \
        "oryginał nigdy nie jest otwierany do zapisu"


def test_a_leftover_temp_name_is_never_overwritten(sp, files, monkeypatch):
    client, root, faults, local = files
    (root / "data" / ".config.xml.hhv2-fixed.part").write_bytes(b"someone's")
    monkeypatch.setattr(sp, "remote_part_path",
                        lambda target: "/data/.config.xml.hhv2-fixed.part")
    with pytest.raises(sp.SafeReplaceError, match="nie został zmieniony"):
        sp.upload_edit(client, local, "/data/config.xml", safe_replace=True)
    assert (root / "data" / "config.xml").read_bytes() == ORIGINAL


# ══════════════════════════════════════════════════════════════════════════
# A broken transfer does not damage the original
# ══════════════════════════════════════════════════════════════════════════

def test_a_dropped_connection_mid_transfer_keeps_the_original(sp, files):
    client, root, faults, local = files
    faults.drop_after_bytes = 50_000
    left = []
    with pytest.raises(sp.SafeReplaceError, match="nie został zmieniony"):
        sp.upload_edit(client, local, "/data/config.xml", safe_replace=True,
                       leftovers=left)
    assert (root / "data" / "config.xml").read_bytes() == ORIGINAL
    # The channel is dead: the fragment cannot be removed and is reported.
    assert len(left) == 1 and leftovers(root) == [left[0].rsplit("/", 1)[1]]


def test_a_write_error_from_the_server_keeps_the_original(sp, files):
    client, root, faults, local = files
    faults.write_fails_after = 30_000           # e.g. the disk filled up
    with pytest.raises(sp.SafeReplaceError, match="nie został zmieniony"):
        sp.upload_edit(client, local, "/data/config.xml", safe_replace=True)
    assert (root / "data" / "config.xml").read_bytes() == ORIGINAL
    assert leftovers(root) == [], "łącze żyje — fragment usunięty"


def test_a_refused_write_in_the_middle_is_never_masked_by_the_size(sp, files):
    """Found by this suite: the server refuses writes from 30 kB on, but the
    last chunk (at a higher offset) is accepted, so the file reaches the
    right size with a hole.  Pipelined writes hid the refusals; each write
    must be acknowledged."""
    client, root, faults, local = files
    tail = len(EDITED) % 32768 or 32768

    real_write = _Handle.write

    def write(self, offset, data):
        if 30_000 < offset + len(data) and offset < len(EDITED) - tail:
            return SFTP_FAILURE
        return real_write(self, offset, data)
    _Handle.write = write
    try:
        with pytest.raises(sp.SafeReplaceError, match="nie został zmieniony"):
            sp.upload_edit(client, local, "/data/config.xml", safe_replace=True)
    finally:
        _Handle.write = real_write
    assert (root / "data" / "config.xml").read_bytes() == ORIGINAL
    assert leftovers(root) == []


def test_a_cancel_mid_transfer_keeps_the_original(sp, files):
    client, root, faults, local = files

    def cb(done, total):
        if done > 40_000:
            raise sp._CancelledError()
    with pytest.raises(sp._CancelledError):
        sp.upload_edit(client, local, "/data/config.xml", safe_replace=True,
                       callback=cb)
    assert (root / "data" / "config.xml").read_bytes() == ORIGINAL
    assert leftovers(root) == []


# ══════════════════════════════════════════════════════════════════════════
# A failed replace loses nothing, and never falls back
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("mode", ["unsupported", "denied"])
def test_a_refused_rename_keeps_the_original_and_cleans_up(sp, files, mode):
    client, root, faults, local = files
    faults.posix_rename = mode
    with pytest.raises(sp.SafeReplaceError, match="nie został zmieniony"):
        sp.upload_edit(client, local, "/data/config.xml", safe_replace=True)
    assert (root / "data" / "config.xml").read_bytes() == ORIGINAL
    assert leftovers(root) == []
    assert not any(op[0] == "open" and op[1] == "/data/config.xml" for op in faults.ops), \
        "bez powrotu do zapisu bezpośredniego"


def test_no_create_permission_in_the_directory_aborts(sp, files):
    client, root, faults, local = files
    faults.deny_create_in.add("/data")
    with pytest.raises(sp.SafeReplaceError, match="tymczasowego"):
        sp.upload_edit(client, local, "/data/config.xml", safe_replace=True)
    assert (root / "data" / "config.xml").read_bytes() == ORIGINAL
    assert [op for op in faults.ops if op[0] == "open"
            and op[1] == "/data/config.xml"] == []


def test_a_missing_file_is_not_created(sp, files):
    client, root, faults, local = files
    with pytest.raises(sp.SafeReplaceError, match="nie istnieje"):
        sp.upload_edit(client, local, "/data/other.xml", safe_replace=True)
    assert not (root / "data" / "other.xml").exists()


def test_a_directory_is_refused(sp, files):
    client, root, faults, local = files
    (root / "data" / "sub").mkdir()
    with pytest.raises(sp.SafeReplaceError, match="zwykłym plikiem"):
        sp.upload_edit(client, local, "/data/sub", safe_replace=True)


# ══════════════════════════════════════════════════════════════════════════
# The default (flag off) — for comparison
# ══════════════════════════════════════════════════════════════════════════

def test_direct_mode_truncates_the_original_on_a_drop(sp, files):
    """What V2 does while SFTP_SAFE_REPLACE_ENABLED is False — the reason
    the safe mode exists."""
    client, root, faults, local = files
    assert sp.SFTP_SAFE_REPLACE_ENABLED is False
    faults.drop_after_bytes = 50_000
    with pytest.raises(Exception):
        sp.upload_edit(client, local, "/data/config.xml")
    damaged = (root / "data" / "config.xml").read_bytes()
    assert damaged != ORIGINAL and len(damaged) <= 50_000


def test_direct_mode_replaces_in_place_when_nothing_fails(sp, files):
    client, root, faults, local = files
    sp.upload_edit(client, local, "/data/config.xml")
    assert (root / "data" / "config.xml").read_bytes() == EDITED
    assert [op[1] for op in faults.ops if op[0] == "open"] == ["/data/config.xml"]


def test_direct_mode_can_hide_a_refused_write_behind_the_right_size(sp, files):
    """Known limit of the default path (paramiko ``put`` writes pipelined and
    only compares sizes): a write refused in the middle followed by an
    accepted last chunk is NOT reported and leaves a damaged file.  Pinned
    here so a change to the default is a decision, not an accident."""
    client, root, faults, local = files
    tail = len(EDITED) % 32768 or 32768
    real_write = _Handle.write

    def write(self, offset, data):
        if 30_000 < offset + len(data) and offset < len(EDITED) - tail:
            return SFTP_FAILURE
        return real_write(self, offset, data)
    _Handle.write = write
    try:
        sp.upload_edit(client, local, "/data/config.xml")      # no error raised
    finally:
        _Handle.write = real_write
    damaged = (root / "data" / "config.xml").read_bytes()
    assert len(damaged) == len(EDITED) and damaged != EDITED
