"""SSH/SFTP safety fixes (2026-10-14, audit C1) — on fakes, no network.

* C1-01/C1-02 — a file opened from SFTP gets a local copy that belongs to one
  panel and one (server, remote path); two windows, two servers or two
  directories never share it, so the edit watcher of one can never upload the
  other's content.
* C1-06 — a remote file name is not trusted as a Windows path when several
  files are downloaded into a folder.
* C1-05 — closing a tab while it is still logging in leaves no shell open.
* C1-17 — closing a tab wakes a login prompt waiting for typed input.
* C1-03 — a connection's watched files survive a tab switch.
* C1-04 — edits still in temp are pushed before the session's SFTP is closed.
"""

import os
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
# C1-01 / C1-02 — local copies are never shared
# ══════════════════════════════════════════════════════════════════════════

def test_c101_two_servers_never_share_a_local_copy(sp):
    a = sp.sftp_temp_path("P", "10.0.0.1:22", "/etc/app/config.xml", "config.xml")
    b = sp.sftp_temp_path("P", "10.0.0.2:22", "/etc/app/config.xml", "config.xml")
    assert a != b
    assert os.path.basename(a) == os.path.basename(b) == "config.xml"


def test_c101_two_windows_never_share_a_local_copy(sp, app):
    first, second = sp.SftpPanel(), sp.SftpPanel()
    try:
        assert first.temp_dir() != second.temp_dir()
        assert os.path.dirname(first.temp_dir()) == sp.sftp_temp_root()
    finally:
        first.deleteLater()
        second.deleteLater()


def test_c102_two_directories_of_one_server_never_share_a_local_copy(sp):
    a = sp.sftp_temp_path("P", "h:22", "/a/config.xml", "config.xml")
    b = sp.sftp_temp_path("P", "h:22", "/b/config.xml", "config.xml")
    assert a != b


def test_c101_the_same_file_reopened_reuses_its_copy(sp):
    assert (sp.sftp_temp_path("P", "h:22", "/a/x.txt", "x.txt")
            == sp.sftp_temp_path("P", "h:22", "/a/x.txt", "x.txt"))


@pytest.mark.parametrize("name", ["..\\..\\evil.bat", "C:\\x", "", None])
def test_c101_a_copy_always_stays_inside_the_panel_directory(sp, name):
    path = sp.sftp_temp_path(os.path.join("T", "p1"), "h:22", "/r", name)
    assert os.path.commonpath([os.path.abspath(path),
                               os.path.abspath(os.path.join("T", "p1"))]) \
        == os.path.abspath(os.path.join("T", "p1"))


def test_c101_closing_a_window_removes_only_its_own_directory(sp):
    src = open(sp.__file__, encoding="utf-8").read()
    body = src[src.index("    def closeEvent(self, event):"):]
    body = body[:body.index("super().closeEvent(event)")]
    assert "tmp_dir = self._sftp_panel.temp_dir()" in body
    assert "HospitalHubV2_" not in body


# ══════════════════════════════════════════════════════════════════════════
# C1-06 — remote names as Windows file names
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("name", [
    "..\\..\\AppData\\Roaming\\Startup\\x.bat", "C:\\Windows\\x.dll", "x:y",
    "a/b", "..", ".", "CON", "con.txt", "LPT1", "trailing.", "trailing ",
    "", "bad\x01name", "a" * 256, "q?", "s*", "p|q", "<x>", 'quo"te'])
def test_c106_unsafe_remote_names_are_refused(sp, name):
    assert sp.safe_local_name(name) is None


@pytest.mark.parametrize("name", [
    "config.xml", "HL7_20261014.dat", "zażółć.txt", ".bashrc", "a b.log",
    "CONSOLE.txt", "x" * 255])
def test_c106_ordinary_names_pass_unchanged(sp, name):
    assert sp.safe_local_name(name) == name


# ══════════════════════════════════════════════════════════════════════════
# C1-05 / C1-17 — closing a tab during login
# ══════════════════════════════════════════════════════════════════════════

class FakeClient:
    def __init__(self):
        self.closed = False
        self.sessions = 0

    def get_transport(self):
        client = self

        class T:
            def open_session(self):
                client.sessions += 1
                raise AssertionError("powloka nie moze zostac otwarta")
        return T()

    def close(self):
        self.closed = True


def test_c105_stop_during_login_opens_no_shell_and_closes_the_client(sp, app,
                                                                     monkeypatch):
    worker = sp._SshWorker("10.0.0.1", "user", "secret")
    client = FakeClient()

    def make_client(host, user, password, port=22):
        worker.stop()                  # the tab is closed while logging in
        return client
    monkeypatch.setattr(sp, "_make_client", make_client)
    connected = []
    worker.connected.connect(lambda: connected.append(True))

    worker.run()                       # synchronously, in this thread

    assert client.sessions == 0, "brak open_session po stop()"
    assert client.closed
    assert connected == [] and worker._running is False


def test_c117_stop_wakes_a_login_prompt_at_once(sp, app):
    worker = sp._SshWorker("10.0.0.1", "", "")
    worker.stop()
    assert worker._read_interactive_line(echo=False) == ""


def test_c117_a_prompt_still_reads_typed_input(sp, app):
    worker = sp._SshWorker("10.0.0.1", "", "")
    worker._send_q.put(b"admin\r")
    assert worker._read_interactive_line(echo=True) == "admin"


# ══════════════════════════════════════════════════════════════════════════
# C1-03 — watched files across a tab switch
# ══════════════════════════════════════════════════════════════════════════

class Client:
    """Stands in for a paramiko SSHClient (weak-referenceable, like it)."""

    closed = False

    def close(self):
        self.closed = True


def fake_panel(sp, client):
    events = []
    btn = SimpleNamespace(setEnabled=lambda on: None)
    panel = SimpleNamespace(
        _flush_pending_edits=lambda final=False: events.append("flush"),
        _watch_poll=SimpleNamespace(stop=lambda: events.append("poll-stop"),
                                    start=lambda: events.append("poll-start")),
        _watched_files={}, _upload_active=set(), _download_active=set(),
        _watch_store={},
        _sftp=object(), _ssh_client=client, _history=[], _listing_active=False,
        _btn_up=btn, _btn_home=btn, _btn_ref=btn, _btn_mkdir=btn, _btn_ul=btn,
        _listing_gen=0,
        _list=lambda path: events.append(("list", path)),
        _path_lbl=SimpleNamespace(setText=lambda t: None),
        _table=SimpleNamespace(setRowCount=lambda n: None),
        _update_history_menu=lambda: None)
    for name in ("_remember_watches", "_recall_watches", "bound_to",
                 "forget_connection", "rebind_connection"):
        method = getattr(sp.SftpPanel, name)
        setattr(panel, name, lambda *a, _m=method: _m(panel, *a))
    return panel, events


def switch(sp, panel, client):
    sp.SftpPanel.switch_sftp(panel, object() if client else None, client, "/")


def test_c103_a_tab_switch_keeps_and_restores_each_connections_watches(sp):
    a, b = Client(), Client()
    panel, events = fake_panel(sp, a)
    panel._watched_files = {"local-a": {"remote": "/x"}}

    switch(sp, panel, b)
    assert panel._watched_files == {}, "zakladka B ma wlasne"
    assert events[0] == "flush", "edycje A wyslane przed przelaczeniem"

    switch(sp, panel, a)
    assert panel._watched_files == {"local-a": {"remote": "/x"}}
    assert "poll-start" in events, "obserwacja A wznowiona"


def test_c103_a_closed_session_forgets_its_watches(sp):
    a = Client()
    panel, _ = fake_panel(sp, Client())
    panel._remember_watches(a, {"x": {}})
    panel.forget_connection(a)
    assert panel._watch_store == {}


def test_s1_closing_the_active_tab_leaves_nothing_to_inherit(sp):
    """Review 66/S1: closing the active tab used to store its watches again
    (the tab change came after the forget), under a bare id()."""
    a = Client()
    panel, _ = fake_panel(sp, a)
    panel._watched_files = {"local-a": {"remote": "/etc/app.conf"}}
    panel.forget_connection(a)          # _close_session, before removeTab
    switch(sp, panel, None)             # the tab change that follows
    assert panel._watch_store == {} and panel._watched_files == {}


def test_s1_a_new_client_that_reuses_a_dead_ones_id_inherits_nothing(sp):
    """An id() is reused once its object is freed.  Forge exactly that: an
    entry under the new client's id whose weak reference is dead."""
    new = Client()
    panel, events = fake_panel(sp, Client())

    dead = Client()
    import weakref
    dead_ref = weakref.ref(dead)
    del dead
    assert dead_ref() is None
    panel._watch_store[id(new)] = (dead_ref, {"local-x": {"remote": "/etc/x"}})

    switch(sp, panel, new)
    assert panel._watched_files == {}, "obce wpisy nie wracaja"
    assert "poll-start" not in events


def test_s1_an_entry_for_a_different_live_object_is_not_restored(sp):
    new, other = Client(), Client()
    panel, _ = fake_panel(sp, Client())
    import weakref
    panel._watch_store[id(new)] = (weakref.ref(other), {"local-x": {}})
    switch(sp, panel, new)
    assert panel._watched_files == {}


def test_s1_a_reconnect_moves_the_watches_off_the_old_client(sp):
    """2026-10-16 (UX audit S-01): the reconnect of one session rebinds its
    watches to the new client instead of dropping them; nothing stays keyed
    by the old client's id (review 66/S1)."""
    old, new = Client(), Client()
    rebound = []
    session = SimpleNamespace(sftp=object(), sftp_client=old, sftp_path="/",
                              sftp_history=[])
    dialog = SimpleNamespace(
        _sessions=[session],
        _sftp_panel=SimpleNamespace(
            rebind_connection=lambda o, n: rebound.append((o, n)),
            switch_sftp=lambda *a, **k: None),
        _active_session=lambda: None)
    sp.SshDialog._on_sftp_ready(dialog, session, Client(), new)
    assert rebound == [(old, new)] and session.sftp_client is new
    assert old.closed, "stare polaczenie zamkniete (C1-08)"
    assert not new.closed


def test_c108_sftp_ready_for_a_closed_tab_closes_the_connection(sp):
    session = SimpleNamespace(sftp=None, sftp_client=None)
    sftp, client = Client(), Client()
    dialog = SimpleNamespace(_sessions=[], _sftp_panel=None,
                             _active_session=lambda: None)
    sp.SshDialog._on_sftp_ready(dialog, session, sftp, client)
    assert sftp.closed and client.closed
    assert session.sftp_client is None


def test_s1_an_unreferenceable_client_is_simply_not_kept(sp):
    panel, _ = fake_panel(sp, Client())
    panel._remember_watches(object(), {"x": {}})    # object(): no weakref
    assert panel._watch_store == {}


# ══════════════════════════════════════════════════════════════════════════
# C1-04 — flush before the session's SFTP is closed
# ══════════════════════════════════════════════════════════════════════════

def test_c104_closing_a_tab_flushes_its_edits_before_the_teardown(sp):
    order = []
    sftp_client = object()
    session = SimpleNamespace(
        sftp_client=sftp_client,
        worker=SimpleNamespace(stop=lambda: order.append("worker-stop"),
                               wait=lambda ms: None),
        pane=SimpleNamespace(setParent=lambda p: None, deleteLater=lambda: None))
    panel = SimpleNamespace(
        bound_to=lambda c: c is sftp_client,
        _flush_pending_edits=lambda final=False: order.append("flush"),
        forget_connection=lambda c: order.append("forget"))
    dialog = SimpleNamespace(
        _sessions=[session], _sftp_panel=panel, _multiexec=False,
        _tab_widget=SimpleNamespace(removeTab=lambda i: None),
        _teardown_session=lambda s: order.append("teardown"))
    sp.SshDialog._close_session(dialog, 0)
    assert order.index("flush") < order.index("worker-stop") < order.index("teardown")


def test_c104_closing_the_window_stops_the_sftp_panel_first(sp):
    src = open(sp.__file__, encoding="utf-8").read()
    body = src[src.index("    def closeEvent(self, event):"):]
    assert body.index("self._sftp_panel.stop()") < body.index("s.worker.stop()")


# ══════════════════════════════════════════════════════════════════════════
# Review 67/S2 and N1
# ══════════════════════════════════════════════════════════════════════════

def watch_panel(sp, client):
    panel, events = fake_panel(sp, client)
    panel._watch_poll.isActive = lambda: False
    panel._watch_for_other = lambda *a: sp.SftpPanel._watch_for_other(panel, *a)
    return panel, events


def test_s2_a_download_finished_after_a_tab_switch_stays_with_its_connection(sp, tmp_path):
    """The file came through A; the user switched to B before the download
    ended.  It must be watched for A, never uploaded through B."""
    a, b = Client(), Client()
    panel, events = watch_panel(sp, b)          # panel already on B
    local = str(tmp_path / "config.xml")
    sp.SftpPanel._watch_file(panel, local, "/etc/config.xml", 10, False, 0, 0, a)

    assert local not in panel._watched_files, "nie trafia do obserwacji B"
    assert "poll-start" not in events
    switch(sp, panel, a)                        # back to A
    assert local in panel._watched_files


def test_s2_the_active_connections_download_is_watched_as_before(sp, tmp_path):
    a = Client()
    panel, events = watch_panel(sp, a)
    local = str(tmp_path / "x.txt")
    sp.SftpPanel._watch_file(panel, local, "/x.txt", 1, False, 0, 0, a)
    assert local in panel._watched_files and "poll-start" in events


def test_n1_forgetting_the_bound_connection_unbinds_the_panel(sp):
    a = Client()
    panel, _ = fake_panel(sp, a)
    enabled = []
    btn = SimpleNamespace(setEnabled=enabled.append)
    panel.__dict__.update(_btn_up=btn, _btn_home=btn, _btn_ref=btn,
                          _btn_mkdir=btn, _btn_ul=btn)
    panel.forget_connection(a)
    assert panel._sftp is None and panel._ssh_client is None
    assert enabled == [False] * 5


def test_s3_two_connections_to_one_address_never_share_a_copy(sp):
    """Review 67/S3: two tabs to one ip:port (two accounts, a load-balanced
    VIP, a bastion) shared one local copy; a watch of one then uploaded
    what the other had downloaded."""
    a, b = Client(), Client()
    panel_dir = "P"
    pa = sp.sftp_temp_path(panel_dir, sp.connection_token(a), "/etc/x.conf", "x.conf")
    pb = sp.sftp_temp_path(panel_dir, sp.connection_token(b), "/etc/x.conf", "x.conf")
    assert pa != pb
    assert sp.connection_token(a) == sp.connection_token(a), "stabilny dla klienta"


def test_s3_a_token_is_never_handed_out_twice(sp):
    seen = set()
    for _ in range(200):
        c = Client()
        token = sp.connection_token(c)
        assert token not in seen
        seen.add(token)
        del c                       # freed: a new object may reuse its id()


# ══════════════════════════════════════════════════════════════════════════
# C1-09 — host key verification (TOFU)
# ══════════════════════════════════════════════════════════════════════════

class Key:
    def __init__(self, kind, blob):
        self._kind, self._blob = kind, blob

    def get_name(self):
        return self._kind

    def asbytes(self):
        return self._blob


class Prompt:
    def __init__(self, first=True, changed=False):
        self.first, self.changed, self.asked = first, changed, []

    def ask_first(self, host, kind, fp):
        self.asked.append(("first", host, kind))
        return self.first

    def ask_changed(self, host, kind, old, new):
        self.asked.append(("changed", host, kind))
        return self.changed


@pytest.fixture
def tofu(sp, monkeypatch, tmp_path):
    policy = sp._TofuHostKeyPolicy
    monkeypatch.setattr(policy, "_KEYS_FILE", str(tmp_path / "known_hosts"))
    monkeypatch.setattr(policy, "_cache", None)
    prompt = {"p": Prompt()}
    monkeypatch.setattr(sp, "_get_host_key_prompt", lambda: prompt["p"])
    return sp, policy, prompt, tmp_path


def test_c109_a_known_host_with_a_new_key_type_is_a_changed_key(tofu):
    sp, policy, prompt, _ = tofu
    policy().missing_host_key(None, "srv", Key("ssh-ed25519", b"ED"))
    prompt["p"] = Prompt(changed=False)
    with pytest.raises(sp.paramiko.BadHostKeyException):
        policy().missing_host_key(None, "srv", Key("ssh-rsa", b"RSA-MITM"))
    assert prompt["p"].asked == [("changed", "srv", "ssh-rsa")], \
        "ostrzezenie o zmianie, nie okno pierwszego polaczenia"


def test_c109_without_a_gui_a_new_key_type_is_refused(tofu, monkeypatch):
    sp, policy, prompt, _ = tofu
    policy().missing_host_key(None, "srv", Key("ssh-ed25519", b"ED"))
    monkeypatch.setattr(sp, "_get_host_key_prompt", lambda: None)
    with pytest.raises(sp.paramiko.BadHostKeyException):
        policy().missing_host_key(None, "srv", Key("ssh-rsa", b"RSA"))


def test_c109_the_same_key_passes_silently_and_a_rotation_can_be_accepted(tofu):
    sp, policy, prompt, _ = tofu
    policy().missing_host_key(None, "srv", Key("ssh-ed25519", b"ED"))
    prompt["p"] = Prompt()
    policy().missing_host_key(None, "srv", Key("ssh-ed25519", b"ED"))
    assert prompt["p"].asked == []
    prompt["p"] = Prompt(changed=True)
    policy().missing_host_key(None, "srv", Key("ssh-ed25519", b"ED-NEW"))
    assert prompt["p"].asked == [("changed", "srv", "ssh-ed25519")]


def test_c109_a_damaged_file_is_set_aside_not_overwritten(tofu):
    sp, policy, prompt, tmp_path = tofu
    keys = tmp_path / "known_hosts"
    keys.write_text("{damaged", encoding="utf-8")
    policy().missing_host_key(None, "srv", Key("ssh-ed25519", b"ED"))
    aside = list(tmp_path.glob("known_hosts.corrupt-*"))
    assert len(aside) == 1 and aside[0].read_text(encoding="utf-8") == "{damaged"
    import json
    assert "srv" in json.loads(keys.read_text(encoding="utf-8"))
    assert not list(tmp_path.glob("*.tmp"))


# ══════════════════════════════════════════════════════════════════════════
# C1-07 — cancelling deletes only what the transfer created
# C1-12 — the write probe never opens the file for writing
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("mode,uid,gid,identity,expected", [
    (0o100644, 1000, 1000, (1000, {1000}), True),     # owner rw
    (0o100444, 1000, 1000, (1000, {1000}), False),    # nobody writes
    (0o100644, 0, 0, (1000, {1000}), False),          # root's file, other r
    (0o100664, 0, 50, (1000, {50}), True),            # group writable, in group
    (0o100664, 0, 50, (1000, {51}), False),
    (0o100666, 0, 0, (1000, set()), True),            # world writable
    (0o100644, 5, 5, (0, {0}), True),                 # root writes anything
    (0o100644, 5, 5, None, True),                     # identity unknown
    (None, 5, 5, (1000, set()), True),                # mode unknown
])
def test_c112_mode_allows_write(sp, mode, uid, gid, identity, expected):
    assert sp.mode_allows_write(mode, uid, gid, identity) is expected


def test_c112_the_probe_never_opens_the_file(sp):
    class Sftp:
        def stat(self, path):
            return SimpleNamespace(st_mode=0o100644, st_uid=1000, st_gid=1000)

        def open(self, *a, **k):
            raise AssertionError("open() wyzwala IN_CLOSE_WRITE na serwerze")

    class Out:
        def read(self):
            return b"1000\n1000 4\n"

    calls = []

    class Ssh:
        def exec_command(self, cmd, timeout=None):
            calls.append(cmd)
            return None, Out(), None

    client = Ssh()
    panel = SimpleNamespace(_sftp=Sftp(), _ssh_client=client, _identity_cache={})
    panel._remote_identity = lambda: sp.SftpPanel._remote_identity(panel)
    assert sp.SftpPanel._probe_writable(panel, "/hl7/in/msg.dat") is True
    assert sp.SftpPanel._probe_writable(panel, "/hl7/in/msg2.dat") is True
    assert calls == ["id -u; id -G"], "id raz na polaczenie"


def transfer_panel(sp, remote_exists):
    emitted = []
    panel = SimpleNamespace(
        _transfer_queue=[], _transfer_finished_cleanup=lambda: None,
        _sftp=SimpleNamespace(remove=lambda p: emitted.append(("remove", p))),
        _path="/", _list=lambda p: None,
        status_msg=SimpleNamespace(emit=lambda m, err: emitted.append((m, err))))
    return panel, emitted


def test_c107_cancelling_an_overwrite_keeps_the_server_file_and_warns(sp):
    panel, emitted = transfer_panel(sp, True)
    sp.SftpPanel._transfer_cancelled(panel, None, remote_partial=None,
                                     overwritten="/etc/app.conf")
    assert not [e for e in emitted if e[0] == "remove"]
    assert any("app.conf" in str(e[0]) and e[1] is True for e in emitted)
    assert not any(e[0] == "Transfer anulowany" for e in emitted)


def test_c107_cancelling_a_new_upload_still_removes_the_fragment(sp):
    panel, emitted = transfer_panel(sp, False)
    sp.SftpPanel._transfer_cancelled(panel, None, remote_partial="/tmp/new.bin")
    assert ("remove", "/tmp/new.bin") in emitted


def test_c107_existence_is_checked_before_the_transfer_starts(sp):
    src = open(sp.__file__, encoding="utf-8").read()
    body = src[src.index("    def _start_single_transfer"):]
    body = body[:body.index("w.start()")]
    assert body.index("target_existed") < body.index("_TransferWorker(")
    assert "not target_existed" in body


def test_c107_unknown_existence_counts_as_existing(sp):
    class Sftp:
        def stat(self, p):
            raise OSError("connection lost")
    panel = SimpleNamespace(_sftp=Sftp())
    assert sp.SftpPanel._remote_exists(panel, "/x") is True
    missing = IOError(2, "No such file")
    class Missing:
        def stat(self, p):
            raise missing
    assert sp.SftpPanel._remote_exists(SimpleNamespace(_sftp=Missing()), "/x") is False


# ══════════════════════════════════════════════════════════════════════════
# C1-10 — a late listing of the previous connection is dropped
# ══════════════════════════════════════════════════════════════════════════

def test_c110_a_listing_older_than_a_switch_is_ignored(sp):
    panel, events = fake_panel(sp, Client())
    panel._listing_gen = 4                     # the listing in flight was #4
    sp.SftpPanel.switch_sftp(panel, object(), Client(), "/")
    assert panel._listing_gen == 5
    panel._path = "/b"
    sp.SftpPanel._on_listing(panel, "/srv-a/data", [("x", False, 1, "", "")], 4)
    assert panel._path == "/b", "sciezka serwera A nie trafia do panelu B"
    sp.SftpPanel._on_listing_error(panel, "boom", 4)    # also ignored, no error


def test_c110_the_current_listing_is_applied(sp):
    src = open(sp.__file__, encoding="utf-8").read()
    body = src[src.index("    def _list(self, path: str):"):]
    body = body[:body.index("w.start()")]
    assert "self._listing_gen += 1" in body
    assert "g=gen" in body


# ══════════════════════════════════════════════════════════════════════════
# C1-11 — bounded SFTP channels for the UI thread
# ══════════════════════════════════════════════════════════════════════════

def test_c111_the_ui_channel_has_a_timeout_on_open_and_on_replies(sp, monkeypatch):
    seen = {}

    class Channel:
        def settimeout(self, t):
            seen["settimeout"] = t

        def invoke_subsystem(self, name):
            seen["subsystem"] = name

    class Transport:
        def is_active(self):
            return True

        def open_session(self, timeout=None):
            seen["open_timeout"] = timeout
            return Channel()

    client = SimpleNamespace(get_transport=lambda: Transport())
    monkeypatch.setattr(sp.paramiko, "SFTPClient", lambda ch: ("sftp", ch))
    result = sp.open_sftp_bounded(client, timeout=7)
    assert result[0] == "sftp"
    assert seen == {"open_timeout": 7, "settimeout": 7, "subsystem": "sftp"}


def test_c111_a_closed_connection_fails_fast(sp):
    dead = SimpleNamespace(get_transport=lambda: SimpleNamespace(is_active=lambda: False))
    with pytest.raises(sp.paramiko.SSHException):
        sp.open_sftp_bounded(dead)
    with pytest.raises(sp.paramiko.SSHException):
        sp.open_sftp_bounded(SimpleNamespace(get_transport=lambda: None))


# ══════════════════════════════════════════════════════════════════════════
# Review 68
# ══════════════════════════════════════════════════════════════════════════

def test_r68_a_cancel_after_a_tab_switch_deletes_nothing_on_the_other_server(sp):
    a, b = Client(), Client()
    removed, msgs = [], []
    panel = SimpleNamespace(
        _transfer_queue=[], _transfer_finished_cleanup=lambda: None,
        _ssh_client=b, _sftp=SimpleNamespace(remove=removed.append),
        _path="/", _list=lambda p: None,
        status_msg=SimpleNamespace(emit=lambda m, err: msgs.append((m, err))))
    panel.bound_to = lambda c: sp.SftpPanel.bound_to(panel, c)
    sp.SftpPanel._transfer_cancelled(panel, None, remote_partial="/srv/new.bin",
                                     owner=a)
    assert removed == [], "nic nie usunięte przez połączenie B"
    assert any("usuń go ręcznie" in m and err for m, err in msgs)


def test_r68_a_cancel_on_the_same_connection_still_cleans_up(sp):
    a = Client()
    removed = []
    panel = SimpleNamespace(
        _transfer_queue=[], _transfer_finished_cleanup=lambda: None,
        _ssh_client=a, _sftp=SimpleNamespace(remove=removed.append),
        _path="/", _list=lambda p: None,
        status_msg=SimpleNamespace(emit=lambda m, err: None))
    panel.bound_to = lambda c: sp.SftpPanel.bound_to(panel, c)
    sp.SftpPanel._transfer_cancelled(panel, None, remote_partial="/srv/new.bin",
                                     owner=a)
    assert removed == ["/srv/new.bin"]


def test_r68_an_unreadable_known_hosts_file_is_not_wiped(tofu, monkeypatch):
    sp, policy, prompt, tmp_path = tofu
    keys = tmp_path / "known_hosts"
    keys.write_text('{"srv": {"ssh-ed25519": "aa"}}', encoding="utf-8")
    real_open = open

    def locked(path, *a, **k):
        if str(path) == str(keys) and (not a or "r" in a[0]):
            raise PermissionError("locked by antivirus")
        return real_open(path, *a, **k)
    monkeypatch.setattr("builtins.open", locked)
    with pytest.raises(sp.paramiko.SSHException):
        policy().missing_host_key(None, "other", Key("ssh-ed25519", b"X"))
    monkeypatch.undo()
    assert '"srv"' in keys.read_text(encoding="utf-8"), "klucze nietknięte"
    assert not list(tmp_path.glob("known_hosts.corrupt-*"))


def test_r68_root_may_write_a_read_only_file(sp):
    assert sp.mode_allows_write(0o100444, 5, 5, (0, {0})) is True
    assert sp.mode_allows_write(0o100444, 5, 5, (1000, {1000})) is False


# ══════════════════════════════════════════════════════════════════════════
# C1-14 / C1-15
# ══════════════════════════════════════════════════════════════════════════

class FakeTransport:
    instances = []

    def __init__(self, sock):
        self.closed = False
        FakeTransport.instances.append(self)

    def start_client(self):
        pass

    def get_remote_server_key(self):
        return Key("ssh-ed25519", b"K")

    def auth_interactive(self, user, handler):
        raise sp_module().paramiko.AuthenticationException("bad")

    def close(self):
        self.closed = True


def sp_module():
    from ui import ssh_panel
    return ssh_panel


@pytest.fixture
def kbd(sp, monkeypatch):
    FakeTransport.instances = []
    seen = []

    class Policy:
        def missing_host_key(self, client, name, key):
            seen.append(name)

    class Client2:
        def set_missing_host_key_policy(self, p):
            pass

        def connect(self, **kw):
            raise sp.paramiko.ssh_exception.AuthenticationException("pw rejected")

        def close(self):
            pass

    import socket
    monkeypatch.setattr(socket, "create_connection", lambda addr, timeout=None: object())
    monkeypatch.setattr(sp.paramiko, "Transport", FakeTransport)
    monkeypatch.setattr(sp.paramiko, "SSHClient", Client2)
    monkeypatch.setattr(sp, "_TofuHostKeyPolicy", Policy)
    return seen


def test_c114_a_failed_keyboard_interactive_login_closes_the_transport(sp, kbd):
    with pytest.raises(sp.paramiko.AuthenticationException):
        sp._make_client("10.0.0.1", "u", "zle-haslo", 2222)
    assert FakeTransport.instances and FakeTransport.instances[0].closed


def test_c114_the_host_key_name_matches_paramikos(sp, kbd):
    with pytest.raises(sp.paramiko.AuthenticationException):
        sp._make_client("10.0.0.1", "u", "x", 2222)
    with pytest.raises(sp.paramiko.AuthenticationException):
        sp._make_client("10.0.0.1", "u", "x", 22)
    assert kbd == ["[10.0.0.1]:2222", "10.0.0.1"]


@pytest.mark.parametrize("ext", [".py", ".lnk", ".url", ".chm", ".xlsm",
                                 ".settingcontent-ms", ".appref-ms"])
def test_c115_more_executable_extensions_are_flagged(sp, ext):
    assert ext in sp.SftpPanel._DANGEROUS_EXT


def test_s1_a_rebind_leaves_nothing_under_the_old_id(sp):
    old, new = Client(), Client()
    panel, _ = fake_panel(sp, old)
    panel._remember_watches(old, {"x": {"owner": None}})
    panel.rebind_connection(old, new)
    assert id(old) not in panel._watch_store
    ref, files = panel._watch_store[id(new)]
    assert ref() is new and files["x"]["owner"]() is new
