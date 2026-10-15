"""G8 (decision 2026-10-15): X11 forwarding stays ON by default — on fakes.

Pins what the SSH terminal did before the decision, so a later change cannot
switch it off by accident:

* every shell session asks for X11 (``request_x11``) before the PTY and the
  shell, on the same channel, with the Xming proxy handler;
* a server that refuses X11 still gets a working shell on a fresh channel;
* the X11 handler proxies to the local X server and closes the channel when
  none is running.

There is no per-connection switch in V2 today (nothing in the connection
model or dialog) — a session cannot opt out; adding one is a separate change.
"""

import os
import sys

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


class Channel:
    def __init__(self, log, n, refuse_x11=False):
        self.log, self.n, self.refuse_x11 = log, n, refuse_x11
        self.closed = False

    def request_x11(self, screen_number=None, single_connection=None,
                    handler=None, **kw):
        self.log.append(("x11", self.n, screen_number, single_connection, handler))
        if self.refuse_x11:
            raise Exception("X11 forwarding request denied")

    def get_pty(self, term=None, width=None, height=None):
        self.log.append(("pty", self.n, term))

    def invoke_shell(self):
        self.log.append(("shell", self.n))

    def recv_ready(self):
        return False

    def exit_status_ready(self):
        return True                 # the shell ends at once: run() returns

    def close(self):
        self.closed = True


class Client:
    def __init__(self, refuse_x11=False):
        self.log, self.refuse_x11, self.sessions = [], refuse_x11, []

    def get_transport(self):
        client = self

        class T:
            def open_session(self, *a, **k):
                ch = Channel(client.log, len(client.sessions),
                             refuse_x11=client.refuse_x11 and not client.sessions)
                client.sessions.append(ch)
                return ch

            def is_active(self):
                return True
        return T()

    def close(self):
        pass


def run_worker(sp, monkeypatch, client):
    worker = sp._SshWorker("10.0.0.1", "user", "secret")
    monkeypatch.setattr(sp, "_make_client", lambda *a, **k: client)
    connected, errors = [], []
    worker.connected.connect(lambda: connected.append(True))
    worker.error.connect(errors.append)
    worker.run()                    # synchronously, in this thread
    return connected, errors


def test_g8_every_shell_asks_for_x11_first(sp, monkeypatch):
    client = Client()
    connected, errors = run_worker(sp, monkeypatch, client)

    assert errors == [] and connected == [True]
    assert [e[0] for e in client.log] == ["x11", "pty", "shell"]
    _, n, screen, single, handler = client.log[0]
    assert (n, screen, single) == (0, 0, False)
    assert handler is sp._x11_handler
    assert {e[1] for e in client.log} == {0}, "X11, PTY i powłoka na jednym kanale"


def test_g8_a_server_that_refuses_x11_still_gets_a_shell(sp, monkeypatch):
    client = Client(refuse_x11=True)
    connected, errors = run_worker(sp, monkeypatch, client)

    assert errors == [] and connected == [True]
    assert [e[:2] for e in client.log] == [("x11", 0), ("pty", 1), ("shell", 1)]


def test_g8_no_local_x_server_closes_the_x11_channel(sp, monkeypatch):
    import socket

    class NoServer:
        def __init__(self, *a, **k):
            pass

        def connect(self, addr):
            assert addr == ("localhost", 6000)
            raise ConnectionRefusedError(10061, "refused")

    monkeypatch.setattr(socket, "socket", NoServer)
    ch = Channel([], 0)
    sp._x11_handler(ch, ("127.0.0.1", 6010))
    assert ch.closed
