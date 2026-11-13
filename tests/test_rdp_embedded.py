"""2026-11-13: RDP as a tab of the terminal window, with "Wsparcie Claude".

The owner: "RDP should open inside, in the terminal window, so I can switch
Wsparcie Claude on for such a session — with a choice: a separate window or
the terminal".  The Remote Desktop control itself is never created here
(it would connect); these tests pin the pure helpers, the screenshot mode of
the support panel, the default setting and that the SSH-only paths of the
window leave RDP tabs alone.
"""

import ast
import os
import sys
import threading
import types

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import claude_support as cs  # noqa: E402


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


# ══════════════════════════════════════════════════════════════════════════
# Pure helpers
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("login,expected", [
    ("SZPITAL\\jan", ("jan", "SZPITAL")),
    ("jan", ("jan", "")),
    ("jan@szpital.local", ("jan@szpital.local", "")),
    ("  ", ("", "")),
    ("\\jan", ("\\jan", "")),
])
def test_split_login(login, expected):
    from ui.rdp_embedded import split_login
    assert split_login(login) == expected


def test_only_the_chosen_drives_are_redirected():
    from ui.rdp_embedded import drives_to_redirect
    available = ["C:\\", "D:\\", "E:\\"]
    assert drives_to_redirect(["d:"], available) == ["D:\\"]
    assert drives_to_redirect([], available) == []
    # A vault edited by hand: nothing but one letter and a colon counts.
    assert drives_to_redirect(["C:\\;D:", "E", 5, None], available) == []


def test_disconnect_text():
    from ui.rdp_embedded import disconnect_text
    assert disconnect_text(1) == "Sesja RDP zakończona."
    assert disconnect_text(3, "x") == "Sesja RDP zakończona."
    assert disconnect_text(516, "Nie można połączyć") == "Rozłączono: Nie można połączyć"
    assert disconnect_text(516) == "Rozłączono (kod 516)."


def test_a_blank_capture_is_recognised(app):
    from PyQt6.QtGui import QColor, QImage
    from ui.rdp_embedded import is_blank
    img = QImage(200, 100, QImage.Format.Format_RGB32)
    img.fill(QColor("black"))
    assert is_blank(img)
    from PyQt6.QtGui import QPainter
    p = QPainter(img)
    p.fillRect(90, 40, 20, 20, QColor("white"))      # a window on the desktop
    p.end()
    assert not is_blank(img)
    assert is_blank(None)


def test_the_control_is_loaded_only_when_a_tab_opens():
    """Importing the module must not touch comtypes (tests, start-up)."""
    with open(os.path.join(_PARENT, "ui", "rdp_embedded.py"), encoding="utf-8") as f:
        tree = ast.parse(f.read())
    top = [n for n in tree.body if isinstance(n, (ast.Import, ast.ImportFrom))]
    names = {a.name for n in top for a in n.names} | {
        n.module for n in top if isinstance(n, ast.ImportFrom)}
    assert not any(str(n).startswith("comtypes") for n in names), names


def test_the_password_goes_to_the_control_not_to_the_credential_manager():
    with open(os.path.join(_PARENT, "ui", "rdp_embedded.py"), encoding="utf-8") as f:
        src = f.read()
    assert "ClearTextPassword" in src
    for banned in ("CredWriteW", "_cmdkey_add", "cmdkey"):
        assert banned not in src, banned


def test_both_builds_carry_the_mstscax_wrapper():
    for spec in ("HospitalHubV2.spec", "HospitalHubRemote.spec"):
        with open(os.path.join(_PARENT, spec), encoding="utf-8") as f:
            text = f.read()
        assert "'comtypes.gen.MSTSCLib'" in text, spec
        assert "_8C11EFA1_92C3_11D1_BC1E_00C04FA31489_0_1_0" in text, spec


def test_machine_with_first():
    from ui.rdp import machine_with_first
    a, b = object(), object()
    m = types.SimpleNamespace(credentials=[a, b])
    assert machine_with_first(m, None) is m
    copy = machine_with_first(m, b)
    assert copy.credentials == [b, a] and m.credentials == [a, b]


# ══════════════════════════════════════════════════════════════════════════
# The default place: a separate window, as before, until the owner switches
# ══════════════════════════════════════════════════════════════════════════

def test_rdp_in_terminal_is_off_until_switched_on(tmp_path, monkeypatch):
    import config
    monkeypatch.setattr(config, "_load_all", lambda: {})
    assert config.load_rdp_in_terminal() is False
    store = {}
    monkeypatch.setattr(config, "_load_all", lambda: dict(store))
    monkeypatch.setattr(config, "_save_all", lambda d: store.update(d))
    config.save_rdp_in_terminal(True)
    assert config.load_rdp_in_terminal() is True


# ══════════════════════════════════════════════════════════════════════════
# The support panel on an RDP tab: screenshots on request, no live mode
# ══════════════════════════════════════════════════════════════════════════

class ScreenTarget:
    def __init__(self, image=None, alive=True):
        self._image, self._alive = image, alive
        self.captures = 0

    def kind(self):
        return "screen"

    def label(self):
        return "10.0.5.12 (srvTerm)"

    def alive(self):
        return self._alive

    def capture(self):
        self.captures += 1
        return self._image


class FakeServer:
    def __init__(self, handler, tools=None):
        self.handler, self.tools, self.token = handler, tools, "t"

    def start(self):
        return "http://127.0.0.1:1/mcp"

    def stop(self):
        pass


class FakeProcess:
    instances = []

    def __init__(self, url, token, prompt, on_event, tools=None):
        self.prompt, self.tools, self.sent = prompt, tools, []
        FakeProcess.instances.append(self)

    def start(self):
        pass

    def send(self, text):
        self.sent.append(text)

    def stop(self):
        pass


def make_panel(target):
    from ui.claude_panel import ClaudeSupportPanel
    FakeProcess.instances.clear()
    panel = ClaudeSupportPanel(target, process_factory=FakeProcess,
                               server_factory=FakeServer,
                               find_claude=lambda: "claude.exe")
    assert panel.start()
    return panel, FakeProcess.instances[0]


def call_tool(panel, name):
    from PyQt6.QtWidgets import QApplication
    out = {}
    t = threading.Thread(target=lambda: out.update(r=panel._handle_tool(name, {})))
    t.start()
    for _ in range(100):
        QApplication.processEvents()
        if not t.is_alive():
            break
        t.join(0.02)
    return out["r"]


def test_an_rdp_panel_offers_the_screenshot_tool_only(app):
    panel, proc = make_panel(ScreenTarget())
    assert proc.tools == cs.SCREEN_TOOLS
    assert panel._server.tools == cs.SCREEN_TOOLS
    assert "screen_capture" in proc.prompt and "NIE są maskowane" in proc.prompt
    assert panel._btn_live.isHidden()
    panel._toggle_live(True)
    assert not panel._live_timer.isActive()
    text, is_error = call_tool(panel, cs.TOOL_READ)
    assert is_error
    panel.end()


def test_a_screenshot_is_sent_as_an_image_and_shown_in_the_panel(app):
    from PyQt6.QtGui import QColor, QImage
    img = QImage(3000, 1500, QImage.Format.Format_RGB32)
    img.fill(QColor("#336699"))
    target = ScreenTarget(img)
    panel, _proc = make_panel(target)
    content, is_error = call_tool(panel, cs.TOOL_SCREEN)
    assert not is_error and target.captures == 1
    assert content[0]["type"] == "image" and content[0]["mimeType"] == "image/png"
    # Scaled to the long side of 1568 px.
    assert "1568×784" in content[1]["text"]
    assert panel._shots == 1 and "wysłane zrzuty: 1" in panel._scope.text()
    panel.end()


def test_no_screenshot_when_the_session_is_not_there(app):
    panel, _ = make_panel(ScreenTarget(image=None))
    text, is_error = call_tool(panel, cs.TOOL_SCREEN)
    assert is_error and "zrzutu" in text
    panel.end()
    panel2, _ = make_panel(ScreenTarget(alive=False))
    text, is_error = call_tool(panel2, cs.TOOL_SCREEN)
    assert is_error
    panel2.end()


def test_the_owner_is_warned_that_screenshots_are_not_masked(app):
    panel, _ = make_panel(ScreenTarget())
    from PyQt6.QtWidgets import QLabel
    texts = " ".join(l.text() for l in panel.findChildren(QLabel))
    assert "nie" in texts and "zamaskować" in texts
    panel.end()


# ══════════════════════════════════════════════════════════════════════════
# The window: SSH-only paths leave RDP tabs alone
# ══════════════════════════════════════════════════════════════════════════

def test_an_rdp_session_is_never_typed_into_by_multi_exec():
    from ui.ssh_panel import _RdpSession, _Session
    assert _RdpSession.excluded is True and _RdpSession.is_rdp is True
    assert _Session.is_rdp is False
    s = _RdpSession(pane=object(), label="x", machine=None)
    assert s.worker is None and s.term is None and s.claude_panel is None


def test_multi_exec_parks_rdp_tabs_instead_of_unparenting_them():
    """A parentless native widget gets a window of its own — the session
    would be lost (2026-11-13)."""
    with open(os.path.join(_PARENT, "ui", "ssh_panel.py"), encoding="utf-8") as f:
        src = f.read()
    start = src.index("    def _rebuild_grid(self):")
    body = src[start:src.index("    def _rebuild_tabs(self):", start)]
    assert "_rdp_parking" in body
    assert "if not s.is_rdp" in body


# ══════════════════════════════════════════════════════════════════════════
# "Dopasuj rozdzielczość" (owner 2026-11-13: "nothing changes on Windows")
# ══════════════════════════════════════════════════════════════════════════

class _FakeClient:
    def __init__(self):
        self.Connected = 1
        self.disconnects = 0

    def Disconnect(self):
        self.disconnects += 1
        self.Connected = 0


def _view(app, size=(1000, 600)):
    from ui.rdp_embedded import RdpView
    v = RdpView("192.0.2.1", 3389, "admin", "x", [])
    v.resize(*size)
    v._client = _FakeClient()
    v.session_size = v._physical_size()
    return v


def test_refit_when_the_desktop_already_fits_does_not_reconnect(app):
    v = _view(app)
    assert v.fits()
    assert v.refit() is False
    assert v._client.disconnects == 0 and not v._refit_pending


def test_refit_after_a_resize_reconnects_on_a_fresh_control(app, monkeypatch):
    from PyQt6.QtCore import QTimer
    v = _view(app)
    v.resize(700, 500)
    assert not v.fits()
    assert v.refit() is True
    assert v._client.disconnects == 1 and v._refit_pending
    calls = []
    monkeypatch.setattr(QTimer, "singleShot", lambda ms, fn: fn())
    monkeypatch.setattr(v, "_destroy_control", lambda: calls.append("destroy"))
    monkeypatch.setattr(v, "start", lambda: calls.append("start"))
    v._on_disconnected(1)
    assert calls == ["destroy", "start"], "nowa kontrolka, potem połączenie"
