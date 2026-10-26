"""2026-10-26 (owner): an AMMS button next to VPN — open the hospital's web
AMMS and sign in; right click edits the URL and the account.

The page side was read from a live AMMS (Angular ``an-login-form``: inputs
labelled by ``lblUser`` / ``lblPassword``, ``#btnLogIn``, a
``.messagebox-dialog`` for "Niepoprawna nazwa użytkownika lub hasło").  Here
everything is fake: a scripted page, a fake browser, a local websocket peer.
"""

import base64
import hashlib
import json
import os
import socket
import struct
import sys
import threading

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import amms_login as al  # noqa: E402
import models  # noqa: E402


class Clock:
    def __init__(self):
        self.t = 0.0

    def __call__(self):
        return self.t

    def sleep(self, s):
        self.t += s


class FakePage:
    """Answers form_call() by mode, from a script of states per mode."""

    def __init__(self, probes, fill=None, submits=None):
        self.probes = list(probes)
        self.fill = fill
        self.submits = list(submits or [{"state": "clicked"}])
        self.calls = []

    def evaluate(self, expression):
        mode = json.loads(expression[expression.rindex(")(") + 2:].split(",")[0])
        self.calls.append((mode, expression))
        if mode == "probe":
            st = self.probes.pop(0) if len(self.probes) > 1 else self.probes[0]
            if isinstance(st, Exception):
                raise st
            return st
        if mode == "fill":
            return self.fill(expression) if callable(self.fill) else self.fill
        if mode == "submit":
            return self.submits.pop(0) if len(self.submits) > 1 else self.submits[0]

    def modes(self):
        return [m for m, _ in self.calls]


FORM = {"state": "form", "hasPassword": True, "message": ""}
NONE = {"state": "none", "frames": 2}


def filled(user="jkowalski", n=7):
    return {"state": "filled", "user": user, "passLength": n}


def run(page, clock=None, **kw):
    clock = clock or Clock()
    return al.fill_and_submit(page, "jkowalski", "Secret1", sleep=clock.sleep,
                              clock=clock, **kw)


# -- the page steps ------------------------------------------------------- #

def test_1_waits_for_form_fills_clicks_and_sees_it_go():
    page = FakePage([NONE, NONE, FORM, FORM, NONE], fill=filled())
    r = run(page)
    assert r.outcome == al.LOGGED_IN
    assert page.modes()[:5] == ["probe", "probe", "probe", "fill", "submit"]


def test_2_message_box_after_click_is_a_rejection_with_its_text():
    msg = "Niepoprawna nazwa użytkownika lub hasło."
    page = FakePage([FORM, FORM, dict(FORM, message=msg)], fill=filled())
    r = run(page)
    assert (r.outcome, r.detail) == (al.REJECTED, msg)


def test_3_fields_that_do_not_take_the_values_are_never_submitted():
    page = FakePage([FORM], fill=filled(user=""))
    r = run(page)
    assert r.outcome == al.FILL_MISMATCH
    assert page.modes().count("fill") == 2
    assert "submit" not in page.modes()


def test_4_login_compared_without_case_password_by_length():
    page = FakePage([FORM, NONE], fill=filled(user="JKOWALSKI"))
    assert run(page).outcome == al.LOGGED_IN
    page = FakePage([FORM], fill=filled(n=6))
    assert run(page).outcome == al.FILL_MISMATCH


def test_5_two_factor_screen_is_left_to_the_user():
    page = FakePage([FORM, FORM, {"state": "mfa"}], fill=filled())
    assert run(page).outcome == al.NEEDS_2FA


def test_6_no_form_in_time():
    clock = Clock()
    page = FakePage([NONE])
    r = run(page, clock=clock, form_timeout=5)
    assert r.outcome == al.FORM_NOT_FOUND
    assert "fill" not in page.modes()
    assert clock.t >= 5


def test_7_cancel_before_the_form_fills_nothing():
    page = FakePage([NONE])
    r = run(page, should_stop=lambda: True)
    assert r.outcome == al.CANCELLED
    assert page.modes() == []


def test_8_disabled_button_is_not_forced():
    page = FakePage([FORM], fill=filled(), submits=[{"state": "button-disabled"}])
    r = run(page)
    assert (r.outcome, r.detail) == (al.SUBMITTED, "button-disabled")


def test_9_navigation_errors_read_as_no_form_not_as_logged_in():
    # A page between navigations throws; that must not count as "form gone".
    page = FakePage([FORM, FORM, al.CdpError("context destroyed"),
                     al.CdpError("context destroyed"), NONE], fill=filled())
    assert run(page).outcome == al.LOGGED_IN
    page = FakePage([FORM, FORM, al.CdpError("context destroyed")], fill=filled())
    assert run(page, result_timeout=3).outcome == al.SUBMITTED


def test_10_values_go_in_as_json_literals():
    tricky = 'a"b\\c\');alert(1);//</script> '
    expr = al.form_call("fill", tricky, tricky)
    tail = expr[expr.rindex(")(") + 2:-1]
    assert json.loads("[" + tail + "]") == ["fill", tricky, tricky]


def test_11_the_form_script_targets_the_amms_markup():
    js = al._FORM_JS
    for needle in ('aria-labelledby="lblUser"', 'aria-labelledby="lblPassword"',
                   "btnLogIn", "messagebox-dialog", "mfa-code-input",
                   "HTMLInputElement.prototype", "'input'"):
        assert needle in js


# -- sign_in and the browser ---------------------------------------------- #

class FakeBrowser:
    def __init__(self, target="default"):
        self.target = target if target != "default" else {
            "id": "T2", "webSocketDebuggerUrl": "ws://127.0.0.1:9/devtools/page/T2"}
        self.opened = []

    def open(self, url, should_stop=None):
        self.opened.append(url)
        return self.target


def test_12_without_login_the_page_is_only_opened():
    made = []
    b = FakeBrowser()
    r = al.sign_in("192.0.2.10/index.html", "", "", browser=b,
                   page_factory=lambda url: made.append(url))
    assert r.outcome == al.OPENED
    assert b.opened == ["http://192.0.2.10/index.html"]
    assert made == []


def test_13_no_target_is_a_browser_failure():
    r = al.sign_in("http://192.0.2.10", "u", "p", browser=FakeBrowser(target=None),
                   page_factory=lambda url: None)
    assert r.outcome == al.BROWSER_FAILED


def test_14_socket_errors_end_as_error_and_close_the_page():
    class Boom:
        closed = False

        def call(self, method, params=None):
            return {}

        def evaluate(self, expression):
            raise TimeoutError("timed out")

        def close(self):
            Boom.closed = True

    r = al.sign_in("http://192.0.2.10", "u", "p", browser=FakeBrowser(),
                   page_factory=lambda url: Boom())
    assert r.outcome == al.ERROR and Boom.closed


def test_15_open_returns_the_tab_that_was_not_there_before(monkeypatch, tmp_path):
    b = al.Browser("chrome.exe", tmp_path)
    state = {"launched": False}
    old = {"id": "OLD", "type": "page", "webSocketDebuggerUrl": "ws://x/OLD"}
    new = {"id": "NEW", "type": "page", "webSocketDebuggerUrl": "ws://x/NEW"}
    monkeypatch.setattr(b, "port", lambda: 9222)
    monkeypatch.setattr(b, "pages", lambda port: [old, new] if state["launched"] else [old])
    monkeypatch.setattr(b, "launch", lambda url: state.update(launched=True))
    assert b.open("http://192.0.2.10", sleep=lambda s: None)["id"] == "NEW"


def test_16_launch_uses_its_own_profile_and_never_carries_secrets(monkeypatch, tmp_path):
    seen = []

    class Popen:
        def __init__(self, args, **kw):
            seen.append(args)

    monkeypatch.setattr(al.subprocess, "Popen", Popen)
    al.Browser("chrome.exe", tmp_path / "prof").launch("http://192.0.2.10/index.html")
    args = seen[0]
    assert args[0] == "chrome.exe"
    assert f"--user-data-dir={tmp_path / 'prof'}" in args
    assert "--remote-debugging-port=0" in args
    assert args[-1] == "http://192.0.2.10/index.html"


def test_17_port_comes_from_devtoolsactiveport(monkeypatch, tmp_path):
    b = al.Browser("chrome.exe", tmp_path)
    assert b.port() is None
    (tmp_path / "DevToolsActivePort").write_text("51234\n/devtools/browser/x\n")
    asked = []
    monkeypatch.setattr(al, "_http_json", lambda port, path, timeout=2.0: asked.append((port, path)) or {})
    assert b.port() == 51234
    assert asked == [(51234, "/json/version")]


def test_18_normalize_url():
    assert al.normalize_url(" 192.0.2.10/index.html ") == "http://192.0.2.10/index.html"
    assert al.normalize_url("https://amms.example") == "https://amms.example"
    assert al.normalize_url("") == ""


# -- the websocket, against a local peer ---------------------------------- #

def _peer(server, replies):
    conn, _ = server.accept()
    data = b""
    while b"\r\n\r\n" not in data:
        data += conn.recv(1024)
    key = [l.split(":", 1)[1].strip() for l in data.decode().split("\r\n")
           if l.lower().startswith("sec-websocket-key")][0]
    accept = base64.b64encode(hashlib.sha1(
        (key + al._WebSocket._GUID).encode()).digest()).decode()
    conn.sendall(("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n"
                  f"Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n").encode())

    def read_frame():
        b0, b1 = conn.recv(2, socket.MSG_WAITALL)
        n = b1 & 0x7F
        if n == 126:
            n = struct.unpack(">H", conn.recv(2, socket.MSG_WAITALL))[0]
        mask = conn.recv(4, socket.MSG_WAITALL)
        body = b""
        while len(body) < n:
            body += conn.recv(n - len(body))
        assert b1 & 0x80, "client frames must be masked"
        return bytes(c ^ mask[i % 4] for i, c in enumerate(body))

    request = json.loads(read_frame())
    conn.sendall(b"\x89\x00")                       # a ping first
    assert read_frame() == b""                      # the pong
    conn.sendall(b"\x81" + bytes([len(b'{"method":"x"}')]) + b'{"method":"x"}')
    reply = json.dumps({"id": request["id"], "result": {"result": {"value": replies}}}).encode()
    half = len(reply) // 2                          # fragmented: text + continuation
    conn.sendall(b"\x01" + bytes([126]) + struct.pack(">H", half) + reply[:half])
    conn.sendall(b"\x80" + bytes([126]) + struct.pack(">H", len(reply) - half) + reply[half:])
    conn.close()


def test_19_websocket_handshake_ping_fragments_and_events():
    server = socket.socket()
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    port = server.getsockname()[1]
    value = {"state": "form", "pad": "x" * 300}
    t = threading.Thread(target=_peer, args=(server, value), daemon=True)
    t.start()
    page = al.Page(f"ws://127.0.0.1:{port}/devtools/page/T1", timeout=5)
    assert page.evaluate("1") == value
    t.join(5)
    server.close()


# -- model, dialog, button ------------------------------------------------ #

def test_20_amms_fields_live_in_the_hospital_and_survive_the_vault():
    h = models.Hospital(name="A", amms_url="http://192.0.2.10/index.html",
                        amms_login="u", amms_password="p")
    back = models.from_dict(json.loads(json.dumps(models.to_dict([h]))))[0]
    assert (back.amms_url, back.amms_login, back.amms_password) == (
        "http://192.0.2.10/index.html", "u", "p")
    old = models.from_dict({"hospitals": [{"id": "h", "name": "B"}]})[0]
    assert (old.amms_url, old.amms_login, old.amms_password) == ("", "", "")


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def test_21_dialog_saves_normalised_url_and_empty_url_clears_all(app):
    from ui.amms import AmmsDialog
    h = models.Hospital(name="A")
    dlg = AmmsDialog(None, h)
    dlg._url_edit.setText("192.0.2.10/index.html")
    dlg._login_edit.setText(" u ")
    dlg._pass_edit.setText(" p ")
    dlg._accept()
    assert dlg.values() == ("http://192.0.2.10/index.html", "u", " p ")
    h = models.Hospital(name="A", amms_url="http://x", amms_login="u", amms_password="p")
    dlg = AmmsDialog(None, h)
    dlg._url_edit.setText("")
    dlg._accept()
    assert dlg.values() == ("", "", "")


def test_22_every_outcome_has_a_status_text():
    from ui.amms import OUTCOME_TEXTS
    outcomes = {al.LOGGED_IN, al.NEEDS_2FA, al.SUBMITTED, al.REJECTED,
                al.OPENED, al.NO_BROWSER, al.BROWSER_FAILED, al.FORM_NOT_FOUND,
                al.FILL_MISMATCH, al.CANCELLED, al.ERROR}
    assert outcomes == set(OUTCOME_TEXTS)


@pytest.fixture
def panel(app):
    from ui import detail_panel as dp
    p = dp.DetailPanel()
    h = models.Hospital(name="Szpital A")
    p.show_hospital(h, [h])
    yield p
    p.cleanup()
    p.deleteLater()


def test_23_button_sits_next_to_vpn_and_starts_greyed(panel):
    header = panel._vpn_header
    assert header.indexOf(panel._amms_btn) == header.indexOf(panel._vpn_btn) - 1
    assert "#484f58" in panel._amms_btn.styleSheet()
    assert "nie skonfigurowany" in panel._amms_btn.toolTip()


def test_24_click_without_url_opens_the_editor_and_edit_saves(panel, monkeypatch):
    import ui.amms as ua
    opened = []

    class Dlg:
        def __init__(self, parent, hospital):
            opened.append(hospital)

        def exec(self):
            return True

        def values(self):
            return ("http://192.0.2.10/index.html", "u", "p")

    monkeypatch.setattr(ua, "AmmsDialog", Dlg)
    changed = []
    panel.data_changed.connect(lambda: changed.append(1))
    panel._on_amms_btn_clicked()
    h = panel.current_hospital
    assert opened == [h] and changed == [1]
    assert (h.amms_url, h.amms_login, h.amms_password) == (
        "http://192.0.2.10/index.html", "u", "p")
    assert "jako u" in panel._amms_btn.toolTip()


def test_25_click_with_url_runs_the_worker_and_shows_the_outcome(panel, monkeypatch):
    import ui.amms as ua
    started = []

    class Worker:
        def __init__(self, url, login, password, parent=None):
            started.append((url, login, password))
            self.progress = self.done = self.finished = self

        def connect(self, slot):
            pass

        def start(self):
            pass

        def deleteLater(self):
            pass

    monkeypatch.setattr(ua, "AmmsWorker", Worker)
    h = panel.current_hospital
    h.amms_url, h.amms_login, h.amms_password = "http://192.0.2.10", "u", "p"
    panel._on_amms_btn_clicked()
    panel._on_amms_btn_clicked()                # second click while running: ignored
    assert started == [("http://192.0.2.10", "u", "p")]
    panel._on_amms_done(al.REJECTED, "Niepoprawna nazwa użytkownika lub hasło.")
    assert panel._amms_worker is None
    assert "odrzucone" in panel._amms_status_lbl.text()
    assert "Niepoprawna" in panel._amms_status_lbl.text()
    panel._start_amms(with_login=False)
    assert started[-1] == ("http://192.0.2.10", "", "")


def test_26_worker_reports_and_forgets_the_password(app):
    from ui.amms import AmmsWorker
    got = {}

    def sign_in(url, login, password, progress, should_stop):
        got["args"] = (url, login, password)
        progress("x")
        return al.AmmsResult(al.LOGGED_IN)

    w = AmmsWorker("http://192.0.2.10", "u", "p", sign_in=sign_in)
    done = []
    w.done.connect(lambda o, d: done.append(o))
    w.run()                                      # in this thread, synchronously
    assert got["args"] == ("http://192.0.2.10", "u", "p")
    assert done == [al.LOGGED_IN]
    assert w._password == ""


def test_27_menu_copies_the_password_the_private_way(panel, monkeypatch):
    from PyQt6.QtWidgets import QMenu
    from ui import detail_panel as dp
    copied, shown = [], []
    monkeypatch.setattr(dp, "_clipboard_copy", copied.append)
    monkeypatch.setattr(QMenu, "exec", lambda self, *a: shown.append(
        {a.text(): a for a in self.actions()}))
    h = panel.current_hospital
    panel._on_amms_menu(panel._amms_btn.rect().center())
    assert "Kopiuj hasło" not in shown[-1]          # nothing saved yet
    h.amms_url, h.amms_login, h.amms_password = "http://192.0.2.10", "u", "Secret1"
    panel._on_amms_menu(panel._amms_btn.rect().center())
    shown[-1]["Kopiuj hasło"].trigger()
    assert copied == ["Secret1"]


# -- the VPN card --------------------------------------------------------- #

def test_28_vpn_profile_keeps_amms_in_the_vpn_vault():
    p = models.VpnProfile(name="V", amms_url="http://192.0.2.10", amms_login="u",
                          amms_password="p")
    back = models.vpn_from_dict(json.loads(json.dumps(models.vpn_to_dict([p]))))[0]
    assert back == p
    old = models.vpn_from_dict({"vpn_profiles": [{"name": "W"}]})[0]
    assert (old.amms_url, old.amms_login, old.amms_password) == ("", "", "")


@pytest.fixture
def vpn(app, monkeypatch):
    from ui import vpn_panel as vp
    monkeypatch.setattr(vp.VpnPanel, "_poll_status", lambda self: None)
    p = models.VpnProfile(name="Profil tylko VPN", provider="FortiClient")
    panel = vp.VpnPanel([p])
    yield panel, p, vp
    panel.cleanup()
    panel.deleteLater()


def test_29_every_card_has_an_amms_button_greyed_until_set(vpn, monkeypatch):
    panel, p, vp = vpn
    btn = panel._amms_btns[p.id]
    assert btn.text() == "AMMS" and "#484f58" in btn.styleSheet()
    import ui.amms as ua

    class Dlg:
        def __init__(self, parent, obj):
            assert obj is p

        def exec(self):
            return True

        def values(self):
            return ("http://192.0.2.10/index.html", "u", "Secret1")

    monkeypatch.setattr(ua, "AmmsDialog", Dlg)
    changed = []
    panel.data_changed.connect(lambda: changed.append(1))
    btn.click()
    assert (p.amms_url, p.amms_login, p.amms_password) == (
        "http://192.0.2.10/index.html", "u", "Secret1")
    assert changed == [1] and "jako u" in btn.toolTip()


def test_30_card_menu_copies_the_password(vpn, monkeypatch):
    from PyQt6.QtWidgets import QMenu
    panel, p, vp = vpn
    p.amms_url, p.amms_password = "http://192.0.2.10", "Secret1"
    copied, shown = [], []
    monkeypatch.setattr(vp, "_clipboard_copy", copied.append)
    monkeypatch.setattr(QMenu, "exec", lambda self, *a: shown.append(
        {a.text(): a for a in self.actions()}))
    btn = panel._amms_btns[p.id]
    panel._amms_menu(p, btn, btn.rect().center())
    assert set(shown[-1]) == {"Edytuj AMMS…", "Kopiuj hasło", "Otwórz bez logowania"}
    shown[-1]["Kopiuj hasło"].trigger()
    assert copied == ["Secret1"]


def test_31_card_note_survives_the_status_poll_for_a_while(vpn, monkeypatch):
    import ui.amms as ua
    panel, p, vp = vpn
    started = []

    class Worker:
        def __init__(self, url, login, password, parent=None):
            started.append((url, login, password))
            self.progress = self.done = self.finished = self

        def connect(self, slot):
            pass

        def start(self):
            pass

        def deleteLater(self):
            pass

    monkeypatch.setattr(ua, "AmmsWorker", Worker)
    p.amms_url, p.amms_login, p.amms_password = "http://192.0.2.10", "u", "p"
    panel._amms_clicked(p)
    panel._amms_clicked(p)                       # still running: ignored
    assert started == [("http://192.0.2.10", "u", "p")]
    panel._on_amms_done(p, al.REJECTED, "Niepoprawna nazwa użytkownika lub hasło.")
    lbl = panel._status_labels[0]
    panel._apply_status_results({0: "Disconnected"})
    assert "odrzucone" in lbl.text()             # held, not "Rozłączono"
    assert "Niepoprawna" in lbl.toolTip()
    panel._amms_held[0] = 0
    panel._apply_status_results({0: "Disconnected"})
    assert "Rozłączono" in lbl.text()


def test_32_amms_button_sits_left_of_connect(vpn):
    panel, p, vp = vpn
    lay = panel._card_widgets[0].layout()
    order = [lay.itemAt(i).widget() for i in range(lay.count())]
    assert order.index(panel._amms_btns[p.id]) < order.index(panel._toggle_btns[0])


def test_33_vpn_card_uses_the_main_vault_hospital_of_the_same_name(app, monkeypatch):
    """Owner: AMMS filled in for Betanin in the main vault shows on the
    VPN card "Betanin" too; editing it there edits the hospital."""
    from ui import detail_panel as dp
    from ui import vpn_panel as vp
    import ui.amms as ua
    monkeypatch.setattr(vp.VpnPanel, "_poll_status", lambda self: None)
    h = models.Hospital(name="Betanin AMMS", amms_url="http://192.0.2.20/index.html",
                        amms_login="hu", amms_password="hp")
    hosp_panel = dp.DetailPanel()
    hosp_panel.show_hospital(h, [h])
    prof = models.VpnProfile(name="betanin amms ", provider="FortiClient")
    panel = vp.VpnPanel([prof])
    dp.share_vpn_window(panel)
    try:
        btn = panel._amms_btns[prof.id]
        assert "192.0.2.20" in btn.toolTip() and "głównego vaulta" in btn.toolTip()
        started = []

        class Worker:
            def __init__(self, url, login, password, parent=None):
                started.append((url, login, password))
                self.progress = self.done = self.finished = self

            def connect(self, slot):
                pass

            def start(self):
                pass

            def deleteLater(self):
                pass

        monkeypatch.setattr(ua, "AmmsWorker", Worker)
        panel._amms_clicked(prof)
        assert started == [("http://192.0.2.20/index.html", "hu", "hp")]
        panel._amms_workers.clear()

        class Dlg:
            def __init__(self, parent, obj):
                assert obj is h

            def exec(self):
                return True

            def values(self):
                return ("http://192.0.2.21/index.html", "hu2", "hp2")

        monkeypatch.setattr(ua, "AmmsDialog", Dlg)
        saved = []
        hosp_panel.data_changed.connect(lambda: saved.append("main"))
        panel.data_changed.connect(lambda: saved.append("vpn"))
        panel._edit_amms(prof)
        assert (h.amms_url, h.amms_login, h.amms_password) == (
            "http://192.0.2.21/index.html", "hu2", "hp2")
        assert (prof.amms_url, prof.amms_password) == ("", "")
        assert saved == ["main"]
        assert "192.0.2.21" in hosp_panel._amms_btn.toolTip()
        assert "192.0.2.21" in btn.toolTip()
    finally:
        dp.share_vpn_window(None)
        panel.cleanup()
        hosp_panel.cleanup()
        hosp_panel.current_hospital = None
        hosp_panel._all_hospitals = None
