"""2026-10-20: "Wsparcie Claude" — a conversation about one SSH tab, read only.

The owner chose read only: Claude sees the tab's screen and scrollback and
advises; the owner types every command.  These tests pin that nothing in the
feature can type, that Claude Code is started with no built-in tools and only
this server, and that the tool server answers MCP and only to its token.
No real Claude Code is started.
"""

import ast
import json
import os
import sys
import urllib.error
import urllib.request

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import claude_support as cs  # noqa: E402


# ══════════════════════════════════════════════════════════════════════════
# Read only, by construction
# ══════════════════════════════════════════════════════════════════════════

def test_the_only_tool_reads_the_terminal():
    assert [t["name"] for t in cs.TOOLS] == [cs.TOOL_READ]
    assert cs.allowed_tool_names() == ["mcp__hospitalhub__terminal_read"]


def test_the_terminal_target_cannot_type():
    with open(os.path.join(_PARENT, "ui", "ssh_panel.py"), encoding="utf-8") as f:
        tree = ast.parse(f.read())
    target = next(n for n in ast.walk(tree)
                  if isinstance(n, ast.ClassDef) and n.name == "_SupportTarget")
    methods = {n.name for n in target.body if isinstance(n, ast.FunctionDef)}
    assert methods == {"__init__", "label", "alive", "read"}
    called = {n.func.attr for n in ast.walk(target)
              if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    for banned in ("_send_one", "send", "write", "feed", "press_key", "type_text"):
        assert banned not in called, banned


def test_the_panel_never_writes_to_its_target():
    with open(os.path.join(_PARENT, "ui", "claude_panel.py"), encoding="utf-8") as f:
        tree = ast.parse(f.read())
    used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)
            and isinstance(n.value, ast.Attribute) and n.value.attr == "_target"}
    assert used <= {"label", "alive", "read"}, used


def test_claude_code_runs_with_no_built_in_tools_and_only_this_server():
    p = cs.ClaudeProcess("http://127.0.0.1:1/mcp", "t", "x", lambda *a: None)
    cmd = p.command("claude.exe", r"C:\tmp\hh")
    assert cmd[cmd.index("--tools") + 1] == ""
    assert "--strict-mcp-config" in cmd
    assert cmd[cmd.index("--permission-mode") + 1] == "dontAsk"
    allowed = cmd[cmd.index("--allowedTools") + 1:cmd.index("--permission-mode")]
    assert allowed == cs.allowed_tool_names()
    assert "--dangerously-skip-permissions" not in cmd
    assert cmd[cmd.index("--setting-sources") + 1] == ""


# ══════════════════════════════════════════════════════════════════════════
# The tool server speaks MCP, on 127.0.0.1, to its token only
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def server():
    calls = []

    def handler(name, args):
        calls.append((name, args))
        return "[root@srv ~]# uptime", False

    srv = cs.ToolServer(handler)
    url = srv.start()
    yield srv, url, calls
    srv.stop()


def _post(url, token, message):
    req = urllib.request.Request(
        url, data=json.dumps(message).encode(), method="POST",
        headers={"Content-Type": "application/json",
                 **({"Authorization": "Bearer " + token} if token else {})})
    with urllib.request.urlopen(req, timeout=5) as resp:
        body = resp.read()
        return resp.status, (json.loads(body) if body else None)


def test_the_server_listens_on_localhost_only(server):
    _srv, url, _calls = server
    assert url.startswith("http://127.0.0.1:")


def test_without_the_token_nothing_is_answered(server):
    srv, url, calls = server
    with pytest.raises(urllib.error.HTTPError) as err:
        _post(url, "", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert err.value.code == 401
    with pytest.raises(urllib.error.HTTPError):
        _post(url, "wrong", {"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert calls == []


def test_initialize_list_and_call(server):
    srv, url, calls = server
    status, reply = _post(url, srv.token, {"jsonrpc": "2.0", "id": 1, "method": "initialize",
                                           "params": {"protocolVersion": "2025-06-18"}})
    assert status == 200 and reply["result"]["protocolVersion"] == "2025-06-18"
    status, reply = _post(url, srv.token, {"jsonrpc": "2.0", "method":
                                           "notifications/initialized"})
    assert status == 202 and reply is None
    _s, reply = _post(url, srv.token, {"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    assert [t["name"] for t in reply["result"]["tools"]] == [cs.TOOL_READ]
    _s, reply = _post(url, srv.token, {"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                                       "params": {"name": cs.TOOL_READ,
                                                  "arguments": {"lines": 50}}})
    assert reply["result"]["content"][0]["text"] == "[root@srv ~]# uptime"
    assert calls == [(cs.TOOL_READ, {"lines": 50})]


def test_an_unknown_tool_is_refused_without_calling_the_handler(server):
    srv, url, calls = server
    _s, reply = _post(url, srv.token, {"jsonrpc": "2.0", "id": 4, "method": "tools/call",
                                       "params": {"name": "terminal_run",
                                                  "arguments": {"command": "rm -rf /"}}})
    assert "error" in reply and calls == []


# ══════════════════════════════════════════════════════════════════════════
# Claude Code's stream, as events
# ══════════════════════════════════════════════════════════════════════════

def test_stream_json_events_become_panel_events():
    seen = []
    p = cs.ClaudeProcess("u", "t", "x", lambda k, v: seen.append((k, v)))
    p.handle_event({"type": "system", "subtype": "init",
                    "mcp_servers": [{"name": "hospitalhub", "status": "connected"}]})
    p.handle_event({"type": "assistant", "message": {"content": [
        {"type": "tool_use", "name": "mcp__hospitalhub__terminal_read"},
        {"type": "text", "text": "Kontener asi-backend nie działa."}]}})
    p.handle_event({"type": "result", "is_error": False, "result": "ok"})
    assert seen == [("ready", {"connected": True}),
                    ("tool", "mcp__hospitalhub__terminal_read"),
                    ("text", "Kontener asi-backend nie działa."),
                    ("turn_end", {"is_error": False, "text": "ok"})]


# ══════════════════════════════════════════════════════════════════════════
# The panel, with a fake Claude
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


class Target:
    def __init__(self, alive=True):
        self._alive = alive
        self.reads = []

    def label(self):
        return "10.0.60.225 (srvDB)"

    def alive(self):
        return self._alive

    def read(self, lines):
        self.reads.append(lines)
        return "[root@srvDB ~]# docker compose ps\nasi-backend  Exited (1)\n\n\n"


class FakeProcess:
    instances = []

    def __init__(self, url, token, prompt, on_event):
        self.url, self.token, self.prompt, self.on_event = url, token, prompt, on_event
        self.sent, self.stopped = [], False
        FakeProcess.instances.append(self)

    def start(self):
        pass

    def send(self, text):
        self.sent.append(text)

    def stop(self):
        self.stopped = True


def make_panel(app, target=None):
    from ui.claude_panel import ClaudeSupportPanel
    FakeProcess.instances.clear()
    panel = ClaudeSupportPanel(target or Target(), process_factory=FakeProcess,
                               find_claude=lambda: "claude.exe")
    assert panel.start()
    return panel, FakeProcess.instances[0]


def pump():
    from PyQt6.QtWidgets import QApplication
    for _ in range(5):
        QApplication.processEvents()


def test_the_panel_starts_claude_with_its_server_and_the_tab_in_the_prompt(app):
    panel, proc = make_panel(app)
    assert proc.url.startswith("http://127.0.0.1:") and proc.token
    assert "10.0.60.225 (srvDB)" in proc.prompt
    assert "Nie możesz niczego wpisać" in proc.prompt
    panel.end()
    assert proc.stopped


def test_a_read_returns_the_terminal_trimmed(app):
    import threading
    target = Target()
    panel, proc = make_panel(app, target)
    out = {}
    t = threading.Thread(target=lambda: out.update(r=panel._handle_tool(
        cs.TOOL_READ, {"lines": 99999})))
    t.start()
    for _ in range(50):
        pump()
        if not t.is_alive():
            break
        t.join(0.05)
    assert out["r"] == ("[root@srvDB ~]# docker compose ps\nasi-backend  Exited (1)", False)
    assert target.reads == [2000], "limit odczytu"
    panel.end()


def test_a_closed_tab_is_reported_not_read(app):
    import threading
    target = Target(alive=False)
    panel, _proc = make_panel(app, target)
    out = {}
    t = threading.Thread(target=lambda: out.update(r=panel._handle_tool(cs.TOOL_READ, {})))
    t.start()
    for _ in range(50):
        pump()
        if not t.is_alive():
            break
        t.join(0.05)
    assert out["r"][1] is True and target.reads == []
    panel.end()


def test_sending_and_answers(app):
    panel, proc = make_panel(app)
    panel._input.setPlainText("czemu backend nie wstaje?")
    panel._send()
    assert proc.sent == ["czemu backend nie wstaje?"]
    assert not panel._btn_send.isEnabled(), "czeka na odpowiedź"
    proc.on_event("text", "Kontener asi-backend kończy się kodem 1.")
    proc.on_event("turn_end", {"is_error": False, "text": ""})
    pump()
    assert panel._btn_send.isEnabled()
    panel.end()


def test_no_claude_code_installed_says_so(app):
    from ui.claude_panel import ClaudeSupportPanel
    panel = ClaudeSupportPanel(Target(), process_factory=FakeProcess,
                               find_claude=lambda: None)
    assert panel.start() is False
    assert not panel._input.isEnabled()


def test_a_login_error_gets_a_clear_hint():
    from ui.claude_panel import _login_hint
    assert "zaloguj się" in _login_hint("Invalid API key · Please run /login")


def test_proposed_commands_get_a_copy_button(app):
    from ui.claude_panel import code_blocks
    answer = ("Sprawdź logi:\n\n```bash\ndocker compose logs --tail 100 asi-backend\n```\n"
              "A potem:\n```\ndocker inspect asi-backend\n```")
    assert code_blocks(answer) == ["docker compose logs --tail 100 asi-backend",
                                   "docker inspect asi-backend"]
    panel, proc = make_panel(app)
    proc.on_event("text", answer)
    pump()
    from PyQt6.QtWidgets import QApplication, QPushButton
    buttons = [b for b in panel.findChildren(QPushButton) if b.text().startswith("Kopiuj")]
    assert len(buttons) == 2
    buttons[0].click()
    assert QApplication.clipboard().text() == "docker compose logs --tail 100 asi-backend"
    panel.end()


def test_long_code_lines_wrap_instead_of_widening_the_panel():
    from ui.claude_panel import wrapped_html
    html = wrapped_html("```\n" + "x" * 300 + "\n```")
    assert "white-space:pre;" not in html and "white-space: pre;" not in html


# ══════════════════════════════════════════════════════════════════════════
# 2026-10-20 (owner): live mode, a quick "Zakończ", and opening it again
# ══════════════════════════════════════════════════════════════════════════

def test_new_lines_are_what_follows_the_last_known_end():
    from ui.claude_panel import new_lines
    before = ["$ ls", "a b", "$ docker ps", "asi-db Up"]
    after = before + ["$ docker logs asi-backend", "ERROR: no db"]
    assert new_lines(before, after) == ["$ docker logs asi-backend", "ERROR: no db"]
    assert new_lines(before, before) == []
    assert new_lines(before, ["$ clear-screen", "x"]) == ["$ clear-screen", "x"]


class LiveTarget(Target):
    def __init__(self):
        super().__init__()
        self.text = "$ docker ps\nasi-db Up"

    def read(self, lines):
        return self.text


def test_live_mode_sends_only_the_news_after_the_terminal_settles(app, monkeypatch):
    import ui.claude_panel as cp
    clock = [1000.0]
    monkeypatch.setattr("time.monotonic", lambda: clock[0])
    target = LiveTarget()
    panel, proc = make_panel(app, target)
    panel._btn_live.setChecked(True)
    target.text += "\n$ docker logs asi-backend\nERROR: connection refused"
    panel._live_tick()                       # changed: wait for it to settle
    assert proc.sent == []
    clock[0] += cp._LIVE_QUIET_S + 0.1
    panel._live_tick()
    assert len(proc.sent) == 1
    assert proc.sent[0].startswith("[NA ŻYWO]")
    assert "ERROR: connection refused" in proc.sent[0] and "asi-db Up" not in proc.sent[0]
    # Claude says nothing worth showing: no bubble, a quiet status
    before = panel._messages.count()
    proc.on_event("text", "OK")
    proc.on_event("turn_end", {"is_error": False, "text": "OK"})
    pump()
    assert panel._messages.count() == before
    assert "bez uwag" in panel._state.text()
    # more output too soon: held back until the gap has passed
    target.text += "\nERROR: again"
    panel._live_tick()
    clock[0] += cp._LIVE_QUIET_S + 0.1
    panel._live_tick()
    assert len(proc.sent) == 1
    clock[0] += cp._LIVE_MIN_GAP_S
    panel._live_tick()
    assert len(proc.sent) == 2 and "ERROR: again" in proc.sent[1]
    panel.end()


def test_live_mode_off_sends_nothing(app):
    target = LiveTarget()
    panel, proc = make_panel(app, target)
    target.text += "\nERROR: x"
    panel._live_tick()
    assert not panel._live_timer.isActive() and proc.sent == []
    panel.end()


def test_stopping_does_not_wait_for_claude_code():
    import time

    class Slow:
        def __init__(self):
            self.stdin = self

        def close(self):
            pass

        def wait(self, timeout=None):
            time.sleep(timeout or 0)

        def kill(self):
            pass

    p = cs.ClaudeProcess("u", "t", "x", lambda *a: None)
    p._proc = Slow()
    started = time.monotonic()
    p.stop()
    assert time.monotonic() - started < 0.5


def test_support_can_be_opened_again_in_the_same_window(app, tmp_path, monkeypatch):
    sys.path.insert(0, _HERE)
    import time
    import models
    from ssh_fake_server import FakeServer
    from ui import ssh_panel as sp
    import ui.claude_panel as cp
    srv = FakeServer(str(tmp_path))
    monkeypatch.setattr(sp, "_make_client", srv.make_client_patch())
    monkeypatch.setattr(sp.QMessageBox, "warning", lambda *a, **k: None)
    monkeypatch.setattr(cp.cs, "ClaudeProcess", FakeProcess)
    monkeypatch.setattr(cp.cs, "find_claude", lambda: "claude.exe")
    m = models.Machine(ip="10.0.0.5", credentials=[
        models.Credential(login="u", password=srv.password)])
    dlg = sp.SshDialog(m)
    dlg.resize(1300, 700)
    dlg.show()
    end = time.monotonic() + 8
    while time.monotonic() < end and not dlg._sessions:
        pump()
    try:
        for _round in range(2):
            dlg._btn_claude.setChecked(True)
            pump()
            panel = dlg._sessions[0].claude_panel
            assert panel is not None and not panel.ended()
            assert dlg._term_splitter.sizes()[1] > 200, dlg._term_splitter.sizes()
            panel.end()
            pump()
            assert panel.ended() and not dlg._btn_claude.isChecked()
            assert dlg._claude_stack.currentWidget() is panel,                 "zakończona rozmowa zostaje do przeczytania"
        assert dlg._claude_stack.count() == 1, "stare panele nie zostają w oknie"
    finally:
        dlg.close_without_asking()
        srv.drop()


def test_the_typing_bubble_shows_while_claude_works_and_follows_new_messages(app):
    panel, proc = make_panel(app)
    panel.show()
    panel._input.setPlainText("co z backendem?")
    panel._send()
    pump()
    assert panel._typing.running() and panel._typing_row.isVisible()
    proc.on_event("text", "Czytam logi…")
    pump()
    last = panel._messages.itemAt(panel._messages.count() - 2).widget()
    assert last is panel._typing_row, "kropki pod najnowszą wiadomością"
    proc.on_event("turn_end", {"is_error": False, "text": ""})
    pump()
    assert not panel._typing.running() and not panel._typing_row.isVisible()
    panel.end()


def test_each_tab_has_its_own_support_shown_only_on_that_tab(app, tmp_path,
                                                             monkeypatch):
    """2026-10-21 (owner): three tabs — support on the first, only the
    terminal on the second, another conversation on the third."""
    sys.path.insert(0, _HERE)
    import time
    import models
    from ssh_fake_server import FakeServer
    from ui import ssh_panel as sp
    import ui.claude_panel as cp
    srv = FakeServer(str(tmp_path))
    monkeypatch.setattr(sp, "_make_client", srv.make_client_patch())
    monkeypatch.setattr(sp.QMessageBox, "warning", lambda *a, **k: None)
    monkeypatch.setattr(cp.cs, "ClaudeProcess", FakeProcess)
    monkeypatch.setattr(cp.cs, "find_claude", lambda: "claude.exe")
    FakeProcess.instances.clear()
    m = models.Machine(ip="10.0.0.5", credentials=[
        models.Credential(login="u", password=srv.password)])
    dlg = sp.SshDialog(m)
    dlg.resize(1300, 700)
    dlg.show()
    end = time.monotonic() + 8
    while time.monotonic() < end and not dlg._sessions:
        pump()
    for label in ("druga", "trzecia"):
        dlg._add_session(label=label, ip="10.0.0.5", user="u",
                         password=srv.password)
    end = time.monotonic() + 8
    while time.monotonic() < end and len(dlg._sessions) < 3:
        pump()
    tabs, stack, btn = dlg._tab_widget, dlg._claude_stack, dlg._btn_claude
    s1, s2, s3 = dlg._sessions
    try:
        tabs.setCurrentIndex(0)
        btn.setChecked(True)
        pump()
        p1 = s1.claude_panel
        assert p1 is not None and not stack.isHidden()
        # The handle has the window's colour — the grey one was a white
        # stripe beside the dark terminal in the light themes.
        assert isinstance(dlg._term_splitter.handle(1), sp._TermSupportHandle)
        assert dlg._term_splitter.widget(1) is stack
        assert stack.currentWidget() is p1 and btn.isChecked()
        assert tabs.tabText(0).startswith("● ")

        tabs.setCurrentIndex(1)                 # only the terminal
        pump()
        assert stack.isHidden() and not btn.isChecked()
        assert s2.claude_panel is None

        tabs.setCurrentIndex(2)
        btn.setChecked(True)                    # another conversation
        pump()
        p3 = s3.claude_panel
        assert p3 is not None and p3 is not p1
        assert stack.currentWidget() is p3 and not stack.isHidden()
        assert len(FakeProcess.instances) == 2
        assert "trzecia" in FakeProcess.instances[1].prompt

        tabs.setCurrentIndex(0)                 # the first one is still there
        pump()
        assert stack.currentWidget() is p1 and btn.isChecked()
        assert not p1.ended() and not p3.ended()

        btn.setChecked(False)                   # ends only the first
        pump()
        assert p1.ended() and not p3.ended()
        assert stack.currentWidget() is p1, "zostaje do przeczytania"
        assert not tabs.tabText(0).startswith("● ")
        assert tabs.tabText(2).startswith("● ")

        tabs.setCurrentIndex(2)
        pump()
        assert stack.currentWidget() is p3 and btn.isChecked()

        dlg._close_session(2)                   # its panel goes with the tab
        pump()
        assert p3.ended() and stack.indexOf(p3) < 0
        tabs.setCurrentIndex(0)
        pump()
        assert stack.currentWidget() is p1 and not btn.isChecked()
    finally:
        dlg.close_without_asking()
        srv.drop()



# ══════════════════════════════════════════════════════════════════════════
# 2026-10-21: PESEL numbers never leave for Claude
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("text, expected, count", [
    ("pacjent 85010112345 przyjęty", "pacjent [PESEL] przyjęty", 1),       # 1985
    ("PESEL:02270803628;", "PESEL:[PESEL];", 1),                           # 2002 (+20)
    ("ur. 1850 r.: 50820112345", "ur. 1850 r.: [PESEL]", 1),               # 1850 (+80)
    ("00222912345", "[PESEL]", 1),                                         # 29.02.2000
    ("01222912345", "01222912345", 0),                                     # 29.02.2001: no
    ("85013212345", "85013212345", 0),                                     # day 32
    ("12345678901", "12345678901", 0),                                     # month 34
    ("ts 1697543210123 ms", "ts 1697543210123 ms", 0),                     # 13 digits
    ("850101123456", "850101123456", 0),                                   # 12 digits
    ("port 8443 pid 1212 rss 410280", "port 8443 pid 1212 rss 410280", 0),
    ("a=85010112345,b=90122412345", "a=[PESEL],b=[PESEL]", 2),
])
def test_mask_pesel(text, expected, count):
    assert cs.mask_pesel(text) == (expected, count)


def test_inside_a_pid_segment_every_eleven_digits_are_masked():
    msg = ("MSH|^~\\&|HIS|SZP|||20261021||ADT^A01|MSG1|P|2.5\n"
           "PID|1||99999999999^^^SZP^PESEL||KOWALSKI^JAN||19850101|M\n"
           "PV1|1|I|OIOM^12^1||||99999999999")
    out, n = cs.mask_pesel(msg)
    assert n == 1
    assert "PID|1||[PESEL]^^^SZP^PESEL" in out
    assert out.endswith("PV1|1|I|OIOM^12^1||||99999999999"), "poza PID tylko z datą"


def test_a_pid_segment_on_one_line_with_the_others_ends_at_the_next_segment():
    msg = ("MSH|^~\\&|HIS|SZP|||x||ADT^A01|1|P|2.5 PID|1||99999999999^^^PESEL "
           "PV1|1|I|99999999999")
    out, n = cs.mask_pesel(msg)
    assert n == 1 and "PID|1||[PESEL]" in out and out.endswith("PV1|1|I|99999999999")


class PeselTarget(Target):
    def __init__(self):
        super().__init__()
        self.text = ("$ grep 'PID|' adt.log\n"
                     "PID|1||85010112345^^^SZP^PESEL||NOWAK^ANNA\n"
                     "$ grep -c x f\n90122412345")

    def read(self, lines):
        return self.text


def test_the_terminal_read_is_masked_and_counted(app):
    import ui.claude_panel as cp
    panel, proc = make_panel(app, PeselTarget())
    job = cp._Job(cs.TOOL_READ, {"lines": 50})
    panel._on_tool_request(job)
    text, is_error = job.result
    assert not is_error
    assert "85010112345" not in text and "90122412345" not in text
    assert text.count(cs.PESEL_MASK) == 2
    assert "zamaskowane PESEL: 2" in panel._scope.text()
    panel.end()


def test_my_own_message_is_masked_before_sending(app):
    panel, proc = make_panel(app)
    panel._input.setPlainText("co z pacjentem 85010112345?")
    panel._send()
    assert proc.sent == ["co z pacjentem [PESEL]?"]
    assert "zamaskowane PESEL: 1" in panel._scope.text()
    panel.end()


def test_live_mode_news_is_masked(app, monkeypatch):
    import ui.claude_panel as cp
    clock = [1000.0]
    monkeypatch.setattr("time.monotonic", lambda: clock[0])
    target = LiveTarget()
    panel, proc = make_panel(app, target)
    panel._btn_live.setChecked(True)
    target.text += "\nERROR: pacjent 85010112345 nie znaleziony"
    panel._live_tick()
    clock[0] += cp._LIVE_QUIET_S + 0.1
    panel._live_tick()
    assert len(proc.sent) == 1
    assert "85010112345" not in proc.sent[0] and cs.PESEL_MASK in proc.sent[0]
    panel.end()


def test_nothing_reaches_claude_without_the_mask():
    """Every send to Claude Code and the read tool's answer go through
    _mask — a new path that skips it fails here."""
    with open(os.path.join(_PARENT, "ui", "claude_panel.py"), encoding="utf-8") as f:
        tree = ast.parse(f.read())
    funcs = {n.name: n for n in ast.walk(tree) if isinstance(n, ast.FunctionDef)}
    senders = {name for name, fn in funcs.items()
               for n in ast.walk(fn) if isinstance(n, ast.Call)
               and isinstance(n.func, ast.Attribute) and n.func.attr == "send"}
    assert senders == {"_send", "_live_tick"}, senders
    for name in ("_send", "_live_tick", "_on_tool_request"):
        calls = {n.func.attr for n in ast.walk(funcs[name]) if isinstance(n, ast.Call)
                 and isinstance(n.func, ast.Attribute)}
        assert "_mask" in calls, name


def test_claude_is_told_about_the_mask():
    import ui.claude_panel as cp
    assert cs.PESEL_MASK in cp.system_prompt("x")
