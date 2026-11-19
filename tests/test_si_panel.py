"""The "SI" tab of HospitalHub Portable (owner, 2026-11-19): the Serwer
Integracji modules under /opt/asseco, docker compose actions in the start
order of the Asseco guide, root / sudo on the server.

The shell scripts themselves were run in a real bash against a fake
/opt/asseco tree (session 2026-11-19); here a fake SSH client answers with
what such a server prints."""

import os
import sys
import time

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import models  # noqa: E402
import si_docker as sd  # noqa: E402

ROOT = "/opt/asseco"

# What the scan prints on the owner's srv-si (2026-11-19), shortened.
SCAN = "\n".join([
    "@@SI-MOD\tcpi-hl7-services\tdocker-compose.yml",
    "@@SI-ENV\tcpi-hl7-services\tCOMPOSE_PROJECT_NAME=cpi-hl7-services",
    "@@SI-ENV\tcpi-hl7-services\tCPI_VERSION=1.4.65",
    "@@SI-MOD\tpi-hl7-provider\tdocker-compose.yml",
    "@@SI-ENV\tpi-hl7-provider\tPI_VERSION=1.4.0.1",
    "@@SI-MOD\tsi-aism\tdocker-compose.yml",
    "@@SI-ENV\tsi-aism\tVERSION=1.4.55",
    "@@SI-ENV\tsi-aism\tVERSION=9.9.9",
    "@@SI-MOD\tsi-aism-db\tdocker-compose.yml",
    "@@SI-MOD\tsi-aism-keycloak\tdocker-compose.yml",
    "@@SI-MOD\tsi-aism-reverse-proxy\tdocker-compose.yml",
    "@@SI-MOD\tsi-elastic-client\tdocker-compose.yml",
    "@@SI-MOD\tsi-elastic-server\tdocker-compose.yml",
    "@@SI-PS",
    "si-ai-services-container\tamms.asseco.pl/asseco-poz/si-ai-services:1.5.3.1"
    "\trunning\tUp 3 days\t/home/si/ai\tsi-ai-services",
    "pi-hl7-provider-container\tamms.asseco.pl/asseco-poz/pi-hl7-provider:1.4.0.1"
    "\trunning\tUp 2 weeks\t/opt/asseco/pi-hl7-provider\tpi-hl7-provider",
    "cpi-hl7-services-container\tamms.asseco.pl/asseco-poz/cpi-hl7-services:1.4.65"
    "\texited\tExited (1) 2 hours ago\t/opt/asseco/cpi-hl7-services\tcpi-hl7-services",
    "asi-nginx\tnginx:1.29.3-alpine\trunning\tUp 4 weeks (healthy)"
    "\t/opt/asseco/si-aism-reverse-proxy\tsi-aism-reverse-proxy",
    "asi-frontend\tamms.asseco.pl/asseco-poz/asi-frontend:1.4.55\trunning"
    "\tUp 4 weeks\t/opt/asseco/si-aism\tsi-aism",
    "asi-backend\tamms.asseco.pl/asseco-poz/asi-backend:1.4.55\trunning"
    "\tUp 4 weeks (healthy)\t/opt/asseco/si-aism/\tsi-aism",
    "asi-keycloak\tquay.io/phasetwo/phasetwo-keycloak:26.6.7\trunning"
    "\tUp 4 weeks (unhealthy)\t/opt/asseco/si-aism-keycloak\tsi-aism-keycloak",
    "asi-db\tpostgres:14.20-alpine\trunning\tUp 4 weeks (healthy)"
    "\t\tsi-aism-db",
    "kibana\tdocker.elastic.co/kibana/kibana:9.3.4\trunning\tUp 5 months (healthy)"
    "\t/opt/asseco/si-elastic-server\tsi-elastic-server",
    "",
])


# ── si_docker ────────────────────────────────────────────────────────────

def test_the_scan_gives_modules_in_start_order_with_their_containers():
    mods, other = sd.parse_scan(SCAN, ROOT)
    assert [m.name for m in mods] == [
        "si-elastic-server", "si-aism-db", "si-aism-keycloak", "si-aism",
        "si-aism-reverse-proxy", "cpi-hl7-services", "pi-hl7-provider",
        "si-elastic-client"]
    by = {m.name: m for m in mods}
    assert [c.name for c in by["si-aism"].containers] == ["asi-frontend",
                                                         "asi-backend"]
    # No working dir label: matched by the compose project.
    assert [c.name for c in by["si-aism-db"].containers] == ["asi-db"]
    assert [c.name for c in other] == ["si-ai-services-container"]


def test_versions_come_from_the_env_first_file_wins_else_the_image_tag():
    mods, _ = sd.parse_scan(SCAN, ROOT)
    by = {m.name: m for m in mods}
    assert by["si-aism"].version_text() == "1.4.55"
    assert by["cpi-hl7-services"].version_text() == "1.4.65"
    assert by["si-aism-keycloak"].version_text() == "26.6.7"
    assert by["si-elastic-client"].version_text() == ""


def test_module_state():
    mods, _ = sd.parse_scan(SCAN, ROOT)
    by = {m.name: m for m in mods}
    assert sd.module_state(by["si-aism"]) == "ok"
    assert sd.module_state(by["si-aism-keycloak"]) == "warn"   # unhealthy
    assert sd.module_state(by["cpi-hl7-services"]) == "down"
    assert sd.module_state(by["si-elastic-client"]) == "none"


def test_old_is_skipped_by_the_scan_script():
    s = sd.scan_script("/opt/asseco/")
    assert 'for d in /opt/asseco/*/' in s
    assert '" old "' in s


def test_stop_goes_backwards_and_every_module_reports_its_code():
    s = sd.action_script(ROOT, ["si-aism", "cpi-hl7-services",
                                "si-elastic-server"], "stop")
    order = [ln.split()[2] for ln in s.splitlines()
             if ln.startswith("echo @@SI-BEGIN")]
    assert order == ["cpi-hl7-services", "si-aism", "si-elastic-server"]
    assert "( cd /opt/asseco/si-aism && $DC stop ) 2>&1" in s
    assert s.count("@@SI-END") == 3
    start = sd.action_script(ROOT, ["cpi-hl7-services", "si-aism"], "start")
    assert start.index("si-aism &&") < start.index("cpi-hl7-services &&")
    assert "$DC up -d" in start


def test_unknown_action_is_refused():
    with pytest.raises(ValueError):
        sd.action_script(ROOT, ["x"], "rm -rf")


def test_markers():
    assert sd.parse_action_markers("@@SI-BEGIN si-aism") == ("begin", "si-aism")
    assert sd.parse_action_markers("@@SI-END si-aism 0\r") == ("end", "si-aism", 0)
    assert sd.parse_action_markers("Container asi-db  Stopped") is None


@pytest.mark.parametrize("probe,mode", [
    ("0\nDOCKER_OK\n", "root"),
    ("1000\nDOCKER_OK\nSUDO_N\n", "sudo-n"),
    ("1000\nDOCKER_OK\n", "docker"),
    ("1000\n", "sudo-pw"),
])
def test_privilege(probe, mode):
    assert sd.parse_privilege(probe) == mode


def test_wrap_never_puts_a_password_on_the_command_line():
    assert sd.wrap("echo hi", "root") == "sh -c 'echo hi'"
    assert sd.wrap("echo hi", "sudo-n") == "sudo -n sh -c 'echo hi'"
    w = sd.wrap("echo hi", "sudo-pw")
    assert w == "sudo -S -p '' sh -c 'echo hi'"


def test_the_si_settings_travel_with_the_hospital():
    h = models.Hospital(name="X", si={"machine": "m1", "root": "/opt/asseco"})
    d = models._hospital_to_dict(h)
    assert d["si"] == {"machine": "m1", "root": "/opt/asseco"}
    assert models._hospital_from_dict(d).si == h.si
    assert "si" not in models._hospital_to_dict(models.Hospital(name="Y"))


# ── The panel, on a fake SSH client ──────────────────────────────────────

class _Out:
    def __init__(self, text):
        self._t = text

    def read(self):
        return self._t.encode()


class _Chan:
    def __init__(self, server):
        self.s = server
        self._data = b""
        self.stdin = b""

    def set_combine_stderr(self, _):
        pass

    def exec_command(self, cmd):
        self.s.commands.append(cmd)
        if "@@SI-PS" in cmd:
            self._data = SCAN.encode()
            self._code = 0
            return
        out = []
        for ln in cmd.replace("'\"'\"'", "'").split("\n"):
            if "echo @@SI-BEGIN" in ln:
                name = ln.split("@@SI-BEGIN", 1)[1].strip().strip("'")
                code = self.s.codes.get(name, 0)
                out += [f"@@SI-BEGIN {name}", f" Container {name}  done",
                        f"@@SI-END {name} {code}"]
        self._data = ("\n".join(out) + "\n").encode()
        self._code = 0

    def sendall(self, b):
        self.stdin += b
        self.s.stdin.append(b)

    def shutdown_write(self):
        pass

    def recv(self, n):
        d, self._data = self._data[:n], self._data[n:]
        return d

    def recv_exit_status(self):
        return self._code

    def close(self):
        pass


class _Transport:
    def __init__(self, server):
        self.s = server

    def open_session(self):
        return _Chan(self.s)


class FakeServer:
    def __init__(self, probe="0\nDOCKER_OK\n"):
        self.probe = probe
        self.commands = []
        self.stdin = []
        self.codes = {}
        self.logins = []

    def factory(self, host, user, pw, port):
        self.logins.append((host, user, pw, port))
        server = self

        class Client:
            def exec_command(self, cmd, timeout=None):
                server.commands.append(cmd)
                return None, _Out(server.probe), None

            def get_transport(self):
                return _Transport(server)

            def close(self):
                pass
        return Client()


@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


def pump_until(cond, timeout=5.0):
    from PyQt6.QtWidgets import QApplication
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        QApplication.processEvents()
        if cond():
            return True
        time.sleep(0.01)
    return False


def _hospital(si=None):
    m = models.Machine(ip="10.1.1.5", name="srv-si",
                       credentials=[models.Credential(login="root",
                                                      password="tajne")])
    rdp = models.Machine(ip="10.1.1.6", name="win", connection_type="RDP")
    return models.Hospital(name="Szpital", machines=[m, rdp],
                           si=si if si is not None else {"machine": m.id, "root": ROOT}), m


def _panel(app, server, si=None):
    from ui.si_panel import SiPanel
    h, m = _hospital(si)
    p = SiPanel(h, client_factory=server.factory)
    p.resize(360, 700)
    p.show()
    return p, h, m


def _idle(p):
    return pump_until(lambda: not p.busy(), 8)


def test_only_ssh_machines_and_the_saved_one_is_chosen(app):
    srv = FakeServer()
    p, h, m = _panel(app, srv)
    labels = [p._machine.itemText(i) for i in range(p._machine.count())]
    assert labels == ["— wybierz maszynę —", "10.1.1.5  (srv-si)"]
    assert p.current_machine() is m


def test_refresh_fills_the_tree(app):
    srv = FakeServer()
    p, h, m = _panel(app, srv)
    p.scan()
    assert _idle(p)
    assert srv.logins == [("10.1.1.5", "root", "tajne", 22)]
    top = [p._tree.topLevelItem(i).text(0) for i in range(p._tree.topLevelItemCount())]
    assert top[0] == "si-elastic-server"
    assert top[-1] == "Inne kontenery (1)"
    assert "root" in p._info.text() and "modułów: 8" in p._info.text()
    assert srv.commands[-1].startswith("sh -c ")


def test_stop_asks_runs_backwards_marks_each_module_and_reads_again(
        app, monkeypatch):
    import ui.si_panel as sp
    srv = FakeServer()
    srv.codes["si-aism"] = 1
    p, h, m = _panel(app, srv)
    p.scan()
    assert _idle(p)
    asked = []
    monkeypatch.setattr(sp, "confirm",
                        lambda parent, title, text, **k: asked.append(text) or True)
    for i in range(p._tree.topLevelItemCount()):
        it = p._tree.topLevelItem(i)
        if it.text(0) in ("si-aism", "cpi-hl7-services", "si-aism-db"):
            it.setCheckState(0, sp.Qt.CheckState.Checked)
    p.run_action("stop")
    assert asked and asked[0].index("cpi-hl7-services") < asked[0].index("si-aism-db")
    assert pump_until(lambda: "koniec" in p._out.toPlainText(), 8)
    out = p._out.toPlainText()
    assert "✓ cpi-hl7-services: OK" in out
    assert "✗ si-aism: kod 1" in out
    assert "błędy: si-aism" in out
    assert pump_until(lambda: sum("@@SI-PS" in c for c in srv.commands) == 2, 8)
    assert _idle(p)


def test_declining_the_question_runs_nothing(app, monkeypatch):
    import ui.si_panel as sp
    srv = FakeServer()
    p, h, m = _panel(app, srv)
    p.scan()
    assert _idle(p)
    p._tree.setCurrentItem(p._tree.topLevelItem(0))
    monkeypatch.setattr(sp, "confirm", lambda *a, **k: False)
    n = len(srv.commands)
    p.run_action("restart")
    assert not p.busy() and len(srv.commands) == n


def test_pull_needs_no_question(app, monkeypatch):
    import ui.si_panel as sp
    srv = FakeServer()
    p, h, m = _panel(app, srv)
    p.scan()
    assert _idle(p)
    p._tree.setCurrentItem(p._tree.topLevelItem(3))       # si-aism
    monkeypatch.setattr(sp, "confirm",
                        lambda *a, **k: pytest.fail("pull asked"))
    p.run_action("pull")
    assert pump_until(lambda: "koniec" in p._out.toPlainText(), 8)
    assert any("$DC pull" in c for c in srv.commands)


def test_sudo_with_a_password_sends_it_on_stdin_only(app):
    srv = FakeServer(probe="1000\n")
    p, h, m = _panel(app, srv)
    p.scan()
    assert _idle(p)
    assert srv.stdin == [b"tajne\n"]
    assert all("tajne" not in c for c in srv.commands)
    assert srv.commands[-1].startswith("sudo -S -p '' sh -c ")
    assert "sudo (hasło z vaulta)" in p._info.text()


def test_sudo_without_a_password_in_the_vault_stops_with_a_message(app):
    srv = FakeServer(probe="1000\n")
    from ui.si_panel import SiPanel
    m = models.Machine(ip="10.1.1.5", name="srv-si",
                       credentials=[models.Credential(login="si", password="")])
    h = models.Hospital(name="S", machines=[m], si={"machine": m.id})
    p = SiPanel(h, client_factory=srv.factory)
    p.scan()
    assert _idle(p)
    assert "sudo wymaga hasła" in p._info.text()


def test_choosing_a_machine_is_saved_with_the_hospital(app):
    srv = FakeServer()
    p, h, m = _panel(app, srv, si={})
    assert p.current_machine() is None
    saved = []
    p.data_changed.connect(lambda: saved.append(dict(h.si)))
    p._machine.setCurrentIndex(1)
    assert saved[-1] == {"machine": m.id, "root": ROOT}
    p._root.setText("/opt/asseco2/")
    p._root.editingFinished.emit()
    assert h.si == {"machine": m.id, "root": "/opt/asseco2"}


def test_follow_gives_every_ticked_module_its_command(app):
    import ui.si_panel as sp
    srv = FakeServer()
    p, h, m = _panel(app, srv)
    p.scan()
    assert _idle(p)
    got = []
    p.follow_requested.connect(lambda mach, items: got.append((mach, items)))
    for i in range(p._tree.topLevelItemCount()):
        it = p._tree.topLevelItem(i)
        if it.text(0) in ("cpi-hl7-services", "si-aism"):
            it.setCheckState(0, sp.Qt.CheckState.Checked)
    p._follow()
    assert got == [(m, [
        ("si-aism", "cd /opt/asseco/si-aism && docker compose logs -f --tail=100"),
        ("cpi-hl7-services",
         "cd /opt/asseco/cpi-hl7-services && docker compose logs -f --tail=100"),
    ])]


def test_after_start_the_logs_open_for_the_modules_that_started(app):
    import ui.si_panel as sp
    srv = FakeServer()
    srv.codes["cpi-hl7-services"] = 1
    p, h, m = _panel(app, srv)
    p.scan()
    assert _idle(p)
    got = []
    p.follow_requested.connect(lambda mach, items: got.append([n for n, _ in items]))
    for i in range(p._tree.topLevelItemCount()):
        it = p._tree.topLevelItem(i)
        if it.text(0) in ("cpi-hl7-services", "si-aism"):
            it.setCheckState(0, sp.Qt.CheckState.Checked)
    p.run_action("start")
    assert pump_until(lambda: bool(got), 8)
    assert got == [["si-aism"]]           # the failed one gets no tab
    assert _idle(p)


def test_switching_the_auto_logs_off_is_saved_and_respected(app):
    import ui.si_panel as sp
    srv = FakeServer()
    p, h, m = _panel(app, srv)
    p._auto_follow.setChecked(False)
    assert h.si.get("follow_after") is False
    p.scan()
    assert _idle(p)
    got = []
    p.follow_requested.connect(lambda *a: got.append(a))
    p._tree.setCurrentItem(p._tree.topLevelItem(3))
    p.run_action("start")
    assert pump_until(lambda: "koniec" in p._out.toPlainText(), 8)
    assert _idle(p)
    assert got == []


def test_sudo_follow_puts_sudo_before_docker(app):
    srv = FakeServer(probe="1000\nSUDO_N\n")
    p, h, m = _panel(app, srv)
    p.scan()
    assert _idle(p)
    assert p.follow_command("si-aism") == (
        "cd /opt/asseco/si-aism && sudo docker compose logs -f --tail=100")


# ── The window: one terminal tab per module ──────────────────────────────

class _FakeWorker:
    def __init__(self):
        self.sent = []
        self._channel = object()

    def send(self, data):
        self.sent.append(data)


@pytest.fixture
def window(app, tmp_path):
    from crypto import encrypt
    from ui.remote_window import RemoteWindow
    h, m = _hospital()
    path = tmp_path / "s.vault"
    path.write_bytes(encrypt(models.to_dict([h]), "p"))
    w = RemoteWindow(str(path), "p", models.from_dict(models.to_dict([h])))
    opened = []

    def fake_add(label="", ip="", user="", password="", is_first=False,
                 port=22, machine=None):
        class S:
            is_rdp = False
            reconnecting = False
        s = S()
        s.label, s.machine, s.worker = label, machine, _FakeWorker()
        s.pane = None
        w._sessions.append(s)
        opened.append((label, ip, user, port))
    w._add_session = fake_add
    w._send_one = lambda s, data, ctrl: s.worker.sent.append(data)
    w._opened = opened
    yield w
    w._sessions.clear()
    w.close_without_asking()
    pump_until(lambda: False, 0.05)


def test_one_tab_per_module_then_the_same_tabs_again(window):
    m = window._hospital.machines[0]
    items = [("si-aism", "cmd-a"), ("cpi-hl7-services", "cmd-b")]
    window._si_follow(m, items)
    assert [o[0] for o in window._opened] == ["SI: si-aism",
                                              "SI: cpi-hl7-services"]
    assert window._opened[0][1:] == ("10.1.1.5", "root", 22)
    assert pump_until(lambda: all(s.worker.sent for s in window._sessions), 3)
    a, b = window._sessions
    assert a.worker.sent == [b"cmd-a\r"] and b.worker.sent == [b"cmd-b\r"]
    # Again: no new tabs — Ctrl+C and the tail from the start.
    window._si_follow(m, items)
    assert len(window._opened) == 2
    assert pump_until(lambda: len(a.worker.sent) == 3, 3)
    assert a.worker.sent[1:] == [b"\x03", b"cmd-a\r"]


def test_a_closed_module_tab_is_opened_again(window):
    m = window._hospital.machines[0]
    window._si_follow(m, [("si-aism", "c")])
    s = window._sessions[0]
    window._sessions.remove(s)
    window._si_follow(m, [("si-aism", "c")])
    assert len(window._opened) == 2


def test_upgrade_commands_never_go_to_a_log_tab(window):
    m = window._hospital.machines[0]
    window._si_follow(m, [("si-aism", "c")])
    assert window._session_for(m) is None


def test_one_off_jobs_that_ended_with_0_are_not_a_warning():
    """Owner's srv-si, 2026-11-19: elasticsearch-before/-after, kibana-after,
    asi-liquibase, asi-keycloak-config… run once and exit 0."""
    C = sd.Container
    elastic = sd.Module("si-elastic-server", containers=[
        C("kibana-after", "x:latest", "exited", "Exited (0) 5 months ago"),
        C("kibana", "x:9.3.4", "running", "Up 5 months (healthy)"),
        C("elasticsearch-before", "x:1.37.0", "exited", "Exited (0) 5 months ago"),
        C("elasticsearch", "x:9.3.4", "running", "Up 5 months (healthy)"),
    ])
    assert sd.module_state(elastic) == "ok"
    assert elastic.containers[0].finished_ok and elastic.containers[0].exit_code == 0
    aism = sd.Module("si-aism", containers=[
        C("asi-frontend", "x:1.4.55", "running", "Up 4 weeks"),
        C("asi-liquibase", "x:1.4.55", "exited", "Exited (1) 4 weeks ago"),
    ])
    assert sd.module_state(aism) == "warn"
    only_job = sd.Module("x", containers=[
        C("job", "x:1", "exited", "Exited (0) 1 day ago")])
    assert sd.module_state(only_job) == "down"


# ── Before an upgrade: stop, then a copy in old/ (owner, 2026-11-19) ─────

def test_stop_archive_stops_backwards_then_copies_every_folder():
    s = sd.action_script(ROOT, ["si-aism", "cpi-hl7-services"], "stop_archive")
    begins = [ln.split()[2] for ln in s.splitlines()
              if ln.startswith("echo @@SI-BEGIN")]
    assert begins == ["cpi-hl7-services", "si-aism",
                      "cpi-hl7-services@old", "si-aism@old"]
    assert "$DC stop" in s
    # Outside /opt/asseco, which keeps only the production modules.
    assert "mkdir -p /opt/old" in s
    assert "cp -a /opt/asseco/si-aism /opt/old/si-aism_\"$STAMP\"" in s
    assert "/opt/asseco/old" not in s
    # A copy, never a move or a delete: the folders hold the containers' data.
    for word in (" mv ", "rm -", "rmdir"):
        assert word not in s
    assert "exit 3" in s                      # an existing archive is kept


def test_the_archive_button_asks_and_says_what_comes_next(app, monkeypatch):
    import ui.si_panel as sp
    srv = FakeServer()
    p, h, m = _panel(app, srv)
    p.scan()
    assert _idle(p)
    asked = []
    monkeypatch.setattr(sp, "confirm",
                        lambda parent, title, text, **k: asked.append(text) or True)
    for i in range(p._tree.topLevelItemCount()):
        it = p._tree.topLevelItem(i)
        if it.text(0) in ("si-aism", "cpi-hl7-services"):
            it.setCheckState(0, sp.Qt.CheckState.Checked)
    got = []
    p.follow_requested.connect(lambda *a: got.append(a))
    p.run_action("stop_archive")
    assert asked and "/opt/old/" in asked[0]
    assert "/opt/asseco/si-aism  →  /opt/old/si-aism_<data-godzina>" in asked[0]
    assert pump_until(lambda: "koniec" in p._out.toPlainText(), 8)
    out = p._out.toPlainText()
    assert "✓ si-aism: zarchiwizowany" in out
    assert "✓ cpi-hl7-services: zarchiwizowany" in out
    assert "Odśwież → Pobierz → Uruchom" in out
    assert got == []                          # no log tabs for a stop
    assert _idle(p)


def test_an_archive_of_the_same_minute_is_reported(app, monkeypatch):
    import ui.si_panel as sp
    srv = FakeServer()
    srv.codes["si-aism@old"] = 3
    p, h, m = _panel(app, srv)
    p.scan()
    assert _idle(p)
    monkeypatch.setattr(sp, "confirm", lambda *a, **k: True)
    p._tree.setCurrentItem(p._tree.topLevelItem(3))       # si-aism
    p.run_action("stop_archive")
    assert pump_until(lambda: "koniec" in p._out.toPlainText(), 8)
    assert "archiwum już istnieje" in p._out.toPlainText()
    assert "Odśwież → Pobierz" not in p._out.toPlainText()
    assert _idle(p)


# ── Base modules start one after another, each once the one before is up ─
# (owner, 2026-11-19; AISM guide 5.4: db → keycloak → aism → nginx, "Up
# (healthy)", one-off containers "Exited (0)").  The script itself was run
# in a real bash with a fake docker: db waited for healthy, keycloak exited
# 1 → 12, aism and the HL7 module → 4 (skipped).

def test_start_waits_after_each_base_module_but_not_after_services():
    s = sd.action_script(ROOT, ["cpi-hl7-services", "si-aism", "si-aism-db",
                                "pi-hl7-provider"], "start")
    lines = s.splitlines()
    assert "si_wait() {" in s and f"SI_WAIT_MAX={sd.WAIT_MAX}" in s
    body = {ln.split("@@SI-END ")[1].split()[0]: ln for ln in lines
            if "( cd /opt/asseco/" in ln}
    assert "si_wait /opt/asseco/si-aism-db" in body["si-aism-db"]
    assert "si_wait /opt/asseco/si-aism" in body["si-aism"]
    assert "si_wait" not in body["cpi-hl7-services"]
    assert "si_wait" not in body["pi-hl7-provider"]
    assert all('"$SI_SKIP" = 1' in ln for ln in body.values())
    begins = [ln.split()[2] for ln in lines if ln.startswith("echo @@SI-BEGIN")]
    assert begins == ["si-aism-db", "si-aism", "cpi-hl7-services",
                      "pi-hl7-provider"]


def test_the_last_base_module_is_not_waited_for():
    s = sd.action_script(ROOT, ["si-aism-db"], "start")
    assert "si_wait /opt" not in s


def test_a_base_module_that_did_not_come_up_is_told_and_the_rest_skipped(
        app):
    srv = FakeServer()
    srv.codes["si-aism-keycloak"] = 12
    srv.codes["si-aism"] = sd.SKIPPED
    p, h, m = _panel(app, srv)
    p.scan()
    assert _idle(p)
    import ui.si_panel as sp
    for i in range(p._tree.topLevelItemCount()):
        it = p._tree.topLevelItem(i)
        if it.text(0) in ("si-aism-keycloak", "si-aism"):
            it.setCheckState(0, sp.Qt.CheckState.Checked)
    got = []
    p.follow_requested.connect(lambda mach, items: got.append(items))
    p.run_action("start")
    assert pump_until(lambda: "koniec" in p._out.toPlainText(), 8)
    out = p._out.toPlainText()
    assert "✗ si-aism-keycloak: kontener zakończył się błędem" in out
    assert "– si-aism: pominięty" in out
    assert got == []                       # nothing came up: no log tabs
    assert _idle(p)


def test_running_but_unhealthy_warns_and_the_start_goes_on():
    """Owner's asi-keycloak works while "Up (unhealthy)": after the grace
    time it is a warning (14), not a stop.  Real bash run 2026-11-19: db
    ready, keycloak 60 s → 14, aism and the HL7 module started."""
    s = sd.action_script(ROOT, ["si-aism-keycloak", "si-aism"], "start")
    assert "running/unhealthy/*) unh=1" in s
    assert f"SI_UNHEALTHY_GRACE={sd.UNHEALTHY_GRACE}" in s
    kc = next(ln for ln in s.splitlines() if "@@SI-END si-aism-keycloak" in ln)
    assert f'if [ "$w" = 4 ]; then rc={sd.RUNNING_UNHEALTHY}; elif' in kc


def test_the_panel_shows_unhealthy_as_a_warning_and_follows_its_logs(app):
    srv = FakeServer()
    srv.codes["si-aism-keycloak"] = sd.RUNNING_UNHEALTHY
    p, h, m = _panel(app, srv)
    p.scan()
    assert _idle(p)
    import ui.si_panel as sp
    for i in range(p._tree.topLevelItemCount()):
        it = p._tree.topLevelItem(i)
        if it.text(0) in ("si-aism-keycloak", "si-aism"):
            it.setCheckState(0, sp.Qt.CheckState.Checked)
    got = []
    p.follow_requested.connect(lambda mach, items: got.append([n for n, _ in items]))
    p.run_action("start")
    assert pump_until(lambda: "koniec" in p._out.toPlainText(), 8)
    out = p._out.toPlainText()
    assert "⚠ si-aism-keycloak: działa, ale unhealthy" in out
    assert "uwaga (unhealthy): si-aism-keycloak" in out and "błędy" not in out
    assert got == [["si-aism-keycloak", "si-aism"]]
    assert _idle(p)
