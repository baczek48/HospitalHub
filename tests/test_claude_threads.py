"""2026-11-13: saved "Wsparcie Claude" conversations (threads).

The owner: "if I want, remember a conversation as a thread — a click, it gets
a name from the content, and I can return to it from a list".  No real Claude
Code is started; Claude Code's record folder is a temporary one.
"""

import os
import sys
import threading

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import claude_support as cs  # noqa: E402
import claude_threads as ct  # noqa: E402

SID = "0f1e2d3c-4b5a-4987-8765-43210fedcba9"


@pytest.fixture
def records(tmp_path, monkeypatch):
    """A fake ~/.claude/projects with one record of SID."""
    root = tmp_path / "claude_cfg"
    folder = root / "projects" / "C--HH-claude-work"
    folder.mkdir(parents=True)
    (folder / f"{SID}.jsonl").write_text("{}", encoding="utf-8")
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(root))
    return folder


@pytest.fixture
def store(tmp_path):
    return ct.ThreadStore(tmp_path / "hh", key=os.urandom(32))


@pytest.fixture(autouse=True)
def _settings(monkeypatch):
    """Settings are the defaults (screens stripped, 30 days), whatever the
    user's own config says."""
    import config
    monkeypatch.setattr(config, "load_claude_strip_screens", lambda: True)
    monkeypatch.setattr(config, "load_claude_thread_days", lambda: 30)
    ct.LIVE_SESSIONS.clear()
    yield
    ct.LIVE_SESSIONS.clear()


# ══════════════════════════════════════════════════════════════════════════
# Claude Code keeps a record only under our id
# ══════════════════════════════════════════════════════════════════════════

def _cmd(**kw):
    p = cs.ClaudeProcess("http://127.0.0.1:1/mcp", "t", "x", lambda *a: None, **kw)
    return p.command("claude.exe", r"C:\tmp\hh")


def test_without_an_id_nothing_is_kept():
    cmd = _cmd()
    assert "--no-session-persistence" in cmd
    assert "--resume" not in cmd and "--session-id" not in cmd


def test_a_new_conversation_runs_under_our_id_and_a_saved_one_resumes():
    cmd = _cmd(session_id=SID)
    assert cmd[cmd.index("--session-id") + 1] == SID
    assert "--no-session-persistence" not in cmd
    cmd = _cmd(session_id=SID, resume=True)
    assert cmd[cmd.index("--resume") + 1] == SID
    # Still no built-in tools and only our server, resumed or not.
    assert cmd[cmd.index("--tools") + 1] == "" and "--strict-mcp-config" in cmd
    assert cmd[cmd.index("--permission-mode") + 1] == "dontAsk"


def test_the_process_runs_in_the_fixed_folder(tmp_path):
    seen = {}

    class Proc:
        stdin = stdout = stderr = None

    def spawn(cmd, **kw):
        seen.update(kw)
        return Proc()

    p = cs.ClaudeProcess("u", "t", "x", lambda *a: None, executable="claude.exe",
                         spawn=spawn, session_id=SID, cwd=str(tmp_path))
    p.start()
    assert seen["cwd"] == str(tmp_path)
    p.stop()


# ══════════════════════════════════════════════════════════════════════════
# The list, and what is forgotten
# ══════════════════════════════════════════════════════════════════════════

def test_save_rename_list_and_delete(store, records):
    store.save(SID, title="Procesy HL7 LAB", kind="screen", label="192.0.2.44",
               messages=[{"who": "user", "text": "co tu widać?"}])
    [t] = store.threads()
    assert t["title"] == "Procesy HL7 LAB" and t["kind"] == "screen"
    assert t["messages"][0]["text"] == "co tu widać?"
    store.rename(SID, "  Nowa nazwa ")
    assert store.get(SID)["title"] == "Nowa nazwa"
    store.delete(SID)
    assert store.threads() == []
    assert not (records / f"{SID}.jsonl").exists(), "zapis Claude Code też znika"


def test_an_unsaved_conversation_leaves_no_record(store, records):
    store.started(SID)
    store.finished(SID)
    assert not (records / f"{SID}.jsonl").exists()


def test_a_saved_conversation_is_sealed_and_opens_again(store, records, tmp_path):
    (records / f"{SID}.jsonl").write_text('{"x": "KALAFIOR"}\n', encoding="utf-8")
    store.started(SID)
    store.save(SID, title="x", kind="terminal", label="srv", messages=[])
    store.finished(SID)
    assert not (records / f"{SID}.jsonl").exists(), "jawny zapis znika"
    blob = (tmp_path / "hh" / "claude_records" / f"{SID}.enc").read_bytes()
    assert b"KALAFIOR" not in blob
    assert store.open_record(SID)
    assert "KALAFIOR" in (records / f"{SID}.jsonl").read_text(encoding="utf-8")


def test_a_crash_leftover_is_swept_but_not_a_running_one(store, records):
    other = "11111111-2222-4333-8444-555555555555"
    (records / f"{other}.jsonl").write_text("{}", encoding="utf-8")
    store.started(SID)
    store.started(other)
    store.sweep(keep={other})
    assert not (records / f"{SID}.jsonl").exists()
    assert (records / f"{other}.jsonl").exists()


def test_only_an_id_finds_a_record(records):
    assert ct.record_path(SID) is not None
    assert ct.record_path("../../etc") is None
    assert ct.record_path("*") is None


def test_a_damaged_list_reads_as_empty(tmp_path):
    (tmp_path / "claude_threads.enc").write_bytes(b"HHT1" + b"x" * 40)
    assert ct.ThreadStore(tmp_path, key=os.urandom(32)).threads() == []


# ══════════════════════════════════════════════════════════════════════════
# A name from the content
# ══════════════════════════════════════════════════════════════════════════

def test_the_title_comes_from_claude_and_falls_back_to_the_question():
    msgs = [{"who": "user", "text": "dlaczego proces LAB nie loguje od 10:55?"},
            {"who": "claude", "text": "Ostatni wpis jest z 10:55:11…"}]

    class R:
        returncode, stdout = 0, '  „Przestój procesu LAB po 10:55”.\n'

    seen = {}

    def run(cmd, **kw):
        seen["cmd"], seen["input"] = cmd, kw["input"]
        return R()

    title = ct.make_title(msgs, "192.0.2.44", executable="claude.exe", run=run)
    assert title == "Przestój procesu LAB po 10:55"
    assert "--no-session-persistence" in seen["cmd"] and seen["cmd"][seen["cmd"].index("--tools") + 1] == ""
    assert "proces LAB" in seen["input"]

    def broken(cmd, **kw):
        raise OSError

    assert ct.make_title(msgs, "x", executable="claude.exe", run=broken) == \
        "dlaczego proces LAB nie loguje od 10:55?"
    assert ct.fallback_title([]).startswith("Rozmowa ")


# ══════════════════════════════════════════════════════════════════════════
# The panel
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def app():
    from PyQt6.QtWidgets import QApplication
    return QApplication.instance() or QApplication([])


class Target:
    def label(self):
        return "10.0.60.225 (srvDB)"

    def alive(self):
        return True

    def read(self, lines):
        return "ok"


class FakeServer:
    def __init__(self, handler, tools=None):
        self.token = "t"

    def start(self):
        return "http://127.0.0.1:1/mcp"

    def stop(self):
        pass


class FakeProcess:
    instances = []

    def __init__(self, url, token, prompt, on_event, **kw):
        self.kw, self.sent = kw, []
        FakeProcess.instances.append(self)

    def start(self):
        pass

    def send(self, text):
        self.sent.append(text)

    def stop(self):
        pass


def make(store, thread=None, title="Nazwa z treści"):
    from ui.claude_panel import ClaudeSupportPanel
    FakeProcess.instances.clear()
    panel = ClaudeSupportPanel(Target(), process_factory=FakeProcess,
                               server_factory=FakeServer,
                               find_claude=lambda: "claude.exe", store=store,
                               thread=thread, title_maker=lambda m, l: title)
    assert panel.start()
    return panel, FakeProcess.instances[0]


def pump(cond):
    from PyQt6.QtWidgets import QApplication
    for _ in range(100):
        QApplication.processEvents()
        if cond():
            return True
        threading.Event().wait(0.01)
    return False


def test_zapamietaj_saves_the_thread_and_names_it(app, store, monkeypatch, tmp_path):
    monkeypatch.setattr(ct, "workdir", lambda: str(tmp_path))
    panel, proc = make(store)
    assert proc.kw["session_id"] and proc.kw["resume"] is False
    assert proc.kw["cwd"] == str(tmp_path)
    panel._input.setPlainText("sprawdź docker compose")
    panel._send()
    panel._on_process_event("text", "Kontener asi-backend nie działa.")
    panel._on_process_event("turn_end", {"is_error": False})
    panel._save_thread()
    assert pump(lambda: store.get(proc.kw["session_id"])["title"] == "Nazwa z treści")
    t = store.get(proc.kw["session_id"])
    assert [m["who"] for m in t["messages"]] == ["user", "claude"]
    assert not panel._btn_save.isEnabled() and "Nazwa z treści" in panel._thread_lbl.text()
    # A later answer reaches the saved thread too.
    panel._on_process_event("text", "Sprawdź logi.")
    panel._on_process_event("turn_end", {"is_error": False})
    assert len(store.get(proc.kw["session_id"])["messages"]) == 3
    panel.end()


def test_a_saved_thread_resumes_with_its_history(app, store, records, monkeypatch,
                                                 tmp_path):
    monkeypatch.setattr(ct, "workdir", lambda: str(tmp_path))
    thread = store.save(SID, title="Procesy LAB", kind="terminal", label="srv",
                        messages=[{"who": "user", "text": "pytanie"},
                                  {"who": "claude", "text": "odpowiedź"}])
    panel, proc = make(store, thread)
    assert proc.kw == {"session_id": SID, "resume": True, "cwd": str(tmp_path)}
    from PyQt6.QtWidgets import QLabel
    texts = " ".join(l.text() for l in panel.findChildren(QLabel))
    assert "pytanie" in texts and "Wznowiono wątek" in texts
    assert len(panel._log) == 2, "historia nie podwaja się"
    panel.end()
    assert store.get(SID) is not None


def test_an_unsaved_conversation_cannot_be_saved_after_the_end(app, store, monkeypatch,
                                                               tmp_path):
    monkeypatch.setattr(ct, "workdir", lambda: str(tmp_path))
    panel, _ = make(store)
    panel.end()
    assert not panel._btn_save.isEnabled()
    panel._save_thread()
    assert store.threads() == []


# ══════════════════════════════════════════════════════════════════════════
# Encrypted (2026-11-13): the vault's password unlocks, into memory only
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture
def keyring(tmp_path, monkeypatch):
    """The module's key state, empty, for one test."""
    monkeypatch.setitem(ct._STATE, "key", None)
    monkeypatch.setitem(ct._STATE, "owners", set())
    return tmp_path / "hh"


def _saved_thread(root, records):
    store = ct.ThreadStore(root)
    (records / f"{SID}.jsonl").write_text('{"t": "PACJENT"}\n', encoding="utf-8")
    store.started(SID)
    store.save(SID, title="Procesy LAB", kind="screen", label="192.0.2.44",
               messages=[{"who": "user", "text": "Kowalski Jan na liście?"}])
    store.finished(SID)
    return store


def test_nothing_of_a_thread_is_readable_on_disk(keyring, records):
    assert ct.unlock("C:/v/szpitale.vault", "tajne", root=keyring)
    _saved_thread(keyring, records)
    for f in keyring.rglob("*"):
        if f.is_file():
            raw = f.read_bytes()
            assert b"Kowalski" not in raw and b"PACJENT" not in raw \
                and b"Procesy LAB" not in raw, f.name
    assert not list(records.glob("*.jsonl"))


def test_locked_without_the_vault_and_open_with_its_password(keyring, records):
    assert ct.unlock("C:/v/szpitale.vault", "tajne", owner="w1", root=keyring)
    _saved_thread(keyring, records)
    ct.release("w1")
    store = ct.ThreadStore(keyring)
    assert not store.unlocked and store.threads() == []
    with pytest.raises(ct.ThreadsLocked):
        store.save(SID, title="x", kind="screen", label="x", messages=[])
    assert not ct.unlock("C:/v/szpitale.vault", "zle-haslo", root=keyring)
    assert not store.unlocked
    # The same password, the vault moved elsewhere: still its key.
    assert ct.unlock("D:/nowe/szpitale.vault", "tajne", root=keyring)
    assert [t["title"] for t in store.threads()] == ["Procesy LAB"]


def test_a_changed_password_takes_over_and_the_old_one_stops(keyring, records):
    assert ct.unlock("C:/v/a.vault", "stare", owner="w", root=keyring)
    _saved_thread(keyring, records)
    assert ct.unlock("C:/v/a.vault", "nowe", owner="w", root=keyring)
    ct.release("w")
    assert not ct.unlock("C:/v/a.vault", "stare", root=keyring)
    assert ct.unlock("C:/v/a.vault", "nowe", root=keyring)
    assert ct.ThreadStore(keyring).get(SID)["title"] == "Procesy LAB"


def test_a_second_vault_gets_the_same_key_while_one_is_open(keyring, records):
    assert ct.unlock("C:/v/a.vault", "a", owner="a", root=keyring)
    _saved_thread(keyring, records)
    assert ct.unlock("C:/v/b.vault", "b", owner="b", root=keyring)
    ct.release("a")
    assert ct.is_unlocked(), "okno vaulta b nadal otwarte"
    ct.release("b")
    assert not ct.is_unlocked()
    assert ct.unlock("C:/v/b.vault", "b", root=keyring)
    assert ct.ThreadStore(keyring).get(SID) is not None


def test_the_2030_plain_list_is_taken_over_encrypted(keyring, records):
    import json as _json
    keyring.mkdir(parents=True)
    (keyring / "claude_threads.json").write_text(_json.dumps({"threads": [
        {"id": SID, "title": "Stary wątek", "kind": "terminal", "label": "srv",
         "updated": "2099-01-01T00:00:00", "messages": []}], "pending": []}),
        encoding="utf-8")
    assert ct.unlock("C:/v/a.vault", "a", root=keyring)
    assert not (keyring / "claude_threads.json").exists()
    assert not (records / f"{SID}.jsonl").exists(), "zapis zaszyfrowany"
    store = ct.ThreadStore(keyring)
    assert store.get(SID)["title"] == "Stary wątek"
    assert store.open_record(SID)


def test_screenshots_are_taken_out_of_a_sealed_record(store, records):
    import json as _json
    image = {"type": "image", "source": {"type": "base64", "media_type": "image/png",
                                         "data": "UEVTRUw="}}
    line = {"type": "user", "message": {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "t1", "content": [image]}]},
        "toolUseResult": [{"type": "image", "data": "UEVTRUw=", "mimeType": "image/png"}]}
    (records / f"{SID}.jsonl").write_text(_json.dumps(line) + "\n", encoding="utf-8")
    extra = records / SID / "tool-results"
    extra.mkdir(parents=True)
    (extra / "shot.png").write_bytes(b"\x89PNG")
    (extra / "notes.txt").write_text("zostaje", encoding="utf-8")
    store.started(SID)
    store.save(SID, title="x", kind="screen", label="x", messages=[])
    store.finished(SID)
    assert store.open_record(SID)
    text = (records / f"{SID}.jsonl").read_text(encoding="utf-8")
    assert "UEVTRUw=" not in text and ct.SCREEN_REMOVED in text
    back = _json.loads(text)
    assert back["message"]["content"][0]["content"][0]["type"] == "text"
    assert not (extra / "shot.png").exists()
    assert (extra / "notes.txt").read_text(encoding="utf-8") == "zostaje"


def test_screenshots_stay_when_the_owner_wants_them(store, records, monkeypatch):
    import config
    monkeypatch.setattr(config, "load_claude_strip_screens", lambda: False)
    (records / f"{SID}.jsonl").write_text('{"type": "image", "data": "QQ=="}\n',
                                          encoding="utf-8")
    store.started(SID)
    store.save(SID, title="x", kind="screen", label="x", messages=[])
    store.finished(SID)
    store.open_record(SID)
    assert "QQ==" in (records / f"{SID}.jsonl").read_text(encoding="utf-8")


def test_threads_past_their_days_are_deleted(store, records):
    from datetime import datetime, timedelta
    store.save(SID, title="stary", kind="terminal", label="x", messages=[])
    later = datetime.now() + timedelta(days=31)
    assert store.expire(30, now=later) == 1
    assert store.threads() == []
    assert store.expire(0) == 0


def test_a_running_conversation_is_never_sealed_or_expired(store, records):
    from datetime import datetime, timedelta
    store.started(SID, saved=True)
    store.save(SID, title="x", kind="terminal", label="x", messages=[])
    ct.LIVE_SESSIONS.add(SID)
    store.finished(SID)
    store.sweep()
    assert (records / f"{SID}.jsonl").exists()
    assert store.expire(30, now=datetime.now() + timedelta(days=99)) == 0


def test_a_locked_sweep_keeps_a_saved_record_for_later(tmp_path, records, monkeypatch):
    monkeypatch.setitem(ct._STATE, "key", None)
    locked = ct.ThreadStore(tmp_path / "hh")
    locked.started(SID, saved=True)
    locked.sweep()
    assert (records / f"{SID}.jsonl").exists(), "nie kasować zapisanej rozmowy"
    other = "11111111-2222-4333-8444-555555555555"
    (records / f"{other}.jsonl").write_text("{}", encoding="utf-8")
    locked.started(other)
    locked.sweep()
    assert not (records / f"{other}.jsonl").exists(), "niezapisana znika i tak"


def test_a_tampered_record_never_writes_outside_claude_folder(store, records, tmp_path):
    import json as _json
    plain = _json.dumps({"folder": "..", "jsonl": "x", "files": {}}).encode()
    blob = ct._seal_bytes(store.key, plain, SID.encode())
    path = tmp_path / "hh" / "claude_records" / f"{SID}.enc"
    path.parent.mkdir(parents=True)
    (records / f"{SID}.jsonl").unlink()
    path.write_bytes(blob)
    assert store.open_record(SID) is False


def test_zapamietaj_while_locked_says_so(app, tmp_path, monkeypatch):
    monkeypatch.setitem(ct._STATE, "key", None)
    monkeypatch.setattr(ct, "workdir", lambda: str(tmp_path))
    panel, _ = make(ct.ThreadStore(tmp_path / "hh"))
    panel._save_thread()
    from PyQt6.QtWidgets import QLabel
    assert any("szyfrowane" in l.text() for l in panel.findChildren(QLabel))
    assert not panel._saved
    panel.end()


def test_a_screenshot_file_of_claude_code_never_outlives_the_thread(store, records):
    """Live test 2026-11-13: Claude Code keeps an MCP screenshot as a .png in
    <id>/tool-results — it stayed after the .jsonl was gone."""
    shots = records / SID / "tool-results"
    shots.mkdir(parents=True)
    (shots / "mcp-hospitalhub-blob-1.png").write_bytes(b"PNG")
    store.started(SID)
    store.save(SID, title="x", kind="screen", label="x", messages=[])
    store.finished(SID)
    assert not (records / SID).exists()
    shots.mkdir(parents=True)                      # left again by a resume
    (shots / "mcp-hospitalhub-blob-2.png").write_bytes(b"PNG")
    (records / f"{SID}.jsonl").unlink(missing_ok=True)
    store.delete(SID)
    assert not (records / SID).exists()
