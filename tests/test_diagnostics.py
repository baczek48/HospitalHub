"""Tests for the diagnostics foundation.

Two things are being protected here:

* **behaviour** — a trace records what happened, in order, with timings;
* **safety** — nothing that looks like a credential can reach an export.

The safety tests use obviously fake constants defined below. They are not real
credentials and must never be replaced with real ones: a test that fails by
printing a secret would be worse than no test at all.
"""

import json
import os
import sys
import zipfile

import pytest

# Same pattern as tests/test_sftp_logic.py — work from the project root or
# from inside the project directory.
_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import diagnostics  # noqa: E402
from diagnostics import redactor  # noqa: E402
from diagnostics.redactor import (  # noqa: E402
    Masker, Mode, SecretLeakError, assert_no_secrets, find_secrets, redact,
)
from diagnostics.trace import (  # noqa: E402
    STATUS_FAIL, STATUS_OK, STATUS_WARN, TraceRecorder, TraceStore,
)

# ── fake secrets, for tests only ──────────────────────────────────────────
FAKE_PASSWORD = "SuperSecret123"
FAKE_TOKEN = "ABC123"
FAKE_OTP = "123456"
FAKE_PRIVATE_KEY = (
    "-----BEGIN PRIVATE KEY-----\n"
    "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7fake\n"
    "-----END PRIVATE KEY-----"
)


@pytest.fixture(autouse=True)
def diag_dir(tmp_path, monkeypatch):
    """Point diagnostics at a temp dir so the user's %APPDATA% is never touched."""
    monkeypatch.setenv(diagnostics.DIR_ENV_VAR, str(tmp_path / "diag"))
    diagnostics.reset_for_tests()
    yield tmp_path / "diag"
    diagnostics.reset_for_tests()


class FakeClock:
    """Deterministic wall clock + monotonic pair."""

    def __init__(self):
        from datetime import datetime, timezone
        self._wall = datetime(2026, 9, 11, 12, 0, 0, tzinfo=timezone.utc)
        self.t = 100.0

    def now(self):
        return self._wall

    def monotonic(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


# ══════════════════════════════════════════════════════════════════════════
# 1-2. TraceRecorder
# ══════════════════════════════════════════════════════════════════════════

def test_trace_records_steps_in_order_with_status_and_data():
    rec = TraceRecorder("vpn.connect", meta={"provider": "FortiClient"})
    with rec.step("forti.detect") as st:
        st.ok(source="registry", app_version="7.4.1")
    with rec.step("forti.launch") as st:
        st.warn(strategy="explorer_lnk", started=False)
    with rec.step("forti.window") as st:
        st.fail(error_code="window-not-found", timeout_ms=10000)

    data = rec.to_dict()
    assert data["operation"] == "vpn.connect"
    assert data["trace_id"]
    assert [s["step"] for s in data["steps"]] == [
        "forti.detect", "forti.launch", "forti.window"]
    assert [s["status"] for s in data["steps"]] == [
        STATUS_OK, STATUS_WARN, STATUS_FAIL]
    assert data["steps"][0]["data"]["source"] == "registry"
    assert data["steps"][2]["error_code"] == "window-not-found"
    assert data["steps"][0]["started_at"]
    assert rec.worst_status() == STATUS_FAIL


def test_trace_measures_step_duration():
    clock = FakeClock()
    rec = TraceRecorder("vpn.connect", clock=clock.now, monotonic=clock.monotonic)
    with rec.step("slow.step"):
        clock.advance(1.25)
    with rec.step("fast.step"):
        clock.advance(0.002)

    steps = rec.to_dict()["steps"]
    assert steps[0]["duration_ms"] == pytest.approx(1250.0, abs=0.01)
    assert steps[1]["duration_ms"] == pytest.approx(2.0, abs=0.01)


def test_trace_step_records_exception_and_reraises():
    rec = TraceRecorder("vpn.connect")
    with pytest.raises(RuntimeError):
        with rec.step("forti.automation"):
            raise RuntimeError("klient nie odpowiada")

    step = rec.to_dict()["steps"][0]
    assert step["status"] == STATUS_FAIL
    assert step["error_code"] == "RuntimeError"
    assert "klient nie odpowiada" in step["message"]


def test_trace_is_written_to_store_and_retained():
    store = TraceStore(diagnostics.traces_dir(), retention=3)
    for i in range(6):
        rec = TraceRecorder(f"op.{i}", store=store, trace_id=f"id{i:03d}")
        rec.add_step("step", status=STATUS_OK, index=i)
        rec.finish(STATUS_OK)

    files = store.list_traces()
    assert len(files) == 3, "retencja musi usuwać najstarsze trace'y"
    text = store.read_jsonl()
    assert "id005" in text and "id000" not in text


def test_trace_store_file_is_valid_jsonl():
    store = TraceStore(diagnostics.traces_dir(), retention=5)
    rec = TraceRecorder("vpn.status", store=store)
    rec.add_step("adapter.check", status=STATUS_OK, adapter="Fortinet SSL VPN")
    path = rec.finish(STATUS_OK)

    lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert lines[0]["kind"] == "trace"
    assert lines[1]["kind"] == "step"
    assert lines[1]["trace_id"] == lines[0]["trace_id"]


# ══════════════════════════════════════════════════════════════════════════
# 3-6. Redactor — named secrets
# ══════════════════════════════════════════════════════════════════════════

def test_redactor_masks_password():
    out = redact({"password": FAKE_PASSWORD})
    assert out["password"] == redactor.REDACTED
    assert FAKE_PASSWORD not in json.dumps(out)


def test_redactor_masks_token():
    out = redact({"token": FAKE_TOKEN, "access_token": FAKE_TOKEN})
    assert out["token"] == redactor.REDACTED
    assert out["access_token"] == redactor.REDACTED
    assert FAKE_TOKEN not in json.dumps(out)


def test_redactor_masks_otp():
    out = redact({"otp": FAKE_OTP, "otp_code": FAKE_OTP, "verification_code": FAKE_OTP})
    assert all(v == redactor.REDACTED for v in out.values())
    assert FAKE_OTP not in json.dumps(out)


@pytest.mark.parametrize("key", [
    "pass", "passwd", "password", "pwd", "secret", "api_token", "otp",
    "auth_code", "private_key", "ssh_key", "credential", "creds", "pin",
    "password_hash", "salt", "session_id", "bearer", "cookie", "passphrase",
])
def test_redactor_blocks_every_secret_key_shape(key):
    out = redact({key: "wartosc-ktora-nie-moze-wyjsc"})
    assert out[key] == redactor.REDACTED


def test_redactor_drops_unknown_keys_instead_of_trusting_them():
    """Allowlist, not blocklist: an unknown field is assumed unsafe."""
    out = redact({"jakies_nowe_pole": "cokolwiek", "status": "ok"})
    assert out["jakies_nowe_pole"] == redactor.DROPPED
    assert out["status"] == "ok"


def test_redactor_handles_nested_structures():
    out = redact({
        "steps": [
            {"step": "login", "password": FAKE_PASSWORD, "status": "fail"},
            {"step": "retry", "token": FAKE_TOKEN, "status": "ok"},
        ]
    })
    text = json.dumps(out)
    assert FAKE_PASSWORD not in text and FAKE_TOKEN not in text
    assert out["steps"][0]["status"] == "fail"


def test_trace_step_payload_is_redacted_before_storage():
    rec = TraceRecorder("vpn.connect")
    rec.add_step("forti.automation", status=STATUS_OK,
                 password=FAKE_PASSWORD, otp=FAKE_OTP, status_source="uia")
    text = json.dumps(rec.to_dict())
    assert FAKE_PASSWORD not in text
    assert FAKE_OTP not in text
    assert "uia" in text


# ══════════════════════════════════════════════════════════════════════════
# 7-9. Masking
# ══════════════════════════════════════════════════════════════════════════

def test_ip_masking_is_stable_within_a_report():
    masker = Masker(salt=b"test-salt")
    out = redact({"ip": "192.168.1.10", "remote_ip": "192.168.1.10",
                  "server_ip": "192.168.1.10"}, masker=masker)
    values = set(out.values())
    assert len(values) == 1, "ten sam adres musi dać ten sam pseudonim"
    assert "192.168.1.10" not in json.dumps(out)
    assert next(iter(values)).startswith("ip4-priv-")


def test_hostname_masking_is_stable():
    masker = Masker(salt=b"test-salt")
    a = redact({"host": "vpn.szpital-a.pl"}, masker=masker)["host"]
    b = redact({"hostname": "vpn.szpital-a.pl"}, masker=masker)["hostname"]
    assert a == b
    assert a.startswith("host-")
    assert "szpital" not in a


def test_two_different_hosts_get_different_identifiers():
    masker = Masker(salt=b"test-salt")
    a = masker.host("vpn.szpital-a.pl")
    b = masker.host("vpn.szpital-b.pl")
    ip_a = masker.ip("10.0.0.1")
    ip_b = masker.ip("10.0.0.2")
    assert a != b
    assert ip_a != ip_b


def test_masking_differs_between_reports():
    """A new report gets a new salt, so identifiers cannot be correlated."""
    assert Masker().host("vpn.example.pl") != Masker().host("vpn.example.pl")


def test_loopback_is_not_masked():
    masker = Masker(salt=b"test-salt")
    assert masker.ip("127.0.0.1") == "127.0.0.1"
    assert masker.host("localhost") == "localhost"


def test_embedded_ip_in_free_text_is_masked():
    masker = Masker(salt=b"test-salt")
    out = redact({"message": "połączono z 10.20.30.40 w 1,2 s"}, masker=masker)
    assert "10.20.30.40" not in out["message"]
    assert "ip4-priv-" in out["message"]


def test_command_arguments_are_masked():
    out = redact({"cmd": ["C:\\Program Files\\Fortinet\\FortiVPN.exe", "--cli",
                          "--connect", "--tunnel", "SZPITAL-A",
                          "--password", FAKE_PASSWORD]})
    cmd = out["cmd"]
    assert cmd["exe"] == "FortiVPN.exe"
    assert cmd["arg_count"] == 6
    assert "--connect" in cmd["flags"]
    assert "--password" not in cmd["flags"]
    assert FAKE_PASSWORD not in json.dumps(cmd)
    assert "SZPITAL-A" not in json.dumps(cmd)


def test_paths_are_shortened_and_user_stripped(monkeypatch):
    monkeypatch.setenv("USERPROFILE", r"C:\Users\Testowy")
    monkeypatch.setenv("USERNAME", "Testowy")
    out = redact({"path": r"C:\Users\Testowy\Documents\Default.rdp"})
    assert "Testowy" not in out["path"]
    assert out["path"].startswith("%USERPROFILE%")


# ══════════════════════════════════════════════════════════════════════════
# UI Automation model
# ══════════════════════════════════════════════════════════════════════════

def test_uia_node_records_structure_only():
    node = diagnostics.UiaNode(
        control_type="Edit", automation_id="username_field",
        name="Username", class_name="Chrome_RenderWidgetHostHWND",
        pid=1234, is_enabled=True, is_offscreen=False, depth=2,
        has_value_pattern=True,
    )
    out = node.to_dict()
    assert set(out) == {"control_type", "automation_id", "name", "class_name",
                        "depth", "pid", "is_enabled", "is_offscreen",
                        "has_value_pattern"}
    assert "value" not in out, "wartości pól nie wolno zapisywać"
    assert not hasattr(node, "value")


def test_uia_tree_summary():
    child = diagnostics.UiaNode(control_type="Edit", depth=2)
    root = diagnostics.UiaNode(control_type="Window", depth=0,
                               children=[diagnostics.UiaNode(
                                   control_type="Pane", depth=1,
                                   children=[child])])
    assert root.summary() == {"control_count": 3, "tree_depth": 2}


# ══════════════════════════════════════════════════════════════════════════
# Secret detection
# ══════════════════════════════════════════════════════════════════════════

def test_find_secrets_detects_private_key_and_jwt():
    assert find_secrets(FAKE_PRIVATE_KEY)
    assert find_secrets("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdef")


def test_find_secrets_ignores_ordinary_text():
    assert not find_secrets("połączono z adapterem Fortinet SSL VPN po 1,4 s")
    assert not find_secrets(json.dumps({"status": "ok", "duration_ms": 1240.5}))


def test_assert_no_secrets_message_does_not_contain_the_secret():
    with pytest.raises(SecretLeakError) as excinfo:
        assert_no_secrets(FAKE_PRIVATE_KEY, where="report.json")
    assert "MIIEvQIBADANBgkqhkiG9w0" not in str(excinfo.value)
    assert "pem-private-key" in str(excinfo.value)


def test_runtime_mode_blocks_secret_shaped_value_without_raising():
    out = redact({"message": FAKE_PRIVATE_KEY}, mode=Mode.RUNTIME)
    assert out["message"] == redactor.BLOCKED


def test_export_mode_raises_on_secret_shaped_value():
    with pytest.raises(SecretLeakError):
        redact({"message": FAKE_PRIVATE_KEY}, mode=Mode.EXPORT)


# ══════════════════════════════════════════════════════════════════════════
# 10-12. Export
# ══════════════════════════════════════════════════════════════════════════

def test_export_zip_contains_required_files():
    rec = TraceRecorder("vpn.connect")
    rec.add_step("forti.detect", status=STATUS_OK, source="registry")
    rec.finish(STATUS_OK)

    result = diagnostics.export()
    assert result.path.exists()
    with zipfile.ZipFile(result.path) as zf:
        names = set(zf.namelist())
        assert {"report.json", "trace.jsonl", "manifest.json"} <= names
        report = json.loads(zf.read("report.json").decode("utf-8"))
        manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
        trace_text = zf.read("trace.jsonl").decode("utf-8")

    assert report["app_variant"] == "V2"
    # Sections must carry real data — an allowlist gap would leave the key in
    # place with a "<dropped:…>" marker, which looks deceptively fine.
    assert report["sections"]["app"]["app_variant"] == "V2"
    assert report["sections"]["system"]["os_name"]
    assert report["sections"]["runtime"]["pid"] > 0
    assert {f["name"] for f in manifest["files"]} >= {"report.json", "trace.jsonl"}
    assert all(len(f["sha256"]) == 64 for f in manifest["files"])
    assert "forti.detect" in trace_text


def test_export_contains_no_plaintext_secret():
    """The four fake secrets from the brief must not survive the pipeline."""
    rec = TraceRecorder("vpn.connect")
    rec.add_step("forti.automation", status=STATUS_OK,
                 password=FAKE_PASSWORD, token=FAKE_TOKEN, otp=FAKE_OTP,
                 private_key=FAKE_PRIVATE_KEY)
    rec.finish(STATUS_FAIL, error_code="auth-failed")

    result = diagnostics.export(extra={"vpn": {"password": FAKE_PASSWORD,
                                               "token": FAKE_TOKEN,
                                               "otp": FAKE_OTP}})
    blob = result.path.read_bytes()
    with zipfile.ZipFile(result.path) as zf:
        text = "".join(zf.read(n).decode("utf-8", "replace") for n in zf.namelist())

    for secret in (FAKE_PASSWORD, FAKE_TOKEN, FAKE_OTP, "MIIEvQIBADANBgkqhkiG9w0"):
        assert secret not in text, f"sekret trafił do eksportu: {secret[:6]}…"
        assert secret.encode("utf-8") not in blob


def test_export_raises_instead_of_silently_scrubbing_a_suspected_secret():
    with pytest.raises(SecretLeakError):
        diagnostics.export(extra={"note": FAKE_PRIVATE_KEY})


def test_failed_export_writes_nothing():
    before = set(diagnostics.export_dir().glob("*.zip")) if diagnostics.export_dir().exists() else set()
    with pytest.raises(SecretLeakError):
        diagnostics.export(extra={"note": FAKE_PRIVATE_KEY})
    after = set(diagnostics.export_dir().glob("*.zip")) if diagnostics.export_dir().exists() else set()
    assert before == after
    assert not list(diagnostics.export_dir().glob("*.tmp")) if diagnostics.export_dir().exists() else True


def test_preview_builds_without_writing():
    bundle = diagnostics.preview()
    assert "report.json" in bundle.files
    assert not list(diagnostics.export_dir().glob("*.zip")) if diagnostics.export_dir().exists() else True


def test_export_redaction_note_lists_the_rules():
    rec = TraceRecorder("vpn.connect")
    rec.add_step("x", status=STATUS_OK, nieznane_pole="cokolwiek")
    rec.finish(STATUS_OK)
    result = diagnostics.export(extra={"vpn": {"password": FAKE_PASSWORD}})
    with zipfile.ZipFile(result.path) as zf:
        note = zf.read("REDACTION.txt").decode("utf-8")
    assert "allowlist" in note
    assert "password" in note            # the key name, never the value
    assert FAKE_PASSWORD not in note


def test_collectors_do_not_leak_and_stay_within_allowlist():
    data = diagnostics.collect()
    text = json.dumps(data, ensure_ascii=False)
    assert not find_secrets(text)
    assert data["app"]["app_variant"] == "V2"


def test_meipass_flag_survives_redaction():
    """Regression guard: "has_meipass" contains "pass" but is a boolean flag,
    and it is the clearest signal for the FortiClient/Electron launch bug."""
    data = diagnostics.collect()
    assert data["runtime"]["has_meipass"] in (True, False)
    assert data["runtime"]["meipass_env_present"] in (True, False)
    assert data["runtime"]["session_type"] in ("interactive", "windowed")


def test_vault_content_is_never_collected():
    """No collector may read vault data — the section simply does not exist."""
    assert "vault" not in diagnostics.collector.available()
    data = diagnostics.collect()
    assert "vault" not in json.dumps(data).lower() or "vault_label" not in data


# ── 2026-10-14 (audit E-04): user and organisation names in paths ─────────

@pytest.mark.parametrize("path,leak", [
    (r"C:\Users\SEBAST~1\AppData\Local\Temp\x.log", "SEBAST~1"),
    (r"C:\Users\ab\Documents\v.vault", "\ab\\"),
    (r"D:\users\Other.Person\file.txt", "Other.Person"),
    (r"C:\Users\x\OneDrive - Szpital Wojewódzki\v.vault", "Szpital Wojewódzki"),
])
def test_e04_profile_and_organisation_names_do_not_survive(monkeypatch, path, leak):
    from diagnostics import redactor
    monkeypatch.setenv("USERNAME", "someone-else")
    out = redactor.shorten_path(path)
    assert leak not in out, out


def test_e04_ordinary_paths_keep_their_shape():
    from diagnostics import redactor
    assert redactor.shorten_path(r"C:\Program Files\Fortinet\FortiClient\x.exe").endswith(
        r"Fortinet\FortiClient\x.exe")
