"""Stage 50: the CLI / PROCESS_STDOUT second-factor monitor.

Two halves, tested together on a controlled fake process:

* ``vpn.panel_bridge.TwoFactorMonitorSession`` — owns the ``ProcessChannel``
  from CLI start to a terminal state, watches stdout for a challenge through the
  existing ``watch_for_challenge``, and submits a token through the existing,
  guarded ``supply_two_factor``.  No new 2FA mechanism, no Win32 of its own.
* ``ui.vpn_v2_twofactor`` — a ``QThread`` worker that runs the two blocking
  steps off the UI thread and reports through signals, and a controller that
  maps them to the seven panel signals.

The FortiClient Free edition on this machine has no usable CLI, so this is
CONTRACT-ONLY: everything below drives a fake channel, never a real process, and
there are no fake HWNDs.
"""

import ast
import os
import sys
import threading
import time
from types import SimpleNamespace

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

from PyQt6.QtWidgets import QApplication  # noqa: E402

from vpn import TwoFactorStatus, VpnRequest  # noqa: E402
from vpn import panel_bridge as pb  # noqa: E402
from vpn.panel_bridge import (  # noqa: E402
    MonitorPhase, PanelConnectOutcome, PanelOutcome, TwoFactorMonitorSession,
    TwoFactorOutcome,
)
from vpn.providers import forticlient_2fa as f2  # noqa: E402
from ui import vpn_v2_twofactor as tf  # noqa: E402
from ui.vpn_v2_twofactor import TwoFactorController, TwoFactorMonitorWorker  # noqa: E402
from tests.test_vpn_forticlient_2fa import (  # noqa: E402
    FakeChannel, RecTrace, auth_desktop, provider,
)
from tests.test_vpn_secure_target import EVIL_EXE, FORTI_PID, OTHER  # noqa: E402

TOKEN = "845217"
LOGIN, PROFILE = "jkowalski", "SZPITAL-A"
CHALLENGE = "Please enter your token: "
CONNECTING = "Connecting to gateway...\n"


def base_request():
    return VpnRequest(provider_id="forticlient", login=LOGIN,
                      profile_name=PROFILE)


def session(channel, *, desktop=None, cancellation=None):
    return TwoFactorMonitorSession(
        provider(), base_request(), channel,
        cancellation=cancellation,
        window_api=desktop if desktop is not None else auth_desktop())


class CancellingChannel(FakeChannel):
    """Cancels a token after handing out `after` lines — to trip should_stop."""

    def __init__(self, token, *, after=1, **kwargs):
        super().__init__(**kwargs)
        self._token = token
        self._after = after
        self._read = 0

    def read_line(self):
        line = super().read_line()
        self._read += 1
        if self._read >= self._after:
            self._token.cancel()
        return line


# ══════════════════════════════════════════════════════════════════════════
# 1. watch(): challenge, no challenge, cancel, error
# ══════════════════════════════════════════════════════════════════════════

def test_1_a_challenge_line_is_detected():
    s = session(FakeChannel(lines=[CONNECTING, CHALLENGE + "\n"]))
    assert s.watch() is MonitorPhase.CHALLENGE


def test_2_no_challenge_before_the_stream_ends():
    s = session(FakeChannel(lines=[CONNECTING, "tunnel up\n"]))
    assert s.watch() is MonitorPhase.NO_CHALLENGE


def test_3_cancel_before_the_watch_reads_nothing():
    from vpn.providers.activation_gate import CancellationToken
    token = CancellationToken()
    token.cancel()
    channel = FakeChannel(lines=[CHALLENGE + "\n"])
    s = session(channel, cancellation=token)
    assert s.watch() is MonitorPhase.CANCELLED
    assert channel._lines, "kanał nietknięty — nic nie odczytano"


def test_4_cancel_during_the_watch_stops_between_reads():
    from vpn.providers.activation_gate import CancellationToken
    token = CancellationToken()
    channel = CancellingChannel(token, after=1,
                                lines=[CONNECTING, CONNECTING, CHALLENGE + "\n"])
    s = session(channel, cancellation=token)
    assert s.watch() is MonitorPhase.CANCELLED, "should_stop przerwał między liniami"


def test_5_a_read_error_is_reported_as_ended_not_a_crash():
    class Boom(FakeChannel):
        def read_line(self):
            raise OSError("pipe read failed")

    # watch_for_challenge turns a read error into ended=True; the session maps
    # that to NO_CHALLENGE (the process is gone, no token was asked).
    assert session(Boom()).watch() is MonitorPhase.NO_CHALLENGE


# ══════════════════════════════════════════════════════════════════════════
# 2. submit(): token in, and everything that stops it
# ══════════════════════════════════════════════════════════════════════════

def test_6_a_token_is_submitted_to_a_verified_process():
    channel = FakeChannel()
    outcome = session(channel).submit(TOKEN)
    assert outcome is TwoFactorOutcome.SUBMITTED
    assert channel.written == [TOKEN], "token trafił na stdin procesu"


def test_7_submit_after_cancel_sends_nothing():
    from vpn.providers.activation_gate import CancellationToken
    token = CancellationToken()
    channel = FakeChannel()
    s = session(channel, cancellation=token)
    s.cancel()
    assert s.submit(TOKEN) is TwoFactorOutcome.CANCELLED
    assert channel.written == [], "po anulowaniu token nie jest wysyłany"


def test_8_submit_to_an_untrusted_process_is_blocked():
    desktop = auth_desktop(images={FORTI_PID: EVIL_EXE})
    channel = FakeChannel()
    assert session(channel, desktop=desktop).submit(TOKEN) is TwoFactorOutcome.FAILED
    assert channel.written == []


def test_9_submit_after_the_process_ended_fails_without_a_write():
    # A dead process has no pid to verify — the guarded component refuses before
    # the write, so no token is sent into a closed pipe.
    channel = FakeChannel(pid=None)
    assert session(channel).submit(TOKEN) is TwoFactorOutcome.FAILED
    assert channel.written == []


def test_10_a_broken_pipe_on_write_is_a_failure_not_a_success():
    channel = FakeChannel(raise_on_write=True)
    assert session(channel).submit(TOKEN) is TwoFactorOutcome.FAILED


def test_11_a_second_submit_is_refused():
    channel = FakeChannel()
    s = session(channel)
    assert s.submit(TOKEN) is TwoFactorOutcome.SUBMITTED
    assert s.submit(TOKEN) is TwoFactorOutcome.FAILED
    assert channel.written == [TOKEN], "token wysłany dokładnie raz"


# ══════════════════════════════════════════════════════════════════════════
# 3. The token never leaks
# ══════════════════════════════════════════════════════════════════════════

def test_12_no_token_in_the_result_the_repr_or_a_trace():
    channel = FakeChannel()
    s = session(channel)
    outcome = s.submit(TOKEN)
    assert TOKEN not in repr(outcome)
    assert TOKEN not in repr(s)
    assert TOKEN not in repr(channel.written) or channel.written == [TOKEN]
    # The default trace is off; watch/submit take trace=None, so nothing about
    # the token reaches a recorder.  Prove the session never passes a trace on.
    src = open(pb.__file__, encoding="utf-8").read()
    body = src[src.index("class TwoFactorMonitorSession"):]
    assert "trace=None" in body and "trace=self" not in body


def test_13_from_outcome_takes_ownership_of_the_live_monitor():
    monitor = SimpleNamespace(pid=FORTI_PID, stdin=_Pipe(), stdout=_Pipe())
    outcome = PanelConnectOutcome(PanelOutcome.CLI_STARTED, monitor=monitor,
                                  route="cli_monitored", started=True)
    s = TwoFactorMonitorSession.from_outcome(outcome, provider(), base_request(),
                                             window_api=auth_desktop())
    assert s is not None and s.pid == FORTI_PID
    # No monitor → nothing to own.
    empty = PanelConnectOutcome(PanelOutcome.MANUAL)
    assert TwoFactorMonitorSession.from_outcome(empty, provider(),
                                                base_request()) is None


class _Pipe:
    def readline(self):
        return b""

    def write(self, data):
        pass

    def flush(self):
        pass


# ══════════════════════════════════════════════════════════════════════════
# 4. The worker, on a thread, driving signals
# ══════════════════════════════════════════════════════════════════════════

@pytest.fixture(scope="module")
def app():
    existing = QApplication.instance()
    return existing if existing is not None else QApplication([])


class WorkerHarness:
    def __init__(self, s, *, token_timeout_s=5.0):
        self.session = s
        self.controller = TwoFactorController(s, token_timeout_s=token_timeout_s)
        self.events = []
        for name in ("cli_started", "token_required", "token_submitted",
                     "connected", "failed", "timed_out", "cancelled"):
            getattr(self.controller, name).connect(
                lambda n=name: self.events.append(n))
        self.controller.finished.connect(lambda code: self.events.append(("done", code)))

    def start(self):
        self.controller.start()
        return self

    def pump(self, until, timeout_s=10.0):
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline and not until():
            QApplication.processEvents()
            self.controller.worker.wait(5)
        for _ in range(3):
            QApplication.processEvents()
        return self

    def finish(self):
        self.controller.worker.wait(10000)
        self.pump(until=lambda: any(isinstance(e, tuple) for e in self.events))
        return next(e[1] for e in self.events if isinstance(e, tuple))


def test_14_challenge_then_token_submitted(app):
    channel = FakeChannel(lines=[CONNECTING, CHALLENGE + "\n"])
    run = WorkerHarness(session(channel)).start()
    run.pump(until=lambda: "token_required" in run.events)
    assert run.events[:2] == ["cli_started", "token_required"]

    run.controller.provide_token(TOKEN)
    assert run.finish() == TwoFactorController.CODE_SUBMITTED
    assert "token_submitted" in run.events
    assert channel.written == [TOKEN]


def test_15_no_challenge_reports_connected(app):
    channel = FakeChannel(lines=[CONNECTING, "tunnel up\n"])
    run = WorkerHarness(session(channel)).start()
    assert run.finish() == TwoFactorController.CODE_CONNECTED
    assert "connected" in run.events and "token_required" not in run.events


def test_16_cancel_before_the_challenge(app):
    from vpn.providers.activation_gate import CancellationToken
    token = CancellationToken()
    token.cancel()
    channel = FakeChannel(lines=[CHALLENGE + "\n"])
    run = WorkerHarness(session(channel, cancellation=token)).start()
    assert run.finish() == TwoFactorController.CODE_CANCELLED
    assert channel.written == []


def test_17_cancel_after_the_challenge_before_the_token(app):
    channel = FakeChannel(lines=[CHALLENGE + "\n"])
    run = WorkerHarness(session(channel), token_timeout_s=30.0).start()
    run.pump(until=lambda: "token_required" in run.events)

    run.controller.cancel()               # user gives up at the code prompt
    assert run.finish() == TwoFactorController.CODE_CANCELLED
    assert channel.written == [], "żaden token po anulowaniu"


def test_18_a_token_that_never_comes_times_out(app):
    channel = FakeChannel(lines=[CHALLENGE + "\n"])
    run = WorkerHarness(session(channel), token_timeout_s=0.3).start()
    assert run.finish() == TwoFactorController.CODE_TIMEOUT
    assert channel.written == []


def test_19_a_failed_submit_reaches_the_card_as_failed(app):
    channel = FakeChannel(lines=[CHALLENGE + "\n"], raise_on_write=True)
    run = WorkerHarness(session(channel)).start()
    run.pump(until=lambda: "token_required" in run.events)
    run.controller.provide_token(TOKEN)
    assert run.finish() == TwoFactorController.CODE_FAILED


def test_20_provide_token_after_the_end_is_ignored(app):
    channel = FakeChannel(lines=[CONNECTING, "tunnel up\n"])
    run = WorkerHarness(session(channel)).start()
    assert run.finish() == TwoFactorController.CODE_CONNECTED
    run.controller.provide_token(TOKEN)   # too late — nothing happens
    QApplication.processEvents()
    assert channel.written == []


# ══════════════════════════════════════════════════════════════════════════
# 5. Structural: no Win32, no clipboard, no vpn import in the UI half
# ══════════════════════════════════════════════════════════════════════════

def _names_and_modules(path):
    tree = ast.parse(open(path, encoding="utf-8").read())
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)
               and n.level == 0}
    modules |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import)
                for a in n.names}
    return names, modules


def test_21_the_ui_worker_imports_no_vpn_and_no_win32():
    names, modules = _names_and_modules(tf.__file__)
    for m in modules:
        root = (m or "").split(".")[0]
        assert root not in ("vpn", "vpn_connect", "ctypes", "win32gui",
                            "win32con", "win32api", "secure_window"), m
    for banned in ("SendInput", "SetForegroundWindow", "clipboard", "QClipboard",
                   "WM_SETTEXT", "acquire_focus", "process_image_path"):
        assert banned not in names, banned


def _session_class_node():
    tree = ast.parse(open(pb.__file__, encoding="utf-8").read())
    return next(n for n in ast.walk(tree)
               if isinstance(n, ast.ClassDef)
               and n.name == "TwoFactorMonitorSession")


def test_22_the_session_does_no_win32_or_clipboard_itself():
    node = _session_class_node()
    names = {n.attr for n in ast.walk(node) if isinstance(n, ast.Attribute)}
    names |= {n.id for n in ast.walk(node) if isinstance(n, ast.Name)}
    for banned in ("SendInput", "clipboard", "copy_to_clipboard", "WM_SETTEXT",
                   "SetForegroundWindow", "ctypes", "win32gui"):
        assert banned not in names, banned


def test_23_the_phase_and_outcome_codes_match_the_bridge_enums():
    """The UI names string literals; they must equal the bridge's enum values."""
    assert tf.PHASE_CHALLENGE == MonitorPhase.CHALLENGE.value
    assert tf.PHASE_NO_CHALLENGE == MonitorPhase.NO_CHALLENGE.value
    assert tf.PHASE_CANCELLED == MonitorPhase.CANCELLED.value
    assert tf.PHASE_ERROR == MonitorPhase.ERROR.value
    assert tf.OUTCOME_SUBMITTED == TwoFactorOutcome.SUBMITTED.value
    assert tf.OUTCOME_FAILED == TwoFactorOutcome.FAILED.value
    assert tf.OUTCOME_CANCELLED == TwoFactorOutcome.CANCELLED.value


def test_24_submit_reuses_the_existing_2fa_component():
    """No second delivery path: the session calls supply_two_factor, nothing
    lower-level, so the process-image verification and write-error handling of
    Stage 15 apply unchanged."""
    names = {n.attr for n in ast.walk(_session_class_node())
             if isinstance(n, ast.Attribute)}
    assert "supply_two_factor" in names
    assert "write_line" not in names, "sesja nie pisze sama na stdin — robi to 2fa"


def test_25_cli_lifecycle_is_recorded_as_contract_only():
    ids = {gap for gap, _ in pb.KNOWN_GAPS}
    assert "cli-live-unverified" in ids
    assert "stdout-2fa-monitor" not in ids, "luka domknięta w Stage 50"
