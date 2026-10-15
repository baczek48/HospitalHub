"""Stage 12: secrets reach FortiClient only through a confirmed target.

These tests prove the *negative*: when the owner of a window or the keyboard
focus cannot be confirmed, no login, no password, no 2FA token and no Enter
leaves the application — not by SendInput, not by Ctrl+V, not by WM_SETTEXT —
and no secret is put on the clipboard first.

Nothing real is touched.  The desktop is described by a fake
:class:`secure_window.WindowApi`; key presses, typing, clipboard, `win32gui`
and `win32con` are recorded fakes; `time.sleep` records instead of sleeping;
`threading.Thread` runs synchronously; the low-level ``_send_input_key`` is a
tripwire.
"""

import ast
import json
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

import diagnostics  # noqa: E402
import secure_window as sw  # noqa: E402
import vpn_connect  # noqa: E402
from diagnostics import vpn as vpn_diag  # noqa: E402

LOGIN = "jkowalski"
PASSWORD = "SuperSecret123"
TOKEN = "123456"
PREV_CLIP = "schowek-uzytkownika-XYZ"
SECRETS = (LOGIN, PASSWORD, TOKEN, PREV_CLIP)

FORTI_DIR = r"C:\Program Files\Fortinet\FortiClient"
FORTI_GUI = FORTI_DIR + r"\FortiClient.exe"
FORTI_TRAY = FORTI_DIR + r"\FortiTray.exe"
EVIL_EXE = r"C:\Users\Public\Downloads\FortiClient.exe"
NOTEPAD = r"C:\Windows\System32\notepad.exe"

HWND, OTHER_HWND, AUTH = 0x1001, 0x2002, 0x3003
FORTI_PID, EVIL_PID, NOTEPAD_PID = 4100, 6660, 999
FORTI_TID, OUR_TID = 41, 7

VK_TAB, VK_RETURN, VK_CONTROL, VK_DELETE, VK_SPACE = 0x09, 0x0D, 0x11, 0x2E, 0x20
CTRL_V = ("combo", VK_CONTROL, ord("V"))
ENTER = ("key", VK_RETURN)


# ══════════════════════════════════════════════════════════════════════════
# A described desktop
# ══════════════════════════════════════════════════════════════════════════

class FakeDesktop(sw.WindowApi):
    """windows: hwnd -> (pid, tid, root); images: pid -> image path."""

    def __init__(self, events, *, windows=None, images=None, foreground=None,
                 attach_ok=True, set_foreground="ok"):
        self.events = events
        self.windows = windows if windows is not None else {
            HWND: (FORTI_PID, FORTI_TID, HWND),
            OTHER_HWND: (NOTEPAD_PID, 99, OTHER_HWND),
        }
        self.images = images if images is not None else {
            FORTI_PID: FORTI_GUI, NOTEPAD_PID: NOTEPAD}
        self.foreground = foreground if foreground is not None else (lambda n: HWND)
        self.attach_ok = attach_ok
        self.set_foreground = set_foreground
        self.fg_checks = 0

    def window_pid(self, hwnd):
        return self.windows.get(hwnd, (None, None, None))[0]

    def window_thread_id(self, hwnd):
        return self.windows.get(hwnd, (None, None, None))[1]

    def process_image_path(self, pid):
        return self.images.get(pid)

    def foreground_window(self):
        self.fg_checks += 1
        self.events.append(("fg_check",))
        return self.foreground(self.fg_checks)

    def root_window(self, hwnd):
        return self.windows.get(hwnd, (None, None, None))[2]

    def current_thread_id(self):
        return OUR_TID

    def attach_thread_input(self, our_tid, their_tid, attach):
        self.events.append(("attach", attach))
        return self.attach_ok if attach else True

    def restore_window(self, hwnd):
        self.events.append(("restore",))

    def set_foreground_window(self, hwnd):
        self.events.append(("set_foreground",))
        if self.set_foreground == "raises":
            raise OSError("SetForegroundWindow refused")
        return self.set_foreground == "ok"


def focus_lost_after(checks):
    """Foreground is FortiClient for the first `checks` checks, then notepad."""
    return lambda n: HWND if n <= checks else OTHER_HWND


class SyncThread:
    def __init__(self, target=None, args=(), kwargs=None, daemon=None, **_):
        self._target, self._args, self._kwargs = target, args, kwargs or {}

    def start(self):
        self._target(*self._args, **self._kwargs)


class RecTrace:
    def __init__(self):
        self.steps, self.finished = [], None

    def step(self, name, status="ok", error_code=None, message=None, **data):
        self.steps.append({"step": name, "status": status, "error_code": error_code, **data})
        return self

    def ok(self, name, **data):
        return self.step(name, "ok", **data)

    def warn(self, name, message=None, **data):
        return self.step(name, "warn", message=message, **data)

    def fail(self, name, error_code=None, message=None, **data):
        return self.step(name, "fail", error_code, message, **data)

    def child(self, *a, **k):
        return self

    def finish(self, status=None, error_code=None, **result):
        self.finished = {"status": status, "error_code": error_code, **result}

    def events(self):
        return [(s["step"], s.get("event") or s.get("phase"), s["status"], s["error_code"])
                for s in self.steps]


def _tripwire(name):
    def _hit(*a, **k):
        raise AssertionError(f"prawdziwe wejście systemowe: {name}")
    return _hit


@pytest.fixture(autouse=True)
def isolated(monkeypatch, tmp_path):
    monkeypatch.setenv(diagnostics.DIR_ENV_VAR, str(tmp_path / "diag"))
    diagnostics.reset_for_tests()
    monkeypatch.setattr(vpn_connect, "_send_input_key", _tripwire("SendInput"))
    monkeypatch.setattr(vpn_connect, "_click_at", _tripwire("mouse click"))
    monkeypatch.setattr(vpn_connect, "_dbg", lambda *a, **k: None)
    monkeypatch.setattr(vpn_connect, "_trusted_forti_dirs", lambda: (FORTI_DIR,))
    monkeypatch.setattr(threading, "Thread", SyncThread)
    yield
    diagnostics.reset_for_tests()


def run_autofill(monkeypatch, desktop, *, login=LOGIN, password=PASSWORD,
                 profile="SZPITAL-A", window=HWND, trace=None):
    events = desktop.events
    monkeypatch.setattr(vpn_connect, "_window_api", lambda: desktop)
    monkeypatch.setattr(vpn_connect, "_wait_forticlient_window",
                        lambda timeout=10.0: events.append(("window_wait", timeout)) or window)
    monkeypatch.setattr(vpn_connect, "_press_key", lambda vk: events.append(("key", vk)))
    monkeypatch.setattr(vpn_connect, "_press_combo",
                        lambda mod, key: events.append(("combo", mod, key)))
    monkeypatch.setattr(vpn_connect, "_type_text", lambda text: events.append(("type", text)))
    monkeypatch.setattr(vpn_connect, "_copy_to_clipboard",
                        lambda text: events.append(("clipboard_set", text)) or True)
    monkeypatch.setattr(vpn_connect, "_get_clipboard_text",
                        lambda: events.append(("clipboard_get",)) or PREV_CLIP)
    monkeypatch.setattr(time, "sleep", lambda s: events.append(("sleep", s)))
    trace = trace if trace is not None else RecTrace()
    vpn_connect._autofill_forticlient(login, password, profile, tr=trace)
    return events, trace


def secret_operations(events):
    """Everything that would carry a secret or submit the login form.

    The Enter that selects a *profile* in the dropdown is not a secret
    operation; the submit Enter comes after the clipboard was read.
    """
    out = []
    after_clipboard_read = False
    for e in events:
        if e == ("clipboard_get",):
            after_clipboard_read = True
        if e == CTRL_V or (e == ENTER and after_clipboard_read):
            out.append(e)
        elif e[0] == "clipboard_set" and e[1] in (LOGIN, PASSWORD):
            out.append(e)
        elif e[0] == "type" and any(s in e[1] for s in (LOGIN, PASSWORD, TOKEN)):
            out.append(e)
    return out


def inputs(events):
    return [e for e in events if e[0] in ("key", "combo", "type")]


# ══════════════════════════════════════════════════════════════════════════
# 1–2. Focus not acquired → nothing at all
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("set_foreground", ["fails", "raises"])
def test_1_set_foreground_failure_sends_no_secret(set_foreground, monkeypatch):
    desktop = FakeDesktop([], set_foreground=set_foreground)
    events, trace = run_autofill(monkeypatch, desktop)
    assert secret_operations(events) == []
    assert inputs(events) == [], "ani jednego klawisza"
    assert not any(e[0].startswith("clipboard") for e in events)
    assert ("attach", False) in events, "wątki odłączone mimo porażki"
    assert trace.finished["error_code"] == "focus-failed"
    blocked = [s for s in trace.steps if s.get("event") == "secret-input-blocked"]
    assert blocked and blocked[0]["reason"] == "set-foreground-failed"


def test_1b_foreground_is_another_window_despite_success_report(monkeypatch):
    desktop = FakeDesktop([], foreground=lambda n: OTHER_HWND)
    events, trace = run_autofill(monkeypatch, desktop)
    assert inputs(events) == [] and secret_operations(events) == []
    assert trace.steps[-1]["reason"] == "foreground-is-other-window"


def test_2_attach_thread_input_failure_sends_no_secret(monkeypatch):
    desktop = FakeDesktop([], attach_ok=False)
    events, trace = run_autofill(monkeypatch, desktop)
    assert inputs(events) == [] and secret_operations(events) == []
    assert ("set_foreground",) not in events, "bez attach nie próbujemy dalej"
    assert ("attach", False) not in events, "nie było czego odłączać"
    assert trace.finished["error_code"] == "focus-failed"
    assert trace.steps[-1]["reason"] == "attach-failed"


# ══════════════════════════════════════════════════════════════════════════
# 3–4. Wrong owner → nothing at all
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("images,reason", [
    ({FORTI_PID: EVIL_EXE}, "untrusted-image"),                 # same name, wrong place
    ({FORTI_PID: r"C:\Program Files\Fortinet\FortiClientEvil\FortiClient.exe"},
     "untrusted-image"),                                        # prefix confusion
    ({FORTI_PID: FORTI_DIR + r"\..\..\..\Users\x\FortiClient.exe"}, "untrusted-image"),
    ({}, "image-unavailable"),                                  # OpenProcess refused
])
def test_3_main_window_of_untrusted_process_gets_nothing(images, reason, monkeypatch):
    desktop = FakeDesktop([], images=images)
    events, trace = run_autofill(monkeypatch, desktop)
    assert inputs(events) == [] and secret_operations(events) == []
    assert not any(e[0] in ("attach", "clipboard_get", "clipboard_set") for e in events)
    assert trace.finished["error_code"] == "target-window-untrusted"
    rejected = [s for s in trace.steps if s.get("event") == "owner-rejected"]
    assert rejected and rejected[0]["reason"] == reason


def test_3b_window_without_process_gets_nothing(monkeypatch):
    desktop = FakeDesktop([], windows={})
    events, trace = run_autofill(monkeypatch, desktop)
    assert inputs(events) == [] and trace.finished["error_code"] == "target-window-untrusted"


# ══════════════════════════════════════════════════════════════════════════
# 5. Valid window + focus → the existing autofill is unchanged
# ══════════════════════════════════════════════════════════════════════════

EXPECTED_SEQUENCE = [
    ("attach", True), ("restore",), ("set_foreground",),
    ("key", VK_TAB), ("key", VK_SPACE), ("type", "SZPITAL-A"), ("key", VK_RETURN),
    ("key", VK_TAB), ("key", VK_TAB), ("clipboard_get",),
    ("combo", VK_CONTROL, ord("A")), ("key", VK_DELETE), ("clipboard_set", LOGIN), CTRL_V,
    ("key", VK_TAB),
    ("combo", VK_CONTROL, ord("A")), ("key", VK_DELETE), ("clipboard_set", PASSWORD), CTRL_V,
    ENTER, ("clipboard_set", PREV_CLIP), ("attach", False),
]
EXPECTED_SLEEPS = [1.5, 0.3, 0.5, 0.3, 0.5, 0.2, 0.3, 0.2, 0.2, 0.2, 0.5, 0.5,
                   0.2, 0.2, 0.2, 0.9, 0.6, 1.5]


def test_5_trusted_window_and_focus_autofill_still_works(monkeypatch):
    desktop = FakeDesktop([])
    events, trace = run_autofill(monkeypatch, desktop)
    visible = [e for e in events if e[0] not in ("fg_check", "sleep", "window_wait")]
    assert visible == EXPECTED_SEQUENCE
    assert [e[1] for e in events if e[0] == "sleep"] == EXPECTED_SLEEPS, "timeouty bez zmian"
    assert ("window_wait", 10.0) in events
    assert trace.finished == {"status": "ok", "error_code": None,
                              "result": "sequence-completed"}
    assert ("vpn.target_window", "owner-verified", "ok", None) in trace.events()


def test_5b_every_secret_operation_is_immediately_preceded_by_a_confirmation(monkeypatch):
    desktop = FakeDesktop([])
    events, _ = run_autofill(monkeypatch, desktop)
    meaningful = [e for e in events if e[0] != "sleep"]
    submit_enter = max(i for i, e in enumerate(meaningful) if e == ENTER)
    for index, event in enumerate(meaningful):
        if event == CTRL_V or index == submit_enter:
            assert meaningful[index - 1] == ("fg_check",), f"{event} bez potwierdzenia"
        if event[0] == "clipboard_set" and event[1] in (LOGIN, PASSWORD):
            # confirm → Ctrl+A → Delete → clipboard
            assert meaningful[index - 3] == ("fg_check",), (
                f"{event[1]!r} w schowku bez potwierdzenia")
    assert desktop.fg_checks == 7, "fokus + nawigacja + 2×login + 2×hasło + Enter"


@pytest.mark.parametrize("checks,login_pasted,password_on_clipboard", [
    (1, False, False),   # focus confirmed, gone after the 1.5 s render wait
    (3, False, False),   # gone after login was *selected*, before it hit the clipboard
    (4, True, False),    # login pasted, gone before the password field
    (5, True, True),     # password on clipboard, gone before Ctrl+V
    (6, True, True),     # both pasted, gone before Enter
])
def test_5c_focus_lost_midway_stops_before_the_next_secret(checks, login_pasted,
                                                          password_on_clipboard,
                                                          monkeypatch):
    desktop = FakeDesktop([], foreground=focus_lost_after(checks))
    events, trace = run_autofill(monkeypatch, desktop)
    assert events.count(ENTER) == (1 if checks >= 2 else 0), (
        "najwyżej Enter wyboru profilu — nigdy Enter wysyłający formularz")
    assert ENTER not in secret_operations(events)
    pastes = events.count(CTRL_V)
    assert pastes == (1 if login_pasted else 0) + (1 if checks >= 6 else 0)
    assert (("clipboard_set", PASSWORD) in events) is password_on_clipboard
    if any(e[0] == "clipboard_set" and e[1] in (LOGIN, PASSWORD) for e in events):
        assert events[-2:] == [("clipboard_set", PREV_CLIP), ("attach", False)], (
            "schowek przywrócony od razu po blokadzie")
    assert trace.finished["error_code"] == "secret-input-blocked"
    assert trace.steps[-1]["reason"] == "foreground-is-other-window"


def test_5d_owner_image_replaced_during_autofill_blocks(monkeypatch):
    """PID reuse: same window handle, different image by the time we paste."""
    desktop = FakeDesktop([])
    original = desktop.foreground

    def swap_after_navigation(n):
        if n == 3:
            desktop.images[FORTI_PID] = EVIL_EXE
        return original(n)

    desktop.foreground = swap_after_navigation
    events, trace = run_autofill(monkeypatch, desktop)
    assert secret_operations(events) == []
    assert not [e for e in events if e[0] == "clipboard_set"]
    assert trace.steps[-1]["reason"] == "untrusted-image"


# ══════════════════════════════════════════════════════════════════════════
# EMS authentication window and 2FA token (6–7)
# ══════════════════════════════════════════════════════════════════════════

EDIT_CLS, BUTTON_CLS = "WindowsForms10.EDIT.app.0.141b42a_r6_ad1", "WindowsForms10.BUTTON.app.0.141b42a_r6_ad1"
LOGIN_EDIT, PASS_EDIT, TOKEN_EDIT, CONNECT_BTN, CANCEL_BTN = 0x3101, 0x3102, 0x3103, 0x3201, 0x3202


def auth_desktop(events, *, owner_pid=FORTI_PID, image=FORTI_TRAY, child_pids=None,
                 extra_windows=None):
    child_pids = child_pids or {}
    windows = {AUTH: (owner_pid, 51, AUTH)}
    for child in (LOGIN_EDIT, PASS_EDIT, TOKEN_EDIT, CONNECT_BTN, CANCEL_BTN):
        windows[child] = (child_pids.get(child, owner_pid), 51, AUTH)
    windows.update(extra_windows or {})
    return FakeDesktop(events, windows=windows, images={FORTI_PID: FORTI_TRAY,
                                                         owner_pid: image,
                                                         EVIL_PID: EVIL_EXE})


def install_win32gui(monkeypatch, sent, tops):
    """tops: list of (hwnd, title); every top window has the standard children."""
    children = [(LOGIN_EDIT, EDIT_CLS, ""), (PASS_EDIT, EDIT_CLS, ""),
                (TOKEN_EDIT, EDIT_CLS, ""), (CONNECT_BTN, BUTTON_CLS, "Connect"),
                (CANCEL_BTN, BUTTON_CLS, "Cancel")]
    titles = dict(tops)
    texts = {c: t for c, _, t in children}
    classes = {c: cls for c, cls, _ in children}

    def enum_windows(callback, extra):
        for hwnd, _title in tops:
            if callback(hwnd, extra) is False:
                break

    fake = SimpleNamespace(
        EnumWindows=enum_windows,
        IsWindowVisible=lambda h: True,
        GetWindowText=lambda h: titles.get(h, texts.get(h, "")),
        EnumChildWindows=lambda h, cb, extra: [cb(c, extra) for c, _, _ in children],
        GetClassName=lambda h: classes.get(h, "Static"),
        SendMessage=lambda h, msg, wp, lp: sent.append((h, msg, lp)),
    )
    monkeypatch.setitem(sys.modules, "win32gui", fake)
    monkeypatch.setitem(sys.modules, "win32con", SimpleNamespace(WM_SETTEXT=0x000C,
                                                                 BM_CLICK=0x00F5))
    clock = [0.0]

    def fake_time():
        clock[0] += 0.05
        return clock[0]

    monkeypatch.setattr(time, "time", fake_time)
    monkeypatch.setattr(time, "sleep", lambda s: None)


TITLE = "FortiClient VPN Authentication"


def test_6_trusted_auth_window_still_receives_credentials(monkeypatch):
    sent = []
    install_win32gui(monkeypatch, sent, [(AUTH, TITLE)])
    monkeypatch.setattr(vpn_connect, "_window_api", lambda: auth_desktop([]))
    ok, msg = vpn_connect._fill_forti_auth_window(LOGIN, PASSWORD, timeout=0.1)
    assert (ok, msg) == (True, "Łączenie przez FortiClient...")
    assert sent == [(LOGIN_EDIT, 0x000C, LOGIN), (PASS_EDIT, 0x000C, PASSWORD),
                    (CONNECT_BTN, 0x00F5, 0)]


def test_6b_trusted_auth_window_still_receives_the_token(monkeypatch):
    sent = []
    install_win32gui(monkeypatch, sent, [(AUTH, TITLE)])
    monkeypatch.setattr(vpn_connect, "_window_api", lambda: auth_desktop([]))
    ok, msg = vpn_connect.fill_forticlient_token(TOKEN, timeout=0.1)
    assert (ok, msg) == (True, "Token wpisany, kliknięto Connect.")
    assert sent == [(TOKEN_EDIT, 0x000C, TOKEN), (CONNECT_BTN, 0x00F5, 0)]


@pytest.mark.parametrize("owner_pid,image,child_pids,reason", [
    (EVIL_PID, EVIL_EXE, None, "untrusted-image"),                     # same title & classes
    (FORTI_PID, FORTI_TRAY, {PASS_EDIT: EVIL_PID}, "control-not-owned-by-target"),
    (FORTI_PID, FORTI_TRAY, {TOKEN_EDIT: EVIL_PID}, "control-not-owned-by-target"),
])
def test_7_untrusted_auth_window_gets_no_login_password_or_token(
        owner_pid, image, child_pids, reason, monkeypatch):
    sent = []
    install_win32gui(monkeypatch, sent, [(AUTH, TITLE)])
    desktop = auth_desktop([], owner_pid=owner_pid, image=image, child_pids=child_pids)
    monkeypatch.setattr(vpn_connect, "_window_api", lambda: desktop)

    assert vpn_connect._find_forti_auth_window(timeout=0.1) == (None, [], [])
    assert vpn_connect._fill_forti_auth_window(LOGIN, PASSWORD, timeout=0.1) == (False, "")
    ok, msg = vpn_connect.fill_forticlient_token(TOKEN, timeout=0.1)
    assert (ok, msg) == (False, "Nie znaleziono okna FortiClient z polem Token.")
    assert sent == [], "ani login, ani hasło, ani token, ani kliknięcie"

    text = diagnostics.get_store().read_jsonl()
    assert '"owner-rejected"' in text and f'"{reason}"' in text


def test_7b_impostor_first_real_window_second(monkeypatch):
    sent = []
    impostor = 0x4004
    install_win32gui(monkeypatch, sent, [(impostor, TITLE), (AUTH, TITLE)])
    desktop = auth_desktop([], extra_windows={impostor: (EVIL_PID, 66, impostor)})
    monkeypatch.setattr(vpn_connect, "_window_api", lambda: desktop)
    hwnd, edits, _ = vpn_connect._find_forti_auth_window(timeout=0.1)
    assert hwnd == AUTH and len(edits) == 3


def test_7c_owner_changes_between_find_and_send_blocks_the_token(monkeypatch):
    sent = []
    install_win32gui(monkeypatch, sent, [(AUTH, TITLE)])
    desktop = auth_desktop([])
    monkeypatch.setattr(vpn_connect, "_window_api", lambda: desktop)
    real_find = vpn_connect._find_forti_auth_window

    def find_then_swap(timeout=3.0, tr=None):
        found = real_find(timeout=timeout, tr=tr)
        desktop.images[FORTI_PID] = EVIL_EXE          # PID reused by another image
        return found

    monkeypatch.setattr(vpn_connect, "_find_forti_auth_window", find_then_swap)
    ok, _ = vpn_connect.fill_forticlient_token(TOKEN, timeout=0.1)
    assert ok is False and sent == []
    assert vpn_connect._fill_forti_auth_window(LOGIN, PASSWORD, timeout=0.1) == (False, "")
    assert sent == []
    assert '"secret-input-blocked"' in diagnostics.get_store().read_jsonl()


def test_7d_detail_panel_detection_ignores_an_impostor(monkeypatch):
    """The 2FA dialog must not open for a window that would be refused the token."""
    sent = []
    install_win32gui(monkeypatch, sent, [(AUTH, TITLE)])
    desktop = auth_desktop([], owner_pid=EVIL_PID, image=EVIL_EXE)
    monkeypatch.setattr(vpn_connect, "_window_api", lambda: desktop)
    hwnd, _edits, _buttons = vpn_connect._find_forti_auth_window(timeout=0.2)
    assert hwnd is None


def test_7e_no_candidate_window_writes_no_trace(monkeypatch):
    install_win32gui(monkeypatch, [], [])
    monkeypatch.setattr(vpn_connect, "_window_api", lambda: auth_desktop([]))
    assert vpn_connect._fill_forti_auth_window(LOGIN, PASSWORD, timeout=0.1) == (False, "")
    assert list(diagnostics.get_store().list_traces()) == [], (
        "0,1 s przy każdym connect nie śmieci")


# ══════════════════════════════════════════════════════════════════════════
# 8–9. Trace and clipboard
# ══════════════════════════════════════════════════════════════════════════

def test_8_secrets_never_reach_the_trace_store(monkeypatch):
    scenarios = [
        FakeDesktop([], set_foreground="fails"),
        FakeDesktop([], attach_ok=False),
        FakeDesktop([], images={FORTI_PID: EVIL_EXE}),
        FakeDesktop([], foreground=focus_lost_after(5)),
        FakeDesktop([]),
    ]
    for desktop in scenarios:
        trace = vpn_diag.start("vpn.autofill", provider="FortiClient",
                               automation_mode="tab_sequence")
        run_autofill(monkeypatch, desktop, trace=trace)
    sent = []
    install_win32gui(monkeypatch, sent, [(AUTH, TITLE)])
    monkeypatch.setattr(vpn_connect, "_window_api",
                        lambda: auth_desktop([], owner_pid=EVIL_PID, image=EVIL_EXE))
    vpn_connect.fill_forticlient_token(TOKEN, timeout=0.1)
    vpn_connect._fill_forti_auth_window(LOGIN, PASSWORD, timeout=0.1)

    text = diagnostics.get_store().read_jsonl()
    for secret in SECRETS:
        assert secret not in text, secret
    assert "Downloads" not in text and "Program Files" not in text, "bez ścieżek"
    for event in ("secret-input-blocked", "owner-rejected", "owner-verified",
                  "focus-failed", "target-window-untrusted"):
        assert event in text, event
    assert '"image_name": "forticlient.exe"' in text


def test_9_no_secret_is_prepared_before_the_target_is_confirmed(monkeypatch):
    for desktop in (FakeDesktop([], set_foreground="fails"), FakeDesktop([], attach_ok=False),
                    FakeDesktop([], images={FORTI_PID: EVIL_EXE}),
                    FakeDesktop([], foreground=focus_lost_after(1)),
                    FakeDesktop([], foreground=focus_lost_after(2))):
        events, _ = run_autofill(monkeypatch, desktop)
        assert not [e for e in events if e[0] == "clipboard_set"], (
            "sekret w schowku bez potwierdzonego celu")


def test_9c_login_prepared_after_confirmation_is_withdrawn_when_paste_is_blocked(monkeypatch):
    """Confirmed → on the clipboard → confirmation lost before Ctrl+V → restored."""
    desktop = FakeDesktop([], foreground=focus_lost_after(3))
    events, _ = run_autofill(monkeypatch, desktop)
    copy_at = events.index(("clipboard_set", LOGIN))
    assert [e for e in events[:copy_at] if e == ("fg_check",)][-1] == ("fg_check",)
    assert CTRL_V not in events
    assert events[-2:] == [("clipboard_set", PREV_CLIP), ("attach", False)]


def test_9b_password_is_never_on_the_clipboard_when_login_is_blocked(monkeypatch):
    desktop = FakeDesktop([], foreground=focus_lost_after(4))
    events, _ = run_autofill(monkeypatch, desktop)
    assert ("clipboard_set", LOGIN) in events
    assert ("clipboard_set", PASSWORD) not in events


# ══════════════════════════════════════════════════════════════════════════
# The guard itself
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("path,inside", [
    (FORTI_GUI, True),
    (FORTI_GUI.upper(), True),
    ("\\\\?\\" + FORTI_TRAY, True),
    (FORTI_DIR + r"\x64\helper.exe", True),
    (r"C:\Program Files\Fortinet\FortiClientEvil\FortiClient.exe", False),
    (FORTI_DIR + r"\..\FortiClient.exe", False),
    (FORTI_DIR, False),
    (EVIL_EXE, False),
    ("", False),
    (None, False),
])
def test_is_inside(path, inside):
    assert sw.is_inside(path, FORTI_DIR) is inside


def test_trusted_dirs_accept_only_program_files_installdir():
    roots = (r"C:\Program Files", r"C:\Program Files (x86)", r"D:\Program Files")
    existing = {r"D:\Program Files\Fortinet\FortiClient", r"C:\Users\Public\Forti"}
    is_dir = existing.__contains__
    assert sw.trusted_install_dirs(r"D:\Program Files\Fortinet\FortiClient", is_dir, roots) == (
        *sw.KNOWN_FORTI_DIRS, r"D:\Program Files\Fortinet\FortiClient")
    for untrusted in (r"C:\Users\Public\Forti", r"D:\Program Files\Ghost", "", 5, None,
                      r"C:\Program Files"):
        assert sw.trusted_install_dirs(untrusted, is_dir, roots) == sw.KNOWN_FORTI_DIRS


def test_verify_owner_uses_process_image_not_title():
    desktop = FakeDesktop([])
    trusted = (FORTI_DIR,)
    ok = sw.verify_window_owner(HWND, trusted, desktop)
    assert (ok.verified, ok.pid, ok.image_name) == (True, FORTI_PID, "forticlient.exe")
    desktop.images[FORTI_PID] = EVIL_EXE
    bad = sw.verify_window_owner(HWND, trusted, desktop)
    assert (bad.verified, bad.reason, bad.image_name) == (False, "untrusted-image",
                                                           "forticlient.exe")
    assert sw.verify_window_owner(None, trusted, desktop).reason == "no-window"


def test_guard_module_sends_no_input_and_touches_no_clipboard():
    tree = ast.parse(open(sw.__file__, encoding="utf-8").read())
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)} | {
        n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    for forbidden in ("SendInput", "SendMessage", "keybd_event", "PostMessage",
                      "SetClipboardText", "win32clipboard"):
        assert forbidden not in names


@pytest.mark.parametrize("answer", [(0, -150394016), (0, 4100), (41, 0), (41, -5)])
def test_invalid_hwnd_never_yields_a_garbage_pid(answer, monkeypatch):
    """GetWindowThreadProcessId leaves the PID uninitialised for a bad HWND.

    Found by the read-only smoke test on a real desktop (window_pid(0) returned
    -150394016).  A garbage PID could match a real FortiClient process, so a
    zero thread id or a non-positive PID must read as "unknown".
    """
    monkeypatch.setitem(sys.modules, "win32process",
                        SimpleNamespace(GetWindowThreadProcessId=lambda hwnd: answer))
    api = sw.Win32WindowApi()
    assert api.window_pid(0xDEAD) is None
    assert api.window_thread_id(0xDEAD) is None
    assert sw.verify_window_owner(0xDEAD, (FORTI_DIR,), api).reason == "no-process"


def test_real_windows_api_reads_this_process_image():
    """Read-only smoke test of the real seam: no window is touched."""
    api = sw.Win32WindowApi()
    image = api.process_image_path(os.getpid())
    assert image and os.path.normcase(image) == os.path.normcase(sys.executable)
    assert api.window_pid(0) is None
    assert api.process_image_path(0) is None


# ══════════════════════════════════════════════════════════════════════════
# Scope: timeouts, connect and production untouched
# ══════════════════════════════════════════════════════════════════════════

def _function_source(name):
    tree = ast.parse(open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read())
    return ast.unparse(next(n for n in ast.walk(tree)
                            if isinstance(n, ast.FunctionDef) and n.name == name))


def test_timeouts_unchanged():
    assert "_wait_forticlient_window(timeout=10.0)" in _function_source("_autofill_forticlient")
    assert "time.sleep(0.5)" in _function_source("_find_forti_auth_window")
    connect = _function_source("connect")
    assert "_fill_forti_auth_window(login, password, timeout=0.1)" in connect
    assert "_wait_forticlient_window(timeout=0.5)" in connect
    assert "def fill_forticlient_token(token: str, timeout: float=15.0)" in _function_source(
        "fill_forticlient_token")


def test_every_secret_sink_in_legacy_is_guarded():
    """Each function that sends a secret calls the guard before its first send."""
    autofill = _function_source("_autofill_forticlient")
    assert autofill.index("verify_window_owner") < autofill.index("acquire_focus") < \
        autofill.index("_copy_to_clipboard(login)")
    for name in ("_fill_forti_auth_window", "fill_forticlient_token"):
        src = _function_source(name)
        assert src.index("controls_belong_to") < src.index("win32con.WM_SETTEXT"), name
    assert "verify_window_owner" in _function_source("_find_forti_auth_window")


def test_production_still_uses_legacy_and_not_the_new_architecture():
    tree = ast.parse(open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read())
    modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert "secure_window" in modules
    assert not any(m and (m == "vpn" or m.startswith("vpn.")) for m in modules)
    for rel in (os.path.join("ui", "vpn_panel.py"), os.path.join("ui", "detail_panel.py")):
        source = open(os.path.join(_PARENT, rel), encoding="utf-8").read()
        assert "vpn_connect.connect_monitored" in source
        assert "secure_window" not in source and "FortiClientProvider" not in source
