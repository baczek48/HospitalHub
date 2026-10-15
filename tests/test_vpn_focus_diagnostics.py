"""Stage 20: the focus attempt explains itself — without changing its mind.

`acquire_focus` decided "yes" or "no" and said almost nothing about why, which
is how Stage 19 ended up with a theory instead of an answer.  It now collects
the surrounding facts — which window held the foreground, which process, the
Win32 error, how long since the user last touched the machine — but only when
a caller asks, and never as an input to a decision.

Two properties are worth more than the rest and both are pinned here:

* **with `diagnose` off, not one extra call reaches the desktop.**  That keeps
  the production path identical and keeps the measurement from disturbing what
  it measures — the fake desktops in this suite count foreground reads.
* **the notes are numbers.**  Handles, pids, thread ids, booleans, an idle time
  and an error code.  No window title (a title is whatever document the user
  has open), no image path (it contains their profile directory).
"""

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import secure_window as sw  # noqa: E402
from vpn.providers import SecureWindowTarget, TargetRejected, VerifiedWindow  # noqa: E402
from tests.test_vpn_secure_target import (  # noqa: E402
    EVIL_PID, FORTI_PID, HWND, OTHER, TRUSTED, FakeDesktop, ListFinder,
)

USER_PATH = r"C:\Users\Sebastian\Documents\pacjent-kowalski.pdf"


class CountingDesktop(FakeDesktop):
    """Counts every question asked of the desktop, per method.

    Keeps the base WindowApi answer of None for the Stage-20 questions:
    these tests are about what the notes record when a seam *cannot tell*, so
    this desktop must go on not telling even after Stage 33B taught the plain
    fake to state its visibility.
    """

    def __init__(self, **kwargs):
        kwargs.setdefault('iconic', None)
        super().__init__(**kwargs)
        self.calls = {}

    def _tally(self, name):
        self.calls[name] = self.calls.get(name, 0) + 1

    def foreground_window(self):
        self._tally("foreground_window")
        return super().foreground_window()

    def window_pid(self, hwnd):
        self._tally("window_pid")
        return super().window_pid(hwnd)

    def window_thread_id(self, hwnd):
        self._tally("window_thread_id")
        return super().window_thread_id(hwnd)


class TellingDesktop(CountingDesktop):
    """A desktop that can answer the Stage-20 questions."""

    def __init__(self, *, idle=12.5, iconic=False, sfw_error=0, **kwargs):
        super().__init__(**kwargs)
        self.idle, self.iconic, self.sfw_error = idle, iconic, sfw_error

    def user_idle_seconds(self):
        self._tally("user_idle_seconds")
        return self.idle

    def is_iconic(self, hwnd):
        self._tally("is_iconic")
        return self.iconic

    def set_foreground_window_detail(self, hwnd):
        ok = super().set_foreground_window(hwnd)
        return ok, None if ok else self.sfw_error


def acquire(desktop, *, diagnose=False, hwnd=HWND, pid=FORTI_PID):
    return sw.acquire_focus(hwnd, pid, TRUSTED, desktop, diagnose=diagnose)


# ══════════════════════════════════════════════════════════════════════════
# 1. The notes are collected
# ══════════════════════════════════════════════════════════════════════════

def test_a_refusal_records_why_it_was_refused():
    desktop = TellingDesktop(set_foreground="fail", idle=0.2, sfw_error=0)
    result = acquire(desktop, diagnose=True)

    assert result.ok is False and result.reason == "set-foreground-failed"
    notes = result.diagnostics
    assert notes["set_foreground_ok"] is False
    assert notes["set_foreground_error"] == 0
    assert notes["attach_ok"] is True
    assert notes["idle_s"] == 0.2
    assert notes["target_pid"] == FORTI_PID and notes["target_tid"]
    assert notes["foreground_before"] == HWND
    assert notes["foreground_after"] == HWND, "odmowa nie zmienia foreground"
    assert "confirm_ok" not in notes, "nie doszliśmy do potwierdzenia"


def test_a_success_records_the_confirmation_too():
    result = acquire(TellingDesktop(idle=40.0), diagnose=True)
    assert result.ok is True
    notes = result.diagnostics
    assert notes["set_foreground_ok"] is True
    assert notes["confirm_ok"] is True and notes["confirm_reason"] == "focused"
    assert notes["idle_s"] == 40.0
    assert "set_foreground_error" not in notes


def test_the_foreground_owner_is_recorded_on_both_sides():
    desktop = TellingDesktop(set_foreground="fail",
                             foreground=lambda n: OTHER)
    notes = acquire(desktop, diagnose=True).diagnostics
    assert notes["foreground_before"] == OTHER
    assert notes["foreground_pid_before"] == EVIL_PID
    assert notes["foreground_tid_before"] == 99
    assert notes["target_pid"] == FORTI_PID


def test_a_minimised_target_is_recorded_as_such():
    notes = acquire(TellingDesktop(iconic=True), diagnose=True).diagnostics
    assert notes["target_iconic"] is True


@pytest.mark.parametrize("failure,expected_reason", [
    (dict(windows={HWND: (FORTI_PID, None, HWND)}), "no-thread"),
    (dict(attach_ok=False), "attach-failed"),
    (dict(set_foreground="fail"), "set-foreground-failed"),
])
def test_every_refusal_path_still_answers_the_same_way(failure, expected_reason):
    plain = acquire(TellingDesktop(**failure))
    noted = acquire(TellingDesktop(**failure), diagnose=True)
    assert plain.reason == noted.reason == expected_reason
    assert plain.ok is noted.ok is False
    assert plain.diagnostics == {}, "bez pytania — bez notatek"


# ══════════════════════════════════════════════════════════════════════════
# 2. Win32 that misbehaves
# ══════════════════════════════════════════════════════════════════════════

def test_a_seam_that_raises_leaves_the_notes_safe_and_the_answer_unchanged():
    class Hostile(TellingDesktop):
        def user_idle_seconds(self):
            raise OSError("GetLastInputInfo failed")

        def is_iconic(self, hwnd):
            raise OSError("IsIconic failed")

        def foreground_window(self):
            raise OSError("GetForegroundWindow failed")

    result = acquire(Hostile(set_foreground="fail"), diagnose=True)
    assert result.ok is False and result.reason == "set-foreground-failed"
    for absent in ("idle_s", "target_iconic", "foreground_before",
                   "foreground_after"):
        assert absent not in result.diagnostics, absent
    assert result.diagnostics["attach_ok"] is True


def test_a_seam_that_cannot_tell_records_nothing_rather_than_a_lie():
    """The base WindowApi answers None to the Stage-20 questions."""
    result = acquire(CountingDesktop(set_foreground="fail"), diagnose=True)
    assert "idle_s" not in result.diagnostics
    assert "target_iconic" not in result.diagnostics
    assert "set_foreground_error" not in result.diagnostics
    assert result.diagnostics["set_foreground_ok"] is False


def test_the_detail_call_defaults_to_the_plain_one():
    desktop = CountingDesktop()
    assert desktop.set_foreground_window_detail(HWND) == (True, None)
    desktop = CountingDesktop(set_foreground="fail")
    assert desktop.set_foreground_window_detail(HWND) == (False, None)


def test_pywin32_refusal_maps_to_false_exactly_as_before():
    """The real seam: an exception is False, a return is True — unchanged."""
    import types

    api = sw.Win32WindowApi()
    fake = types.SimpleNamespace()
    refusal = OSError("refused")
    refusal.winerror = 0
    fake.SetForegroundWindow = lambda hwnd: (_ for _ in ()).throw(refusal)
    sys.modules["win32gui"] = fake
    try:
        assert api.set_foreground_window_detail(HWND) == (False, 0)
        assert api.set_foreground_window(HWND) is False
        fake.SetForegroundWindow = lambda hwnd: 1
        assert api.set_foreground_window_detail(HWND) == (True, None)
        assert api.set_foreground_window(HWND) is True
    finally:
        del sys.modules["win32gui"]


# ══════════════════════════════════════════════════════════════════════════
# 3. No secrets, ever
# ══════════════════════════════════════════════════════════════════════════

def test_the_notes_carry_only_documented_keys():
    for kwargs in (dict(), dict(set_foreground="fail"), dict(attach_ok=False)):
        notes = acquire(TellingDesktop(**kwargs), diagnose=True).diagnostics
        assert set(notes) <= set(sw.FOCUS_DIAGNOSTIC_KEYS), set(notes)


def test_no_documented_key_smells_like_a_credential():
    from diagnostics.redactor import is_secret_key
    for key in sw.FOCUS_DIAGNOSTIC_KEYS:
        assert not is_secret_key(key), key


def test_the_notes_carry_no_title_and_no_path():
    """A hostile desktop volunteering user data must not get it into a result."""
    class Chatty(TellingDesktop):
        def process_image_path(self, pid):
            return USER_PATH if pid == EVIL_PID else super().process_image_path(pid)

    notes = acquire(Chatty(set_foreground="fail"), diagnose=True).diagnostics
    blob = repr(notes)
    for leak in (USER_PATH, "Sebastian", "pacjent", ".pdf"):
        assert leak not in blob, leak
    assert all(isinstance(v, (int, float, bool, type(None)))
               or isinstance(v, str) and len(v) < 40 for v in notes.values())


def test_the_only_text_in_the_notes_is_a_reason_code():
    notes = acquire(TellingDesktop(), diagnose=True).diagnostics
    text = {k: v for k, v in notes.items() if isinstance(v, str)}
    assert set(text) <= {"confirm_reason"}
    assert text.get("confirm_reason") == "focused"


# ══════════════════════════════════════════════════════════════════════════
# 4 + 5. The decision, and the desktop, are untouched
# ══════════════════════════════════════════════════════════════════════════

def test_diagnosing_costs_the_desktop_nothing_when_it_is_off():
    quiet = TellingDesktop()
    acquire(quiet, diagnose=False)
    talkative = TellingDesktop()
    acquire(talkative, diagnose=True)

    assert quiet.calls["foreground_window"] == 1, "tylko confirm_target pyta"
    assert talkative.calls["foreground_window"] > quiet.calls["foreground_window"]
    assert "user_idle_seconds" not in quiet.calls
    assert "is_iconic" not in quiet.calls


def test_the_answer_is_identical_with_and_without_the_notes():
    for kwargs in (dict(), dict(set_foreground="fail"), dict(attach_ok=False),
                   dict(foreground=lambda n: OTHER)):
        plain = acquire(TellingDesktop(**kwargs))
        noted = acquire(TellingDesktop(**kwargs), diagnose=True)
        assert (plain.ok, plain.reason, plain.attached) == \
               (noted.ok, noted.reason, noted.attached), kwargs


def test_no_focus_still_means_no_focus_through_the_provider():
    desktop = TellingDesktop(set_foreground="fail")
    target = SecureWindowTarget(TRUSTED, api=desktop, finder=ListFinder((HWND,)))
    rejected = target.acquire_any(diagnose=True)
    assert isinstance(rejected, TargetRejected)
    assert rejected.reason == "set-foreground-failed"
    assert rejected.diagnostics["set_foreground_ok"] is False
    assert target.last_focus_diagnostics["idle_s"] == 12.5


def test_a_verified_window_is_still_verified_and_carries_no_notes_itself():
    desktop = TellingDesktop()
    target = SecureWindowTarget(TRUSTED, api=desktop, finder=ListFinder((HWND,)))
    window = target.acquire_any(diagnose=True)
    assert isinstance(window, VerifiedWindow)
    assert not hasattr(window, "diagnostics")
    assert target.last_focus_diagnostics["confirm_ok"] is True
    window.release()


def test_the_autofill_does_not_ask_for_notes_and_sends_nothing_extra():
    """Stage 14 is untouched: it never turns diagnosis on."""
    import ast
    from vpn.providers import forticlient_autofill as fa

    tree = ast.parse(open(fa.__file__, encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            assert not [k for k in node.keywords if k.arg == "diagnose"], \
                "autofill nie włącza diagnostyki"


# ══════════════════════════════════════════════════════════════════════════
# 6. Parity with legacy
# ══════════════════════════════════════════════════════════════════════════

def test_legacy_calls_the_same_function_and_gets_the_same_decision():
    legacy = open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read()
    assert "focus = acquire_focus(hwnd, owner.pid, trusted, api)" in legacy
    assert "diagnose" not in legacy, "legacy nie prosi o notatki i nic nie płaci"


def test_legacy_shaped_call_leaves_the_notes_empty():
    """Positional call, exactly as the legacy makes it."""
    result = sw.acquire_focus(HWND, FORTI_PID, TRUSTED, TellingDesktop())
    assert result.ok is True and result.diagnostics == {}


def test_diagnose_is_keyword_only_so_no_caller_turns_it_on_by_accident():
    import inspect
    parameter = inspect.signature(sw.acquire_focus).parameters["diagnose"]
    assert parameter.kind is inspect.Parameter.KEYWORD_ONLY
    assert parameter.default is False
