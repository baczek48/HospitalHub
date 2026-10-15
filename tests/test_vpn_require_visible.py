"""Stage 29 / Variant 1: the guards ask what the gate asked.

Stage 22 made the connect wait until the user had FortiClient in front of them,
and refused a minimised window while waiting.  Stage 25 then found that the
promise stopped at the door: inside the autofill every guard goes through
``confirm_target``, which never looks at ``is_iconic`` — so a client the user
minimised halfway through still satisfied all nine guards and received both
credentials (``test_vpn_minimised_race::test_6``, as it read before this
stage).

Variant 1 closes that with one condition in one place: ``VerifiedWindow``
carries a ``require_visible`` flag, ``confirm()`` applies it after the shared
check has already said yes, and the FortiClient main-window target is the only
thing that turns it on.  Nothing is added to the autofill, nothing is taken
from the legacy, and no new way of touching the desktop is introduced.

What this deliberately does **not** claim
-----------------------------------------
There is no atomicity between the last reading and the keystroke that follows
it; Windows does not offer any.  Every *closable* case — the window going away
between two operations — is closed here.  The microscopic gap inside a single
guarded operation stays open and is a known limitation, not an oversight.

``SW_RESTORE`` also stays exactly where it is, inside ``acquire_focus``.  That
is Variant 2's problem and is not touched.
"""

import ast
import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import secure_window as sw  # noqa: E402
from vpn import AutofillStatus  # noqa: E402
from vpn.providers import secure_target as st  # noqa: E402
from vpn.providers.secure_target import (  # noqa: E402
    REASON_MINIMISED, SecureWindowTarget, VerifiedWindow,
)
from tests.test_vpn_forticlient_autofill import (  # noqa: E402
    CTRL_V, ENTER, LOGIN, PASSWORD, clipboard_secrets, run, secret_ops,
)
from tests.test_vpn_secure_target import (  # noqa: E402
    FORTI_PID, HWND, OTHER, OUR_TID, TRUSTED, FakeDesktop, ListFinder,
    focus_lost_after,
)

FORTI_TID = 41


class IconicDesktop(FakeDesktop):
    """A desktop with an opinion about ``is_iconic`` — fixed, or on a counter.

    ``minimise_after`` counts *readings*, not operations, because that is what
    the guard actually does: one reading per confirmed guard.  It lets a test
    say "the user minimised the client just before the password" precisely.
    """

    def __init__(self, *, iconic=False, minimise_after=None, raises=False,
                 **kwargs):
        super().__init__(**kwargs)
        self._iconic = iconic
        self._minimise_after = minimise_after
        self._raises = raises
        self.iconic_reads = 0

    def is_iconic(self, hwnd):
        self.iconic_reads += 1
        if self._raises:
            raise OSError("pulpit odmówił odpowiedzi")
        if self._minimise_after is not None:
            return self.iconic_reads >= self._minimise_after
        return self._iconic


def window(desktop, *, require_visible=True):
    """A VerifiedWindow built directly — no focus taken, none needed here."""
    return VerifiedWindow(HWND, FORTI_PID, "forticlient.exe", TRUSTED, desktop,
                          OUR_TID, FORTI_TID, require_visible=require_visible)


# ══════════════════════════════════════════════════════════════════════════
# A. The condition itself
# ══════════════════════════════════════════════════════════════════════════

def test_1_a_visible_target_still_confirms():
    desktop = IconicDesktop(iconic=False)
    check = window(desktop).confirm()
    assert check.ok and check.reason == "focused"
    assert desktop.iconic_reads == 1, "dokładnie jeden dodatkowy odczyt"


def test_2_a_minimised_target_is_refused():
    check = window(IconicDesktop(iconic=True)).confirm()
    assert not check.ok and check.reason == REASON_MINIMISED


def test_3_a_desktop_that_cannot_tell_does_not_veto():
    """``None`` is "unknown", and unknown has never been a refusal here.

    Every fake ``WindowApi`` in this suite answers None, and Stage 22 settled
    the same rule for ``foreground_check``.  Treating it as a block would turn
    "we could not see" into "the user went away".
    """
    desktop = FakeDesktop()                      # base is_iconic -> None
    check = window(desktop).confirm()
    assert check.ok and check.reason == "focused"


def test_4_a_seam_that_raises_is_fail_closed():
    check = window(IconicDesktop(raises=True)).confirm()
    assert not check.ok
    assert check.reason.startswith("iconic-error:"), check.reason
    # And a guard built on it runs nothing at all.
    ran = []
    result = window(IconicDesktop(raises=True)).run_guarded(
        "test", lambda: ran.append(True))
    assert not result.performed and ran == []


def test_5_without_the_flag_the_old_behaviour_is_exactly_preserved():
    """A minimised window still confirms when nobody asked for visibility."""
    desktop = IconicDesktop(iconic=True)
    check = window(desktop, require_visible=False).confirm()
    assert check.ok and check.reason == "focused"
    assert desktop.iconic_reads == 0, "nie pytamy, gdy nikt nie prosił"


def test_5b_the_flag_can_only_narrow_never_widen():
    """A target the shared check already refused stays refused, and is not asked."""
    desktop = IconicDesktop(iconic=False, foreground=lambda n: OTHER)
    check = window(desktop).confirm()
    assert not check.ok and check.reason == "foreground-is-other-window"
    assert desktop.iconic_reads == 0, "confirm_target decyduje pierwszy"


# ══════════════════════════════════════════════════════════════════════════
# B. The real autofill, with the client going away mid-sequence
# ══════════════════════════════════════════════════════════════════════════

def test_6_minimised_before_the_first_secret_sends_no_login():
    # Readings: 1 V2 pre-check, 2 navigation, 3 locate-field, 4 profile reading
    # (2026-10-14), 5 login-clear, 6 login-probe, 7 login-clipboard <- the secret.
    result, events, _tr = run(desktop=IconicDesktop(minimise_after=7))

    assert result.status is not AutofillStatus.DONE
    assert not result.login_entered and not result.password_entered
    assert clipboard_secrets(events) == []
    assert secret_ops(events) == []
    assert result.blocked_at == "login-clipboard", result.blocked_at


def test_7_minimised_between_login_and_password_sends_no_password():
    # 8 confirm after the profile re-read, 9-10 login-paste and its confirm,
    # 11 login-verify, 12 password-clear-tab: the user puts the client away once
    # the username is in and before the password is anywhere near the clipboard.
    result, events, _tr = run(desktop=IconicDesktop(minimise_after=12))

    assert result.status is not AutofillStatus.DONE
    assert result.login_entered, "login zdążył wejść"
    assert not result.password_entered
    assert clipboard_secrets(events) == [LOGIN]
    assert PASSWORD not in [e[1] for e in events if e[0] == "clip_set"]
    assert ENTER not in events


def test_8_minimised_before_the_submit_sends_no_enter():
    # The pre-check, fourteen guards and four confirms after a profile re-read;
    # the nineteenth reading is the submit.
    result, events, _tr = run(desktop=IconicDesktop(minimise_after=19))

    assert result.status is not AutofillStatus.DONE
    assert result.login_entered and result.password_entered
    assert ENTER not in events, "Enter to próba połączenia — nie wolno jej wysłać"
    assert result.blocked_at == "submit", result.blocked_at


def test_9_switching_to_another_window_still_blocks_as_before():
    """The pre-existing refusal is untouched — this stage only added one term."""
    result, events, _tr = run(desktop=FakeDesktop(foreground=focus_lost_after(3)))
    assert result.status is not AutofillStatus.DONE
    assert clipboard_secrets(events) == []


def test_10_a_target_that_disappears_between_guards_is_still_fail_closed():
    """Owner gone mid-sequence: refused by the shared check, before iconic."""
    desktop = IconicDesktop(iconic=False)
    result, events, _tr = run(desktop=desktop)
    assert result.status is AutofillStatus.DONE          # baseline

    vanishing = IconicDesktop(iconic=False)
    original = vanishing.window_pid
    reads = {"n": 0}

    def pid_gone(hwnd):
        reads["n"] += 1
        return None if reads["n"] > 4 else original(hwnd)

    vanishing.window_pid = pid_gone
    result, events, _tr = run(desktop=vanishing)
    assert result.status is not AutofillStatus.DONE
    assert PASSWORD not in [e[1] for e in events if e[0] == "clip_set"]


# ══════════════════════════════════════════════════════════════════════════
# C. The legacy, and the default
# ══════════════════════════════════════════════════════════════════════════

def test_11_the_legacy_never_sees_the_option():
    """It does not build one of these at all — it calls the shared module."""
    legacy = open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read()
    for token in ("require_visible", "SecureWindowTarget", "VerifiedWindow"):
        assert token not in legacy, token
    shared = open(sw.__file__, encoding="utf-8").read()
    assert "require_visible" not in shared, \
        "warunek należy do warstwy V2, nie do modułu dzielonego z legacy"


def test_12_confirm_target_still_knows_nothing_about_iconic():
    source = open(sw.__file__, encoding="utf-8").read()
    body = source[source.index("def confirm_target"):source.index("def acquire_focus")]
    assert "is_iconic" not in body

    # Proof by behaviour as well: the shared function still passes a minimised
    # window, which is exactly why the new condition had to live above it.
    assert sw.confirm_target(HWND, FORTI_PID, TRUSTED,
                             IconicDesktop(iconic=True)).ok


def test_13_the_option_is_off_unless_someone_asks():
    plain = SecureWindowTarget(TRUSTED, api=IconicDesktop(iconic=True),
                               finder=ListFinder((HWND,)))
    acquired = plain.acquire_any()
    assert isinstance(acquired, VerifiedWindow)
    assert acquired.confirm().ok, "domyślnie zachowanie bez zmian"
    acquired.release()


def test_13b_the_forticlient_main_window_asks_and_the_auth_window_does_not():
    from vpn.providers import FortiClientProvider
    from tests.test_vpn_forticlient_detect import FakeEnvironment
    from tests.test_vpn_secure_target import FORTI_DIR, FORTI_GUI

    provider = FortiClientProvider(
        FakeEnvironment(files=[FORTI_GUI], dirs=[FORTI_DIR]))
    assert provider.secure_window_target()._require_visible is True
    assert provider.auth_window_target()._require_visible is False, \
        "okno EMS to inna ścieżka (WM_SETTEXT) — celowo poza zakresem"


# ══════════════════════════════════════════════════════════════════════════
# D. Shape of the change
# ══════════════════════════════════════════════════════════════════════════

def test_14_the_new_code_reaches_for_nothing():
    """One reading was added.  No way to move a window came with it."""
    tree = ast.parse(open(st.__file__, encoding="utf-8").read())
    function = next(n for n in ast.walk(tree)
                    if isinstance(n, ast.FunctionDef) and n.name == "confirm")
    names = {n.attr for n in ast.walk(function) if isinstance(n, ast.Attribute)}
    names |= {n.id for n in ast.walk(function) if isinstance(n, ast.Name)}
    assert "is_iconic" in names
    for banned in ("set_foreground_window", "SetForegroundWindow",
                   "restore_window", "ShowWindow", "SW_RESTORE",
                   "attach_thread_input", "AttachThreadInput", "SendInput",
                   "BringWindowToTop", "SetFocus", "SwitchToThisWindow"):
        assert banned not in names, banned


def test_15_the_check_lives_in_confirm_and_nowhere_else():
    """Not sprinkled through the autofill: one method protects all nine guards."""
    from vpn.providers import forticlient_autofill as fa

    autofill = open(fa.__file__, encoding="utf-8").read()
    for token in ("is_iconic", "require_visible", REASON_MINIMISED):
        assert token not in autofill, token

    # And the guard path really does funnel through `confirm`.
    tree = ast.parse(open(st.__file__, encoding="utf-8").read())
    guarded = next(n for n in ast.walk(tree)
                   if isinstance(n, ast.FunctionDef) and n.name == "run_guarded")
    calls = {n.func.attr for n in ast.walk(guarded)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert "confirm" in calls


def test_15b_every_guarded_operation_pays_for_exactly_one_reading():
    """One reading per guarded operation — plus the V2 acquire's own, plus one
    more wherever a key follows a profile re-read.

    Twenty in total: the Stage-33 pre-check that refuses to attach to a window
    which is not already in front and visible, then one per guarded operation
    (fourteen since the profile reading of 2026-10-14).  Stage 42 added three
    of those operations (two probes and a verify).  The five operations that
    re-read the profile first — both clipboard writes, both pastes and the
    submit — confirm the window again after that reading (Stage 63, R4), so
    they pay twice.  No operation slips past unmeasured.
    """
    desktop = IconicDesktop(iconic=False)
    result, _events, _tr = run(desktop=desktop)
    assert result.status is AutofillStatus.DONE
    assert desktop.iconic_reads == 20, desktop.iconic_reads
