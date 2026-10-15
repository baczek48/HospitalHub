"""Stage 18: which controls may receive an operation — and which merely exist.

Stage 17 put the contract in front of a real FortiClient and found a question
we had been asking wrongly.  The client's main window is Electron; its children
are a render surface owned by the client's own process **and** a Direct3D
surface owned by a *second* FortiClient process.  Measured on the live window:

    controls_belong_to(window, all children)  -> control-not-owned-by-target
    controls_belong_to(window, [renderer])    -> verified

So "is every child of this window mine?" answers *no* for a genuine client, and
answers nothing at all about where a secret would go.  The question that decides
whether a password is safe is asked per control: *may this handle receive it?*

These tests pin both halves: the per-control rule is exactly as strict as it
ever was (same process, same window — presence inside a trusted window buys a
handle nothing), while a foreign child the operation never touches no longer
condemns the window.  The EMS layout-integrity rule, which deliberately *does*
condemn a window over a foreign field, is unchanged.
"""

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import secure_window as sw  # noqa: E402
from vpn.providers import SecureWindowTarget, VerifiedWindow  # noqa: E402
from tests.test_vpn_secure_target import (  # noqa: E402
    EVIL_EXE, EVIL_PID, FORTI_DIR, FORTI_GUI, FORTI_PID, HWND, OTHER, TRUSTED,
    FakeDesktop, ListFinder,
)

# The live Electron layout, as observed: the window, a renderer of the same
# process, and a D3D surface belonging to a different FortiClient process.
RENDERER = 0x105DC
D3D_SURFACE = 0x105E4
GPU_PID = 9348
# A control of the right process that lives in another window of that process.
ELSEWHERE = 0x105F0
# A genuinely hostile control: another process' handle parented into our window.
HOSTILE = 0x105FF


def electron_desktop(**kwargs):
    """The real FortiClient main window's shape, on a fake desktop."""
    windows = {
        HWND: (FORTI_PID, 41, HWND),
        RENDERER: (FORTI_PID, 41, HWND),          # ours, in this window
        D3D_SURFACE: (GPU_PID, 77, HWND),         # FortiClient's GPU process
        ELSEWHERE: (FORTI_PID, 41, OTHER),        # ours, another window
        HOSTILE: (EVIL_PID, 99, HWND),            # stranger, in this window
        OTHER: (FORTI_PID, 41, OTHER),
    }
    images = {FORTI_PID: FORTI_GUI, GPU_PID: FORTI_GUI, EVIL_PID: EVIL_EXE}
    kwargs.setdefault("windows", windows)
    kwargs.setdefault("images", images)
    return FakeDesktop(**kwargs)


def target(desktop, finder=None):
    return SecureWindowTarget(TRUSTED, api=desktop,
                              finder=finder or ListFinder((HWND,)))


def acquired(desktop) -> VerifiedWindow:
    window = target(desktop).acquire(HWND)
    assert isinstance(window, VerifiedWindow), window
    return window


# ══════════════════════════════════════════════════════════════════════════
# 1 + 4. What the operation may touch
# ══════════════════════════════════════════════════════════════════════════

def test_1_electron_window_with_its_own_renderer_is_accepted():
    desktop = electron_desktop()
    check = sw.operation_controls_verified(HWND, [RENDERER], TRUSTED, desktop)
    assert check.ok and check.reason == "verified"


def test_4_a_control_of_the_verified_process_is_accepted():
    window = acquired(electron_desktop())
    assert window.operation_controls([RENDERER]).ok
    assert window.controls_owned([RENDERER]).ok
    guard = window.run_guarded("paste", lambda: "wysłano", controls=[RENDERER])
    assert guard.performed and guard.value == "wysłano"


# ══════════════════════════════════════════════════════════════════════════
# 2. Infrastructure children no longer condemn the window
# ══════════════════════════════════════════════════════════════════════════

def test_2_a_foreign_infrastructure_child_does_not_condemn_the_window():
    """The measured Electron case: a D3D surface of another process."""
    desktop = electron_desktop()
    children = [RENDERER, D3D_SURFACE]

    partition = sw.partition_controls(HWND, children, TRUSTED, desktop)
    assert partition.owner is not None and partition.owner.verified, \
        "okno nadal jest zweryfikowane, mimo obcego dziecka"
    assert partition.usable == (RENDERER,)
    assert partition.foreign == (D3D_SURFACE,)
    assert partition.ok is False, "nie wszystkie oferowane uchwyty są zdatne"

    # ...and the window itself is still a legitimate, usable target.
    assert sw.operation_controls_verified(HWND, [RENDERER], TRUSTED, desktop).ok
    assert sw.verify_window_owner(HWND, TRUSTED, desktop).verified


def test_2b_the_window_stays_usable_through_the_verified_handle():
    window = acquired(electron_desktop())
    partition = window.partition_controls([RENDERER, D3D_SURFACE])
    assert partition.usable == (RENDERER,) and partition.foreign == (D3D_SURFACE,)
    # The operation goes ahead on the usable handle only.
    guard = window.run_guarded("paste", lambda: "ok", controls=partition.usable)
    assert guard.performed


def test_2c_the_old_question_is_the_one_that_was_wrong():
    """Pins the actual defect: asking about every child rejects a real client."""
    desktop = electron_desktop()
    whole_tree = sw.controls_belong_to(HWND, [RENDERER, D3D_SURFACE], TRUSTED,
                                       desktop)
    assert whole_tree.ok is False
    assert whole_tree.reason == "control-not-owned-by-target"
    # Same desktop, same window, correct question:
    assert sw.operation_controls_verified(HWND, [RENDERER], TRUSTED, desktop).ok


# ══════════════════════════════════════════════════════════════════════════
# 3 + 6. A control the operation WOULD touch is still verified strictly
# ══════════════════════════════════════════════════════════════════════════

def test_3_an_operation_control_of_a_foreign_process_is_rejected():
    desktop = electron_desktop()
    check = sw.operation_controls_verified(HWND, [RENDERER, D3D_SURFACE],
                                           TRUSTED, desktop)
    assert check.ok is False and check.reason == "control-not-owned-by-target"


def test_6_being_inside_a_trusted_window_makes_a_control_nothing():
    """A stranger's handle parented into the real window is still a stranger."""
    desktop = electron_desktop()
    assert desktop.root_window(HOSTILE) == HWND, "naprawdę leży w tym oknie"
    check = sw.operation_controls_verified(HWND, [HOSTILE], TRUSTED, desktop)
    assert check.ok is False and check.reason == "control-not-owned-by-target"

    window = acquired(desktop)
    guard = window.run_guarded("paste", _must_not_run, controls=[HOSTILE])
    assert guard.performed is False


def test_6b_a_control_of_the_right_process_in_another_window_is_rejected():
    desktop = electron_desktop()
    check = sw.operation_controls_verified(HWND, [ELSEWHERE], TRUSTED, desktop)
    assert check.ok is False and check.reason == "control-outside-window"
    partition = sw.partition_controls(HWND, [ELSEWHERE], TRUSTED, desktop)
    assert partition.foreign == (ELSEWHERE,) and not partition.usable


def test_6c_the_two_ways_a_control_can_be_wrong_are_told_apart():
    desktop = electron_desktop()
    foreign_process = sw.operation_controls_verified(HWND, [D3D_SURFACE],
                                                     TRUSTED, desktop)
    other_window = sw.operation_controls_verified(HWND, [ELSEWHERE], TRUSTED,
                                                  desktop)
    assert foreign_process.reason == "control-not-owned-by-target"
    assert other_window.reason == "control-outside-window"
    # The legacy entry point keeps reporting the single string it always did.
    for control in (D3D_SURFACE, ELSEWHERE):
        legacy = sw.controls_belong_to(HWND, [control], TRUSTED, desktop)
        assert legacy.ok is False
        assert legacy.reason == "control-not-owned-by-target"


def _must_not_run():
    raise AssertionError("operacja wykonana mimo odrzuconej kontrolki")


# ══════════════════════════════════════════════════════════════════════════
# 5. EMS keeps its stricter rule
# ══════════════════════════════════════════════════════════════════════════

def test_5_ems_still_demands_that_every_offered_control_belongs():
    """The layout-integrity rule: one foreign field and the window is out."""
    desktop = electron_desktop()
    window = acquired(desktop)
    assert window.controls_owned([RENDERER]).ok
    assert window.controls_owned([RENDERER, D3D_SURFACE]).ok is False
    assert window.controls_owned([RENDERER, HOSTILE]).ok is False


def test_5b_the_ems_path_still_calls_the_strict_check():
    """Stage 15 is untouched: it condemns the auth window over a foreign field."""
    import ast
    from vpn.providers import forticlient_2fa as f2

    source = open(f2.__file__, encoding="utf-8").read()
    assert "win.controls_owned([c.hwnd for c in controls])" in source
    tree = ast.parse(source)
    calls = {n.func.attr for n in ast.walk(tree)
             if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute)}
    assert "controls_owned" in calls, "EMS nadal pyta o integralność układu"


def test_5c_the_legacy_module_is_untouched_and_still_curates_its_set():
    legacy = open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read()
    assert "controls_belong_to(hwnd, [token_edit] + [b for b, _ in buttons]," in legacy
    assert "controls_belong_to(hwnd, [edits[0][0], edits[1][0]] + " in legacy
    assert "partition_controls" not in legacy, "legacy nie zmienia kontraktu"


# ══════════════════════════════════════════════════════════════════════════
# 7. Stage 12/13 fail-closed, unchanged
# ══════════════════════════════════════════════════════════════════════════

def test_7_an_unverified_window_makes_every_control_foreign():
    desktop = electron_desktop(images={FORTI_PID: EVIL_EXE, GPU_PID: EVIL_EXE,
                                       EVIL_PID: EVIL_EXE})
    partition = sw.partition_controls(HWND, [RENDERER], TRUSTED, desktop)
    assert partition.owner is None
    assert partition.usable == () and partition.foreign == (RENDERER,)
    assert partition.ok is False
    assert partition.reason == "untrusted-image"
    assert sw.operation_controls_verified(HWND, [RENDERER], TRUSTED,
                                          desktop).ok is False


def test_7b_a_released_window_answers_no_to_everything():
    window = acquired(electron_desktop())
    window.release()
    assert window.operation_controls([RENDERER]).ok is False
    assert window.controls_owned([RENDERER]).ok is False
    partition = window.partition_controls([RENDERER])
    assert partition.owner is None and partition.foreign == (RENDERER,)
    assert window.run_guarded("paste", _must_not_run,
                              controls=[RENDERER]).performed is False


def test_7c_a_desktop_that_raises_is_refused_not_trusted():
    class Hostile(FakeDesktop):
        def window_pid(self, hwnd):
            if hwnd == RENDERER:
                raise OSError("GetWindowThreadProcessId failed")
            return super().window_pid(hwnd)

    desktop = Hostile(windows=electron_desktop().windows,
                      images=electron_desktop().images)
    partition = sw.partition_controls(HWND, [RENDERER], TRUSTED, desktop)
    assert partition.foreign == (RENDERER,)
    assert sw.operation_controls_verified(HWND, [RENDERER], TRUSTED,
                                          desktop).ok is False


def test_7d_losing_the_foreground_still_beats_a_perfect_control_set():
    """Control ownership is never a substitute for the focus confirmation."""
    desktop = electron_desktop(foreground=lambda n: HWND if n <= 1 else OTHER)
    window = acquired(desktop)
    guard = window.run_guarded("paste", _must_not_run, controls=[RENDERER])
    assert guard.performed is False
    assert guard.reason == "foreground-is-other-window"


@pytest.mark.parametrize("controls", [[], ()])
def test_an_empty_operation_set_is_vacuously_fine(controls):
    """The Electron main window enumerates no input controls at all."""
    desktop = electron_desktop()
    assert sw.operation_controls_verified(HWND, controls, TRUSTED, desktop).ok
    assert sw.partition_controls(HWND, controls, TRUSTED, desktop).ok


def test_the_autofill_never_passes_controls_at_all():
    """Stage 14 guards on owner+foreground; the Electron window has no fields."""
    import ast
    from vpn.providers import forticlient_autofill as fa

    tree = ast.parse(open(fa.__file__, encoding="utf-8").read())
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) \
                and node.func.attr == "run_guarded":
            assert not [k for k in node.keywords if k.arg == "controls"], \
                "autofill nie ma kontrolek do sprawdzenia — okno jest Electronem"
