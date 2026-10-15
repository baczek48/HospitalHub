"""Stage 35: the live harness's own pass/fail criterion.

`acquire-race` is run by hand, so until now its verdict was the one piece of
security reasoning in the tree that nothing checked.  Stage 34B showed why that
matters: the criterion demanded `reason == "target-minimised"` and therefore
reported WARN on a run where every invariant it actually cared about held.  The
reason code was decided by Windows — clicking minimise hands the foreground to
the next window, so the foreground term refuses first — and a criterion that
fails a run for that is measuring the operating system, not the code.

These tests are about the criterion only.  They import from `smoke/`, which is
legitimate here and nowhere else: `tests/` and `smoke/` are the two directories
the production tripwire excludes.
"""

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from smoke.activation_live import (  # noqa: E402
    SAFE_REFUSAL_REASONS, acquire_race_verdict,
)

NO_WRITES = {"restore_window": 0, "set_foreground_window": 0,
             "attach_thread_input": 0}


def verdict(**overrides):
    kwargs = dict(verified=False, writes=dict(NO_WRITES),
                  reason="target-minimised", target_was_minimised=True,
                  input_events=0, clipboard_writes=0)
    kwargs.update(overrides)
    return acquire_race_verdict(**kwargs)


@pytest.mark.parametrize("reason", SAFE_REFUSAL_REASONS)
def test_1_both_safe_refusals_pass(reason):
    """Which of the two arrives is Windows' choice, not a difference in safety."""
    ok, failures = verdict(reason=reason)
    assert ok and failures == []


def test_2_the_two_safe_reasons_are_exactly_these():
    assert set(SAFE_REFUSAL_REASONS) == {"target-minimised",
                                         "foreground-is-other-window"}


def test_3_an_unrelated_refusal_does_not_pass():
    """"It refused" is not the property; *why* it refused is part of it.

    A run that ends in `no-verified-target` refused too — because it never
    found the window.  That is a broken run, not a demonstration.
    """
    for reason in ("no-verified-target", "untrusted-image", "attach-failed",
                   "visibility-unknown", None):
        ok, failures = verdict(reason=reason)
        assert not ok, reason
        assert "powod odmowy jest bezpieczny" in failures


# ══════════════════════════════════════════════════════════════════════════
# The criterion may not be satisfied by a good-looking status alone
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("write", sorted(NO_WRITES))
def test_4_any_single_desktop_write_fails_the_run(write):
    ok, failures = verdict(writes=dict(NO_WRITES, **{write: 1}))
    assert not ok
    assert "{} == 0".format(write) in failures


def test_5_a_verified_window_fails_the_run():
    """If `acquire_any()` succeeded, Variant 2 did not do its job."""
    ok, failures = verdict(verified=True)
    assert not ok
    assert "acquire_any() odmowil" in failures


def test_6_a_run_where_nothing_was_minimised_proves_nothing():
    ok, failures = verdict(target_was_minimised=False)
    assert not ok
    assert "target byl zminimalizowany przez operatora" in failures


@pytest.mark.parametrize("field,label", [
    ("input_events", "brak zdarzen InputSystem"),
    ("clipboard_writes", "brak zapisow do schowka"),
])
def test_7_any_input_or_clipboard_activity_fails_the_run(field, label):
    ok, failures = verdict(**{field: 1})
    assert not ok and label in failures


def test_8_every_failing_invariant_is_named_not_just_the_first():
    """The report prints what went wrong, so the criterion has to say all of it."""
    ok, failures = verdict(verified=True, reason="attach-failed",
                           writes=dict(NO_WRITES, restore_window=1),
                           input_events=3)
    assert not ok
    assert len(failures) == 4, failures
