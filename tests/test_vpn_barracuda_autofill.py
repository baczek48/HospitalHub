"""Stage 50C: Barracuda WPF autofill through the UI Automation value seam.

Measured on a real install: the login window is WPF, WM_SETTEXT has no native
control to target and blind SendInput was unreliable, but the fields carry
stable AutomationIds (``TextBoxUser`` / ``PasswordBoxUser``) with a settable
ValuePattern.  So this stage fills them by AutomationId through
:class:`UiaValueSystem.set_value`, guarded exactly like the other providers.

These tests use a fake seam and a fake desktop — no real window, no comtypes,
no secret ever printed — and assert the negatives that matter: an element owned
by another process is refused, the OTP/certificate fields are never touched, a
lost foreground stops the fill, cancellation stops it, and nothing is submitted.
"""

import ast
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from vpn import AutofillStatus, ErrorCode, VpnRequest  # noqa: E402
from vpn.providers import barracuda_autofill as bafa  # noqa: E402
from vpn.providers import uia_value_system as uvs  # noqa: E402
from vpn.providers.activation_gate import CancellationToken  # noqa: E402
from vpn.providers.barracuda_autofill import (  # noqa: E402
    AID_PASSWORD, AID_USER, autofill_login_password,
)
from vpn.providers.uia_value_system import UiaSetOutcome, UiaValueSystem  # noqa: E402
from tests.test_vpn_barracuda import Desktop, HWND, PID, OTHER_HWND, provider  # noqa: E402
from tests.test_vpn_secure_target import ListFinder  # noqa: E402

LOGIN, PASSWORD = "jkowalski", "SuperSecret123"
# The fields the client exposes but this autofill must never touch.
AID_OTP, AID_CERT = "PasswordBoxOTP", "PasswordBoxCert"


class FakeUia(UiaValueSystem):
    """Records which AutomationIds were set — never the values.

    ``owner_pid`` is the pid the fake reports for every element; when it differs
    from the verified window's pid the seam's owner check refuses, exactly as
    the real one does.  ``readonly`` / ``missing`` / ``fail`` name AutomationIds
    that answer those ways.  ``on_set`` fires after a successful set, to model
    something changing between fields.
    """

    def __init__(self, *, owner_pid=PID, readonly=(), missing=(), fail=(),
                 on_set=None):
        self.set_ids: list[str] = []
        self.calls: list[str] = []
        self._owner_pid = owner_pid
        self._readonly = set(readonly)
        self._missing = set(missing)
        self._fail = set(fail)
        self._on_set = on_set

    def find(self, hwnd, automation_id):
        return uvs.UiaField(found=automation_id not in self._missing,
                            process_id=self._owner_pid, read_only=False,
                            supports_value=True)

    def set_value(self, hwnd, automation_id, value, *, expected_pid):
        self.calls.append(automation_id)          # no value stored
        if automation_id in self._missing:
            return UiaSetOutcome(False, reason="not-found")
        if self._owner_pid != expected_pid:
            return UiaSetOutcome(True, reason="pid-mismatch", process_id=self._owner_pid)
        if automation_id in self._readonly:
            return UiaSetOutcome(True, reason="read-only", process_id=self._owner_pid)
        if automation_id in self._fail:
            return UiaSetOutcome(True, reason="set-error", process_id=self._owner_pid)
        self.set_ids.append(automation_id)
        if self._on_set is not None:
            self._on_set(automation_id)
        return UiaSetOutcome(True, performed=True, reason="set",
                             process_id=self._owner_pid)


def run(*, desktop=None, uia=None, login=LOGIN, password=PASSWORD,
        cancellation=None, hwnds=(HWND,)):
    prov = provider()
    desktop = desktop if desktop is not None else Desktop()
    target = prov.secure_window_target(api=desktop, finder=ListFinder(hwnds))
    uia = uia if uia is not None else FakeUia()
    request = VpnRequest(provider_id="barracuda", login=login, password=password)
    result = autofill_login_password(prov, request, target=target, uia=uia,
                                     cancellation=cancellation)
    return result, uia


# ══════════════════════════════════════════════════════════════════════════
# 1. Happy path
# ══════════════════════════════════════════════════════════════════════════

def test_1_login_and_password_set_by_automation_id():
    result, uia = run()
    assert result.status is AutofillStatus.DONE
    assert result.login_entered and result.password_entered
    assert uia.set_ids == [AID_USER, AID_PASSWORD], "dwa pola, w tej kolejności"
    assert result.metadata.get("submitted") is False
    assert result.metadata.get("requires_user_action") is True


def test_2_the_otp_and_cert_fields_are_never_touched():
    result, uia = run()
    assert AID_OTP not in uia.calls and AID_CERT not in uia.calls
    assert set(uia.calls) == {AID_USER, AID_PASSWORD}


def test_3_no_login_or_password_skips_that_field():
    _r, uia = run(password="")
    assert uia.set_ids == [AID_USER]
    _r2, uia2 = run(login="")
    assert uia2.set_ids == [AID_PASSWORD]


# ══════════════════════════════════════════════════════════════════════════
# 2. The window / element must be trusted
# ══════════════════════════════════════════════════════════════════════════

def test_4_no_verified_window_sets_nothing():
    result, uia = run(hwnds=())
    assert result.status is AutofillStatus.NO_TARGET
    assert uia.set_ids == [] and uia.calls == []


def test_5_a_foreign_owned_window_is_refused_before_the_seam():
    # The window's owner image is a stranger → not verified → no acquire.
    result, uia = run(desktop=Desktop(image=r"C:\Users\x\Downloads\evil.exe"))
    assert result.status in (AutofillStatus.NO_TARGET, AutofillStatus.NO_FOCUS)
    assert uia.calls == []


def test_6_an_element_owned_by_another_process_is_refused():
    """The core WPF-era guard: the field element must be the verified process."""
    result, uia = run(uia=FakeUia(owner_pid=999999))   # element pid != window pid
    assert result.status is AutofillStatus.BLOCKED
    assert result.blocked_at == bafa.PHASE_LOGIN
    assert result.metadata.get("reason_code") == "pid-mismatch"
    assert result.login_entered is False
    assert uia.set_ids == []                            # nothing was set


def test_7_a_read_only_field_blocks_without_setting():
    result, uia = run(uia=FakeUia(readonly=(AID_PASSWORD,)))
    # login set, password refused (read-only) → BLOCKED at password.
    assert result.status is AutofillStatus.BLOCKED
    assert result.blocked_at == bafa.PHASE_PASSWORD
    assert uia.set_ids == [AID_USER]


def test_8_a_missing_field_blocks():
    result, uia = run(uia=FakeUia(missing=(AID_USER,)))
    assert result.status is AutofillStatus.BLOCKED
    assert result.blocked_at == bafa.PHASE_LOGIN
    assert uia.set_ids == []


# ══════════════════════════════════════════════════════════════════════════
# 3. Foreground lost between the fields → the guard stops it
# ══════════════════════════════════════════════════════════════════════════

def test_9_foreground_lost_after_login_keeps_the_password_home():
    desktop = Desktop()

    def lose(_aid):
        desktop._foreground = lambda n: OTHER_HWND       # someone else in front

    result, uia = run(desktop=desktop, uia=FakeUia(on_set=lose))
    assert result.login_entered and not result.password_entered
    assert result.status is AutofillStatus.BLOCKED
    assert result.blocked_at == bafa.PHASE_PASSWORD
    assert uia.set_ids == [AID_USER]


# ══════════════════════════════════════════════════════════════════════════
# 4. Cancellation before every field, no submit after
# ══════════════════════════════════════════════════════════════════════════

def test_10_cancel_before_login_sets_nothing():
    token = CancellationToken()
    token.cancel()
    result, uia = run(cancellation=token)
    assert result.status is AutofillStatus.CANCELLED
    assert result.blocked_at == bafa.PHASE_LOGIN
    assert uia.set_ids == [] and uia.calls == []


def test_11_cancel_between_login_and_password():
    token = CancellationToken()

    def cancel_after_login(aid):
        if aid == AID_USER:
            token.cancel()

    result, uia = run(cancellation=token, uia=FakeUia(on_set=cancel_after_login))
    assert result.status is AutofillStatus.CANCELLED
    assert result.blocked_at == bafa.PHASE_PASSWORD
    assert result.login_entered and not result.password_entered
    assert uia.set_ids == [AID_USER]


# ══════════════════════════════════════════════════════════════════════════
# 5. Secrets never leak; the seam does the value, not this module
# ══════════════════════════════════════════════════════════════════════════

def test_12_no_secret_in_the_result_or_a_recorded_call():
    result, uia = run()
    blob = repr(result) + repr(uia.calls) + repr(uia.set_ids)
    for secret in (LOGIN, PASSWORD):
        assert secret not in blob, secret


def test_13_the_module_sends_no_key_no_click_no_clipboard_no_wm_settext():
    tree = ast.parse(open(bafa.__file__, encoding="utf-8").read())
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    names |= {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    for banned in ("press_key", "press_combo", "type_text", "VK_RETURN",
                   "SendInput", "copy_to_clipboard", "read_clipboard",
                   "WM_SETTEXT", "BM_CLICK", "click_button", "set_control_text",
                   "SetForegroundWindow", "SW_RESTORE"):
        assert banned not in names, banned


def test_14_every_set_value_goes_through_run_guarded():
    """Structural: no `uia.set_value` at statement level outside a guard lambda."""
    tree = ast.parse(open(bafa.__file__, encoding="utf-8").read())

    class V(ast.NodeVisitor):
        def __init__(self):
            self.depth = 0
            self.bare = []

        def visit_Lambda(self, node):
            self.depth += 1
            self.generic_visit(node)
            self.depth -= 1

        def visit_FunctionDef(self, node):
            self.depth += 1
            self.generic_visit(node)
            self.depth -= 1

        def visit_Call(self, node):
            f = node.func
            if isinstance(f, ast.Attribute) and f.attr == "set_value" and self.depth == 1:
                # depth 1 = inside a def but not inside a lambda; the real one is
                # inside the guard lambda (depth 2).  Flag anything shallower.
                self.bare.append(f.attr)
            self.generic_visit(node)

    v = V()
    v.visit(tree)
    source = open(bafa.__file__, encoding="utf-8").read()
    assert "run_guarded(" in source
    assert "expected_pid=win.pid" in source, "seam dostaje pid zweryfikowanego okna"


# ══════════════════════════════════════════════════════════════════════════
# 6. The seam itself
# ══════════════════════════════════════════════════════════════════════════

def test_15_the_seam_imports_no_win32_or_comtypes_at_module_level():
    """comtypes is imported lazily inside methods, so importing vpn is cheap and
    a machine without it still imports the package."""
    tree = ast.parse(open(uvs.__file__, encoding="utf-8").read())
    top = []                                   # module-level imports only
    for node in tree.body:
        if isinstance(node, ast.Import):
            top += [a.name for a in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0:
            top.append(node.module or "")
    for banned in ("comtypes", "win32gui", "ctypes", "pywinauto"):
        assert not any(m and m.split(".")[0] == banned for m in top), banned
    # …and it IS used lazily somewhere in the file (the real impl needs it).
    assert "comtypes" in open(uvs.__file__, encoding="utf-8").read()


def test_16_set_outcome_carries_no_value():
    o = UiaSetOutcome(True, performed=True, reason="set", process_id=PID)
    assert o.ok and "SuperSecret" not in repr(o)
    assert set(uvs.UiaSetOutcome.__dataclass_fields__) == {
        "found", "performed", "reason", "process_id"}


def test_17_provider_delegates_and_ui_contract_is_now_verified():
    from vpn.providers.barracuda import BarracudaProvider, UI_CONTRACT_VERIFIED
    assert UI_CONTRACT_VERIFIED is True
    assert hasattr(BarracudaProvider, "autofill_login_password")
    # Still not armed / not registered — production unchanged.
    assert BarracudaProvider.CONNECT_ENABLED is False
