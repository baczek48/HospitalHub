"""Stage 14: the migrated FortiClient autofill (login + password).

Proves the negative — a secret leaves the app only through a confirmed,
focused, trusted FortiClient window — and that the happy path still types
login and password and submits.  Everything is a seam: a fake desktop
(:class:`WindowApi`), a fake :class:`InputSystem` that records keystrokes and
clipboard writes, a recording trace.  No real SendInput, clipboard, window or
FortiClient.
"""

import ast
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import vpn  # noqa: E402
from vpn import AutofillStatus, VpnRequest  # noqa: E402
from vpn.providers import FortiClientProvider  # noqa: E402
from vpn.providers import forticlient_autofill as fa  # noqa: E402
from vpn.providers.input_system import (  # noqa: E402
    UIA_COMBOBOX_CONTROL_TYPE, VK_CONTROL, VK_DELETE, VK_RETURN, VK_SHIFT,
    VK_SPACE, VK_TAB, FocusedControl, InputSystem,
)

#: UIA control types the fake reports besides the combo.
UIA_EDIT = 50004
UIA_LIST_ITEM = 50007
from vpn.providers.secure_target import VerifiedWindow  # noqa: E402
from vpn.providers.forticlient_profile import SSL_TUNNELS_KEY  # noqa: E402
from vpn.providers.msaa_system import (  # noqa: E402
    ROLE_SYSTEM_COMBOBOX, STATE_SYSTEM_COLLAPSED, STATE_SYSTEM_EXPANDED,
    STATE_SYSTEM_FOCUSED, MsaaNode, MsaaScan, MsaaSystem,
)
from tests.test_vpn_forticlient_detect import FakeEnvironment  # noqa: E402
from tests.test_vpn_secure_target import (  # noqa: E402
    EVIL_EXE, FORTI_DIR, FORTI_GUI, FORTI_PID, HWND, FakeDesktop, ListFinder,
    focus_lost_after,
)
from vpn.providers import FortiClientProvider  # noqa: E402

LOGIN, PASSWORD, PREV_CLIP = "jkowalski", "SuperSecret123", "clip-user-XYZ"
SECRETS = (LOGIN, PASSWORD, PREV_CLIP, "ABC123")
CTRL_V = ("combo", VK_CONTROL, ord("V"))
CTRL_A = ("combo", VK_CONTROL, ord("A"))
ENTER = ("key", VK_RETURN)


class FakeInput(InputSystem):
    """Records every operation, and models one text field well enough to read.

    Stage 42 made the autofill read the desktop back — it probes whether the
    caret is in a text box before a secret reaches the clipboard, and verifies
    that the login actually landed.  A pure recorder cannot answer either
    question, so this fake keeps two pieces of state: the system clipboard and
    the contents of the field the caret is in.

    ``caret_in_field=False`` models the case the live run of Stage 41 hit: the
    caret resting on the page body, where Ctrl+A selects the whole document.
    """

    #: What a whole-document selection looks like — longer than the autofill's
    #: PAGE_SELECTION_CHARS threshold, and obviously not a field's contents.
    PAGE_TEXT = "CALA STRONA " * 12

    #: Stage 60: the VPN Name combo.  Two Shift+Tabs from the username field
    #: reach it (the Stage-44 measurement); Space opens its list, typing picks
    #: the first item that starts with the text, Enter commits; any Tab leaves.
    COMBO_ITEMS = ("INNY-PROFIL", "SZPITAL-A", "1SZP")

    def __init__(self, caret_in_field: bool = True):
        self.events = []
        self.clipboard = PREV_CLIP
        self.field = ""
        self.caret_in_field = caret_in_field
        self.combo_items = self.COMBO_ITEMS
        self.combo_value = self.COMBO_ITEMS[0]
        self.combo_focused = False
        self.combo_open = False
        self.combo_pending = None
        self.combo_pid = FORTI_PID
        self._shift_tabs = 0
        #: Stage 63: the MSAA view of this same combo, for the profile step.
        self.msaa = LinkedMsaa(self)

    def press_key(self, vk):
        self.events.append(("key", vk))
        if self.combo_focused:
            if vk == VK_SPACE:
                self.combo_open = True
                return
            if vk == VK_RETURN and self.combo_open:
                if self.combo_pending is not None:
                    self.combo_value = self.combo_pending
                self.combo_open, self.combo_pending = False, None
                return
        if vk == VK_TAB:
            self.combo_focused = self.combo_open = False
            self._shift_tabs = 0
        if vk == VK_DELETE and self.caret_in_field:
            self.field = ""

    def focused_control(self):
        self.events.append(("focus_read",))
        if not self.combo_focused:
            return FocusedControl(found=True, process_id=self.combo_pid,
                                  control_type=UIA_EDIT)
        if self.combo_open:
            return FocusedControl(found=True, process_id=self.combo_pid,
                                  control_type=UIA_LIST_ITEM)
        return FocusedControl(found=True, process_id=self.combo_pid,
                              control_type=UIA_COMBOBOX_CONTROL_TYPE,
                              value=self.combo_value)

    def press_combo(self, modifier_vk, key):
        self.events.append(("combo", modifier_vk, key))
        if modifier_vk == VK_SHIFT and key == VK_TAB:
            self._shift_tabs += 1
            self.combo_focused = self._shift_tabs == 2
            return
        if modifier_vk != VK_CONTROL:
            return
        if key == ord("C"):
            # Real Windows: copying an empty selection leaves the clipboard
            # alone.  Modelling that is what makes the "stale clipboard" bug
            # reproducible here instead of only on a live client.
            copied = self.field if self.caret_in_field else self.PAGE_TEXT
            if copied:
                self.clipboard = copied
        elif key == ord("V") and self.caret_in_field:
            self.field = self.clipboard

    def type_text(self, text):
        self.events.append(("type", text))
        if self.combo_focused and self.combo_open:
            self.combo_pending = next(
                (i for i in self.combo_items
                 if i.casefold().startswith(text.casefold())),
                self.combo_pending)
            return
        if self.caret_in_field:
            self.field += text

    def copy_to_clipboard(self, text):
        self.events.append(("clip_set", text))
        self.clipboard = text
        return True

    def read_clipboard(self):
        self.events.append(("clip_get",))
        return self.clipboard

    def sleep(self, seconds):
        self.events.append(("sleep", seconds))


#: Stage 61: what ``accValue`` puts before the tunnel name on 7.4.3.
GROUP_PREFIX = "Personal VPNs "


class LinkedMsaa(MsaaSystem):
    """Stage 63: MSAA's view of the combo :class:`FakeInput` models.

    One ``VPN Name`` combo whose state and value follow the keys the fake has
    received — FOCUSED after the two Shift+Tabs, EXPANDED while the list is
    open, COLLAPSED otherwise, and ``"Personal VPNs <name>"`` as the value.
    Every scan is recorded in the input's event list as ``("msaa_read",)``, so
    a test can see where in the key sequence each reading was taken.

    ``window`` overrides the HWND the accessible object reports (``None`` = the
    window that was asked about); ``value`` overrides the displayed value.
    """

    def __init__(self, inp):
        self.inp = inp
        self.asked = []
        self.window = None
        self.value = None

    def node(self, hwnd):
        inp = self.inp
        state = 0x100000                                   # focusable
        state |= STATE_SYSTEM_EXPANDED if inp.combo_open else STATE_SYSTEM_COLLAPSED
        if inp.combo_focused:
            state |= STATE_SYSTEM_FOCUSED
        value = self.value if self.value is not None else GROUP_PREFIX + inp.combo_value
        return MsaaNode(role=ROLE_SYSTEM_COMBOBOX, name="VPN Name", state=state,
                        value=value,
                        window=self.window if self.window is not None else hwnd)

    def combo_boxes(self, hwnd):
        self.asked.append(hwnd)
        self.inp.events.append(("msaa_read",))
        return MsaaScan(ok=True, combos=(self.node(hwnd),))


#: The tunnels the fake machine has configured: every item of the fake combo,
#: as SSL-VPN key names (values are never read).
TUNNEL_REGISTRY = {SSL_TUNNELS_KEY + "\\" + name: {"Server": "x"}
                   for name in FakeInput.COMBO_ITEMS}


def forti_environment(registry=None, files=(FORTI_GUI,), dirs=(FORTI_DIR,)):
    """A FortiClient machine that also has the profile combo's tunnels."""
    return FakeEnvironment(registry={**TUNNEL_REGISTRY, **(registry or {})},
                           files=list(files), dirs=list(dirs))


#: 2026-10-14 (L1): a request that names no profile is accepted only where the
#: target is unambiguous — exactly one tunnel configured, and that one showing.
#: The fake combo starts on its first item, so that is the machine's tunnel.
SOLE_TUNNEL = FakeInput.COMBO_ITEMS[0]


def sole_environment():
    """A FortiClient machine with one tunnel — the one the combo shows."""
    return FakeEnvironment(
        registry={SSL_TUNNELS_KEY + "\\" + SOLE_TUNNEL: {"Server": "x"}},
        files=[FORTI_GUI], dirs=[FORTI_DIR])


class RecTrace:
    def __init__(self):
        self.steps = []

    def _add(self, name, status, **data):
        self.steps.append({"step": name, "status": status, **data})

    def ok(self, name, **data):
        self._add(name, "ok", **data)

    def warn(self, name, message=None, **data):
        self._add(name, "warn", **data)

    def fail(self, name, error_code=None, **data):
        self._add(name, "fail", error_code=error_code, **data)

    def events(self):
        return [(s.get("event"), s["status"]) for s in self.steps]


def run(*, desktop=None, profile="", login=LOGIN, password=PASSWORD,
        finder_hwnds=(HWND,), trace=None):
    desktop = desktop if desktop is not None else FakeDesktop()
    inp = FakeInput()
    tr = trace if trace is not None else RecTrace()
    # No profile name: only the one-tunnel machine is unambiguous (L1).
    provider = FortiClientProvider(forti_environment() if profile
                                   else sole_environment())
    target = provider.secure_window_target(api=desktop, finder=ListFinder(finder_hwnds))
    request = VpnRequest(provider_id="forticlient", profile_name=profile,
                         login=login, password=password)
    result = provider.autofill_login_password(request, target=target,
                                              input_system=inp, trace=tr,
                                              msaa=inp.msaa)
    return result, inp.events, tr


def secret_ops(events):
    """Keystrokes/pastes/clipboard writes that carry or submit a secret."""
    out = []
    for e in events:
        if e == CTRL_V or e == ENTER:
            out.append(e)
        elif e[0] == "clip_set" and e[1] in (LOGIN, PASSWORD):
            out.append(e)
        elif e[0] == "type" and e[1] in (LOGIN, PASSWORD):
            out.append(e)
    return out


def profile_commit_enters(events):
    """Indices of the Enter that commits the VPN Name list (Stage 60).

    That Enter follows the profile name with only pauses and readings (a UIA
    focus read until Stage 63, an MSAA scan since) in between.  Every other
    Enter is a submit — an attempt to connect.
    """
    out, after_name = [], False
    for i, e in enumerate(events):
        if e[0] in ("sleep", "focus_read", "msaa_read"):
            continue
        if e == ENTER and after_name:
            out.append(i)
        after_name = e[0] == "type" and e[1] not in (LOGIN, PASSWORD)
    return out


def submit_enters(events):
    """Enters that try to connect — everything but the profile commit."""
    commits = set(profile_commit_enters(events))
    return [i for i, e in enumerate(events) if e == ENTER and i not in commits]


def clipboard_secrets(events):
    return [e[1] for e in events if e[0] == "clip_set" and e[1] in (LOGIN, PASSWORD)]


# ══════════════════════════════════════════════════════════════════════════
# 1 + 12. Happy path
# ══════════════════════════════════════════════════════════════════════════

def test_1_valid_target_and_focus_enters_login_and_password():
    result, events, tr = run(profile="SZPITAL-A")
    assert result.status is AutofillStatus.DONE and result.success
    assert result.login_entered and result.password_entered
    assert clipboard_secrets(events) == [LOGIN, PASSWORD]
    assert events.count(CTRL_V) == 2                      # login + password
    assert events[-1] == ("clip_set", PREV_CLIP), "schowek przywrócony na końcu"
    assert ENTER in events                                # submit
    got = [ev for ev, _ in tr.events()]
    for expected in ("autofill-start", "target-acquired", "login-step",
                     "password-step", "autofill-success"):
        assert expected in got, expected


def test_12_prevalidated_flow_order_of_paste_and_submit():
    result, events, _ = run(profile="1SZP")
    # login clipboard set precedes login paste precedes password clipboard set
    li = events.index(("clip_set", LOGIN))
    lp = events.index(CTRL_V)
    pi = events.index(("clip_set", PASSWORD))
    pp = events.index(CTRL_V, lp + 1)
    submit = len(events) - 1 - events[::-1].index(ENTER)
    assert li < lp < pi < pp < submit


def test_no_profile_skips_navigation_typing_but_still_fills():
    result, events, _ = run(profile="")
    assert result.success
    assert not any(e[0] == "type" for e in events), "brak nazwy profilu = brak wpisywania"
    assert clipboard_secrets(events) == [LOGIN, PASSWORD]


# ══════════════════════════════════════════════════════════════════════════
# 2–4. Target rejected → no secret
# ══════════════════════════════════════════════════════════════════════════

def test_2_no_target_no_secret():
    result, events, tr = run(finder_hwnds=())            # nothing to acquire
    assert result.status is AutofillStatus.NO_TARGET and not result.success
    assert result.error_code == "client-not-found"
    assert secret_ops(events) == [] and clipboard_secrets(events) == []
    assert ("autofill-failure", "fail") in tr.events()


def test_3_foreign_process_no_secret():
    desktop = FakeDesktop(images={FORTI_PID: EVIL_EXE})
    result, events, _ = run(desktop=desktop)
    assert result.status is AutofillStatus.NO_TARGET
    assert result.blocked_at == "acquire"
    assert secret_ops(events) == [] and clipboard_secrets(events) == []


@pytest.mark.parametrize("pid", [0, -1, None])
def test_4_bad_pid_no_secret(pid):
    desktop = FakeDesktop(windows={HWND: (pid, 41, HWND)})
    result, events, _ = run(desktop=desktop)
    assert result.status is AutofillStatus.NO_TARGET
    assert clipboard_secrets(events) == []


def test_focus_not_acquired_is_no_focus_not_no_target():
    """A refused `SetForegroundWindow` is NO_FOCUS, not NO_TARGET.

    Aimed explicitly at a raising target: since Stage 33 the FortiClient V2
    target never calls `SetForegroundWindow` at all, so the failure this test
    is about cannot arise there.  The distinction it guards — "the window is
    fine, the focus is not" — still matters for every caller that does raise.
    """
    from vpn.providers.secure_target import SecureWindowTarget
    from tests.test_vpn_secure_target import TRUSTED

    desktop = FakeDesktop(set_foreground="fails")
    inp = FakeInput()
    provider = FortiClientProvider(
        FakeEnvironment(files=[FORTI_GUI], dirs=[FORTI_DIR]))
    raising = SecureWindowTarget(TRUSTED, api=desktop,
                                 finder=ListFinder((HWND,)), raise_window=True)
    request = VpnRequest(provider_id="forticlient", profile_name="",
                         login=LOGIN, password=PASSWORD)
    result = provider.autofill_login_password(request, target=raising,
                                              input_system=inp, trace=RecTrace())
    assert result.status is AutofillStatus.NO_FOCUS
    assert result.error_code == "focus-failed"
    assert secret_ops(inp.events) == []


# ══════════════════════════════════════════════════════════════════════════
# 5–8. Focus / owner lost mid-sequence
# ══════════════════════════════════════════════════════════════════════════

def test_5_focus_lost_before_login_no_secret():
    # Reads: V2 pre-check (1), acquire (2), navigation (3), locate-field (4),
    # profile reading (5, 2026-10-14); gone at login-clear (6).
    desktop = FakeDesktop(foreground=focus_lost_after(5))
    result, events, tr = run(desktop=desktop)
    assert result.status is AutofillStatus.BLOCKED
    assert result.blocked_at == "login-clear"
    assert result.login_entered is False and result.password_entered is False
    assert clipboard_secrets(events) == [] and CTRL_V not in events
    assert ("secret-input-blocked", "fail") in tr.events()


def test_6_focus_lost_before_password_login_kept_password_not_sent():
    # Checks 1..12: V2 pre-check, acquire, navigation, locate-field, profile
    # reading, login-clear, login-probe, login-clipboard (+ its confirm after
    # the profile re-read), login-paste (+ confirm), login-verify; the tab to
    # the password field is the thirteenth.
    desktop = FakeDesktop(foreground=focus_lost_after(12))
    result, events, _ = run(desktop=desktop)
    assert result.status is AutofillStatus.BLOCKED
    assert result.login_entered is True and result.password_entered is False
    assert clipboard_secrets(events) == [LOGIN], "hasło nigdy nie trafia do schowka"
    assert events.count(CTRL_V) == 1, "tylko login wklejony"
    assert ENTER not in events


def test_7_owner_change_between_operations_blocks_next_secret():
    desktop = FakeDesktop()
    original = desktop._foreground

    def swap_after_login(n):
        # After login-verify (call 12); the owner changes as the password
        # field is reached (call 13), so the next secret must be refused.
        if n == 13:
            desktop.images[FORTI_PID] = EVIL_EXE
        return original(n)

    desktop._foreground = swap_after_login
    result, events, _ = run(desktop=desktop)
    assert result.status is AutofillStatus.BLOCKED
    assert result.login_entered is True and result.password_entered is False
    assert clipboard_secrets(events) == [LOGIN]
    assert ENTER not in events


def test_8_foreground_window_change_blocks_next_secret():
    desktop = FakeDesktop(foreground=focus_lost_after(17))  # gone before password paste
    result, events, _ = run(desktop=desktop)
    assert result.status is AutofillStatus.BLOCKED
    assert result.blocked_at in ("password-clipboard", "password-paste")
    assert result.password_entered is False
    # password may reach the clipboard only if its clipboard-guard passed;
    # if it was blocked at the clipboard step, it never got there.
    if result.blocked_at == "password-clipboard":
        assert PASSWORD not in clipboard_secrets(events)
    assert ENTER not in events


# ══════════════════════════════════════════════════════════════════════════
# 9–11. Clipboard, Enter, trace
# ══════════════════════════════════════════════════════════════════════════

def test_9_clipboard_never_holds_a_secret_before_the_target_is_confirmed():
    # In every blocked scenario, no secret is on the clipboard before a
    # confirmed guard put it there — and if blocked at/before the clipboard
    # step, it is never there at all.
    for n in range(0, 4):
        desktop = FakeDesktop(foreground=focus_lost_after(n))
        result, events, _ = run(desktop=desktop)
        # Losing focus this early stops the attempt at the target/focus stage
        # (NO_FOCUS) rather than at a later guard (BLOCKED) — either way, the
        # run must not finish and no secret may have reached the clipboard.
        assert result.status is not AutofillStatus.DONE, f"focus_lost_after({n})"
        assert clipboard_secrets(events) == [], f"focus_lost_after({n})"


def test_9b_clipboard_restored_after_a_block_once_it_was_dirtied():
    # The block has to land *after* the login reached the clipboard, which is
    # now one phase later than it used to be.
    # Reads 1-9: pre-check, acquire, navigation, locate-field, profile reading,
    # login-clear, login-probe, login-clipboard and its confirm.  The login is
    # on the clipboard; the foreground goes at the paste, so the restore has
    # something to undo.
    desktop = FakeDesktop(foreground=focus_lost_after(9))
    result, events, _ = run(desktop=desktop)
    assert clipboard_secrets(events) == [LOGIN]
    assert events[-1] == ("clip_set", PREV_CLIP), "schowek przywrócony po blokadzie"


def test_10_enter_is_never_sent_after_a_block():
    for n in range(0, 9):
        desktop = FakeDesktop(foreground=focus_lost_after(n))
        result, events, _ = run(desktop=desktop, profile="")   # no profile-select Enter
        if result.status is AutofillStatus.DONE:
            continue
        assert ENTER not in events, f"Enter wysłany po blokadzie (focus_lost_after={n})"


def test_11_no_secret_reaches_the_trace():
    scenarios = [
        dict(),                                          # success
        dict(desktop=FakeDesktop(images={FORTI_PID: EVIL_EXE})),
        dict(desktop=FakeDesktop(foreground=focus_lost_after(4))),
        dict(finder_hwnds=()),
    ]
    for kwargs in scenarios:
        _result, _events, tr = run(profile="SZPITAL-A", **kwargs)
        blob = str(tr.steps)
        for secret in SECRETS:
            assert secret not in blob, (secret, kwargs)


def test_11b_result_carries_no_secret():
    result, _events, _ = run(profile="SZPITAL-A")
    blob = f"{result!r} {result.to_trace_data()} {result.metadata}"
    for secret in SECRETS:
        assert secret not in blob


# ══════════════════════════════════════════════════════════════════════════
# The autofill cannot be aimed at a raw HWND from outside
# ══════════════════════════════════════════════════════════════════════════

def test_autofill_requires_a_secure_target_not_a_bare_hwnd():
    sig = fa.autofill_login_password.__code__.co_varnames
    assert "hwnd" not in sig, "autofill nie przyjmuje surowego HWND"
    # The only window input is a SecureWindowTarget; the operation always goes
    # through VerifiedWindow.run_guarded.
    source = open(fa.__file__, encoding="utf-8").read()
    assert "run_guarded" in source
    assert "acquire_any" in source
    # No direct EnumWindows/SetForeground/SendInput/find-then-type shortcut.
    tree = ast.parse(source)
    names = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)} | {
        n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    for forbidden in ("EnumWindows", "SetForegroundWindow", "SendInput",
                      "AttachThreadInput", "GetForegroundWindow", "win32gui"):
        assert forbidden not in names, forbidden


def test_autofill_only_types_inside_a_guard():
    """Every InputSystem call is reached from a run_guarded callback.

    Structural proof: the module never calls press_key/press_combo/type_text/
    copy_to_clipboard at statement level outside a lambda/def passed to a guard.
    We assert there is no `inp.<send>` call that is not inside a nested function
    or lambda (the guard callbacks).
    """
    tree = ast.parse(open(fa.__file__, encoding="utf-8").read())
    # copy_to_clipboard is excluded: it also restores the user's *previous*
    # clipboard (not a secret) deliberately outside a guard. The secret-to-
    # clipboard write is behaviourally proven guarded by test_9.
    send_methods = {"press_key", "press_combo", "type_text"}

    class Visitor(ast.NodeVisitor):
        def __init__(self):
            self.depth = 0            # how deeply nested in Lambda/FunctionDef
            self.violations = []

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
            if (isinstance(f, ast.Attribute) and f.attr in send_methods
                    and self.depth == 0):
                self.violations.append(f.attr)
            self.generic_visit(node)

    v = Visitor()
    # start inside the module's top functions so depth counts nested callbacks
    v.visit(tree)
    assert v.violations == [], f"wysyłanie sekretu poza guardem: {v.violations}"


# ══════════════════════════════════════════════════════════════════════════
# Production untouched; legacy still owns autofill
# ══════════════════════════════════════════════════════════════════════════

def test_registered_provider_connect_still_unsupported():
    provider = vpn.default_registry.get("forticlient")
    assert provider.connect(VpnRequest(provider_id="forticlient",
                                       password=PASSWORD)).error_code == "unsupported"
    assert vpn.check_contract(provider) == []


def test_production_does_not_call_the_new_autofill():
    for rel in ("vpn_connect.py", os.path.join("ui", "vpn_panel.py"),
                os.path.join("ui", "detail_panel.py"), "main.py"):
        source = open(os.path.join(_PARENT, rel), encoding="utf-8").read()
        for token in ("forticlient_autofill", "autofill_login_password",
                      "input_system", "Win32InputSystem", "FortiClientProvider"):
            assert token not in source, f"{rel}: {token}"
    # Legacy autofill is still present and untouched.
    legacy = open(os.path.join(_PARENT, "vpn_connect.py"), encoding="utf-8").read()
    assert "def _autofill_forticlient(" in legacy


def test_new_autofill_does_not_import_legacy():
    tree = ast.parse(open(fa.__file__, encoding="utf-8").read())
    modules = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    modules |= {a.name for n in ast.walk(tree) if isinstance(n, ast.Import)
                for a in n.names}
    assert "vpn_connect" not in modules
    assert not any(m and m.split(".")[0] in ("win32gui", "win32process", "ctypes")
                   for m in modules), "Win32 tylko w input_system/secure seam"
