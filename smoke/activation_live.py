"""Stage 24 — does the activation gate behave on a real FortiClient?

Stage 22 built the gate and Stage 23 put a banner on it, both against fakes.
What a fake cannot answer is whether the *real* client — an Electron window
owning a Direct3D surface from a second process, on a desktop where Windows
refuses to hand us the foreground — is seen, pinned and waited for the way the
design assumes.

Everything here is an observation.  Nothing switches production, arms
``connect()``, touches the UI panels, or sends a character.  The gate itself is
read-only by construction; these commands add no way for it to become anything
else, and two of them exist precisely to prove that the *guards after* the gate
still close when the user walks away mid-flow.

Commands
--------
Read-only, safe at any time::

    py -3.13 -m smoke.activation_live probe

Disturbs the desktop (starts the client, or waits with a window on screen)::

    py -3.13 -m smoke.activation_live launch     --i-am-at-the-keyboard
    py -3.13 -m smoke.activation_live wait       --i-am-at-the-keyboard [--ui]
    py -3.13 -m smoke.activation_live zero-wait  --i-am-at-the-keyboard
    py -3.13 -m smoke.activation_live race       --i-am-at-the-keyboard
    py -3.13 -m smoke.activation_live cancel     --i-am-at-the-keyboard

Scenarios, and which command performs them
------------------------------------------
=====  ==========================================  ====================
A      client exists, another window in front      ``wait``
B      the user switches to the client mid-wait    ``wait --ui`` (by hand)
C      the client is already in front              ``zero-wait``
D      foreground lost *after* the gate said yes   ``race``
E      client → other → client while waiting       ``wait`` (by hand)
F      Cancel, on the real banner                  ``cancel``
=====  ==========================================  ====================

What none of this does
----------------------
No real login, no real password, no token, no Enter, no connect, no clipboard
write, no keystroke.  ``race`` runs the Stage-14 autofill with the sending seam
replaced by the recorder from ``forticlient_live`` — the one that stores
lengths, never content — and carries the same literal placeholders.

Nothing printed here is a secret or a user's data: state names, counters,
reason codes, a window handle, a pid and an executable's base name.  Window
titles are deliberately never read — they are whatever the user happens to
have open.  That is the same line the Stage 17-20 tooling already draws.
"""

from __future__ import annotations

import argparse
import os
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import secure_window as sw                                       # noqa: E402
import vpn                                                       # noqa: E402
from vpn import AutofillStatus, VpnRequest                       # noqa: E402
from vpn.providers.activation_gate import (                      # noqa: E402
    ActivationGate, ActivationState, CancellationToken,
)
from vpn.providers.secure_target import VerifiedWindow           # noqa: E402
from vpn.providers.window_message_system import (                # noqa: E402
    Win32WindowMessageSystem,
)
from vpn import AutofillResult, AutofillStatus                   # noqa: E402
from vpn.providers import forticlient_connect as fcc             # noqa: E402
from vpn.providers.forticlient_runtime import FortiConnectRuntime  # noqa: E402
from vpn.providers.launch_system import LaunchSystem             # noqa: E402
from smoke.forticlient_live import (                             # noqa: E402
    BAD, DRY_LOGIN, DRY_PASSWORD, INFO, OK, WARN, BlockedInput, head, line,
    steal_foreground,
)

#: Long enough for a person to alt-tab and click, short enough that a forgotten
#: run does not hold a terminal for a minute.  Overridable per command.
DEFAULT_TIMEOUT_S = 20.0


def beep(kind: str = "act") -> None:
    """A sound the operator can actually hear, distinct per step.

    Two rising tones mean "the first thing is now"; three short high ones mean
    "the second thing is now".  They differ on purpose: the operator is meant
    to be looking at FortiClient, not at a terminal, so the cue has to say
    *which* step it is without being read.
    """
    try:
        import winsound
        if kind == "act":
            winsound.Beep(700, 180)
            time.sleep(0.05)
            winsound.Beep(1100, 260)
        else:
            for _ in range(3):
                winsound.Beep(1400, 120)
                time.sleep(0.07)
    except Exception:
        print("\a", end="", flush=True)      # last resort: a real terminal


#: Refusals that mean "the window was not a place a secret may go".  Both are
#: correct outcomes of the same operator action, and which one arrives is
#: decided by Windows, not by us: clicking the minimise button hands the
#: foreground to the next window, so `confirm_target` refuses on the
#: foreground term before the visibility term is ever reached.  A minimised
#: window that *keeps* the foreground — measured in Stage 24 after a
#: programmatic minimise — produces the other.  Treating only one as a pass
#: would fail the run for a property of Windows.
SAFE_REFUSAL_REASONS = ("target-minimised", "foreground-is-other-window")


def acquire_race_verdict(*, verified, writes, reason, target_was_minimised,
                         input_events=0, clipboard_writes=0):
    """Did the run demonstrate a safe refusal?  Pure decision, no printing.

    Separated from the command so the criterion itself can be tested — it is
    the thing that says whether a security property held, and a criterion that
    is only ever exercised by a manual run is a criterion nobody checks.

    Returns ``(ok, failures)``; `failures` names every invariant that did not
    hold, so the report can print them rather than a single verdict word.
    """
    checks = (
        ("acquire_any() odmowil", not verified),
        ("target byl zminimalizowany przez operatora", bool(target_was_minimised)),
        ("restore_window == 0", writes.get("restore_window", 0) == 0),
        ("set_foreground_window == 0", writes.get("set_foreground_window", 0) == 0),
        ("attach_thread_input == 0", writes.get("attach_thread_input", 0) == 0),
        ("brak zdarzen InputSystem", input_events == 0),
        ("brak zapisow do schowka", clipboard_writes == 0),
        ("powod odmowy jest bezpieczny", reason in SAFE_REFUSAL_REASONS),
    )
    failures = [name for name, held in checks if not held]
    return (not failures), failures


def provider():
    return vpn.default_registry.get("forticlient")


def target():
    return provider().secure_window_target()


def report_check(check, *, prefix="foreground_check") -> None:
    """Print a reading.  Handle, pid and image only — never a title."""
    status = OK if check.ok else (INFO if check.found else WARN)
    line(status, f"{prefix}: ok={check.ok} found={check.found} "
                 f"reason={check.reason}")
    if check.found or check.pid:
        line(INFO, f"  hwnd={hex(check.hwnd) if check.hwnd else None} "
                   f"pid={check.pid} image={check.image_name} "
                   f"foreground={check.foreground} iconic={check.iconic}")


def report_result(result, desktop_reads: int | None = None) -> None:
    line(OK if result.ok else WARN,
         f"state={result.state.value} reason={result.reason}")
    line(INFO, f"  polls={result.polls} waited_s={result.waited_s:.2f} "
               f"repins={result.repins}")
    line(INFO, f"  pinned: hwnd={hex(result.hwnd) if result.hwnd else None} "
               f"pid={result.pid} image={result.image_name}")
    if desktop_reads is not None:
        line(INFO, f"  odczytów foreground: {desktop_reads}")


class CountingApi(sw.Win32WindowApi):
    """The real desktop, with a counter.  Reads only — it adds no capability.

    Exists so the report can say how many times the gate looked, which is the
    difference between "it waited" and "it gave up immediately".
    """

    def __init__(self):
        super().__init__()
        self.fg_checks = 0

    def foreground_window(self):
        self.fg_checks += 1
        return super().foreground_window()


def live_gate(*, timeout_s: float, cancellation=None, observer=None,
              api=None) -> tuple:
    """A gate pointed at the real client.  Real clock: this one really waits."""
    api = api if api is not None else CountingApi()
    gate = ActivationGate(
        target=provider().secure_window_target(api=api),
        cancellation=cancellation if cancellation is not None
        else CancellationToken(),
        timeout_s=timeout_s, observer=observer)
    return gate, api


def require_window() -> bool:
    found = target().first_verified_candidate()
    if found is None:
        line(WARN, "brak zweryfikowanego okna FortiClienta",
             "uruchom GUI klienta (`launch --i-am-at-the-keyboard`) i powtórz")
        return False
    hwnd, owner = found
    line(OK, f"zweryfikowane okno: hwnd={hex(hwnd)} pid={owner.pid} "
             f"image={owner.image_name}")
    return True


# --------------------------------------------------------------------------- #
# Taking the foreground away — honestly, and giving it back                    #
# --------------------------------------------------------------------------- #

class ForegroundWatchingInput(BlockedInput):
    """The recorder from Stage 17, plus: who was in front at that instant?

    This is the question scenario D is really asking.  "The autofill refused"
    is reassuring but indirect; "not one simulated keystroke happened while a
    different window held the foreground" is the property that keeps a password
    out of somebody else's text box, and it can only be measured here, at the
    moment of each send.
    """

    def __init__(self, target_hwnd):
        super().__init__()
        self.hwnd = target_hwnd
        self.misdirected: list[tuple] = []

    def _record(self, event) -> None:
        import win32gui
        if event[0] in ("type", "key", "combo", "clipboard-write-blocked"):
            # "Foreground" alone is not the safety condition.  Stage 19
            # measured that a *minimised* window can still be reported as the
            # foreground window, and keystrokes do not reach a minimised
            # window's fields — so the same pair the Stage-22 reading uses is
            # the pair that matters here: in front AND not iconic.
            try:
                usable = (win32gui.GetForegroundWindow() == self.hwnd
                          and not win32gui.IsIconic(self.hwnd))
            except Exception:
                usable = None
            if usable is not True:
                self.misdirected.append(event)
        super()._record(event)


def wait_for_operator_to_switch_away(target_hwnd, seconds: float):
    """Block until the operator clicks another window.  Read-only, always.

    Part A of Stage 25 needs the one state this machine will not produce on
    request: a *foreign* process holding the foreground while our flow tries to
    take it back.  Stage 24 established that no amount of asking moves it —
    starting a window does not claim the foreground from the client, and
    ``SetForegroundWindow`` from a background process is refused by policy.

    So the tool stops asking and waits.  A person clicks; this function only
    looks, once every 200 ms, at ``GetForegroundWindow()``.  It never restores,
    activates, attaches, or sends anything — the barrier is a pause, not a
    mechanism, and that is what keeps the measurement honest.

    Returns ``(switched, front_hwnd, front_pid)``.
    """
    import win32gui
    import win32process

    line(INFO, "")
    beep("step2")
    line(INFO, "  >>> KLIKNIJ TERAZ W INNE OKNO (np. przegladarke albo edytor).")
    line(INFO, f"  >>> Czekam do {seconds:.0f} s. Narzedzie tylko PATRZY na "
               f"foreground — niczego nie przestawia.")
    line(INFO, "")
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        time.sleep(0.2)
        try:
            front = win32gui.GetForegroundWindow()
        except Exception:
            continue
        if not front or front == target_hwnd:
            continue
        try:
            root = win32gui.GetAncestor(front, 2)             # GA_ROOT
        except Exception:
            root = front
        if root == target_hwnd:
            continue
        try:
            _tid, pid = win32process.GetWindowThreadProcessId(front)
        except Exception:
            pid = None
        return True, front, pid
    return False, None, None


def take_foreground_away(target_hwnd):
    """Stop the client from being the usable foreground window.

    Two ways, tried in that order, because they are not equally convincing:

    ``other-window`` — start a plain Notepad and wait for it to claim the
    foreground.  This is what a user switching away actually looks like.  On
    this machine it **does not happen**: the client keeps the foreground even
    after another process opens a window (measured 2026-09-14), which is the
    same wall Stage 18's ``--steal-focus-at`` hit.

    ``minimise`` — minimise the client.  The window stops being usable
    (Stage 22's reading refuses it as ``target-minimised``) even though Windows
    may still report it as the foreground.  Weaker than the first, but real,
    reversible, and measurable without a person in the chair.

    Returns ``(how, cleanup)``, or ``(None, cleanup)`` when neither worked.
    """
    import subprocess
    import win32gui

    helper = subprocess.Popen(["notepad.exe"])

    def cleanup():
        helper.terminate()
        try:
            win32gui.ShowWindow(target_hwnd, 9)               # SW_RESTORE
        except Exception:
            pass

    for _ in range(20):
        time.sleep(0.25)
        current = win32gui.GetForegroundWindow()
        if current and current != target_hwnd:
            return "other-window", cleanup

    helper.terminate()
    try:
        win32gui.ShowWindow(target_hwnd, 6)                   # SW_MINIMIZE
    except Exception:
        return None, cleanup
    for _ in range(20):
        time.sleep(0.1)
        if win32gui.IsIconic(target_hwnd):
            return "minimise", cleanup
    return None, cleanup


# --------------------------------------------------------------------------- #
# probe — read-only; scenario 9 (Electron) lives here                          #
# --------------------------------------------------------------------------- #

def cmd_probe(_args) -> int:
    """What the gate would see, without running one.  Touches nothing."""
    head("czy okno klienta jest znalezione i zweryfikowane")
    found = target().first_verified_candidate()
    if found is None:
        line(WARN, "brak zweryfikowanego okna — GUI klienta nie działa")
        return 2
    hwnd, owner = found
    line(OK, f"hwnd={hex(hwnd)} pid={owner.pid} image={owner.image_name}")

    head("foreground_check — jeden odczyt, zero działania")
    api = CountingApi()
    live = provider().secure_window_target(api=api)
    report_check(live.foreground_check())
    report_check(live.foreground_check(hwnd), prefix="foreground_check(pinned)")
    line(INFO, f"odczytów foreground: {api.fg_checks}")

    head("Electron: obcy child D3D nie może skazić celu (Etap 18)")
    # `enumerate_controls` answers with Edit/Button controls, of which an
    # Electron window has none; the D3D surface is a plain child window, so
    # this asks the desktop directly.  Read-only, and the module-level
    # `partition_controls` is used deliberately: the method of the same name
    # lives on an *acquired* window, and acquiring would take the foreground.
    import win32gui
    children = []
    win32gui.EnumChildWindows(hwnd, lambda h, acc: acc.append(h), children)
    line(INFO, f"kontrolek Edit/Button: "
               f"{len(Win32WindowMessageSystem().enumerate_controls(hwnd))}")
    line(INFO, f"okien-dzieci: {len(children)}")
    partition = sw.partition_controls(hwnd, children,
                                      provider().trusted_window_dirs(), api)
    line(OK if partition.usable or not children else WARN,
         f"usable={len(partition.usable)} foreign={len(partition.foreign)} "
         f"reason={partition.reason}")
    for child in children:
        owned = child in partition.usable
        try:
            cls = win32gui.GetClassName(child)
        except Exception:
            cls = "?"
        line(INFO, f"  {'własny' if owned else 'OBCY  '} {hex(child)} class={cls}")
    line(OK, "obecność obcego childa NIE odrzuciła okna: "
             f"zweryfikowane={found is not None}")
    line(OK if all(c not in partition.usable for c in partition.foreign) else BAD,
         "foreground_check nie sięga po obcego childa: pracuje wyłącznie na "
         f"HWND okna głównego ({hex(hwnd)})")

    head("czy bramka trzyma się tego samego HWND/PID/obrazu")
    identities = {live.foreground_check().identity for _ in range(3)}
    line(OK if len(identities) == 1 else BAD,
         f"tożsamość stabilna w 3 odczytach: {len(identities) == 1}")
    return 0


# --------------------------------------------------------------------------- #
# launch — start the client so the other commands have something to look at    #
# --------------------------------------------------------------------------- #

def cmd_launch(_args) -> int:
    """Start the real client through the migrated LAUNCH capability."""
    head("uruchomienie GUI FortiClienta (zmigrowane `launch`)")
    result = provider().launch(VpnRequest(provider_id="forticlient"))
    line(OK if result.started else BAD,
         f"started={result.started} strategy={result.strategy} "
         f"pid={result.pid} fallback={result.fallback} "
         f"error={result.error_code}")
    for _ in range(40):
        time.sleep(0.5)
        if target().first_verified_candidate() is not None:
            break
    return 0 if require_window() else 2


# --------------------------------------------------------------------------- #
# wait — scenarios A, B, E                                                     #
# --------------------------------------------------------------------------- #

def _minimise(hwnd) -> bool:
    """Stop the client being a usable foreground — the operator's hand, scripted.

    Scenario A needs "the client is not the window in front".  On this desktop
    another process' window will not take the foreground from the client
    (measured), so minimising is how that state is reached without a person.
    The distinction that matters is untouched: this is the *tool* moving a
    window, never the gate, which still only reads.
    """
    import win32gui
    try:
        win32gui.ShowWindow(hwnd, 6)                          # SW_MINIMIZE
    except Exception:
        return False
    for _ in range(20):
        time.sleep(0.1)
        if win32gui.IsIconic(hwnd):
            return True
    return False


def _restore_later(hwnd, delay_s: float):
    """Bring the client back after `delay_s`, from a thread — like a user would.

    Deliberately *not* part of the gate: it runs in the smoke tool, and the
    gate learns about it the only way it ever learns anything, by looking.
    """
    import threading
    import win32gui

    def run():
        time.sleep(delay_s)
        try:
            win32gui.ShowWindow(hwnd, 9)                      # SW_RESTORE
            line(INFO, f"[narzędzie] przywróciłem okno klienta po {delay_s:.1f} s")
        except Exception as exc:
            line(WARN, f"[narzędzie] nie udało się przywrócić: {type(exc).__name__}")

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    return thread


def cmd_wait(args) -> int:
    """Run a real wait.  A on its own; B and E scripted or by hand."""
    if not require_window():
        return 2
    head(f"oczekiwanie na aktywację (budżet {args.timeout:.0f} s)")
    line(INFO, "scenariusz A: nie rób nic — bramka ma CZEKAĆ")
    line(INFO, "scenariusz B: przełącz się do FortiClienta w trakcie")
    line(INFO, "scenariusz E: FortiClient -> inne okno -> FortiClient")

    hwnd = target().first_verified_candidate()[0]
    if args.minimise_first:
        line(OK if _minimise(hwnd) else WARN,
             "zminimalizowałem klienta — cel istnieje, ale nie jest z przodu")
    if args.restore_after:
        _restore_later(hwnd, args.restore_after)
    if args.flap:
        # Scenario E: away, back, away again — and the "back" is deliberately
        # shorter than one poll interval.  The gate must answer from what the
        # desktop says at the instant it looks, never from having seen an
        # activation earlier; a gate with a memory would report success after
        # the window had already gone again.
        import threading

        def flap():
            import win32gui
            for _ in range(int(args.timeout / max(args.flap, 0.5)) + 1):
                time.sleep(args.flap)
                try:
                    win32gui.ShowWindow(hwnd, 9)              # SW_RESTORE
                    line(INFO, f"[narzedzie] okno z powrotem (na {args.flap_hold} s)")
                    time.sleep(args.flap_hold)
                    win32gui.ShowWindow(hwnd, 6)              # SW_MINIMIZE
                    line(INFO, "[narzedzie] i znowu zminimalizowane")
                except Exception:
                    return

        threading.Thread(target=flap, daemon=True).start()

    seen: list[str] = []
    if args.ui:
        return _wait_with_ui(args, seen)

    gate, api = live_gate(timeout_s=args.timeout,
                          observer=lambda s: (seen.append(s.value),
                                              line(INFO, f"stan -> {s.value}")))
    started = time.monotonic()
    result = gate.wait()
    head("wynik")
    report_result(result, api.fg_checks)
    line(INFO, f"  ściana zegara: {time.monotonic() - started:.2f} s")
    line(INFO, f"  przejścia stanów: {seen}")
    return _verdict(result, seen)


def _verdict(result, seen) -> int:
    if result.state is ActivationState.ACTIVATION_OBSERVED:
        line(OK, "scenariusz B/E: użytkownik aktywował klienta, bramka to ZOBACZYŁA")
        return 0
    if result.state is ActivationState.ACTIVATION_TIMEOUT:
        waited = "awaiting-activation" in seen
        line(OK if waited else BAD,
             "scenariusz A: bramka czekała i sama niczego nie aktywowała"
             if waited else "bramka nie doszła do AWAITING_ACTIVATION")
        return 0 if waited else 1
    line(WARN, f"nierozstrzygające: {result.state.value}")
    return 2


def _wait_with_ui(args, seen) -> int:
    """The same wait, with the real Stage-23 banner on screen.

    Worth the extra machinery: it is the only way to see that the sentence and
    the Cancel button appear at the right moment on a real desktop, and the
    banner's own window becoming the foreground is exactly the situation the
    gate is built for.
    """
    from PyQt6.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget
    from ui.activation_prompt import ActivationPrompt, ActivationWorker

    app = QApplication.instance() or QApplication([])
    window = QWidget()
    window.setWindowTitle("Etap 24 — oczekiwanie na aktywację")
    window.setStyleSheet("background: #0d1117;")
    window.resize(460, 110)
    layout = QVBoxLayout(window)
    status = QLabel("")
    status.setWordWrap(True)
    layout.addWidget(status)
    prompt = ActivationPrompt(window, status_label=status)
    layout.addWidget(prompt)

    gate, api = live_gate(timeout_s=args.timeout)
    worker = ActivationWorker(gate.wait)
    gate.observer = worker.report_state
    worker.state_changed.connect(prompt.apply_state)
    worker.state_changed.connect(lambda s: (seen.append(s),
                                            line(INFO, f"stan -> {s}")))
    prompt.cancelled.connect(gate.cancellation.cancel)
    results: list = []
    worker.finished_with.connect(results.append)

    window.show()
    worker.start()
    deadline = time.monotonic() + args.timeout + 10
    while worker.isRunning() and time.monotonic() < deadline:
        app.processEvents()
        worker.wait(20)
    for _ in range(5):
        app.processEvents()
    window.close()

    head("wynik")
    if not results:
        line(BAD, "worker nie zwrócił wyniku")
        return 1
    report_result(results[0], api.fg_checks)
    line(INFO, f"  ostatnie zdanie na ekranie: {prompt.message!r}")
    if results[0].state is ActivationState.CANCELLED:
        line(OK, "scenariusz F: anulowane z prawdziwego przycisku")
        return 0
    return _verdict(results[0], seen)


# --------------------------------------------------------------------------- #
# zero-wait — scenario C                                                       #
# --------------------------------------------------------------------------- #

def cmd_zero_wait(args) -> int:
    """The client is already in front: the gate must not invent a delay."""
    if not require_window():
        return 2
    head("scenariusz C — klient już z przodu, zero oczekiwania")
    api = CountingApi()
    before = provider().secure_window_target(api=api).foreground_check()
    report_check(before, prefix="stan przed uruchomieniem bramki")
    if not before.ok:
        line(WARN, "klient NIE jest teraz oknem z przodu — aktywuj go ręcznie "
                   "i powtórz; ten pomiar wymaga takiego stanu")
        return 2

    gate, api = live_gate(timeout_s=args.timeout)
    started = time.monotonic()
    result = gate.wait()
    wall = time.monotonic() - started

    head("wynik")
    report_result(result, api.fg_checks)
    line(INFO, f"  ściana zegara: {wall:.3f} s")
    # Not `waited_s == 0.0`.  Against the fake clock of the unit tests that is
    # exact; against a real `time.monotonic()` the gate reads the clock twice,
    # so the difference is a few microseconds and literal zero would be a test
    # of the clock's resolution, not of the gate.  "No poll interval was ever
    # slept" is the property that matters, and POLL_INTERVAL_S is 0.5 s.
    line(INFO, f"  waited_s dokładnie: {result.waited_s!r}")
    checks = [(result.ok, "ACTIVATION_OBSERVED"),
              (result.polls == 1, "polls == 1"),
              (result.waited_s < 0.01, "waited_s praktycznie zero (< 10 ms, "
                                       "przy interwale pollingu 500 ms)"),
              (wall < 1.0, "brak sztucznego opóźnienia (< 1 s)")]
    for passed, what in checks:
        line(OK if passed else BAD, what)
    return 0 if all(passed for passed, _ in checks) else 1


# --------------------------------------------------------------------------- #
# race — scenario D                                                            #
# --------------------------------------------------------------------------- #

def cmd_race(args) -> int:
    """Let the gate say yes, take the foreground away, then try the autofill.

    The point of the whole design in one command: the gate's success is
    permission to *start*, and the guards — not the gate — decide whether a
    single character may be sent.  If this prints DONE, the guards are broken
    and the gate has been allowed to stand in for them.
    """
    if not require_window():
        return 2
    head("scenariusz D — utrata foreground PO sukcesie bramki")
    api = CountingApi()
    live = provider().secure_window_target(api=api)
    check = live.foreground_check()
    report_check(check, prefix="stan przed bramką")
    if not check.ok:
        line(WARN, "klient nie jest z przodu — aktywuj go ręcznie i powtórz: "
                   "ten scenariusz zaczyna się od SUKCESU bramki")
        return 2

    gate, api = live_gate(timeout_s=args.timeout)
    result = gate.wait()
    report_result(result, api.fg_checks)
    if not result.ok:
        line(WARN, "bramka nie doszła do ACTIVATION_OBSERVED — "
                   "nierozstrzygające")
        return 2

    head("odbieram oknu foreground (bramka już powiedziała TAK)")
    how, cleanup = take_foreground_away(result.hwnd)
    line(OK if how else WARN, f"cel przestał być użytecznym foregroundem: {how}")
    if how is None:
        line(WARN, "nie udało się — wynik NIEROZSTRZYGAJĄCY, nie zaliczenie")
        cleanup()
        return 2
    if how == "minimise":
        line(INFO, "wariant słabszy: obce okno nie przejmuje foreground na tej "
                   "maszynie (tak samo jak --steal-focus-at w Etapie 18); "
                   "wariant 'obce okno z przodu' wymaga operatora")
    try:
        after = provider().secure_window_target().foreground_check(result.hwnd)
        report_check(after, prefix="stan po odebraniu")

        head("dopiero teraz autofill (atrapy, szew wysyłający zablokowany)")
        recorder = ForegroundWatchingInput(result.hwnd)
        request = VpnRequest(provider_id="forticlient", login=DRY_LOGIN,
                             password=DRY_PASSWORD, profile_name="")
        filled = provider().autofill_login_password(request,
                                                    input_system=recorder)
    finally:
        cleanup()
        line(INFO, "posprzątane — okno pomocnicze zamknięte, klient przywrócony")

    line(OK if filled.status is not AutofillStatus.DONE else WARN,
         f"status={filled.status.value} blocked_at={filled.blocked_at} "
         f"error={filled.error_code}")
    sends = [e for e in recorder.events
             if e[0] in ("type", "key", "combo", "clipboard-write-blocked")]
    line(INFO, f"symulowanych wysyłek łącznie: {len(sends)}")
    line(OK if not recorder.misdirected else BAD,
         f"wysyłek w chwili, gdy cel NIE był oknem z przodu: "
         f"{len(recorder.misdirected)}")
    blob = repr(recorder.events) + repr(filled)
    leaked = [s for s in (DRY_LOGIN, DRY_PASSWORD) if s in blob]
    line(OK if not leaked else BAD, f"atrapy w rejestrze/wyniku: {leaked or 'brak'}")

    # Two acceptable outcomes, one unacceptable.  Either the guard refused
    # (fail-closed), or `acquire_focus` genuinely got the window back in front
    # first and the sequence ran with the target really focused — which is not
    # a hole, it is the mechanism working.  What must never happen is a
    # keystroke while some other window holds the foreground.
    refused = filled.status is not AutofillStatus.DONE
    safe = not recorder.misdirected and not leaked
    if refused and safe:
        line(OK, "fail-closed po utracie foreground — guard odmówił")
    elif safe:
        line(OK, "guard NIE odmówił, ale acquire_focus realnie odzyskał "
                 "foreground: każda wysyłka nastąpiła przy celu z przodu")
    else:
        line(BAD, "ROZBIEŻNOŚĆ: wysyłka przy obcym oknie z przodu")
    return 0 if safe else 1


# --------------------------------------------------------------------------- #
# cancel — scenario F                                                          #
# --------------------------------------------------------------------------- #

def cmd_cancel(args) -> int:
    """Cancel on the real banner, from the real button.

    ``--after`` clicks it for you after N state reports, so the scenario can be
    observed without a person in the chair; leave it off and click yourself.
    """
    if not require_window():
        return 2
    from PyQt6.QtCore import QTimer
    from PyQt6.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget
    from ui.activation_prompt import ActivationPrompt, ActivationWorker

    head("scenariusz F — anulowanie na żywym oknie")
    if args.minimise_first:
        hwnd = target().first_verified_candidate()[0]
        line(OK if _minimise(hwnd) else WARN,
             "zminimalizowałem klienta, żeby bramka miała na co czekać")
    app = QApplication.instance() or QApplication([])
    window = QWidget()
    window.setWindowTitle("Etap 24 — anulowanie")
    window.resize(460, 110)
    layout = QVBoxLayout(window)
    status = QLabel("")
    status.setWordWrap(True)
    layout.addWidget(status)
    prompt = ActivationPrompt(window, status_label=status)
    layout.addWidget(prompt)

    recorder = BlockedInput()          # handed to nobody; proof it stays empty
    gate, api = live_gate(timeout_s=args.timeout)
    worker = ActivationWorker(gate.wait)
    gate.observer = worker.report_state
    seen: list[str] = []
    worker.state_changed.connect(prompt.apply_state)
    worker.state_changed.connect(lambda s: (seen.append(s),
                                            line(INFO, f"stan -> {s}")))
    prompt.cancelled.connect(gate.cancellation.cancel)
    prompt.cancelled.connect(lambda: line(INFO, "kliknięto Anuluj"))
    results: list = []
    worker.finished_with.connect(results.append)

    if args.after:
        line(INFO, f"kliknę Anuluj po {args.after:.1f} s")
        QTimer.singleShot(int(args.after * 1000), prompt.cancel_button.click)
    else:
        line(INFO, "kliknij Anuluj w oknie, które właśnie się pojawiło")

    window.show()
    worker.start()
    deadline = time.monotonic() + args.timeout + 10
    while worker.isRunning() and time.monotonic() < deadline:
        app.processEvents()
        worker.wait(20)
    for _ in range(5):
        app.processEvents()
    window.close()

    head("wynik")
    if not results:
        line(BAD, "worker nie zwrócił wyniku")
        return 1
    result = results[0]
    report_result(result, api.fg_checks)
    line(INFO, f"  zdanie na ekranie: {prompt.message!r}")
    checks = [(result.state is ActivationState.CANCELLED, "CANCELLED"),
              (not result.ok, "brak zgody na autofill"),
              (not prompt.cancel_button.isVisible(), "przycisk zniknął"),
              (recorder.events == [], "InputSystem nietknięty"),
              (not prompt.presenter.waiting, "UI wróciło do stanu końcowego")]
    for passed, what in checks:
        line(OK if passed else BAD, what)
    return 0 if all(passed for passed, _ in checks) else 1


def cmd_operator_race(args) -> int:
    """Stage 25 part A: the real race, with a person supplying the switch.

    Sequence, and nothing is skipped: the client must be in front, the gate
    really runs and really says yes, the tool then stops and waits for the
    operator to click elsewhere, and only after that does the Stage-14 autofill
    start — with the sending seam blocked, carrying placeholders.

    The interesting answer is not "did it refuse".  It is: **was a single
    simulated keystroke issued while somebody else's window held the
    foreground?**
    """
    if not require_window():
        return 2
    head("scenariusz D (Etap 25 A) — operator zabiera foreground")
    hwnd = target().first_verified_candidate()[0]
    api = CountingApi()
    check = provider().secure_window_target(api=api).foreground_check()
    report_check(check, prefix="stan przed bramka")

    # No hard refusal when the client is not in front: waiting for exactly that
    # is what the gate is for, and demanding it up front would mean the run can
    # only be started from a desktop that is already in the state under test.
    # The operator does both halves of the scenario in one go.
    line(INFO, "")
    beep("act")
    line(INFO, "  >>> KROK 1: kliknij TERAZ w okno FortiClienta.")
    line(INFO, "  >>> KROK 2: policz do trzech i kliknij w INNE okno "
               "(przegladarka, edytor) — i tam zostan.")
    line(INFO, "")

    gate, api = live_gate(timeout_s=args.timeout,
                          observer=lambda st: line(INFO, f"stan -> {st.value}"))
    result = gate.wait()
    report_result(result, api.fg_checks)
    if not result.ok:
        line(WARN, "bramka nie doszla do ACTIVATION_OBSERVED — nierozstrzygajace")
        return 2

    head("BARIERA — flow wstrzymany miedzy bramka a autofillem")
    switched, front, front_pid = wait_for_operator_to_switch_away(
        hwnd, args.operator_timeout)
    if not switched:
        line(WARN, "operator nie przelaczyl okna w wyznaczonym czasie — "
                   "wynik NIEROZSTRZYGAJACY, nie zaliczenie")
        return 2
    line(OK, f"foreground trzyma teraz obce okno: hwnd={hex(front)} "
             f"pid={front_pid} (nasz cel: pid={result.pid})")
    before = provider().secure_window_target().foreground_check(hwnd)
    report_check(before, prefix="stan celu tuz przed autofillem")

    head("dopiero teraz autofill (atrapy, szew wysylajacy zablokowany)")
    recorder = ForegroundWatchingInput(hwnd)
    request = VpnRequest(provider_id="forticlient", login=DRY_LOGIN,
                         password=DRY_PASSWORD, profile_name="")
    filled = provider().autofill_login_password(request, input_system=recorder)

    line(INFO, f"status={filled.status.value} blocked_at={filled.blocked_at} "
               f"error={filled.error_code}")
    line(INFO, f"login_entered={filled.login_entered} "
               f"password_entered={filled.password_entered}")
    sends = [e for e in recorder.events
             if e[0] in ("type", "key", "combo", "clipboard-write-blocked")]
    line(INFO, f"symulowanych wysylek lacznie: {len(sends)}")
    line(OK if not recorder.misdirected else BAD,
         f"wysylek, gdy cel NIE byl widocznym oknem z przodu: "
         f"{len(recorder.misdirected)}")
    blob = repr(recorder.events) + repr(filled)
    leaked = [s for s in (DRY_LOGIN, DRY_PASSWORD) if s in blob]
    line(OK if not leaked else BAD, f"atrapy w rejestrze/wyniku: {leaked or 'brak'}")
    after = provider().secure_window_target().foreground_check(hwnd)
    report_check(after, prefix="stan celu po probie")

    head("werdykt")
    refused = filled.status is not AutofillStatus.DONE
    if refused:
        line(OK, f"guard ODMOWIL: blocked_at={filled.blocked_at} "
                 f"error={filled.error_code} — zero znakow, fail-closed")
    elif not recorder.misdirected:
        line(WARN, "guard NIE odmowil, ale kazda wysylka nastapila przy celu "
                   "z przodu — acquire_focus odzyskal okno mimo przelaczenia "
                   "operatora; to jest wynik do opisania, nie zaliczenie D")
    else:
        line(BAD, "ROZBIEZNOSC: wysylka przy obcym oknie z przodu")
    return 0 if (refused or not recorder.misdirected) else 1


# --------------------------------------------------------------------------- #
# connect-race — the real V2 flow, stopped between the gate and the autofill   #
# --------------------------------------------------------------------------- #

class RefusingLaunch(LaunchSystem):
    """A launch system that starts nothing and says so.

    The flow only reaches a launch when it found no client window, which is not
    the case this run is about.  Wiring a refusing one in makes that a fact
    rather than a hope: if the route ever changed, the run would report an
    attempt instead of quietly starting a process.
    """

    def __init__(self):
        self.attempts: list[tuple] = []

    def open_with_explorer(self, path):
        self.attempts.append(("explorer", path))
        raise OSError("smoke: launch blocked")

    def spawn_detached(self, exe, cwd):
        self.attempts.append(("spawn_detached", exe))
        raise OSError("smoke: launch blocked")

    def wait_for_process(self, image_name, timeout):
        self.attempts.append(("wait_for_process", image_name))
        return False

    def run_capture(self, cmd, timeout):
        self.attempts.append(("run_capture", cmd[0] if cmd else None))
        return 1, "smoke: probe blocked"

    def spawn_hidden(self, cmd):
        self.attempts.append(("spawn_hidden", cmd[0] if cmd else None))
        raise OSError("smoke: launch blocked")

    def spawn_monitored(self, cmd):
        self.attempts.append(("spawn_monitored", cmd[0] if cmd else None))
        raise OSError("smoke: launch blocked")


class BarrierRuntime(FortiConnectRuntime):
    """The real runtime, with one pause in it.

    ``start_autofill`` is the exact seam this stage needs: the gate has already
    answered, and **nothing has yet touched the desktop** — every Win32 write in
    the flow (``AttachThreadInput``, ``SW_RESTORE``, ``SetForegroundWindow``)
    lives inside ``acquire_focus``, which this method calls.  Pausing on the way
    in stops the flow after the activation and before the first of them, which
    no other point in the flow can do.

    The pause is a callback supplied by the tool.  The runtime is otherwise
    untouched, and the production flow does not know this class exists.
    """

    def __init__(self, provider, *, barrier=None, **seams):
        super().__init__(provider, **seams)
        self._barrier = barrier
        self.barrier_result = None
        self.autofill_started = False
        self.check_result = None

    def activation_still_holds(self, hwnd):
        """Pause here, then let the real Stage-26 reading run.

        This is the seam the whole run is about: the gate has said yes, the
        operator is given their moment, and only then does the flow look again.
        """
        if self._barrier is not None and self.barrier_result is None:
            self.barrier_result = self._barrier()
        self.check_result = super().activation_still_holds(hwnd)
        return self.check_result

    def start_autofill(self, login, password, profile_name):
        if self.barrier_result is not None and not self.barrier_result[0]:
            # The operator never switched, so the flow reaching this point
            # proves nothing about the race.  Refuse in the shape a blocked
            # autofill has, rather than running the ordinary happy path.
            return AutofillResult(
                provider_id=self._provider.id, success=False,
                status=AutofillStatus.BLOCKED, blocked_at="smoke-barrier",
                error_code="operator-did-not-switch")
        self.autofill_started = True
        return super().start_autofill(login, password, profile_name)


class ReadOnlyBarrierRuntime(BarrierRuntime):
    """Phase 1: stop at the barrier and never enter the real autofill at all.

    Separate class rather than a patched attribute so that "no Win32 write
    happened" is a property of the code that ran, readable here, instead of
    something the reader has to reconstruct from a lambda.
    """

    def start_autofill(self, login, password, profile_name):
        """Never the real autofill in phase 1 — not one Win32 write."""
        return AutofillResult(
            provider_id=self._provider.id, success=False,
            status=AutofillStatus.BLOCKED, blocked_at="smoke-barrier",
            error_code="phase-1-read-only")


def cmd_connect_race(args) -> int:
    """Stage 26 A: the real V2 connect, real window, operator supplies the race.

    Two phases, deliberately separable, because the brief asks for two things
    that cannot both hold at once:

    **Phase 1 (always, read-only).**  After the operator switches away, ask
    ``foreground_check`` about the pinned window.  Not one byte is written to
    the desktop, and the answer is whether V2 *can see* that the activation no
    longer holds.

    **Phase 2 (only with --through-guard).**  Let the real Stage-14 autofill
    run.  It calls ``acquire_focus``, which *does* call ``AttachThreadInput``,
    ``SW_RESTORE`` and ``SetForegroundWindow`` — production code being
    measured, not the tool switching windows, and the only way to watch the
    existing guard refuse.  Off by default, so a run can be made with no Win32
    write whatsoever.

    Credentials are placeholders and the sending seam is blocked in both.
    """
    if not require_window():
        return 2
    head("Etap 26 A — realny flow V2, operator zabiera foreground")
    hwnd = target().first_verified_candidate()[0]
    line(INFO, "poswiadczenia to jawne atrapy; szew wysylajacy jest zablokowany")
    line(INFO, "faza 2 (prawdziwy autofill przez acquire_focus): "
               + ("WLACZONA" if args.through_guard else "wylaczona"))
    line(INFO, "")
    beep("act")
    line(INFO, "  >>> KROK 1: kliknij TERAZ w okno FortiClienta (profil Betanin).")
    line(INFO, "  >>> KROK 2: gdy uslyszysz drugi sygnal — kliknij w INNE okno.")
    line(INFO, "")

    api = CountingApi()
    recorder = ForegroundWatchingInput(hwnd)
    launch = RefusingLaunch()
    barrier_state = {}

    def barrier():
        head("BARIERA — bramka powiedziala TAK, autofill jeszcze nie ruszyl")
        switched, front, front_pid = wait_for_operator_to_switch_away(
            hwnd, args.operator_timeout)
        barrier_state.update(switched=switched, front=front, front_pid=front_pid)
        return switched, front, front_pid

    runtime_class = BarrierRuntime if args.through_guard else ReadOnlyBarrierRuntime
    runtime = runtime_class(
        provider(), barrier=barrier, launch_system=launch,
        input_system=recorder, window_api=api,
        activation_timeout_s=args.timeout)

    request = VpnRequest(provider_id="forticlient", login=DRY_LOGIN,
                         password=DRY_PASSWORD, profile_name=args.profile or "",
                         app_path=args.app_path or "", autofill=True)
    result = provider().connect(request, fcc.ENTRY_CONNECT_MONITORED,
                                system=runtime)

    head("przebieg flow")
    for step in result.steps:
        line(INFO, "  {:<20} {:<8} {} {}".format(
            step.phase, step.status, step.error_code or "",
            step.reason_code or ""))

    head("czy operator naprawde przelaczyl okno")
    switched = barrier_state.get("switched")
    if not switched:
        line(WARN, "operator nie przelaczyl okna — wynik NIEROZSTRZYGAJACY")
    else:
        line(OK, "foreground trzyma obce okno: hwnd={} pid={}".format(
            hex(barrier_state["front"]), barrier_state["front_pid"]))

    head("Etap 26 B — co odpowiedzial nowy check we flow")
    check_result = getattr(runtime, "check_result", None)
    if check_result is None:
        line(WARN, "activation_still_holds nie zostal wywolany")
    else:
        report_check(check_result, prefix="activation_still_holds")
        line(OK if not check_result.ok else WARN,
             "flow zablokowal autofill na podstawie tego odczytu: {}".format(
                 not check_result.ok))
    line(INFO, "autofill wystartowal: {}".format(
        getattr(runtime, "autofill_started", False)))

    head("faza 1 — czy V2 WIDZI utrate aktywacji (tylko odczyt)")
    after = provider().secure_window_target().foreground_check(hwnd)
    report_check(after, prefix="foreground_check przypietego okna")
    seen = bool(switched) and not after.ok
    line(OK if seen else WARN,
         "V2 wykrywa utrate wlasciwego foregroundu: {}".format(seen))

    if args.through_guard:
        head("faza 2 — co zrobil istniejacy guard")
        line(INFO, "autofill wystartowal: {}".format(runtime.autofill_started))
        line(INFO, "error_code flow: {}".format(result.error_code))

    head("co dotknelo maszyny")
    sends = [e for e in recorder.events
             if e[0] in ("type", "key", "combo", "clipboard-write-blocked")]
    line(OK if not sends else INFO, "symulowanych wysylek: {}".format(len(sends)))
    line(OK if not recorder.misdirected else BAD,
         "wysylek, gdy cel NIE byl widocznym oknem z przodu: {}".format(
             len(recorder.misdirected)))
    line(OK, "realnych znakow / Enter / zapisow do schowka: 0 "
             "(szew wysylajacy rejestruje, nie wysyla)")
    line(OK if not launch.attempts else BAD,
         "prob uruchomienia procesu: {} {}".format(len(launch.attempts),
                                                   launch.attempts))
    blob = repr(recorder.events) + repr(result)
    leaked = [x for x in (DRY_LOGIN, DRY_PASSWORD) if x in blob]
    line(OK if not leaked else BAD,
         "atrapy w rejestrze/wyniku: {}".format(leaked or "brak"))

    head("werdykt")
    if not switched:
        line(WARN, "NIEROZSTRZYGNIETY — brak recznego przelaczenia okna")
        return 2
    if not seen:
        line(BAD, "operator przelaczyl okno, a V2 tego NIE widzi")
        return 1
    line(OK, "ACTIVATION_OBSERVED nastapilo, operator zabral foreground, "
             "V2 to widzi, zero realnych znakow")
    return 0


# --------------------------------------------------------------------------- #
# autofill-race — Stage 30: the client goes away *during* the sequence         #
# --------------------------------------------------------------------------- #

#: Where the sequence may be paused, expressed in what the seam actually sees.
#: Named after the guard that runs *next*, since that is the one under test.
PAUSE_POINTS = {
    # The navigation guard ends by reading the clipboard; the next guard is
    # `login-clear`, the first one that touches the username field.
    "before-login": ("clipboard-read-skipped", 1),
    # The second paste is the password going in; the next guard is `submit`,
    # which is the one that would press Enter.
    "before-submit": ("paste", 2),
}


def wait_for_operator_to_minimise(hwnd, seconds: float, *, prompt=None) -> bool:
    """Block until the operator minimises the window.  Reads, never acts.

    ``IsIconic`` once every 200 ms and nothing else: the tool must not be the
    thing that minimises the client, or the run would be measuring itself.
    """
    import win32gui

    beep("step2")
    line(INFO, "")
    line(INFO, prompt or "  >>> ZMINIMALIZUJ TERAZ OKNO FORTICLIENTA (przycisk _ ).")
    line(INFO, "  >>> Czekam do {:.0f} s. Narzedzie tylko CZYTA IsIconic — "
               "niczego nie minimalizuje ani nie przywraca.".format(seconds))
    line(INFO, "")
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        time.sleep(0.2)
        try:
            if win32gui.IsIconic(hwnd):
                line(OK, "wykryto minimalizacje")
                return True
        except Exception:
            continue
    line(WARN, "operator nie zminimalizowal okna w wyznaczonym czasie")
    return False


class OperatorPauseInput(ForegroundWatchingInput):
    """Records instead of sending, and stops once so a person can act.

    The stop is deliberately placed *between* two guarded operations: the flow
    has a verified window, the autofill is under way, and the next thing that
    happens is another ``VerifiedWindow.confirm()``.  That is the only moment
    at which "the user minimised the client mid-sequence" can be staged
    honestly — and the tool stages it by waiting, not by minimising anything
    itself.
    """

    def __init__(self, hwnd, pause_point, timeout_s):
        super().__init__(hwnd)
        self.kind, self.nth = PAUSE_POINTS[pause_point]
        self.seen = 0
        self.paused_at = None
        self.became_iconic = None
        self._timeout_s = timeout_s

    def _matches(self, event) -> bool:
        if self.kind == "paste":
            # Ctrl+V — the modifier/key pair the autofill uses to paste.
            return (event[0] == "combo" and len(event) == 3
                    and event[2] == ord("V"))
        return event[0] == self.kind

    def _record(self, event) -> None:
        super()._record(event)
        if self.paused_at is not None or not self._matches(event):
            return
        self.seen += 1
        if self.seen < self.nth:
            return
        self.paused_at = len(self.events)
        self.became_iconic = self._wait_for_minimise()

    def _wait_for_minimise(self) -> bool:
        head("PAUZA W SRODKU AUTOFILLU — flow ma zweryfikowane okno")
        return wait_for_operator_to_minimise(self.hwnd, self._timeout_s)


class IconicCountingApi(CountingApi):
    """The real desktop, counting the readings — and the three writes.

    The counters over ``restore_window``, ``set_foreground_window`` and
    ``attach_thread_input`` are the whole evidence of Stage 34B: each one wraps
    a method the API already had, adds one increment, and delegates.  Nothing
    new reaches the desktop through this class; it only records what does.
    """

    def __init__(self):
        super().__init__()
        self.iconic_reads = 0
        self.restore_calls = 0
        self.set_foreground_calls = 0
        self.attach_calls = 0

    def is_iconic(self, hwnd):
        self.iconic_reads += 1
        return super().is_iconic(hwnd)

    def restore_window(self, hwnd):
        self.restore_calls += 1
        return super().restore_window(hwnd)

    def set_foreground_window(self, hwnd):
        self.set_foreground_calls += 1
        return super().set_foreground_window(hwnd)

    def set_foreground_window_detail(self, hwnd):
        self.set_foreground_calls += 1
        return super().set_foreground_window_detail(hwnd)

    def attach_thread_input(self, our_tid, their_tid, attach):
        self.attach_calls += 1
        return super().attach_thread_input(our_tid, their_tid, attach)

    def writes(self):
        return {"restore_window": self.restore_calls,
                "set_foreground_window": self.set_foreground_calls,
                "attach_thread_input": self.attach_calls}


def cmd_autofill_race(args) -> int:
    """Stage 30: does require_visible refuse on a *real* minimised client?

    The autofill is the real Stage-14 one and the guards are the real ones; the
    only substitution is the sending seam, which records lengths and sends
    nothing.  Credentials are the usual placeholders.
    """
    if not require_window():
        return 2
    hwnd = target().first_verified_candidate()[0]
    head("Etap 30 — minimalizacja W TRAKCIE sekwencji (punkt: {})".format(
        args.pause_at))
    line(INFO, "poswiadczenia to atrapy; szew wysylajacy rejestruje, nie wysyla")

    # Step 1 of the scenario: a real ACTIVATION_OBSERVED, from the real gate.
    # Using the gate rather than a bespoke wait keeps the precondition honest:
    # it is the same read-only machinery production itself would use, and it
    # means the operator does both halves of the scenario in one run.
    line(INFO, "")
    beep("act")
    line(INFO, "  >>> KROK 1: kliknij TERAZ w okno FortiClienta.")
    line(INFO, "  >>> KROK 2: na drugi sygnal ZMINIMALIZUJ je (przycisk _ ).")
    line(INFO, "")
    gate, gate_api = live_gate(
        timeout_s=args.timeout,
        observer=lambda st: line(INFO, "stan -> " + st.value))
    activation = gate.wait()
    report_result(activation, gate_api.fg_checks)
    if not activation.ok:
        line(WARN, "bramka nie doszla do ACTIVATION_OBSERVED - NIEROZSTRZYGAJACE")
        return 2

    api = IconicCountingApi()
    recorder = OperatorPauseInput(hwnd, args.pause_at, args.operator_timeout)
    request = VpnRequest(provider_id="forticlient", login=DRY_LOGIN,
                         password=DRY_PASSWORD,
                         profile_name=args.profile or "")
    result = provider().autofill_login_password(
        request, target=provider().secure_window_target(api=api),
        input_system=recorder)

    head("wynik autofillu")
    line(INFO, "status={} blocked_at={} error={}".format(
        result.status.value, result.blocked_at, result.error_code))
    line(INFO, "login_entered={} password_entered={}".format(
        result.login_entered, result.password_entered))
    line(INFO, "reason_code={}".format(
        (result.metadata or {}).get("reason_code")))

    head("pomiary")
    line(INFO, "odczytow is_iconic (po jednym na guard): {}".format(
        api.iconic_reads))
    line(INFO, "odczytow foreground: {}".format(api.fg_checks))
    line(INFO, "zdarzen seamu lacznie: {} (pauza po {})".format(
        len(recorder.events), recorder.paused_at))
    sends = [e for e in recorder.events
             if e[0] in ("type", "key", "combo", "clipboard-write-blocked")]
    line(INFO, "symulowanych wysylek: {}".format(len(sends)))
    clips = [e for e in recorder.events if e[0] == "clipboard-write-blocked"]
    line(INFO, "prob zapisu do schowka (zablokowanych): {}".format(len(clips)))
    enters = [e for e in recorder.events if e[0] == "key" and e[1] == 13]
    line(INFO, "zarejestrowanych ENTER: {}".format(len(enters)))
    line(OK, "realnych znakow / Enter / zapisow do schowka: 0")

    head("werdykt")
    if not recorder.became_iconic:
        line(WARN, "okno nie zostalo zminimalizowane — NIEROZSTRZYGAJACE")
        return 2
    blocked = result.status is not AutofillStatus.DONE
    line(OK if blocked else BAD,
         "guard zablokowal po minimalizacji: {} (blocked_at={})".format(
             blocked, result.blocked_at))
    reason = (result.metadata or {}).get("reason_code")
    line(OK if reason == "target-minimised" else WARN,
         "powod odmowy: {}".format(reason))
    blob = repr(recorder.events) + repr(result)
    leaked = [x for x in (DRY_LOGIN, DRY_PASSWORD) if x in blob]
    line(OK if not leaked else BAD, "atrapy w wyniku: {}".format(leaked or "brak"))
    return 0 if blocked else 1


def cmd_acquire_race(args) -> int:
    """Stage 34B: the second line of Variant 2, on a real minimised client.

    **This exercises one component**, ``SecureWindowTarget.acquire_any()``, not
    the whole connect.  The flow's own earlier check (``activation_still_holds``,
    Stage 26B) would refuse before ever reaching here — that is its job, and it
    was measured on this machine in Stage 30.  What has never been measured
    live is what happens if a minimised window reaches ``acquire`` anyway, and
    that is what this command asks.  The target is the production one, with the
    production configuration; nothing about the acquire path is simulated.
    """
    if not require_window():
        return 2
    hwnd = target().first_verified_candidate()[0]
    head("Etap 34B — acquire_any() po recznej minimalizacji")
    line(INFO, "ZAKRES: komponent SecureWindowTarget.acquire_any(), nie pelny Connect")
    line(INFO, "zadnych poswiadczen — autofill nie zostanie uruchomiony")

    # 1. A real activation, from the real gate.
    line(INFO, "")
    beep("act")
    line(INFO, "  >>> KROK 1: kliknij TERAZ w okno FortiClienta.")
    line(INFO, "  >>> KROK 2: na drugi sygnal ZMINIMALIZUJ je.")
    line(INFO, "")
    gate, gate_api = live_gate(
        timeout_s=args.timeout,
        observer=lambda st: line(INFO, "stan -> " + st.value))
    activation = gate.wait()
    report_result(activation, gate_api.fg_checks)
    if not activation.ok:
        line(WARN, "bramka nie doszla do ACTIVATION_OBSERVED - NIEROZSTRZYGAJACE")
        return 2
    line(OK, "ACTIVATION_OBSERVED: hwnd={} pid={} image={}".format(
        hex(activation.hwnd), activation.pid, activation.image_name))

    # 2. The operator puts it away.  We only watch.
    head("PAUZA — po ACTIVATION_OBSERVED, przed acquire_any()")
    if not wait_for_operator_to_minimise(
            hwnd, args.operator_timeout,
            prompt="  >>> ZMINIMALIZUJ TERAZ OKNO FORTICLIENTA, POTEM POCZEKAJ."):
        return 2

    # 3. What the strict reading says, on its own.
    head("strict_foreground_check() — sam odczyt")
    read_api = IconicCountingApi()
    check = provider().secure_window_target(
        api=read_api).strict_foreground_check(hwnd)
    report_check(check, prefix="strict_foreground_check")
    line(INFO, "zapisy podczas samego odczytu: {}".format(read_api.writes()))

    # 4. The real acquire, with the production configuration.
    head("acquire_any() — prawdziwy, konfiguracja FortiClient V2")
    api = IconicCountingApi()
    live_target = provider().secure_window_target(api=api)
    line(INFO, "raise_window={} require_visible={}".format(
        live_target._raise_window, live_target._require_visible))
    acquired = live_target.acquire_any()

    verified = isinstance(acquired, VerifiedWindow)
    if verified:
        line(BAD, "POWSTAL VerifiedWindow — to jest niezgodne z kontraktem")
        acquired.release()
    else:
        line(OK, "acquire_any() ODMOWIL: reason={}".format(
            getattr(acquired, "reason", "?")))

    head("co dotknelo pulpitu podczas acquire_any()")
    writes = api.writes()
    for name, count in writes.items():
        line(OK if count == 0 else BAD, "{} = {}".format(name, count))
    line(INFO, "odczytow is_iconic: {}  foreground: {}".format(
        api.iconic_reads, api.fg_checks))

    head("sekrety")
    line(OK, "autofill NIE zostal uruchomiony — zero zdarzen InputSystem")
    line(OK, "zero prob zapisu do schowka, zero prawdziwych poswiadczen")

    head("werdykt")
    reason = getattr(acquired, "reason", None)
    ok, failures = acquire_race_verdict(
        verified=verified, writes=writes, reason=reason,
        target_was_minimised=True,      # the run does not get here otherwise
        input_events=0, clipboard_writes=0)
    for name in ("acquire_any() odmowil",
                 "target byl zminimalizowany przez operatora",
                 "restore_window == 0", "set_foreground_window == 0",
                 "attach_thread_input == 0", "brak zdarzen InputSystem",
                 "brak zapisow do schowka", "powod odmowy jest bezpieczny"):
        line(BAD if name in failures else OK, name)
    line(INFO, "powod odmowy: {} (bezpieczne: {})".format(
        reason, ", ".join(SAFE_REFUSAL_REASONS)))
    if ok:
        line(OK, "Wariant 2 POTWIERDZONY na zywo: bezpieczna odmowa, "
                 "zero SW_RESTORE, zero SetForegroundWindow, zero attach")
    else:
        line(BAD, "NIEZGODNOSC: " + "; ".join(failures))
    return 0 if ok else 1


COMMANDS = {
    "probe": (cmd_probe, False),
    "launch": (cmd_launch, True),
    "wait": (cmd_wait, True),
    "zero-wait": (cmd_zero_wait, True),
    "race": (cmd_race, True),
    "operator-race": (cmd_operator_race, True),
    "connect-race": (cmd_connect_race, True),
    "autofill-race": (cmd_autofill_race, True),
    "acquire-race": (cmd_acquire_race, True),
    "cancel": (cmd_cancel, True),
}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m smoke.activation_live", description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("command", choices=sorted(COMMANDS))
    parser.add_argument("--i-am-at-the-keyboard", action="store_true",
                        help="wymagane dla poleceń, które ruszają pulpit")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT_S,
                        help="budżet oczekiwania w sekundach")
    parser.add_argument("--ui", action="store_true",
                        help="pokaż prawdziwy baner Etapu 23 podczas `wait`")
    parser.add_argument("--after", type=float, default=0.0,
                        help="`cancel`: kliknij Anuluj po tylu sekundach")
    parser.add_argument("--minimise-first", action="store_true",
                        help="`wait`: zminimalizuj klienta przed startem (A)")
    parser.add_argument("--restore-after", type=float, default=0.0,
                        help="`wait`: przywróć okno klienta po tylu sekundach (B)")
    parser.add_argument("--flap", type=float, default=0.0,
                        help="`wait`: co tyle sekund przywróć okno na chwilę (E)")
    parser.add_argument("--flap-hold", type=float, default=0.3,
                        help="`wait`: jak długo okno zostaje z przodu przy --flap")
    parser.add_argument("--operator-timeout", type=float, default=45.0,
                        help="`operator-race`: ile sekund czekać na kliknięcie")
    parser.add_argument("--through-guard", action="store_true",
                        help="`connect-race`: pozwól prawdziwemu autofillowi "
                             "spróbować (acquire_focus wykona zapisy Win32)")
    parser.add_argument("--profile", default="",
                        help="`connect-race`: nazwa tunelu SSL-VPN (np. Betanin)")
    parser.add_argument("--pause-at", default="before-login",
                        choices=sorted(PAUSE_POINTS),
                        help="`autofill-race`: gdzie zatrzymac sekwencje")
    parser.add_argument("--app-path", default="",
                        help="`connect-race`: ścieżka klienta, gdy detekcja "
                             "jej nie poda")
    args = parser.parse_args(argv)

    handler, disturbs = COMMANDS[args.command]
    if disturbs and not args.i_am_at_the_keyboard:
        line(WARN, f"`{args.command}` rusza pulpit — dodaj --i-am-at-the-keyboard")
        return 2
    return handler(args)


if __name__ == "__main__":                                # pragma: no cover
    raise SystemExit(main())
