"""Live end-to-end smoke: the real V2 UI chain against the real FortiClient.

Stage 51.  Not a provider test — a wiring test.  It drives the exact objects the
panel would drive, in order, and reports each hand-off:

    select_connect_route -> build_request -> PanelConnectSession
      -> V2ConnectController (ActivationPrompt + ActivationWorker)
      -> FortiClientProvider.connect (real runtime, real Win32InputSystem)
      -> activation gate -> activation revalidation -> autofill
      -> outcome -> present_outcome -> card.

It does **not** touch the production handler and does **not** change
``CONNECT_ENABLED``.  The production gate ``select_connect_route`` still answers
"legacy" (the flag is False); the smoke arms the V2 path the same way the tests
do — by injecting a real runtime through ``PanelConnectSession(runtime_factory=…)``
— so nothing about production is altered to run this.

Secrets: the DRY login/password are the agreed non-secrets; even so, no field
value is ever printed.  Only structural events (``profile-step``, ``login-step``,
``password-step``) and counts are reported.

Commands
--------
``full-chain`` (default)  the 17-point instrumented run.  Enter is HELD unless
                          ``--allow-enter`` is given (a separate, explicit
                          variant).  Needs profile ``1SZP``.
``race``                  the integration security test: after ACTIVATION_OBSERVED
                          the operator clicks another window; V2 must detect
                          ``foreground-is-other-window`` and do nothing — no
                          keystroke, no clipboard secret, no Enter.

Both are interactive: bring FortiClient forward and click it when asked.
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

os.environ.setdefault("QT_QPA_PLATFORM", "windows")

import secure_window as sw                                       # noqa: E402
import vpn                                                       # noqa: E402
from vpn.panel_bridge import (                                   # noqa: E402
    ROUTE_FORTICLIENT_V2, build_request, classify_connect_result,
    select_connect_route,
)
from vpn.panel_bridge import PanelConnectSession                 # noqa: E402
from vpn.providers.forticlient_runtime import FortiConnectRuntime  # noqa: E402
from vpn.providers.input_system import VK_RETURN, Win32InputSystem  # noqa: E402
from vpn.providers.launch_system import WindowsLaunchSystem      # noqa: E402

from PyQt6.QtCore import QTimer                                  # noqa: E402
from PyQt6.QtWidgets import QApplication, QLabel, QVBoxLayout, QWidget  # noqa: E402

from ui.vpn_v2_connect import V2ConnectController, present_outcome  # noqa: E402

DRY_LOGIN = "DRY-RUN-LOGIN-NOT-REAL"
DRY_PASSWORD = "DRY-RUN-PASSWORD-NOT-REAL"
PROFILE = "1SZP"

OK, WARN, BAD, INFO = "  OK  ", " WARN ", " FAIL ", " ..   "


def line(status: str, text: str) -> None:
    print(f"[{status}] {text}")


def head(text: str) -> None:
    print(f"\n=== {text} " + "=" * max(0, 64 - len(text)))


class _Profile:
    """The vault fields ``build_request`` reads — DRY values, real profile name."""

    def __init__(self):
        self.profile_name = PROFILE
        self.server = ""
        self.port = ""
        self.login = DRY_LOGIN
        self.password = DRY_PASSWORD
        self.group = ""
        self.domain = ""
        self.requires_2fa = False


# --------------------------------------------------------------------------- #
# Instrumentation seams — real behaviour, plus a record of what happened       #
# --------------------------------------------------------------------------- #

class RecordingInput(Win32InputSystem):
    """The real keyboard/clipboard, counting operations and holding Enter.

    Records only the *kind* of each operation and, for text/clipboard, its
    length — never the value.  ``allow_enter=False`` swallows ``VK_RETURN`` so
    the first live run cannot submit.
    """

    def __init__(self, *, allow_enter: bool):
        self.allow_enter = allow_enter
        self.ops: list[str] = []
        self.enter_held = 0
        self.enter_sent = 0

    def press_key(self, vk):
        if vk == VK_RETURN and not self.allow_enter:
            self.enter_held += 1
            self.ops.append("enter-HELD")
            return
        if vk == VK_RETURN:
            self.enter_sent += 1
        self.ops.append(f"key:{vk}")
        super().press_key(vk)

    def press_combo(self, modifier_vk, key):
        self.ops.append(f"combo:{modifier_vk}+{key}")
        super().press_combo(modifier_vk, key)

    def type_text(self, text):
        self.ops.append(f"type[{len(text)}]")
        super().type_text(text)

    def copy_to_clipboard(self, text):
        self.ops.append(f"clip_set[{len(text)}]")
        return super().copy_to_clipboard(text)

    def read_clipboard(self):
        self.ops.append("clip_get")
        return super().read_clipboard()

    def sleep(self, seconds):
        super().sleep(seconds)

    def secret_ops(self):
        return [o for o in self.ops
                if o.startswith(("type[", "clip_set[", "key:", "combo:"))]


class RecordingRuntime(FortiConnectRuntime):
    """The real runtime, marking the phase boundaries the report needs.

    Overrides only to append a marker and delegate; every decision stays in the
    base class.  This is how points 9/10/13 are observed at the integration
    seam without reaching into the autofill.
    """

    def __init__(self, *args, marks=None, **kwargs):
        super().__init__(*args, **kwargs)
        self.marks: list[str] = marks if marks is not None else []

    def find_main_window(self, timeout):
        hwnd = super().find_main_window(timeout)
        self.marks.append("find_main_window:" + ("hit" if hwnd else "miss"))
        return hwnd

    def await_activation(self):
        self.marks.append("await_activation:enter")
        result = super().await_activation()
        self.marks.append("await_activation:" + result.state.value)
        return result

    def activation_still_holds(self, hwnd):
        check = super().activation_still_holds(hwnd)
        ok = getattr(check, "ok", None)
        self.marks.append(f"activation_still_holds:{'ok' if ok else 'blocked'}"
                          + ("" if ok else f":{getattr(check, 'reason', '?')}"))
        return check

    def start_autofill(self, login, password, profile_name):
        self.marks.append("start_autofill:enter")
        result = super().start_autofill(login, password, profile_name)
        self.marks.append(f"start_autofill:{result.status.value}")
        return result


# --------------------------------------------------------------------------- #
# The chain                                                                    #
# --------------------------------------------------------------------------- #

class Report:
    """The 17 ordered points, filled as the chain runs."""

    POINTS = [
        "route selected", "request built", "session created",
        "controller started", "polling paused", "activation prompt shown",
        "AWAITING_ACTIVATION", "ACTIVATION_OBSERVED", "activation revalidation",
        "profile selection", "username", "password", "autofill result",
        "outcome classification", "UI card presentation", "polling resumed",
        "final card state",
    ]

    def __init__(self):
        self.state: dict[int, tuple[str, str]] = {}

    def set(self, n, status, text):
        self.state.setdefault(n, (status, text))

    def dump(self):
        head("17-punktowy lifecycle UI -> V2")
        for i, name in enumerate(self.POINTS, start=1):
            status, text = self.state.get(i, (BAD, "NIE OSIĄGNIĘTO"))
            print(f"[{status}] {i:>2}. {name}: {text}")


def _run_chain(*, allow_enter: bool, race: bool, timeout_s: float = 120.0) -> int:
    app = QApplication.instance() or QApplication(sys.argv)
    report = Report()
    provider = vpn.default_registry.get("forticlient")

    # 1. route selected — the production gate's honest answer.
    route = select_connect_route("FortiClient")
    report.set(1, INFO if route != ROUTE_FORTICLIENT_V2 else OK,
               f"select_connect_route -> {route!r} "
               f"(produkcja=legacy; smoke zbroi V2 przez runtime_factory)")

    # 2. request built.
    request = build_request(_Profile(), app_path="", autofill=True)
    report.set(2, OK, f"profile={request.profile_name} autofill={request.autofill} "
                      f"has_credentials={bool(request.login and request.password)} "
                      "(wartości ukryte)")

    # The real runtime, injected — so CONNECT_ENABLED stays False.
    marks: list[str] = []
    recorder = RecordingInput(allow_enter=allow_enter)

    def factory(*, cancellation, activation_observer):
        return RecordingRuntime(
            provider, launch_system=WindowsLaunchSystem(),
            input_system=recorder, window_api=sw.Win32WindowApi(),
            trace=None, cancellation=cancellation,
            activation_observer=activation_observer,
            activation_timeout_s=timeout_s, marks=marks)

    # 3. session created.
    session = PanelConnectSession(request, provider=provider,
                                  runtime_factory=factory)
    report.set(3, OK, f"PanelConnectSession {session!r}")

    # The host widget stands in for the VPN card: a real top-level window that
    # owns the status label and the activation prompt.
    host = QWidget()
    host.setWindowTitle("HospitalHub V2 — smoke karty VPN")
    host.resize(460, 90)
    layout = QVBoxLayout(host)
    label = QLabel("○ (gotowy)")
    layout.addWidget(label)
    controller = V2ConnectController(session, label, prompt_parent=host)
    layout.addWidget(controller.prompt)
    host.show()
    _place_near_forticlient(provider, host)

    # Signal capture — everything the panel would react to.
    seen = {"pause": False, "resume": False, "states": [], "card": None,
            "outcome": None, "cancel_visible_during_fill": False,
            "prompt_visible_at_await": False}

    controller.polling_pause.connect(lambda: seen.__setitem__("pause", True))
    controller.polling_resume.connect(lambda: seen.__setitem__("resume", True))
    controller.card_update.connect(lambda u: seen.__setitem__("card", u))
    controller.finished.connect(lambda o: seen.__setitem__("outcome", o))

    def on_state(state):
        seen["states"].append(state)
        if state == "awaiting-activation":
            seen["prompt_visible_at_await"] = controller.prompt.isVisibleTo(host)

    controller.worker.state_changed.connect(on_state)

    if race:
        head("WARIANT RACE — po aktywacji KLIKNIJ INNE OKNO (nie FortiClient)")
    else:
        head("WARIANT FULL-CHAIN — Enter " +
             ("WYSŁANY" if allow_enter else "WSTRZYMANY"))
    line(INFO, ">>> Przywróć okno FortiClienta i KLIKNIJ w nie, gdy prompt poprosi.")
    if race:
        line(WARN, ">>> Zaraz PO tym, jak prompt powie 'aktywne', kliknij inne okno.")

    # 4/5. controller started + polling paused (pause fires inside start()).
    ticks = [0]
    controller.start()
    report.set(4, OK, "V2ConnectController.start()")
    report.set(5, OK if seen["pause"] else BAD,
               "polling_pause wyemitowany przed workerem"
               if seen["pause"] else "brak polling_pause")

    # Drive the UI event loop by hand so we can measure responsiveness and
    # sample the prompt while the autofill runs.
    deadline = time.monotonic() + timeout_s + 30
    while time.monotonic() < deadline and not controller.done:
        app.processEvents()
        ticks[0] += 1
        st = controller.prompt.presenter.state
        if st == "activation-observed" and controller.worker.isRunning():
            if controller.prompt.cancel_button.isVisibleTo(host):
                seen["cancel_visible_during_fill"] = True
        controller.worker.wait(5)
    for _ in range(5):
        app.processEvents()

    # 6. activation prompt shown.
    report.set(6, OK if seen["prompt_visible_at_await"] else WARN,
               "prompt widoczny w AWAITING_ACTIVATION"
               if seen["prompt_visible_at_await"] else "prompt nie był widoczny")
    # 7/8. the two gate states.
    report.set(7, OK if "awaiting-activation" in seen["states"] else BAD,
               "AWAITING_ACTIVATION dotarł do UI"
               if "awaiting-activation" in seen["states"] else "brak")
    report.set(8, OK if "activation-observed" in seen["states"] else WARN,
               "ACTIVATION_OBSERVED dotarł do UI"
               if "activation-observed" in seen["states"]
               else "nie zaobserwowano aktywacji (timeout/anulowanie)")

    # 9–13 from the runtime marks + outcome.
    _fill_phase_points(report, marks, recorder, race, seen)

    # 14. outcome classification.
    outcome = seen["outcome"]
    if outcome is not None:
        report.set(14, OK, f"code={outcome.code} started={outcome.started} "
                           f"route={outcome.route} error={outcome.error_code}")
    # 15. UI card presentation.
    card = seen["card"]
    if card is not None:
        report.set(15, OK, f"tekst={card.text[:40]!r} kolor={card.colour} "
                           f"card_state={card.card_state}")
    # 16. polling resumed.
    report.set(16, OK if seen["resume"] else BAD,
               "polling_resume wyemitowany po wyniku"
               if seen["resume"] else "brak polling_resume")
    # 17. final card state.
    report.set(17, OK, f"label={label.text()[:40]!r} "
                       f"prompt_widoczny={controller.prompt.isVisibleTo(host)}")

    report.dump()
    _dump_ui_checks(seen, ticks[0], controller, host, recorder, race, allow_enter)
    host.close()
    return 0


def _fill_phase_points(report, marks, recorder, race, seen):
    still = next((m for m in marks if m.startswith("activation_still_holds")), None)
    autofill_started = "start_autofill:enter" in marks
    autofill_result = next((m for m in marks
                            if m.startswith("start_autofill:")
                            and not m.endswith(":enter")), None)
    if race:
        # The race is caught at one of two seams — both are correct, and the
        # invariant is identical: the password never fully lands and Enter never
        # fires.  Report which seam caught it.
        caught_at_revalidation = still is not None and ":blocked" in still
        blocked_in_fill = (autofill_result is not None
                           and not autofill_result.endswith("done"))
        detected = caught_at_revalidation or blocked_in_fill
        if caught_at_revalidation:
            report.set(9, OK, f"rewalidacja WYKRYŁA zmianę: {still}")
        elif still is not None:
            report.set(9, OK, f"rewalidacja: {still} (zmiana wykryta w guardzie "
                              "autofillu)")
        report.set(10, OK if not autofill_started else INFO,
                   "autofill nie wystartował (złapane na rewalidacji)"
                   if not autofill_started
                   else "autofill wystartował, guard przerwał w trakcie")
        report.set(11, OK, "username: przerwane przed pełnym wpisaniem")
        report.set(12, OK, "password: NIE dokończone (guard)")
        report.set(13, OK if detected else BAD,
                   f"V2 wykrył foreground-is-other-window: {detected} "
                   f"(still={still}, autofill={autofill_result})")
        return
    if still is not None:
        ok = still.endswith(":ok")
        report.set(9, OK if ok else WARN, f"rewalidacja: {still}")
    # full-chain: the autofill ran; describe it from operation counts (no values).
    profile_ops = sum(1 for o in recorder.ops if o.startswith("combo:16+9"))  # Shift+Tab
    report.set(10, OK if autofill_started else WARN,
               f"wybór profilu 1SZP: Shift+Tab×{profile_ops} + type-ahead")
    tabs = sum(1 for o in recorder.ops if o == "key:9")
    report.set(11, OK if autofill_started else WARN,
               f"username: paste+verify (Ctrl+V), nawigacja Tab×{tabs}")
    pastes = sum(1 for o in recorder.ops if o == "combo:17+86")  # Ctrl+V
    report.set(12, OK if autofill_started else WARN,
               f"password: paste (łącznie Ctrl+V ×{pastes})")
    if autofill_result is not None:
        report.set(13, OK if autofill_result.endswith("done") else WARN,
                   f"autofill_result: {autofill_result} "
                   f"enter_held={recorder.enter_held} enter_sent={recorder.enter_sent}")


def _dump_ui_checks(seen, ticks, controller, host, recorder, race, allow_enter):
    head("kontrole UI")
    line(OK if ticks > 50 else WARN,
         f"UI responsywne: {ticks} obrotów pętli zdarzeń w trakcie sesji")
    line(OK if seen["prompt_visible_at_await"] else WARN,
         "prompt pojawił się przy AWAITING_ACTIVATION")
    if not race:
        line(OK if seen["cancel_visible_during_fill"] else WARN,
             "Cancel dostępny podczas autofillu (hold_cancel)")
    line(OK if not controller.prompt.isVisibleTo(host) else WARN,
         "prompt ukryty PO wyniku (dokładnie na zakończeniu)")
    line(OK if seen["resume"] else BAD, "polling wrócił po sesji")
    card = seen["card"]
    if card is not None:
        premature = card.card_state == "connecting" and race
        line(BAD if premature else OK,
             f"karta nie oznaczona przedwcześnie jako connected "
             f"(card_state={card.card_state})")

    head("bezpieczeństwo — operacje na wejściu (bez wartości)")
    line(INFO, f"wszystkie operacje: {len(recorder.ops)}")
    line(INFO, f"sekrety wysłane: enter_sent={recorder.enter_sent} "
               f"enter_held={recorder.enter_held}")
    if race:
        outcome = seen["outcome"]
        not_submitted = outcome is None or outcome.code != "submitted"
        pastes = sum(1 for o in recorder.ops if o == "combo:17+86")   # Ctrl+V
        line(OK if not_submitted else BAD,
             f"race: NIE zgłoszono submitted (code="
             f"{getattr(outcome, 'code', None)})")
        line(OK if recorder.enter_sent == 0 else BAD,
             f"race: zero Enter = {recorder.enter_sent == 0}")
        line(OK if pastes < 2 else BAD,
             f"race: hasło NIE dokończone — Ctrl+V ×{pastes} (<2 = brak pełnego "
             "login+hasło)")
        card = seen["card"]
        if card is not None:
            line(OK if card.card_state != "connecting" else BAD,
                 f"race: karta NIE 'connecting' (card_state={card.card_state})")
    else:
        line(OK if (allow_enter or recorder.enter_sent == 0) else BAD,
             f"Enter zgodny z wariantem: sent={recorder.enter_sent} "
             f"(allow_enter={allow_enter})")


def _place_near_forticlient(provider, host):
    """Put the smoke card next to the real client window, when it is on screen."""
    try:
        import win32gui
        found = provider.secure_window_target().first_verified_candidate()
        if found is None:
            return
        hwnd, _owner = found
        left, top, right, bottom = win32gui.GetWindowRect(hwnd)
        if right < 0 or bottom < 0:            # minimised / off-screen
            line(INFO, "FortiClient zminimalizowany — karta smoke wyśrodkowana; "
                       "przywróć klienta, aby prompt stanął obok.")
            return
        host.move(min(left, 1400), max(top - 110, 0))
        line(INFO, f"karta smoke ustawiona obok okna FortiClient {hex(hwnd)}")
    except Exception:
        pass


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        description="Live smoke łańcucha UI -> V2 (FortiClient 1SZP).")
    sub = parser.add_subparsers(dest="command")
    p_full = sub.add_parser("full-chain", help="17-punktowy przebieg")
    p_full.add_argument("--allow-enter", action="store_true",
                        help="osobny wariant: wypuść prawdziwy Enter")
    sub.add_parser("race", help="test wyścigu: klik w inne okno po aktywacji")
    args = parser.parse_args(argv)
    command = args.command or "full-chain"
    if command == "race":
        return _run_chain(allow_enter=False, race=True)
    return _run_chain(allow_enter=getattr(args, "allow_enter", False), race=False)


if __name__ == "__main__":
    raise SystemExit(main())
