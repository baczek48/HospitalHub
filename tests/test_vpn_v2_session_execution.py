"""Stage 54: the V2 session *executes* each provider's own connect flow.

Stage 53 made the session pick the right provider; execution stayed
FortiClient-shaped — ``provider.connect(request, entry, system=)`` over
``provider.connect_runtime(...)``, two methods only FortiClient had.  Had a flag
been flipped for Stormshield or Barracuda, the session would have hit an
``AttributeError``, swallowed it, and reported a plain ``FAILED`` — a misleading
answer at exactly the moment a cutover needs an honest one.

So the two providers grew the same two methods, each delegating to **its own**
flow (``StormshieldConnectFlow`` / ``BarracudaConnectFlow``), and Stormshield
grew the runtime it never had (``StormshieldConnectRuntime``, the twin of
Barracuda's).  The bridge is unchanged: it still speaks only the provider
contract.

What must stay true, and is pinned here:
  * disarmed is still disarmed — every provider answers ``unsupported`` without
    building a runtime, and all three flags are off;
  * an armed provider runs *its own* flow, never another provider's;
  * the flows still stop before typing — the systems they run on have no method
    that could send a keystroke;
  * cancellation still wins before anything is attempted.
"""

import inspect
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

from vpn import VpnRequest  # noqa: E402
from vpn.panel_bridge import PanelConnectSession, PanelOutcome  # noqa: E402
from vpn.providers.barracuda import BarracudaProvider  # noqa: E402
from vpn.providers.barracuda_connect import (  # noqa: E402
    BarracudaConnectFlow, BarracudaConnectRuntime, BarracudaConnectSystem,
)
from vpn.providers.forticlient import FortiClientProvider  # noqa: E402
from vpn.providers.stormshield import StormshieldProvider  # noqa: E402
from vpn.providers.stormshield_connect import (  # noqa: E402
    StormshieldConnectFlow, StormshieldConnectRuntime, StormshieldConnectSystem,
)
from vpn.types import DetectionState, ErrorCode  # noqa: E402

HWND = 4242

#: The two providers this stage generalised, each with the flow and runtime it
#: is supposed to reach — and the flow it must never reach is every other row.
NEW = [
    ("stormshield", StormshieldProvider, StormshieldConnectFlow,
     StormshieldConnectRuntime, StormshieldConnectSystem),
    ("barracuda", BarracudaProvider, BarracudaConnectFlow,
     BarracudaConnectRuntime, BarracudaConnectSystem),
]
ALL_PROVIDERS = [("forticlient", FortiClientProvider)] + [
    (pid, cls) for pid, cls, *_ in NEW]


class Answer:
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)


class Recording:
    """A fake machine: records the phase, answers what the test wants.

    Not a subclass of any provider's system on purpose — the flows only ever
    duck-type, and a shared fake proves the two flows ask for the same five
    things.
    """

    def __init__(self, *, detection=None, launch=None, handle=HWND,
                 activation=None, still=None):
        self.calls: list[str] = []
        self._detection = detection if detection is not None else Answer(
            state=DetectionState.INSTALLED)
        self._launch = launch if launch is not None else Answer(
            success=True, error_code=None)
        self._handle, self._activation, self._still = handle, activation, still

    def detect(self, request):
        self.calls.append("detect")
        return self._detection

    def launch(self, request):
        self.calls.append("launch")
        return self._launch

    def find_main_window(self, timeout):
        self.calls.append("find_main_window")
        return self._handle

    def await_activation(self):
        self.calls.append("await_activation")
        return self._activation

    def activation_still_holds(self, hwnd):
        self.calls.append("activation_still_holds")
        return self._still


def request(provider_id):
    return VpnRequest(provider_id=provider_id, profile_name="SZP",
                      server="vpn.x", port="443", login="jkowalski",
                      password="SuperSecret123", app_path=r"C:\x\client.exe")


# ══════════════════════════════════════════════════════════════════════════
# A. Disarmed stays disarmed — the new methods change nothing today
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("pid,cls", ALL_PROVIDERS)
def test_a_flag_is_off(pid, cls):
    """Production is still legacy: this stage arms nobody."""
    assert cls.CONNECT_ENABLED is False


@pytest.mark.parametrize("pid,cls", ALL_PROVIDERS)
def test_a2_connect_without_a_system_is_unsupported(pid, cls):
    result = cls().connect(request(pid))
    assert result.success is False
    assert result.error_code == ErrorCode.UNSUPPORTED.value
    assert result.provider_id == pid


@pytest.mark.parametrize("pid,cls", ALL_PROVIDERS)
def test_a3_disarmed_connect_builds_no_runtime(pid, cls, monkeypatch):
    """The refusal comes *before* a runtime is built — nothing is constructed."""
    built = []
    monkeypatch.setattr(cls, "connect_runtime",
                        lambda self, **kw: built.append(kw))
    cls().connect(request(pid))
    assert built == []


@pytest.mark.parametrize("pid,cls", ALL_PROVIDERS)
def test_a4_session_on_a_disarmed_provider_is_unsupported(pid, cls):
    """Through the panel's session, not just the provider — the same answer."""
    outcome = PanelConnectSession(request(pid)).run()
    assert outcome.code is PanelOutcome.UNSUPPORTED
    assert outcome.error_code == ErrorCode.UNSUPPORTED.value


# ══════════════════════════════════════════════════════════════════════════
# B. Armed: each provider runs ITS OWN flow, over the five read-only phases
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("pid,cls,flow_cls,runtime_cls,system_cls", NEW)
def test_b_connect_runs_the_providers_own_flow(pid, cls, flow_cls, runtime_cls,
                                               system_cls):
    """An injected system runs the flow — no flag, no real machine."""
    system = Recording(activation=Answer(ok=True, state=Answer(
        value="activation-observed"), hwnd=HWND), still=Answer(ok=True))
    result = cls().connect(request(pid), system=system)

    assert system.calls == ["detect", "launch", "find_main_window",
                            "await_activation", "activation_still_holds"]
    assert result.provider_id == pid
    assert result.requires_user_action is True


@pytest.mark.parametrize("pid,cls,flow_cls,runtime_cls,system_cls", NEW)
def test_b2_the_flow_class_is_the_providers_own(pid, cls, flow_cls, runtime_cls,
                                                system_cls, monkeypatch):
    """Not FortiClient's, and not the other new provider's."""
    seen = []

    class Spy(flow_cls):
        def __init__(self, provider, system):
            seen.append((type(provider).__name__, type(self).__bases__[0]))
            super().__init__(provider, system)

    monkeypatch.setattr(sys.modules[cls.__module__], flow_cls.__name__, Spy)
    cls().connect(request(pid), system=Recording())
    assert seen == [(cls.__name__, flow_cls)]


@pytest.mark.parametrize("pid,cls,flow_cls,runtime_cls,system_cls", NEW)
def test_b3_detection_failure_stops_the_flow(pid, cls, flow_cls, runtime_cls,
                                             system_cls):
    system = Recording(detection=Answer(state=DetectionState.NOT_INSTALLED))
    result = cls().connect(request(pid), system=system)
    assert system.calls == ["detect"]
    assert result.success is False
    assert result.error_code == ErrorCode.CLIENT_NOT_FOUND.value


# ══════════════════════════════════════════════════════════════════════════
# C. The runtime: the provider's own, seams passed through, read-only
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("pid,cls,flow_cls,runtime_cls,system_cls", NEW)
def test_c_connect_runtime_builds_the_providers_own_runtime(
        pid, cls, flow_cls, runtime_cls, system_cls):
    provider = cls()
    runtime = provider.connect_runtime()
    assert type(runtime) is runtime_cls
    assert isinstance(runtime, system_cls)


@pytest.mark.parametrize("pid,cls,flow_cls,runtime_cls,system_cls", NEW)
def test_c2_runtime_takes_the_seams_the_session_passes(
        pid, cls, flow_cls, runtime_cls, system_cls):
    """``PanelConnectSession`` passes exactly these two — both must arrive."""
    marks = []
    token = object()
    observer = marks.append
    runtime = cls().connect_runtime(cancellation=token,
                                    activation_observer=observer)
    assert runtime.cancellation is token
    assert runtime.activation_observer is observer


@pytest.mark.parametrize("pid,cls,flow_cls,runtime_cls,system_cls", NEW)
def test_c3_runtime_signature_matches_barracudas(pid, cls, flow_cls, runtime_cls,
                                                 system_cls):
    """The two runtimes are twins — one shape, so the bridge needs no branch."""
    mine = inspect.signature(runtime_cls.__init__).parameters
    theirs = inspect.signature(BarracudaConnectRuntime.__init__).parameters
    assert list(mine) == list(theirs)


@pytest.mark.parametrize("pid,cls,flow_cls,runtime_cls,system_cls", NEW)
def test_c4_runtime_cannot_type(pid, cls, flow_cls, runtime_cls, system_cls):
    """No autofill, no keystroke, no clipboard — the flows stop before typing.

    A method that could type would be reachable from an armed connect, so its
    absence is the guarantee, not a convention.
    """
    forbidden = ("autofill", "type", "send", "press", "click", "clipboard",
                 "paste", "key")
    names = [n for n in dir(runtime_cls) if not n.startswith("__")]
    assert not [n for n in names
                if any(word in n.lower() for word in forbidden)], names


@pytest.mark.parametrize("pid,cls,flow_cls,runtime_cls,system_cls", NEW)
def test_c5_building_a_runtime_touches_nothing(pid, cls, flow_cls, runtime_cls,
                                               system_cls):
    """Construction is I/O-free: it stores seams and asks the machine nothing.

    An exploding provider proves it — if the runtime called detection, launch or
    the window target while being built, this would raise.
    """
    class Exploding(cls):
        def detect(self, request=None):
            raise AssertionError("detection during construction")

        def launch(self, request=None):
            raise AssertionError("launch during construction")

        def secure_window_target(self, api=None, finder=None):
            raise AssertionError("window target during construction")

    Exploding().connect_runtime()


# ══════════════════════════════════════════════════════════════════════════
# D. Isolation — one provider's session never reaches another's flow
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("pid,cls,flow_cls,runtime_cls,system_cls", NEW)
def test_d_other_providers_flows_are_never_entered(pid, cls, flow_cls,
                                                   runtime_cls, system_cls,
                                                   monkeypatch):
    intruders = []
    for other_pid, other_cls, other_flow, _rt, _sys in NEW:
        if other_pid == pid:
            continue

        def trap(provider, system, _name=other_flow.__name__):
            intruders.append(_name)
            raise AssertionError(f"{_name} entered for {pid}")

        monkeypatch.setattr(sys.modules[other_cls.__module__],
                            other_flow.__name__, trap)
    cls().connect(request(pid), system=Recording())
    assert intruders == []


def test_d2_a_session_runs_the_flow_of_the_provider_it_names(monkeypatch):
    """End to end through the bridge: armed via ``runtime_factory`` (Stage 51's
    seam), the session hands the runtime to the named provider's flow."""
    for pid, cls, flow_cls, _rt, _sys in NEW:
        system = Recording(activation=Answer(ok=True, state=Answer(
            value="activation-observed"), hwnd=HWND), still=Answer(ok=True))
        session = PanelConnectSession(request(pid),
                                      runtime_factory=lambda **kw: system)
        outcome = session.run()
        assert system.calls[0] == "detect", pid
        assert len(system.calls) == 5, pid
        assert outcome.code in (PanelOutcome.MANUAL, PanelOutcome.STARTED), pid


# ══════════════════════════════════════════════════════════════════════════
# E. Cancellation and the entry parameter
# ══════════════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("pid,cls", ALL_PROVIDERS)
def test_e_cancel_before_run_attempts_nothing(pid, cls):
    system = Recording()
    session = PanelConnectSession(request(pid),
                                  runtime_factory=lambda **kw: system)
    session.cancel()
    outcome = session.run()
    assert outcome.code is PanelOutcome.CANCELLED
    assert system.calls == []


@pytest.mark.parametrize("pid,cls,flow_cls,runtime_cls,system_cls", NEW)
def test_e2_entry_is_accepted_and_ignored(pid, cls, flow_cls, runtime_cls,
                                          system_cls):
    """One client, one route: the caller's entry value changes nothing.

    It is accepted because the contract has it (FortiClient follows two legacy
    entry points) — pinned so nobody later reads it as meaningful.
    """
    outcomes = []
    for entry in ("", "connect", "connect_monitored", "nonsense"):
        system = Recording()
        result = cls().connect(request(pid), entry, system=system)
        outcomes.append((system.calls, result.success, result.error_code))
    assert len(set(map(str, outcomes))) == 1, outcomes


# ══════════════════════════════════════════════════════════════════════════
# F. The bridge stayed provider-agnostic
# ══════════════════════════════════════════════════════════════════════════

def test_f_bridge_names_no_provider_class_in_its_execution():
    """``PanelConnectSession.run`` speaks only the contract, not a provider.

    The whole point of Stages 53–54: the execution path mentions no concrete
    provider, so adding a fourth one needs no edit here.
    """
    source = inspect.getsource(PanelConnectSession.run)
    for name in ("FortiClientProvider", "StormshieldProvider",
                 "BarracudaProvider", "FortiConnectFlow",
                 "StormshieldConnectFlow", "BarracudaConnectFlow"):
        assert name not in source, name


@pytest.mark.parametrize("pid,cls", ALL_PROVIDERS)
def test_f2_every_v2_provider_answers_the_same_two_methods(pid, cls):
    """The contract the session relies on, pinned for all three."""
    connect = inspect.signature(cls.connect).parameters
    assert "request" in connect and "system" in connect
    assert connect["system"].kind is inspect.Parameter.KEYWORD_ONLY
    assert callable(getattr(cls, "connect_runtime"))
