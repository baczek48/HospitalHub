"""A secret-safe contract for interacting with another program's window.

Stage 13 lifts the Stage-12 security rule into the new architecture as a
first-class contract, so a future migrated ``connect()`` cannot be built with
a weaker guarantee than the corrected legacy:

    no verified FortiClient window + no verified focus
        = no secret, no clipboard, no SendInput, no Enter.

Shared implementation, not duplicated
--------------------------------------
The actual security checks live in the project-root module ``secure_window``:
HWND → PID (PID > 0), process image via ``QueryFullProcessImageNameW``, safe
path canonicalisation, "image under a trusted FortiClient directory", control
ownership, and focus acquisition.  Both the legacy ``vpn_connect`` and this
contract import *that* module, so there is exactly one copy of the security
logic.  Legacy cannot import ``vpn`` (that would be a layering cycle); it does
not need to — it uses the same primitives directly.  This module only *composes*
them into a provider-facing object.

Secret-free by construction
---------------------------
Nothing here takes a ``username``, ``password``, ``token`` or clipboard value.
A caller that has a secret to deliver hands in a **zero-argument callback**;
:meth:`VerifiedWindow.run_guarded` re-confirms the target and only then calls
it.  The contract never receives, stores, or forwards the secret, and there is
no code path that performs an operation without a fresh confirmation.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable

from secure_window import (
    REASON_VERIFIED, ControlPartition, OwnerCheck, TargetCheck, WindowApi,
    Win32WindowApi, WindowCandidateFinder, acquire_focus, confirm_target,
    controls_belong_to, operation_controls_verified, partition_controls,
    verify_window_owner,
)

__all__ = [
    "SecureWindowTarget", "VerifiedWindow", "TargetRejected", "GuardResult",
    "WindowCandidateFinder", "ControlPartition", "ForegroundCheck",
    "REASON_MINIMISED",
    "REASON_VISIBILITY_UNKNOWN",
]

#: Reason reported when a guarded operation is refused because it was aimed at
#: no verified window at all (fail-closed default).
REASON_NO_TARGET = "no-verified-target"

#: The verified window is the foreground window *and* minimised.  Windows can
#: report both at once — measured on a real FortiClient — and a window nobody
#: can see is not a window a user just activated.
REASON_MINIMISED = "target-minimised"
#: The desktop could not say whether the window is minimised.  Only the
#: ``raise_window=False`` path treats this as a refusal; see
#: :meth:`SecureWindowTarget.strict_foreground_check`.
REASON_VISIBILITY_UNKNOWN = "visibility-unknown"


# --------------------------------------------------------------------------- #
# Results                                                                      #
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class TargetRejected:
    """A window (or the whole target) that must not receive anything."""

    reason: str
    pid: int | None = None
    image_name: str | None = None
    #: Why the desktop said no, when the caller asked to be told (Stage 20).
    #: Numbers and handles only — see ``secure_window.FOCUS_DIAGNOSTIC_KEYS``.
    diagnostics: dict = field(default_factory=dict)

    ok = False

    def to_trace_data(self) -> dict:
        return {key: value for key, value in (
            ("event", "target-rejected"), ("reason", self.reason),
            ("pid", self.pid), ("image_name", self.image_name),
        ) if value is not None}


@dataclass(frozen=True)
class GuardResult:
    """Outcome of a guarded operation.  ``performed`` is the only proof the
    callback ran; when False the callback was never called."""

    purpose: str
    performed: bool
    reason: str
    value: Any = None

    ok = property(lambda self: self.performed)

    def to_trace_data(self) -> dict:
        return {"purpose": self.purpose, "performed": self.performed,
                "reason": self.reason}


# --------------------------------------------------------------------------- #
# Verified window handle                                                       #
# --------------------------------------------------------------------------- #

class VerifiedWindow:
    """A window whose owner is a trusted FortiClient process and to which
    focus has been acquired.

    Obtained only from :meth:`SecureWindowTarget.acquire`; it cannot be
    constructed as "verified" from an arbitrary HWND by a caller.  Every
    operation goes through :meth:`run_guarded`, which re-confirms the target
    first — a handle held across time proves nothing on its own.

    Holds the thread attachment from focus acquisition; :meth:`release` (and
    the context-manager exit) detaches it.  Deliberately exposes no method that
    types, pastes, or sends a keystroke.
    """

    ok = True

    def __init__(self, hwnd, pid, image_name, trusted_dirs, api: WindowApi,
                 our_tid, their_tid, require_visible: bool = False):
        self._hwnd = hwnd
        self._pid = pid
        self._image_name = image_name
        self._trusted = trusted_dirs
        self._api = api
        self._our_tid = our_tid
        self._their_tid = their_tid
        self._released = False
        #: Also refuse a minimised window (Stage 29).  Off by default so the
        #: contract behaves exactly as it did for every existing caller.
        self._require_visible = bool(require_visible)

    @property
    def hwnd(self):
        """The verified window — read-only, for a *reader* that must look at
        this very window (Stage 63: the MSAA profile read).  Nothing here sends
        to it; every send still goes through :meth:`run_guarded`."""
        return self._hwnd

    @property
    def pid(self) -> int | None:
        return self._pid

    @property
    def image_name(self) -> str | None:
        return self._image_name

    def confirm(self) -> TargetCheck:
        """Is *this* verified window, owned by *this* process, in the
        foreground right now?  Re-reads the desktop every time.

        With `require_visible` the question gains the second half of what the
        activation gate promised the user: **and not minimised**.  Stage 25
        measured why that matters — ``confirm_target`` never asks about
        ``is_iconic``, and Windows keeps reporting a minimised window as the
        foreground window, so a client the user had put away satisfied every
        guard and received both credentials.  Since all nine guards of the
        autofill reach the desktop through this one method, asking here covers
        all of them without a single check inside the autofill itself.

        The shared ``confirm_target`` is unchanged and still decides first: the
        extra reading only ever turns a "yes" into a "no", never the reverse.
        """
        if self._released:
            return TargetCheck(False, REASON_NO_TARGET)
        check = confirm_target(self._hwnd, self._pid, self._trusted, self._api)
        if not check.ok or not self._require_visible:
            return check
        try:
            iconic = self._api.is_iconic(self._hwnd)
        except Exception as exc:
            # A seam that breaks must not become a way through.  The real
            # `Win32WindowApi.is_iconic` answers None rather than raising, so
            # this is a broken or hostile seam, not an unknowing one.
            return TargetCheck(False, f"iconic-error:{type(exc).__name__}")
        if iconic is True:
            return TargetCheck(False, REASON_MINIMISED)
        # None means the desktop cannot tell.  Stage 22 settled that an unknown
        # answer does not veto (`foreground_check` behaves the same way), and
        # every existing fake WindowApi answers None.
        return check

    def controls_owned(self, controls) -> TargetCheck:
        """Layout integrity: the window and *every* control offered is its own.

        This is the stricter of the two questions and belongs to callers that
        curate the set themselves — the EMS authentication window hands in its
        Edit/Button controls, and one foreign field there means the layout
        cannot be trusted at all (the legacy rule, kept).  Do not hand this a
        window's raw child list: see :meth:`partition_controls`.
        """
        if self._released:
            return TargetCheck(False, REASON_NO_TARGET)
        return controls_belong_to(self._hwnd, controls, self._trusted, self._api)

    def operation_controls(self, controls) -> TargetCheck:
        """May these specific handles receive the operation about to happen?

        The question a secret path asks.  Same per-control rule as
        :meth:`controls_owned` — owned by this window's process, rooted in this
        window — but it reports *how* a control failed, and it says nothing
        about the rest of the window's children.
        """
        if self._released:
            return TargetCheck(False, REASON_NO_TARGET)
        return operation_controls_verified(self._hwnd, controls, self._trusted,
                                           self._api)

    def partition_controls(self, controls) -> ControlPartition:
        """Which of `controls` may be used, and which may not.

        A window is not condemned by a child it merely contains: a real
        FortiClient main window is Electron and owns a Direct3D surface through
        a *second* process.  Asking "is every child mine?" rejects a genuine
        client while proving nothing about the destination of a secret.  Ask
        instead which handles are usable, then use only those.
        """
        if self._released:
            return ControlPartition((), tuple(controls), REASON_NO_TARGET, None)
        return partition_controls(self._hwnd, controls, self._trusted, self._api)

    def run_guarded(self, purpose: str, operation: Callable[[], Any], *,
                    controls=()) -> GuardResult:
        """Confirm the target, then run `operation` — or refuse, having run
        nothing.

        `operation` takes no arguments and is supplied by the caller; the
        secret (if any) is captured in that closure and never passes through
        this contract.  The order is fixed: foreground+owner confirmation,
        then optional control-ownership, then — and only then — the callback.
        Fail-closed: any failure, or an exception from the confirmation itself,
        returns ``performed=False`` without calling `operation`.
        """
        try:
            check = self.confirm()
            if not check.ok:
                return GuardResult(purpose, False, check.reason)
            if controls:
                # The operation set — the handles this very operation touches.
                owned = self.operation_controls(controls)
                if not owned.ok:
                    return GuardResult(purpose, False, owned.reason)
        except Exception as exc:                       # confirmation itself broke
            return GuardResult(purpose, False, f"confirm-error:{type(exc).__name__}")
        value = operation()
        return GuardResult(purpose, True, REASON_VERIFIED, value)

    def release(self) -> None:
        if self._released:
            return
        self._released = True
        try:
            self._api.attach_thread_input(self._our_tid, self._their_tid, False)
        except Exception:
            pass

    def __enter__(self) -> "VerifiedWindow":
        return self

    def __exit__(self, *exc) -> None:
        self.release()

    def __repr__(self) -> str:      # never a secret, never a raw path
        return (f"<VerifiedWindow image={self._image_name!r} "
                f"released={self._released}>")


@dataclass(frozen=True)
class ForegroundCheck:
    """Is the client's window the one the user is looking at, right now?

    A **reading**, never an action: nothing here activates, restores, raises or
    types.  It exists so that a caller can wait for the user to bring the
    client forward instead of trying to do it for them — which Windows refuses
    from a background process anyway (Stages 18-20).

    Carries no secret and no user data: a handle, a pid, an executable's base
    name, and booleans.  A window *title* is deliberately absent — it is
    whatever document the user happens to have open.
    """

    ok: bool
    reason: str
    hwnd: Any = None
    pid: int | None = None
    image_name: str | None = None
    #: The verified window is the foreground window at this instant.
    foreground: bool = False
    #: True / False / None when the desktop seam cannot tell.
    iconic: bool | None = None

    @property
    def found(self) -> bool:
        """A trusted client window exists — whether or not it is in front."""
        return self.hwnd is not None

    @property
    def identity(self) -> tuple:
        """What has to stay the same for this to be the same window."""
        return (self.hwnd, self.pid, self.image_name)

    def to_trace_data(self) -> dict:
        return {key: value for key, value in (
            ("event", "foreground-check"), ("reason", self.reason),
            ("pid", self.pid), ("image_name", self.image_name),
            ("foreground", self.foreground),
        ) if value is not None}


# --------------------------------------------------------------------------- #
# The contract                                                                 #
# --------------------------------------------------------------------------- #

class SecureWindowTarget:
    """Turns candidate windows into a :class:`VerifiedWindow`, or refuses.

    Responsibilities, each delegated to ``secure_window``:

    * find a candidate (via an injected :class:`WindowCandidateFinder`);
    * verify HWND → PID;
    * verify the owning process image path;
    * verify the image sits in a trusted FortiClient install directory;
    * acquire focus safely (attach + set-foreground + confirm);
    * hand back a handle that re-confirms before every operation.

    It never sees a secret.  `trusted_dirs` is computed by the caller (the
    provider, from its own detection) so this class does no I/O beyond the
    injected :class:`WindowApi` seam.
    """

    def __init__(self, trusted_dirs, api: WindowApi | None = None,
                 finder: WindowCandidateFinder | None = None, *,
                 require_visible: bool = False, raise_window: bool = True):
        self._trusted = tuple(trusted_dirs)
        self._api = api if api is not None else Win32WindowApi()
        self._finder = finder
        #: Passed to every :class:`VerifiedWindow` this target produces.  Only
        #: the migrated FortiClient connect turns it on; the legacy never
        #: builds one of these at all.
        self._require_visible = bool(require_visible)
        #: May :meth:`acquire` raise the window?  ``False`` is the Stage-29/33
        #: contract: after the user has activated the client themselves, this
        #: side does not restore, raise or activate anything — it only checks
        #: that they really did, and refuses otherwise.
        self._raise_window = bool(raise_window)
        #: Diagnostics of the most recent focus attempt, when one was asked
        #: for.  Empty otherwise; never consulted by any decision.
        self.last_focus_diagnostics: dict = {}

    # -- verification (no side effects) ------------------------------------ #

    def verify_owner(self, hwnd) -> OwnerCheck:
        return verify_window_owner(hwnd, self._trusted, self._api)

    def find_candidates(self) -> list:
        return list(self._finder.candidates()) if self._finder is not None else []

    def first_verified_candidate(self) -> tuple[Any, OwnerCheck] | None:
        """The first candidate whose owner verifies — used to *locate*, never
        to send anything."""
        for hwnd in self.find_candidates():
            owner = self.verify_owner(hwnd)
            if owner.verified:
                return hwnd, owner
        return None

    def foreground_check(self, hwnd=None) -> ForegroundCheck:
        """Read-only: is a trusted client window in front and visible?

        Composed entirely from the checks that already exist — the candidate
        search, :func:`verify_window_owner` and :func:`confirm_target` — so
        there is one definition of "this window may be trusted" and this is not
        a second one.  `hwnd` asks about one particular window (the caller has
        pinned it); without it, the first verified candidate is examined.

        Sends nothing, activates nothing, and takes no focus: it cannot be used
        to reach a window, only to notice that the user already did.
        """
        if hwnd is None:
            found = self.first_verified_candidate()
            if found is None:
                return ForegroundCheck(False, REASON_NO_TARGET)
            hwnd, owner = found
        else:
            owner = self.verify_owner(hwnd)
            if not owner.verified:
                return ForegroundCheck(False, owner.reason, None, owner.pid,
                                       owner.image_name)

        try:
            check = confirm_target(hwnd, owner.pid, self._trusted, self._api)
        except Exception as exc:                      # a seam misbehaved
            return ForegroundCheck(False, f"confirm-error:{type(exc).__name__}",
                                   hwnd, owner.pid, owner.image_name)
        try:
            iconic = self._api.is_iconic(hwnd)
        except Exception:
            iconic = None

        if not check.ok:
            return ForegroundCheck(False, check.reason, hwnd, owner.pid,
                                   owner.image_name, False, iconic)
        if iconic is True:
            # Foreground *and* minimised: real, observed, and not an activation.
            return ForegroundCheck(False, REASON_MINIMISED, hwnd, owner.pid,
                                   owner.image_name, True, True)
        return ForegroundCheck(True, check.reason, hwnd, owner.pid,
                               owner.image_name, True, iconic)

    def bring_forward(self, hwnd) -> bool:
        """Ask Windows to put a *verified* client window in front.

        2026-10-19 (owner's decision after the field test): waiting for the
        user to click the client made every connect stop at "switch to the
        window".  The measurement that ruled raising out (Stages 18-20) was of
        a background process; HospitalHub is the foreground program at the
        moment "Połącz" is clicked, and Windows lets the foreground program
        hand the foreground on -- measured: ``SetForegroundWindow`` from the
        connect's worker thread succeeds.

        This only *moves the window*.  It types nothing, and it decides
        nothing: the gate still waits until :meth:`foreground_check` sees the
        window in front, and every guard before every keystroke still re-reads
        the desktop.  A window whose owner does not verify is not touched.
        Returns whether Windows accepted the request; never raises.
        """
        try:
            if not self.verify_owner(hwnd).verified:
                return False
        except Exception:
            return False
        try:
            if self._api.is_iconic(hwnd) is True:
                self._api.restore_window(hwnd)
        except Exception:
            pass
        try:
            return bool(self._api.set_foreground_window(hwnd))
        except Exception:
            return False

    def strict_foreground_check(self, hwnd=None) -> ForegroundCheck:
        """:meth:`foreground_check`, with "unknown" counted as "no".

        The difference is one word in one place.  :meth:`foreground_check` is
        shared with the activation gate, where an unreadable ``is_iconic`` must
        not be able to end a wait the user is in the middle of — "we could not
        see" is not "the user went away".  Here the question is the opposite
        one: *may a password be typed into this window?*  An answer of "we
        could not see" is not a yes, and this path has no way to find out
        later, because it is about to stop looking and start typing.

        So the composition is deliberate: the shared reading decides
        everything it already decided, and this adds the single rule that a
        visibility of anything other than ``False`` refuses.
        """
        check = self.foreground_check(hwnd)
        if not check.ok:
            return check
        if check.iconic is False:
            return check
        reason = (REASON_MINIMISED if check.iconic is True
                  else REASON_VISIBILITY_UNKNOWN)
        return ForegroundCheck(False, reason, check.hwnd, check.pid,
                               check.image_name, check.foreground, check.iconic)

    # -- focus (attaches thread input; the handle must be released) --------- #

    def acquire_any(self, *, diagnose: bool = False
                    ) -> VerifiedWindow | TargetRejected:
        """Acquire the first candidate whose owner verifies and focus succeeds.

        Candidates come from the finder (title match); each is fully verified
        by :meth:`acquire`.  Returns the last rejection when none succeed, or a
        no-target rejection when there were no candidates at all.
        """
        rejection: TargetRejected | None = None
        for hwnd in self.find_candidates():
            result = self.acquire(hwnd, diagnose=diagnose)
            if isinstance(result, VerifiedWindow):
                return result
            rejection = result
        return rejection if rejection is not None else TargetRejected(REASON_NO_TARGET)

    def acquire(self, hwnd, *, diagnose: bool = False
                ) -> VerifiedWindow | TargetRejected:
        """Verify ownership and take focus.  On success returns a
        :class:`VerifiedWindow` (attach thread input held); on any failure a
        :class:`TargetRejected`, having detached anything it attached.

        `diagnose` only asks the desktop to explain itself; it changes no
        decision and, left off, causes no extra call at all.
        """
        owner = self.verify_owner(hwnd)
        if not owner.verified:
            return TargetRejected(owner.reason, owner.pid, owner.image_name)
        if not self._raise_window:
            # Asked *before* anything is attached or touched, because the whole
            # point is that this path never activates a window: if the client
            # is not already in front and visible, there is nothing here to do
            # but refuse.  Deliberately the same reading the activation gate
            # polls with — one definition of "the user is looking at it".
            ready = self.strict_foreground_check(hwnd)
            if not ready.ok:
                return TargetRejected(ready.reason, ready.pid, ready.image_name)
        focus = acquire_focus(hwnd, owner.pid, self._trusted, self._api,
                              diagnose=diagnose, raise_window=self._raise_window)
        self.last_focus_diagnostics = dict(focus.diagnostics)
        if not focus.ok:
            if focus.attached:
                try:
                    self._api.attach_thread_input(focus.our_tid, focus.their_tid,
                                                  False)
                except Exception:
                    pass
            return TargetRejected(focus.reason, owner.pid, owner.image_name,
                                  dict(focus.diagnostics))
        return VerifiedWindow(hwnd, owner.pid, owner.image_name, self._trusted,
                              self._api, focus.our_tid, focus.their_tid,
                              require_visible=self._require_visible)
