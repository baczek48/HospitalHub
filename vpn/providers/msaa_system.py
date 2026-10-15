"""MSAA read seam — what a window's accessibility tree says about its combo boxes.

Measured in Stage 61 on FortiClient VPN 7.4.3: the Electron window exposes
**nothing** of its form to UI Automation (16 elements, all window chrome), but
the same window answers MSAA (``AccessibleObjectFromWindow(hwnd, OBJID_CLIENT)``)
with the whole form — among it a ``ROLE_SYSTEM_COMBOBOX`` named ``VPN Name``
whose ``accValue`` is the profile on display.

This seam is deliberately narrow and **read-only**.  It walks one window's
client tree and reports the combo boxes it finds: role, name, ``accState``,
``accValue`` and the window the accessible object belongs to.  It never calls
``accDoDefaultAction``, ``accSelect`` or anything else that acts, it sends no
key and moves no focus, and it reads a value **only** from a node whose role is
a combo box — a text field's contents (a login, a password) are never asked
for.  Whether the window and its process are to be trusted is not decided
here: the caller verifies that through :class:`SecureWindowTarget`.

``comtypes`` / ``ctypes`` are imported lazily, as in the other seams, so
importing ``vpn`` pulls in nothing and the tests use a fake.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["MsaaSystem", "Win32MsaaSystem", "MsaaNode", "MsaaScan",
           "ensure_com_apartment",
           "ROLE_SYSTEM_COMBOBOX", "STATE_SYSTEM_FOCUSED",
           "STATE_SYSTEM_EXPANDED", "STATE_SYSTEM_COLLAPSED"]

ROLE_SYSTEM_COMBOBOX = 0x2E
STATE_SYSTEM_FOCUSED = 0x4
STATE_SYSTEM_EXPANDED = 0x200
STATE_SYSTEM_COLLAPSED = 0x400

_OBJID_CLIENT = -4
#: A ceiling on the walk: the measured form is a few hundred nodes at most, and
#: a tree that never ends must not keep the caller waiting.
_MAX_NODES = 5000
_MAX_DEPTH = 64


@dataclass(frozen=True)
class MsaaNode:
    """One combo box as MSAA reports it.  ``None`` = could not be read."""

    role: int | None
    name: str | None
    state: int | None
    #: ``accValue`` — read for combo boxes only.  Kept out of ``repr``: a
    #: profile name names a hospital and does not belong in a log.
    value: str | None = field(default=None, repr=False)
    #: ``WindowFromAccessibleObject`` — the HWND this object belongs to.
    window: int | None = None


@dataclass(frozen=True)
class MsaaScan:
    """The result of one walk.  ``ok=False`` means the tree was not readable."""

    ok: bool
    combos: tuple[MsaaNode, ...] = ()
    reason: str = ""
    #: The walk hit :data:`_MAX_NODES` or :data:`_MAX_DEPTH` before the end of
    #: the tree (Stage 63).  The combos found are then not *all* of them — a
    #: second ``VPN Name`` could be in the part never seen — so a caller that
    #: needs "exactly one" must treat this as unreadable.
    truncated: bool = False


def ensure_com_apartment(comtypes_module) -> None:
    """Initialise COM for the *calling* thread, if it is not already.

    ``comtypes`` calls ``CoInitializeEx`` once, in whichever thread first
    imports it.  The fills run in a fresh ``QThread`` per connect, so the
    second connect of a session ran without COM and every MSAA/UIA call failed
    — fail-closed, but every profile was refused until the app restarted
    (2026-10-14 audit, L3).

    The multithreaded apartment: it is what these reads measurably ran in
    without an explicit call (the implicit MTA), it is what UI Automation
    recommends for clients, and an object obtained in the MTA is not tied to
    one thread — it may be released later from any thread, including after
    this worker thread has ended (security review 64/N1: an STA object
    released from another thread after its apartment died is undefined
    behaviour).  Never uninitialised, for the same reason.  A thread already in
    a single-threaded apartment (``RPC_E_CHANGED_MODE``) is left as it is.
    """
    try:
        comtypes_module.CoInitializeEx(comtypes_module.COINIT_MULTITHREADED)
    except OSError:
        pass


class MsaaSystem:
    """Read the combo boxes of one window's MSAA client tree.  Nothing else."""

    def combo_boxes(self, hwnd) -> MsaaScan:
        raise NotImplementedError


class Win32MsaaSystem(MsaaSystem):
    """The real thing, over ``oleacc``.  Not exercised by the test suite."""

    def combo_boxes(self, hwnd) -> MsaaScan:
        try:
            import ctypes
            import comtypes
            import comtypes.client
            from comtypes.automation import VARIANT
            ensure_com_apartment(comtypes)
            oleacc = comtypes.client.GetModule("oleacc.dll")
            iface = oleacc.IAccessible
            lib = ctypes.oledll.oleacc
            root = ctypes.POINTER(iface)()
            lib.AccessibleObjectFromWindow(
                hwnd, _OBJID_CLIENT, ctypes.byref(iface._iid_), ctypes.byref(root))
        except Exception as exc:
            return MsaaScan(ok=False, reason=f"msaa-error:{type(exc).__name__}")
        if not root:
            return MsaaScan(ok=False, reason="msaa-no-root")

        self_id = VARIANT(0)

        def read(fn):
            try:
                return fn()
            except Exception:
                return None

        def children(acc):
            n = read(lambda: acc.accChildCount) or 0
            if n <= 0:
                return []
            arr = (VARIANT * n)()
            got = ctypes.c_long()
            try:
                lib.AccessibleChildren(acc, 0, n, arr, ctypes.byref(got))
            except Exception:
                return []
            out = []
            for v in arr[:got.value]:
                try:
                    out.append(v.value.QueryInterface(iface))
                except Exception:
                    continue           # a simple child id, not an object
            return out

        def owner_window(acc):
            h = ctypes.c_void_p()
            try:
                ctypes.windll.oleacc.WindowFromAccessibleObject(acc, ctypes.byref(h))
            except Exception:
                return None
            return h.value

        combos: list[MsaaNode] = []
        budget = [_MAX_NODES]
        cut = [False]

        def walk(acc, depth):
            if budget[0] <= 0 or depth > _MAX_DEPTH:
                cut[0] = True
                return
            budget[0] -= 1
            role = read(lambda: acc.accRole(self_id))
            if role == ROLE_SYSTEM_COMBOBOX:
                # The value is asked for here and only here — never of a text
                # field.
                combos.append(MsaaNode(
                    role=role,
                    name=read(lambda: acc.accName(self_id)),
                    state=read(lambda: acc.accState(self_id)),
                    value=read(lambda: acc.accValue(self_id)),
                    window=owner_window(acc)))
            for child in children(acc):
                walk(child, depth + 1)

        try:
            walk(root, 0)
        except Exception as exc:
            return MsaaScan(ok=False, reason=f"msaa-error:{type(exc).__name__}")
        return MsaaScan(ok=True, combos=tuple(combos), truncated=cut[0])
