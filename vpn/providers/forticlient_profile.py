"""Which VPN profile does the FortiClient window show?  Read, never chosen.

Stage 62.  Stage 60 asked UI Automation which control had the focus and read
the profile from it; Stage 61 measured that FortiClient VPN 7.4.3 shows UI
Automation nothing of its form, so that question can never be answered there.
MSAA can answer it (see :mod:`msaa_system`), and this module is the layer that
turns that answer into a decision — still without touching the window.

Two halves, both fail-closed:

**Reading the control** — :func:`read_profile_control`.

* The window comes from :meth:`SecureWindowTarget.first_verified_candidate`
  (or is re-verified when the caller passes one): HWND → PID → image in a
  trusted FortiClient directory.  That is a read; no focus is taken.
* Among the window's MSAA combo boxes exactly one may be named ``VPN Name``.
  None, or more than one, is a refusal — not a guess at which one is meant.
* The accessible object must belong to that same verified window
  (``WindowFromAccessibleObject``), and that window must still verify to the
  same process.
* ``accState`` and ``accValue`` must both be readable.

**Matching the profile** — :func:`match_profile`.

``accValue`` is not the profile name: on 7.4.3 it reads ``"Personal VPNs
<name>"`` — the list's group label, a space, the tunnel name.  The label is
recognised only from :data:`GROUP_LABELS`, which lists what has been
*measured*, and each label says which kind of tunnel it heads.  The rest of
the value must then equal, character for character, the name of a tunnel of
that kind configured in the registry, and the requested profile.  No prefix,
no substring, no case folding, no trimming: anything else is a refusal.
IPsec and EMS-managed profiles are not assumed to look the same — their
labels have not been measured, so a value under them is an unknown format.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from .msaa_system import (
    ROLE_SYSTEM_COMBOBOX, STATE_SYSTEM_COLLAPSED, STATE_SYSTEM_EXPANDED,
    STATE_SYSTEM_FOCUSED, MsaaSystem,
)

__all__ = ["PROFILE_CONTROL_NAME", "GROUP_LABELS", "TUNNEL_KIND_SSL",
           "TUNNEL_KIND_IPSEC", "SSL_TUNNELS_KEY", "IPSEC_TUNNELS_KEY",
           "TunnelCatalog", "ProfileControlReading", "ProfileMatch",
           "configured_tunnels", "read_profile_control", "match_profile",
           "requested_profile_selectable", "sole_tunnel",
           "verify_displayed_profile"]

#: ``accName`` of the profile combo, as measured on 7.4.3 (Stage 61).  The
#: client's UI was Polish there and the name was still English.
PROFILE_CONTROL_NAME = "VPN Name"

TUNNEL_KIND_SSL = "ssl"
TUNNEL_KIND_IPSEC = "ipsec"

SSL_TUNNELS_KEY = r"SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels"
IPSEC_TUNNELS_KEY = r"SOFTWARE\Fortinet\FortiClient\IPSec\Tunnels"

#: Group labels that have been seen in ``accValue``, and the kind of tunnel
#: each one heads.  Only measured entries belong here — adding one is a
#: decision with a live reading behind it, not a convenience.
#:
#: * ``Personal VPNs`` → SSL-VPN: FortiClient VPN 7.4.3.4726 (Free), Stage 61,
#:   ``accValue == "Personal VPNs <name>"`` with ``<name>`` a key under
#:   ``Sslvpn\Tunnels``.
GROUP_LABELS: dict[str, str] = {
    "Personal VPNs": TUNNEL_KIND_SSL,
}

# Reason codes.  Codes only — never the value, never the profile name.
REASON_NO_WINDOW = "no-verified-window"
REASON_WINDOW_UNTRUSTED = "window-untrusted"
REASON_MSAA_UNAVAILABLE = "msaa-unavailable"
REASON_SCAN_TRUNCATED = "msaa-scan-truncated"
REASON_CONTROL_MISSING = "profile-control-missing"
REASON_CONTROL_AMBIGUOUS = "profile-control-ambiguous"
REASON_FOREIGN_WINDOW = "profile-control-foreign-window"
REASON_FOREIGN_PROCESS = "profile-control-foreign-process"
REASON_STATE_UNREADABLE = "profile-state-unreadable"
REASON_VALUE_UNREADABLE = "profile-value-unreadable"
REASON_REQUEST_EMPTY = "requested-profile-empty"
REASON_REQUEST_UNTRIMMED = "requested-profile-untrimmed"
REASON_REQUEST_NOT_CONFIGURED = "requested-tunnel-not-configured"
REASON_LABEL_COLLISION = "tunnel-name-collides-with-group-label"
REASON_CATALOG_UNAVAILABLE = "tunnel-catalog-unavailable"
REASON_UNKNOWN_GROUP = "unknown-group-label"
REASON_AMBIGUOUS_GROUP = "ambiguous-group-label"
REASON_EMPTY_NAME = "displayed-profile-empty"
REASON_TUNNEL_NOT_CONFIGURED = "tunnel-not-configured"
REASON_AMBIGUOUS_TUNNEL = "ambiguous-tunnel-kind"
REASON_MISMATCH = "profile-mismatch"
REASON_MATCHED = "matched"


@dataclass(frozen=True)
class TunnelCatalog:
    """Tunnel names configured in FortiClient, per kind (registry key names)."""

    ssl: tuple[str, ...] = ()
    ipsec: tuple[str, ...] = ()

    @property
    def empty(self) -> bool:
        return not self.ssl and not self.ipsec

    def of_kind(self, kind: str) -> tuple[str, ...]:
        return {TUNNEL_KIND_SSL: self.ssl, TUNNEL_KIND_IPSEC: self.ipsec}.get(kind, ())


def configured_tunnels(environment) -> TunnelCatalog:
    """Read the tunnel names — key names only, never a value under them.

    The keys hold more than names (server, user, saved credentials); only the
    subkey names are listed.  `environment` is the provider's
    :class:`DetectionEnvironment`, so a test passes a description of a machine.
    """
    def names(key):
        try:
            return tuple(n for n in environment.registry_subkeys(key) if n)
        except Exception:
            return ()
    return TunnelCatalog(ssl=names(SSL_TUNNELS_KEY), ipsec=names(IPSEC_TUNNELS_KEY))


@dataclass(frozen=True)
class ProfileControlReading:
    """What the profile combo shows, or why it could not be read."""

    ok: bool
    reason: str
    hwnd: int | None = None
    pid: int | None = None
    state: int | None = None
    value: str | None = field(default=None, repr=False)

    @property
    def focused(self) -> bool:
        return self.state is not None and bool(self.state & STATE_SYSTEM_FOCUSED)

    @property
    def expanded(self) -> bool:
        return self.state is not None and bool(self.state & STATE_SYSTEM_EXPANDED)

    @property
    def collapsed(self) -> bool:
        return self.state is not None and bool(self.state & STATE_SYSTEM_COLLAPSED)


@dataclass(frozen=True)
class ProfileMatch:
    """Whether the displayed value is exactly the requested tunnel."""

    matched: bool
    reason: str
    group_label: str | None = None
    tunnel_kind: str | None = None


def read_profile_control(target, msaa: MsaaSystem, *, hwnd=None) -> ProfileControlReading:
    """Read the ``VPN Name`` combo of the verified FortiClient window.

    `target` is a :class:`SecureWindowTarget`; without `hwnd` its first
    verified candidate is used, with `hwnd` that window is verified afresh.
    Neither takes focus.  Read-only from end to end.
    """
    if hwnd is None:
        hit = target.first_verified_candidate()
        if hit is None:
            return ProfileControlReading(False, REASON_NO_WINDOW)
        hwnd, owner = hit
    else:
        owner = target.verify_owner(hwnd)
        if not owner.verified:
            return ProfileControlReading(False, REASON_WINDOW_UNTRUSTED, hwnd=hwnd)
    pid = owner.pid

    try:
        scan = msaa.combo_boxes(hwnd)
    except Exception:
        return ProfileControlReading(False, REASON_MSAA_UNAVAILABLE, hwnd=hwnd, pid=pid)
    if not scan.ok:
        return ProfileControlReading(False, REASON_MSAA_UNAVAILABLE, hwnd=hwnd, pid=pid)
    # A walk cut short saw only part of the window: "exactly one VPN Name"
    # cannot be answered from it (Stage 63).
    if getattr(scan, "truncated", False):
        return ProfileControlReading(False, REASON_SCAN_TRUNCATED, hwnd=hwnd, pid=pid)

    named = [n for n in scan.combos
             if n.role == ROLE_SYSTEM_COMBOBOX and n.name == PROFILE_CONTROL_NAME]
    if not named:
        return ProfileControlReading(False, REASON_CONTROL_MISSING, hwnd=hwnd, pid=pid)
    if len(named) > 1:
        return ProfileControlReading(False, REASON_CONTROL_AMBIGUOUS, hwnd=hwnd, pid=pid)
    node = named[0]

    # The accessible object has to live in the window that was verified, and
    # that window has to verify — now — to the same process.
    if node.window is None or node.window != hwnd:
        return ProfileControlReading(False, REASON_FOREIGN_WINDOW, hwnd=hwnd, pid=pid)
    again = target.verify_owner(node.window)
    if not again.verified or pid is None or again.pid != pid:
        return ProfileControlReading(False, REASON_FOREIGN_PROCESS, hwnd=hwnd, pid=pid)

    if not isinstance(node.state, int) or isinstance(node.state, bool):
        return ProfileControlReading(False, REASON_STATE_UNREADABLE, hwnd=hwnd, pid=pid)
    if not isinstance(node.value, str) or not node.value:
        return ProfileControlReading(False, REASON_VALUE_UNREADABLE, hwnd=hwnd, pid=pid,
                                     state=node.state)
    return ProfileControlReading(True, "read", hwnd=hwnd, pid=pid,
                                 state=node.state, value=node.value)


def match_profile(displayed: str | None, requested: str | None,
                  catalog: TunnelCatalog) -> ProfileMatch:
    """Is `displayed` (an ``accValue``) exactly the `requested` tunnel?

    ``"<label> <name>"`` with ``<label>`` from :data:`GROUP_LABELS` and
    ``<name>`` a tunnel of that label's kind, equal to `requested`.  Nothing is
    trimmed or folded.
    """
    if not isinstance(displayed, str) or not displayed:
        return ProfileMatch(False, REASON_VALUE_UNREADABLE)
    if not isinstance(requested, str) or not requested.strip():
        return ProfileMatch(False, REASON_REQUEST_EMPTY)
    if catalog.empty:
        return ProfileMatch(False, REASON_CATALOG_UNAVAILABLE)

    parsed = [(label, displayed[len(label) + 1:]) for label in GROUP_LABELS
              if displayed.startswith(label + " ")]
    if not parsed:
        return ProfileMatch(False, REASON_UNKNOWN_GROUP)
    if len(parsed) > 1:
        return ProfileMatch(False, REASON_AMBIGUOUS_GROUP)
    label, name = parsed[0]
    kind = GROUP_LABELS[label]
    if not name.strip():
        return ProfileMatch(False, REASON_EMPTY_NAME, group_label=label, tunnel_kind=kind)

    if name not in catalog.of_kind(kind):
        return ProfileMatch(False, REASON_TUNNEL_NOT_CONFIGURED,
                            group_label=label, tunnel_kind=kind)
    # The label was measured over one kind only.  A name configured under
    # another kind as well could be either; refusing costs nothing.
    others = [k for k in (TUNNEL_KIND_SSL, TUNNEL_KIND_IPSEC)
              if k != kind and name in catalog.of_kind(k)]
    if others:
        return ProfileMatch(False, REASON_AMBIGUOUS_TUNNEL,
                            group_label=label, tunnel_kind=kind)
    if name != requested:
        return ProfileMatch(False, REASON_MISMATCH, group_label=label, tunnel_kind=kind)
    return ProfileMatch(True, REASON_MATCHED, group_label=label, tunnel_kind=kind)


def requested_profile_selectable(requested: str | None,
                                 catalog: TunnelCatalog) -> ProfileMatch:
    """Could `requested` ever be confirmed by :func:`match_profile`?

    Asked before the first key of the profile step (Stage 63), so a name that
    is not a configured tunnel is refused *before* type-ahead gets the chance
    to pick something merely similar and Enter commits it.  The same rules as
    the match, applied to the request instead of to the display:

    * not empty and not padded — the string typed is the string matched, and
      neither side is trimmed;
    * a tunnel of exactly one kind, and that kind headed by a measured label;
    * no configured tunnel name begins with a label and a space — such a name
      would make ``"<label> <name>"`` parse two ways.
    """
    if not isinstance(requested, str) or not requested.strip():
        return ProfileMatch(False, REASON_REQUEST_EMPTY)
    if requested != requested.strip():
        return ProfileMatch(False, REASON_REQUEST_UNTRIMMED)
    if catalog.empty:
        return ProfileMatch(False, REASON_CATALOG_UNAVAILABLE)
    every = catalog.ssl + catalog.ipsec
    if any(n.startswith(label + " ") for n in every for label in GROUP_LABELS):
        return ProfileMatch(False, REASON_LABEL_COLLISION)
    kinds = [k for k in (TUNNEL_KIND_SSL, TUNNEL_KIND_IPSEC)
             if requested in catalog.of_kind(k)]
    if not kinds:
        return ProfileMatch(False, REASON_REQUEST_NOT_CONFIGURED)
    if len(kinds) > 1:
        return ProfileMatch(False, REASON_AMBIGUOUS_TUNNEL)
    labels = [label for label, kind in GROUP_LABELS.items() if kind == kinds[0]]
    if len(labels) != 1:
        # A kind whose label has not been measured can never be confirmed.
        return ProfileMatch(False, REASON_UNKNOWN_GROUP, tunnel_kind=kinds[0])
    return ProfileMatch(True, REASON_MATCHED, group_label=labels[0],
                        tunnel_kind=kinds[0])


def sole_tunnel(catalog: TunnelCatalog) -> str | None:
    """The one configured tunnel, when the catalog holds exactly one tunnel
    in all, of a kind headed by a measured label; otherwise ``None``.

    Used when a request names no profile (2026-10-14): only then is the
    target unambiguous.
    """
    every = catalog.ssl + catalog.ipsec
    if len(every) != 1:
        return None
    measured = set(GROUP_LABELS.values())
    for kind in (TUNNEL_KIND_SSL, TUNNEL_KIND_IPSEC):
        if every[0] in catalog.of_kind(kind):
            return every[0] if kind in measured else None
    return None


def verify_displayed_profile(target, msaa: MsaaSystem, catalog: TunnelCatalog,
                             requested: str, *, hwnd=None
                             ) -> tuple[ProfileControlReading, ProfileMatch]:
    """Read the combo and match it.  ``match.matched`` is the only yes."""
    reading = read_profile_control(target, msaa, hwnd=hwnd)
    if not reading.ok:
        return reading, ProfileMatch(False, reading.reason)
    return reading, match_profile(reading.value, requested, catalog)
