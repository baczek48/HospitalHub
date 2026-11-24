"""What a vault remembers about its own past, so two copies can be merged.

2026-11-24 (owner): the team keeps copies of one vault and passes them
around.  To merge a colleague's copy without asking about every difference,
each vault keeps a small ``"sync"`` section (inside the encrypted file):

* ``seen``  — ``"<id>.<field>"`` → short hashes of values that field *had*
  and that were replaced.  A value found there is older than the one now in
  the field — in this copy or, once the section travelled, in the other one.
* ``gone``  — ids of items deleted in this copy.
* ``kept``  — ``"<id>.<field>"`` → hashes of a colleague's values this user
  chose not to take ("keep mine"); local to this copy's decisions.
* ``declined`` — ids of a colleague's new items this user chose not to add.

Only hashes, never values: the section adds no copy of a password.  An older
HospitalHub saving the vault drops the section — merges then simply ask more.

The section is recorded on every save (:func:`record`): the window keeps the
dict it last loaded or saved and compares it with the one being saved.
"""

from __future__ import annotations

import copy
import hashlib
import json
import os
from dataclasses import dataclass, field

SYNC_KEY = "sync"
VERSION = 1

#: How the two vault kinds are built: list key, fields compared, children.
SPEC = {
    "hospital": {"fields": ("name", "notes", "amms_url", "amms_login", "amms_password",
                            "upgrade", "si"),
                 "children": (("machines", "machine"), ("databases", "database"))},
    "machine": {"fields": ("name", "ip", "connection_type", "description", "rdp_port",
                           "rdp_drives", "www_url", "admin_only"),
                "children": (("credentials", "credential"),)},
    "database": {"fields": ("name", "host", "port", "db_type", "note", "admin_only"),
                 "children": (("credentials", "credential"),)},
    "credential": {"fields": ("login", "password", "note", "admin_only"), "children": ()},
    "vpn": {"fields": ("name", "provider", "server", "port", "login", "password", "group",
                       "domain", "notes", "profile_name", "requires_2fa", "amms_url",
                       "amms_login", "amms_password", "app_path"),
            "children": ()},
}
TOP = {"hospitals": "hospital", "vpn_profiles": "vpn"}
#: Fields describing this computer, not the shared data: never taken from a
#: colleague (the path to the VPN client on *their* disk).
LOCAL_FIELDS = {("vpn", "app_path")}
#: Multi-line text: two versions can be joined line by line.
TEXT_FIELDS = {("hospital", "notes"), ("machine", "description"), ("database", "note"),
               ("credential", "note"), ("vpn", "notes")}
SECRET_FIELDS = {"password", "amms_password"}

_CAP_SEEN = 20
_CAP_IDS = 5000


def value_hash(value) -> str:
    text = json.dumps(value, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(("hh-sync:" + text).encode("utf-8")).hexdigest()[:16]


def empty() -> dict:
    return {"v": VERSION, "seen": {}, "gone": [], "kept": {}, "declined": []}


def normalized(sync) -> dict:
    """A well-formed section whatever the file held (missing, older, broken)."""
    out = empty()
    if not isinstance(sync, dict):
        return out
    for key in ("seen", "kept"):
        src = sync.get(key)
        if isinstance(src, dict):
            out[key] = {str(k): [str(h) for h in v][-_CAP_SEEN:]
                        for k, v in src.items() if isinstance(v, list)}
    for key in ("gone", "declined"):
        src = sync.get(key)
        if isinstance(src, list):
            out[key] = [str(i) for i in src][-_CAP_IDS:]
    return out


@dataclass
class Node:
    kind: str
    id: str
    data: dict                       # the item's dict (children included)
    parent: str | None               # parent id, None at the top
    list_key: str                    # the key of the list holding it
    admin: bool                      # admin_only here or in a parent
    order: int = 0
    children: list = field(default_factory=list)


def flatten(vault: dict) -> dict[str, Node]:
    """Every item of a vault dict by id, top-down (dict order = tree order)."""
    nodes: dict[str, Node] = {}

    def walk(items, kind, list_key, parent, parent_admin):
        for i, item in enumerate(items or []):
            if not isinstance(item, dict):
                continue
            iid = str(item.get("id") or "")
            if not iid or iid in nodes:
                continue
            admin = parent_admin or bool(item.get("admin_only"))
            node = Node(kind, iid, item, parent, list_key, admin, i)
            nodes[iid] = node
            if parent is not None:
                nodes[parent].children.append(iid)
            for child_key, child_kind in SPEC[kind]["children"]:
                walk(item.get(child_key), child_kind, child_key, iid, admin)

    for list_key, kind in TOP.items():
        walk(vault.get(list_key), kind, list_key, None, False)
    return nodes


def field_value(node: Node, name: str):
    value = node.data.get(name)
    if name == "admin_only" or name == "requires_2fa":
        return bool(value)
    if value is None:
        return {} if name in ("upgrade", "si") else ([] if name == "rdp_drives" else "")
    return value


def plain(vault: dict) -> dict:
    """A deep, JSON-clean copy (the window's snapshot of what is on disk)."""
    clean = {k: v for k, v in vault.items() if k in TOP}
    return json.loads(json.dumps(clean, ensure_ascii=False, default=str))


def record(sync, before: dict, after: dict) -> dict:
    """The section after saving `after` over `before` (both vault dicts)."""
    out = normalized(sync)
    old, new = flatten(before), flatten(after)
    for iid, node in new.items():
        prev = old.get(iid)
        if prev is None:
            continue
        for name in SPEC[node.kind]["fields"]:
            a, b = field_value(prev, name), field_value(node, name)
            if a == b:
                continue
            key = f"{iid}.{name}"
            hashes = [h for h in out["seen"].get(key, []) if h != value_hash(b)]
            ha = value_hash(a)
            if ha not in hashes:
                hashes.append(ha)
            out["seen"][key] = hashes[-_CAP_SEEN:]
    gone = [i for i in out["gone"] if i not in new]
    gone += [i for i in old if i not in new and i not in gone]
    out["gone"] = gone[-_CAP_IDS:]
    return out


# ── what the open windows loaded ──────────────────────────────────────────
# The login dialogs decrypt the file and hand the window only the items; the
# section is noted here on the way, by path, and taken by the window.

_loaded: dict[str, dict] = {}


def _key(path: str) -> str:
    return os.path.normcase(os.path.abspath(path or ""))


def note_loaded(path: str, data) -> None:
    if path and isinstance(data, dict):
        _loaded[_key(path)] = normalized(data.get(SYNC_KEY))


def take_loaded(path: str) -> dict:
    return copy.deepcopy(_loaded.pop(_key(path), None) or empty())
