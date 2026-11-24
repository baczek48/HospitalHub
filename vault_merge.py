"""Merging a colleague's copy of a vault into this one (2026-11-24, owner).

Pure functions on vault dicts (``models.to_dict`` / ``models.vpn_to_dict``
shape plus the ``"sync"`` section of :mod:`vault_sync`).  :func:`plan` lists
the differences with a proposal for each; the window shows them, the user
ticks; :func:`apply` builds the merged vault and its new sync section.

Matching: the same id first (copies of one vault share them), then — for
items both sides created on their own — hospital by name, machine by IP and
name, database by host and name, login by login, VPN profile by name.

Each difference gets a status and a default:

* ``new``           — only the colleague has it: added (ticked);
* ``removed_here``  — only the colleague has it, deleted in this copy: not
  added unless ticked;
* ``declined``      — offered before and not taken: not added unless ticked;
* ``removed_there`` — the colleague deleted it: deleted only when ticked
  (owner: deletions only as an option);
* ``update``        — the colleague's value is newer (this one is in the
  history): taken (ticked);
* ``conflict``      — both changed it, or nothing tells which is newer: kept
  as here unless ticked;
* ``joined``        — text both edited: this one plus the colleague's new
  lines (ticked; nothing of this copy is lost).

The colleague's *older* values (already replaced here) are not listed.

Admin-only items (owner): with admin unlocked they are listed like the rest;
locked, they are hidden and come over as in the colleague's file — added and
changed, except a value older than the one here; never deleted.
"""

from __future__ import annotations

import copy
import difflib
from dataclasses import dataclass, field

import vault_sync as vs
from vault_sync import Node

NEW, REMOVED_HERE, DECLINED, REMOVED_THERE = "new", "removed_here", "declined", "removed_there"
UPDATE, CONFLICT, JOINED = "update", "conflict", "joined"

STATUS_LABELS = {
    NEW: "nowe u kolegi",
    REMOVED_HERE: "usunięte u Ciebie",
    DECLINED: "wcześniej odrzucone",
    REMOVED_THERE: "usunięte u kolegi",
    UPDATE: "nowsze u kolegi",
    CONFLICT: "różni się",
    JOINED: "połączony tekst",
}

KIND_LABELS = {"hospital": "Szpital", "machine": "Maszyna", "database": "Baza",
               "credential": "Login", "vpn": "Profil VPN"}

FIELD_LABELS = {
    "name": "Nazwa", "notes": "Notatki", "amms_url": "AMMS – adres",
    "amms_login": "AMMS – login", "amms_password": "AMMS – hasło",
    "upgrade": "Plan aktualizacji", "si": "Serwer Integracji", "ip": "IP",
    "connection_type": "Typ połączenia", "description": "Opis", "rdp_port": "Port RDP",
    "rdp_drives": "Dyski RDP", "www_url": "Adres WWW", "admin_only": "Tylko admin",
    "host": "Host", "port": "Port", "db_type": "Typ bazy", "note": "Notatka",
    "login": "Login", "password": "Hasło", "provider": "Dostawca", "server": "Serwer",
    "group": "Grupa", "domain": "Domena", "profile_name": "Profil w kliencie",
    "requires_2fa": "Wymaga 2FA",
}


@dataclass
class Change:
    key: str                     # unique in the plan
    action: str                  # "field" | "add" | "delete"
    status: str
    kind: str
    item_id: str                 # id here (field/delete) or there (add)
    group: str                   # hospital name, or "Profile VPN"
    label: str                   # the item, e.g. "Maszyna srvAPP (10.0.0.5)"
    field: str = ""
    mine: object = None
    theirs: object = None
    proposed: object = None
    default: bool = False
    admin: bool = False
    hidden: bool = False         # admin item while admin is locked
    auto: bool = False           # what happens to a hidden one
    count: int = 1               # items an add/delete carries (with children)

    @property
    def secret(self) -> bool:
        return self.field in vs.SECRET_FIELDS


@dataclass
class Plan:
    mine: dict
    theirs: dict
    changes: list = field(default_factory=list)
    matched: dict = field(default_factory=dict)    # their id -> my id
    older_there: int = 0          # their values already replaced here
    only_here: int = 0            # my items the colleague does not have

    @property
    def visible(self):
        return [c for c in self.changes if not c.hidden]

    @property
    def hidden(self):
        return [c for c in self.changes if c.hidden]


# ── matching ───────────────────────────────────────────────────────────────

def _norm(text) -> str:
    return " ".join(str(text or "").split()).casefold()


def _fallback_key(node: Node):
    d = node.data
    if node.kind == "hospital":
        return _norm(d.get("name"))
    if node.kind == "machine":
        return (_norm(d.get("ip")), _norm(d.get("name")))
    if node.kind == "database":
        return (_norm(d.get("host")), _norm(d.get("name")))
    if node.kind == "credential":
        return _norm(d.get("login"))
    if node.kind == "vpn":
        return _norm(d.get("name"))
    return None


def match(mine: dict[str, Node], theirs: dict[str, Node]) -> dict[str, str]:
    """their id -> my id."""
    pairs = {tid: tid for tid, t in theirs.items()
             if tid in mine and mine[tid].kind == t.kind}
    used = set(pairs.values())
    for tid, t in theirs.items():                       # top-down order
        if tid in pairs:
            continue
        my_parent = pairs.get(t.parent) if t.parent else None
        if t.parent and my_parent is None:
            continue                                    # parent is new: comes whole
        key = _fallback_key(t)
        if not key or key == ("", ""):
            continue
        for mid, m in mine.items():
            if (mid not in used and m.kind == t.kind and m.parent == my_parent
                    and m.list_key == t.list_key and _fallback_key(m) == key):
                pairs[tid] = mid
                used.add(mid)
                break
    return pairs


# ── text ───────────────────────────────────────────────────────────────────

def join_text(mine: str, theirs: str) -> str:
    """Mine with the colleague's lines that mine lacks, each where it stood."""
    a, b = (mine or "").splitlines(), (theirs or "").splitlines()
    out = []
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(None, a, b, autojunk=False).get_opcodes():
        out += a[i1:i2]
        if op in ("insert", "replace"):
            out += b[j1:j2]
    return "\n".join(out)


# ── labels ─────────────────────────────────────────────────────────────────

def item_label(node: Node) -> str:
    d = node.data
    k = KIND_LABELS.get(node.kind, node.kind)
    if node.kind == "hospital":
        return d.get("name") or "(bez nazwy)"
    if node.kind == "machine":
        name, ip = d.get("name") or "", d.get("ip") or ""
        return f"{k} {name} ({ip})" if name and ip else f"{k} {name or ip}"
    if node.kind == "database":
        return f"{k} {d.get('name') or ''} ({d.get('host') or ''})".replace(" ()", "")
    if node.kind == "credential":
        return f"{k} {d.get('login') or '(pusty)'}"
    return f"{k} {d.get('name') or ''}"


def _group(nodes: dict[str, Node], node: Node) -> str:
    if node.kind == "vpn":
        return "Profile VPN"
    while node.parent is not None:
        node = nodes[node.parent]
    return node.data.get("name") or "(bez nazwy)"


def _path_label(nodes: dict[str, Node], node: Node) -> str:
    """The item under its hospital: "Maszyna srvAPP (10.0.0.5) › Login root"."""
    parts = []
    while node is not None and node.kind != "hospital":
        parts.append(item_label(node))
        node = nodes.get(node.parent) if node.parent else None
    if not parts:
        return "Dane szpitala"            # the group row already names it
    return " › ".join(reversed(parts))


def _subtree_size(nodes, node, skip=frozenset()) -> int:
    return 1 + sum(_subtree_size(nodes, nodes[c], skip) for c in node.children
                   if c not in skip)


# ── the plan ───────────────────────────────────────────────────────────────

def plan(mine: dict, theirs: dict, *, show_admin: bool = False) -> Plan:
    m_nodes, t_nodes = vs.flatten(mine), vs.flatten(theirs)
    m_sync = vs.normalized(mine.get(vs.SYNC_KEY))
    t_sync = vs.normalized(theirs.get(vs.SYNC_KEY))
    pairs = match(m_nodes, t_nodes)
    mine_of = pairs
    theirs_of = {mid: tid for tid, mid in pairs.items()}
    result = Plan(mine, theirs, matched=pairs)

    def seen(mid, tid, name):
        out = set(m_sync["seen"].get(f"{mid}.{name}", []))
        out |= set(t_sync["seen"].get(f"{mid}.{name}", []))
        if tid != mid:
            out |= set(m_sync["seen"].get(f"{tid}.{name}", []))
            out |= set(t_sync["seen"].get(f"{tid}.{name}", []))
        return out

    def hide(admin):
        return admin and not show_admin

    # Fields of matched items.
    for tid, mid in pairs.items():
        t, m = t_nodes[tid], m_nodes[mid]
        admin = m.admin or t.admin
        for name in vs.SPEC[m.kind]["fields"]:
            if (m.kind, name) in vs.LOCAL_FIELDS:
                continue
            a, b = vs.field_value(m, name), vs.field_value(t, name)
            if a == b:
                continue
            ha, hb = vs.value_hash(a), vs.value_hash(b)
            known_old = seen(mid, tid, name)
            theirs_old = hb in known_old or hb in m_sync["kept"].get(f"{mid}.{name}", [])
            mine_old = ha in known_old
            if theirs_old and not mine_old:
                result.older_there += 1
                continue
            text = (m.kind, name) in vs.TEXT_FIELDS
            if mine_old and not theirs_old:
                status, proposed, default = UPDATE, b, True
            elif text:
                joined = join_text(a, b)
                if joined == a:              # theirs adds nothing: shorter/older
                    status, proposed, default = CONFLICT, b, False
                elif joined == b:            # theirs = mine + more lines
                    status, proposed, default = UPDATE, b, True
                else:
                    status, proposed, default = JOINED, joined, True
            else:
                status, proposed, default = CONFLICT, b, False
            ch = Change(key=f"f:{mid}:{name}", action="field", status=status, kind=m.kind,
                        item_id=mid, group=_group(m_nodes, m), label=_path_label(m_nodes, m),
                        field=name, mine=a, theirs=b, proposed=proposed, default=default,
                        admin=admin, hidden=hide(admin))
            if ch.hidden:
                # As in the colleague's file — the whole value, not a join.
                ch.auto, ch.proposed = True, b
            result.changes.append(ch)

    # Their items I do not have.
    for tid, t in t_nodes.items():
        if tid in pairs:
            continue
        if t.parent is not None and t.parent not in pairs:
            continue                                     # inside a new parent
        if tid in m_sync["gone"]:
            status, default = REMOVED_HERE, False
        elif tid in m_sync["declined"]:
            status, default = DECLINED, False
        else:
            status, default = NEW, True
        parent = m_nodes[pairs[t.parent]] if t.parent else None
        group = _group(m_nodes, parent) if parent else _group(t_nodes, t)
        label = (_path_label(m_nodes, parent) + " › " if parent and parent.kind != "hospital"
                 else "") + item_label(t)
        ch = Change(key=f"a:{tid}", action="add", status=status, kind=t.kind, item_id=tid,
                    group=group, label=label, theirs=t.data, default=default,
                    admin=t.admin, hidden=hide(t.admin),
                    count=_subtree_size(t_nodes, t, skip=set(pairs)))
        if ch.hidden:
            ch.auto = True
        result.changes.append(ch)

    # My items the colleague does not have.
    for mid, m in m_nodes.items():
        if mid in theirs_of:
            continue
        if m.parent is not None and m.parent not in theirs_of:
            continue
        if mid in t_sync["gone"]:
            ch = Change(key=f"d:{mid}", action="delete", status=REMOVED_THERE, kind=m.kind,
                        item_id=mid, group=_group(m_nodes, m),
                        label=_path_label(m_nodes, m), mine=m.data, default=False,
                        admin=m.admin, hidden=hide(m.admin),
                        count=_subtree_size(m_nodes, m))
            result.changes.append(ch)              # hidden: never auto-deleted
        else:
            result.only_here += _subtree_size(m_nodes, m)
    return result


# ── applying ───────────────────────────────────────────────────────────────

def _strip_matched(item: dict, kind: str, matched_theirs: set) -> dict:
    """A copy of their item without the children that already exist here."""
    item = copy.deepcopy(item)
    for child_key, child_kind in vs.SPEC[kind]["children"]:
        item[child_key] = [_strip_matched(c, child_kind, matched_theirs)
                           for c in item.get(child_key) or []
                           if str(c.get("id")) not in matched_theirs]
    for k, name in vs.LOCAL_FIELDS:
        if k == kind:
            item[name] = ""
    return item


def apply(p: Plan, chosen: set) -> tuple[dict, dict]:
    """(merged vault dict, its sync section).  `chosen`: keys of the visible
    changes the user ticked; hidden ones follow their ``auto``."""
    result = {k: copy.deepcopy(v) for k, v in p.mine.items() if k in vs.TOP}
    nodes = vs.flatten(result)
    t_nodes = vs.flatten(p.theirs)
    m_sync = vs.normalized(p.mine.get(vs.SYNC_KEY))
    t_sync = vs.normalized(p.theirs.get(vs.SYNC_KEY))
    sync = vs.normalized(m_sync)
    for key, hashes in t_sync["seen"].items():
        merged = list(dict.fromkeys(sync["seen"].get(key, []) + hashes))
        sync["seen"][key] = merged[-vs._CAP_SEEN:]
    sync["gone"] = list(dict.fromkeys(m_sync["gone"] + t_sync["gone"]))

    def take(ch: Change) -> bool:
        return ch.auto if ch.hidden else ch.key in chosen

    # their id -> where it is in the result (matched, or added below)
    where = dict(p.matched)
    matched_theirs = set(p.matched)

    for ch in p.changes:
        if ch.action == "field":
            if take(ch):
                nodes[ch.item_id].data[ch.field] = copy.deepcopy(ch.proposed)
            else:
                key = f"{ch.item_id}.{ch.field}"
                kept = sync["kept"].setdefault(key, [])
                h = vs.value_hash(ch.theirs)
                if h not in kept:
                    kept.append(h)
                sync["kept"][key] = kept[-vs._CAP_SEEN:]

    # Additions in their order, each after its nearest earlier sibling.
    for ch in p.changes:
        if ch.action != "add":
            continue
        if not take(ch):
            if ch.status == NEW:
                sync["declined"].append(ch.item_id)
            continue
        t = t_nodes[ch.item_id]
        if t.parent is None:
            siblings = result.setdefault(t.list_key, [])
        else:
            siblings = nodes[where[t.parent]].data.setdefault(t.list_key, [])
        pos = 0
        their_list = (p.theirs.get(t.list_key) if t.parent is None
                      else t_nodes[t.parent].data.get(t.list_key)) or []
        before = [str(x.get("id")) for x in their_list[:t.order]]
        ids_here = [str(x.get("id")) for x in siblings]
        for prev in reversed(before):
            here = where.get(prev)
            if here in ids_here:
                pos = ids_here.index(here) + 1
                break
        item = _strip_matched(t.data, t.kind, matched_theirs)
        siblings.insert(pos, item)
        where[t.id] = t.id
        nodes = vs.flatten(result)

    for ch in p.changes:
        if ch.action == "delete" and take(ch):
            node = nodes.get(ch.item_id)
            if node is None:
                continue
            holder = (result.get(node.list_key) if node.parent is None
                      else nodes[node.parent].data.get(node.list_key))
            holder[:] = [x for x in holder if str(x.get("id")) != ch.item_id]
            nodes = vs.flatten(result)

    present = set(vs.flatten(result))
    sync["gone"] = [i for i in sync["gone"] if i not in present][-vs._CAP_IDS:]
    sync["declined"] = [i for i in dict.fromkeys(sync["declined"])
                        if i not in present][-vs._CAP_IDS:]
    return result, sync


def summary(p: Plan, chosen: set) -> dict:
    """What apply() would do, counted for the message after the merge."""
    counts = {"added": 0, "changed": 0, "deleted": 0, "kept": 0, "admin_auto": 0}
    for ch in p.changes:
        took = ch.auto if ch.hidden else ch.key in chosen
        if ch.hidden and took:
            counts["admin_auto"] += 1
        if ch.action == "field":
            counts["changed" if took else "kept"] += 1
        elif ch.action == "add" and took:
            counts["added"] += ch.count
        elif ch.action == "delete" and took:
            counts["deleted"] += ch.count
    return counts


# ── into the window's objects ──────────────────────────────────────────────

def update_in_place(objects: list, merged: list) -> list:
    """Make `objects` (the window's models) equal to `merged` (fresh models
    of the merged vault), keeping every object that already existed — panels
    and open windows hold references to hospitals, machines and profiles."""
    import dataclasses

    def is_model_list(value) -> bool:
        return isinstance(value, list) and bool(value) and dataclasses.is_dataclass(value[0])

    by_id = {getattr(o, "id", None): o for o in objects}
    out = []
    for new in merged:
        old = by_id.get(getattr(new, "id", None))
        if old is None or type(old) is not type(new):
            out.append(new)
            continue
        for f in dataclasses.fields(new):
            value, current = getattr(new, f.name), getattr(old, f.name)
            if is_model_list(value) or is_model_list(current):
                update_in_place(current, value)
            else:
                setattr(old, f.name, value)
        out.append(old)
    objects[:] = out
    return objects
