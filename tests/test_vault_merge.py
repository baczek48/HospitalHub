"""2026-11-24 (owner): the team keeps copies of one vault; instead of
replacing mine with a colleague's, merge it — new data comes in, my own
changes, notes and logins stay, deletions only when ticked, admin items
visible only with the admin password (otherwise as in the colleague's file).

All names, hosts and addresses here are made up (TEST-NET, .example)."""

import copy
import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
for _p in (_PARENT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import models  # noqa: E402
import vault_merge as vm  # noqa: E402
import vault_sync as vs  # noqa: E402


def base_vault() -> dict:
    return {"hospitals": [
        {"id": "h1", "name": "Szpital Alfa", "notes": "VPN przez bramkę\nDyżur: 112",
         "machines": [
             {"id": "m1", "ip": "192.0.2.10", "name": "srvAPP", "description": "",
              "connection_type": "SSH", "rdp_port": "3389", "rdp_drives": [],
              "www_url": "", "admin_only": False,
              "credentials": [{"id": "c1", "login": "root", "password": "stare",
                               "note": "", "admin_only": False}]},
             {"id": "m2", "ip": "192.0.2.11", "name": "srvDB", "description": "",
              "connection_type": "SSH", "rdp_port": "3389", "rdp_drives": [],
              "www_url": "", "admin_only": True,
              "credentials": [{"id": "c2", "login": "oracle", "password": "tajne",
                               "note": "", "admin_only": False}]},
         ],
         "databases": [], "amms_url": "", "amms_login": "", "amms_password": ""},
        {"id": "h2", "name": "Szpital Beta", "notes": "", "machines": [], "databases": [],
         "amms_url": "", "amms_login": "", "amms_password": ""},
    ]}


def saved(before: dict, after: dict, sync=None) -> dict:
    """`after` as the window saves it over `before`: with its sync section."""
    out = copy.deepcopy(after)
    out[vs.SYNC_KEY] = vs.record(sync, vs.plain(before), vs.plain(after))
    return out


def machine(v, mid):
    return next(n.data for n in vs.flatten(v).values() if n.id == mid)


def by_key(plan, key):
    return next(c for c in plan.changes if c.key == key)


def merge(mine, theirs, *, take=None, show_admin=True):
    p = vm.plan(mine, theirs, show_admin=show_admin)
    chosen = {c.key for c in p.visible if c.default} if take is None else set(take)
    return p, vm.apply(p, chosen)


# ── the history ────────────────────────────────────────────────────────────

def test_saving_remembers_replaced_values_and_deleted_items():
    a = base_vault()
    b = copy.deepcopy(a)
    machine(b, "c1")["password"] = "nowe"
    b["hospitals"][1]["machines"] = []
    del b["hospitals"][0]["machines"][1]                       # m2 + c2 deleted
    sync = vs.record(None, vs.plain(a), vs.plain(b))
    assert sync["seen"]["c1.password"] == [vs.value_hash("stare")]
    assert set(sync["gone"]) == {"m2", "c2"}
    assert "stare" not in str(sync) and "nowe" not in str(sync), "tylko skróty"


def test_a_value_set_again_is_no_longer_old():
    a = base_vault()
    b = copy.deepcopy(a)
    machine(b, "c1")["password"] = "nowe"
    s1 = vs.record(None, vs.plain(a), vs.plain(b))
    s2 = vs.record(s1, vs.plain(b), vs.plain(a))                # back to "stare"
    assert vs.value_hash("stare") not in s2["seen"]["c1.password"]
    assert vs.value_hash("nowe") in s2["seen"]["c1.password"]


def test_broken_or_missing_section_is_empty():
    assert vs.normalized(None) == vs.empty()
    assert vs.normalized({"seen": "x", "gone": 5}) == vs.empty()


def test_loaded_section_is_handed_to_the_window_once(tmp_path):
    path = str(tmp_path / "a.vault")
    vs.note_loaded(path, {"hospitals": [], "sync": {"gone": ["x"]}})
    assert vs.take_loaded(path)["gone"] == ["x"]
    assert vs.take_loaded(path) == vs.empty()


# ── the owner's scenarios ──────────────────────────────────────────────────

def test_colleague_adds_a_machine_and_my_own_login_stays():
    common = base_vault()
    mine = copy.deepcopy(common)
    machine(mine, "m1")["credentials"].append(
        {"id": "c-moje", "login": "seba", "password": "moje", "note": "", "admin_only": False})
    theirs = copy.deepcopy(common)
    theirs["hospitals"][1]["machines"].append(
        {"id": "m-new", "ip": "198.51.100.7", "name": "srvPACS", "description": "",
         "connection_type": "RDP", "rdp_port": "3389", "rdp_drives": [], "www_url": "",
         "admin_only": False,
         "credentials": [{"id": "c-new", "login": "admin", "password": "x",
                          "note": "", "admin_only": False}]})
    p, (merged, _sync) = merge(mine, theirs)
    add = by_key(p, "a:m-new")
    assert add.status == vm.NEW and add.default and add.count == 2
    assert add.group == "Szpital Beta"
    assert p.only_here == 1                                    # my login: not even asked
    logins = [c["login"] for c in machine(merged, "m1")["credentials"]]
    assert logins == ["root", "seba"]
    assert [m["id"] for m in merged["hospitals"][1]["machines"]] == ["m-new"]


def test_without_history_a_different_value_is_mine_unless_ticked():
    mine = base_vault()
    theirs = copy.deepcopy(mine)
    machine(theirs, "c1")["password"] = "kolegi"
    p, (merged, sync) = merge(mine, theirs)
    ch = by_key(p, "f:c1:password")
    assert ch.status == vm.CONFLICT and not ch.default and ch.secret
    assert machine(merged, "c1")["password"] == "stare"
    # Kept: the same value of the colleague is not offered again.
    mine2 = copy.deepcopy(merged)
    mine2[vs.SYNC_KEY] = sync
    p2 = vm.plan(mine2, theirs, show_admin=True)
    ch2 = by_key(p2, "f:c1:password")
    assert ch2.skipped and ch2.status == vm.OLDER and not ch2.default
    assert p2.older_there == 1


def test_a_value_the_colleague_replaced_comes_over_by_itself():
    """He changed the password (his save remembers the old one): mine is the
    old one, so his is taken without a question."""
    common = base_vault()
    theirs = copy.deepcopy(common)
    machine(theirs, "c1")["password"] = "nowe"
    theirs = saved(common, theirs)
    mine = copy.deepcopy(common)
    p, (merged, _s) = merge(mine, theirs)
    ch = by_key(p, "f:c1:password")
    assert ch.status == vm.UPDATE and ch.default
    assert machine(merged, "c1")["password"] == "nowe"


def test_my_newer_value_is_not_overwritten_by_his_older_one():
    common = base_vault()
    mine = copy.deepcopy(common)
    machine(mine, "c1")["password"] = "moje-nowe"
    mine = saved(common, mine)
    theirs = copy.deepcopy(common)                             # still "stare"
    p, (merged, _s) = merge(mine, theirs)
    ch = by_key(p, "f:c1:password")
    assert ch.skipped and ch.status == vm.OLDER and not ch.default
    assert p.older_there == 1
    assert machine(merged, "c1")["password"] == "moje-nowe"
    # Shown with „Pokaż pominięte” and ticked: going back is possible.
    _p, (back, _s2) = merge(mine, theirs, take={"f:c1:password"})
    assert machine(back, "c1")["password"] == "stare"


def test_notes_both_wrote_are_joined():
    common = base_vault()
    mine = copy.deepcopy(common)
    mine["hospitals"][0]["notes"] += "\nMoja notatka: login przez jump"
    theirs = copy.deepcopy(common)
    theirs["hospitals"][0]["notes"] = "Kontakt IT: 600 000 000\n" + theirs["hospitals"][0]["notes"]
    p, (merged, _s) = merge(mine, theirs)
    ch = by_key(p, "f:h1:notes")
    assert ch.status == vm.JOINED and ch.default
    assert merged["hospitals"][0]["notes"] == (
        "Kontakt IT: 600 000 000\nVPN przez bramkę\nDyżur: 112\nMoja notatka: login przez jump")


def test_his_deletion_is_only_an_option():
    common = base_vault()
    theirs = copy.deepcopy(common)
    theirs["hospitals"][0]["machines"].pop(0)                 # m1 deleted there
    theirs = saved(common, theirs)
    mine = copy.deepcopy(common)
    p, (merged, _s) = merge(mine, theirs)
    ch = by_key(p, "d:m1")
    assert ch.status == vm.REMOVED_THERE and not ch.default and ch.count == 2
    assert machine(merged, "m1")                               # stays by default
    _p, (merged2, _s2) = merge(mine, theirs, take={"d:m1"})
    assert "m1" not in vs.flatten(merged2)


def test_what_i_deleted_is_not_added_back_by_default():
    common = base_vault()
    mine = copy.deepcopy(common)
    mine["hospitals"].pop(1)
    mine = saved(common, mine)
    theirs = copy.deepcopy(common)
    p, (merged, _s) = merge(mine, theirs)
    ch = by_key(p, "a:h2")
    assert ch.status == vm.REMOVED_HERE and not ch.default
    assert [h["id"] for h in merged["hospitals"]] == ["h1"]


def test_a_declined_new_item_is_not_offered_as_new_again():
    mine = base_vault()
    theirs = copy.deepcopy(mine)
    theirs["hospitals"].append({"id": "h3", "name": "Szpital Gamma", "notes": "",
                                "machines": [], "databases": []})
    p, (merged, sync) = merge(mine, theirs, take=set())
    merged[vs.SYNC_KEY] = sync
    p2 = vm.plan(merged, theirs, show_admin=True)
    assert by_key(p2, "a:h3").status == vm.DECLINED


def test_items_created_on_both_sides_are_matched_by_name_and_address():
    mine = base_vault()
    theirs = copy.deepcopy(mine)
    for n in vs.flatten(theirs).values():                      # all new ids
        n.data["id"] = "t-" + n.id
    machine(theirs, "t-c1")["password"] = "inne"
    p = vm.plan(mine, theirs, show_admin=True)
    assert [c.key for c in p.changes] == ["f:c1:password"]


def test_new_items_go_where_they_stand_in_his_list():
    mine = base_vault()
    theirs = copy.deepcopy(mine)
    theirs["hospitals"].insert(1, {"id": "h-mid", "name": "Szpital Środek", "notes": "",
                                   "machines": [], "databases": []})
    _p, (merged, _s) = merge(mine, theirs)
    assert [h["id"] for h in merged["hospitals"]] == ["h1", "h-mid", "h2"]


# ── admin items ────────────────────────────────────────────────────────────

def admin_change():
    """He changed a login inside the admin machine and added an admin machine."""
    common = base_vault()
    theirs = copy.deepcopy(common)
    machine(theirs, "c2")["password"] = "admin-nowe"
    theirs["hospitals"][0]["machines"].append(
        {"id": "m-adm", "ip": "203.0.113.5", "name": "srvADM", "admin_only": True,
         "credentials": []})
    return common, theirs


def test_with_admin_unlocked_admin_changes_are_listed():
    common, theirs = admin_change()
    p = vm.plan(copy.deepcopy(common), theirs, show_admin=True)
    ch = by_key(p, "f:c2:password")
    assert ch.admin and not ch.hidden and not ch.default
    assert not by_key(p, "a:m-adm").hidden


def test_with_admin_locked_admin_items_come_as_in_his_file_unseen():
    common, theirs = admin_change()
    mine = copy.deepcopy(common)
    p = vm.plan(mine, theirs, show_admin=False)
    assert {c.key for c in p.hidden} == {"f:c2:password", "a:m-adm"}
    assert not any(c.admin for c in p.visible)
    merged, _s = vm.apply(p, set())
    assert machine(merged, "c2")["password"] == "admin-nowe"
    assert machine(merged, "m-adm")["name"] == "srvADM"
    assert vm.summary(p, set())["admin_auto"] == 2


def test_with_admin_locked_nothing_is_deleted_and_nothing_gets_older():
    common = base_vault()
    mine = copy.deepcopy(common)
    machine(mine, "c2")["password"] = "admin-moje-nowsze"
    mine = saved(common, mine)
    theirs = copy.deepcopy(common)
    theirs["hospitals"][0]["machines"] = [m for m in theirs["hospitals"][0]["machines"]
                                          if m["id"] != "m2"]
    theirs = saved(common, theirs)                             # he deleted m2
    p = vm.plan(mine, theirs, show_admin=False)
    merged, _s = vm.apply(p, {c.key for c in p.visible})
    assert machine(merged, "c2")["password"] == "admin-moje-nowsze"
    assert "m2" in vs.flatten(merged)


# ── VPN vaults and the window's objects ───────────────────────────────────

def test_vpn_profiles_merge_and_the_client_path_stays_local():
    mine = {"vpn_profiles": [{"id": "p1", "name": "Alfa", "server": "vpn.alfa.example",
                              "app_path": r"C:\Moje\FortiClient.exe", "password": "a"}]}
    theirs = {"vpn_profiles": [
        {"id": "p1", "name": "Alfa", "server": "vpn2.alfa.example",
         "app_path": r"D:\Jego\FortiClient.exe", "password": "a"},
        {"id": "p2", "name": "Beta", "server": "vpn.beta.example",
         "app_path": r"D:\Jego\FortiClient.exe"}]}
    p, (merged, _s) = merge(mine, theirs, take={"f:p1:server", "a:p2"})
    assert [c.key for c in p.changes] == ["f:p1:server", "a:p2"]
    assert merged["vpn_profiles"][0]["server"] == "vpn2.alfa.example"
    assert merged["vpn_profiles"][0]["app_path"] == r"C:\Moje\FortiClient.exe"
    assert merged["vpn_profiles"][1]["app_path"] == ""


def test_the_windows_objects_are_kept_and_updated():
    hospitals = models.from_dict(base_vault())
    m1 = hospitals[0].machines[0]
    merged_dict = base_vault()
    machine(merged_dict, "c1")["password"] = "nowe"
    merged_dict["hospitals"][0]["machines"][0]["credentials"].append(
        {"id": "c9", "login": "nowy", "password": "", "note": "", "admin_only": False})
    vm.update_in_place(hospitals, models.from_dict(merged_dict))
    assert hospitals[0].machines[0] is m1
    assert [c.login for c in m1.credentials] == ["root", "nowy"]
    assert m1.credentials[0].password == "nowe"


# ── 2026-11-24 (owner, first real merge): empty here is not "different" ────

def test_an_empty_field_here_is_filled_from_the_import():
    """Owner's screenshot: AMMS address/login/password empty here, filled
    there — listed as "different" and unticked; it is a filling-in."""
    mine = base_vault()
    theirs = copy.deepcopy(mine)
    theirs["hospitals"][0]["amms_url"] = "https://amms.alfa.example/"
    p, (merged, _s) = merge(mine, theirs)
    ch = by_key(p, "f:h1:amms_url")
    assert ch.status == vm.FILLED and ch.default
    assert merged["hospitals"][0]["amms_url"] == "https://amms.alfa.example/"


@pytest.mark.parametrize("text", ["Lab Admin: x\nAdmin y", "Lab Admin: x\nAdmin y\n",
                                  "Lab Admin: x\r\nAdmin y\r\n"])
def test_empty_notes_here_get_the_imported_text_as_it_is(text):
    """Owner: with empty notes here one hospital said "newer", another
    "joined text" — only a trailing newline / CRLF made the difference."""
    mine = base_vault()
    mine["hospitals"][1]["notes"] = ""
    theirs = copy.deepcopy(mine)
    theirs["hospitals"][1]["notes"] = text
    p, (merged, _s) = merge(mine, theirs)
    ch = by_key(p, "f:h2:notes")
    assert ch.status == vm.FILLED and ch.default
    assert merged["hospitals"][1]["notes"] == text


def test_a_field_empty_in_the_import_is_not_listed():
    mine = base_vault()
    mine["hospitals"][0]["amms_login"] = "OPERATOR"
    theirs = base_vault()
    p = vm.plan(mine, theirs, show_admin=True)
    assert [(c.status, c.skipped, c.default) for c in p.changes] == [
        (vm.EMPTY_THERE, True, False)]
    assert p.empty_there == 1
    merged, _s = vm.apply(p, set())
    assert merged["hospitals"][0]["amms_login"] == "OPERATOR"
    assert vm.summary(p, set())["kept"] == 0, "pominięte to nie decyzja"


def test_line_endings_and_trailing_spaces_are_no_difference():
    mine = base_vault()
    theirs = copy.deepcopy(mine)
    theirs["hospitals"][0]["notes"] = "VPN przez bramkę  \r\nDyżur: 112\r\n"
    machine(theirs, "m1")["name"] = " srvAPP "
    assert not vm.plan(mine, theirs, show_admin=True).changes


def test_imported_text_with_more_lines_is_extended():
    mine = base_vault()
    theirs = copy.deepcopy(mine)
    theirs["hospitals"][0]["notes"] += "\nNowa linia"
    ch = by_key(vm.plan(mine, theirs, show_admin=True), "f:h1:notes")
    assert ch.status == vm.EXTENDED and ch.default


# ── 2026-11-25 (owner): one machine, its logins under it; no duplicates ────

def test_rows_carry_the_machine_and_login_they_belong_to():
    """Owner's screenshot: "Maszyna srvPDF › Login administrator" and
    "Maszyna srvPDF › Login DIN046\\Admin" read like two machines."""
    mine = base_vault()
    theirs = copy.deepcopy(mine)
    machine(theirs, "c1")["login"] = "ALFA\\platforma"
    machine(theirs, "m1")["credentials"].append(
        {"id": "c-new", "login": "DIN046\\Admin", "password": "x"})
    p = vm.plan(mine, theirs, show_admin=True)
    field = by_key(p, "f:c1:login")
    add = by_key(p, "a:c-new")
    assert field.path == (("m1", "Maszyna srvAPP (192.0.2.10)"), ("c1", "Login root"))
    assert add.path == (("m1", "Maszyna srvAPP (192.0.2.10)"),)
    assert add.title == "Login DIN046\\Admin"


def test_the_same_machine_added_on_both_sides_under_two_names_is_one():
    mine = base_vault()
    theirs = copy.deepcopy(mine)
    m = machine(theirs, "m1")
    m["id"], m["name"] = "m-their", "RDP Alfa"
    for c in m["credentials"]:
        c["id"] = "t-" + c["id"]
    p = vm.plan(mine, theirs, show_admin=True)
    assert p.matched["m-their"] == "m1"
    assert [c.key for c in p.changes] == ["f:m1:name"], "nie druga kopia maszyny"


def test_an_ip_shared_by_two_machines_is_not_guessed():
    mine = base_vault()
    machine(mine, "m2")["ip"] = "192.0.2.10"                 # two machines, one IP
    theirs = copy.deepcopy(mine)
    m = machine(theirs, "m1")
    m["id"], m["name"] = "m-their", "Inna nazwa"
    p = vm.plan(mine, theirs, show_admin=True)
    assert "m-their" not in p.matched
