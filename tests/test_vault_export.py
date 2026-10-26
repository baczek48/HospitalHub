"""2026-10-26 (owner): one hospital exported to its own vault file, e.g. for
HH on a client's remote machine — its own password, admin items only when
asked for, with an admin password of the export's own."""

import os
import sys

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_PARENT = os.path.dirname(_HERE)
if _PARENT not in sys.path:
    sys.path.insert(0, _PARENT)

import models  # noqa: E402
import vault_export  # noqa: E402
from crypto import decrypt, encrypt, hash_admin_password, verify_admin_password  # noqa: E402


def _hospital():
    c_ok = models.Credential(login="user", password="u")
    c_admin = models.Credential(login="root", password="r", admin_only=True)
    m_ok = models.Machine(ip="10.0.0.1", name="app", credentials=[c_ok, c_admin])
    m_admin = models.Machine(ip="10.0.0.2", name="secret", admin_only=True,
                             credentials=[models.Credential(login="x", password="y")])
    d_ok = models.Database(host="db", name="amms",
                           credentials=[models.Credential(login="sa", password="s",
                                                          admin_only=True)])
    d_admin = models.Database(host="db2", name="hidden", admin_only=True)
    return models.Hospital(name="Szpital: Miejski/1", machines=[m_ok, m_admin],
                           databases=[d_ok, d_admin], notes="notatka",
                           amms_url="https://amms", amms_login="a", amms_password="b")


def test_1_admin_items_are_counted_once():
    # admin machine + admin db + admin login in app + admin login in amms db
    assert vault_export.admin_item_count(_hospital()) == 4


def test_2_without_admin_leaves_every_admin_item_out_and_the_rest_in():
    h = _hospital()
    data = vault_export.export_hospital_data(h)
    assert set(data) == {"hospitals"}
    (out,) = models.from_dict(data)
    assert [m.name for m in out.machines] == ["app"]
    assert [c.login for c in out.machines[0].credentials] == ["user"]
    assert [d.name for d in out.databases] == ["amms"]
    assert out.databases[0].credentials == []
    assert (out.name, out.notes, out.amms_url, out.amms_password) == \
        (h.name, "notatka", "https://amms", "b")
    # The hospital in the open vault is not touched.
    assert len(h.machines) == 2 and len(h.machines[0].credentials) == 2


def test_3_with_admin_keeps_everything_and_the_exports_admin_password():
    h = _hospital()
    ah, salt = hash_admin_password("adm1")
    data = vault_export.export_hospital_data(h, include_admin=True,
                                             admin_hash=ah, admin_salt=salt)
    (out,) = models.from_dict(data)
    assert len(out.machines) == 2 and len(out.databases) == 2
    assert len(out.machines[0].credentials) == 2
    assert verify_admin_password("adm1", data["admin_hash"], data["admin_salt"])


def test_4_with_admin_but_no_admin_password_is_refused():
    with pytest.raises(ValueError):
        vault_export.export_hospital_data(_hospital(), include_admin=True)


def test_5_the_file_opens_with_its_own_password_only():
    data = vault_export.export_hospital_data(_hospital())
    content = encrypt(data, "haslo-pliku")
    back = decrypt(content, "haslo-pliku")
    assert [h.name for h in models.from_dict(back)] == ["Szpital: Miejski/1"]
    with pytest.raises(Exception):
        decrypt(content, "haslo-glowne")


def test_6_file_name_without_characters_windows_refuses():
    assert vault_export.export_file_name("Szpital: Miejski/1") == "Szpital_ Miejski_1.vault"
    assert vault_export.export_file_name("  ") == "szpital.vault"
    assert vault_export.export_file_name("Łódź.") == "Łódź.vault"
