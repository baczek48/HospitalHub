"""2026-10-16: the installer replaces HospitalHub 1.x, so 2.x takes over the
1.x settings (registered vaults, personal VPN vault, VPN client paths …)
once, without overriding anything 2.x already has.  APPDATA is a fresh temp
dir for every test (conftest)."""

import json
import os
import sys
from pathlib import Path

_HERE = os.path.dirname(os.path.abspath(__file__))
for _p in (os.path.dirname(_HERE), _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import config


def _v1(data: dict) -> Path:
    d = Path(os.environ["APPDATA"]) / "HospitalHub"
    d.mkdir(parents=True, exist_ok=True)
    (d / "config.json").write_text(json.dumps(data), encoding="utf-8")
    return d / "config.json"


def _vaults(tmp_path, *names):
    out = []
    for n, t in names:
        p = tmp_path / n
        p.write_bytes(b"x")
        out.append({"path": str(p), "type": t, "label": n})
    return out


def test_fresh_2x_takes_everything_from_1x(tmp_path):
    vl = _vaults(tmp_path, ("main.vault", "global"), ("vpn.vault", "vpn"))
    v1 = _v1({"last_vault": vl[0]["path"], "vault_list": vl, "active_vault_index": 1,
              "personal_vpn_vault": vl[1]["path"],
              "vpn_provider_paths": {"FortiClient": "C:/FC/FortiClient.exe"},
              "vpn_autofill_enabled": True, "ssh_start_maximized": True,
              "column_widths": {"machines": [80, 90]}, "theme": "light"})
    before = v1.read_bytes()
    taken = config.import_v1_settings_once()
    assert "vault_list" in taken and "personal_vpn_vault" in taken
    assert config.load_vault_list() == vl
    assert config.load_active_vault_index() == 1
    assert config.load_last_vault() == vl[0]["path"]
    assert config.load_personal_vpn_vault() == vl[1]["path"]
    assert config.load_vpn_provider_paths() == {"FortiClient": "C:/FC/FortiClient.exe"}
    assert config.load_theme() == "light"
    assert v1.read_bytes() == before, "the 1.x file is only read"


def test_2x_settings_win_and_missing_vault_types_are_added(tmp_path):
    vl = _vaults(tmp_path, ("test3.vault", "private"), ("vpn.vault", "vpn"),
                 ("main.vault", "global"), ("other-vpn.vault", "vpn"))
    _v1({"vault_list": [vl[0], vl[1], vl[2]], "active_vault_index": 2, "theme": "light",
         "personal_vpn_vault": vl[1]["path"]})
    config.save_vault_list([vl[2], vl[3]])           # 2.x: main + another VPN vault
    config.save_active_vault_index(0)
    config.save_theme("navy")
    config.import_v1_settings_once()
    paths = [v["path"] for v in config.load_vault_list()]
    assert paths == [vl[2]["path"], vl[3]["path"], vl[0]["path"]]   # private added, vpn kept
    assert config.load_active_vault_index() == 0
    assert config.load_theme() == "navy"
    assert config.load_personal_vpn_vault() == vl[1]["path"]


def test_import_happens_once(tmp_path):
    _v1({"theme": "light"})
    assert config.import_v1_settings_once() == ["theme"]
    config.save_theme("dark")
    assert config.import_v1_settings_once() == []
    assert config.load_theme() == "dark"


def test_no_or_damaged_1x_config_is_harmless():
    assert config.import_v1_settings_once() == []
    d = Path(os.environ["APPDATA"]) / "HospitalHub"
    (d / "config.json").write_text("{not json", encoding="utf-8") if d.exists() else None
    assert config.load_vault_list() == []


def test_unknown_1x_keys_are_not_taken():
    _v1({"admin_password": "x", "theme": "light"})
    config.import_v1_settings_once()
    assert "admin_password" not in config._load_all()
