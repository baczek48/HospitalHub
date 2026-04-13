import json
import os
from pathlib import Path


def _config_path() -> Path:
    app_data = os.environ.get("APPDATA") or Path.home()
    config_dir = Path(app_data) / "HospitalHub"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir / "config.json"


def _load_all() -> dict:
    try:
        with open(_config_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def _save_all(data: dict) -> None:
    try:
        with open(_config_path(), "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def load_last_vault() -> str | None:
    """Returns last used vault path, or None if not set / file missing."""
    data = _load_all()
    path = data.get("last_vault")
    if path and os.path.exists(path):
        return path
    return None


def save_last_vault(path: str) -> None:
    data = _load_all()
    data["last_vault"] = path
    _save_all(data)


def load_vault_list() -> list[dict]:
    """Returns list of registered vaults: [{"path": ..., "type": "global"|"private", "label": ...}, ...]"""
    data = _load_all()
    vaults = data.get("vault_list", [])
    return [v for v in vaults if os.path.exists(v.get("path", ""))]


def save_vault_list(vaults: list[dict]) -> None:
    data = _load_all()
    data["vault_list"] = vaults
    _save_all(data)


def register_vault(path: str, vault_type: str = "global", label: str = "") -> None:
    """Register vault, replacing any existing vault of the same type (max one per type)."""
    vaults = load_vault_list()
    normed = os.path.normpath(path)
    new_entry = {"path": normed, "type": vault_type, "label": label or os.path.basename(path)}
    # Remove existing vault of the same type (replace it)
    vaults = [v for v in vaults if v.get("type") != vault_type]
    # Also remove duplicate path if it existed under a different type
    vaults = [v for v in vaults if os.path.normpath(v["path"]) != normed]
    vaults.append(new_entry)
    save_vault_list(vaults)


def load_active_vault_index() -> int:
    """Returns index of active vault in vault_list."""
    return _load_all().get("active_vault_index", 0)


def save_active_vault_index(index: int) -> None:
    data = _load_all()
    data["active_vault_index"] = index
    _save_all(data)


def load_column_widths(table_key: str) -> list | None:
    """Returns saved column widths list for given table, or None."""
    data = _load_all()
    return data.get("column_widths", {}).get(table_key)


def save_column_widths(table_key: str, widths: list) -> None:
    data = _load_all()
    if "column_widths" not in data:
        data["column_widths"] = {}
    data["column_widths"][table_key] = widths
    _save_all(data)


def load_sqldeveloper_path() -> str | None:
    return _load_all().get("sqldeveloper_path")


def save_sqldeveloper_path(path: str) -> None:
    data = _load_all()
    data["sqldeveloper_path"] = path
    _save_all(data)


def load_vpn_provider_paths() -> dict:
    """Returns dict: provider_name -> exe_path."""
    return _load_all().get("vpn_provider_paths", {})


def save_vpn_provider_paths(paths: dict) -> None:
    data = _load_all()
    data["vpn_provider_paths"] = paths
    _save_all(data)


def load_custom_vpn_providers() -> list:
    """Returns list of user-added VPN provider names."""
    return _load_all().get("custom_vpn_providers", [])


def save_custom_vpn_providers(providers: list) -> None:
    data = _load_all()
    data["custom_vpn_providers"] = providers
    _save_all(data)


def load_personal_vpn_vault() -> str | None:
    """Returns path to user's personal VPN vault, or None if not set."""
    path = _load_all().get("personal_vpn_vault")
    if path and os.path.exists(path):
        return path
    return None


def save_personal_vpn_vault(path: str) -> None:
    data = _load_all()
    data["personal_vpn_vault"] = path
    _save_all(data)
