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
