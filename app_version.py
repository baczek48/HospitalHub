"""Who and what this build is — the one place the app reads its version from.

The number and the release date are written by the build scripts
(``build_v2.bat <wersja>``, ``build_remote.bat <wersja>``) into
``_build_info.py`` right before PyInstaller runs, and the same number goes to
the installer (``ISCC /DMyAppVersion``), so the window and the installer can
never disagree.  The file is removed after the build and never committed;
started from source the app says ``dev``.
"""

from __future__ import annotations

APP_NAME = "HospitalHub"
AUTHOR = "Sebastian Bąk"
COPYRIGHT = "© 2026 Sebastian Bąk. Wszelkie prawa zastrzeżone."
REPO_URL = "https://github.com/baczek48/HospitalHub"
RELEASES_URL = REPO_URL + "/releases/latest"

try:
    from _build_info import RELEASE_DATE, VERSION  # type: ignore
except Exception:                     # from source, or a build without a number
    VERSION = "dev"
    RELEASE_DATE = ""


def version_label() -> str:
    return VERSION if VERSION == "dev" else f"v{VERSION}"
