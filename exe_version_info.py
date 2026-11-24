"""The Windows version resource of the built exe (Properties → Details):
author, copyright, product version — read by both .spec files.

The number comes from app_version (the build script's _build_info.py);
a build without one gets 0.0.0.0 and "dev".
"""

from __future__ import annotations

import app_version


def _numbers(version: str) -> tuple[int, int, int, int]:
    parts = []
    for p in (version or "").split("."):
        if not p.isdigit():
            break
        parts.append(int(p))
    return tuple((parts + [0, 0, 0, 0])[:4])


def version_info(description: str, internal_name: str, original_filename: str):
    from PyInstaller.utils.win32.versioninfo import (
        FixedFileInfo, StringFileInfo, StringStruct, StringTable, VarFileInfo,
        VarStruct, VSVersionInfo,
    )
    nums = _numbers(app_version.VERSION)
    text = app_version.VERSION
    return VSVersionInfo(
        ffi=FixedFileInfo(filevers=nums, prodvers=nums, mask=0x3F, flags=0x0,
                          OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
        kids=[
            StringFileInfo([StringTable("041504B0", [
                StringStruct("CompanyName", app_version.AUTHOR),
                StringStruct("FileDescription", description),
                StringStruct("FileVersion", text),
                StringStruct("InternalName", internal_name),
                StringStruct("LegalCopyright", app_version.COPYRIGHT),
                StringStruct("OriginalFilename", original_filename),
                StringStruct("ProductName", app_version.APP_NAME),
                StringStruct("ProductVersion", text),
            ])]),
            VarFileInfo([VarStruct("Translation", [0x0415, 1200])]),
        ],
    )
