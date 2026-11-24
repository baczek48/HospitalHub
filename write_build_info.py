"""Used by build_v2.bat / build_remote.bat: writes _build_info.py (version
given on the command line, today's date) for app_version to read."""

import datetime
import os
import sys

version = (sys.argv[1] if len(sys.argv) > 1 else "").strip() or "dev"
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "_build_info.py")
with open(path, "w", encoding="utf-8", newline="\n") as f:
    f.write(f"VERSION = {version!r}\n"
            f"RELEASE_DATE = {datetime.date.today().isoformat()!r}\n")
print(f"_build_info.py: {version}, {datetime.date.today().isoformat()}")
