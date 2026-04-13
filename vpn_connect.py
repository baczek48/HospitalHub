"""VPN connection launcher — calls CLI tools for each supported provider."""

import os
import re
import subprocess
import threading
import winreg

# Patterns that indicate a 2FA/OTP prompt in process stdout
_2FA_PATTERNS = re.compile(
    r"(enter.*token|enter.*code|two.?factor|2fa|otp|one.?time|"
    r"authentication code|verification code|token:|passcode|"
    r"sms.*code|email.*code|push.*notification|approve.*request)",
    re.IGNORECASE,
)


def is_2fa_prompt(line: str) -> bool:
    return bool(_2FA_PATTERNS.search(line))


def _hidden_startupinfo():
    si = subprocess.STARTUPINFO()
    si.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    si.wShowWindow = 0
    return si


_NO_WINDOW = subprocess.CREATE_NO_WINDOW


def _find_python_exe() -> list[str]:
    """Return list of candidate python executables, best first.
    Handles PyInstaller where sys.executable is the frozen app."""
    import sys
    candidates = []
    exe = sys.executable or ""
    # If sys.executable is real python (not frozen app)
    if exe and os.path.basename(exe).lower().startswith("python"):
        candidates.append(exe)
    # Check common locations
    for name in ("python", "python3", "py"):
        candidates.append(name)
    # Also check registry / known paths
    for base in (os.environ.get("LOCALAPPDATA", ""),
                 os.environ.get("PROGRAMFILES", "")):
        if not base:
            continue
        for ver in ("Python313", "Python312", "Python311", "Python310"):
            p = os.path.join(base, "Programs", "Python", ver, "python.exe")
            if os.path.isfile(p):
                candidates.append(p)
                break
            p2 = os.path.join(base, "Python", ver, "python.exe")
            if os.path.isfile(p2):
                candidates.append(p2)
                break
    return candidates


def _forti_install_dir() -> str | None:
    """Return FortiClient installation directory from registry."""
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Fortinet\FortiClient")
        install_dir = winreg.QueryValueEx(key, "INSTALLDIR")[0]
        winreg.CloseKey(key)
        return install_dir
    except Exception:
        pass
    for d in [r"C:\Program Files\Fortinet\FortiClient",
              r"C:\Program Files (x86)\Fortinet\FortiClient"]:
        if os.path.isdir(d):
            return d
    return None


# ------------------------------------------------------------------ #
# Provider paths                                                      #
# ------------------------------------------------------------------ #

_PATHS = {
    "FortiClient": [
        r"C:\Program Files\Fortinet\FortiClient\FortiSSLVPNclient.exe",
        r"C:\Program Files (x86)\Fortinet\FortiClient\FortiSSLVPNclient.exe",
    ],
    "GlobalProtect": [
        r"C:\Program Files\Palo Alto Networks\GlobalProtect\PanGPA.exe",
        r"C:\GlobalProtect\PanGPA.exe",
    ],
    "SonicWall NetExtender": [
        r"C:\Program Files (x86)\SonicWall\SSL-VPN\NetExtender\NECLI.exe",
        r"C:\Program Files\SonicWall\SSL-VPN\NetExtender\NECLI.exe",
        r"C:\Program Files (x86)\SonicWall\SSL-VPN\NetExtender\nxcli.exe",
        r"C:\Program Files\SonicWall\SSL-VPN\NetExtender\nxcli.exe",
    ],
    "Stormshield": [],
    "Barracuda": [],
    "Hillstone Secure Connect": [],
}

_FORTIVPN_PATHS = [
    r"C:\Program Files\Fortinet\FortiClient\FortiVPN.exe",
    r"C:\Program Files (x86)\Fortinet\FortiClient\FortiVPN.exe",
]

_FORTICLIENT_GUI_PATHS = [
    r"C:\Program Files\Fortinet\FortiClient\FortiClient.exe",
    r"C:\Program Files (x86)\Fortinet\FortiClient\FortiClient.exe",
]

_SSLVPN_LOG_PATHS = [
    r"C:\Program Files\Fortinet\FortiClient\logs\trace\sslvpndaemon_1.log",
    r"C:\Program Files (x86)\Fortinet\FortiClient\logs\trace\sslvpndaemon_1.log",
]


def find_executable(provider: str) -> str | None:
    for path in _PATHS.get(provider, []):
        if os.path.isfile(path):
            return path
    return None


def _find_fortivpn(app_path: str = "") -> str | None:
    if app_path:
        vpn_exe = os.path.join(os.path.dirname(app_path), "FortiVPN.exe")
        if os.path.isfile(vpn_exe):
            return vpn_exe
    for path in _FORTIVPN_PATHS:
        if os.path.isfile(path):
            return path
    return None


def _find_forticlient_gui(app_path: str = "") -> str | None:
    """Find FortiClient.exe GUI executable."""
    if app_path and os.path.isfile(app_path):
        return app_path
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Fortinet\FortiClient")
        install_dir = winreg.QueryValueEx(key, "INSTALLDIR")[0]
        winreg.CloseKey(key)
        gui = os.path.join(install_dir, "FortiClient.exe")
        if os.path.isfile(gui):
            return gui
    except Exception:
        pass
    for path in _FORTICLIENT_GUI_PATHS:
        if os.path.isfile(path):
            return path
    return None


# ------------------------------------------------------------------ #
# Registry: auto-detect FortiClient tunnels                           #
# ------------------------------------------------------------------ #

def get_forti_tunnels_from_registry() -> list[dict]:
    """
    Read configured SSL VPN tunnels from FortiClient registry.
    Returns list of dicts: [{"name": "...", "server": "...", "port": "..."}, ...]
    """
    tunnels = []
    base_key = r"SOFTWARE\Fortinet\FortiClient\Sslvpn\Tunnels"
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base_key)
    except OSError:
        return tunnels
    try:
        i = 0
        while True:
            try:
                tunnel_name = winreg.EnumKey(key, i)
                tunnel_info = {"name": tunnel_name, "server": "", "port": ""}
                try:
                    tkey = winreg.OpenKey(key, tunnel_name)
                    try:
                        server_val = winreg.QueryValueEx(tkey, "Server")[0]
                        if ":" in server_val:
                            host, port = server_val.rsplit(":", 1)
                            tunnel_info["server"] = host
                            tunnel_info["port"] = port
                        else:
                            tunnel_info["server"] = server_val
                    except OSError:
                        pass
                    winreg.CloseKey(tkey)
                except OSError:
                    pass
                tunnels.append(tunnel_info)
                i += 1
            except OSError:
                break
    finally:
        winreg.CloseKey(key)
    return tunnels


def is_forticlient_installed() -> bool:
    """Check if FortiClient is installed."""
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Fortinet\FortiClient")
        winreg.CloseKey(key)
        return True
    except OSError:
        return False


# ------------------------------------------------------------------ #
# FortiClient edition detection                                        #
# ------------------------------------------------------------------ #

def _is_forti_free_edition() -> bool:
    """Detect FortiClient free/VPN edition via registry (no exe launch needed)."""
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Fortinet\FortiClient\FA_FCM")
        installed = winreg.QueryValueEx(key, "installed")[0]
        winreg.CloseKey(key)
        if installed == 0:
            return True
    except OSError:
        pass
    try:
        base = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, base)
        i = 0
        while True:
            try:
                subkey_name = winreg.EnumKey(key, i)
                try:
                    sk = winreg.OpenKey(key, subkey_name)
                    dn = winreg.QueryValueEx(sk, "DisplayName")[0]
                    winreg.CloseKey(sk)
                    if "forticlient" in dn.lower():
                        if dn.strip().lower() in ("forticlient vpn", "forticlient free"):
                            return True
                except OSError:
                    pass
                i += 1
            except OSError:
                break
        winreg.CloseKey(key)
    except OSError:
        pass
    return False


_cli_supported_cache: dict[str, bool] = {}
# Per-provider last connected profile tracking (avoids cross-provider interference)
_last_connected: dict[str, str] = {}  # provider -> profile_name
_state_lock = threading.Lock()  # guards _last_connected, _adapter_cache, _server_ip_cache


def _is_fortivpn_cli_supported(app_path: str = "") -> bool:
    """Check if FortiVPN.exe supports --cli flag (EMS/ZTNA editions only).
    Uses registry detection first — never launches FortiVPN.exe on free edition."""
    fortivpn = _find_fortivpn(app_path)
    if not fortivpn:
        return False
    if fortivpn in _cli_supported_cache:
        return _cli_supported_cache[fortivpn]

    if _is_forti_free_edition():
        _cli_supported_cache[fortivpn] = False
        return False

    try:
        result = subprocess.run(
            [fortivpn, "--cli", "--status"],
            capture_output=True, text=True, timeout=5,
            startupinfo=_hidden_startupinfo(),
            creationflags=_NO_WINDOW,
        )
        out = (result.stdout + result.stderr).lower()
        supported = "error parsing" not in out and "does not exist" not in out
    except Exception:
        supported = False
    _cli_supported_cache[fortivpn] = supported
    return supported


# ------------------------------------------------------------------ #
# Status from daemon log (works for ALL FortiClient editions)         #
# ------------------------------------------------------------------ #

def _find_sslvpn_log() -> str | None:
    """Find the sslvpndaemon log file."""
    try:
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                             r"SOFTWARE\Fortinet\FortiClient")
        install_dir = winreg.QueryValueEx(key, "INSTALLDIR")[0]
        winreg.CloseKey(key)
        log = os.path.join(install_dir, "logs", "trace", "sslvpndaemon_1.log")
        if os.path.isfile(log):
            return log
    except Exception:
        pass
    for path in _SSLVPN_LOG_PATHS:
        if os.path.isfile(path):
            return path
    return None


def _read_log_tail(size: int = 8192) -> str | None:
    """Read last N bytes of sslvpndaemon log."""
    log_path = _find_sslvpn_log()
    if not log_path:
        return None
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(0, 2)
            fsize = f.tell()
            f.seek(max(0, fsize - size))
            return f.read()
    except Exception:
        return None


_gp_log_cache: dict = {"path": None, "mtime": 0.0, "status": None}


def _get_globalprotect_status_from_log(gp_dir: str = "") -> str | None:
    """Parse PanGPS.log tail for tunnel state. Cached by mtime."""
    candidates = []
    if gp_dir:
        candidates.append(os.path.join(gp_dir, "PanGPS.log"))
    candidates += [
        r"C:\GlobalProtect\PanGPS.log",
        r"C:\Program Files\Palo Alto Networks\GlobalProtect\PanGPS.log",
    ]
    log_path = next((p for p in candidates if os.path.isfile(p)), None)
    if not log_path:
        return None
    try:
        mtime = os.path.getmtime(log_path)
    except OSError:
        return None
    if _gp_log_cache["path"] == log_path and _gp_log_cache["mtime"] == mtime:
        return _gp_log_cache["status"]
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            f.seek(0, 2)
            fsize = f.tell()
            f.seek(max(0, fsize - 16384))
            tail = f.read()
    except OSError:
        return None
    status = None
    for line in reversed(tail.splitlines()):
        low = line.lower()
        if "isconnected() is 1" in low or "tunnel is up" in low or "tunnel connected" in low:
            status = "Connected"
            break
        if ("isconnected() is 0" in low or "no tunnel" in low
                or "tunnel is down" in low or "disconnect" in low):
            status = "Disconnected"
            break
        if "connecting" in low and "tunnel" in low:
            status = "Connecting"
            break
    _gp_log_cache.update(path=log_path, mtime=mtime, status=status)
    return status


def _get_status_from_log() -> str | None:
    """Parse log for VPN status. Returns 'Disconnected', 'Connecting', or None."""
    tail = _read_log_tail()
    if not tail:
        return None
    for line in reversed(tail.splitlines()):
        low = line.lower()
        if "ssl vpn tunnel is disconnected" in low:
            return "Disconnected"
        if "fortissl_disconnect() called" in low:
            return "Disconnected"
        if "tunnel_loop() exits" in low:
            return "Disconnected"
        if "received sslvpn_req_disconnect" in low:
            return "Disconnected"
        if "received sslvpn_req_connect" in low:
            return "Connecting"
        if "tcp connected" in low:
            return "Connecting"
    return None


_server_ip_cache: dict[str, str] = {}


def _resolve_server(host: str) -> str:
    """Resolve hostname to IP. Cached. Returns original string on failure."""
    with _state_lock:
        if host in _server_ip_cache:
            return _server_ip_cache[host]
    # Already an IP
    if all(c.isdigit() or c == '.' for c in host):
        with _state_lock:
            _server_ip_cache[host] = host
        return host
    import socket
    try:
        ip = socket.gethostbyname(host)
        with _state_lock:
            _server_ip_cache[host] = ip
        return ip
    except Exception:
        with _state_lock:
            _server_ip_cache[host] = host
        return host


def _servers_match(a: str, b: str) -> bool:
    """Check if two server addresses refer to the same host (handles hostname vs IP)."""
    if a == b:
        return True
    return _resolve_server(a) == _resolve_server(b)


def _get_last_connected_server() -> str | None:
    """Get the server IP/hostname from the last SSLVPN_REQ_CONNECT in the log.
    Reads the whole file (called once, result is cached)."""
    log_path = _find_sslvpn_log()
    if not log_path:
        return None
    try:
        with open(log_path, "r", encoding="utf-8", errors="replace") as f:
            content = f.read()
    except Exception:
        return None
    last_server = None
    for line in content.splitlines():
        if "Server name=" in line:
            try:
                last_server = line.split("Server name=")[1].split()[0].strip()
            except (IndexError, KeyError):
                pass
    return last_server


def _get_vpn_connected_server_ip(process_name: str) -> str | None:
    """Get the remote server IP that a VPN daemon process is connected to via netstat.
    Returns the IP (without port) of the ESTABLISHED TCP connection, or None."""
    try:
        r = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {process_name}", "/NH", "/FO", "CSV"],
            capture_output=True, text=True, timeout=5,
            startupinfo=_hidden_startupinfo(),
            creationflags=_NO_WINDOW)
        pids = set()
        for line in (r.stdout or "").strip().split("\n"):
            parts = line.strip().strip('"').split('","')
            if len(parts) >= 2 and parts[0].lower() == process_name.lower():
                try:
                    pids.add(parts[1])
                except (ValueError, IndexError):
                    pass
        if not pids:
            return None
        r2 = subprocess.run(
            ["netstat", "-n", "-o", "-p", "tcp"],
            capture_output=True, timeout=5,
            startupinfo=_hidden_startupinfo(),
            creationflags=_NO_WINDOW)
        output = (r2.stdout or b"").decode("utf-8", errors="replace")
        for line in output.splitlines():
            if "ESTABLISHED" not in line:
                continue
            parts = line.split()
            if len(parts) >= 5 and parts[4] in pids:
                remote = parts[2]
                ip = remote.rsplit(":", 1)[0]
                return ip
    except Exception:
        pass
    return None


def _has_visible_window(title_keyword: str) -> bool:
    """Return True if any *visible* top-level window's title contains keyword."""
    try:
        import win32gui
        found = [False]
        def cb(hwnd, _):
            if win32gui.IsWindowVisible(hwnd):
                title = win32gui.GetWindowText(hwnd)
                if title and title_keyword in title.lower():
                    found[0] = True
            return True
        win32gui.EnumWindows(cb, None)
        return found[0]
    except Exception:
        return False


def _show_existing_window(title_keyword: str) -> bool:
    """Find a window by title keyword (including hidden/tray windows), restore and bring to front.
    Uses WM_SYSCOMMAND+SC_RESTORE which works for Qt tray windows."""
    try:
        import win32gui
        import win32con
        found = []
        def cb(hwnd, _):
            title = win32gui.GetWindowText(hwnd)
            if title and title_keyword in title.lower():
                found.append(hwnd)
            return True
        win32gui.EnumWindows(cb, None)
        if found:
            hwnd = found[0]
            if win32gui.IsWindowVisible(hwnd):
                # Already visible — just bring to front
                try:
                    win32gui.SetForegroundWindow(hwnd)
                except Exception:
                    pass
                return True
            # Hidden in tray — restore via WM_SYSCOMMAND
            win32gui.PostMessage(hwnd, win32con.WM_SYSCOMMAND, win32con.SC_RESTORE, 0)
            return True
    except Exception:
        pass
    return False


def _restore_tray_window(title_keyword: str) -> bool:
    """Restore a Qt tray window using a separate python.exe process.
    Must be a different process — PostMessage from same process freezes Qt windows."""
    script = (
        "import win32gui,win32con,sys\n"
        f"kw={title_keyword!r}\n"
        "found=[]\n"
        "win32gui.EnumWindows(lambda h,_: found.append(h)"
        " if win32gui.GetWindowText(h) and kw in win32gui.GetWindowText(h).lower()"
        " else None, None)\n"
        "if not found: sys.exit(1)\n"
        "win32gui.PostMessage(found[0], win32con.WM_SYSCOMMAND, win32con.SC_RESTORE, 0)\n"
    )
    # Find python.exe — try common locations
    for py in _find_python_exe():
        try:
            result = subprocess.run(
                [py, "-c", script],
                capture_output=True, timeout=5,
                creationflags=_NO_WINDOW,
            )
            return result.returncode == 0
        except FileNotFoundError:
            continue
        except Exception:
            return False
    return False


def _restore_tray_by_process(exe_name: str) -> bool:
    """Restore a tray window by finding ALL windows (including hidden) owned by
    the process exe_name. Runs from a SEPARATE python.exe process to avoid
    freezing Qt apps. Tries SC_RESTORE, ShowWindow, and tray icon activation."""
    script = (
        "import win32gui,win32con,win32process,subprocess,sys,time\n"
        f"exe={exe_name.lower()!r}\n"
        "r=subprocess.run(['tasklist','/FI','IMAGENAME eq '+exe,'/NH','/FO','CSV'],"
        "capture_output=True,text=True,timeout=5)\n"
        "pids=set()\n"
        "for l in (r.stdout or '').strip().split('\\n'):\n"
        "  p=l.strip().strip('\"').split('\",\"')\n"
        "  if len(p)>=2 and p[0].lower()==exe:\n"
        "    try: pids.add(int(p[1]))\n"
        "    except: pass\n"
        "if not pids: sys.exit(1)\n"
        "wins=[]\n"
        "def cb(h,_):\n"
        "  _,pid=win32process.GetWindowThreadProcessId(h)\n"
        "  if pid in pids: wins.append(h)\n"
        "  return True\n"
        "win32gui.EnumWindows(cb,None)\n"
        "if not wins: sys.exit(2)\n"
        # Try each window: SC_RESTORE from separate process, then ShowWindow
        "ok=False\n"
        "for h in wins:\n"
        "  try:\n"
        "    cl=win32gui.GetClassName(h)\n"
        "    if 'TrayIcon' in cl or 'tooltip' in cl.lower(): continue\n"
        "    win32gui.PostMessage(h,win32con.WM_SYSCOMMAND,win32con.SC_RESTORE,0)\n"
        "    ok=True; break\n"
        "  except: pass\n"
        "if not ok: sys.exit(3)\n"
        "time.sleep(0.5)\n"
        # Bring to front
        "for h in wins:\n"
        "  try:\n"
        "    if win32gui.IsWindowVisible(h) and win32gui.GetWindowText(h):\n"
        "      win32gui.SetForegroundWindow(h)\n"
        "      break\n"
        "  except: pass\n"
    )
    for py in _find_python_exe():
        try:
            result = subprocess.run(
                [py, "-c", script],
                capture_output=True, timeout=8,
                creationflags=_NO_WINDOW,
            )
            _dbg(f"_restore_tray_by_process({exe_name}): rc={result.returncode} "
                 f"stderr={result.stderr[:200] if result.stderr else ''}")
            return result.returncode == 0
        except FileNotFoundError:
            continue
        except Exception:
            return False
    return False


def _activate_qt_tray_icon(exe_name: str) -> bool:
    """Simulate double-click on a Qt5 system tray icon to restore the app.
    Finds the TrayIcon callback window owned by the process and sends the
    Qt5 tray icon callback (WM_APP+101) with WM_LBUTTONDBLCLK.
    Class name varies by Qt build: 'QTrayIconMessageWindow' or
    'Qt5158TrayIconMessageWindowClass' etc — we match 'TrayIcon' substring."""
    script = (
        "import win32gui,win32process,sys\n"
        f"exe={exe_name.lower()!r}\n"
        "import subprocess\n"
        "r=subprocess.run(['tasklist','/FI','IMAGENAME eq '+exe,'/NH','/FO','CSV'],"
        "capture_output=True,text=True,timeout=5)\n"
        "pids=set()\n"
        "for l in (r.stdout or '').strip().split('\\n'):\n"
        "  p=l.strip().strip('\"').split('\",\"')\n"
        "  if len(p)>=2 and p[0].lower()==exe:\n"
        "    try: pids.add(int(p[1]))\n"
        "    except: pass\n"
        "if not pids: sys.exit(1)\n"
        "found=[]\n"
        "def cb(h,_):\n"
        "  _,pid=win32process.GetWindowThreadProcessId(h)\n"
        "  if pid in pids and 'TrayIcon' in win32gui.GetClassName(h):\n"
        "    found.append(h)\n"
        "  return True\n"
        "win32gui.EnumWindows(cb,None)\n"
        "if not found: sys.exit(2)\n"
        "MYWM=0x8000+101\n"  # WM_APP+101 = Qt5 tray callback
        "WM_LBUTTONDBLCLK=0x0203\n"
        "win32gui.PostMessage(found[0],MYWM,0,WM_LBUTTONDBLCLK)\n"
    )
    for py in _find_python_exe():
        try:
            result = subprocess.run(
                [py, "-c", script],
                capture_output=True, timeout=5,
                creationflags=_NO_WINDOW,
            )
            _dbg(f"_activate_qt_tray_icon({exe_name}): rc={result.returncode}")
            return result.returncode == 0
        except FileNotFoundError:
            continue
        except Exception:
            return False
    return False


def _show_window_by_process(exe_name: str) -> bool:
    """Find a window owned by a process with given exe name and restore it."""
    try:
        import win32gui
        import win32process
        # Get PIDs of target process
        result = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {exe_name}", "/NH", "/FO", "CSV"],
            capture_output=True, text=True, timeout=5,
            startupinfo=_hidden_startupinfo(),
            creationflags=_NO_WINDOW)
        pids = set()
        for line in (result.stdout or "").strip().split("\n"):
            parts = line.strip().strip('"').split('","')
            if len(parts) >= 2 and parts[0].lower() == exe_name.lower():
                try:
                    pids.add(int(parts[1]))
                except ValueError:
                    pass
        if not pids:
            return False
        # Find windows owned by those PIDs
        found = []
        def cb(hwnd, _):
            _, pid = win32process.GetWindowThreadProcessId(hwnd)
            if pid in pids:
                found.append(hwnd)
            return True
        win32gui.EnumWindows(cb, None)
        for hwnd in found:
            try:
                win32gui.ShowWindow(hwnd, 9)  # SW_RESTORE
                win32gui.SetForegroundWindow(hwnd)
                return True
            except Exception:
                continue
    except Exception:
        pass
    return False


def _bring_window_to_front(title_keyword: str, force_show: bool = False) -> bool:
    """Find window by title keyword and bring to front using TOPMOST trick.
    If force_show=True, also calls ShowWindow (use only when window was never shown).
    Default: only SetWindowPos — safe for Qt5 windows already shown via tray click."""
    try:
        import win32gui
        import win32con
        found = []
        def cb(hwnd, _):
            title = win32gui.GetWindowText(hwnd)
            if title and title_keyword in title.lower():
                found.append(hwnd)
            return True
        win32gui.EnumWindows(cb, None)
        if not found:
            return False
        hwnd = found[0]
        if force_show or not win32gui.IsWindowVisible(hwnd):
            win32gui.ShowWindow(hwnd, win32con.SW_SHOW)
            win32gui.ShowWindow(hwnd, win32con.SW_RESTORE)
            import time; time.sleep(0.2)
        # TOPMOST trick — set topmost then remove, forces window to front
        win32gui.SetWindowPos(hwnd, win32con.HWND_TOPMOST, 0, 0, 0, 0,
                               win32con.SWP_NOMOVE | win32con.SWP_NOSIZE)
        win32gui.SetWindowPos(hwnd, win32con.HWND_NOTOPMOST, 0, 0, 0, 0,
                               win32con.SWP_NOMOVE | win32con.SWP_NOSIZE)
        return True
    except Exception:
        return False


def _find_hillstone_exe() -> str | None:
    """Auto-detect Hillstone Secure Connect GUI executable."""
    for base in (os.environ.get("PROGRAMFILES(X86)", ""), os.environ.get("PROGRAMFILES", "")):
        if not base:
            continue
        candidate = os.path.join(base, "Hillstone", "Hillstone Secure Connect", "HillstoneSecureConnect.exe")
        if os.path.isfile(candidate):
            return candidate
    return None


def _find_netextender_cli(app_path: str) -> str | None:
    """Find nxcli.exe or NECLI.exe near the given NetExtender app_path."""
    _dbg(f"_find_netextender_cli: app_path={app_path!r}")
    if not app_path:
        exe = find_executable("SonicWall NetExtender")
        _dbg(f"  no app_path, find_executable returned {exe!r}")
        return exe
    d = os.path.dirname(app_path)
    _dbg(f"  searching in dir: {d!r}")
    for name in ("nxcli.exe", "NECLI.exe", "necli.exe"):
        p = os.path.join(d, name)
        exists = os.path.isfile(p)
        _dbg(f"  checking {p!r} -> {exists}")
        if exists:
            return p
    base = os.path.basename(app_path).lower()
    if base in ("nxcli.exe", "necli.exe"):
        return app_path
    _dbg("  CLI not found!")
    return None


def _focus_pid_window(pid: int) -> bool:
    """Find a visible window belonging to given PID and bring it to foreground."""
    try:
        import win32gui, win32process
        import ctypes as _ct
        found = []
        def cb(hwnd, _):
            if win32gui.IsWindowVisible(hwnd):
                _, wpid = win32process.GetWindowThreadProcessId(hwnd)
                if wpid == pid:
                    found.append(hwnd)
            return True
        win32gui.EnumWindows(cb, None)
        if not found:
            return False
        hwnd = found[0]
        our_tid = _ct.windll.kernel32.GetCurrentThreadId()
        fg_tid, _ = win32process.GetWindowThreadProcessId(hwnd)
        _ct.windll.user32.AttachThreadInput(our_tid, fg_tid, True)
        try:
            win32gui.SetForegroundWindow(hwnd)
        except Exception:
            pass
        _ct.windll.user32.AttachThreadInput(our_tid, fg_tid, False)
        return True
    except Exception:
        return False


def _nxcli_pty_run(cli: str, args: list[str], auto_answers: dict[str, str] = None,
                   timeout: int = 20) -> tuple[bool, str]:
    """Run nxcli command in a pseudo-terminal (PTY) to handle ReadConsole prompts.
    auto_answers maps lowercase prompt substrings to responses (e.g. {"save": "Y"})."""
    try:
        from winpty import PtyProcess
    except ImportError:
        _dbg("pywinpty not available")
        return False, "Brak modułu pywinpty."
    import time
    _dbg(f"_nxcli_pty_run: {cli} {args}")
    try:
        p = PtyProcess.spawn([cli] + args)
        output = ""
        start = time.time()
        answered = set()
        while time.time() - start < timeout:
            time.sleep(0.3)
            try:
                data = p.read(4096)
                if data:
                    output += data
                    _dbg(f"  pty read: {data!r}")
            except Exception:
                pass
            # Check for prompts to auto-answer
            if auto_answers:
                low = output.lower()
                for prompt_key, response in auto_answers.items():
                    if prompt_key in low and prompt_key not in answered:
                        p.write(response + "\r\n")
                        answered.add(prompt_key)
                        _dbg(f"  auto-answered '{prompt_key}' with '{response}'")
            # Check if process exited
            if not p.isalive():
                break
        # Read remaining output
        try:
            data = p.read(4096)
            if data:
                output += data
        except Exception:
            pass
        p.close()
        _dbg(f"  pty output: {output!r}")
        return True, output
    except Exception as e:
        _dbg(f"_nxcli_pty_run error: {e}")
        return False, str(e)


def _find_netextender_gui(app_path: str) -> str | None:
    """Find NetExtender.exe (GUI) — never returns nxcli/NECLI."""
    dirs = set()
    if app_path and os.path.isfile(app_path):
        dirs.add(os.path.dirname(app_path))
    cli = _find_netextender_cli(app_path)
    if cli:
        dirs.add(os.path.dirname(cli))
    for d in dirs:
        gui = os.path.join(d, "NetExtender.exe")
        if os.path.isfile(gui):
            return gui
    return None


_cli_valid_cache: dict[str, bool] = {}

# NT status codes indicating broken exe (DLL init / DLL not found)
_BAD_EXIT_CODES = {-1073741502, -1073741515}  # 0xC0000142, 0xC0000135


def _validate_cli(cli: str) -> bool:
    """Check if a CLI exe can run by executing 'cli status' with suppressed error dialogs.
    Sets SEM_FAILCRITICALERRORS|SEM_NOGPFAULTERRORBOX|SEM_NOOPENFILEERRORBOX in parent
    so child inherits them (no CREATE_DEFAULT_ERROR_MODE — that would reset child's mode).
    Also suppresses WER dialog via registry-free approach: short timeout + kill."""
    if cli in _cli_valid_cache:
        return _cli_valid_cache[cli]
    if not os.path.isfile(cli):
        _cli_valid_cache[cli] = False
        return False
    import ctypes
    # SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX
    old_mode = ctypes.windll.kernel32.SetErrorMode(0x8003)
    try:
        # No CREATE_DEFAULT_ERROR_MODE — child must inherit parent's error mode
        proc = subprocess.Popen(
            [cli, "status"], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            startupinfo=_hidden_startupinfo(),
            creationflags=_NO_WINDOW)
        try:
            stdout, stderr = proc.communicate(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=3)
            # Timeout likely means DLL dialog is blocking — kill any WerFault
            try:
                subprocess.run(["taskkill", "/F", "/IM", "WerFault.exe"],
                    capture_output=True, timeout=3,
                    startupinfo=_hidden_startupinfo(),
                    creationflags=_NO_WINDOW)
            except Exception:
                pass
            _dbg(f"_validate_cli: {cli!r} timed out (DLL dialog?) — marking broken")
            _cli_valid_cache[cli] = False
            return False
        if proc.returncode in _BAD_EXIT_CODES:
            _dbg(f"_validate_cli: {cli!r} exit code {proc.returncode} — broken")
            _cli_valid_cache[cli] = False
            return False
        _dbg(f"_validate_cli: {cli!r} OK (rc={proc.returncode})")
        _cli_valid_cache[cli] = True
        return True
    except OSError as e:
        _dbg(f"_validate_cli: {cli!r} OSError: {e}")
        _cli_valid_cache[cli] = False
        return False
    except Exception:
        _cli_valid_cache[cli] = True
        return True
    finally:
        ctypes.windll.kernel32.SetErrorMode(old_mode)


def _is_process_running(exe_name: str) -> bool:
    """Check if a process with given exe name is running.
    Uses /FO CSV to avoid tasklist truncating long exe names."""
    try:
        result = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {exe_name}", "/NH", "/FO", "CSV"],
            capture_output=True, text=True, timeout=5,
            startupinfo=_hidden_startupinfo(),
            creationflags=_NO_WINDOW)
        return exe_name.lower() in (result.stdout or "").lower()
    except Exception:
        return False


_adapter_cache: tuple[float, str, str] = (0.0, "", "")  # (timestamp, ipconfig_out, netsh_out)
_ADAPTER_CACHE_TTL = 2.0  # seconds


def _get_adapter_outputs() -> tuple[str, str]:
    """Return cached (ipconfig_output, netsh_output). Refreshed every _ADAPTER_CACHE_TTL seconds."""
    global _adapter_cache
    import time
    now = time.monotonic()
    with _state_lock:
        if now - _adapter_cache[0] < _ADAPTER_CACHE_TTL and _adapter_cache[1]:
            return _adapter_cache[1], _adapter_cache[2]

    ipconfig_out = ""
    netsh_out = ""
    try:
        r = subprocess.run(["ipconfig", "/all"], capture_output=True, timeout=5,
                           startupinfo=_hidden_startupinfo(), creationflags=_NO_WINDOW)
        ipconfig_out = (r.stdout or b"").decode("utf-8", errors="replace")
    except Exception:
        pass
    try:
        r = subprocess.run(["netsh", "interface", "show", "interface"],
                           capture_output=True, timeout=5,
                           startupinfo=_hidden_startupinfo(), creationflags=_NO_WINDOW)
        netsh_out = (r.stdout or b"").decode("utf-8", errors="replace")
    except Exception:
        pass

    with _state_lock:
        _adapter_cache = (now, ipconfig_out, netsh_out)
    return ipconfig_out, netsh_out


def _check_adapter_status(*keywords: str) -> str | None:
    """Check adapter status by searching ipconfig /all (description) and netsh (name).
    Returns 'Connected', 'Disconnected', or None if adapter not found."""
    ipconfig_out, netsh_out = _get_adapter_outputs()

    # Search ipconfig /all — matches adapter description + checks for IP
    low_ip = ipconfig_out.lower()
    in_section = False
    has_ip = False
    for line in low_ip.splitlines():
        stripped = line.strip()
        # Detect adapter section header (contains keyword in description)
        if not line.startswith(" ") and not line.startswith("\t") and stripped:
            if in_section:
                # Previous section matched — return based on IP
                return "Connected" if has_ip else "Disconnected"
            in_section = any(kw in stripped for kw in keywords)
            has_ip = False
            continue
        if in_section:
            if any(m in stripped for m in ("media disconnected", "nośnik odłączony",
                                                "odłączony", "odmowa nośnika")):
                return "Disconnected"
            if "ipv4" in stripped and ":" in stripped:
                addr = stripped.split(":", 1)[1].strip()
                if addr and addr[0].isdigit():
                    has_ip = True
    if in_section:
        return "Connected" if has_ip else "Disconnected"

    # Fallback: netsh interface show interface — matches Name only
    for line in netsh_out.lower().splitlines():
        if any(kw in line for kw in keywords):
            # Check disconnected first (EN: "Disconnected", PL: "Odłączony"/"Rozłączony")
            if any(w in line for w in ("disconnected", "odłącz", "rozłącz")):
                return "Disconnected"
            if any(w in line for w in ("connected", "połącz")):
                return "Connected"
            return "Disconnected"
    return None


def _is_forti_tunnel_active() -> bool:
    """Check if FortiClient VPN adapter has an IP address (= tunnel is up).
    Uses cached ipconfig /all output."""
    status = _check_adapter_status("fortinet ssl", "fortissl")
    return status == "Connected"


# ------------------------------------------------------------------ #
# Open FortiClient GUI (simple — no GUI automation)                    #
# ------------------------------------------------------------------ #

_FORTI_LNK = r"C:\Users\Public\Desktop\FortiClient VPN.lnk"


def _open_forticlient_gui(app_path: str = "") -> tuple[bool, str]:
    """Open FortiClient GUI via desktop shortcut through explorer.exe.
    explorer.exe = clean process, no inherited PyInstaller env."""
    _dbg(f"_open_forticlient_gui(app_path={app_path!r}) lnk_exists={os.path.isfile(_FORTI_LNK)}")
    # Prefer desktop shortcut, fallback to exe — both via explorer.exe for clean env
    target = None
    if os.path.isfile(_FORTI_LNK):
        target = _FORTI_LNK
    else:
        forti_gui = _find_forticlient_gui(app_path)
        if forti_gui:
            target = forti_gui
    if target:
        try:
            subprocess.Popen(["explorer.exe", target])
            _dbg(f"  -> explorer.exe {target} OK")
            return True, "Otwarto FortiClient — połącz się w oknie klienta."
        except Exception as e:
            _dbg(f"  -> explorer.exe {target} FAIL: {e}")
            return False, f"Błąd uruchamiania FortiClient:\n{e}"
    # Fallback: direct exe
    import ctypes
    forti_gui = _find_forticlient_gui(app_path)
    forti_dir = _forti_install_dir()
    if not forti_gui:
        return False, "Nie znaleziono FortiClient.\nUruchom klienta VPN ręcznie."
    cwd = forti_dir or os.path.dirname(forti_gui)
    try:
        ctypes.windll.shell32.ShellExecuteW(None, "open", forti_gui, None, cwd, 1)
        return True, "Otwarto FortiClient — połącz się w oknie klienta."
    except Exception as e:
        return False, f"Błąd uruchamiania FortiClient:\n{e}"


# ------------------------------------------------------------------ #
# Keyboard simulation for Chromium-based FortiClient (SendInput)       #
# ------------------------------------------------------------------ #

# INPUT structs must include MOUSEINPUT in union for correct sizeof on 64-bit
import ctypes as _ct
from ctypes import wintypes as _wt


class _MOUSEINPUT(_ct.Structure):
    _fields_ = [("dx", _ct.c_long), ("dy", _ct.c_long),
                ("mouseData", _wt.DWORD), ("dwFlags", _wt.DWORD),
                ("time", _wt.DWORD), ("dwExtraInfo", _ct.POINTER(_ct.c_ulong))]


class _KEYBDINPUT(_ct.Structure):
    _fields_ = [("wVk", _wt.WORD), ("wScan", _wt.WORD),
                ("dwFlags", _wt.DWORD), ("time", _wt.DWORD),
                ("dwExtraInfo", _ct.POINTER(_ct.c_ulong))]


class _HARDWAREINPUT(_ct.Structure):
    _fields_ = [("uMsg", _wt.DWORD), ("wParamL", _wt.WORD), ("wParamH", _wt.WORD)]


class _INPUT(_ct.Structure):
    class _U(_ct.Union):
        _fields_ = [("mi", _MOUSEINPUT), ("ki", _KEYBDINPUT), ("hi", _HARDWAREINPUT)]
    _fields_ = [("type", _wt.DWORD), ("u", _U)]


def _send_input_key(vk: int = 0, scan: int = 0, flags: int = 0):
    """Send a single keyboard input event via SendInput."""
    inp = _INPUT(type=1)  # INPUT_KEYBOARD
    inp.u.ki.wVk = vk
    inp.u.ki.wScan = scan
    inp.u.ki.dwFlags = flags
    inp.u.ki.time = 0
    inp.u.ki.dwExtraInfo = None
    _ct.windll.user32.SendInput(1, _ct.byref(inp), _ct.sizeof(_INPUT))


def _type_text(text: str):
    """Type text via SendInput unicode events."""
    import time
    for ch in text:
        code = ord(ch)
        _send_input_key(scan=code, flags=0x0004)  # KEYEVENTF_UNICODE
        _send_input_key(scan=code, flags=0x0004 | 0x0002)  # + KEYEVENTF_KEYUP
        time.sleep(0.01)


def _press_key(vk: int):
    """Press and release a virtual key."""
    import time
    _send_input_key(vk=vk)
    time.sleep(0.03)
    _send_input_key(vk=vk, flags=0x0002)
    time.sleep(0.05)


def _press_combo(vk_modifier: int, vk_key: int):
    """Press modifier+key combo (e.g. Ctrl+A)."""
    import time
    _send_input_key(vk=vk_modifier)
    time.sleep(0.02)
    _send_input_key(vk=vk_key)
    time.sleep(0.02)
    _send_input_key(vk=vk_key, flags=0x0002)
    time.sleep(0.02)
    _send_input_key(vk=vk_modifier, flags=0x0002)
    time.sleep(0.05)


def _click_at(x: int, y: int):
    """Click at absolute screen coordinates using SendInput."""
    import time
    sx = _ct.windll.user32.GetSystemMetrics(0)  # SM_CXSCREEN
    sy = _ct.windll.user32.GetSystemMetrics(1)  # SM_CYSCREEN
    # Convert to normalized 0-65535 coords
    nx = int(x * 65535 / sx)
    ny = int(y * 65535 / sy)
    inp = _INPUT(type=0)  # INPUT_MOUSE
    inp.u.mi.dx = nx
    inp.u.mi.dy = ny
    inp.u.mi.dwFlags = 0x0001 | 0x8000 | 0x0002  # MOVE|ABSOLUTE|LEFTDOWN
    inp.u.mi.mouseData = 0
    inp.u.mi.time = 0
    inp.u.mi.dwExtraInfo = None
    _ct.windll.user32.SendInput(1, _ct.byref(inp), _ct.sizeof(_INPUT))
    time.sleep(0.05)
    inp.u.mi.dwFlags = 0x0001 | 0x8000 | 0x0004  # MOVE|ABSOLUTE|LEFTUP
    _ct.windll.user32.SendInput(1, _ct.byref(inp), _ct.sizeof(_INPUT))
    time.sleep(0.1)


def _wait_forticlient_window(timeout: float = 10.0):
    """Wait for visible FortiClient window. Returns hwnd or None."""
    import time
    try:
        import win32gui
    except ImportError:
        return None

    deadline = time.time() + timeout
    while time.time() < deadline:
        result = [None]
        def cb(hwnd, _):
            if not win32gui.IsWindowVisible(hwnd):
                return True
            title = win32gui.GetWindowText(hwnd)
            if title and "FortiClient" in title and "Authentication" not in title:
                result[0] = hwnd
                return False
            return True
        try:
            win32gui.EnumWindows(cb, None)
        except Exception:
            pass
        if result[0]:
            return result[0]
        time.sleep(0.5)
    return None


def _autofill_forticlient(login: str, password: str, profile_name: str = ""):
    """Auto-fill FortiClient Free GUI fields via keyboard simulation.
    Runs in a background thread so it doesn't block UI.
    Uses AttachThreadInput for proper focus + correct INPUT struct size.
    FortiClient tab order: VPN Name dropdown → Username → Password → Connect
    """
    import time
    import threading

    VK_TAB = 0x09
    VK_RETURN = 0x0D
    VK_CONTROL = 0x11

    def _fill():
        _dbg(f"_autofill: waiting for window (profile={profile_name!r})")
        hwnd = _wait_forticlient_window(timeout=10.0)
        if not hwnd:
            _dbg("_autofill: window not found, aborting")
            return

        try:
            import win32gui
            import win32process
            import win32api

            # Attach thread input for proper keyboard focus
            fc_tid, _ = win32process.GetWindowThreadProcessId(hwnd)
            our_tid = win32api.GetCurrentThreadId()
            _ct.windll.user32.AttachThreadInput(our_tid, fc_tid, True)

            win32gui.ShowWindow(hwnd, 9)  # SW_RESTORE
            win32gui.SetForegroundWindow(hwnd)
        except Exception as e:
            _dbg(f"_autofill: focus error: {e}")

        time.sleep(1.5)  # let FC render fully

        _dbg("_autofill: starting keyboard input")

        # Click on VPN Name dropdown area — press Tab to focus it first
        _press_key(VK_TAB)
        time.sleep(0.3)

        # Type profile name to search/select in dropdown
        if profile_name:
            # Open dropdown, type to filter
            _press_key(0x20)  # VK_SPACE to open dropdown
            time.sleep(0.5)
            _type_text(profile_name)
            time.sleep(0.3)
            _press_key(VK_RETURN)  # Select
            time.sleep(0.5)

        # Tab twice — first Tab hits hamburger menu, second reaches Username
        _press_key(VK_TAB)
        time.sleep(0.2)
        _press_key(VK_TAB)
        time.sleep(0.3)

        # Select all + type login (handles case when login is pre-filled)
        if login:
            _press_combo(VK_CONTROL, ord('A'))
            time.sleep(0.1)
            _type_text(login)
            time.sleep(0.3)

        # Tab to Password field
        _press_key(VK_TAB)
        time.sleep(0.3)

        # Type password
        if password:
            _type_text(password)
            time.sleep(0.3)

        # Enter to Connect
        _press_key(VK_RETURN)
        _dbg("_autofill: pressed Connect")

        # Detach thread
        try:
            _ct.windll.user32.AttachThreadInput(our_tid, fc_tid, False)
        except Exception:
            pass

        _dbg("_autofill: done")

    t = threading.Thread(target=_fill, daemon=True)
    t.start()


def _auto_disconnect_forticlient():
    """Auto-click Disconnect in FortiClient GUI and close the window.
    When connected: Tab order is VPN Name → hamburger → Disconnect button.
    """
    import time
    import threading

    VK_TAB = 0x09
    VK_RETURN = 0x0D
    VK_F4 = 0x73
    VK_ALT = 0x12  # VK_MENU

    def _do():
        _dbg("_auto_disconnect: waiting for window")
        hwnd = _wait_forticlient_window(timeout=10.0)
        if not hwnd:
            _dbg("_auto_disconnect: window not found")
            return

        try:
            import win32gui
            import win32process
            import win32api

            fc_tid, _ = win32process.GetWindowThreadProcessId(hwnd)
            our_tid = win32api.GetCurrentThreadId()
            _ct.windll.user32.AttachThreadInput(our_tid, fc_tid, True)
            win32gui.ShowWindow(hwnd, 9)
            win32gui.SetForegroundWindow(hwnd)
        except Exception as e:
            _dbg(f"_auto_disconnect: focus error: {e}")

        time.sleep(1.5)

        # Tab once to Disconnect button
        _press_key(VK_TAB)
        time.sleep(0.3)

        # Press Enter on Disconnect
        _press_key(VK_RETURN)
        _dbg("_auto_disconnect: pressed Disconnect")

        # Wait for disconnect to process, then close window
        time.sleep(2.0)
        _press_combo(VK_ALT, VK_F4)
        _dbg("_auto_disconnect: closed window")

        try:
            _ct.windll.user32.AttachThreadInput(our_tid, fc_tid, False)
        except Exception:
            pass

    t = threading.Thread(target=_do, daemon=True)
    t.start()


def _autofill_stormshield(server: str, port: str, login: str, password: str):
    """Auto-fill Stormshield SSL VPN Client (Qt5).
    Focus starts on Password field. Shift+Tab x2 to Address, then type forward."""
    import time
    try:
        import win32gui
        import win32process
        import win32api

        # Wait for window to appear — retry up to 10s
        hwnd = None
        def cb(h, _):
            nonlocal hwnd
            title = win32gui.GetWindowText(h)
            if "stormshield" in title.lower():
                hwnd = h
                return False
            return True
        for _ in range(20):
            hwnd = None
            win32gui.EnumWindows(cb, None)
            if hwnd and win32gui.IsWindowVisible(hwnd):
                break
            hwnd = None
            time.sleep(0.5)
        if not hwnd:
            _dbg("_autofill_stormshield: window not found")
            return

        _dbg(f"_autofill_stormshield: found hwnd={hwnd}")

        # Activate window and attach input
        tid, _ = win32process.GetWindowThreadProcessId(hwnd)
        our_tid = win32api.GetCurrentThreadId()
        _ct.windll.user32.AttachThreadInput(our_tid, tid, True)
        try:
            win32gui.SetForegroundWindow(hwnd)
        except Exception:
            pass
        time.sleep(1.5)  # wait for window to fully render

        addr = f"{server}:{port}" if port else server

        # Cursor starts on Password. Shift+Tab x2 → Address field
        for _ in range(2):
            _send_input_key(vk=0x10)       # Shift down
            time.sleep(0.03)
            _send_input_key(vk=0x09)       # Tab down
            time.sleep(0.03)
            _send_input_key(vk=0x09, flags=0x0002)  # Tab up
            time.sleep(0.03)
            _send_input_key(vk=0x10, flags=0x0002)  # Shift up
            time.sleep(0.1)

        # Now on Address field
        if addr:
            _press_combo(0x11, 0x41)  # Ctrl+A
            time.sleep(0.05)
            _type_text(addr)
            time.sleep(0.15)

        _press_key(0x09)  # Tab → Login
        time.sleep(0.15)
        if login:
            _press_combo(0x11, 0x41)  # Ctrl+A
            time.sleep(0.05)
            _type_text(login)
            time.sleep(0.15)

        _press_key(0x09)  # Tab → Password
        time.sleep(0.15)
        if password:
            _type_text(password)

        _ct.windll.user32.AttachThreadInput(our_tid, tid, False)
        _dbg("_autofill_stormshield: done")
    except Exception as e:
        _dbg(f"_autofill_stormshield error: {e}")


def _autofill_native_vpn_window(login: str, password: str, exe_name: str = ""):
    """Auto-fill username/password in a native/modern VPN app.
    First tries WM_SETTEXT on Win32 Edit controls.
    Falls back to SendInput (Tab + typing) for Electron/WPF/modern UIs.
    """
    import time
    import threading

    def _do():
        try:
            import win32gui
            import win32con
            import win32api
            import win32process
        except ImportError:
            return

        _dbg(f"_autofill_native: waiting for window (exe={exe_name!r})")
        app_name = exe_name.replace(".exe", "").lower() if exe_name else ""

        # Wait for the app window to appear (up to 15s)
        hwnd = None
        deadline = time.time() + 15.0
        while time.time() < deadline:
            candidates = []

            def cb(h, _):
                if not win32gui.IsWindowVisible(h):
                    return True
                title = win32gui.GetWindowText(h).lower()
                cls = win32gui.GetClassName(h).lower()
                # Skip HospitalHub itself and browser windows
                if "hospitalhub" in title or "chrome" in cls:
                    return True
                if app_name and app_name in title:
                    candidates.append(h)
                elif any(k in title for k in ("vpn", "barracuda", "credential",
                                               "sonicwall", "pulse", "globalprotect")):
                    candidates.append(h)
                return True

            try:
                win32gui.EnumWindows(cb, None)
            except Exception:
                pass

            if candidates:
                hwnd = candidates[0]
                break
            time.sleep(0.5)

        if not hwnd:
            _dbg("_autofill_native: window not found")
            return

        title = win32gui.GetWindowText(hwnd)
        _dbg(f"_autofill_native: found hwnd={hwnd} title={title!r}")
        time.sleep(1.0)  # let window render

        # Try WM_SETTEXT approach first — works for classic Win32 apps
        edits = []

        def enum_child(child_hwnd, _):
            cls = win32gui.GetClassName(child_hwnd).upper()
            if "EDIT" in cls:
                edits.append(child_hwnd)
            return True

        try:
            win32gui.EnumChildWindows(hwnd, enum_child, None)
        except Exception:
            pass

        _dbg(f"_autofill_native: found {len(edits)} edit fields")

        if len(edits) >= 2:
            # Classic Win32 — fill via WM_SETTEXT
            _dbg("_autofill_native: using WM_SETTEXT approach")
            if login:
                win32gui.SendMessage(edits[0], win32con.WM_SETTEXT, 0, login)
            if password:
                win32gui.SendMessage(edits[1], win32con.WM_SETTEXT, 0, password)

            # Try to click Connect/OK button
            def enum_buttons(child_hwnd, _):
                cls = win32gui.GetClassName(child_hwnd).upper()
                if "BUTTON" in cls:
                    text = win32gui.GetWindowText(child_hwnd).lower()
                    if any(k in text for k in ("connect", "ok", "log", "sign")):
                        win32gui.SendMessage(child_hwnd, win32con.BM_CLICK, 0, 0)
                        _dbg(f"_autofill_native: clicked button '{win32gui.GetWindowText(child_hwnd)}'")
                        return False
                return True

            try:
                win32gui.EnumChildWindows(hwnd, enum_buttons, None)
            except Exception:
                pass
        else:
            # Modern UI (Electron/WPF/etc.) — use SendInput like FortiClient
            _dbg("_autofill_native: no EDIT fields, using SendInput approach")

            # Activate window with AttachThreadInput
            try:
                fc_tid, _ = win32process.GetWindowThreadProcessId(hwnd)
                our_tid = win32api.GetCurrentThreadId()
                _ct.windll.user32.AttachThreadInput(our_tid, fc_tid, True)
            except Exception:
                pass

            try:
                win32gui.SetForegroundWindow(hwnd)
            except Exception:
                pass
            time.sleep(0.5)

            # Click on dropdown area to set known focus position
            # Dropdown is at ~40% height of the window
            rect = win32gui.GetWindowRect(hwnd)
            wx, wy, wx2, wy2 = rect
            ww = wx2 - wx
            wh = wy2 - wy
            cx = wx + ww // 2
            _click_at(cx, wy + int(wh * 0.40))
            time.sleep(0.3)
            # Press Escape in case dropdown opened
            _press_key(0x1B)  # VK_ESCAPE
            time.sleep(0.2)

            # Now focus is on dropdown — Tab to User Password
            _press_key(0x09)  # VK_TAB
            time.sleep(0.3)
            if login:
                _type_text(login)
                time.sleep(0.2)

            # Tab to Certificate/License Password
            _press_key(0x09)  # VK_TAB
            time.sleep(0.3)
            if password:
                _type_text(password)
                time.sleep(0.8)

            # Enter while still in password field triggers Connect
            _press_key(0x0D)  # VK_RETURN
            time.sleep(0.5)
            _press_key(0x0D)  # VK_RETURN (second)
            _dbg("_autofill_native: SendInput sequence done")

            # Detach thread input
            try:
                _ct.windll.user32.AttachThreadInput(our_tid, fc_tid, False)
            except Exception:
                pass

        _dbg("_autofill_native: done")

    t = threading.Thread(target=_do, daemon=True)
    t.start()


def _copy_to_clipboard(text: str) -> bool:
    """Copy text to clipboard. Returns True on success."""
    try:
        import win32clipboard
        win32clipboard.OpenClipboard()
        win32clipboard.EmptyClipboard()
        win32clipboard.SetClipboardText(text)
        win32clipboard.CloseClipboard()
        return True
    except Exception:
        return False


def _autofill_globalprotect(login: str, password: str, portal: str = ""):
    """Auto-fill GlobalProtect two-step flow:
    Step 1: Portal/profile selection → click Connect
    Step 2: Wait for login/password fields → fill → click Connect
    """
    import time
    import threading

    def _do():
        try:
            import win32gui
            import win32api
            import win32process
        except ImportError:
            return

        _dbg(f"_autofill_gp: starting (portal={portal!r})")

        # Wait for GP window
        hwnd = None
        deadline = time.time() + 15.0
        while time.time() < deadline:
            candidates = []
            def cb(h, _):
                if not win32gui.IsWindowVisible(h):
                    return True
                title = win32gui.GetWindowText(h).lower()
                cls = win32gui.GetClassName(h).lower()
                if "hospitalhub" in title or "chrome" in cls:
                    return True
                if "globalprotect" in title or "pangpa" in cls.lower():
                    candidates.append(h)
                return True
            try:
                win32gui.EnumWindows(cb, None)
            except Exception:
                pass
            if candidates:
                hwnd = candidates[0]
                break
            time.sleep(0.5)

        if not hwnd:
            _dbg("_autofill_gp: window not found")
            return

        _dbg(f"_autofill_gp: found hwnd={hwnd} title={win32gui.GetWindowText(hwnd)!r}")
        time.sleep(1.0)

        # Activate window
        try:
            fc_tid, _ = win32process.GetWindowThreadProcessId(hwnd)
            our_tid = win32api.GetCurrentThreadId()
            _ct.windll.user32.AttachThreadInput(our_tid, fc_tid, True)
        except Exception:
            pass
        try:
            win32gui.SetForegroundWindow(hwnd)
        except Exception:
            pass
        time.sleep(0.5)

        # Step 1: Portal already selected — just press Enter to Connect
        rect = win32gui.GetWindowRect(hwnd)
        wx, wy, wx2, wy2 = rect
        ww = wx2 - wx
        wh = wy2 - wy
        cx = wx + ww // 2
        _press_key(0x0D)  # VK_RETURN
        _dbg("_autofill_gp: step 1 — clicked Connect on portal screen")

        # Step 2: Wait for login/password screen to appear
        # The window stays the same size, content changes
        time.sleep(3.0)  # wait for connection + screen transition

        # Re-activate window (might have lost focus)
        try:
            win32gui.SetForegroundWindow(hwnd)
        except Exception:
            pass
        time.sleep(0.5)

        # Click on first field area (~40% height — should be username now)
        rect = win32gui.GetWindowRect(hwnd)
        wx, wy, wx2, wy2 = rect
        ww = wx2 - wx
        wh = wy2 - wy
        cx = wx + ww // 2
        _click_at(cx, wy + int(wh * 0.40))
        time.sleep(0.3)

        # Type login
        if login:
            _type_text(login)
            time.sleep(0.2)

        # Tab to password
        _press_key(0x09)  # VK_TAB
        time.sleep(0.3)

        # Type password
        if password:
            _type_text(password)
            time.sleep(0.8)

        # Enter to Connect
        _press_key(0x0D)  # VK_RETURN
        time.sleep(0.5)
        _press_key(0x0D)  # VK_RETURN (second)
        _dbg("_autofill_gp: step 2 — filled credentials and clicked Connect")

        # Detach
        try:
            _ct.windll.user32.AttachThreadInput(our_tid, fc_tid, False)
        except Exception:
            pass

    t = threading.Thread(target=_do, daemon=True)
    t.start()


# ------------------------------------------------------------------ #
# EMS edition: WinForms auth window (WM_SETTEXT — no pyautogui)       #
# ------------------------------------------------------------------ #

def _find_forti_auth_window(timeout: float = 3.0):
    """
    Wait for FortiClient VPN Authentication window (WinForms, EMS edition).
    Returns (hwnd, edits, buttons) or (None, [], []).
    """
    import time
    try:
        import win32gui
    except ImportError:
        return None, [], []

    deadline = time.time() + timeout

    while time.time() < deadline:
        candidates = []

        def _enum_cb(hwnd, results):
            if win32gui.IsWindowVisible(hwnd):
                title = win32gui.GetWindowText(hwnd)
                if "FortiClient" in title and "Authentication" in title:
                    results.append(hwnd)
            return True

        win32gui.EnumWindows(_enum_cb, candidates)

        for hwnd in candidates:
            edits = []
            buttons = []

            def _enum_child(child_hwnd, _):
                cls = win32gui.GetClassName(child_hwnd)
                text = win32gui.GetWindowText(child_hwnd)
                if "EDIT" in cls.upper() and ("WindowsForms" in cls or cls == "Edit"):
                    edits.append((child_hwnd, text))
                elif "BUTTON" in cls.upper() and ("WindowsForms" in cls or cls == "Button"):
                    buttons.append((child_hwnd, text))
                return True

            win32gui.EnumChildWindows(hwnd, _enum_child, None)

            if len(edits) >= 2:
                return hwnd, edits, buttons

        time.sleep(0.5)

    return None, [], []


def _fill_forti_auth_window(login: str, password: str, timeout: float = 3.0) -> tuple[bool, str]:
    """Try to fill FortiClient EMS authentication window via WM_SETTEXT."""
    try:
        import win32gui
        import win32con
    except ImportError:
        return False, ""

    hwnd, edits, buttons = _find_forti_auth_window(timeout=timeout)
    if not hwnd or len(edits) < 2:
        return False, ""

    win32gui.SendMessage(edits[0][0], win32con.WM_SETTEXT, 0, login)
    win32gui.SendMessage(edits[1][0], win32con.WM_SETTEXT, 0, password)
    for btn_hwnd, btn_text in buttons:
        if "onnect" in btn_text and "Cancel" not in btn_text:
            win32gui.SendMessage(btn_hwnd, win32con.BM_CLICK, 0, 0)
            return True, "Łączenie przez FortiClient..."
    return True, "Dane wpisane — kliknij Connect ręcznie."


def fill_forticlient_token(token: str, timeout: float = 15.0) -> tuple[bool, str]:
    """Fill FortiClient GUI Token field (EMS edition, WinForms window)."""
    try:
        import win32gui
        import win32con
    except ImportError:
        return False, "Brak modułu pywin32."

    hwnd, edits, buttons = _find_forti_auth_window(timeout=timeout)
    if not hwnd:
        return False, "Nie znaleziono okna FortiClient z polem Token."
    if len(edits) < 3:
        return False, "Nie znaleziono pola Token."

    token_edit = edits[-1][0]
    win32gui.SendMessage(token_edit, win32con.WM_SETTEXT, 0, token)
    for btn_hwnd, btn_text in buttons:
        if "onnect" in btn_text and "Cancel" not in btn_text:
            win32gui.SendMessage(btn_hwnd, win32con.BM_CLICK, 0, 0)
            return True, "Token wpisany, kliknięto Connect."
    return True, "Token wpisany — kliknij Connect ręcznie."


# ------------------------------------------------------------------ #
# Connect / disconnect                                                 #
# ------------------------------------------------------------------ #

_DEBUG_LOG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "vpn_debug.log")


_DBG_MAX_SIZE = 1_000_000  # 1 MB


def _dbg(msg: str):
    import datetime
    try:
        if os.path.exists(_DEBUG_LOG) and os.path.getsize(_DEBUG_LOG) > _DBG_MAX_SIZE:
            os.replace(_DEBUG_LOG, _DEBUG_LOG + ".old")
        with open(_DEBUG_LOG, "a", encoding="utf-8") as f:
            f.write(f"{datetime.datetime.now()} {msg}\n")
    except Exception:
        pass


def connect(provider: str, server: str, port: str, login: str, password: str,
            group: str = "", domain: str = "",
            app_path: str = "", profile_name: str = "") -> tuple[bool, str]:

    _dbg(f"connect() provider={provider} app_path={app_path!r} profile={profile_name!r}")

    _last_connected[provider] = profile_name or ""
    _dbg(f"  _last_connected[{provider}] set to {_last_connected[provider]!r}")

    if provider == "FortiClient":
        import threading

        # Fast path: check if FortiClient GUI is already open
        fc_hwnd = _wait_forticlient_window(timeout=0.5)
        if fc_hwnd:
            _dbg("  fast-path: FortiClient window already open, bringing to front")
            try:
                import win32gui
                win32gui.ShowWindow(fc_hwnd, 9)  # SW_RESTORE
                win32gui.SetForegroundWindow(fc_hwnd)
            except Exception:
                pass
            # Auto-fill in background
            threading.Thread(target=_autofill_forticlient,
                             args=(login, password, profile_name),
                             daemon=True).start()
            return True, "FortiClient — wypełniam dane..."

        # Check for EMS auth window (instant check — no waiting)
        ok, msg = _fill_forti_auth_window(login, password, timeout=0.1)
        if ok:
            return True, msg

        # CLI (EMS/ZTNA) — non-blocking Popen
        cli_ok = _is_fortivpn_cli_supported(app_path)
        _dbg(f"  cli_supported={cli_ok} profile={profile_name!r}")
        if cli_ok and profile_name:
            fortivpn = _find_fortivpn(app_path)
            cmd = [fortivpn, "--cli", "--connect", "--tunnel", profile_name]
            if login:
                cmd += ["--username", login]
            if password:
                cmd += ["--password", password]
            cmd.append("--savecredentials")
            _dbg(f"  CLI Popen: {cmd[0]} (profile={profile_name!r})")
            try:
                subprocess.Popen(cmd,
                                 startupinfo=_hidden_startupinfo(),
                                 creationflags=_NO_WINDOW)
                return True, f"Łączenie z '{profile_name}'..."
            except Exception:
                pass

        # Legacy FortiSSLVPNclient.exe
        exe = find_executable(provider)
        if exe:
            addr = f"{server}:{port}" if port else server
            cmd = [exe, "connect", "-s", addr, "-u", login]
            if password:
                cmd += ["-p", password]
            try:
                subprocess.Popen(cmd, creationflags=_NO_WINDOW)
                return True, "Łączenie z FortiClient (legacy)..."
            except Exception:
                pass

        # Open GUI + auto-fill in background
        ok, msg = _open_forticlient_gui(app_path)
        if ok:
            threading.Thread(target=_autofill_forticlient,
                             args=(login, password, profile_name),
                             daemon=True).start()
            return True, "Otwarto FortiClient — wypełniam dane..."
        return ok, msg

    elif provider == "GlobalProtect":
        exe = app_path if (app_path and os.path.isfile(app_path)) else find_executable(provider)
        if not exe:
            return False, "Nie znaleziono GlobalProtect.\nSprawdź instalację lub uruchom ręcznie."
        gp_dir = os.path.dirname(exe)
        # Check if CLI version exists (globalprotect.exe — newer GP 5.x+)
        gp_cli = os.path.join(gp_dir, "globalprotect.exe")
        if os.path.isfile(gp_cli):
            cmd = [gp_cli, "connect", "--portal", server or profile_name]
            if login:
                cmd += ["--username", login]
            if password:
                cmd += ["--password", password]
            _dbg(f"GlobalProtect CLI: connect --portal {server or profile_name}")
            try:
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=30,
                                        startupinfo=_hidden_startupinfo(),
                                        creationflags=_NO_WINDOW)
                out = (result.stdout or "").strip()
                _dbg(f"GlobalProtect CLI result: rc={result.returncode} out={out!r}")
                if result.returncode == 0 or "connect" in out.lower():
                    _last_connected[provider] = profile_name or ""
                    return True, f"Łączenie GlobalProtect ({profile_name or server})..."
            except Exception as e:
                _dbg(f"GlobalProtect CLI exception: {e}")
        # GUI approach: just open PanGPA.exe (user fills manually, can copy password)
        _last_connected[provider] = profile_name or ""
        try:
            os.startfile(exe)
            return True, f"Otwarto GlobalProtect — użyj 📋 by skopiować hasło."
        except Exception as e:
            return False, f"Błąd uruchamiania GlobalProtect:\n{e}"

    elif provider == "SonicWall NetExtender":
        # Open NetExtender GUI (never launch nxcli/NECLI as GUI)
        gui_exe = None
        # If app_path is nxcli/NECLI, find NetExtender.exe next to it
        if app_path and os.path.isfile(app_path):
            base = os.path.basename(app_path).lower()
            if base in ("nxcli.exe", "necli.exe"):
                gui = os.path.join(os.path.dirname(app_path), "NetExtender.exe")
                if os.path.isfile(gui):
                    gui_exe = gui
            else:
                gui_exe = app_path
        if not gui_exe:
            cli = _find_netextender_cli("")
            if cli:
                gui = os.path.join(os.path.dirname(cli), "NetExtender.exe")
                if os.path.isfile(gui):
                    gui_exe = gui
        if gui_exe:
            running = _is_process_running("NetExtender.exe")
            has_window = _has_visible_window("netextender") if running else False
            # Stuck state (e.g. GDI+ error): process runs, no visible window.
            # Kill stale instance before relaunching — don't message a dead hwnd.
            if running and not has_window:
                try:
                    subprocess.run(["taskkill", "/F", "/IM", "NetExtender.exe"],
                                   capture_output=True, timeout=5,
                                   startupinfo=_hidden_startupinfo(),
                                   creationflags=_NO_WINDOW)
                except Exception:
                    pass
                import time; time.sleep(0.4)
                running = False
            if running and has_window:
                if _show_existing_window("netextender"):
                    return True, "Przywrócono okno NetExtender."
            try:
                os.startfile(gui_exe)
                return True, "Otwarto NetExtender."
            except Exception as e:
                return False, f"Błąd:\n{e}"
        return False, "Nie znaleziono NetExtender."

    elif provider == "Hillstone Secure Connect":
        exe = app_path if (app_path and os.path.isfile(app_path)) else _find_hillstone_exe()
        exe_name = os.path.basename(exe) if exe else "HillstoneSecureConnect.exe"
        if exe_name and _is_process_running(exe_name):
            # Qt app in tray — simulate tray icon double-click (goes through
            # Qt event loop, won't freeze). SC_RESTORE causes frozen windows.
            if _activate_qt_tray_icon(exe_name):
                import time; time.sleep(1)
                return True, "Przywrócono okno Hillstone."
            # All restore methods failed — do NOT launch second instance
            return True, "Hillstone działa w trayu — kliknij ikonę w zasobniku."
        # Not running — launch exe
        if exe:
            try:
                os.startfile(exe)
                return True, "Uruchomiono Hillstone Secure Connect."
            except Exception as e:
                return False, f"Błąd uruchamiania:\n{e}"
        return False, "Hillstone — uruchom klienta ręcznie."

    elif provider == "Stormshield":
        _last_connected[provider] = server or profile_name or ""
        exe = app_path if (app_path and os.path.isfile(app_path)) else None
        exe_name = os.path.basename(exe) if exe else "sslvpn_client.exe"

        def _storm_show_and_fill():
            """Activate tray icon (Qt5 shows window itself) then bring to front."""
            import time
            if _activate_qt_tray_icon(exe_name):
                time.sleep(1.5)
                # Window already visible via Qt — just bring to front (no ShowWindow!)
                _bring_window_to_front("stormshield")
                if login or password:
                    time.sleep(0.5)
                    _autofill_stormshield(server, port, login, password)
                return True
            return False

        # If window is already visible — just bring to front
        try:
            import win32gui
            _found = []
            def _cb(h, _):
                t = win32gui.GetWindowText(h)
                if t and "stormshield" in t.lower() and win32gui.IsWindowVisible(h):
                    _found.append(h)
                return True
            win32gui.EnumWindows(_cb, None)
            if _found:
                _bring_window_to_front("stormshield")
                if login or password:
                    import time; time.sleep(0.5)
                    _autofill_stormshield(server, port, login, password)
                return True, "Przywrócono Stormshield + wypełniono."
        except Exception:
            pass

        # Window hidden (in tray) or not found — try tray icon activation
        if _is_process_running(exe_name):
            if _storm_show_and_fill():
                return True, "Przywrócono Stormshield + wypełniono."
            # Tray activation failed — kill and restart
            try:
                subprocess.run(["taskkill", "/F", "/IM", exe_name],
                    capture_output=True, timeout=5,
                    startupinfo=_hidden_startupinfo(),
                    creationflags=_NO_WINDOW)
                import time; time.sleep(1)
            except Exception:
                pass

        # Process not running — launch, wait for tray icon, then activate it.
        # NEVER use ShowWindow on Qt5 — causes white/blank window.
        # Let Qt show the window itself via tray icon double-click simulation.
        # Use subprocess.Popen instead of os.startfile — startfile may open the
        # parent folder instead of running the exe (Windows shell association quirk).
        if exe:
            try:
                subprocess.Popen([exe],
                                 startupinfo=_hidden_startupinfo(),
                                 creationflags=subprocess.CREATE_NEW_PROCESS_GROUP)
                import time; time.sleep(4)
                if _storm_show_and_fill():
                    return True, "Uruchomiono Stormshield."
                # Tray activation failed — window might need more time
                time.sleep(2)
                if _storm_show_and_fill():
                    return True, "Uruchomiono Stormshield."
                return True, "Stormshield uruchomiony — kliknij ikonę w trayu."
            except Exception as e:
                return False, f"Błąd uruchamiania:\n{e}"
        return False, "Stormshield — uruchom klienta ręcznie."

    elif provider == "Barracuda":
        _last_connected[provider] = profile_name or ""
        # Try app_path first (direct exe launch + autofill)
        exe = app_path if (app_path and os.path.isfile(app_path)) else None
        if exe:
            try:
                os.startfile(exe)
                if login or password:
                    _autofill_native_vpn_window(login, password, os.path.basename(exe))
                return True, f"Łączenie {profile_name or provider}..."
            except Exception as e:
                return False, f"Błąd uruchamiania:\n{e}"
        # Fallback: rasdial (server or profile_name as connection name)
        # Note: rasdial requires password as CLI arg — Windows API limitation.
        # CREATE_NO_WINDOW + capture_output mitigate exposure.
        conn_name = server or profile_name
        if conn_name:
            try:
                cmd = ["rasdial", conn_name, login, password]
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=15,
                                        startupinfo=_hidden_startupinfo(),
                                        creationflags=_NO_WINDOW)
                if result.returncode == 0:
                    return True, "Połączono przez rasdial."
                return False, f"rasdial nie powiodło się:\n{result.stderr or result.stdout}"
            except FileNotFoundError:
                return False, "rasdial niedostępny."
            except Exception as e:
                return False, f"Błąd:\n{e}"
        return False, "Podaj ścieżkę do klienta VPN lub nazwę połączenia."

    # Generic handler for custom providers — just launch the exe
    exe = app_path if (app_path and os.path.isfile(app_path)) else None
    if exe:
        try:
            os.startfile(exe)
            return True, f"Uruchomiono {provider}."
        except Exception as e:
            return False, f"Błąd uruchamiania {provider}:\n{e}"

    return False, f"Nieobsługiwany provider: {provider}"


def disconnect(provider: str, server: str = "",
               app_path: str = "", profile_name: str = "") -> tuple[bool, str]:

    if provider == "FortiClient":
        _last_connected.pop(provider, None)
        if _is_fortivpn_cli_supported(app_path):
            fortivpn = _find_fortivpn(app_path)
            cmd = [fortivpn, "--cli", "--disconnect"]
            if profile_name:
                cmd += ["--tunnel", profile_name]
            try:
                subprocess.run(cmd, capture_output=True, text=True, timeout=15,
                               startupinfo=_hidden_startupinfo(),
                               creationflags=_NO_WINDOW)
                return True, "Rozłączanie FortiClient..."
            except Exception:
                pass

        exe = find_executable(provider)
        if exe:
            try:
                subprocess.Popen([exe, "disconnect"], creationflags=_NO_WINDOW)
                return True, "Rozłączanie FortiClient..."
            except Exception:
                pass

        # Free edition — open GUI and auto-click Disconnect
        ok, msg = _open_forticlient_gui(app_path)
        if ok:
            _auto_disconnect_forticlient()
            return True, "Rozłączanie FortiClient..."
        return False, "Rozłącz ręcznie w kliencie VPN."

    elif provider == "SonicWall NetExtender":
        _last_connected.pop(provider, None)
        return True, "Rozłącz ręcznie w kliencie NetExtender."

    elif provider == "GlobalProtect":
        _last_connected.pop(provider, None)
        exe = app_path if (app_path and os.path.isfile(app_path)) else find_executable(provider)
        gp_dir = os.path.dirname(exe) if exe else ""
        gp_cli = os.path.join(gp_dir, "globalprotect.exe") if gp_dir else ""
        if gp_cli and os.path.isfile(gp_cli):
            try:
                result = subprocess.run([gp_cli, "disconnect"],
                                        capture_output=True, text=True, timeout=15,
                                        startupinfo=_hidden_startupinfo(),
                                        creationflags=_NO_WINDOW)
                return True, "Rozłączanie GlobalProtect..."
            except Exception:
                pass
        return False, "Rozłącz ręcznie w kliencie GlobalProtect."

    elif provider == "Stormshield":
        _last_connected.pop(provider, None)
        exe = app_path if (app_path and os.path.isfile(app_path)) else None
        exe_name = os.path.basename(exe) if exe else "sslvpn_client.exe"
        # Check if window is already visible — just bring to front
        restored = False
        try:
            import win32gui as _wg
            _vis = []
            def _dcb(h, _):
                t = _wg.GetWindowText(h)
                if t and "stormshield" in t.lower() and _wg.IsWindowVisible(h):
                    _vis.append(h)
                return True
            _wg.EnumWindows(_dcb, None)
            if _vis:
                _bring_window_to_front("stormshield")
                restored = True
        except Exception:
            pass
        # Window hidden — activate via tray icon (Qt5 shows it properly)
        if not restored:
            if _activate_qt_tray_icon(exe_name):
                import time; time.sleep(1.5)
                _bring_window_to_front("stormshield")
                restored = True
        if restored:
            import threading
            def _disconnect_storm():
                import time
                time.sleep(1.5)
                _press_key(0x0D)  # Enter = disconnect
            threading.Thread(target=_disconnect_storm, daemon=True).start()
            return True, "Rozłączanie Stormshield..."
        return False, "Rozłącz ręcznie w kliencie Stormshield."

    elif provider == "Hillstone Secure Connect":
        _last_connected.pop(provider, None)
        return True, "Rozłącz ręcznie w aplikacji Hillstone Secure Connect."

    elif provider == "Barracuda":
        _last_connected.pop(provider, None)
        return True, "Rozłącz ręcznie w kliencie Barracuda."

    # Generic custom provider
    _last_connected.pop(provider, None)
    return True, f"Rozłącz ręcznie w kliencie {provider}."


# ------------------------------------------------------------------ #
# Status                                                               #
# ------------------------------------------------------------------ #

def get_status(provider: str, app_path: str = "",
               profile_name: str = "", server: str = "") -> str | None:
    """Returns 'Connected', 'Disconnected', 'Connecting', or None."""

    if provider == "FortiClient":
        _dbg(f"get_status: FortiClient profile={profile_name!r} server={server!r}")
        # CLI (EMS/ZTNA)
        if _is_fortivpn_cli_supported(app_path) and profile_name:
            fortivpn = _find_fortivpn(app_path)
            try:
                result = subprocess.run(
                    [fortivpn, "--cli", "--status", "--tunnel", profile_name],
                    capture_output=True, text=True, timeout=5,
                    startupinfo=_hidden_startupinfo(),
                    creationflags=_NO_WINDOW,
                )
                out = (result.stdout or "").strip()
                if "::" in out:
                    raw = out.split("::", 1)[1].strip().lower()
                    if raw == "connected":
                        return "Connected"
                    elif "connecting" in raw:
                        return "Connecting"
                    else:
                        return "Disconnected"
            except Exception:
                pass

        # Primary: ipconfig adapter check (works for older/free FortiClient)
        if _is_forti_tunnel_active():
            last = _last_connected.get("FortiClient", "")
            if last:
                if profile_name and profile_name != last:
                    return "Disconnected"
                return "Connected"
            # No record which profile is connected — require IP match.
            # Without server data we can't verify → safer to show Disconnected
            # than to light up every profile row during disconnect grace window.
            if not server:
                return "Disconnected"
            connected_ip = _get_vpn_connected_server_ip("FortiSSLVPNdaemon.exe")
            if not connected_ip:
                return "Disconnected"
            profile_ip = _resolve_server(server.split(":")[0])
            if connected_ip != profile_ip:
                return "Disconnected"
            return "Connected"

        # Secondary: FortiSSLVPNdaemon.exe ESTABLISHED connection = tunnel up
        # (EMS/ZTNA editions may not create a named adapter in ipconfig)
        connected_ip = _get_vpn_connected_server_ip("FortiSSLVPNdaemon.exe")
        if connected_ip:
            last = _last_connected.get("FortiClient", "")
            if last:
                if profile_name and profile_name != last:
                    return "Disconnected"
                return "Connected"
            if not server:
                return "Disconnected"
            profile_ip = _resolve_server(server.split(":")[0])
            if connected_ip != profile_ip:
                return "Disconnected"
            return "Connected"

        # Tertiary: daemon log (for Connecting state detection)
        log_status = _get_status_from_log()
        if log_status == "Connecting":
            return "Connecting"

        if is_forticlient_installed():
            return "Disconnected"

    elif provider == "GlobalProtect":
        exe = app_path if (app_path and os.path.isfile(app_path)) else find_executable(provider)
        gp_dir = os.path.dirname(exe) if exe else ""
        gp_cli = os.path.join(gp_dir, "globalprotect.exe") if gp_dir else ""
        if gp_cli and os.path.isfile(gp_cli):
            try:
                result = subprocess.run([gp_cli, "show", "--status"],
                                        capture_output=True, text=True, timeout=5,
                                        startupinfo=_hidden_startupinfo(),
                                        creationflags=_NO_WINDOW)
                out = (result.stdout or "").strip().lower()
                _dbg(f"GlobalProtect status: {out!r}")
                if "connected" in out and "not" not in out:
                    return "Connected"
                elif "connecting" in out:
                    return "Connecting"
                elif "disconnect" in out or "not connected" in out:
                    return "Disconnected"
            except Exception:
                pass
        # Fallback: check netsh for PANGP adapter
        status = _check_adapter_status("pangp", "globalprotect", "palo")
        if status == "Connected":
            return status
        # Log-based fallback (consumer GP installs without CLI, e.g. C:\GlobalProtect)
        log_status = _get_globalprotect_status_from_log(gp_dir)
        if log_status:
            return log_status
        if status:
            return status
        return "Disconnected"

    elif provider == "Barracuda":
        status = _check_adapter_status("nacvpn", "barracuda")
        if status:
            last = _last_connected.get("Barracuda", "")
            if last and profile_name != last:
                return "Disconnected"
            return status
        # Fallback: session-based
        last = _last_connected.get("Barracuda", "")
        if last and profile_name == last:
            return "Connected"
        return "Disconnected"

    elif provider == "Hillstone Secure Connect":
        status = _check_adapter_status("hillstone", "virtualnet")
        if status:
            return status
        return "Disconnected"

    elif provider == "Stormshield":
        # Stormshield tunnels via TAP driver — no TCP connections visible in netstat.
        # Check "stormshield-tap" adapter state + _last_connected (stores server)
        # to distinguish which profile is actually connected.
        last = _last_connected.get("Stormshield", "")
        profile_key = server or profile_name or ""
        status = _check_adapter_status("stormshield-tap")
        if not status or status == "Disconnected":
            status = _check_adapter_status("stormshield ssl vpn")
        if status == "Connected":
            if not last:
                # Connected externally (not via HospitalHub) — can't tell which profile
                return None
            if profile_key and profile_key != last:
                return "Disconnected"
            return "Connected"
        if status == "Disconnected":
            return "Disconnected"
        return None

    elif provider == "SonicWall NetExtender":
        # Primary: adapter check (fast, cached — no subprocess per poll)
        status = _check_adapter_status("sonicwall", "netextender")
        if status:
            return status
        return "Disconnected"

    # Remote desktop tools — always running in background, status not meaningful
    _REMOTE_DESKTOP_KEYWORDS = ("anydesk", "teamviewer", "rustdesk", "supremo",
                                "ammyy", "ultraviewer", "parsec", "splashtop",
                                "remotepc", "nomachine", "chrome remote")
    provider_lower = provider.lower()
    if any(kw in provider_lower for kw in _REMOTE_DESKTOP_KEYWORDS):
        return None

    # Generic custom provider: check if exe process is running
    exe = app_path if app_path else None
    if exe:
        exe_name = os.path.basename(exe)
        if _is_process_running(exe_name):
            return "Connected"
        return "Disconnected"

    return None


# ------------------------------------------------------------------ #
# Monitored connect (for 2FA stdout detection)                        #
# ------------------------------------------------------------------ #

def connect_monitored(provider: str, server: str, port: str, login: str, password: str,
                      group: str = "", domain: str = "",
                      app_path: str = "", profile_name: str = "",
                      token: str = "") -> tuple[bool, str, object]:
    """
    Like connect() but returns (ok, msg, process) where process is a Popen
    whose stdout can be monitored for 2FA prompts. process is None when
    interactive monitoring is not available.
    """
    if provider == "FortiClient" and _is_fortivpn_cli_supported(app_path):
        fortivpn = _find_fortivpn(app_path)
        cmd = [fortivpn, "--cli", "--connect", "--tunnel", profile_name]
        if login:
            cmd += ["--username", login]
        if password:
            cmd += ["--password", password]
        if token:
            cmd += ["--token", token]
        cmd.append("--savecredentials")
        try:
            process = subprocess.Popen(
                cmd,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                startupinfo=_hidden_startupinfo(),
                creationflags=_NO_WINDOW,
            )
            return True, f"Łączenie z '{profile_name}'...", process
        except Exception as e:
            return False, f"Błąd FortiVPN.exe:\n{e}", None

    # NetExtender: open GUI directly
    if provider == "SonicWall NetExtender":
        ok, msg = connect(provider, server, port, login, password, group, domain,
                          app_path, profile_name)
        return ok, msg, None

    ok, msg = connect(provider, server, port, login, password, group, domain,
                      app_path, profile_name)
    return ok, msg, None


# ------------------------------------------------------------------ #
# Launch VPN client app                                                #
# ------------------------------------------------------------------ #

def launch_app(app_path: str) -> tuple[bool, str]:
    _dbg(f"launch_app(app_path={app_path!r})")
    if not app_path:
        return False, "Nie podano ścieżki do aplikacji."
    if not os.path.isfile(app_path):
        return False, f"Nie znaleziono pliku:\n{app_path}"
    try:
        app_name = os.path.basename(app_path).lower()
        if "forticlient" in app_name:
            return _open_forticlient_gui(app_path)
        # If app_path is nxcli/NECLI, launch NetExtender.exe GUI instead
        if app_name in ("nxcli.exe", "necli.exe"):
            gui = os.path.join(os.path.dirname(app_path), "NetExtender.exe")
            if os.path.isfile(gui):
                os.startfile(gui)
                return True, "Uruchomiono NetExtender."
            return False, "Nie znaleziono NetExtender.exe obok nxcli."
        os.startfile(app_path)
        return True, "Uruchomiono klienta VPN."
    except Exception as e:
        return False, f"Błąd uruchamiania:\n{e}"
