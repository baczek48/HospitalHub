"""VPN connection launcher — calls CLI tools for each supported provider."""

import os
import re
import subprocess
import threading
import time
import winreg

def _validate_exe(exe):
    """Sanity check executable path before launching. Returns (ok, error_msg)."""
    if not exe:
        return False, "Nie podano ścieżki do executable."
    if not os.path.exists(exe):
        return False, f"Plik nie istnieje: {exe}"
    if os.path.isdir(exe):
        return False, f"Ścieżka wskazuje na katalog, nie plik: {exe}"
    if not os.path.isfile(exe):
        return False, f"Ścieżka nie jest zwykłym plikiem: {exe}"
    return True, ""


def _wait_for_process(exe_name: str, timeout: float = 3.0) -> bool:
    """Poll tasklist until `exe_name` is present or timeout elapses."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if _is_process_running(exe_name):
            return True
        time.sleep(0.25)
    return False

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

def _clean_pyinstaller_env() -> dict:
    """Return os.environ with PyInstaller bootloader vars stripped.
    Electron apps (FortiClient) crash when inheriting _MEIPASS-tainted env —
    their Logger fails with 'Cannot read properties of null (reading TraceLog)'.
    Strip _MEI* / _PYI* so child processes see a clean shell-like environment."""
    env = os.environ.copy()
    for k in list(env.keys()):
        if k.startswith("_MEI") or k.startswith("_PYI"):
            env.pop(k, None)
    return env

_SHELLEXEC_ERRORS = {
    0: "SE_ERR_OOM (out of memory)",
    2: "ERROR_FILE_NOT_FOUND",
    3: "ERROR_PATH_NOT_FOUND",
    5: "ERROR_ACCESS_DENIED",
    8: "SE_ERR_OOM (insufficient memory)",
    11: "ERROR_BAD_FORMAT",
    26: "SE_ERR_SHARE",
    27: "SE_ERR_ASSOCINCOMPLETE",
    28: "SE_ERR_DDETIMEOUT",
    29: "SE_ERR_DDEFAIL",
    30: "SE_ERR_DDEBUSY",
    31: "SE_ERR_NOASSOC (no application associated)",
    32: "SE_ERR_DLLNOTFOUND",
}

def _shell_launch(exe: str, cwd: str = "", provider: str = "") -> tuple[bool, str]:
    """Launch an exe via ShellExecuteW 'open' — handles UAC elevation prompts
    when the target has a requireAdministrator manifest (Stormshield SN VPN,
    Hillstone Secure Connect). Plain subprocess.Popen fails silently with
    ERROR_ELEVATION_REQUIRED on those when caller is non-admin."""
    import ctypes
    if not cwd:
        cwd = os.path.dirname(exe) or None
    try:
        # ShellExecuteW returns an HINSTANCE > 32 on success
        rc = ctypes.windll.shell32.ShellExecuteW(None, "open", exe, None, cwd, 1)
        if rc > 32:
            return True, ""
        err_name = _SHELLEXEC_ERRORS.get(rc, f"unknown rc={rc}")
        err = f"ShellExecuteW rc={rc} ({err_name})"
        return False, err
    except Exception as e:
        return False, str(e)

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
# Per-provider last connected profile tracking (avoids cross-provider interference).
# _last_connected holds the legacy single string used by FortiClient and others;
# _last_connected_meta tracks BOTH server and profile_name so that get_status() can
# correctly light up the same logical profile in a different vault that may carry
# only one of those fields (e.g. main vault knows the profile_name but has no server).
_last_connected: dict[str, str] = {}  # provider -> profile_name
_last_connected_meta: dict[str, dict] = {}  # provider -> {"server": str, "profile_name": str}
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
    """Restore a Qt tray window — IN-PROCESS via pywin32.

    Target window lives in a different process, so PostMessage is async
    and cannot freeze our Qt loop. The previous variant shelled out to
    python.exe, which fails on frozen-build deployments (no Python on
    end-user machines → cmd rc=9009)."""
    try:
        import win32gui, win32con
    except ImportError as e:
        return False
    try:
        kw = title_keyword.lower()
        found: list[int] = []

        def _cb(hwnd, _):
            t = win32gui.GetWindowText(hwnd)
            if t and kw in t.lower():
                found.append(hwnd)
            return True

        win32gui.EnumWindows(_cb, None)
        if not found:
            return False
        win32gui.PostMessage(found[0], win32con.WM_SYSCOMMAND,
                             win32con.SC_RESTORE, 0)
        return True
    except Exception as e:
        return False

def _restore_tray_by_process(exe_name: str) -> bool:
    """Restore a tray window owned by `exe_name` — IN-PROCESS via pywin32.

    Skips TrayIcon-message and tooltip helper windows; targets the first
    real top-level window. Sends SC_RESTORE and then attempts to raise it.
    Same rationale as _activate_qt_tray_icon: PostMessage across processes
    is async, so no Qt loop is starved."""
    try:
        import win32gui, win32con, win32process
    except ImportError as e:
        return False
    try:
        r = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {exe_name}", "/NH", "/FO", "CSV"],
            capture_output=True, text=True, timeout=5,
            startupinfo=_hidden_startupinfo(),
            creationflags=_NO_WINDOW,
        )
        pids: set[int] = set()
        for line in (r.stdout or "").strip().split("\n"):
            parts = line.strip().strip('"').split('","')
            if len(parts) >= 2 and parts[0].lower() == exe_name.lower():
                try:
                    pids.add(int(parts[1]))
                except ValueError:
                    pass
        if not pids:
            return False
        wins: list[int] = []

        def _cb(hwnd, _):
            try:
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                if pid in pids:
                    wins.append(hwnd)
            except Exception:
                pass
            return True

        win32gui.EnumWindows(_cb, None)
        if not wins:
            return False
        target = None
        for h in wins:
            try:
                cls = win32gui.GetClassName(h)
                if "TrayIcon" in cls or "tooltip" in cls.lower():
                    continue
                win32gui.PostMessage(h, win32con.WM_SYSCOMMAND,
                                     win32con.SC_RESTORE, 0)
                target = h
                break
            except Exception:
                pass
        if target is None:
            return False
        import time as _time
        _time.sleep(0.5)
        for h in wins:
            try:
                if win32gui.IsWindowVisible(h) and win32gui.GetWindowText(h):
                    win32gui.SetForegroundWindow(h)
                    break
            except Exception:
                pass
        return True
    except Exception as e:
        return False

def _activate_qt_tray_icon(exe_name: str) -> bool:
    """Simulate double-click on a Qt5 system tray icon — IN-PROCESS via pywin32.

    The target tray window is in a different process (Hillstone, Stormshield,
    NetExtender …), so PostMessage is fully async and cannot freeze our own
    Qt event loop. Earlier versions shelled out to a separate python.exe to
    avoid same-process PostMessage freezes — but that path fails on machines
    without a Python interpreter (CMD returns rc=9009 = command not found),
    which is the situation on every end-user laptop running the frozen build.

    Matches both classic 'QTrayIconMessageWindow' and the Qt5-versioned
    'Qt5158TrayIconMessageWindowClass' by substring 'TrayIcon'.
    """
    try:
        import win32gui, win32process
    except ImportError as e:
        return False
    try:
        r = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {exe_name}", "/NH", "/FO", "CSV"],
            capture_output=True, text=True, timeout=5,
            startupinfo=_hidden_startupinfo(),
            creationflags=_NO_WINDOW,
        )
        pids: set[int] = set()
        for line in (r.stdout or "").strip().split("\n"):
            parts = line.strip().strip('"').split('","')
            if len(parts) >= 2 and parts[0].lower() == exe_name.lower():
                try:
                    pids.add(int(parts[1]))
                except ValueError:
                    pass
        if not pids:
            _dbg(f"_activate_qt_tray_icon({exe_name}): no PIDs in tasklist")
            return False
        found: list[int] = []

        def _cb(hwnd, _):
            try:
                _, pid = win32process.GetWindowThreadProcessId(hwnd)
                if pid in pids and "TrayIcon" in win32gui.GetClassName(hwnd):
                    found.append(hwnd)
            except Exception:
                pass
            return True

        win32gui.EnumWindows(_cb, None)
        if not found:
            _dbg(f"_activate_qt_tray_icon({exe_name}): no TrayIcon window "
                 f"for pids={sorted(pids)}")
            return False
        MYWM = 0x8000 + 101            # WM_APP+101 = Qt5 tray callback
        WM_LBUTTONDBLCLK = 0x0203
        win32gui.PostMessage(found[0], MYWM, 0, WM_LBUTTONDBLCLK)
        _dbg(f"_activate_qt_tray_icon({exe_name}): posted to hwnd={found[0]} "
             f"pids={sorted(pids)}")
        return True
    except Exception as e:
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

# ====================================================================== #
# Native Windows API: GetAdaptersAddresses                                 #
# ====================================================================== #
# Zastępuje subprocess'y ipconfig / netsh / PowerShell Get-NetAdapter
# jednym natywnym wywołaniem przez ctypes (~1-5ms, zero spawn'ów procesu).
# To eliminuje mikro-zacięcia UI powodowane wcześniej przez spawn co 5s.

_ADAPTERS_CACHE: tuple[float, list] = (0.0, [])  # (ts, list[dict])
_ADAPTERS_CACHE_TTL = 2.0  # API call jest szybkie, krótki cache OK

def _build_winapi_structs():
    """Lazy build of GetAdaptersAddresses ctypes structs (called once)."""
    import ctypes
    from ctypes import wintypes, POINTER, Structure, c_ulong, c_int, c_ubyte, c_ushort, c_byte, c_wchar_p, c_char_p

    class SOCKADDR(Structure):
        _fields_ = [
            ("sa_family", c_ushort),
            ("sa_data", c_byte * 26),
        ]

    class SOCKET_ADDRESS(Structure):
        _fields_ = [
            ("lpSockaddr", POINTER(SOCKADDR)),
            ("iSockaddrLength", c_int),
        ]

    class IP_ADAPTER_UNICAST_ADDRESS(Structure):
        pass

    IP_ADAPTER_UNICAST_ADDRESS._fields_ = [
        ("Length", c_ulong),
        ("Flags", c_ulong),
        ("Next", POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
        ("Address", SOCKET_ADDRESS),
        ("PrefixOrigin", c_int),
        ("SuffixOrigin", c_int),
        ("DadState", c_int),
        ("ValidLifetime", c_ulong),
        ("PreferredLifetime", c_ulong),
        ("LeaseLifetime", c_ulong),
        ("OnLinkPrefixLength", c_ubyte),
    ]

    # IP_ADAPTER_ADDRESSES_LH (Vista+) — używamy tylko pól nas interesujących,
    # reszta jako padding (c_void_p × N) do wystarczającej długości.
    # Pełna struktura jest długa i ma różne wersje — ale Length, Next, Description,
    # FriendlyName, FirstUnicastAddress, OperStatus są stabilne na Vista+.
    class IP_ADAPTER_ADDRESSES(Structure):
        pass

    # Layout (Vista+, sprawdzony):
    # union { ULONGLONG Alignment; struct { ULONG Length; DWORD IfIndex; }; }
    # PIP_ADAPTER_ADDRESSES Next;
    # PCHAR AdapterName;
    # PIP_ADAPTER_UNICAST_ADDRESS_LH FirstUnicastAddress;
    # PIP_ADAPTER_ANYCAST_ADDRESS_XP FirstAnycastAddress;
    # PIP_ADAPTER_MULTICAST_ADDRESS_XP FirstMulticastAddress;
    # PIP_ADAPTER_DNS_SERVER_ADDRESS_XP FirstDnsServerAddress;
    # PWCHAR DnsSuffix;
    # PWCHAR Description;
    # PWCHAR FriendlyName;
    # BYTE PhysicalAddress[MAX_ADAPTER_ADDRESS_LENGTH=8];
    # ULONG PhysicalAddressLength;
    # ULONG Flags;
    # ULONG Mtu;
    # DWORD IfType;
    # IF_OPER_STATUS OperStatus;  (enum, c_int)
    # ... (więcej pól, ale nieinteresujących)
    IP_ADAPTER_ADDRESSES._fields_ = [
        ("Length", c_ulong),
        ("IfIndex", c_ulong),
        ("Next", POINTER(IP_ADAPTER_ADDRESSES)),
        ("AdapterName", c_char_p),
        ("FirstUnicastAddress", POINTER(IP_ADAPTER_UNICAST_ADDRESS)),
        ("FirstAnycastAddress", ctypes.c_void_p),
        ("FirstMulticastAddress", ctypes.c_void_p),
        ("FirstDnsServerAddress", ctypes.c_void_p),
        ("DnsSuffix", c_wchar_p),
        ("Description", c_wchar_p),
        ("FriendlyName", c_wchar_p),
        ("PhysicalAddress", c_ubyte * 8),
        ("PhysicalAddressLength", c_ulong),
        ("Flags", c_ulong),
        ("Mtu", c_ulong),
        ("IfType", c_ulong),
        ("OperStatus", c_int),
        # Reszta pól jako padding (ZoneIndices, FirstPrefix, TransmitLinkSpeed, ...)
        # Allokujemy duży bufor w wywołaniu, więc nadmiar nie szkodzi.
        ("_padding", c_ubyte * 256),
    ]

    return IP_ADAPTER_ADDRESSES, IP_ADAPTER_UNICAST_ADDRESS

# Windows constants
_AF_INET = 2
_AF_UNSPEC = 0
_ERROR_BUFFER_OVERFLOW = 111
_ERROR_SUCCESS = 0
_GAA_FLAG_SKIP_ANYCAST = 0x0002
_GAA_FLAG_SKIP_MULTICAST = 0x0004
_GAA_FLAG_SKIP_DNS_SERVER = 0x0008
_IF_OPER_STATUS_UP = 1

_winapi_cached_structs = None

def _enumerate_adapters_winapi() -> list:
    """Return [{description, friendly_name, ipv4_addresses, oper_status_up}].

    Zwraca pustą listę gdy API zawiedzie — caller powinien fallback'ować
    na ipconfig/netsh.
    """
    global _winapi_cached_structs
    import ctypes
    from ctypes import POINTER, byref, c_ulong, cast

    try:
        if _winapi_cached_structs is None:
            _winapi_cached_structs = _build_winapi_structs()
        IP_ADAPTER_ADDRESSES, _ = _winapi_cached_structs

        iphlpapi = ctypes.windll.iphlpapi
        get_adapters = iphlpapi.GetAdaptersAddresses
        get_adapters.argtypes = [
            c_ulong, c_ulong, ctypes.c_void_p,
            POINTER(IP_ADAPTER_ADDRESSES), POINTER(c_ulong)
        ]
        get_adapters.restype = c_ulong

        flags = (_GAA_FLAG_SKIP_ANYCAST | _GAA_FLAG_SKIP_MULTICAST
                 | _GAA_FLAG_SKIP_DNS_SERVER)
        size = c_ulong(32768)
        buf = ctypes.create_string_buffer(size.value)
        ret = get_adapters(_AF_INET, flags, None,
                           cast(buf, POINTER(IP_ADAPTER_ADDRESSES)),
                           byref(size))
        if ret == _ERROR_BUFFER_OVERFLOW:
            buf = ctypes.create_string_buffer(size.value)
            ret = get_adapters(_AF_INET, flags, None,
                               cast(buf, POINTER(IP_ADAPTER_ADDRESSES)),
                               byref(size))
        if ret != _ERROR_SUCCESS:
            return []

        result = []
        p = cast(buf, POINTER(IP_ADAPTER_ADDRESSES))
        while p:
            try:
                a = p.contents
            except (ValueError, OSError):
                break
            ipv4 = []
            ua = a.FirstUnicastAddress
            while ua:
                try:
                    sa_ptr = ua.contents.Address.lpSockaddr
                    if sa_ptr:
                        sa = sa_ptr.contents
                        if sa.sa_family == _AF_INET:
                            # sin_addr at offset 4 (after sa_family + sin_port)
                            data = bytes(sa.sa_data[:6])
                            ipv4.append("{}.{}.{}.{}".format(
                                data[2] & 0xFF, data[3] & 0xFF,
                                data[4] & 0xFF, data[5] & 0xFF))
                    ua = ua.contents.Next
                except (ValueError, OSError):
                    break
            result.append({
                "description": (a.Description or "").lower(),
                "friendly_name": (a.FriendlyName or "").lower(),
                "ipv4_addresses": ipv4,
                "oper_status_up": a.OperStatus == _IF_OPER_STATUS_UP,
            })
            p = a.Next
        return result
    except Exception:
        return []

def _get_adapters() -> list:
    """Cached adapter list via Windows API."""
    global _ADAPTERS_CACHE
    import time
    now = time.monotonic()
    with _state_lock:
        if now - _ADAPTERS_CACHE[0] < _ADAPTERS_CACHE_TTL and _ADAPTERS_CACHE[1] is not None:
            return _ADAPTERS_CACHE[1]

    adapters = _enumerate_adapters_winapi()

    with _state_lock:
        _ADAPTERS_CACHE = (now, adapters)
    return adapters

def invalidate_adapter_cache() -> None:
    """Wymuś świeży odczyt adapterów przy najbliższym _check_adapter_status.

    Wywoływane z UI po connect/disconnect — bez tego cache (2s) opóźniałby
    aktualizację statusu o do 2s. Z natywnym API to mała różnica, ale
    natychmiastowa reakcja po akcji użytkownika lepsza niż czekanie.
    """
    global _ADAPTERS_CACHE, _adapter_cache
    with _state_lock:
        _ADAPTERS_CACHE = (0.0, [])
        _adapter_cache = (0.0, "", "")
        _rasdial_cache["ts"] = 0.0
        _rasdial_cache["active"] = set()

# ---------------------------------------------------------------------- #
# Fallback: subprocess-based (gdy WinAPI zawiedzie — rzadkie)              #
# ---------------------------------------------------------------------- #

_adapter_cache: tuple[float, str, str] = (0.0, "", "")  # (ts, ipconfig, netsh)
_ADAPTER_CACHE_TTL = 4.0  # seconds

def _get_adapter_outputs() -> tuple[str, str]:
    """Fallback: ipconfig+netsh subprocess. Wywoływane tylko gdy WinAPI zwróci pusto."""
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
    """Check adapter status using native Windows API (GetAdaptersAddresses).
    Returns 'Connected', 'Disconnected', or None if adapter not found.

    Logika:
      - 'Connected'   = adapter pasuje (description/friendly_name) AND ma IPv4
                        OR (oper_status=Up — łapie Forti IPsec NDIS bez IPv4)
      - 'Disconnected'= adapter pasuje ale brak IPv4 i oper_status != Up
      - None          = żaden adapter nie pasuje do keywords

    Fallback: jeśli WinAPI zwróci pustą listę, spada do ipconfig/netsh.
    """
    adapters = _get_adapters()
    if adapters:
        any_match = False
        any_up_or_ip = False
        for ad in adapters:
            if any(kw in ad["description"] or kw in ad["friendly_name"] for kw in keywords):
                any_match = True
                # Connected = ma IPv4, LUB oper_status=Up (Forti IPsec NDIS bez IPv4)
                if ad["ipv4_addresses"] or ad["oper_status_up"]:
                    any_up_or_ip = True
        if any_match:
            return "Connected" if any_up_or_ip else "Disconnected"
        return None

    # Fallback path — gdy WinAPI zawiedzie (bardzo rzadkie)
    ipconfig_out, netsh_out = _get_adapter_outputs()

    low_ip = ipconfig_out.lower()
    in_section = False
    section_has_ip = False
    section_disconnected = False
    any_match = False
    any_connected = False

    def _finalize_section():
        nonlocal any_connected
        if in_section and section_has_ip and not section_disconnected:
            any_connected = True

    for line in low_ip.splitlines():
        stripped = line.strip()
        if not line.startswith(" ") and not line.startswith("\t") and stripped:
            _finalize_section()
            in_section = any(kw in stripped for kw in keywords)
            if in_section:
                any_match = True
            section_has_ip = False
            section_disconnected = False
            continue
        if in_section:
            if any(m in stripped for m in ("media disconnected", "nośnik odłączony",
                                                "odłączony", "odmowa nośnika")):
                section_disconnected = True
                continue
            if "ipv4" in stripped and ":" in stripped:
                addr = stripped.split(":", 1)[1].strip()
                if addr and addr[0].isdigit():
                    section_has_ip = True
    _finalize_section()
    if any_match:
        return "Connected" if any_connected else "Disconnected"

    for line in netsh_out.lower().splitlines():
        if any(kw in line for kw in keywords):
            if any(w in line for w in ("disconnected", "odłącz", "rozłącz")):
                return "Disconnected"
            if any(w in line for w in ("connected", "połącz")):
                return "Connected"
            return "Disconnected"
    return None

def _is_forti_tunnel_active() -> bool:
    """Check if FortiClient VPN adapter has an IP address (= tunnel is up).
    Uses cached ipconfig /all output.

    Wzorce pokrywają oba tryby FortiClient:
      - SSL VPN: 'Fortinet SSL VPN Virtual Ethernet Adapter' / 'fortissl'
      - IPsec:   'Fortinet Virtual Ethernet Adapter (NDIS x.xx)'
    Samo wykrycie adaptera NIE decyduje, który profil jest 'Connected' —
    to rozstrzyga logika w get_status (match po _last_connected albo IP
    serwera profilu vs IP aktualnie utrzymywanego połączenia).
    """
    status = _check_adapter_status("fortinet ssl", "fortissl", "fortinet virtual")
    return status == "Connected"

# ------------------------------------------------------------------ #
# Open FortiClient GUI (simple — no GUI automation)                    #
# ------------------------------------------------------------------ #

_FORTI_LNK = r"C:\Users\Public\Desktop\FortiClient VPN.lnk"

def _open_forticlient_gui(app_path: str = "") -> tuple[bool, str]:
    """Open FortiClient GUI with a clean (PyInstaller-free) environment.

    Two-stage strategy:

    1. **Primary**: `explorer.exe <FortiClient VPN.lnk>` — re-parents the launch
       to the shell, so FortiClient inherits explorer's env (not HospitalHub's
       _MEIPASS-tainted env). This is the only way to make .lnk activation work
       AND avoid the Electron `Logger TraceLog` crash. Works on every machine
       where the .lnk file exists and has not been hijacked.

    2. **Fallback** (no .lnk, or explorer launch raised): direct `Popen` on the
       .exe with PyInstaller env stripped + cwd set to install dir + DETACHED
       process group. Used when the public-desktop .lnk is missing or when its
       shell association has been hijacked (WinRAR/7-Zip), which on that one
       machine made `explorer.exe foo.lnk` open the user's "Dokumenty" folder
       instead of activating the shortcut.

    Note: `explorer.exe <exe>` (without .lnk) does NOT launch the exe — it
    fallbacks to opening the profile folder. Hence the explicit Popen fallback.
    """
    _dbg(f"_open_forticlient_gui(app_path={app_path!r}) lnk_exists={os.path.isfile(_FORTI_LNK)}")

    # Stage 1: explorer.exe <lnk>. Verify that FortiClient actually started —
    # if .lnk association is hijacked (WinRAR/7-Zip), explorer opens the user's
    # "Dokumenty" folder instead. Detect that and fall through to Popen.
    if os.path.isfile(_FORTI_LNK):
        ok_v, err_v = _validate_exe(_FORTI_LNK)
        if ok_v:
            popen_err = None
            try:
                subprocess.Popen(["explorer.exe", _FORTI_LNK])
                _dbg(f"  -> explorer.exe {_FORTI_LNK} Popen OK")
            except Exception as e:
                popen_err = e
                _dbg(f"  -> explorer.exe {_FORTI_LNK} FAIL: {e}")
            if popen_err is None:
                started = _wait_for_process("FortiClient.exe", timeout=4.0)
                if started:
                    return True, "Otwarto FortiClient — połącz się w oknie klienta."
                # explorer didn't spawn FortiClient — .lnk association hijacked.
                _dbg("  -> explorer.exe did NOT spawn FortiClient.exe (likely "
                     ".lnk association hijacked); falling back to direct Popen.")

    # Stage 2 (fallback): direct exe with clean env + correct CWD + detached.
    forti_gui = _find_forticlient_gui(app_path)
    forti_dir = _forti_install_dir()
    if not forti_gui:
        return False, "Nie znaleziono FortiClient.\nUruchom klienta VPN ręcznie."
    ok_v, err_v = _validate_exe(forti_gui)
    if not ok_v:
        return False, f"Błąd uruchamiania FortiClient:\n{err_v}"
    cwd = forti_dir or os.path.dirname(forti_gui)
    flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP
    try:
        proc = subprocess.Popen(
            [forti_gui],
            env=_clean_pyinstaller_env(),
            cwd=cwd,
            creationflags=flags,
            close_fds=True,
        )
        _dbg(f"  -> Popen(clean env) {forti_gui} cwd={cwd} pid={proc.pid} OK")
        _wait_for_process("FortiClient.exe", timeout=3.0)
        return True, "Otwarto FortiClient — połącz się w oknie klienta."
    except Exception as e:
        _dbg(f"  -> Popen(clean env) {forti_gui} FAIL: {e}")
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

        import win32gui
        import win32process
        import win32api

        fc_tid, _ = win32process.GetWindowThreadProcessId(hwnd)
        our_tid = win32api.GetCurrentThreadId()
        attached = False
        try:
            try:
                _ct.windll.user32.AttachThreadInput(our_tid, fc_tid, True)
                attached = True
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

            # Remember the user's clipboard up front (before we hijack it for
            # login/password paste); restored after the form is submitted.
            prev_clip = _get_clipboard_text()

            # Select all + PASTE login (handles case when login is pre-filled).
            # Pasted, not typed: synthetic typing into the Chromium UI sometimes
            # drops every char → username reaches the gateway empty.
            if login:
                _press_combo(VK_CONTROL, ord('A'))
                time.sleep(0.2)
                _press_key(0x2E)                  # VK_DELETE — clear field
                time.sleep(0.2)
                _copy_to_clipboard(login)
                time.sleep(0.2)
                _press_combo(VK_CONTROL, ord('V'))
                time.sleep(0.5)

            # Tab to Password field
            _press_key(VK_TAB)
            time.sleep(0.5)

            # Fill password by PASTING, not typing. Synthetic KEYEVENTF_UNICODE
            # keystrokes are dropped/mangled by FortiClient's Chromium UI, so a
            # typed password reaches the gateway subtly wrong → 'Permission denied'
            # even though the same password pasted by hand connects fine.
            # We keep the password on the clipboard for the whole submit and only
            # restore it AFTER Connect, so there is no clipboard-restore race that
            # could make Ctrl+V paste stale contents.
            if password:
                _press_combo(VK_CONTROL, ord('A'))   # select any prefilled value
                time.sleep(0.2)
                _press_key(0x2E)                      # VK_DELETE — clear field
                time.sleep(0.2)
                _copy_to_clipboard(password)
                time.sleep(0.2)
                _press_combo(VK_CONTROL, ord('V'))    # paste
                time.sleep(0.9)                       # let Chromium commit paste

            # Settle before submit — do NOT press Enter the instant paste fires,
            # the field needs a beat to register the value first.
            time.sleep(0.6)

            # Enter (from inside the password field) submits the FortiClient form.
            _press_key(VK_RETURN)
            _dbg("_autofill: pressed Connect")

            # Restore the user's clipboard only after the form was submitted.
            time.sleep(1.5)
            try:
                _copy_to_clipboard(prev_clip if prev_clip is not None else "")
            except Exception:
                pass
        finally:
            if attached:
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

        import win32gui
        import win32process
        import win32api

        fc_tid, _ = win32process.GetWindowThreadProcessId(hwnd)
        our_tid = win32api.GetCurrentThreadId()
        attached = False
        try:
            try:
                _ct.windll.user32.AttachThreadInput(our_tid, fc_tid, True)
                attached = True
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
        finally:
            if attached:
                try:
                    _ct.windll.user32.AttachThreadInput(our_tid, fc_tid, False)
                except Exception:
                    pass

    t = threading.Thread(target=_do, daemon=True)
    t.start()

def _autofill_stormshield(server: str, port: str, login: str, password: str):
    """Auto-fill Stormshield SSL VPN Client (Qt5).
    Focus starts on Password field. Shift+Tab x2 to Address, then type forward.
    Runs on a background thread so AttachThreadInput is scoped to a short-lived
    thread — even if cleanup is missed, the OS releases the attachment when the
    thread terminates (cf. _autofill_forticlient)."""
    import threading

    def _do():
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

            tid, _ = win32process.GetWindowThreadProcessId(hwnd)
            our_tid = win32api.GetCurrentThreadId()
            attached = False
            try:
                _ct.windll.user32.AttachThreadInput(our_tid, tid, True)
                attached = True
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
            finally:
                if attached:
                    try:
                        _ct.windll.user32.AttachThreadInput(our_tid, tid, False)
                    except Exception:
                        pass
            _dbg("_autofill_stormshield: done")
        except Exception as e:
            _dbg(f"_autofill_stormshield error: {e}")

    threading.Thread(target=_do, daemon=True).start()

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

def _get_clipboard_text():
    """Read current clipboard text (CF_UNICODETEXT), or None."""
    try:
        import win32clipboard
        win32clipboard.OpenClipboard()
        try:
            data = win32clipboard.GetClipboardData(win32clipboard.CF_UNICODETEXT)
        except Exception:
            data = None
        win32clipboard.CloseClipboard()
        return data
    except Exception:
        return None

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
# Windows built-in VPN (rasdial / phonebook)                          #
# ------------------------------------------------------------------ #
# Wbudowany w Windows klient VPN. Profil musi być wcześniej utworzony
# w Settings → VPN (lub Network Connections) z zaznaczonym "Zapamiętaj
# moje dane logowania" — wtedy rasdial łączy się headless.
#
# CLI: rasdial.exe "Nazwa profilu"            -> connect
#      rasdial.exe "Nazwa profilu" /DISCONNECT -> disconnect
#      rasdial.exe                              -> lista aktywnych
#
# Status: parsowanie rasdial (bez argów). Aktywne profile są wcięte
# w stdout, więc filtrujemy po startswith(' '|'\t') — niezależnie od
# języka systemu (PL/EN/itd.).

_rasdial_cache: dict = {"ts": 0.0, "active": set()}
_RASDIAL_CACHE_TTL = 3.0

def _rasdial_active_connections() -> set[str]:
    """Return set of active VPN connection names (per `rasdial` no-args).
    Cached for _RASDIAL_CACHE_TTL seconds to keep status polls cheap."""
    import time
    now = time.monotonic()
    with _state_lock:
        if now - _rasdial_cache["ts"] < _RASDIAL_CACHE_TTL:
            return _rasdial_cache["active"]
    active: set[str] = set()
    try:
        r = subprocess.run(
            ["rasdial"], capture_output=True, timeout=5,
            startupinfo=_hidden_startupinfo(), creationflags=_NO_WINDOW,
        )
        # rasdial uses Windows ANSI (mbcs) — Polish chars may appear in names.
        output = (r.stdout or b"").decode("mbcs", errors="replace")
        # Active profile lines are indented (tab or spaces). Header / trailer
        # lines start at column 0. Language-agnostic.
        for line in output.splitlines():
            if line.startswith((" ", "\t")):
                name = line.strip()
                if name:
                    active.add(name)
    except Exception:
        pass
    with _state_lock:
        _rasdial_cache["ts"] = now
        _rasdial_cache["active"] = active
    return active

def _invalidate_rasdial_cache() -> None:
    with _state_lock:
        _rasdial_cache["ts"] = 0.0
        _rasdial_cache["active"] = set()

def _resolve_rasdial() -> str:
    """Locate rasdial.exe explicitly — PyInstaller-stripped env may hide
    System32 PATH on some setups; absolute path is bulletproof."""
    for base in (os.environ.get("SystemRoot", r"C:\Windows"),
                 r"C:\Windows", r"C:\WINNT"):
        p = os.path.join(base, "System32", "rasdial.exe")
        if os.path.isfile(p):
            return p
        p2 = os.path.join(base, "Sysnative", "rasdial.exe")  # WOW64 case
        if os.path.isfile(p2):
            return p2
    return "rasdial.exe"  # fallback to PATH

def _run_rasdial_async(args: list[str], action: str, profile_name: str) -> None:
    """Run rasdial in a background thread, capture stdout/stderr + return
    code, log everything to vpn_debug.log. Status poll then reflects the
    actual outcome within the cache TTL."""
    import threading

    def _do():
        exe = _resolve_rasdial()
        cmd = [exe] + args
        _dbg(f"rasdial {action} '{profile_name}': cmd={cmd}")
        try:
            r = subprocess.run(
                cmd, capture_output=True, timeout=90,
                startupinfo=_hidden_startupinfo(),
                creationflags=_NO_WINDOW,
            )
            out = (r.stdout or b"").decode("mbcs", errors="replace").strip()
            err = (r.stderr or b"").decode("mbcs", errors="replace").strip()
            _dbg(f"rasdial {action} '{profile_name}' rc={r.returncode} "
                 f"out={out!r} err={err!r}")
        except subprocess.TimeoutExpired:
            _dbg(f"rasdial {action} '{profile_name}' TIMEOUT (90s)")
        except FileNotFoundError as e:
            _dbg(f"rasdial {action} '{profile_name}' FileNotFound: {e}")
        except Exception as e:
            _dbg(f"rasdial {action} '{profile_name}' EXC: {e}")
        finally:
            _invalidate_rasdial_cache()

    threading.Thread(target=_do, daemon=True).start()

def _resolve_rasphone() -> str:
    """Locate rasphone.exe (classic dial UI)."""
    for base in (os.environ.get("SystemRoot", r"C:\Windows"),
                 r"C:\Windows", r"C:\WINNT"):
        p = os.path.join(base, "System32", "rasphone.exe")
        if os.path.isfile(p):
            return p
    return "rasphone.exe"

def _open_rasphone_dial(profile_name: str) -> bool:
    """Open the classic Windows dial dialog for `profile_name`.

    Used as a fallback when rasdial.exe fails to find stored credentials
    (common for VPN profiles created via the modern Settings UI on Win10/11:
    creds are stored in a Credential Manager target that rasdial doesn't
    consult, but rasphone's dialog displays them pre-filled — user clicks
    Connect once).

    Spawned via ShellExecuteW (open verb, SW_SHOWNORMAL) — NOT subprocess
    with _hidden_startupinfo, which sets wShowWindow=SW_HIDE and silently
    hides the dialog (process runs, no window visible — confirmed bug)."""
    import ctypes
    exe = _resolve_rasphone()
    try:
        # ShellExecuteW: lpVerb='open', nShowCmd=SW_SHOWNORMAL(1)
        # Parameters string must escape profile name for spaces/quotes.
        params = f'-d "{profile_name}"'
        rc = ctypes.windll.shell32.ShellExecuteW(None, "open", exe, params, None, 1)
        _dbg(f"rasphone -d '{profile_name}' ShellExecuteW rc={rc}")
        return rc > 32
    except Exception as e:
        _dbg(f"rasphone -d '{profile_name}' EXC: {e}")
        return False

def _run_rasdial_with_fallback_async(profile_name: str) -> None:
    """Try `rasdial entryname` headless first. On non-zero exit (e.g. 691
    when modern-Settings creds aren't visible to rasdial), open the classic
    rasphone dial dialog so the user can confirm with one click."""
    import threading

    def _do():
        exe = _resolve_rasdial()
        cmd = [exe, profile_name]
        _dbg(f"rasdial connect '{profile_name}': cmd={cmd}")
        rc = -1
        out = ""
        err = ""
        try:
            r = subprocess.run(
                cmd, capture_output=True, timeout=90,
                startupinfo=_hidden_startupinfo(),
                creationflags=_NO_WINDOW,
            )
            rc = r.returncode
            out = (r.stdout or b"").decode("mbcs", errors="replace").strip()
            err = (r.stderr or b"").decode("mbcs", errors="replace").strip()
            _dbg(f"rasdial connect '{profile_name}' rc={rc} out={out!r} err={err!r}")
        except subprocess.TimeoutExpired:
            _dbg(f"rasdial connect '{profile_name}' TIMEOUT (90s)")
        except Exception as e:
            _dbg(f"rasdial connect '{profile_name}' EXC: {e}")
        finally:
            _invalidate_rasdial_cache()

        if rc != 0:
            _dbg(f"rasdial failed → opening rasphone dial dialog for '{profile_name}'")
            ok = _open_rasphone_dial(profile_name)
            _dbg(f"rasphone fallback opened={ok}")

    threading.Thread(target=_do, daemon=True).start()

def _windows_vpn_connect(profile_name: str) -> tuple[bool, str]:
    """Connect: rasdial headless first; if it fails (e.g. 691 because the
    modern Settings store hides creds from rasdial), open the classic
    rasphone dial dialog where Windows pre-fills the saved username/password
    — user clicks Connect once. See vpn_debug.log for the rasdial rc."""
    if not profile_name:
        return False, "Podaj nazwę profilu Windows VPN."
    _run_rasdial_with_fallback_async(profile_name)
    return True, f"Łączenie z '{profile_name}'..."

def _windows_vpn_disconnect(profile_name: str) -> tuple[bool, str]:
    """Disconnect via rasdial /DISCONNECT — needs no credentials, always works."""
    if not profile_name:
        return False, "Podaj nazwę profilu Windows VPN."
    _run_rasdial_async([profile_name, "/DISCONNECT"], "disconnect", profile_name)
    return True, f"Rozłączanie '{profile_name}'..."

# ------------------------------------------------------------------ #
# Connect / disconnect                                                 #
# ------------------------------------------------------------------ #

def _resolve_log_dir() -> str:
    """Persistent log dir. For PyInstaller --onefile, __file__ lives in
    _MEIPASS (temp, deleted on exit) — use sys.executable instead so
    vpn_debug.log lands next to HospitalHub.exe and survives restarts."""
    import sys
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))

_DEBUG_LOG = os.path.join(_resolve_log_dir(), "vpn_debug.log")

_DBG_MAX_SIZE = 1_000_000  # 1 MB

def _dbg(msg: str):
    """No-op — debug logging wyłączone na życzenie usera (2026-05-28).
    Call sites zostawione, żeby było łatwo wpiąć z powrotem przez przywrócenie
    poprzedniej implementacji (file write do _DEBUG_LOG)."""
    pass

def connect(provider: str, server: str, port: str, login: str, password: str,
            group: str = "", domain: str = "",
            app_path: str = "", profile_name: str = "",
            autofill: bool = True) -> tuple[bool, str]:

    _dbg(f"connect() provider={provider} app_path={app_path!r} profile={profile_name!r} autofill={autofill}")

    _last_connected[provider] = profile_name or ""
    _last_connected_meta[provider] = {"server": server or "",
                                      "profile_name": profile_name or ""}
    _dbg(f"  _last_connected[{provider}] set to {_last_connected[provider]!r}")

    # Autofill OFF: copy password to clipboard once, up-front, so the user can paste
    # manually into any VPN client window. Subsequent branches skip CLI credential
    # passing and GUI-field autofill threads.
    if not autofill and password:
        _copy_to_clipboard(password)

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
            if autofill:
                threading.Thread(target=_autofill_forticlient,
                                 args=(login, password, profile_name),
                                 daemon=True).start()
                return True, "FortiClient — wypełniam dane..."
            return True, "FortiClient — hasło w schowku."

        # Check for EMS auth window (instant check — no waiting) — only when autofill on
        if autofill:
            ok, msg = _fill_forti_auth_window(login, password, timeout=0.1)
            if ok:
                return True, msg

        # CLI (EMS/ZTNA) — non-blocking Popen. Skip when autofill disabled
        # (CLI would pass credentials headless, bypassing the user's intent).
        cli_ok = _is_fortivpn_cli_supported(app_path)
        _dbg(f"  cli_supported={cli_ok} profile={profile_name!r}")
        if autofill and cli_ok and profile_name:
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

        # Legacy FortiSSLVPNclient.exe — also passes credentials, skip when autofill off
        if autofill:
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

        # Open GUI (+ auto-fill in background when enabled)
        ok, msg = _open_forticlient_gui(app_path)
        if ok:
            if autofill:
                threading.Thread(target=_autofill_forticlient,
                                 args=(login, password, profile_name),
                                 daemon=True).start()
                return True, "Otwarto FortiClient — wypełniam dane..."
            return True, "Otwarto FortiClient — hasło w schowku."
        return ok, msg

    elif provider == "GlobalProtect":
        exe = app_path if (app_path and os.path.isfile(app_path)) else find_executable(provider)
        if not exe:
            return False, "Nie znaleziono GlobalProtect.\nSprawdź instalację lub uruchom ręcznie."
        gp_dir = os.path.dirname(exe)
        # CLI version (passes credentials) — only when autofill is enabled
        gp_cli = os.path.join(gp_dir, "globalprotect.exe")
        if autofill and os.path.isfile(gp_cli):
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
            msg = ("Otwarto GlobalProtect — hasło w schowku."
                   if not autofill else
                   "Otwarto GlobalProtect — użyj 📋 by skopiować hasło.")
            return True, msg
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
        running = _is_process_running(exe_name) if exe_name else False
        _dbg(f"Hillstone connect: exe={exe!r} exe_name={exe_name!r} running={running}")
        if app_path:
            _validate_exe(app_path)
        elif exe:
            _validate_exe(exe)
        if exe_name and running:
            # Qt app in tray — simulate tray icon double-click (goes through
            # Qt event loop, won't freeze). SC_RESTORE causes frozen windows.
            if _activate_qt_tray_icon(exe_name):
                import time; time.sleep(1)
                return True, "Przywrócono okno Hillstone."
            # All restore methods failed — do NOT launch second instance
            return True, "Hillstone działa w trayu — kliknij ikonę w zasobniku."
        # Not running — launch via ShellExecuteW (handles UAC elevation that
        # Hillstone's manifest requires; plain Popen would fail silently).
        if exe:
            ok, err = _shell_launch(exe, provider="Hillstone Secure Connect")
            _dbg(f"Hillstone launch via _shell_launch: ok={ok} err={err}")
            if ok:
                _wait_for_process(exe_name, timeout=4.0)
                return True, "Uruchomiono Hillstone Secure Connect."
            # ShellExecuteW failed — try Popen fallback so we can capture stderr
            try:
                proc = subprocess.Popen(
                    [exe],
                    env=_clean_pyinstaller_env(),
                    cwd=os.path.dirname(exe) or None,
                    creationflags=subprocess.DETACHED_PROCESS
                    | subprocess.CREATE_NEW_PROCESS_GROUP,
                    close_fds=True,
                )
                _wait_for_process(exe_name, timeout=4.0)
                return True, "Uruchomiono Hillstone Secure Connect."
            except Exception as pe:
                return False, f"Błąd uruchamiania Hillstone:\n{err}\n{pe}"
        return False, "Hillstone — uruchom klienta ręcznie."

    elif provider == "Stormshield":
        _last_connected[provider] = server or profile_name or ""
        exe = app_path if (app_path and os.path.isfile(app_path)) else None
        exe_name = os.path.basename(exe) if exe else "sslvpn_client.exe"
        if app_path:
            _validate_exe(app_path)

        def _storm_show_and_fill():
            """Activate tray icon (Qt5 shows window itself) then bring to front."""
            import time
            if _activate_qt_tray_icon(exe_name):
                time.sleep(1.5)
                # Window already visible via Qt — just bring to front (no ShowWindow!)
                _bring_window_to_front("stormshield")
                if autofill and (login or password):
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
                if autofill and (login or password):
                    import time; time.sleep(0.5)
                    _autofill_stormshield(server, port, login, password)
                    return True, "Przywrócono Stormshield + wypełniono."
                return True, "Przywrócono Stormshield — hasło w schowku."
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
        # Use ShellExecuteW (via _shell_launch) — Stormshield SN VPN Client has
        # a requireAdministrator manifest; plain subprocess.Popen fails silently
        # with ERROR_ELEVATION_REQUIRED on non-admin accounts (i.e. colleagues'
        # machines). ShellExecuteW shows the UAC prompt automatically.
        if exe:
            ok, err = _shell_launch(exe, provider="Stormshield")
            _dbg(f"Stormshield launch via _shell_launch: ok={ok} err={err}")
            if not ok:
                # Fallback: Popen with clean env in case ShellExecuteW failed
                # (e.g. UAC denied, association issue). Log the fallback path.
                try:
                    proc = subprocess.Popen(
                        [exe],
                        env=_clean_pyinstaller_env(),
                        cwd=os.path.dirname(exe) or None,
                        creationflags=subprocess.DETACHED_PROCESS
                        | subprocess.CREATE_NEW_PROCESS_GROUP,
                        close_fds=True,
                    )
                except Exception as pe:
                    return False, f"Błąd uruchamiania Stormshield:\n{err}\n{pe}"
            import time; time.sleep(4)
            _wait_for_process(exe_name, timeout=2.0)
            if _storm_show_and_fill():
                return True, "Uruchomiono Stormshield."
            # Tray activation failed — window might need more time
            time.sleep(2)
            if _storm_show_and_fill():
                return True, "Uruchomiono Stormshield."
            return True, "Stormshield uruchomiony — kliknij ikonę w trayu."
        return False, "Stormshield — uruchom klienta ręcznie."

    elif provider == "Barracuda":
        _last_connected[provider] = profile_name or ""
        exe = app_path if (app_path and os.path.isfile(app_path)) else None
        if exe:
            try:
                os.startfile(exe)
                if autofill and (login or password):
                    _autofill_native_vpn_window(login, password, os.path.basename(exe))
                    return True, f"Łączenie {profile_name or provider}..."
                return True, f"Otwarto {provider} — hasło w schowku."
            except Exception as e:
                return False, f"Błąd uruchamiania:\n{e}"
        # Fallback: rasdial (headless auth with credentials on CLI) — only with autofill on
        conn_name = server or profile_name
        if autofill and conn_name:
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

    elif provider == "Windows VPN":
        # Wbudowany klient VPN Windows — rasdial używa nazwy profilu z
        # rasphone.pbk. Credentiale muszą być zapisane w profilu
        # ("Zapamiętaj moje dane logowania") — nie przekazujemy ich z
        # HospitalHub, żeby nie obejść intencji użytkownika.
        conn_name = profile_name or server
        _last_connected[provider] = conn_name or ""
        _last_connected_meta[provider] = {"server": server or "",
                                          "profile_name": conn_name or ""}
        return _windows_vpn_connect(conn_name)

    # Generic handler for custom providers — just launch the exe
    exe = app_path if (app_path and os.path.isfile(app_path)) else None
    if exe:
        try:
            os.startfile(exe)
            if not autofill and password:
                return True, f"Uruchomiono {provider} — hasło w schowku."
            return True, f"Uruchomiono {provider}."
        except Exception as e:
            return False, f"Błąd uruchamiania {provider}:\n{e}"

    return False, f"Nieobsługiwany provider: {provider}"

def disconnect(provider: str, server: str = "",
               app_path: str = "", profile_name: str = "") -> tuple[bool, str]:

    if provider == "FortiClient":
        _last_connected.pop(provider, None)
        _last_connected_meta.pop(provider, None)
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
        _last_connected_meta.pop(provider, None)
        return True, "Rozłącz ręcznie w kliencie NetExtender."

    elif provider == "GlobalProtect":
        _last_connected.pop(provider, None)
        _last_connected_meta.pop(provider, None)
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
        _last_connected_meta.pop(provider, None)
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
        _last_connected_meta.pop(provider, None)
        return True, "Rozłącz ręcznie w aplikacji Hillstone Secure Connect."

    elif provider == "Barracuda":
        _last_connected.pop(provider, None)
        _last_connected_meta.pop(provider, None)
        return True, "Rozłącz ręcznie w kliencie Barracuda."

    elif provider == "Windows VPN":
        conn_name = profile_name or server
        _last_connected.pop(provider, None)
        _last_connected_meta.pop(provider, None)
        return _windows_vpn_disconnect(conn_name)

    # Generic custom provider
    _last_connected.pop(provider, None)
    _last_connected_meta.pop(provider, None)
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
        # Check "stormshield-tap" adapter state + _last_connected to distinguish
        # which profile is actually connected. We also peek at _last_connected_meta
        # so that the same logical profile in a *different* vault (e.g. main vault
        # carries profile_name but blank server, while the VPN vault has the server)
        # still lights up green — without it, a missing field on either side made
        # the comparison fall through to Disconnected.
        last = _last_connected.get("Stormshield", "")
        meta = _last_connected_meta.get("Stormshield") or {}
        profile_key = server or profile_name or ""
        status = _check_adapter_status("stormshield-tap")
        if not status or status == "Disconnected":
            status = _check_adapter_status("stormshield ssl vpn")
        if status == "Connected":
            if not last:
                return None  # connected outside HospitalHub — can't pin a profile
            meta_srv = meta.get("server", "")
            meta_prof = meta.get("profile_name", "")
            matches = (
                (profile_key and profile_key == last)
                or (server and meta_srv and server == meta_srv)
                or (profile_name and meta_prof and profile_name == meta_prof)
            )
            if profile_key and not matches:
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

    elif provider == "Windows VPN":
        # Status nie pollowany — rasdial enumeration nie pokrywa połączeń
        # odpalanych z modern Settings flyout. UI dla tego providera nie ma
        # status label, więc None tu jest spójne z brakiem renderowania.
        return None

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
                      token: str = "",
                      autofill: bool = True) -> tuple[bool, str, object]:
    """
    Like connect() but returns (ok, msg, process) where process is a Popen
    whose stdout can be monitored for 2FA prompts. process is None when
    interactive monitoring is not available.
    """
    # When autofill is disabled, skip the FortiClient CLI path (it would pass
    # credentials headless, bypassing the user's manual-entry intent) and fall
    # through to connect(), which handles clipboard + GUI-only launch.
    if autofill and provider == "FortiClient" and _is_fortivpn_cli_supported(app_path):
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
                          app_path, profile_name, autofill=autofill)
        return ok, msg, None

    ok, msg = connect(provider, server, port, login, password, group, domain,
                      app_path, profile_name, autofill=autofill)
    return ok, msg, None

# ------------------------------------------------------------------ #
# Launch VPN client app                                                #
# ------------------------------------------------------------------ #

def launch_app(app_path: str) -> tuple[bool, str]:
    _dbg(f"launch_app(app_path={app_path!r})")
    if not app_path:
        return False, "Nie podano ścieżki do aplikacji."
    ok_v, err_v = _validate_exe(app_path)
    if not ok_v:
        return False, err_v
    try:
        app_name = os.path.basename(app_path).lower()
        if "forticlient" in app_name:
            return _open_forticlient_gui(app_path)
        # If app_path is nxcli/NECLI, launch NetExtender.exe GUI instead
        if app_name in ("nxcli.exe", "necli.exe"):
            gui = os.path.join(os.path.dirname(app_path), "NetExtender.exe")
            if os.path.isfile(gui):
                os.startfile(gui)
                _wait_for_process("NetExtender.exe", timeout=3.0)
                return True, "Uruchomiono NetExtender."
            return False, "Nie znaleziono NetExtender.exe obok nxcli."
        os.startfile(app_path)
        return True, "Uruchomiono klienta VPN."
    except Exception as e:
        return False, f"Błąd uruchamiania:\n{e}"
