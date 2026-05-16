"""
process_discovery.py
Handles process enumeration, PID resolution, exe path normalization,
and SHA-256 hash computation for the ABFS pipeline.
"""

import os
import ctypes
import ctypes.wintypes
import hashlib
from typing import Optional

import psutil


def normalize_exe(path: str) -> str:
    """Return a stable, case-normalized absolute path for use as a baseline key."""
    return os.path.normcase(os.path.abspath(path))


def compute_sha256(path: str) -> Optional[str]:
    """
    Stream-compute SHA-256 of the executable binary.
    Returns hex digest string, or None if the file cannot be read.
    """
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except (PermissionError, OSError):
        return None


# ── Layer 1: System-account usernames ────────────────────────────────────
_SERVICE_ACCOUNTS = {
    "system",
    "local service",
    "network service",
    "nt authority\\system",
    "nt authority\\local service",
    "nt authority\\network service",
}

# ── Layer 2: OS system directories (exes here are almost always services) ─
_SYSTEM_DIRS = (
    "c:\\windows\\system32\\",
    "c:\\windows\\syswow64\\",
    "c:\\windows\\servicing\\",
    "c:\\windows\\uus\\",
    "c:\\windows\\winsxs\\",
)

# User-visible shell processes that live in system dirs but are NOT services
_SYSTEM_DIR_ALLOWLIST = {
    "explorer.exe",
    "searchhost.exe",
    "startmenuexperiencehost.exe",
    "systemsettings.exe",
    "ctfmon.exe",
}

# ── Layer 3: Name-suffix heuristics for user-account services ─────────────
# Matches exe names that end with these strings (case-insensitive, no extension)
_SERVICE_NAME_SUFFIXES = (
    "srv",
    "svc",
    "service",
    "serv",
    "daemon",
    "helper",
    "agent",
    "host",
    "broker",
    "worker",
    "monitor",
    "updater",
    "launcher",
    "handler",
    "manager",
)

# Well-known user-facing apps whose names happen to end with a suffix above
_SUFFIX_ALLOWLIST = {
    "spotify.exe",
    "whatsapp.exe",
    "discord.exe",
    "slack.exe",
    "teams.exe",
    "zoom.exe",
    "lively.exe",
    "ollama app.exe",
}


def _get_service_pids() -> set:
    """
    Layer 0 (most authoritative): Query the Windows Service Control Manager
    via psutil.win_service_iter() and return the set of PIDs that belong to
    registered Windows services. Only available on Windows.
    """
    service_pids: set[int] = set()
    if not hasattr(psutil, "win_service_iter"):
        return service_pids
    try:
        for svc in psutil.win_service_iter():
            try:
                pid = svc.pid()
                if pid and pid > 0:
                    service_pids.add(pid)
            except Exception:
                continue
    except Exception:
        pass
    return service_pids


def _is_service(info: dict, service_pids: set) -> bool:
    """
    Return True if the process is a background Windows service rather than
    a user-facing application. Uses four independent layers:

      Layer 0 – PID is registered in the Windows SCM (most reliable)
      Layer 1 – Process runs under a system/service account
      Layer 2 – Executable lives in a Windows system directory
      Layer 3 – Executable name ends with a known service-name suffix
    """
    pid  = info.get("pid", 0)
    name = (info.get("name") or "").lower()
    exe  = (info.get("exe")  or "").lower().replace("/", "\\")
    username = (info.get("username") or "").lower().strip()

    # Layer 0: SCM registry
    if pid in service_pids:
        return True

    # Layer 1: System account
    if username in _SERVICE_ACCOUNTS:
        return True

    # Layer 2: System directory (with user-shell allowlist)
    if any(exe.startswith(d) for d in _SYSTEM_DIRS):
        if name not in _SYSTEM_DIR_ALLOWLIST:
            return True

    # Layer 3: Name-suffix heuristic (skip allowlisted user apps)
    if name not in _SUFFIX_ALLOWLIST:
        stem = name.removesuffix(".exe")  # e.g. "lghub_agent"
        # Normalise separators so "lghub_agent" → "lghubagenr" won't false-fire;
        # we check the full stem ends-with, not just contains.
        for suffix in _SERVICE_NAME_SUFFIXES:
            if stem.endswith(suffix):
                return True

    return False


def list_processes(filter_str: str = None) -> list[dict]:
    """
    Return a list of running *user-application* process dicts with keys:
    pid, name, exe, status, username.

    All four filter layers are applied to exclude Windows services and
    background system processes, leaving only interactive applications.
    Silently skips processes that raise access errors.
    Optionally filters by case-insensitive name substring.
    """
    service_pids = _get_service_pids()
    results = []

    for proc in psutil.process_iter(["pid", "name", "exe", "status", "username"]):
        try:
            info = proc.info
            name = info.get("name") or ""

            if _is_service(info, service_pids):
                continue

            if filter_str and filter_str.lower() not in name.lower():
                continue

            results.append({
                "pid":      info["pid"],
                "name":     name,
                "exe":      info.get("exe") or "",
                "status":   info.get("status", "?"),
                "username": info.get("username", "?"),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return results


def resolve_pid_group(pids: list[int]) -> tuple[dict, list]:
    """
    Map each PID to a psutil.Process and group by normalized exe path.

    Returns:
        groups   – dict keyed by normalized exe path, each value:
                   {"exe_path": str, "processes": [psutil.Process, ...]}
        errors   – list of (pid, reason_str) for PIDs that failed
    """
    groups: dict[str, dict] = {}
    errors: list[tuple[int, str]] = []

    for pid in pids:
        try:
            proc = psutil.Process(pid)
            exe = proc.exe()
        except psutil.NoSuchProcess:
            errors.append((pid, "process does not exist"))
            continue
        except psutil.AccessDenied:
            errors.append((pid, "access denied reading exe path — try running as administrator"))
            continue
        except (OSError, ValueError):
            errors.append((pid, "could not retrieve exe path"))
            continue

        if not exe:
            errors.append((pid, "exe path is empty"))
            continue

        key = normalize_exe(exe)
        if key not in groups:
            groups[key] = {"exe_path": exe, "processes": []}
        groups[key]["processes"].append(proc)

    return groups, errors


# ── GUI application detection (Windows only) ─────────────────────────────

# Window style flags (from winuser.h)
_WS_CAPTION  = 0x00C00000   # title bar
_WS_SYSMENU  = 0x00080000   # close / system menu
_GWL_STYLE   = -16

# Processes that may own visible windows but are NOT user-launched applications:
#   - Windows shell components (explorer desktop/taskbar)
#   - Embedded renderer sub-processes (WebView2, Chromium GPU)
#   - UWP/XAML container hosts
#   - System utility windows launched by the OS
_APP_BLOCKLIST = {
    "explorer.exe",                  # Windows shell — desktop & taskbar
    "msedgewebview2.exe",            # Embedded WebView2 renderer
    "applicationframehost.exe",      # UWP app container host
    "shellexperiencehost.exe",       # Windows shell experience
    "searchhost.exe",                # Windows Search UI
    "startmenuexperiencehost.exe",   # Start menu
    "systemsettings.exe",            # Settings app (OS-launched)
    "textinputhost.exe",             # On-screen / touch keyboard
    "lockapp.exe",                   # Lock screen
    "logonui.exe",                   # Login UI
    "dwm.exe",                       # Desktop Window Manager
    "taskhostw.exe",                 # Task host window
    "sihost.exe",                    # Shell infrastructure host
    "fontdrvhost.exe",               # Font driver
}


def _get_window_pids() -> set:
    """
    Enumerate top-level windows via the Win32 API and return PIDs that own
    at least one real application window. Uses a HYBRID strategy:

      TRACK A — Traditional apps (WS_CAPTION + WS_SYSMENU):
        Visible + non-empty title + native title bar.
        Accepted at ANY size (including 160x28 when minimized to taskbar).

      TRACK B — Frameless / Electron / custom-titlebar apps:
        Visible + non-empty title but NO native WS_CAPTION.
        Accepted only when window rect >= _FRAMELESS_MIN_W x _FRAMELESS_MIN_H.
        This correctly includes Antigravity, Spotify, Discord, VS Code, etc.
        while excluding OEM tray tools (AsHotplugCtrl = 0x0, AsHDRControl = 0x0).
    """
    # Minimum rect for frameless apps (OEM tools are 0x0, real apps are much larger)
    _FRAMELESS_MIN_W = 200
    _FRAMELESS_MIN_H = 100

    class _RECT(ctypes.Structure):
        _fields_ = [("left",   ctypes.c_long), ("top",    ctypes.c_long),
                    ("right",  ctypes.c_long), ("bottom", ctypes.c_long)]

    pids: set[int] = set()

    try:
        user32 = ctypes.windll.user32
        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool,
                                         ctypes.wintypes.HWND,
                                         ctypes.wintypes.LPARAM)

        def _enum_callback(hwnd, _lparam):
            # Must be visible with a title
            if not user32.IsWindowVisible(hwnd):
                return True
            if user32.GetWindowTextLengthW(hwnd) == 0:
                return True

            style = user32.GetWindowLongW(hwnd, _GWL_STYLE)
            has_native_bar = bool(style & _WS_CAPTION and style & _WS_SYSMENU)

            if not has_native_bar:
                # TRACK B: frameless app — require a real on-screen footprint
                rect = _RECT()
                user32.GetWindowRect(hwnd, ctypes.byref(rect))
                w = rect.right  - rect.left
                h = rect.bottom - rect.top
                if w < _FRAMELESS_MIN_W or h < _FRAMELESS_MIN_H:
                    return True  # too small — OEM tray / hidden helper window

            # Accepted — record the owning PID
            pid = ctypes.wintypes.DWORD(0)
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            if pid.value:
                pids.add(pid.value)
            return True  # continue enumeration

        user32.EnumWindows(WNDENUMPROC(_enum_callback), 0)
    except Exception:
        pass

    return pids



def list_apps(filter_str: str = None) -> list[dict]:
    """
    Return only processes that are genuine user-launched GUI applications.

    A process qualifies when ALL of the following hold:
      1. It owns a visible window with WS_CAPTION+WS_SYSMENU and a real size
      2. It is NOT a registered Windows service (SCM check)
      3. It is NOT in the known shell/renderer/system-component blocklist
      4. It is NOT running under a system account

    Optionally filters by case-insensitive name substring.
    """
    window_pids  = _get_window_pids()
    service_pids = _get_service_pids()

    results = []

    for proc in psutil.process_iter(["pid", "name", "exe", "status", "username"]):
        try:
            info = proc.info
            pid  = info.get("pid", 0)
            name = (info.get("name") or "").lower()

            # Must own a qualifying GUI window
            if pid not in window_pids:
                continue

            # Skip Windows services (SCM registry)
            if pid in service_pids:
                continue

            # Skip known shell / renderer / system-component processes
            if name in _APP_BLOCKLIST:
                continue

            # Skip system-account processes
            username = (info.get("username") or "").lower().strip()
            if username in _SERVICE_ACCOUNTS:
                continue

            display_name = info.get("name") or ""
            if filter_str and filter_str.lower() not in display_name.lower():
                continue

            results.append({
                "pid":      pid,
                "name":     display_name,
                "exe":      info.get("exe") or "",
                "status":   info.get("status", "?"),
                "username": info.get("username", "?"),
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    return results
