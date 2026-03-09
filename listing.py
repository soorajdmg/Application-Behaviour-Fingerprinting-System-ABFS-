import psutil
import win32gui
import win32process
import win32con


def get_pids_with_visible_windows():
    """Get PIDs of processes that have real application windows (appear in taskbar/Alt+Tab)."""
    pids = set()

    def callback(hwnd, _):
        # Must be visible with a title
        if not win32gui.IsWindowVisible(hwnd):
            return True
        title = win32gui.GetWindowText(hwnd).strip()
        if not title:
            return True

        # Check window style - skip tool windows (tray icons, helpers, overlays)
        ex_style = win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE)
        if ex_style & win32con.WS_EX_TOOLWINDOW:
            return True

        # Check window size - skip tiny/hidden windows (but allow minimized ones)
        if not win32gui.IsIconic(hwnd):
            rect = win32gui.GetWindowRect(hwnd)
            width = rect[2] - rect[0]
            height = rect[3] - rect[1]
            if width < 50 or height < 50:
                return True

        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        pids.add(pid)
        return True

    win32gui.EnumWindows(callback, None)
    return pids


def list_processes():
    print("\n=================================================")
    print("      Application Behaviour Fingerprinting System")
    print("=================================================\n")

    print(f"{'PID':<10}{'Application Name'}")
    print("-------------------------------------------------")

    # Get PIDs of processes with visible windows
    pids_with_windows = get_pids_with_visible_windows()

    process_count = 0
    seen_apps = set()

    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pid = proc.info['pid']
            name = proc.info['name']

            if not name:
                continue

            # Only show processes that have visible windows
            if pid not in pids_with_windows:
                continue

            # Skip Windows system processes by path
            try:
                exe_path = proc.exe()
                if exe_path.startswith('C:\\Windows'):
                    continue
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

            # Avoid duplicate app names
            if name in seen_apps:
                continue
            seen_apps.add(name)

            print(f"{pid:<10}{name}")
            process_count += 1

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    print("\n-------------------------------------------------")
    print(f"Total Running Applications: {process_count}")
    print("=================================================\n")