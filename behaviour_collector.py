import time
from datetime import datetime

import psutil
import win32gui
import win32process
import win32con


# ---------------------------------------------------------------------------
# Helper: get PIDs with visible application windows
# ---------------------------------------------------------------------------

def _get_pids_with_visible_windows():
    """Return a set of PIDs that own at least one real visible window."""
    pids = set()

    def _callback(hwnd, _):
        if not win32gui.IsWindowVisible(hwnd):
            return True
        title = win32gui.GetWindowText(hwnd).strip()
        if not title:
            return True
        ex_style = win32gui.GetWindowLong(hwnd, win32con.GWL_EXSTYLE)
        if ex_style & win32con.WS_EX_TOOLWINDOW:
            return True
        if not win32gui.IsIconic(hwnd):
            rect = win32gui.GetWindowRect(hwnd)
            if (rect[2] - rect[0]) < 50 or (rect[3] - rect[1]) < 50:
                return True
        _, pid = win32process.GetWindowThreadProcessId(hwnd)
        pids.add(pid)
        return True

    win32gui.EnumWindows(_callback, None)
    return pids


# ---------------------------------------------------------------------------
# Core: collect behavioural metrics for a single process
# ---------------------------------------------------------------------------

def collect_process_behaviour(proc, include_network=True):

    try:
        with proc.oneshot():
            pid = proc.pid
            name = proc.name()
            exe_path = proc.exe()

            # ---- CPU usage (interval=0.5 s for a non-blocking sample) ----
            cpu_percent = proc.cpu_percent(interval=0.5)
            cpu_percent = round(cpu_percent / psutil.cpu_count(), 2)

            # ---- Memory ----
            mem_info = proc.memory_info()
            mem_percent = proc.memory_percent()

            # ---- Runtime ----
            create_time = proc.create_time()
            uptime_seconds = round(time.time() - create_time, 2)
            started_at = datetime.fromtimestamp(create_time).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            # ---- Status ----
            status = proc.status()

            # ---- Network (optional) ----
            network = None
            if include_network:
                try:
                    connections = proc.net_connections(kind="inet")
                    # Keep only connections that have a remote address
                    active_connections = [
                        c for c in connections if c.raddr
                    ]
                    network = {
                        "open_connections": len(active_connections),
                        "connection_details": [
                            {
                                "fd": c.fd,
                                "family": str(c.family),
                                "type": str(c.type),
                                "local_addr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else None,
                                "remote_addr": f"{c.raddr.ip}:{c.raddr.port}",
                                "status": c.status,
                            }
                            for c in active_connections
                        ],
                    }
                except (psutil.AccessDenied, psutil.NoSuchProcess):
                    network = {"open_connections": 0, "connection_details": [], "note": "Access denied"}

        return {
            "pid": pid,
            "name": name,
            "exe_path": exe_path,
            "cpu_percent": cpu_percent,
            "memory": {
                "rss_bytes": mem_info.rss,
                "rss_mb": round(mem_info.rss / (1024 * 1024), 2),
                "vms_bytes": mem_info.vms,
                "vms_mb": round(mem_info.vms / (1024 * 1024), 2),
                "percent": round(mem_percent, 2),
            },
            "runtime": {
                "uptime_seconds": uptime_seconds,
                "started_at": started_at,
            },
            "status": status,
            "network": network,
            "collected_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None


# ---------------------------------------------------------------------------
# Collect behaviour for ALL visible applications
# ---------------------------------------------------------------------------

def collect_all_behaviours(include_network=True):
    pids_with_windows = _get_pids_with_visible_windows()
    results = []
    seen_apps = set()

    for proc in psutil.process_iter(['pid', 'name']):
        try:
            pid = proc.info['pid']
            name = proc.info['name']

            if not name or pid not in pids_with_windows:
                continue

            # Skip Windows system processes
            try:
                exe_path = proc.exe()
                if exe_path.startswith("C:\\Windows"):
                    continue
            except (psutil.AccessDenied, psutil.NoSuchProcess):
                continue

            # Avoid duplicates
            if name in seen_apps:
                continue
            seen_apps.add(name)

            data = collect_process_behaviour(proc, include_network=include_network)
            if data:
                results.append(data)

        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue

    return results


# ---------------------------------------------------------------------------
# Collect behaviour for a SINGLE process by PID
# ---------------------------------------------------------------------------

def collect_behaviour_by_pid(pid, include_network=True):
    try:
        proc = psutil.Process(pid)
        return collect_process_behaviour(proc, include_network=include_network)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        return None


# ---------------------------------------------------------------------------
# Pretty-print collected data
# ---------------------------------------------------------------------------

def display_behaviour(data_list):
    """Print a formatted table of behavioural data to the console."""
    if not data_list:
        print("  No behavioural data collected.\n")
        return

    print(f"\n{'='*80}")
    print("  Behaviour Data Collection Report")
    print(f"  Collected at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"{'='*80}\n")

    for i, d in enumerate(data_list, 1):
        print(f"  [{i}] {d['name']}  (PID: {d['pid']})")
        print(f"  {'-'*60}")
        print(f"    Executable   : {d['exe_path']}")
        print(f"    Status       : {d['status']}")
        print(f"    CPU Usage    : {d['cpu_percent']:.1f} %")
        print(f"    Memory (RSS) : {d['memory']['rss_mb']:.2f} MB  ({d['memory']['percent']:.2f} %)")
        print(f"    Memory (VMS) : {d['memory']['vms_mb']:.2f} MB")
        print(f"    Uptime       : {_format_uptime(d['runtime']['uptime_seconds'])}")
        print(f"    Started At   : {d['runtime']['started_at']}")

        net = d.get("network")
        if net:
            print(f"    Network Conns: {net['open_connections']}")
            if net.get("note"):
                print(f"                   ({net['note']})")
            for conn in net.get("connection_details", [])[:5]:
                print(f"      - {conn['local_addr']} -> {conn['remote_addr']}  [{conn['status']}]")
            if len(net.get("connection_details", [])) > 5:
                print(f"      ... and {len(net['connection_details']) - 5} more connections")

        print()

    print(f"{'='*80}")
    print(f"  Total applications monitored: {len(data_list)}")
    print(f"{'='*80}\n")


def _format_uptime(seconds):
    """Convert seconds to a human-readable string."""
    days, rem = divmod(int(seconds), 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    parts.append(f"{secs}s")
    return " ".join(parts)
