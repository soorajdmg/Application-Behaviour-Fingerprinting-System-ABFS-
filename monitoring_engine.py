"""
monitoring_engine.py
Monitoring Engine for ABFS.

Collects CPU, file system, and network metrics across a group of processes
over a timed observation window.  Two public entry points:

  collect_baseline(processes, duration=60) → RuntimeMetrics dict
  collect_runtime(processes, duration=30)  → RuntimeMetrics dict

Both share the same internal loop; only the default duration differs.

Watchdog PID-context strategy
──────────────────────────────
watchdog is directory-aware, not PID-aware.  We approximate PID-contextual
file tracking by:
  1. Seeding watched directories from proc.open_files() at start
  2. Refreshing watched dirs every 10 ticks as the process opens new files
  3. Scheduling each directory non-recursively (reduces noise)
  4. The handler logs all file events inside those directories

This captures the vast majority of file activity for the target processes
with acceptable noise from other processes sharing the same directories.
"""

import os
import time
import threading
import statistics
from typing import Optional, List

import psutil
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


# ── Helpers ───────────────────────────────────────────────────────────────

def _snapshot_net():
    """Return current system-wide network I/O counters."""
    return psutil.net_io_counters()


def _get_open_dirs(processes: list) -> set:
    """
    Return the set of normalized directory paths that are currently open
    across all alive processes.  Silently ignores access errors.
    """
    dirs: set[str] = set()
    for proc in processes:
        try:
            for f in proc.open_files():
                if f.path:
                    d = os.path.normcase(os.path.dirname(f.path))
                    if d and os.path.isdir(d):
                        dirs.add(d)
        except (psutil.NoSuchProcess, psutil.AccessDenied, OSError):
            continue
    return dirs


def _cpu_stats(samples: list[float]) -> dict:
    """Compute mean, peak, and variance from a list of CPU % samples."""
    if not samples:
        return {"mean": 0.0, "peak": 0.0, "variance": 0.0}
    mean = statistics.mean(samples)
    peak = max(samples)
    variance = statistics.variance(samples) if len(samples) > 1 else 0.0
    return {
        "mean": round(mean, 4),
        "peak": round(peak, 4),
        "variance": round(variance, 6),
    }


# ── Watchdog collector ────────────────────────────────────────────────────

class _FileEventHandler(FileSystemEventHandler):
    """Thread-safe handler that records normalized file paths into a set."""

    def __init__(self, watched_dirs_ref: set, event_log: set, lock: threading.Lock):
        super().__init__()
        self._watched_dirs = watched_dirs_ref
        self._event_log = event_log
        self._lock = lock

    def on_any_event(self, event):
        if event.is_directory:
            return
        src = os.path.normcase(event.src_path)
        src_dir = os.path.normcase(os.path.dirname(event.src_path))
        # Only record if the file lives in one of our watched directories
        for watched in self._watched_dirs:
            if src_dir == watched or src_dir.startswith(watched + os.sep):
                with self._lock:
                    self._event_log.add(src)
                return


class WatchdogCollector:
    """
    Manages a watchdog Observer for the set of directories currently open
    by monitored processes.  Supports dynamic addition of new directories.
    """

    def __init__(self, initial_dirs: set):
        self.watched_dirs: set[str] = set()
        self._event_log: set[str] = set()
        self._lock = threading.Lock()
        self._handler = _FileEventHandler(self.watched_dirs, self._event_log, self._lock)
        self._observer = Observer()
        self._event_count = 0

        for d in initial_dirs:
            self._schedule(d)

    def _schedule(self, directory: str) -> None:
        """Schedule a directory for watching if it exists and isn't already watched."""
        d = os.path.normcase(directory)
        if d not in self.watched_dirs and os.path.isdir(d):
            try:
                self._observer.schedule(self._handler, d, recursive=False)
                self.watched_dirs.add(d)
            except Exception:
                pass  # Some system dirs may refuse scheduling; skip silently

    def start(self) -> None:
        self._observer.start()

    def add_dirs(self, new_dirs: set) -> None:
        """Add any directories not yet being watched."""
        for d in new_dirs:
            self._schedule(d)

    def stop(self) -> None:
        self._observer.stop()
        self._observer.join()

    def get_file_set(self) -> set:
        with self._lock:
            return set(self._event_log)

    def get_event_count(self) -> int:
        with self._lock:
            return len(self._event_log)


# ── Core collection loop ──────────────────────────────────────────────────

def _run_collection_loop(
    processes: list,
    duration: float,
    interval: float,
    progress_cb=None,
) -> dict:
    """
    Run the timed observation loop and return a raw RuntimeMetrics dict.

    progress_cb: optional callable(elapsed, total) called each tick for display.
    """
    warnings: list[str] = []
    cpu_samples: list[float] = []
    alive = list(processes)

    # Network baseline snapshot
    net_start = _snapshot_net()

    # Seed watchdog with currently open directories
    initial_dirs = _get_open_dirs(alive)
    watcher = WatchdogCollector(initial_dirs)
    watcher.start()

    # Prime cpu_percent (first call always returns 0.0 — must discard)
    for proc in alive:
        try:
            proc.cpu_percent(interval=None)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

    start_time = time.time()
    tick = 0

    while True:
        time.sleep(interval)
        elapsed = time.time() - start_time
        tick += 1

        if elapsed >= duration:
            break

        # Collect CPU across all still-alive processes
        total_cpu = 0.0
        still_alive = []
        for proc in alive:
            try:
                total_cpu += proc.cpu_percent(interval=None)
                still_alive.append(proc)
            except psutil.NoSuchProcess:
                warnings.append("PID %d exited at t=%.0fs" % (proc.pid, elapsed))
            except psutil.AccessDenied:
                still_alive.append(proc)  # keep; contributes 0 to cpu

        alive = still_alive
        if not alive:
            warnings.append("All monitored processes exited before collection completed.")
            break

        cpu_samples.append(total_cpu)

        # Refresh watched dirs every 10 ticks
        if tick % 10 == 0:
            new_dirs = _get_open_dirs(alive)
            watcher.add_dirs(new_dirs)

        if progress_cb:
            progress_cb(elapsed, duration)

    watcher.stop()
    net_end = _snapshot_net()

    actual_duration = time.time() - start_time

    # Network deltas (system-wide; scoped to observation window)
    bytes_sent = max(0, net_end.bytes_sent - net_start.bytes_sent)
    bytes_recv = max(0, net_end.bytes_recv - net_start.bytes_recv)

    file_paths = watcher.get_file_set()
    event_count = watcher.get_event_count()

    cpu = _cpu_stats(cpu_samples)

    return {
        "pids": [p.pid for p in processes],
        "observation_duration_secs": round(actual_duration, 1),
        "sample_count": len(cpu_samples),
        "cpu": cpu,
        "files": {
            "accessed_paths": sorted(file_paths),
            "access_event_count": event_count,
        },
        "network": {
            "bytes_sent_total": bytes_sent,
            "bytes_recv_total": bytes_recv,
        },
        "warnings": warnings,
    }


# ── Public API ────────────────────────────────────────────────────────────

def collect_baseline(
    processes: list,
    duration: float = 60.0,
    interval: float = 1.0,
    progress_cb=None,
) -> dict:
    """
    Run the baseline learning phase (default 60 s).
    Returns a RuntimeMetrics dict suitable for conversion to a BaselineFingerprint.
    """
    return _run_collection_loop(processes, duration, interval, progress_cb)


def collect_runtime(
    processes: list,
    duration: float = 30.0,
    interval: float = 1.0,
    progress_cb=None,
) -> dict:
    """
    Run the runtime monitoring phase (default 30 s).
    Returns a RuntimeMetrics dict for comparison against a stored baseline.
    """
    return _run_collection_loop(processes, duration, interval, progress_cb)


def build_fingerprint(
    runtime_metrics: dict,
    exe_path: str,
    exe_hash: Optional[str],
) -> dict:
    """
    Convert a RuntimeMetrics dict into a BaselineFingerprint dict
    suitable for storage in the baseline store.
    """
    import datetime
    return {
        "exe_path": exe_path,
        "exe_hash": exe_hash,
        "created_at": datetime.datetime.now().isoformat(timespec="seconds"),
        "observation_duration_secs": runtime_metrics["observation_duration_secs"],
        "sample_count": runtime_metrics["sample_count"],
        "cpu": runtime_metrics["cpu"],
        "files": runtime_metrics["files"],
        "network": runtime_metrics["network"],
    }
