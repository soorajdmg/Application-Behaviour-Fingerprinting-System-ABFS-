"""
process_discovery.py
Handles process enumeration, PID resolution, exe path normalization,
and SHA-256 hash computation for the ABFS pipeline.
"""

import os
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


def list_processes(filter_str: str = None) -> list[dict]:
    """
    Return a list of running process dicts with keys:
    pid, name, exe, status, username.
    Silently skips processes that raise access errors.
    Optionally filters by case-insensitive name substring.
    """
    results = []
    for proc in psutil.process_iter(["pid", "name", "exe", "status", "username"]):
        try:
            info = proc.info
            name = info.get("name") or ""
            if filter_str and filter_str.lower() not in name.lower():
                continue
            results.append({
                "pid": info["pid"],
                "name": name,
                "exe": info.get("exe") or "",
                "status": info.get("status", "?"),
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
