"""
baseline_store.py
Persistent JSON store for behavioural fingerprints.
Baselines are keyed by normalized exe path and stored at ~/.abfs/baselines.json.
"""

import json
import os
from pathlib import Path
from typing import Optional

STORE_PATH = Path.home() / ".abfs" / "baselines.json"


def load_store() -> dict:
    """Load the full baseline store from disk. Returns {} if file does not exist."""
    if not STORE_PATH.exists():
        return {}
    try:
        with open(STORE_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def save_store(store: dict) -> None:
    """Write the full baseline store to disk atomically, creating the directory if needed."""
    os.makedirs(STORE_PATH.parent, exist_ok=True)
    tmp_path = STORE_PATH.with_suffix(".tmp")
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(store, f, indent=2)
        tmp_path.replace(STORE_PATH)
    except OSError:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)


def get_baseline(store: dict, exe_key: str) -> Optional[dict]:
    """Return the baseline fingerprint for the given exe key, or None if absent."""
    return store.get(exe_key)


def save_baseline(store: dict, exe_key: str, fingerprint: dict) -> None:
    """Insert or replace a baseline fingerprint and persist to disk."""
    store[exe_key] = fingerprint
    save_store(store)
