"""
analysis_engine.py
Behaviour Analysis Engine for ABFS.

Computes similarity scores between baseline and runtime metrics,
calculates the weighted Fingerprint Match Score, and determines
the Risk Score and Risk Level classification.

All functions are pure (no I/O), making them independently testable.
"""

import math as _math


# ── Similarity weights ──────────────────────────────────────────────────
CPU_WEIGHT = 0.40
FILE_WEIGHT = 0.35
NETWORK_WEIGHT = 0.25

# ── Identity penalty magnitudes (added to risk score) ──────────────────
EXE_PATH_PENALTY = 20.0   # exe moved or renamed
HASH_PENALTY = 30.0        # binary content changed

# ── Risk level thresholds ───────────────────────────────────────────────
RISK_LOW_MAX = 40.0
RISK_MEDIUM_MAX = 70.0


_CPU_TOLERANCE_PCT = 2.0   # ±2 percentage points always treated as zero deviation
_CPU_MAX_DEVIATION = 20.0  # deviation beyond this collapses to 0% similarity


def cpu_similarity(baseline_mean: float, runtime_mean: float) -> float:
    """
    Normalized CPU similarity (0–100) using absolute deviation with a
    tolerance band.

    Low-CPU apps (e.g. idle Notepad at ~0-3%) fluctuate naturally between
    runs.  Pure proportional comparison breaks here because tiny absolute
    differences produce huge percentage deviations.

    Strategy:
      - Compute absolute deviation in CPU percentage points.
      - Subtract the tolerance band (2 pp) so normal idle drift is forgiven.
      - Scale the remaining deviation against a max-deviation cap (20 pp).
    """
    if baseline_mean == 0.0 and runtime_mean == 0.0:
        return 100.0

    abs_deviation = abs(runtime_mean - baseline_mean)
    # Subtract tolerance; anything within tolerance band → perfect similarity
    penalised = max(0.0, abs_deviation - _CPU_TOLERANCE_PCT)
    similarity = max(0.0, 1.0 - penalised / _CPU_MAX_DEVIATION) * 100.0
    return similarity


_FILE_JACCARD_WEIGHT = 0.5   # weight for path-overlap score
_FILE_VOLUME_WEIGHT  = 0.5   # weight for activity-volume score


def file_similarity(baseline_paths: set, runtime_paths: set) -> float:
    """
    Blended file similarity (0–100): Jaccard path overlap + volume ratio.

    Pure Jaccard breaks when watchdog captures different transient paths
    each run (temp files, cache writes, log rotations) for the same app
    doing the same thing.

    Blend strategy:
      - Jaccard: rewards re-accessing the same stable paths.
      - Volume ratio: rewards similar *amount* of file activity, regardless
        of which specific transient paths appeared.

    Both empty → 100 (expected no activity, saw none).
    One empty  → volume score 0 (activity appeared or disappeared entirely).
    """
    if not baseline_paths and not runtime_paths:
        return 100.0

    b_count = len(baseline_paths)
    r_count = len(runtime_paths)

    # Jaccard on path sets
    if baseline_paths and runtime_paths:
        intersection = len(baseline_paths & runtime_paths)
        union = len(baseline_paths | runtime_paths)
        jaccard = (intersection / union) * 100.0
    else:
        jaccard = 0.0

    # Volume similarity: how close are the counts?
    if b_count == 0 and r_count == 0:
        volume = 100.0
    elif b_count == 0 or r_count == 0:
        volume = 0.0
    else:
        ratio = min(b_count, r_count) / max(b_count, r_count)
        volume = ratio * 100.0

    return _FILE_JACCARD_WEIGHT * jaccard + _FILE_VOLUME_WEIGHT * volume


_NET_NOISE_FLOOR = 512 * 1024   # 512 KB — differences below this are noise
_NET_TOLERANCE_RATIO = 3.0      # up to 3× difference is "similar" (system bg traffic)


def network_similarity(
    baseline_sent: int,
    baseline_recv: int,
    runtime_sent: int,
    runtime_recv: int,
) -> float:
    """
    Log-scale network similarity (0–100).

    Raw proportional comparison is unreliable because network counters are
    system-wide (not per-process).  Background OS/browser traffic during
    either window skews the delta enormously.

    Strategy:
      - If both windows are below the noise floor (512 KB), treat as equal.
      - Compare on log scale: score = 100 * (1 - |log10(r/b)| / log10(cap))
        where cap = _NET_TOLERANCE_RATIO (3×).  This means a 3× difference
        still scores ~0%, but a 1.5× difference scores ~50%.
      - Anything within the noise floor of each other → 100%.
    """
    baseline_total = baseline_sent + baseline_recv
    runtime_total = runtime_sent + runtime_recv

    if baseline_total == 0 and runtime_total == 0:
        return 100.0

    # Both below noise floor → treat as equivalent idle traffic
    if baseline_total <= _NET_NOISE_FLOOR and runtime_total <= _NET_NOISE_FLOOR:
        return 100.0

    if baseline_total == 0 or runtime_total == 0:
        return 0.0

    log_ratio = abs(_math.log10(runtime_total / baseline_total))
    log_cap = _math.log10(_NET_TOLERANCE_RATIO)
    return max(0.0, 1.0 - log_ratio / log_cap) * 100.0


def compute_match_score(
    cpu_sim: float,
    file_sim: float,
    net_sim: float,
) -> float:
    """
    Weighted Fingerprint Match Score (0–100).
    CPU 40%  +  Files 35%  +  Network 25%
    """
    return (cpu_sim * CPU_WEIGHT) + (file_sim * FILE_WEIGHT) + (net_sim * NETWORK_WEIGHT)


def compute_risk_score(
    match_score: float,
    exe_path_mismatch: bool = False,
    hash_mismatch: bool = False,
) -> tuple[float, float]:
    """
    Compute Risk Score = 100 - match_score + identity penalties.
    Returns (risk_score, identity_penalty).
    Risk score is clamped to [0, 100].
    """
    identity_penalty = 0.0
    if exe_path_mismatch:
        identity_penalty += EXE_PATH_PENALTY
    if hash_mismatch:
        identity_penalty += HASH_PENALTY
    risk = 100.0 - match_score + identity_penalty
    return min(100.0, max(0.0, risk)), identity_penalty


def risk_level(risk_score: float) -> tuple[str, str]:
    """
    Classify risk score into (level_str, verdict_str).
    LOW < 40 → NORMAL
    40–70 → MEDIUM / ABNORMAL
    > 70 → HIGH / ABNORMAL
    """
    if risk_score < RISK_LOW_MAX:
        return "LOW", "NORMAL"
    elif risk_score <= RISK_MEDIUM_MAX:
        return "MEDIUM", "ABNORMAL"
    else:
        return "HIGH", "ABNORMAL"


def analyze(
    baseline: dict,
    runtime_metrics: dict,
    exe_path_mismatch: bool = False,
    hash_mismatch: bool = False,
) -> dict:
    """
    Top-level analysis function. Computes all similarity scores, match score,
    risk score, and risk classification from baseline and runtime dicts.

    Returns an AnalysisResult dict.
    """
    # CPU similarity
    cpu_sim = cpu_similarity(
        baseline["cpu"]["mean"],
        runtime_metrics["cpu"]["mean"],
    )

    # File similarity (Jaccard on path sets)
    baseline_files = set(baseline["files"]["accessed_paths"])
    runtime_files = set(runtime_metrics["files"]["accessed_paths"])
    file_sim = file_similarity(baseline_files, runtime_files)

    # Network similarity
    net_sim = network_similarity(
        baseline["network"]["bytes_sent_total"],
        baseline["network"]["bytes_recv_total"],
        runtime_metrics["network"]["bytes_sent_total"],
        runtime_metrics["network"]["bytes_recv_total"],
    )

    # Aggregated scores
    match = compute_match_score(cpu_sim, file_sim, net_sim)
    risk, penalty = compute_risk_score(match, exe_path_mismatch, hash_mismatch)
    level, verdict = risk_level(risk)

    return {
        "cpu_similarity": round(cpu_sim, 2),
        "file_similarity": round(file_sim, 2),
        "network_similarity": round(net_sim, 2),
        "match_score": round(match, 2),
        "exe_path_mismatch": exe_path_mismatch,
        "hash_mismatch": hash_mismatch,
        "identity_penalty": round(penalty, 1),
        "risk_score": round(risk, 2),
        "risk_level": level,
        "verdict": verdict,
    }
