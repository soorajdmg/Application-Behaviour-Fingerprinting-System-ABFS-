"""
renderer.py
ASCII CLI visualization renderer for ABFS reports.
Produces bar graphs and structured 6-section behaviour reports.
"""

import sys

# Unicode block characters — renderer falls back to ASCII if encoding fails
_FILL = "\u2588"   # █  full block
_EMPTY = "\u2591"  # ░  light shade
_FILL_FALLBACK = "#"
_EMPTY_FALLBACK = "-"

REPORT_WIDTH = 62


def _safe_char(char: str, fallback: str) -> str:
    """Return char if it can be encoded to stdout, otherwise return fallback."""
    try:
        char.encode(sys.stdout.encoding or "utf-8")
        return char
    except (UnicodeEncodeError, LookupError):
        return fallback


def render_bar(value: float, width: int = 10) -> str:
    """
    Build an ASCII bar graph for a 0–100 percentage value.
    Example: render_bar(72.4) → "[███████░░░]  72.4%"
    """
    value = max(0.0, min(100.0, value))
    filled = round((value / 100.0) * width)
    fill_ch = _safe_char(_FILL, _FILL_FALLBACK)
    empty_ch = _safe_char(_EMPTY, _EMPTY_FALLBACK)
    bar = fill_ch * filled + empty_ch * (width - filled)
    return "[%s] %5.1f%%" % (bar, value)


def _fmt_bytes(n: int) -> str:
    """Format byte count to a human-readable string."""
    if n < 0:
        sign = "-"
        n = -n
    else:
        sign = ""
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return "%s%.1f %s" % (sign, n, unit)
        n /= 1024
    return "%s%.1f TB" % (sign, n)


def _fmt_bytes_signed(n: int) -> str:
    """Format a signed byte delta (e.g. +1.2 KB or -800 B)."""
    prefix = "+" if n >= 0 else ""
    return prefix + _fmt_bytes(n)


def _divider(char: str = "=") -> str:
    return char * REPORT_WIDTH


def _section(title: str) -> str:
    return "\n[%s]" % title


def print_report(
    process_info: dict,
    baseline: dict,
    runtime_metrics: dict,
    analysis_result: dict,
) -> None:
    """
    Print the full 6-section ABFS Application Behaviour Report to stdout.

    process_info keys : exe_path, pids, exe_hash
    baseline keys     : see BaselineFingerprint schema
    runtime_metrics   : see RuntimeMetrics schema
    analysis_result   : see AnalysisResult schema
    """
    p = print  # shorthand

    p(_divider("="))
    p("  ABFS — Application Behaviour Fingerprinting System")
    p("  Application Behaviour Report")
    p(_divider("="))

    # ── Section 1: Process Identity ──────────────────────────────────────
    p(_section("1. PROCESS IDENTITY"))
    p("  Executable : %s" % process_info["exe_path"])
    p("  PIDs       : %s" % ", ".join(str(pid) for pid in process_info["pids"]))
    hash_val = process_info.get("exe_hash") or "(not computed)"
    p("  SHA-256    : %s" % hash_val)

    if analysis_result.get("exe_path_mismatch"):
        p("  [!] WARNING: Exe path differs from baseline record")
    if analysis_result.get("hash_mismatch"):
        p("  [!] WARNING: SHA-256 hash differs — binary may have been modified")

    # ── Section 2: Baseline Summary ──────────────────────────────────────
    p(_section("2. BASELINE SUMMARY  (recorded: %s)" % baseline.get("created_at", "unknown")))
    bc = baseline["cpu"]
    bf = baseline["files"]
    bn = baseline["network"]
    p("  CPU        : mean=%.2f%%  peak=%.2f%%  variance=%.4f"
      % (bc["mean"], bc["peak"], bc["variance"]))
    p("  File paths : %d unique path(s) observed  (%d events)"
      % (len(bf["accessed_paths"]), bf.get("access_event_count", 0)))
    p("  Network    : sent=%-10s  recv=%s"
      % (_fmt_bytes(bn["bytes_sent_total"]), _fmt_bytes(bn["bytes_recv_total"])))
    p("  Window     : %ds  (%d samples)"
      % (baseline.get("observation_duration_secs", 0), baseline.get("sample_count", 0)))

    # ── Section 3: Runtime Observations ─────────────────────────────────
    p(_section("3. RUNTIME OBSERVATIONS  (%ds window, %d samples)"
               % (runtime_metrics.get("observation_duration_secs", 0),
                  runtime_metrics.get("sample_count", 0))))
    rc = runtime_metrics["cpu"]
    rf = runtime_metrics["files"]
    rn = runtime_metrics["network"]
    p("  CPU        : mean=%.2f%%  peak=%.2f%%  variance=%.4f"
      % (rc["mean"], rc["peak"], rc["variance"]))
    p("  File paths : %d unique path(s) observed  (%d events)"
      % (len(rf["accessed_paths"]), rf.get("access_event_count", 0)))
    p("  Network    : sent=%-10s  recv=%s"
      % (_fmt_bytes(rn["bytes_sent_total"]), _fmt_bytes(rn["bytes_recv_total"])))

    for warning in runtime_metrics.get("warnings", []):
        p("  [!] %s" % warning)

    # ── Section 4: Deviation Breakdown ───────────────────────────────────
    p(_section("4. DEVIATION BREAKDOWN"))
    cpu_delta = rc["mean"] - bc["mean"]
    p("  CPU mean delta    : %+.2f%% from baseline (baseline=%.2f%%, runtime=%.2f%%)"
      % (cpu_delta, bc["mean"], rc["mean"]))
    p("  CPU peak delta    : %+.2f%% (baseline peak=%.2f%%, runtime peak=%.2f%%)"
      % (rc["peak"] - bc["peak"], bc["peak"], rc["peak"]))

    baseline_file_count = len(bf["accessed_paths"])
    runtime_file_count = len(rf["accessed_paths"])
    file_delta = runtime_file_count - baseline_file_count
    p("  File path delta   : %+d paths  (baseline=%d, runtime=%d)"
      % (file_delta, baseline_file_count, runtime_file_count))

    baseline_net = bn["bytes_sent_total"] + bn["bytes_recv_total"]
    runtime_net = rn["bytes_sent_total"] + rn["bytes_recv_total"]
    net_delta = runtime_net - baseline_net
    p("  Network delta     : %s from baseline  (baseline=%s, runtime=%s)"
      % (_fmt_bytes_signed(net_delta), _fmt_bytes(baseline_net), _fmt_bytes(runtime_net)))

    if analysis_result.get("identity_penalty", 0) > 0:
        p("  Identity penalty  : +%.0f pts  (exe or hash mismatch detected)"
          % analysis_result["identity_penalty"])

    # ── Section 5: Similarity Scores ─────────────────────────────────────
    p(_section("5. SIMILARITY SCORES"))
    p("  CPU     (40%%)  %s" % render_bar(analysis_result["cpu_similarity"]))
    p("  Files   (35%%)  %s" % render_bar(analysis_result["file_similarity"]))
    p("  Network (25%%)  %s" % render_bar(analysis_result["network_similarity"]))
    p("  " + _divider("-")[:40])
    p("  Match Score    %s" % render_bar(analysis_result["match_score"]))

    # ── Section 6: Risk Assessment ───────────────────────────────────────
    p(_section("6. RISK ASSESSMENT"))
    p("  Fingerprint Match Score : %.1f%%" % analysis_result["match_score"])
    penalty = analysis_result.get("identity_penalty", 0)
    if penalty > 0:
        p("  Identity Penalty        : +%.0f pts" % penalty)
    p("  Risk Score              : %.1f / 100" % analysis_result["risk_score"])
    p("  Risk Level              : %s" % analysis_result["risk_level"])
    p("")

    verdict = analysis_result["verdict"]
    risk_level = analysis_result["risk_level"]
    if verdict == "NORMAL":
        p("  ╔══════════════════════════════════════╗")
        p("  ║  VERDICT:  NORMAL                    ║")
        p("  ║  Behaviour matches baseline profile  ║")
        p("  ╚══════════════════════════════════════╝")
    elif risk_level == "MEDIUM":
        p("  ╔══════════════════════════════════════╗")
        p("  ║  VERDICT:  ABNORMAL  [MEDIUM RISK]   ║")
        p("  ║  Moderate deviation from baseline    ║")
        p("  ╚══════════════════════════════════════╝")
    else:
        p("  ╔══════════════════════════════════════╗")
        p("  ║  VERDICT:  ABNORMAL  [HIGH RISK]     ║")
        p("  ║  Significant deviation detected      ║")
        p("  ╚══════════════════════════════════════╝")

    p("\n" + _divider("="))


def _wrap_pids(pids: list[int], indent: int, width: int) -> list[str]:
    """
    Wrap a list of PIDs into lines that fit within `width` columns,
    each indented by `indent` spaces.
    """
    prefix = " " * indent
    lines = []
    current = prefix
    for i, pid in enumerate(pids):
        token = str(pid) + ("," if i < len(pids) - 1 else "")
        if len(current) + len(token) + 1 > width and current.strip():
            lines.append(current.rstrip(","))
            current = prefix + token + " "
        else:
            current += token + " "
    if current.strip():
        lines.append(current.rstrip(", "))
    return lines


def print_process_list(processes: list[dict], baseline_keys: set = None) -> None:
    """
    Print a card-style grouped list of running processes.
    Each unique executable is one card; multi-process apps list all PIDs
    wrapped to fit the terminal width.
    """
    from process_discovery import normalize_exe

    if baseline_keys is None:
        baseline_keys = set()

    W = REPORT_WIDTH

    # ── Group by normalized exe path ──────────────────────────────────────
    groups: dict[str, dict] = {}
    for proc in processes:
        exe = proc["exe"] or ""
        key = normalize_exe(exe) if exe else ("__noexe__" + proc["name"])
        if key not in groups:
            groups[key] = {
                "name": proc["name"],
                "exe": exe,
                "pids": [],
                "statuses": set(),
            }
        groups[key]["pids"].append(proc["pid"])
        groups[key]["statuses"].add(proc["status"])

    sorted_groups = sorted(groups.items(), key=lambda kv: min(kv[1]["pids"]))
    total_processes = len(processes)

    # ── Header ────────────────────────────────────────────────────────────
    print(_divider("="))
    print("  ABFS  ·  Running Processes")
    print(_divider("="))

    for idx, (key, g) in enumerate(sorted_groups):
        pids        = sorted(g["pids"])
        name        = g["name"]
        exe         = g["exe"]
        proc_count  = len(pids)
        has_baseline = key in baseline_keys
        status      = sorted(g["statuses"])[0]

        # ── Card header line ──────────────────────────────────────────────
        badge     = " [B]" if has_baseline else ""
        tag       = (" (%d processes)" % proc_count) if proc_count > 1 else ""
        print("  %s%s%s" % (name, tag, badge))

        # ── Exe path (truncate to fit, prefixed with └) ───────────────────
        exe_prefix  = "  \u2514 "           # "  └ "
        max_exe_len = W - len(exe_prefix)
        if len(exe) > max_exe_len:
            exe_display = "..." + exe[-(max_exe_len - 3):]
        else:
            exe_display = exe
        print("%s%s" % (exe_prefix, exe_display))

        # ── PID list ──────────────────────────────────────────────────────
        if proc_count == 1:
            print("    PID    : %d  |  status: %s" % (pids[0], status))
        else:
            print("    PIDs   : ", end="")
            pid_lines = _wrap_pids(pids, indent=13, width=W)
            # First line goes on the same line as "PIDs   : "
            print(pid_lines[0].lstrip())
            for pl in pid_lines[1:]:
                print(pl)
            print("    Status : %s  |  To analyze: --pid %s"
                  % (status, " ".join(str(p) for p in pids)))

        # ── Divider between cards (not after last) ────────────────────────
        if idx < len(sorted_groups) - 1:
            print("  " + _divider("-")[:W - 2])

    # ── Footer ────────────────────────────────────────────────────────────
    print(_divider("="))
    print("  %d application(s)  ·  %d total process(es)  ·  [B] = baseline on disk"
          % (len(groups), total_processes))
    print(_divider("="))


def print_baseline_progress(elapsed: float, total: float) -> None:
    """Print an inline progress bar during baseline learning (overwrites current line)."""
    pct = (elapsed / total) * 100.0 if total > 0 else 0
    bar = render_bar(pct, width=20)
    line = "\r  Baseline learning... %s  %.0f/%ds" % (bar, elapsed, total)
    sys.stdout.write(line)
    sys.stdout.flush()


def print_monitoring_progress(elapsed: float, total: float) -> None:
    """Print an inline progress bar during runtime monitoring."""
    pct = (elapsed / total) * 100.0 if total > 0 else 0
    bar = render_bar(pct, width=20)
    line = "\r  Runtime monitoring... %s  %.0f/%ds" % (bar, elapsed, total)
    sys.stdout.write(line)
    sys.stdout.flush()
