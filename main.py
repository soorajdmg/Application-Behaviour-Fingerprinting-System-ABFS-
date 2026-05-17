"""
main.py
ABFS — Application Behaviour Fingerprinting System
CLI entry point and phase orchestration controller.

Usage:
  python main.py list [--filter NAME]
  python main.py list apps [--filter NAME]
  python main.py analyze --pid PID [PID ...] [--no-hash] [--baseline-only]
"""

import sys
import argparse
from typing import Optional

import process_discovery
import baseline_store
import monitoring_engine
import analysis_engine
import renderer


# ── stdout UTF-8 reconfiguration (for Windows CP1252 terminals) ───────────

def _configure_stdout() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


# ── CLI argument parser ───────────────────────────────────────────────────

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="abfs",
        description="Application Behaviour Fingerprinting System (ABFS)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py list\n"
            "  python main.py list --filter notepad\n"
            "  python main.py analyze --pid 2044\n"
            "  python main.py analyze --pid 2044 3112\n"
            "  python main.py analyze --pid 2044 --no-hash\n"
            "  python main.py analyze --pid 2044 --baseline-only\n"
        ),
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    # ── list subcommand ───────────────────────────────────────────────────
    list_p = subparsers.add_parser("list", help="List running processes or GUI applications")
    list_p.add_argument(
        "subcommand",
        nargs="?",
        choices=["apps"],
        default=None,
        metavar="apps",
        help="'apps' to show only interactive GUI applications (windows only)",
    )
    list_p.add_argument(
        "--filter",
        metavar="NAME",
        default=None,
        help="Filter by process name substring (case-insensitive)",
    )

    # ── analyze subcommand ────────────────────────────────────────────────
    analyze_p = subparsers.add_parser(
        "analyze",
        help="Fingerprint and monitor process behaviour",
    )
    analyze_p.add_argument(
        "--pid",
        nargs="+",
        type=int,
        required=True,
        metavar="PID",
        help="One or more PIDs to monitor (should share the same executable)",
    )
    analyze_p.add_argument(
        "--no-hash",
        action="store_true",
        help="Skip SHA-256 computation of the executable binary",
    )
    analyze_p.add_argument(
        "--baseline-only",
        action="store_true",
        help="Record or refresh baseline only; skip runtime monitoring",
    )
    analyze_p.add_argument(
        "--remove-baseline",
        action="store_true",
        help="Remove the stored baseline for the given PID's executable and exit",
    )

    return parser


# ── Command handlers ──────────────────────────────────────────────────────

def _cmd_list(args) -> int:
    """Handle the 'list' subcommand (and 'list apps' variant)."""
    store = baseline_store.load_store()
    baseline_keys = set(store.keys())

    if args.subcommand == "apps":
        apps = process_discovery.list_apps(args.filter)
        renderer.print_app_list(apps, baseline_keys)
    else:
        processes = process_discovery.list_processes(args.filter)
        renderer.print_process_list(processes, baseline_keys)

    return 0


def _cmd_analyze(args) -> int:
    """Handle the 'analyze' subcommand — the core ABFS pipeline."""

    pids: list[int] = args.pid
    use_hash: bool = not args.no_hash
    baseline_only: bool = args.baseline_only

    # ── Step 1: Resolve PIDs to process objects ────────────────────────
    print("Resolving PID(s): %s ..." % ", ".join(str(p) for p in pids))
    groups, errors = process_discovery.resolve_pid_group(pids)

    for pid, reason in errors:
        print("  [!] PID %d skipped: %s" % (pid, reason))

    if not groups:
        print("\nError: No accessible processes found for the given PID(s).")
        print("Hint : Try running as administrator for system processes.")
        return 1

    if len(groups) > 1:
        keys = list(groups.keys())
        print(
            "  [!] Warning: PIDs belong to %d different executables. "
            "Using the first group (%s)." % (len(groups), groups[keys[0]]["exe_path"])
        )

    # Take the first (or only) exe group
    exe_key = next(iter(groups))
    group = groups[exe_key]
    exe_path: str = group["exe_path"]
    processes: list = group["processes"]
    active_pids = [p.pid for p in processes]

    print("  Executable : %s" % exe_path)
    print("  Active PIDs: %s" % ", ".join(str(p) for p in active_pids))

    # ── Step 2: Compute SHA-256 hash ──────────────────────────────────
    exe_hash: Optional[str] = None
    if use_hash:
        print("  Computing SHA-256 ...")
        exe_hash = process_discovery.compute_sha256(exe_path)
        if exe_hash:
            print("  SHA-256    : %s" % exe_hash)
        else:
            print("  SHA-256    : (could not read — permission denied or locked)")

    # ── Step 3: Load baseline store ────────────────────────────────────
    store = baseline_store.load_store()
    
    if getattr(args, "remove_baseline", False):
        if baseline_store.remove_baseline(store, exe_key):
            print("\n[✓] Successfully removed baseline for:")
            print("    %s" % exe_path)
        else:
            print("\n[!] No existing baseline found for:")
            print("    %s" % exe_path)
        return 0

    existing_baseline = baseline_store.get_baseline(store, exe_key)

    # ── Step 4: Baseline learning phase ───────────────────────────────
    if existing_baseline is None or baseline_only:
        if existing_baseline is None:
            print("\nNo baseline found for this executable.")
        else:
            print("\n--baseline-only flag set. Re-recording baseline.")

        print("Starting 60-second baseline learning phase ...")
        print("(Ensure the application is running under normal conditions)\n")

        def baseline_progress(elapsed, total):
            renderer.print_baseline_progress(elapsed, total)

        raw_metrics = monitoring_engine.collect_baseline(
            processes,
            duration=60.0,
            interval=1.0,
            progress_cb=baseline_progress,
        )

        print()  # newline after progress bar

        if raw_metrics["sample_count"] == 0:
            print("\nError: No samples collected during baseline learning.")
            print("All monitored processes may have exited.")
            return 1

        fingerprint = monitoring_engine.build_fingerprint(raw_metrics, exe_path, exe_hash)
        baseline_store.save_baseline(store, exe_key, fingerprint)

        print("\nBaseline saved to: %s" % baseline_store.STORE_PATH)
        print("  Samples : %d" % fingerprint["sample_count"])
        print("  CPU mean: %.2f%%" % fingerprint["cpu"]["mean"])
        print("  Files   : %d unique path(s)" % len(fingerprint["files"]["accessed_paths"]))
        print(
            "  Network : sent=%d B  recv=%d B"
            % (fingerprint["network"]["bytes_sent_total"],
               fingerprint["network"]["bytes_recv_total"])
        )

        if baseline_only:
            print("\nBaseline-only mode: done.")
            return 0

        # Re-load the freshly saved baseline for the monitoring phase
        existing_baseline = fingerprint

    # ── Step 5: Runtime monitoring phase ──────────────────────────────
    print("\nBaseline loaded (recorded: %s)." % existing_baseline.get("created_at", "unknown"))
    print("Starting 30-second runtime monitoring phase ...\n")

    def monitor_progress(elapsed, total):
        renderer.print_monitoring_progress(elapsed, total)

    runtime_metrics = monitoring_engine.collect_runtime(
        processes,
        duration=30.0,
        interval=1.0,
        progress_cb=monitor_progress,
    )

    print()  # newline after progress bar

    if runtime_metrics["sample_count"] == 0:
        print("\nError: No samples collected during runtime monitoring.")
        print("All monitored processes may have exited.")
        return 1

    # Add exe info for the report
    runtime_metrics["exe_path"] = exe_path
    runtime_metrics["exe_hash"] = exe_hash

    # ── Step 6: Identity validation ────────────────────────────────────
    baseline_exe_key = process_discovery.normalize_exe(existing_baseline["exe_path"])
    exe_path_mismatch = (baseline_exe_key != exe_key)

    hash_mismatch = False
    if exe_hash and existing_baseline.get("exe_hash"):
        hash_mismatch = (exe_hash != existing_baseline["exe_hash"])

    # ── Step 7: Behaviour analysis ─────────────────────────────────────
    result = analysis_engine.analyze(
        baseline=existing_baseline,
        runtime_metrics=runtime_metrics,
        exe_path_mismatch=exe_path_mismatch,
        hash_mismatch=hash_mismatch,
    )

    # ── Step 8: Render report ──────────────────────────────────────────
    process_info = {
        "exe_path": exe_path,
        "pids": active_pids,
        "exe_hash": exe_hash,
    }

    print()
    renderer.print_report(process_info, existing_baseline, runtime_metrics, result)

    return 0


# ── Entry point ───────────────────────────────────────────────────────────

def main() -> None:
    _configure_stdout()
    parser = _build_parser()
    args = parser.parse_args()

    try:
        if args.command == "list":
            sys.exit(_cmd_list(args))
        elif args.command == "analyze":
            sys.exit(_cmd_analyze(args))
    except KeyboardInterrupt:
        print("\n\nAborted by user.")
        sys.exit(0)
    except Exception as exc:
        print("\nUnexpected error: %s" % exc)
        sys.exit(1)


if __name__ == "__main__":
    main()
