# Application Behaviour Fingerprinting System (ABFS)

ABFS is a robust, terminal-based behaviour analysis engine that fingerprints and monitors Windows applications. Instead of relying on static malware signatures, ABFS learns how an application *normally* behaves (its baseline) and flags abnormal behaviour at runtime based on CPU usage, File System activity, and Network I/O.

---

## 🏗️ System Architecture & Modules

The project is modularized into six highly decoupled components to ensure clean separation of concerns:

### 1. `main.py` (The CLI Orchestrator)
The entry point of the application. It provides the command-line interface using `argparse`. 
- **Commands:**
  - `list`: Lists all user processes, heavily filtered to remove background Windows services.
  - `list apps`: Uses Win32 APIs to list *only* interactive GUI applications (e.g., WhatsApp, Chrome).
  - `analyze`: The core command. It takes a `--pid`, resolves the executable, computes its SHA-256 hash, and then orchestrates the baseline learning or runtime monitoring phases.

### 2. `process_discovery.py` (Process & GUI Detection)
Responsible for finding, filtering, and grouping running processes.
- **Service Filtering:** Uses heuristic layering (SCM registry checks, system account filters, and blocklists) to exclude noise like `svchost.exe` and background daemons.
- **GUI Detection (`list apps`):** Uses the `ctypes` Win32 API (`EnumWindows`) to find processes that own a *visible* window with a native title bar (`WS_CAPTION + WS_SYSMENU`), or a frameless window larger than 200x100px. This definitively identifies real user-launched apps.

### 3. `monitoring_engine.py` (The Data Collector)
Collects the raw metrics for both the **Baseline (60s)** and **Runtime (30s)** phases.
- **CPU:** Uses `psutil.cpu_percent()` on the specific PIDs.
- **Network:** Takes a system-wide network snapshot (`psutil.net_io_counters()`) at the start and end of the observation window.
- **Files:** Uses the `watchdog` library to actively monitor the directories where the application has open files (discovered via `proc.open_files()`). It records every specific file path accessed.

### 4. `analysis_engine.py` (The Scoring Brain)
A pure-math module (no I/O) that compares the Baseline metrics against the Runtime metrics to generate a Fingerprint Match Score. 
*See "How Similarity is Calculated" below.*

### 5. `baseline_store.py` (Storage Manager)
A tiny, safe JSON storage wrapper. It saves the baseline fingerprints to `~/.abfs/baselines.json`, keyed by the normalized path of the executable.

### 6. `renderer.py` (The UI Engine)
Responsible for all ASCII terminal output. It formats the progress bars, groupings, and the final 6-section coloured Analysis Report. It dynamically applies ANSI color codes (Red/Yellow/Green) based on the final Risk Level.

---

## 🧠 How Similarity is Calculated

When an application is analyzed, its runtime behaviour is compared to its baseline across three vectors.

### 1. CPU Similarity (Weight: 40%)
Low-CPU apps naturally fluctuate (e.g., jumping from 0% to 2% idle). Pure percentage comparisons break here. 
- **Method:** ABFS calculates the *absolute deviation* in percentage points. 
- **Tolerance:** A 2.0% tolerance band is applied. Any deviation under 2% is forgiven entirely.
- **Cap:** A deviation of 20% or more results in a 0% similarity score.

### 2. File Similarity (Weight: 35%)
Some apps generate unique temporary files every run, which breaks simple exact-path matching.
- **Method:** A blended score consisting of two parts:
  - **Jaccard Index (50%):** Measures exact path overlap (Intersection / Union).
  - **Volume Ratio (50%):** Measures if the *amount* of file activity is similar, even if the paths are entirely different.

### 3. Network Similarity (Weight: 25%)
Because network tracking is system-wide, background OS traffic causes large raw byte differences.
- **Method:** Log-scale comparison.
- **Noise Floor:** If both baseline and runtime traffic are under 512 KB, it is considered normal idle noise (100% similarity).
- **Log Ratio:** If above the floor, ABFS tolerates up to a 3x difference in traffic magnitude before dropping the score to 0%.

### 🚨 Risk Assessment & Verdict
The weighted similarities generate a **Match Score (0-100%)**. 
The **Risk Score** is calculated as `100 - Match Score`, plus identity penalties (e.g., if the executable's SHA-256 hash changed, adding +30 points).

- **NORMAL (Green):** Risk < 40
- **MEDIUM RISK (Yellow):** Risk 40-70
- **HIGH RISK (Red):** Risk > 70

---

## 💻 Usage Guide

**1. See what apps are running:**
```bash
python main.py list apps
```

**2. Baseline an application (Learn its normal behaviour):**
```bash
python main.py analyze --pid <PID> --baseline-only
```

**3. Monitor an application (Compare to baseline):**
```bash
python main.py analyze --pid <PID>
```

**4. Remove a saved baseline:**
```bash
python main.py analyze --pid <PID> --remove-baseline
```

---

## 🎭 Presentation & Demo Guide

A special script is included to perfectly demonstrate ABFS detecting a simulated malware attack.

**Step 1:** Run the simulator in Terminal A.
```bash
python demo_tools\anomaly_simulator.py
```
*Note the PID it prints out. Leave the script sitting in its "IDLE STATE".*

**Step 2:** In Terminal B, establish the normal baseline.
```bash
python main.py analyze --pid <PID> --baseline-only
```

**Step 3:** Back in Terminal A, type `start`. 
*The script will use background threads to spike the CPU, write junk files to disk (using a watchdog anchor to ensure detection), and download files from the internet.*

**Step 4:** While the anomaly is running, return to Terminal B and analyze it.
```bash
python main.py analyze --pid <PID>
```

**Result:** ABFS will output a beautiful, bright red **HIGH RISK** verdict, explicitly showing the CPU, File, and Network values skyrocketing compared to the idle baseline.
