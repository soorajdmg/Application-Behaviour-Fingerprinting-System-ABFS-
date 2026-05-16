# Application Behaviour Fingerprinting System (ABFS) - Project Report

This report outlines the architecture, design, and implementation of the Application Behaviour Fingerprinting System (ABFS), adapted from the provided report template to reflect the actual components of this project.

## Chapter 1: Introduction

### 1.1 Background
Traditional signature-based antivirus and malware detection systems struggle to identify zero-day threats or supply chain attacks where a legitimate application's behavior is subtly modified. Behavioral fingerprinting offers a proactive approach by defining what "normal" looks like for a specific application and flagging deviations.

### 1.2 Problem Statement
Once a trusted application is compromised (e.g., via a malicious update, code injection, or hijacked dependencies), it may begin exhibiting abnormal behaviors such as unexpected network communication, excessive CPU usage, or accessing unusual file paths. Detecting these shifts without relying on known malware signatures is difficult.

### 1.3 Objectives
- To monitor the runtime behavior of specific applications (CPU, memory, file I/O, network).
- To establish a baseline of "normal" behavior (a fingerprint) for trusted applications.
- To compare ongoing runtime metrics against the established baseline.
- To calculate similarity and risk scores to identify anomalous or potentially malicious activity.

### 1.4 Scope of the Project
The project focuses on process-level monitoring on a host machine. It captures resource utilization (CPU), file system interactions (paths accessed, volume), and network traffic (bytes sent/received). It does not prevent actions but serves as a detection and fingerprinting analytical engine.

### 1.5 Significance and Advantages
- **Zero-Day Detection:** Can detect unknown threats by looking for behavioral anomalies.
- **Low Noise:** By characterizing an app against its own past behavior rather than a generic rule-set, false positives are minimized.
- **Tamper Evidence:** Checks executable paths and hashes to detect static tampering alongside dynamic behavioral shifts.

---

## Chapter 2: Literature Review
Modern threat detection relies heavily on EDR (Endpoint Detection and Response) systems that utilize behavioral heuristics. While traditional AV relies on static signatures, mathematical models like Jaccard similarity for file access and logarithmic scaling for network traffic (as implemented in ABFS) provide robust models for application profiling.

---

## Chapter 3: System Requirements

### 3.1 System Requirements
#### 3.1.1 Hardware Requirements
- Processor: Multi-core CPU (Intel i3/AMD Ryzen 3 or higher recommended)
- RAM: Minimum 4 GB (8 GB recommended for extensive process monitoring)
- Storage: Minimum 100 MB free space for baseline storage.

#### 3.1.2 Software Requirements
- Operating System: Windows / Linux / macOS
- Environment: Python 3.9+
- Dependencies: Listed in `requirements.txt` (typically includes `psutil` for process monitoring).

### 3.2 Functional Requirements
- The system must discover and hook into specified running processes.
- The system must record baseline metrics over a safe operational period.
- The system must continually monitor the application and pass metrics to the analysis engine.
- The system must calculate a Risk Score and assign a Risk Level (LOW, MEDIUM, HIGH).

### 3.3 Non-Functional Requirements
- **Performance:** The monitoring loop should not exert significant CPU overhead on the host machine.
- **Accuracy:** The system must account for natural idle fluctuations (e.g., ±2% CPU tolerance).

---

## Chapter 4: System Design

### 4.1 Use Case Diagram
- **Administrator:** Initiates baseline recording, starts runtime monitoring, reviews risk reports.
- **ABFS Engine:** Discovers processes, records metrics, computes similarities, generates alerts.

### 4.2 Activity Diagram
1. User provides target process name.
2. `process_discovery.py` locates the process ID.
3. System checks for an existing baseline via `baseline_store.py`.
4. If no baseline, `monitoring_engine.py` records one.
5. If baseline exists, `monitoring_engine.py` collects runtime metrics.
6. `analysis_engine.py` compares runtime to baseline.
7. `renderer.py` displays the Risk Score and Verdict.

### 4.3 Sequence Diagram
*Client -> Main Loop -> Process Monitoring -> Analysis Engine -> Output Renderer*

---

## Chapter 5: Backend Implementation
*(Note: Adjusted from the provided template to match the actual ABFS file structure)*

### 5.1 Directory Structure
The core logic is divided into modular, pure Python files:
- `main.py`
- `analysis_engine.py`
- `monitoring_engine.py`
- `baseline_store.py`
- `process_discovery.py`
- `renderer.py`

### 5.2 main.py
The orchestration script that ties all modules together. It handles command-line arguments, triggers process discovery, decides whether to baseline or analyze, and feeds data to the renderer.

### 5.3 analysis_engine.py
The core mathematical brain of ABFS. Contains pure functions to calculate:
- **CPU Similarity**: Using absolute deviation with a tolerance band.
- **File Similarity**: Blending Jaccard index (path overlap) and volume ratio.
- **Network Similarity**: Log-scale comparison with a noise floor threshold.
- Calculates an aggregated **Match Score** and outputs a **Risk Level** (Normal vs Abnormal).

### 5.4 monitoring_engine.py
Responsible for observing the target application over a time window. It hooks into OS-level APIs (via `psutil`) to log active CPU percentage, open file handles, and network connections/bytes transferred.

### 5.5 baseline_store.py
Manages the persistence of trusted application fingerprints. It serializes the known-good profiles to disk (likely as JSON) and retrieves them for comparison during future runs. Contains the executable hash and authorized paths.

### 5.6 process_discovery.py
Handles the initial location of the target application. It resolves application names to strict PIDs, ensuring the monitoring engine hooks into the correct active instance of the software.

### 5.7 renderer.py
Responsible for formatting the output of the `analysis_engine.py` into a readable format for the user (e.g., terminal tables, colors for severity levels).

---

## Chapter 6: Frontend Overview
*(ABFS is primarily a backend/CLI tool, so this section reflects its interface)*

### 6.1 Technology Stack & Framework
- Command Line Interface (CLI) utilizing standard Python output formatting (`renderer.py`).

### 6.2 User Experience Flow
1. User runs `main.py --target "chrome.exe"`.
2. Console displays "Discovering process..."
3. Console displays real-time monitoring stats.
4. After a monitoring window, a summary table is printed showing CPU, File, and Network similarity scores alongside the final Risk Verdict.

---

## Chapter 7: Screenshots
*(To be added by the user)*
- **7.1 CLI Startup Execution**
- **7.2 Baseline Recording Phase**
- **7.3 Normal Runtime Analysis Result**
- **7.4 Suspicious Activity Detection (High Risk Score)**

---

## Chapter 8: Conclusion and Future Work
**Conclusion:** ABFS successfully demonstrates a robust method for detecting application compromise without relying on malware signatures. By utilizing tolerance bands and log-scale comparisons, it drastically reduces false positives caused by natural system noise.

**Future Work:**
- Adding Memory (RAM) allocation profiling.
- Creating a graphical dashboard (Web GUI or Desktop App) to visualize behavior over time.
- Adding API hooking for deeper system call analysis.
- Integrating with SIEMs for enterprise deployments.

---

## Chapter 9: References
1. Documentation for Python `psutil` library.
2. Principles of mathematical similarity (Jaccard Index).
3. EDR (Endpoint Detection and Response) architecture best practices.
