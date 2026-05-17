import os
import time
import urllib.request
import tempfile
import threading

def cpu_burner(stop_event):
    """Burns CPU cycles by performing continuous calculations within the same PID."""
    while not stop_event.is_set():
        # Meaningless math to keep the CPU busy
        _ = [x**2.5 for x in range(1000)]

def trigger_anomaly(duration=120):
    print(f"\n[!] INITIATING ABNORMAL ACTIVITY FOR {duration} SECONDS...")
    print("    - Spiking CPU usage (launching background threads)")
    print("    - Generating anomalous file system activity (creating temp files)")
    print("    - Generating anomalous network traffic (downloading files)")
    
    stop_event = threading.Event()
    
    # 1. Start CPU burners as THREADS (so they share the monitored PID)
    burners = []
    # 2 threads are usually enough to max out the process CPU tracking
    for _ in range(2):
        t = threading.Thread(target=cpu_burner, args=(stop_event,))
        t.daemon = True
        t.start()
        burners.append(t)
        
    # 2. Network and File spiker thread
    def spiker_worker():
        test_url = "https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css"
        
        # ANCHOR FILE: We keep this file OPEN for the entire duration. 
        # This guarantees that ABFS's proc.open_files() scan will reliably 
        # spot the Temp directory and attach the watchdog observer to it.
        with tempfile.NamedTemporaryFile(delete=False, prefix="abfs_anchor_") as anchor:
            anchor.write(b"Anchor to keep directory open")
            anchor.flush()
            
            while not stop_event.is_set():
                # A. File Anomaly: Create unique junk files
                with tempfile.NamedTemporaryFile(delete=False, prefix="abfs_malware_sim_") as f:
                    f.write(os.urandom(1024 * 100)) # 100KB
                    temp_name = f.name
                
                # B. Network Anomaly: Download a file
                try:
                    req = urllib.request.Request(test_url, headers={'User-Agent': 'Mozilla/5.0'})
                    with urllib.request.urlopen(req, timeout=3) as response:
                        response.read()
                except Exception:
                    pass
                
                # Cleanup the junk file
                try:
                    os.remove(temp_name)
                except OSError:
                    pass
                
                time.sleep(0.5)
                
        # Cleanup anchor
        try:
            os.remove(anchor.name)
        except OSError:
            pass

    spiker_thread = threading.Thread(target=spiker_worker)
    spiker_thread.daemon = True
    spiker_thread.start()

    # Wait for the duration
    start_time = time.time()
    while time.time() - start_time < duration:
        remaining = int(duration - (time.time() - start_time))
        print(f"\r    Time remaining: {remaining}s ...", end="", flush=True)
        time.sleep(1)
        
    # Cleanup
    print("\n[✓] Anomaly simulation complete. Cleaning up...")
    stop_event.set()
    for t in burners:
        t.join(timeout=1.0)
    spiker_thread.join(timeout=1.0)
        
    print("[✓] Returned to NORMAL IDLE state.\n")

if __name__ == '__main__':
    print("=====================================================")
    print("    ABFS Spike File ")
    print("=====================================================")
    print(f"  PID: {os.getpid()}")
    print("  Status: NORMAL IDLE STATE")
    print("=====================================================\n")
    print("INSTRUCTIONS FOR PRESENTATION:")
    print("  1. Leave this window open and idle.")
    print(f"  2. In another terminal, run ABFS to baseline this app:")
    print(f"     python main.py analyze --pid {os.getpid()} --baseline-only")
    print("  3. Once baseline is complete, type 'start' below.")
    print("  4. While the anomaly is running, run ABFS again to detect it:")
    print(f"     python main.py analyze --pid {os.getpid()}")
    print("-----------------------------------------------------\n")
    
    while True:
        try:
            cmd = input("Type 'start' to trigger a 2-minute anomaly, or 'quit' to exit: ")
            cmd = cmd.strip().lower()
            if cmd == 'start':
                trigger_anomaly(120)
            elif cmd == 'quit':
                break
            else:
                print("Unknown command. Type 'start' or 'quit'.")
        except KeyboardInterrupt:
            print("\nExiting...")
            break
