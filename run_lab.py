"""
run_lab.py - Master One-Click Prototype Launcher.
Spawns all mini-ICR components concurrently:
  1. sim_inverters.py (3x Modbus TCP inverters)
  2. sim_iec104.py (Grid Substation RTU)
  3. scada_poller.py (SCADA Master poller)
  4. edge_watchman.py (Passive Security Sensor)
  5. app.py (Streamlit Web Dashboard)
"""

import subprocess
import sys
import time
import os

processes = []

def start_component(cmd, name):
    print(f"[*] Starting {name}...")
    p = subprocess.Popen([sys.executable] + cmd, cwd=os.path.dirname(os.path.abspath(__file__)))
    processes.append((name, p))
    time.sleep(1.0)

def main():
    print("=" * 70)
    print("  SOLARWATCH AI: PART B PROTOTYPE LAB - LAUNCHING ALL SERVICES")
    print("  Western Gujarat Desert Solar Park - Inverter Control Room (ICR)")
    print("=" * 70)

    try:
        # 1. Start Inverters
        start_component(["sim_inverters.py"], "3x Modbus Inverters (Ports 5020-5022)")

        # 2. Start IEC-104 Substation Gateway
        start_component(["sim_iec104.py"], "Substation IEC-104 Gateway (Port 2404)")

        # 3. Start Security Watchman Passive Sensor
        start_component(["edge_watchman.py"], "Security Watchman Sensor (Passive SPAN)")

        # 4. Start SCADA Poller
        start_component(["scada_poller.py"], "Legitimate SCADA Master Poller")

        print("\n" + "=" * 70)
        print("  [SUCCESS] All Industrial Services are Running Steadily!")
        print("  Launching Streamlit Web Dashboard at http://localhost:8501...")
        print("  Press Ctrl+C to gracefully shut down the lab.")
        print("=" * 70 + "\n")

        # 5. Launch Streamlit Dashboard
        p_dash = subprocess.Popen([sys.executable, "-m", "streamlit", "run", "app.py", "--server.port", "8501", "--server.headless", "true"],
                                  cwd=os.path.dirname(os.path.abspath(__file__)))
        processes.append(("Streamlit Dashboard", p_dash))

        # Keep alive
        while True:
            time.sleep(1.0)

    except KeyboardInterrupt:
        print("\n[*] Shutting down all lab processes...")
        for name, p in processes:
            p.terminate()
        print("[+] All services stopped cleanly.")

if __name__ == "__main__":
    main()
