"""
sim_iec104.py - Simulates the Pooling Substation RTU Gateway via IEC 60870-5-104.
Listens on TCP port 2404, handles APCI handshakes (STARTDT / TESTFR),
and simulates telecontrol command processing (Type 45 Breaker Actuation).
"""

import socket
import threading
import json
import time

STATE_FILE = "iec104_state.json"

# Substation state
substation_state = {
    "rtu_name": "GETCO-Pooling-Substation-RTU-01",
    "station_address": 1,
    "feeder_breaker_ioa_10": "CLOSED",  # Normal: CLOSED (Power flows to grid)
    "grid_frequency_hz": 50.02,
    "bus_voltage_kv": 33.1,
    "active_telemetry_uplink": True,
    "total_export_mw": 7.5,
    "last_command_received": None,
    "last_command_time": None
}

def save_state():
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(substation_state, f, indent=2)
    except Exception:
        pass

def handle_client(conn, addr):
    print(f"[+] IEC-104 SLDC Client connected from {addr[0]}:{addr[1]}")
    substation_state["active_telemetry_uplink"] = True
    save_state()

    try:
        while True:
            data = conn.recv(1024)
            if not data:
                break

            # Parse APCI Start Byte
            if data[0] == 0x68 and len(data) >= 6:
                apci_ctrl = data[2]

                # U-Format: STARTDT act (0x07)
                if apci_ctrl == 0x07:
                    # Respond with STARTDT con (0x0B)
                    conn.sendall(bytes([0x68, 0x04, 0x0B, 0x00, 0x00, 0x00]))
                    print("    -> Handled IEC-104 STARTDT act -> Sent STARTDT con")

                # U-Format: TESTFR act (0x43)
                elif apci_ctrl == 0x43:
                    # Respond with TESTFR con (0x83)
                    conn.sendall(bytes([0x68, 0x04, 0x83, 0x00, 0x00, 0x00]))
                    print("    -> Handled IEC-104 TESTFR act -> Sent TESTFR con")

                # I-Format containing ASDU
                elif len(data) >= 16:
                    asdu_type = data[6]
                    cot = data[8]
                    ioa = data[12]
                    cmd_val = data[15]

                    # Type 45: C_SC_NA_1 (Single Command)
                    if asdu_type == 45:
                        # IOA 10 = Main 33 kV Outgoing Feeder Breaker
                        # cmd_val & 0x01: 1 = Open/Trip, 0 = Close
                        is_trip = (cmd_val & 0x01) == 1
                        substation_state["feeder_breaker_ioa_10"] = "TRIPPED / OPEN" if is_trip else "CLOSED"
                        substation_state["total_export_mw"] = 0.0 if is_trip else 7.5
                        substation_state["last_command_received"] = f"Type 45 IOA:{ioa} {'TRIP BREAKER' if is_trip else 'CLOSE BREAKER'}"
                        substation_state["last_command_time"] = time.strftime("%H:%M:%S")
                        save_state()

                        print(f"    [!] CRITICAL: IEC-104 Command Executed! IOA:{ioa} -> Breaker State: {substation_state['feeder_breaker_ioa_10']}")

                        # Send Confirmation / Activation Confirmation (COT 7)
                        ack_frame = bytearray(data)
                        ack_frame[8] = 0x07  # COT = Activation Confirmation
                        conn.sendall(bytes(ack_frame))
    except Exception as e:
        print(f"[-] Client connection error: {e}")
    finally:
        conn.close()

def run_server():
    save_state()
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    port = 2404
    try:
        server.bind(("127.0.0.1", port))
    except PermissionError:
        port = 24040
        server.bind(("127.0.0.1", port))

    server.listen(5)
    print("=" * 65)
    print(f"  SIMULATING IEC 60870-5-104 SUBSTATION RTU GATEWAY")
    print(f"  Listening on 127.0.0.1:{port} (Pooling Substation)")
    print("=" * 65)

    while True:
        conn, addr = server.accept()
        t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
        t.start()

if __name__ == "__main__":
    try:
        run_server()
    except KeyboardInterrupt:
        print("\n[*] IEC-104 Gateway stopped.")
