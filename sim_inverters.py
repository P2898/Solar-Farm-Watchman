"""
sim_inverters.py - High-Fidelity Simulation of 3 Central Solar Inverters (2.5 MW each).
Exposes standard Modbus TCP holding registers on ports 5020, 5021, and 5022.
Western Gujarat Solar Park - Inverter Control Room (ICR).
"""

import socket
import threading
import time
import random
import sys

# Register Map (Base address 40000 / offset 0):
# 0: Active Power (kW) - Default 2500 kW (2.5 MW)
# 1: DC Bus Voltage (V) - Default 500 V
# 2: Grid Frequency (Hz * 100) - Default 5000 (50.00 Hz)
# 3: Reactive Power (kVAR) - Default 0
# 4: Active Power Setpoint (kW) - Default 2500 kW
# 5: Inverter Heat Sink Temp (°C) - Default 52 °C
# 6: Operating State (1 = Running, 2 = Curtailed, 3 = Tripped)

class CentralInverter:
    def __init__(self, name: str, unit_id: int, port: int):
        self.name = name
        self.unit_id = unit_id
        self.port = port
        self.regs = [2500, 500, 5000, 0, 2500, 52, 1]
        self.running = True
        self.server_sock = None

    def start_dynamics(self):
        """Simulates physical solar dynamics and response to setpoint commands."""
        def dynamic_loop():
            while self.running:
                p_set = self.regs[4]
                state = self.regs[6]

                if state == 3:  # Tripped
                    self.regs[0] = 0
                elif p_set < 100:  # Curtailed to 0
                    self.regs[0] = p_set
                    self.regs[6] = 2  # State = Curtailed
                else:
                    # Normal operation: fluctuate within ±15 kW around setpoint
                    jitter = random.randint(-15, 15)
                    self.regs[0] = max(0, min(2500, p_set + jitter))
                    self.regs[6] = 1  # State = Running

                # Voltage & frequency realistic physical noise
                self.regs[1] = 500 + random.randint(-2, 2)
                self.regs[2] = 5000 + random.randint(-5, 5)
                self.regs[5] = 52 + random.randint(-1, 1)

                time.sleep(1.0)

        t = threading.Thread(target=dynamic_loop, daemon=True)
        t.start()

    def handle_client(self, conn: socket.socket):
        while self.running:
            try:
                data = conn.recv(1024)
                if not data:
                    break
                
                # Modbus TCP Framing:
                # 0-1: Transaction ID
                # 2-3: Protocol ID (0x0000 = Modbus)
                # 4-5: Length
                # 6:   Unit ID
                # 7:   Function Code
                if len(data) >= 8:
                    trans_id = data[0:2]
                    proto_id = data[2:4]
                    unit_id = data[6]
                    fc = data[7]

                    if fc == 0x03 or fc == 0x04:  # Read Holding / Input Registers
                        start = (data[8] << 8) | data[9]
                        count = (data[10] << 8) | data[11]
                        vals = self.regs[start:start+count]
                        byte_count = len(vals) * 2
                        payload = bytearray([fc, byte_count])
                        for v in vals:
                            payload.extend([(v >> 8) & 0xFF, v & 0xFF])
                        
                        resp_len = 1 + len(payload)  # Unit ID + payload
                        header = bytearray(trans_id + proto_id + bytearray([(resp_len >> 8) & 0xFF, resp_len & 0xFF, unit_id]))
                        conn.sendall(header + payload)

                    elif fc == 0x06:  # Write Single Register
                        reg = (data[8] << 8) | data[9]
                        val = (data[10] << 8) | data[11]
                        if reg < len(self.regs):
                            self.regs[reg] = val
                        # Inverter mirrors request as standard Modbus ACK
                        conn.sendall(data[:12])

                    elif fc == 0x10:  # Write Multiple Registers
                        start = (data[8] << 8) | data[9]
                        count = (data[10] << 8) | data[11]
                        resp_len = 6
                        header = bytearray(trans_id + proto_id + bytearray([(resp_len >> 8) & 0xFF, resp_len & 0xFF, unit_id]))
                        payload = bytearray([fc, (start >> 8) & 0xFF, start & 0xFF, (count >> 8) & 0xFF, count & 0xFF])
                        conn.sendall(header + payload)

            except Exception:
                break
        conn.close()

    def run(self):
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.bind(("127.0.0.1", self.port))
        self.server_sock.listen(10)
        print(f"[+] Started {self.name} (Unit ID {self.unit_id}) listening on 127.0.0.1:{self.port}")
        self.start_dynamics()

        while self.running:
            try:
                conn, _ = self.server_sock.accept()
                t = threading.Thread(target=self.handle_client, args=(conn,), daemon=True)
                t.start()
            except Exception:
                break

def main():
    print("=" * 65)
    print("  SIMULATING 3 CENTRAL SOLAR INVERTERS (7.5 MW TOTAL CAPACITY)")
    print("  Western Gujarat Solar Park - Inverter Control Room (ICR)")
    print("=" * 65)

    invs = [
        CentralInverter("Inverter-01", 1, 5020),
        CentralInverter("Inverter-02", 2, 5021),
        CentralInverter("Inverter-03", 3, 5022),
    ]

    threads = []
    for inv in invs:
        t = threading.Thread(target=inv.run, daemon=True)
        t.start()
        threads.append(t)

    try:
        while True:
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[*] Stopping inverters...")
        for inv in invs:
            inv.running = False
            if inv.server_sock:
                inv.server_sock.close()
        print("[+] Inverters stopped cleanly.")

if __name__ == "__main__":
    main()
