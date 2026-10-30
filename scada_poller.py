"""
scada_poller.py - Simulates the Legitimate Plant SCADA Master.
Polls 3 inverters via Modbus TCP every 2.0 seconds and monitors link latency.
Acts as the empirical witness for Table B.2: Zero Impact on Control Traffic.
"""

import time
import json
from pymodbus.client import ModbusTcpClient

METRICS_FILE = "scada_metrics.json"

scada_metrics = {
    "total_poll_cycles": 0,
    "successful_polls": 0,
    "failed_polls": 0,
    "packet_success_rate_percent": 100.0,
    "average_latency_ms": 1.5,
    "last_poll_timestamp": None,
    "inverter_telemetry": {
        "Inverter-01": {"power_kw": 2500, "voltage_v": 500, "freq_hz": 50.0},
        "Inverter-02": {"power_kw": 2500, "voltage_v": 500, "freq_hz": 50.0},
        "Inverter-03": {"power_kw": 2500, "voltage_v": 500, "freq_hz": 50.0},
    }
}

def save_metrics():
    try:
        with open(METRICS_FILE, "w") as f:
            json.dump(scada_metrics, f, indent=2)
    except Exception:
        pass

def run_scada():
    print("=" * 65)
    print("  STARTING LEGITIMATE SCADA MASTER POLLING (2.0s CYCLE)")
    print("  Monitoring Control Traffic Latency & Availability Baseline")
    print("=" * 65)

    inverters = [
        ("Inverter-01", 5020, 1),
        ("Inverter-02", 5021, 2),
        ("Inverter-03", 5022, 3),
    ]

    while True:
        cycle_start = time.time()
        latencies = []
        all_success = True

        for name, port, unit_id in inverters:
            t0 = time.time()
            client = ModbusTcpClient("127.0.0.1", port=port, timeout=1.0)
            try:
                if client.connect():
                    # Read 6 registers starting at address 0 (40000)
                    try:
                        result = client.read_holding_registers(0, count=6)
                    except TypeError:
                        result = client.read_holding_registers(0, 6)
                    lat = (time.time() - t0) * 1000.0  # ms
                    latencies.append(lat)

                    if not result.isError():
                        regs = result.registers
                        scada_metrics["inverter_telemetry"][name] = {
                            "power_kw": regs[0],
                            "voltage_v": regs[1],
                            "freq_hz": round(regs[2] / 100.0, 2),
                            "p_set_kw": regs[4],
                            "temp_c": regs[5],
                        }
                    else:
                        all_success = False
                    client.close()
                else:
                    all_success = False
            except Exception:
                all_success = False

        scada_metrics["total_poll_cycles"] += 1
        if all_success:
            scada_metrics["successful_polls"] += 1
        else:
            scada_metrics["failed_polls"] += 1

        total = scada_metrics["total_poll_cycles"]
        succ = scada_metrics["successful_polls"]
        scada_metrics["packet_success_rate_percent"] = round((succ / total) * 100.0, 2)
        if latencies:
            scada_metrics["average_latency_ms"] = round(sum(latencies) / len(latencies), 2)
        scada_metrics["last_poll_timestamp"] = time.strftime("%H:%M:%S")

        save_metrics()
        
        # Display periodic status
        if total % 5 == 0:
            p1 = scada_metrics["inverter_telemetry"]["Inverter-01"]["power_kw"]
            p2 = scada_metrics["inverter_telemetry"]["Inverter-02"]["power_kw"]
            p3 = scada_metrics["inverter_telemetry"]["Inverter-03"]["power_kw"]
            print(f"[SCADA Poll #{total}] Latency: {scada_metrics['average_latency_ms']}ms | Success: {scada_metrics['packet_success_rate_percent']}% | Inverters P: {p1}kW, {p2}kW, {p3}kW")

        time.sleep(2.0)

if __name__ == "__main__":
    try:
        run_scada()
    except KeyboardInterrupt:
        print("\n[*] SCADA Poller stopped.")
