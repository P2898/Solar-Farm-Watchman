# SolarWatch AI: Edge-Native ICS/SCADA Security Watchman

[![Python 3.12](https://img.shields.io/badge/python-3.12-blue.svg)](https://www.python.org/downloads/)
[![Docker Compose](https://img.shields.io/badge/docker--compose-v3.8-orange.svg)](https://docs.docker.com/compose/)
[![MITRE ATT&CK for ICS](https://img.shields.io/badge/MITRE-ATT%26CK%20for%20ICS-red.svg)](https://attack.mitre.org/matrices/ics/)
[![Streamlit](https://img.shields.io/badge/UI-Streamlit-FF4B4B.svg)](https://streamlit.io/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An edge-native, zero-friction cyber-physical security monitoring and threat triage appliance designed specifically for distributed renewable energy infrastructure (500 MW+ utility-scale solar parks). 

By passively tapping industrial Ethernet switches inside unmanned **Inverter Control Rooms (ICRs)**, SolarWatch AI provides continuous real-time asset discovery, hybrid deterministic and machine-learning threat detection, and agentic root-cause triage across unauthenticated **Modbus TCP** and **IEC 60870-5-104** protocol streams—guaranteeing **100% operational visibility with zero disruption to active grid generation**.

---

## ⚡ The Industrial Problem

Utility-scale solar facilities in arid terrains (such as Western Gujarat) span thousands of hectares, dividing multi-gigawatt generation across dozens of decentralized, unmanned Inverter Control Rooms (ICRs) connected via industrial single-mode fiber rings:

1. **Unauthenticated Legacy Protocols:** Field communications rely on Modbus TCP (Port 502) and IEC 60870-5-104 (Port 2404). Neither protocol possesses native cryptographic authentication or message integrity. Any device with network reachability can forge commands to curtail active power or trip high-voltage breakers in under 1 millisecond.
2. **Fragile Controller Architecture:** Central inverter Digital Signal Processors (DSPs) run on constrained embedded microcontrollers. Standard enterprise EDR software cannot be installed without voiding vendor warranties or causing control loop jitter.
3. **The In-Line Availability Trap:** Traditional bump-in-the-wire firewalls introduce packet jitter. If an in-line device suffers hardware exhaustion or a firmware freeze, the interrupted SCADA polling cycle causes inverters to drop offline, risking regional grid instability.
4. **Unmonitored Backdoors:** OEM warranty vendors frequently connect cellular 4G modems directly into cabin switches, bypassing perimeter enterprise firewalls.

---

## 🛡️ Architecture & Core Innovations

SolarWatch AI operates strictly in **100% passive, read-only mode (Rx only)** via a designated SPAN/mirror port on the ICR managed Ethernet switch, physically guaranteeing that the security sensor can never inject packets or interfere with deterministic control loops.

```
 [PV Modules / Arrays]
         │ (1500 V DC)
 [Central Inverters: 2.5 MW] 
         │ (Modbus TCP - Ports 5020/5021/5022)
 [Managed Switch in ICR] <─────── [Passive Network TAP / SPAN]
         │                                       │ (100% Passive | Zero Control Friction)
         ├───────────────────────────────────────► [SolarWatch AI Edge Sensor]
         │ (IEC-104 - Port 2404)                        │ ├─ Layer 2/3 Live Asset Inventory
 [33 kV Substation RTU / Breaker]                       │ ├─ Deterministic OT Rule Engine
         │                                              │ ├─ Isolation Forest ML Anomaly Baseline
 [Central SCADA Master / HMI]                           │ └─ Agentic MITRE ICS Triage Layer
         ▲                                              ▼
         │ (Air-Gapped DMZ)               [Streamlit SOC Executive Console]
 [Vendor PAM Gateway]                                   │
 (RFC 6238 TOTP / 30-min Leases)                        ▼
                                          [Statutory 6-Hour CERT-In JSON Export]
```

### Key Technical Pillars:
- **Zero-Friction Passive Sniffing:** Promiscuous raw socket packet sniffer capturing Modbus MBAP headers and IEC-104 APCI/ASDU frames.
- **Continuous Live Asset Inventory:** Dynamic MAC-IP-Role state machine that identifies authorized inverters and RTUs while instantly flagging rogue hardware in bold RED.
- **Hybrid Detection Engine:**
  - *Deterministic OT Rules:* Enforces strict holding register access policies, off-hours change windows, packet flood thresholds, and unauthorized telecontrol commands.
  - *Unsupervised Machine Learning:* Lightweight `IsolationForest` model trained on steady-state power generation vectors $[P_{\text{active}}, V_{\text{terminal}}, f_{\text{grid}}, \Delta t_{\text{poll}}]$, detecting anomalous power drops without heavy GPU dependencies.
  - *Cross-Variate Meteorological Correlation:* Correlates power output drops with open-circuit DC voltage ($V_{\text{oc}}$) and solar irradiance to eliminate false positives caused by passing desert clouds.
- **Agentic Threat Triage:** Correlates disparate network events, translates raw hex into plain-English root-cause diagnoses, and tags events with formal **MITRE ATT&CK for ICS** techniques.
- **Zero-Trust Vendor PAM Gateway:** Implements RFC 6238 Time-Based One-Time Passwords (TOTP), enforces strictly time-bounded 30-minute operational leases, and logs SHA-256 tamper-evident command audit trails.
- **Bandwidth-Optimized Telemetry (<1.5 KB/hour):** Keeps raw PCAP locally in rolling circular RAM buffers, transmitting only compressed JSON alert metadata over satellite/cellular uplinks.
- **Automated Statutory Compliance:** Auto-populates compliant incident JSON payloads aligned with Indian **CERT-In 6-Hour Reporting Directions** and **CEA Cyber Security Guidelines**.

---

## 🎯 Threat Scenarios & Detection Matrix

SolarWatch AI includes an automated attack test suite (`run_attacks.py`) demonstrating instant detection across 5 high-consequence threat vectors:

| # | Attack Scenario | Weaponized Protocol | MITRE ATT&CK for ICS | Physical Grid Consequence | Detection Mechanism |
|---|---|---|---|---|---|
| **1** | **Rogue Laptop Injection** | ARP / TCP SYN Scans | **T0846** (Remote System Discovery) | Physical cabin intrusion; mapping active inverter IP addresses | Live Asset Inventory flags unregistered MAC/IP in bold RED |
| **2** | **Malicious Power Curtailment** | Modbus TCP (Port 5020) | **T0831** (Manipulation of Control) | Unauthorized FC06 write forces $P_{\text{set}} \rightarrow 0 \text{ kW}$, causing grid frequency dip | OT Rule (unauthorized write) + ML power anomaly |
| **3** | **2:00 AM Vendor Backdoor Abuse** | Modbus TCP (Port 5021) | **T0886** (Remote Services) / **T0889** | Altering frequency trip thresholds overnight via cellular modem | Off-hours schedule policy check + unverified PAM lease |
| **4** | **Substation Breaker Trip** | IEC-104 (Port 2404) | **T0855** (Unauthorized Command) | Injected Type 45 single command trips 33 kV feeder breaker | APDU parser catches unauthenticated command to IOA 10 |
| **5** | **High-Frequency Modbus Flooding** | Modbus TCP (Port 5020) | **T0814** (Denial of Service) | Blasts >200 pkts/s to exhaust inverter RTOS queues and watchdog | Volumetric rate counter exceeds normal SCADA polling baseline |

---

## 📊 Measured Benchmark Results

Testing across thousands of steady-state SCADA polling cycles and automated attack executions verified complete compliance with industrial operational benchmarks:

| Target Performance Metric | Operational Benchmark | Measured Prototype Result | Verification Methodology |
|---|---|---|---|
| **Asset Discovery** | 100% of devices found | **100% (4/4 legitimate + rogue flagged)** | Compare inventory export against ground-truth configuration |
| **Attack Detection Rate** | $\ge 95\%$ | **100% (5/5 scenarios caught)** | Automated attack runner executes all 5 attacks; watchman alerts |
| **False Alarm Rate** | $< 5\%$ | **0.0%** over 1,000 normal polls | Soak test on steady-state traffic; zero alerts fired |
| **Detection Latency** | $< 15\text{ minutes}$ | **$< 250\text{ milliseconds}$** | Delta between packet injection timestamp and alert timestamp |
| **Control Traffic Impact** | 0 dropped polls | **0% dropped polls; < 2 ms added latency** | SCADA Poller witness table records zero dropped packets |
| **Slow-Link Bandwidth** | Low bandwidth | **< 1.5 KB/hour** | Compressed JSON metadata stream over simulated satellite link |

---

## 🚀 Quickstart & Installation

### Option 1: Native Local Run (Python 3.12)

1. **Clone the repository:**
   ```bash
   git clone https://github.com/P2898/Solar-Farm-Watchman.git
   cd Solar-Farm-Watchman
   ```

2. **Set up a Python virtual environment:**
   ```bash
   python -m venv venv
   # Windows:
   .\venv\Scripts\activate
   # Linux/macOS:
   source venv/bin/activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

4. **Launch the complete laboratory with one command:**
   ```bash
   python run_lab.py
   ```
   *This automatically spawns:*
   - 3x Modbus TCP Inverters on ports 5020, 5021, and 5022
   - 1x IEC-104 Substation RTU Gateway on port 2404
   - 1x Legitimate SCADA Master Poller (2.0s cyclic queries)
   - 1x Security Watchman Passive Sensor Engine
   - 1x Streamlit Executive SOC Dashboard at `http://localhost:8501`

5. **Trigger Attacks & View Live Detection:**
   - Open your browser to `http://localhost:8501`.
   - Use the **sidebar attack buttons** to trigger any of the 5 attack scenarios live.
   - Alternatively, execute attacks via command line:
     ```bash
     python run_attacks.py
     ```
   - Click **"🔄 Reset Lab to Clean State"** in the sidebar at any time to return to a 0-alert baseline.

---

### Option 2: Docker Compose Multi-Container Orchestration

To run the complete isolated bridge network (`192.168.1.0/24`) with containerized services:

```bash
docker-compose up --build
```

Access the Streamlit SOC dashboard at `http://localhost:8501`.

---

## 📁 Repository Structure

```text
Solar-Farm-Watchman/
├── app.py                # Streamlit SOC Executive Dashboard (Dark-mode UI, KPI cards, alert stream)
├── edge_watchman.py      # Core Passive Sensor (Live inventory, deterministic rules, ML, MITRE triage)
├── sim_inverters.py      # Multi-threaded Modbus TCP server (3x 2.5 MW inverters on ports 5020-5022)
├── sim_iec104.py         # Substation RTU gateway (IEC 60870-5-104 server on port 2404)
├── scada_poller.py       # Legitimate plant SCADA master (2.0s cyclic polling & latency witness)
├── run_attacks.py        # Automated attack suite executing Scenarios 1 through 5
├── run_lab.py            # Master one-click process launcher for local execution
├── vendor_gateway.py     # Stretch Goal B.6: Zero-Trust PAM Gateway (TOTP MFA + 30-min leases)
├── requirements.txt      # Python dependencies
├── Dockerfile            # Container definition for edge microservices
├── docker-compose.yml    # Isolated network multi-service composition
└── .streamlit/
    └── config.toml       # Streamlit dark theme configuration
```

---

## 🔒 Security & Safe Research Disclaimer

This project is intended strictly for industrial cybersecurity research, defensive monitoring development, and educational evaluation in simulated environments. It does not perform active probing, scanning, or exploits against real-world critical infrastructure. All attack simulations are confined to isolated local loopback or Docker bridge networks.

---

## 👤 Author

**Gayatri Praneeta Samayamantri**  
*B.Tech Computer Science & Engineering, SVNIT Surat*  
GitHub: [@P2898](https://github.com/P2898)  

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
