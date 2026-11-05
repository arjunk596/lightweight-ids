# Lightweight Network Intrusion Detection System (L-IDS)

A high-performance, modular Network Intrusion Detection System (NIDS) written in Python 3 utilizing Scapy for real-time packet inspection and a Flask-powered Security Operations Center (SOC) web dashboard.

---

## Capabilities & Architecture

1. **Privilege & Environment Guard**:
   * Verifies POSIX root (`EUID == 0`), macOS Berkeley Packet Filter (`/dev/bpf*` r/w access via `access_bpf`), or Windows Administrator privileges before raw socket binding.
   * Exits gracefully with descriptive remediation steps if privileges are insufficient.

2. **Signature-Based Credential Leak Detection (Phase 3)**:
   * Inspects TCP `Raw` payload layers.
   * Decodes cleartext payloads using UTF-8 (defensive binary error suppression).
   * Flags sensitive patterns (`user=`, `pass=`, `password=`, `login=`).
   * Emits bright red ANSI terminal alerts and logs to CSV.

3. **Anomaly-Based SYN Flood / Port Scan Detection (Phase 4)**:
   * Tracks TCP SYN packet frequencies per Source IP across a sliding 10-second time window.
   * Triggers bright yellow ANSI terminal warnings when an IP exceeds 50 SYN packets within the window.
   * Automatically flushes tracking state every 10 seconds to eliminate memory leaks during extended continuous monitoring.

4. **Persistent CSV Audit Logging (Phases 5 & 6)**:
   * Thread-safe logging to [`ids_alerts.csv`](./ids_alerts.csv).
   * 4-column schema: `[Timestamp, Source IP, Destination IP, Alert Type]`.
   * Immediate file close after each write to prevent file locking.

5. **Security Operations Center (SOC) Live Web Dashboard (Phases 7, 8 & 10)**:
   * Dark-mode cyberpunk SOC interface (`#111827`) built with Tailwind CSS.
   * Asynchronous AJAX polling via `fetch('/api/alerts')` every 3 seconds (smooth, flicker-free, no page reloads).
   * Blinking `Status: Monitoring Live Traffic...` activity indicator.
   * Reverse chronological threat stream (newest alerts at the top).
   * Neon visual accents (neon red for critical leaks, neon yellow for port scans).

---

## Project Structure

```text
.
├── lids.py              # Main L-IDS engine and packet sniffer
├── app.py               # SOC Web Dashboard server (Flask)
├── templates/
│   └── index.html       # Dark-Mode SOC HTML template
├── spoof_attack.py      # Advanced adversary simulator with international IP spoofing
├── test_leak.py         # Test harness for cleartext credential leak simulation
├── test_syn_flood.py    # Test harness for SYN flood / port scan simulation
├── ids_alerts.csv       # Persistent audit log for intrusion alerts
├── requirements.txt     # Python dependency specifications
└── .gitignore           # VCS ignore patterns
```

---

## Installation & Setup

1. **Set up virtual environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Run L-IDS Packet Sniffer (Terminal 1)**:
   ```bash
   # Sniff on loopback (local testing - default on macOS)
   ./.venv/bin/python lids.py

   # Or sniff on Wi-Fi / physical interface
   sudo ./.venv/bin/python lids.py -i en0
   ```

3. **Run SOC Web Dashboard (Terminal 2)**:
   ```bash
   ./.venv/bin/python app.py
   ```
   * Access dashboard at: **`http://localhost:5000`** (or **`http://localhost:5001`** if macOS AirPlay Receiver occupies port 5000).

---

## Attack Simulation & Verification

* **Simulate International Spoofed Attacks (Recommended)**:
  ```bash
  # Execute both UK/EU spoofed credential leak & rapid port scan
  ./.venv/bin/python spoof_attack.py --mode all

  # Or simulate a specific scenario
  ./.venv/bin/python spoof_attack.py --mode leak --src-country UK
  ./.venv/bin/python spoof_attack.py --mode scan --src-country EU --count 60
  ```

* **Simulate Basic Local Credential Leak**:
  ```bash
  ./.venv/bin/python test_leak.py --payload "user=admin&password=SecretPassword123"
  ```

* **Simulate Basic Port Scan / SYN Flood**:
  ```bash
  ./.venv/bin/python test_syn_flood.py --count 55
  ```

