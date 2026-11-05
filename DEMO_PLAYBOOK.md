# 🛡️ Lightweight IDS (L-IDS) Live Demonstration Playbook

This playbook provides a step-by-step presentation guide for demonstrating the **Lightweight Network Intrusion Detection System (L-IDS)** and its real-time **Security Operations Center (SOC) Web Dashboard** in a 3-window split-screen configuration.

---

## 1. Split-Screen Window Arrangement

Arrange your monitor into **3 distinct zones** so your audience can witness the attacker actions, the defender terminal analysis, and the live SOC dashboard telemetry simultaneously.

```
+------------------------------------+------------------------------------+
|                                    |                                    |
|       WINDOW 1: WEB BROWSER        |     WINDOW 2: ATTACKER TERMINAL    |
|   (Live SOC Dashboard - Chrome)    |     (Simulated Threat Actor)       |
|                                    |                                    |
|   - URL: http://localhost:5000     |     - Runs curl & nmap commands    |
|   - AJAX Polling every 3s (No lag) |     - High-contrast Red/Amber text |
|   - Neon Alert Visualization       |                                    |
|                                    |                                    |
+------------------------------------+------------------------------------+
|                                                                         |
|                       WINDOW 3: DEFENDER TERMINAL                       |
|                          (L-IDS Sniffer Engine)                         |
|                                                                         |
|   - Runs lids.py with sudo (raw packet inspection)                      |
|   - Shows real-time packet telemetry & ANSI colored terminal alerts     |
|                                                                         |
+-------------------------------------------------------------------------+
```

### Setup Instructions:
* **Top-Left (Window 1)**: Open your browser (Chrome/Safari) at `http://localhost:5000` (or `http://localhost:5001`). Press `Cmd + Shift + F` (or full height half-screen) to focus on the threat stream.
* **Top-Right (Window 2)**: Open a terminal titled **ATTACKER**. (Optionally set profile background to dark red or amber).
* **Bottom Half (Window 3)**: Open a terminal titled **DEFENDER / SOC ENGINE**. This shows the core packet stream and terminal-level detection.

---

## 2. Startup Sequence (Defender Terminal)

Open the **Defender Terminal (Window 3)** in the project directory:

```bash
cd /Users/arjunkharche/Personal/College/Sem-V/CyberSec/mini_project
```

### Step 2.1 — Start the SOC Web Dashboard in Background
Launch `app.py` in the background with output redirected:
```bash
./.venv/bin/python app.py > dashboard.log 2>&1 &
```
*(Verify it is running by checking `http://localhost:5000` or `http://localhost:5001` in Window 1).*

### Step 2.2 — Start the L-IDS Packet Sniffer (Foreground)
Run `lids.py` with elevated privileges targeting the loopback interface (`lo0`):
```bash
sudo ./.venv/bin/python lids.py -i lo0
```

> **Expected Output in Defender Terminal**:
> ```text
> [*] Initializing Lightweight Network Intrusion Detection System (L-IDS)...
> [+] Privilege verification passed (Packet sniffing authorized).
> [*] Starting live packet capture (store=False)...
> [*] Bound to interface: lo0
> [*] Press Ctrl+C at any time to halt inspection.
> ----------------------------------------------------------------------
> ```

---

## 3. The Live Attack Script (Attacker Terminal)

Switch to the **Attacker Terminal (Window 2)** to execute the attack scenarios in front of the audience.

---

### Scenario A: Signature Attack — Cleartext Credential Exfiltration

* **Concept**: Explaining why transmitting unencrypted credentials over HTTP/TCP exposes organizations to immediate interception.
* **Attacker Action**: Send a mock authentication request containing cleartext credentials using `curl`:

```bash
curl -X POST \
  -d "user=admin&password=SuperSecretPassword2026!" \
  http://127.0.0.1:5001/login
```
*(Note: Use port `5001` or `5000` matching the active dashboard port, or target any local port).*

#### Real-Time Audience Visuals:
1. **Defender Terminal (Window 3)**:
   Immediately halts packet stream and prints a **Bright Red Alert**:
   ```text
   =================================================================
   [!] CRITICAL ALERT: Sensitive Credential Leak Detected!
   =================================================================
   [-] Source IP        : 127.0.0.1:54321
   [-] Destination IP   : 127.0.0.1:5001
   [-] Trigger Pattern  : user=, password=
   [-] Leaked Snippet   : ...user=admin&password=SuperSecretPassword2026!...
   [-] Action           : Recorded in ids_alerts.csv
   =================================================================
   ```
2. **Web Browser (Window 1)**:
   Within **3 seconds**, the page refreshes and pops a glowing **Neon Red** entry at the top:
   * **Badge**: `🚨 Cleartext Leak`
   * **Source IP**: `127.0.0.1`
   * **KPI Card**: "Cleartext Leaks" counter increments by +1.

---

### Scenario B: Anomaly Attack — Port Scan / SYN Flood Reconnaissance

* **Concept**: Explaining how threat actors map open ports and conduct Denial-of-Service via rapid TCP SYN bursts.
* **Attacker Action**: Execute a fast TCP SYN scan with `nmap` targeting 70 ports (exceeding the >50 threshold):

```bash
sudo nmap -sS -T4 -p 1-70 127.0.0.1
```

> **Fallback (if `nmap` is not installed on the system)**:
> Run the built-in attack script:
> ```bash
> ./.venv/bin/python test_syn_flood.py --count 60
> ```

#### Real-Time Audience Visuals:
1. **Defender Terminal (Window 3)**:
   Upon packet #51, immediately triggers a **Bright Yellow Warning**:
   ```text
   =================================================================
   [!] WARNING: Potential Port Scan or SYN Flood!
   =================================================================
   [-] Source IP        : 127.0.0.1
   [-] SYN Packet Count : 51 (Threshold: >50 in 10s)
   [-] Target Host/Port : 127.0.0.1:51
   [-] Action           : Recorded in ids_alerts.csv
   =================================================================
   ```
2. **Web Browser (Window 1)**:
   The dashboard reloads and places a **Neon Yellow** entry at the top of the feed:
   * **Badge**: `⚠️ Port Scan`
   * **Source IP**: `127.0.0.1`
   * **KPI Card**: "Port Scans" counter increments by +1.

---

## 4. Teardown & Graceful Shutdown Demonstration

To conclude the presentation, highlight defensive engineering and session auditing:

1. **In the Defender Terminal (Window 3)**:
   Press **`Ctrl + C`**.
2. **Show Audience the Automatic Telemetry Report**:
   ```text
   =================================================================
                L-IDS SESSION SHUTDOWN SUMMARY
   =================================================================
    [+] Total Runtime          : 02m 14s (134.12s)
    [+] Total Packets Analyzed : 384
    [+] Total Alerts Triggered : 2
    [+] Persistent Alert Log   : /.../mini_project/ids_alerts.csv
   =================================================================
   ```
3. **Stop Background Dashboard**:
   ```bash
   kill $(pgrep -f "python app.py")
   ```

---

## 5. Speaker Talking Points Checklist

* [ ] **Zero-Drop Architecture**: Point out `store=False` in Scapy to prove the sniffer avoids memory bloat even under flood conditions.
* [ ] **Sliding Window Garbage Collection**: Explain that `syn_tracker` flushes every 10 seconds to guarantee memory stability.
* [ ] **Multi-Vector Defense**: Emphasize how signature analysis (payload inspection) and anomaly analysis (rate-limiting heuristics) work in parallel.
* [ ] **Air-Gapped SOC Dashboard**: Explain that `ids_alerts.csv` decouples the packet inspection engine from the presentation layer, allowing SOC analysts to view threats independently of root sniffer processes.
